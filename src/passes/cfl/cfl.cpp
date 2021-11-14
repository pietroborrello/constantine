
#include <pass.h>

#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/CFG.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/IR/IRBuilder.h"

using namespace llvm;

#define DEBUG_TYPE "cfl"
#define cflPassLog(M) LLVM_DEBUG(dbgs() << "CFLPass: " << M << "\n")
#define oprint(s) outs() << s << "\n"

static cl::list<std::string>
Functions("cfl-funcs",
    cl::desc("Specify all the comma-separated function regexes to cfl"),
    cl::ZeroOrMore, cl::CommaSeparated, cl::NotHidden);

static cl::opt<bool>
SimpleBranches("cfl-simple-branches",
    cl::desc("Linearize only simple branches"),
    cl::init(false), cl::NotHidden);

static cl::opt<bool>
MemProtect("cfl-protect-mem",
    cl::desc("CFL: protect memory accesses (disable if run after DFL)"),
    cl::init(true), cl::NotHidden);

static cl::opt<bool>
BranchProtect("cfl-protect-branches",
    cl::desc("CFL: protect branches"),
    cl::init(true), cl::NotHidden);

static cl::opt<bool>
CFLRelaxed("cfl-relaxed",
    cl::desc("Avoid linearizing non tainted branches for which we may prove they are safe"),
    cl::init(false), cl::NotHidden);

typedef long imd_t;

namespace {

  class IfCondition {
  public:
      BranchInst *Branch;
      BasicBlock *MergePoint;
      BasicBlock *IfTrue;
      BasicBlock *IfFalse;
      BasicBlock *IfTruePred;
  };

  class CFLPass : public ModulePass {

    unsigned long CFLedFuncs         = 0;
    unsigned long totalFuncs         = 0;
    unsigned long linearizedBranches = 0;
    unsigned long totalBranches      = 0;
    unsigned long totalIFCs          = 0;
    
  public:
    static char ID;
    CFLPass() : ModulePass(ID) {}

    void setInstructionTaint(Instruction *I, bool taint) {
        LLVMContext& C = I->getContext();
        MDNode* N = MDNode::get(C, ConstantAsMetadata::get(ConstantInt::get(C, APInt(sizeof(imd_t)*8, taint, true))));
        I->setMetadata("t", N);
    }

    bool getInstructionTaint(Instruction &I) {
        MDNode* N;
        Constant *val;
        N = I.getMetadata("t");
        assert(N);
        if (N == NULL) return false;
        val = dyn_cast<ConstantAsMetadata>(N->getOperand(0))->getValue();
        assert(val);
        int taint = cast<ConstantInt>(val)->getSExtValue();
        return taint;
    }

    // check if the instruction has been marked as uninteresting by the 
    // loadtainted pass
    bool isInstructionUninteresting(Instruction &I) {
        MDNode* N;
        N = I.getMetadata("uninteresting_direction");
        if (N == NULL) return false;
        return true;
    }

    bool getUninterestingDirection(Instruction &I) {
        MDNode* N;
        Constant *val;
        N = I.getMetadata("uninteresting_direction");
        assert(N);
        val = dyn_cast<ConstantAsMetadata>(N->getOperand(0))->getValue();
        assert(val);
        int direction = cast<ConstantInt>(val)->getSExtValue();
        return direction;
    }

    int getBGID(Instruction &I) {
        MDNode* N;
        Constant *val;
        BasicBlock *BB = I.getParent();
        N = BB->getTerminator()->getMetadata("b-gid");
        val = dyn_cast<ConstantAsMetadata>(N->getOperand(0))->getValue();
        assert(val);
        int b_gid = cast<ConstantInt>(val)->getSExtValue();
        return b_gid;
    }

    int getIBID(Instruction &I) {
        MDNode* N;
        Constant *val;
        N = I.getMetadata("i-bid");
        val = dyn_cast<ConstantAsMetadata>(N->getOperand(0))->getValue();
        assert(val);
        int i_bid = cast<ConstantInt>(val)->getSExtValue();
        return i_bid;
    }

    ConstantInt* makeConstI32(LLVMContext &C, int value) {
        return ConstantInt::get(C, APInt(sizeof(int)*8, value, true));
    }

    ConstantInt* makeConstBool(LLVMContext &C, int value) {
        ConstantInt *BoolTrue = ConstantInt::getTrue(C);
        ConstantInt *BoolFalse = ConstantInt::getFalse(C);
        return value? BoolTrue : BoolFalse;
    }

    void wrapIntrinsicCall(CallSite &CS, Function *Callee) {
        const char *wrapper = NULL;
        switch(Callee->getIntrinsicID()) {
        case Intrinsic::memcpy:
            wrapper = "cfl_memcpy";
            break;
        case Intrinsic::memmove:
            wrapper = "cfl_memmove";
            break;
        case Intrinsic::memset:
            wrapper = "cfl_memset";
            break;
        default:
            return;
        }
        Function *NewCallee = Callee->getParent()->getFunction(wrapper);
        CS.setCalledFunction(NewCallee);
    }

    void wrapExtCall(CallSite &CS, Function *Callee) {
        static Function *F = Callee->getParent()->getFunction("cfl_fptr_wrap");
        assert(F);
        std::vector<Value*> args;
        args.push_back(CastInst::CreatePointerCast(Callee, F->getParamByValType(0)->getPointerTo(), "", CS.getInstruction()));
        CallInst *CI = CallInst::Create(F, args, "", CS.getInstruction());
        CS.setCalledFunction(CastInst::CreatePointerCast(CI, Callee->getType(), "", CS.getInstruction()));
    }

    void wrapLoad(LoadInst *LI) {
        static Function *F = LI->getParent()->getParent()->getParent()->getFunction("cfl_ptr_wrap");
        static InlineFunctionInfo IFI;
        assert(F);
        std::vector<Value*> args;
        args.push_back(CastInst::CreatePointerCast(LI->getPointerOperand(), F->getParamByValType(0)->getPointerTo(), "", LI));
        CallInst *CI = CallInst::Create(F, args, "", LI);
        CallSite CS(CI);
        LI->setOperand(0, CastInst::CreatePointerCast(CI, LI->getPointerOperandType(), "", LI));
        // do not inline now to avoid loops-cfl detecting this as an escaping value
        // due to the call to an unrecognized function
        // assert(InlineFunction(CS, IFI));
    }

    void wrapStore(StoreInst *SI) {
        static Function *F = SI->getParent()->getParent()->getParent()->getFunction("cfl_ptr_wrap");
        static InlineFunctionInfo IFI;
        assert(F);
        std::vector<Value*> args;
        args.push_back(CastInst::CreatePointerCast(SI->getPointerOperand(), F->getParamByValType(0)->getPointerTo(), "", SI));
        CallInst *CI = CallInst::Create(F, args, "", SI);
        CallSite CS(CI);
        SI->setOperand(1, CastInst::CreatePointerCast(CI, SI->getPointerOperandType(), "", SI));
        // do not inline now to avoid loops-cfl detecting this as an escaping value
        // due to the call to an unrecognized function
        // assert(InlineFunction(CS, IFI));
    }


    void wrapUninterestingCondition(IfCondition &IFC) {
        static Function *CondF;

        // Init
        Function *F = IFC.MergePoint->getParent();
        LLVMContext& C = F->getContext();
        BasicBlock *IfHeader = IFC.Branch->getParent();
        Value *IfCond = IFC.Branch->getCondition();
        if (!CondF) {
            CondF = F->getParent()->getFunction("cfl_br_get_fixed");
        }

        int branchBGID = getBGID(*IFC.Branch);
        int branchIBID = getIBID(*IFC.Branch);

        // assert that the branch is not tainted
        assert(!getInstructionTaint(*IFC.Branch));

        bool fixed_res = getUninterestingDirection(*IFC.Branch);
        // Call the wrapper
        std::vector<Value*> CondFArgs;
        CondFArgs.push_back(IfCond);
        CondFArgs.push_back(makeConstBool(C, fixed_res));
        // add the required IDs if CFL_DEBUG==2
        if (CondF->arg_size() > CondFArgs.size()) {
            CondFArgs.push_back(makeConstI32(C, branchBGID));
            CondFArgs.push_back(makeConstI32(C, branchIBID));
        }
        Value *FixedCond = CallInst::Create(CondF, CondFArgs, "", IfHeader->getTerminator());
        IFC.Branch->setCondition(FixedCond);
    }

    void wrapCondition(IfCondition &IFC) {
        static Function *CondF, *IfTrueF, *IfFalseF, *MergePointF;

        // Init
        Function *F = IFC.MergePoint->getParent();
        BasicBlock *IfHeader = IFC.Branch->getParent();
        Value *IfCond = IFC.Branch->getCondition();
        if (!CondF) {
            CondF = F->getParent()->getFunction("cfl_br_cond");
            IfTrueF = F->getParent()->getFunction("cfl_br_iftrue");
            IfFalseF = F->getParent()->getFunction("cfl_br_iffalse");
            MergePointF = F->getParent()->getFunction("cfl_br_merge");
        }

        // Create local to pass to wrappers
        AllocaInst *AITmp = new AllocaInst(CondF->getParamByValType(0), 0, "cfl_tmp", &*(F->getEntryBlock().getFirstInsertionPt()));
        const DataLayout &DL = AITmp->getParent()->getParent()->getParent()->getDataLayout();
        LLVMContext& C = AITmp->getContext();
        // Set lifetime start information
        llvm::IRBuilder<> BuilderStart(AITmp->getNextNode());
        BuilderStart.CreateLifetimeStart(AITmp, ConstantInt::get(Type::getInt64Ty(C), DL.getTypeAllocSize(AITmp->getAllocatedType())));
#if 0
        errs() << IFC.MergePoint->getName() << "\n";
        IfCond->print(errs()); errs() << "\n";
        if (IFC.IfTrue) errs() << IFC.IfTrue->getName() << "\n";
        if (IFC.IfFalse) errs() << IFC.IfFalse->getName() << "\n";
#endif

        int branchBGID = getBGID(*IFC.Branch);
        int branchIBID = getIBID(*IFC.Branch);

        // Call wrappers
        std::vector<Value*> CondFArgs;
        CondFArgs.push_back(AITmp);
        // add the required IDs if CFL_DEBUG==2
        if (CondF->arg_size() > CondFArgs.size()) {
            CondFArgs.push_back(makeConstI32(C, branchBGID));
            CondFArgs.push_back(makeConstI32(C, branchIBID));
        }
        CallInst::Create(CondF, CondFArgs, "", IfHeader->getTerminator());

        if (IFC.IfTrue != IFC.MergePoint) {
            std::vector<Value*> IfTrueFArgs;
            IfTrueFArgs.push_back(AITmp);
            IfTrueFArgs.push_back(IfCond);
            CallInst::Create(IfTrueF, IfTrueFArgs, "", &*(IFC.IfTrue->getFirstInsertionPt()));
        }

        if (IFC.IfFalse != IFC.MergePoint) {
            std::vector<Value*> IfFalseFArgs;
            IfFalseFArgs.push_back(AITmp);
            IfFalseFArgs.push_back(IfCond);
            CallInst::Create(IfFalseF, IfFalseFArgs, "", &*(IFC.IfFalse->getFirstInsertionPt()));
        }

        std::vector<Value*> MergePointFArgs;
        MergePointFArgs.push_back(AITmp);
        CallInst* MergeCall = CallInst::Create(MergePointF, MergePointFArgs, "", &*(IFC.MergePoint->getFirstInsertionPt()));

        // Create lifetime end at the merge point
        llvm::IRBuilder<> BuilderEnd(MergeCall->getNextNode());
        BuilderEnd.CreateLifetimeEnd(AITmp, ConstantInt::get(Type::getInt64Ty(C), DL.getTypeAllocSize(AITmp->getAllocatedType())));

        // Turn any PHIs into Selects in MergePoint block
        while (PHINode *PN = dyn_cast<PHINode>(IFC.MergePoint->begin())) {
            assert(PN->getNumIncomingValues() == 2);
            Value *TrueVal = PN->getIncomingValue(PN->getIncomingBlock(0) == IFC.IfTruePred ? 0 : 1);
            Value *FalseVal = PN->getIncomingValue(PN->getIncomingBlock(0) == IFC.IfTruePred ? 1 : 0);
            Value *Sel = SelectInst::Create(IfCond, TrueVal, FalseVal, "", &*(IFC.MergePoint->getFirstInsertionPt()));
            PN->replaceAllUsesWith(Sel);
            Sel->takeName(PN);
            PN->eraseFromParent();
        }

        // Move IfFalse block (might be MergePoint) under IfTrue block
        BranchInst *BI = dyn_cast<BranchInst>(IFC.IfTruePred->getTerminator());
        for (unsigned i=0;i<BI->getNumSuccessors();i++) {
            if (BI->getSuccessor(i) == IFC.MergePoint) {
                // In the case where IfTruePred == IfHeader, the IFC.Branch
                // will now point twice to IFFalse, but it's ok
                BI->setSuccessor(i, IFC.IfFalse);
                BI = NULL;
                break;
            }
        }
        assert(!BI);

        // Remove conditional branch if IfTruePred != IfHeader
        // Otherwise we already fixed the jumps while connecting IfTrue to IFFalse
        if (IFC.IfTruePred != IfHeader) {
            BranchInst::Create(IFC.IfTrue, IFC.Branch);
            IFC.Branch->eraseFromParent();
        }
    }

    BasicBlock *getImmediatePostdominator(PostDominatorTree *PDT, BasicBlock* BB) {
        auto SuccIt = ++df_begin(BB);
        auto SuccEnd = df_end(BB);
        while (SuccIt != SuccEnd) {
            BasicBlock *SuccBB = *SuccIt;
            if (PDT->dominates(SuccBB, BB)) {
                return SuccBB;
            }
            SuccIt++;
        }
        return NULL;
    }

    IfCondition *getIfCondition(DominatorTree *DT, PostDominatorTree *PDT, BranchInst *BI) {
        static IfCondition IFC;

        // Only conditional branches
        if (!BI->isConditional() || BI->getNumSuccessors()!=2)
            return NULL;

        // Look for i-postdominator with 2 predecessors, dominated by branch
        BasicBlock *BB = BI->getParent();
        BasicBlock *IPD = getImmediatePostdominator(PDT, BB);
        if (!IPD || !IPD->hasNPredecessors(2) || !DT->dominates(BB, IPD))
            return NULL;

        // Found candidate merge point, ensure it isn't someone else's point
        auto SuccIt = ++df_begin(BB);
        auto SuccEnd = df_end(BB);
        while (SuccIt != SuccEnd) {
            BasicBlock *SuccBB = *SuccIt;
            if (SuccBB == IPD)
                break;
            BranchInst *BI = dyn_cast<BranchInst>(SuccBB->getTerminator());
            if (BI && BI->isConditional() && DT->dominates(SuccBB, IPD))
                return NULL;
            SuccIt++;
        }

        // Found the merge point block, fill info and return
        IFC.Branch = BI;
        IFC.MergePoint = IPD;
        IFC.IfTrue = BI->getSuccessor(0);
        IFC.IfFalse = BI->getSuccessor(1);
        IFC.IfTruePred = NULL;
        for (BasicBlock *Pred : predecessors(IFC.MergePoint)) {
            if (!DT->dominates(IFC.IfTrue, Pred))
                continue;
            assert(!IFC.IfTruePred);
            IFC.IfTruePred = Pred;
        }
        // if no predecessor of the MergePoint is dominated by the IFTrue Block
        // it means IFTrue == MergePoint, so we set IFTruePred = BranchBB
        if(!IFC.IfTruePred) {
            IFC.IfTruePred = IFC.Branch->getParent();
        }
        return &IFC;
    }

    void cfl(Function *F) {
        cflPassLog("CFLing " << F->getName());
        DominatorTree *DT = &getAnalysis<DominatorTreeWrapperPass>(*F).getDomTree();
        PostDominatorTree *PDT = &getAnalysis<PostDominatorTreeWrapperPass>(*F).getPostDomTree();
        F->addFnAttr("null-pointer-is-valid", "true");

        // Wrap loads, stores, memory intrinsics, and external calls
        for (auto &BB : *F)
        for (auto &I : BB) {
            // If we run after DFL we must not wrap memory accesses since the only
            // mem accesses that have been left unprotected are the one DFL needs
            if (MemProtect == true) {
                if (LoadInst *LI = dyn_cast<LoadInst>(&I)) {
                    wrapLoad(LI);
                    continue;
                }
                if (StoreInst *SI = dyn_cast<StoreInst>(&I)) {
                    wrapStore(SI);
                    continue;
                }
            }
            CallSite CS(&I);
            if (!CS.getInstruction() || CS.isInlineAsm())
                continue; // not a call
            Function *Callee = dyn_cast<Function>(CS.getCalledValue()->stripPointerCasts());
            if (!Callee)
                continue; // not a direct call
            if (Callee->isIntrinsic())
                wrapIntrinsicCall(CS, Callee);
            else if (Callee->isDeclaration())
                wrapExtCall(CS, Callee);
        }

        if( BranchProtect == false) return;

        // Loop over CFG to first find and then wrap conditions
        std::vector<IfCondition> ifConditions;
        for (auto &BB : *F) {
            BranchInst *BI = dyn_cast<BranchInst>(BB.getTerminator());
            if (!BI)
                continue;
            if(BI->isConditional()) ++totalBranches;
            IfCondition *IFC = getIfCondition(DT, PDT, BI);
            if (!IFC)
                continue;
            ++totalIFCs;
            if (SimpleBranches) {
                // Only simple branches LLVM's GetIfCondition can handle
                BasicBlock *IfTrue, *IfFalse;
                if (!GetIfCondition(IFC->MergePoint, IfTrue, IfFalse))
                    continue;
            }
            ifConditions.push_back(*IFC);
        }
        for (auto &IFC : ifConditions) {
            if (isInstructionUninteresting(*IFC.Branch)) {
                wrapUninterestingCondition(IFC);
                continue;
            }
            if (CFLRelaxed && (getInstructionTaint(*IFC.Branch) == false)) {
                // While it is necessary to set the taken variable in dummy/non-dummy
                // mode to properly wrap the memory accesses,
                // we can avoid linearizing the branch if it is not necessary
                // since this branch may be an inner branch of a tainted one, and it
                // may not leak anything
                continue;
            }
            ++linearizedBranches;
            wrapCondition(IFC);
        }
    }

    virtual bool runOnModule(Module &M) {
        cflPassLog("Running...");

        std::vector<Regex*> FunctionRegexes;
        if (Functions.empty())
            Functions.push_back("main");
        passListRegexInit(FunctionRegexes, Functions);

        /* Iterate all functions in the module to cfl */
        std::set<Function*> cflFunctionSet;
        for (auto &F : M.getFunctionList()) {
            if (F.isDeclaration())
                continue;
            ++totalFuncs;
            const std::string &FName = F.getName();
            if (!passListRegexMatch(FunctionRegexes, FName))
                continue;
            if (F.getSection().equals("dfl_code") || F.getSection().equals("cfl_code") 
                || F.getSection().equals("cgc_code") || F.getSection().equals("icp_code"))
                continue;
            cflFunctionSet.insert(&F);
        }
        while (!cflFunctionSet.empty()) {
            ++CFLedFuncs;
            Function *F = *cflFunctionSet.begin();
            cflFunctionSet.erase(cflFunctionSet.begin());
            // Linearize the control flow of the whole function
            cfl(F);
        }
        oprint("--------[ CFL STATS ]--------");
        oprint("[+] Total Functions    : " << totalFuncs);
        oprint("[+] CFLed Functions    : " << CFLedFuncs);
        oprint("[+] Total Branches     : " << totalBranches);
        oprint("[+] Total IFCs         : " << totalIFCs);
        oprint("[+] Linearized Branches: " << linearizedBranches);
        return true;
    }

    void getAnalysisUsage(AnalysisUsage &AU) const {
        AU.addRequired<DominatorTreeWrapperPass>();
        AU.addRequired<PostDominatorTreeWrapperPass>();
    }

  };

}

char CFLPass::ID = 0;
RegisterPass<CFLPass> MP("cfl", "CFL Pass");
