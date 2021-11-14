
#include <pass.h>

#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/CFG.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Analysis/LoopPass.h"
#include "llvm/Analysis/LoopInfo.h"

using namespace llvm;

#define DEBUG_TYPE "check-cfl"
#define cflPassLog(M) LLVM_DEBUG(dbgs() << "CheckCFLPass: " << M << "\n")
#define oprint(s) outs() << s << "\n"

static cl::list<std::string>
Functions("check-cfl-funcs",
    cl::desc("Specify all the comma-separated function regexes to check-cfl"),
    cl::ZeroOrMore, cl::CommaSeparated, cl::NotHidden);

static cl::opt<bool>
NoBranches("check-cfl-no-branches",
    cl::desc("Check there are no branches apart from loops"),
    cl::init(true), cl::NotHidden);

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

  class CheckCFLPass : public ModulePass {

  public:
    static char ID;
    CheckCFLPass() : ModulePass(ID) {}

    int loopsNum = 0;
    int rockyVars = 0;
    int IFCNum = 0;

    void setInstructionTaint(Instruction *I, bool taint) {
        LLVMContext& C = I->getContext();
        MDNode* N = MDNode::get(C, ConstantAsMetadata::get(ConstantInt::get(C, APInt(sizeof(imd_t)*8, taint, true))));
        I->setMetadata("t", N);
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

    Loop *getNaturalLoop(DominatorTree *DT, PostDominatorTree *PDT, LoopInfo* LI, BranchInst *BI) {
        // Only conditional branches
        if (!BI->isConditional() || BI->getNumSuccessors()!=2) {
            return NULL;
        }

        BasicBlock *BB = BI->getParent();
        Loop* L = LI->getLoopFor(BB);

        // get only the loop if the branch is the exiting block for
        if (!L || L->getExitingBlock() != BB) {
            return NULL;
        }

        // assert we have a simple loop
        assert(L->getLoopDepth() == 1);
        return L;
    }

    void check_cfl(Function *F) {
        // oprint("Checking " << F->getName());
        DominatorTree *DT = &getAnalysis<DominatorTreeWrapperPass>(*F).getDomTree();
        PostDominatorTree *PDT = &getAnalysis<PostDominatorTreeWrapperPass>(*F).getPostDomTree();
        LoopInfo *LI = &getAnalysis<LoopInfoWrapperPass>(*F).getLoopInfo();

        // Loop over CFG to first find and then wrap conditions
        std::vector<IfCondition> ifConditions;
        std::vector<Loop*> loops;
        size_t conditionals = 0;
        for (auto &BB : *F) {
            BranchInst *BI = dyn_cast<BranchInst>(BB.getTerminator());
            if (!BI)
                continue;
            if (BI->isConditional())
                ++conditionals;
            IfCondition *IFC = getIfCondition(DT, PDT, BI);
            Loop *L = getNaturalLoop(DT, PDT, LI, BI);
            if (!IFC && !L)
                continue;
            if(IFC) {
                assert(!L);
                ifConditions.push_back(*IFC);
                IFCNum++;
                // check properly formed IFCondition
                assert(IFC->IfTruePred);
                assert(IFC->IfTrue);
                assert(IFC->IfFalse);
                assert(IFC->MergePoint);
                assert(IFC->Branch);

                assert(DT->dominates(IFC->Branch->getParent(), IFC->IfTrue));
                assert(DT->dominates(IFC->Branch->getParent(), IFC->IfFalse));
                assert(DT->dominates(IFC->Branch->getParent(), IFC->MergePoint));

                assert(PDT->dominates(IFC->MergePoint, IFC->IfTrue));
                assert(PDT->dominates(IFC->MergePoint, IFC->IfFalse));
                assert(PDT->dominates(IFC->MergePoint, IFC->Branch->getParent()));

                // check that the branch is in normal form
                // N.B.: this may fail for rewired BB due to noreturn calls
                assert(IFC->IfTrue != IFC->MergePoint);
            } else {
                assert(!IFC);

                // check properly formed loop
                BasicBlock* PreheaderBlock = L->getLoopPreheader();
                BasicBlock* HeaderBlock = L->getHeader();
                BasicBlock* ExitingBlock   = L->getExitingBlock();
                BranchInst* ExitingBranch  = dyn_cast<BranchInst>(ExitingBlock->getTerminator());
                BasicBlock* ExitBlock      = L->getExitBlock();

                Value *LoopCond = ExitingBranch->getCondition();
                assert(PreheaderBlock && ExitingBlock && ExitBlock && HeaderBlock);
                assert(LoopCond);
                assert(ExitBlock == ExitingBranch->getSuccessor(0));
                assert(HeaderBlock == ExitingBranch->getSuccessor(1));
                assert(PreheaderBlock->getUniqueSuccessor() == HeaderBlock);
                assert(PDT->dominates(ExitBlock, PreheaderBlock));
                assert(PDT->dominates(ExitBlock, ExitingBlock));
                // oprint(*PreheaderBlock);
                // oprint(*L->getHeader());
                // oprint("Loop: " << *L);

                std::set<BasicBlock*> allBB(L->getBlocks().begin(), L->getBlocks().end());
                bool seen = false;
                // assert no value gets used outside the loop
                for(BasicBlock *BB: L->getBlocks()) {
                    for (Instruction &I: *BB) {
                        for(User* user: I.users()) {
                            Instruction *II = dyn_cast<Instruction>(user);
                            assert(II);

                            // check that the value gets used only inside the loop!
                            if (allBB.find(II->getParent()) == allBB.end()) {
                                // oprint(*F);
                                oprint("Value: " << I);
                                oprint("User : " << *II);
                                // assert(false);
                                seen = true;
                            }
                        }
                    }
                }

                loops.push_back(L);
                ++loopsNum;
                if(seen)
                    ++rockyVars;
            }
        }

        // check we only have at most a branch per function
        assert(conditionals <= 1);

        if(NoBranches) {
            // check that every branch that is present is a loop
            assert(conditionals == loops.size());
        }

        // check that every branches get recognized
        assert(conditionals == (loops.size() + ifConditions.size()));
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
            const std::string &FName = F.getName();
            if (!passListRegexMatch(FunctionRegexes, FName))
                continue;
            if (F.getSection().equals("dfl_code") || F.getSection().equals("cfl_code") 
                || F.getSection().equals("cgc_code") || F.getSection().equals("icp_code"))
                continue;
            cflFunctionSet.insert(&F);
        }
        while (!cflFunctionSet.empty()) {
            Function *F = *cflFunctionSet.begin();
            cflFunctionSet.erase(cflFunctionSet.begin());
            // Check the control flow of the whole function
            check_cfl(F);
        }
        oprint("IFCs: " << IFCNum);
        oprint("Loops: " << loopsNum);
        oprint("rockyVars: " << rockyVars);
        return true;
    }

    void getAnalysisUsage(AnalysisUsage &AU) const {
        AU.addRequired<DominatorTreeWrapperPass>();
        AU.addRequired<PostDominatorTreeWrapperPass>();
        AU.addRequired<LoopInfoWrapperPass>();
    }

  };

}

char CheckCFLPass::ID = 0;
RegisterPass<CheckCFLPass> MP("check-cfl", "CheckCFL Pass");
