
#include <pass.h>

#include "llvm/IR/Module.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/CFG.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Transforms/Utils/CodeExtractor.h"
#include "llvm/Analysis/LoopPass.h"
#include "llvm/Analysis/LoopInfo.h"
#include <set>
using namespace llvm;

#define DEBUG_TYPE "remove-unreachable"
#define removeUnreachablePassLog(M) LLVM_DEBUG(dbgs() << "removeUnreachablePass: " << M << "\n")

#define oprint(s) outs() << s << "\n"
#define qprint(s) std::cout << s << std::endl

#define STACK_PROM_DEBUG 0

static cl::list<std::string>
Functions("remove-unreachable-funcs",
    cl::desc("Specify all the comma-separated function regexes for which to remove unreachable statements"),
    cl::ZeroOrMore, cl::CommaSeparated, cl::NotHidden);

typedef long imd_t;

namespace {

  class RemoveUnreachablePass : public ModulePass {

  public:
    static char ID;
    RemoveUnreachablePass() : ModulePass(ID) {
    }

    bool removeNoReturns(BasicBlock *BB) {
        bool removed = false;
        // search for all the calls to noreturn functions and remove the attribute recursively
        for (auto &I : *BB) {
            CallSite CS(&I);
            if (!CS.getInstruction() || CS.isInlineAsm())
                continue; // not a call
            Function *Callee = dyn_cast<Function>(CS.getCalledValue()->stripPointerCasts());
            if (!Callee)
                continue; // not a direct call
            
            // remove the attribute from the callsite
            if(CS.hasFnAttr(Attribute::NoReturn)) {
                CallInst *CI = dyn_cast<CallInst>(&I);
                oprint("removing noreturn from call: " << *CI);
                CI->removeAttribute(AttributeList::FunctionIndex, Attribute::NoReturn);
                removed = true;
            }

            // remove the attribute from the function
            // previous calls to this functon may have already removed it
            if (Callee->hasFnAttribute(Attribute::NoReturn)) {
                oprint("removing noreturn from func: " << Callee->getName().str());
                removed = true;
                // remove the noreturn attribute
                Callee->removeFnAttr(Attribute::NoReturn);

                // if is a declaration we are done with it
                if (Callee->isDeclaration())
                    continue;

                // recursively remove all the noreturn attributes of called functions
                for (auto &recBB : *Callee) {
                    removeNoReturns(&recBB);
                }
            }
        }
        return removed;
    }

    void removeUnreachable(Function *F) {
        DominatorTree *DT = &getAnalysis<DominatorTreeWrapperPass>(*F).getDomTree();
        PostDominatorTree *PDT = &getAnalysis<PostDominatorTreeWrapperPass>(*F).getPostDomTree();

        std::set<UnreachableInst*> unreachableInsts;
        for (auto &BB : *F) {
            // collect all unreachable instructions
            if (UnreachableInst *UI = dyn_cast<UnreachableInst>(BB.getTerminator())) {
                oprint("unreachable instruction in " << F->getName().str());
                unreachableInsts.insert(UI);
            }
        }

        for (auto *UI : unreachableInsts) {
            BasicBlock *BBUI = UI->getParent();

            // avoid dealing with spurious BBs
            int NPred = 0;
            for (BasicBlock * _pred : predecessors(BBUI)) {
                ++NPred;
            }

            // remove the noreturn attributes from the functions called in the BB
            bool removed = removeNoReturns(BBUI);

            // if the BB has no predecessor (may be the entry point), continue
            if (NPred == 0) continue;
            
            // check that the basic block actually contained a call to a noreturn
            // function, otherwise it would be a bit suspect, and it is better to
            // check this manually sorry
            assert(removed);

            // for each unreachable instruction, substitute it with a jump to the
            // block b such that:
            // 1) b does not dominates UI
            // 2) the block jumping to b is the nearest predecessor of UI not postdominated by it
            
            // oprint("unreachable instruction: " << BBUI->getName().str() <<" - " << *UI);

            // search for the nearest (?) predecessor of BBUI not postominated by it
            auto PredIt = ++idf_begin(BBUI);
            auto PredEnd = idf_end(BBUI);
            BasicBlock *PredUIBB = nullptr;
            while (PredIt != PredEnd) {
                BasicBlock *PredBB = *PredIt;
                if (!PDT->dominates(BBUI, PredBB)) {
                    PredUIBB = PredBB;
                    break;
                }
                PredIt++;
            }
            assert(PredUIBB && "Did not find a predecessor which is not postdominated by the unreachable instr");
            // oprint("    " << PredUIBB->getName().str());

            // Find the successor of PredUIBB that does not dominates BBUI
            BasicBlock *targetBB = nullptr;
            for (BasicBlock * SuccBB : successors(PredUIBB)) {
                if (!DT->dominates(SuccBB, BBUI)) {
                    targetBB = SuccBB;
                    break;
                }
            }
            assert(targetBB && "Did not find a successor of PredUIBB which is not dominated by the unreachable instr");
            // oprint("    " << targetBB->getName().str());

            // insert a jump to the targetBB instead of unreachable statement
            BranchInst::Create(targetBB, UI);
            UI->eraseFromParent();

            // Update all phi nodes in targetBB adding the BBUI case
            for (PHINode &Phi: targetBB->phis()) {
                Value *Undef = UndefValue::get(Phi.getType());
                Phi.addIncoming(Undef, BBUI);
            }

            // update dominator info
            DT->recalculate(*F);
            PDT->recalculate(*F);
        }
    }

    virtual bool runOnModule(Module &M) override {
        removeUnreachablePassLog("Running...");
        std::vector<Regex*> FunctionRegexes;
        if (Functions.empty())
            Functions.push_back("main");
        passListRegexInit(FunctionRegexes, Functions);

        /* Iterate all functions in the module to collect unreachables */
        std::set<Function*> functionSet;
        for (auto &F : M.getFunctionList()) {
            if (F.isDeclaration())
                continue;
            const std::string &FName = F.getName();
            if (!passListRegexMatch(FunctionRegexes, FName))
                continue;
            functionSet.insert(&F);
        }
        while (!functionSet.empty()) {
            Function *F = *functionSet.begin();
            functionSet.erase(functionSet.begin());
            removeUnreachable(F);
        }
        return true;
    }
 
   void getAnalysisUsage(AnalysisUsage &AU) const override {
        AU.addRequired<DominatorTreeWrapperPass>();
        AU.addRequired<PostDominatorTreeWrapperPass>();
    }
  };

}

char RemoveUnreachablePass::ID = 0;
RegisterPass<RemoveUnreachablePass> MP("remove-unreachable", "Remove Unreachable Pass");
