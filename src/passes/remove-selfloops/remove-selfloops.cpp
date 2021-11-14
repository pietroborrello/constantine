
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

#define DEBUG_TYPE "remove-selfloops"
#define removeSelfloopsPassLog(M) LLVM_DEBUG(dbgs() << "removeSelfloopsPass: " << M << "\n")

#define oprint(s) outs() << s << "\n"
#define qprint(s) std::cout << s << std::endl

#define STACK_PROM_DEBUG 0

static cl::list<std::string>
Functions("remove-selfloops-funcs",
    cl::desc("Specify all the comma-separated function regexes for which to remove selfloops statements"),
    cl::ZeroOrMore, cl::CommaSeparated, cl::NotHidden);

typedef long imd_t;

// This pass aims to identify and remove basic blocks which naively loop to theirselves
// This is done changing the unconditional branch to the same bb, to a conditional one
// with a fixed condition:
// body:
//     br label %body
// 
// to =>
// body:
//     br i1 true, label %body, label %other
// with `other` such that:
//     1) `other` does not dominates `body`
//     2) the block jumping to `other` is the nearest predecessor of `body` not postdominated by it 
// This will remove simple self loops creating merge points 
// Additionally we add a loop preheader and exit nodes to ease passes
// Please Note: Running an optimization pass after, will remove the fake conditional branch
namespace {

  class RemoveSelfloopsPass : public ModulePass {

  public:
    static char ID;
    RemoveSelfloopsPass() : ModulePass(ID) {
    }

    void removeSelfloops(Function *F) {
        DominatorTree *DT = &getAnalysis<DominatorTreeWrapperPass>(*F).getDomTree();
        PostDominatorTree *PDT = &getAnalysis<PostDominatorTreeWrapperPass>(*F).getPostDomTree();

        std::set<BasicBlock*> selfLoops;
        for (auto &BB : *F) {
            // only identify naive self loops, that branch to teh block itself
            if (BranchInst *BI = dyn_cast<BranchInst>(BB.getTerminator())) {
                if (BI->isUnconditional() && BI->getSuccessor(0) == &BB) {
                    selfLoops.insert(&BB);
                }
            }
        }

        for (auto *BB : selfLoops) {
            oprint("self loop in " << F->getName().str());
            // oprint(*BB);

            BranchInst *BI = dyn_cast<BranchInst>(BB->getTerminator());

            // for each selfloop, substitute it with a conditional jump to
            // itself (always true) and to the block b (alkways false) such that:
            //   1) b does not dominates UI
            //   2) the block jumping to b is the nearest predecessor of UI not postdominated by it
            
            // search for the nearest (?) predecessor of BB not postominated by it
            auto PredIt = ++idf_begin(BB);
            auto PredEnd = idf_end(BB);
            BasicBlock *PredBB = nullptr;
            while (PredIt != PredEnd) {
                BasicBlock *currBB = *PredIt;
                if (!PDT->dominates(BB, currBB)) {
                    PredBB = currBB;
                    break;
                }
                PredIt++;
            }
            assert(PredBB && "Did not find a predecessor which is not postdominated by the selfloop");
            // oprint("    " << PredBB->getName().str());

            // Find the successor of PredBB that does not dominates BB
            BasicBlock *targetBB = nullptr;
            for (BasicBlock * SuccBB : successors(PredBB)) {
                if (!DT->dominates(SuccBB, BB)) {
                    targetBB = SuccBB;
                    break;
                }
            }
            assert(targetBB && "Did not find a successor of PredBB which is not dominated by the self loop");
            // oprint("    " << targetBB->getName().str());

            // insert a loop header (may be already present)
            BasicBlock *NewBB = SplitBlock(BB, BB->getTerminator());
            // Now BB is the loop header
            // oprint("New BB: " << *NewBB);

            // create an exiting node 
            BasicBlock *ExitBB = BasicBlock::Create(F->getContext(), "fake_exit", F, targetBB);
            BranchInst::Create(targetBB, ExitBB);
            // oprint("Exit Block: " << *ExitBB);

            // insert the conditional jump to the ExitBB instead of self loop
            static ConstantInt *BoolTrue = ConstantInt::getTrue(F->getContext());
            BranchInst *NewBI = BranchInst::Create(BB, ExitBB, BoolTrue);
            ReplaceInstWithInst(BI, NewBI);
            assert(NewBI->getParent() == NewBB);

            // oprint("Updated Block: " << *NewBB);

            // Update all phi nodes in targetBB adding the ExitBB case
            for (PHINode &Phi: targetBB->phis()) {
                Value *Undef = UndefValue::get(Phi.getType());
                Phi.addIncoming(Undef, ExitBB);
            }

            // update dominator info
            DT->recalculate(*F);
            PDT->recalculate(*F);
        }
    }

    virtual bool runOnModule(Module &M) override {
        removeSelfloopsPassLog("Running...");
        std::vector<Regex*> FunctionRegexes;
        if (Functions.empty())
            Functions.push_back("main");
        passListRegexInit(FunctionRegexes, Functions);

        /* Iterate all functions in the module to collect selfloops*/
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
            removeSelfloops(F);
        }
        return true;
    }
 
   void getAnalysisUsage(AnalysisUsage &AU) const override {
        AU.addRequired<DominatorTreeWrapperPass>();
        AU.addRequired<PostDominatorTreeWrapperPass>();
    }
  };

}

char RemoveSelfloopsPass::ID = 0;
RegisterPass<RemoveSelfloopsPass> MP("remove-selfloops", "Remove Selfloops Pass");
