#include <pass.h>
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/CFG.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionExpressions.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "SVF-FE/GEPTypeBridgeIterator.h" // include bridge_gep_iterator
#include "llvm/IR/IRBuilder.h"

using namespace llvm;
#define oprint(s) (outs() << s << "\n")
typedef long imd_t;

namespace {
  // Dump tainted instruction statistics, assumes structurized CFG
  class TaintStatsPass : public FunctionPass {

    unsigned long taintedBranches = 0;
    unsigned long taintedLoops = 0;
    unsigned long taintedReads = 0;
    unsigned long taintedWrites = 0;
    unsigned long totBranches = 0;
    unsigned long totLoops = 0;
    unsigned long totAccesses = 0;
    
  public:
    static char ID; // Pass identification, replacement for typeid
    TaintStatsPass() : FunctionPass(ID) {
    }

    ~TaintStatsPass() {
        // We should not be allowed to keep info between runOnLoop invocations,
        // but we like living dangerously
        oprint("--------[ TAINT STATS ]--------");
        oprint("[+] Tot Branches:     " << totBranches);
        oprint("[+] Tot Loops:        " << totLoops);
        oprint("[+] Tot Accesses:     " << totAccesses);
        oprint("[+] Tainted Branches: " << taintedBranches);
        oprint("[+] Tainted Loops:    " << taintedLoops);
        oprint("[+] Tainted Reads:    " << taintedReads);
        oprint("[+] Tainted Writes:   " << taintedWrites);
    }

    bool getInstructionTaint(Instruction &I) {
        MDNode* N;
        Constant *val;
        N = I.getMetadata("t");
        if (N == NULL) return false;
        val = dyn_cast<ConstantAsMetadata>(N->getOperand(0))->getValue();
        assert(val);
        int taint = cast<ConstantInt>(val)->getSExtValue();
        return taint;
    }

    bool runOnFunction(Function &F) override {
        LoopInfo &LI = getAnalysis<LoopInfoWrapperPass>().getLoopInfo();
        ScalarEvolution &SE = getAnalysis<ScalarEvolutionWrapperPass>().getSE();

        std::set<Instruction *> loopBranches;

        for(Loop* L : LI.getLoopsInPreorder()) {
            BasicBlock* ExitingBlock   = L->getExitingBlock();
            BranchInst* ExitingBranch  = dyn_cast<BranchInst>(ExitingBlock->getTerminator());
            assert(ExitingBlock && ExitingBranch);

            loopBranches.insert(ExitingBranch);
            if (getInstructionTaint(*ExitingBranch)) {
                ++taintedLoops;
            }
            ++totLoops;
        }

        for (auto &BB : F)
        for (auto &I : BB) {

            if (LoadInst *LI = dyn_cast<LoadInst>(&I)) {
                if (getInstructionTaint(I)) ++taintedReads;
                ++totAccesses;
                continue;
            }
            if (StoreInst *SI = dyn_cast<StoreInst>(&I)) {
                if (getInstructionTaint(I)) ++taintedWrites;
                ++totAccesses;
                continue;
            }

            if (BranchInst *BI = dyn_cast<BranchInst>(&I)) {
                // only if not a loop branch
                if (loopBranches.find(BI) == loopBranches.end()) if (getInstructionTaint(I)) ++taintedBranches;
                ++totBranches;
                continue;
            }
        
        }
        return true;
    }

    void getAnalysisUsage(AnalysisUsage &AU) const override {
        AU.addRequired<ScalarEvolutionWrapperPass>();
        AU.addRequired<LoopInfoWrapperPass>();
        AU.addRequired<TargetLibraryInfoWrapperPass>();
    }
  };
}

char TaintStatsPass::ID = 0;
RegisterPass<TaintStatsPass> DBGPP("taint-stats", "Taint Stats pass");
