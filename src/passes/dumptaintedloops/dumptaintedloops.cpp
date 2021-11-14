
#include <pass.h>
#include <iostream>
#include <fstream>
#include <iomanip>

#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Analysis/LoopPass.h"

using namespace llvm;

#define DEBUG_TYPE "dumptaintedloops"
#define dumptaintedloopsPassLog(M) LLVM_DEBUG(dbgs() << "DumpTaintedLoopsPass: " << M << "\n")

typedef long imd_t;

static cl::opt<std::string>
DumpFilename("dump-file",
    cl::desc("The file where to dump loops"),
    cl::init("loops.log"), cl::NotHidden);

namespace {

  class DumpTaintedLoopsPass : public LoopPass {

    std::ofstream dumpfile;
  public:
    static char ID;
    DumpTaintedLoopsPass() : LoopPass(ID) {
        dumpfile.open(DumpFilename);
    }

    ~DumpTaintedLoopsPass() {
        dumpfile.close();
    }

    void dumpIDs(llvm::Instruction& I, llvm::BasicBlock &BB, int taint){
        MDNode* N;
        Constant *val;
        N = BB.getTerminator()->getMetadata("b-gid");
        val = dyn_cast<ConstantAsMetadata>(N->getOperand(0))->getValue();
        assert(val);
        int b_gid = cast<ConstantInt>(val)->getSExtValue();
        N = I.getMetadata("i-bid");
        val = dyn_cast<ConstantAsMetadata>(N->getOperand(0))->getValue();
        assert(val);
        int i_bid = cast<ConstantInt>(val)->getSExtValue();
        dumpfile << (taint == 1? "  loop:T00000:" : "  loop:0t0000:") << std::setfill('0') 
                 << std::setw(8) << b_gid << ":" << std::setfill('0') << std::setw(4) 
                 << i_bid << std::endl;
    }

    bool runOnLoop(Loop *L, LPPassManager &LPM) override {
        if (skipLoop(L))
        return false;

        llvm::SmallVector<llvm::BasicBlock*, 16> ExitingBlocks;
        MDNode* N;
        Constant *val;
        L->getExitingBlocks(ExitingBlocks);

        for(llvm::BasicBlock* BB: ExitingBlocks) {
            llvm::BranchInst *EndBranch = dyn_cast<BranchInst>(BB->getTerminator());
            N = EndBranch->getMetadata("t");
            if (N == NULL) continue;
            val = dyn_cast<ConstantAsMetadata>(N->getOperand(0))->getValue();
            assert(val);
            int taint = cast<ConstantInt>(val)->getSExtValue();
            dumpIDs(*EndBranch, *BB, taint);
        }
        
        return false;
   }
 
   void getAnalysisUsage(AnalysisUsage &AU) const override {
     AU.setPreservesCFG();
   }
  };

}

char DumpTaintedLoopsPass::ID = 0;
RegisterPass<DumpTaintedLoopsPass> MP("dumptaintedloops", "Dump Tainted Loops Pass");
