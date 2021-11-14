
#include <pass.h>

#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IRBuilder.h"

using namespace llvm;

#define DEBUG_TYPE "fixScalarizer"
#define fixScalarizerPassLog(M) LLVM_DEBUG(dbgs() << "FixScalarizerPass: " << M << "\n")

typedef long imd_t;

namespace {

  class FixScalarizerPass : public ModulePass {

  public:
    static char ID;
    FixScalarizerPass() : ModulePass(ID) {}

    void fix(PHINode* PN) {
        // Move the phi node at the beginning of the function, where it should be
        BasicBlock *BB = PN->getParent();
        PN->removeFromParent();
        PN->insertBefore(&BB->front());
    }

    // This pass has to fix the non grouped phi nodes that the Scalarizer pass 
    // somethimes creates in llvm IR
    // Why should we fix the pass when we can patch the damages?
    virtual bool runOnModule(Module &M) {
        fixScalarizerPassLog("Running...");

        std::vector<PHINode*> toFix;
        for (Function &F : M.getFunctionList()) {
          for (BasicBlock &BB : F) {
                for (Instruction &I : BB) {
                    // copy the check that the verify IR pass would do
                    if(PHINode *PN = dyn_cast<PHINode>(&I)) {
                        // Ensure that the PHI nodes are all grouped together at the top of the block.
                        // This can be tested by checking whether the instruction before this is
                        // either nonexistent (because this is begin()) or is a PHI node.  If not,
                        // then there is some other instruction before a PHI.
                        if (!(PN == &PN->getParent()->front() || isa<PHINode>(--BasicBlock::iterator(PN))))
                            toFix.push_back(PN);
                    }
                }
            }
        }
        for (PHINode *I : toFix) {
            // I->dump();
            fix(I);
        }

        // dft_pass_init->dump();
        return true;
    }
  };

}

char FixScalarizerPass::ID = 0;
RegisterPass<FixScalarizerPass> MP("fix-scalarizer", "Fix Scalarizer Pass");
