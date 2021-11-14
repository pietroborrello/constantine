
#include <pass.h>

using namespace llvm;

#define DEBUG_TYPE "dummy"
#define dummyPassLog(M) LLVM_DEBUG(dbgs() << "DummyPass: " << M << "\n")

namespace {

  class DummyPass : public ModulePass {

  public:
    static char ID;
    DummyPass() : ModulePass(ID) {}

    virtual bool runOnModule(Module &M) {
      dummyPassLog("Running...");

      return false;
    }
  };

}

char DummyPass::ID = 0;
RegisterPass<DummyPass> MP("dummy", "Dummy Pass");

