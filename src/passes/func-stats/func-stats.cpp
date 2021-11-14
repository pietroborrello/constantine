
#include <pass.h>

using namespace llvm;

#define DEBUG_TYPE "FuncStats"
#define FuncStatsPassLog(M) LLVM_DEBUG(dbgs() << "FuncStatsPass: " << M << "\n")
#define oprint(s) outs() << s << "\n"

namespace {

  class FuncStatsPass : public ModulePass {

  public:
    static char ID;
    FuncStatsPass() : ModulePass(ID) {}

    virtual bool runOnModule(Module &M) {
      int num_funcs = 0;
      int total_BB = 0;
      for (auto &F : M.getFunctionList()) {
        if (F.isDeclaration())
          continue;
        ++num_funcs;
        for(auto &BB: F) {
          ++total_BB;
        }
      }

      oprint("Num functions: " << num_funcs);
      oprint("Num BBs      : " << total_BB);

      return false;
    }
  };

}

char FuncStatsPass::ID = 0;
RegisterPass<FuncStatsPass> MP("func-stats", "FuncStats Pass");

