
#include <pass.h>

#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/CFG.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Transforms/Utils/CodeExtractor.h"
#include "llvm/Analysis/LoopPass.h"
#include "llvm/Analysis/LoopInfo.h"
#include <set>
using namespace llvm;

#define DEBUG_TYPE "check-undefined"
#define checkUndefinedPassLog(M) LLVM_DEBUG(dbgs() << "checkUndefinedPass: " << M << "\n")

#define oprint(s) outs() << s << "\n"
#define qprint(s) std::cout << s << std::endl

static cl::list<std::string>
Functions("check-undefined-funcs",
    cl::desc("Specify all the comma-separated function regexes for which to check undefined values"),
    cl::ZeroOrMore, cl::CommaSeparated, cl::NotHidden);

static cl::opt<bool>
IgnorePhis("check-undef-ignore-phi",
    cl::desc("Ignore PHI nodes when checking undef uses"),
    cl::init(true), cl::NotHidden);

typedef long imd_t;

// This pass dumps undefined values used in the IR
namespace {

  class CheckUndefinedPass : public ModulePass {

  public:
    static char ID;
    CheckUndefinedPass() : ModulePass(ID) {
    }

    // Check if the body of the function actually uses the provided argument
    bool functionUsesArg(Function *F, int arg_num) {
        Value *arg = (F->arg_begin() + arg_num);
        if (arg->getNumUses() > 0)
            return true;
        return false;
    }

    void print_error(Instruction *I) {
        BasicBlock *BB = I->getParent();
        Function *F = BB->getParent();
        oprint("[WARNING] undef use: " << *I << " ( in " << F->getName().str() << ": " << BB->getName().str() << " )");
    }

    void checkUndefined(Function *F) {
        // search for all the lifetimes start in the function
        std::set<Instruction*> Lifetimes;
        for (auto &BB : *F) {
            for(auto &I: BB) {
                // oprint(I);
                if (IgnorePhis && (isa<InsertElementInst>(I) || isa<ShuffleVectorInst>(I))) {
                    continue;
                }
                // check for undefined values
                int op_num = 0;
                for (Value *op : I.operand_values()) {
                    // oprint("-  " << *op);
                    if (isa<UndefValue>(op)) {
                        if (isa<CallInst>(I)) {
                            Function* F = dyn_cast<CallInst>(&I)->getCalledFunction();

                            // We may have a call instruciton with an undefined
                            // argument which is in fact not used
                            if (functionUsesArg(F, op_num)) {
                                print_error(&I);
                            }
                        } else {
                            print_error(&I);
                        }
                    }

                    ++op_num;
                }
            }
        }
    }

    virtual bool runOnModule(Module &M) override {
        checkUndefinedPassLog("Running...");
        std::vector<Regex*> FunctionRegexes;
        if (Functions.empty())
            Functions.push_back(".*");
        passListRegexInit(FunctionRegexes, Functions);

        /* Iterate all functions in the module to collect Lifetimes*/
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
            checkUndefined(F);
        }
        return false;
    }
 
   void getAnalysisUsage(AnalysisUsage &AU) const override {
    }
  };

}

char CheckUndefinedPass::ID = 0;
RegisterPass<CheckUndefinedPass> MP("check-undefined", "Remove Multiple Lifetimes Pass");
