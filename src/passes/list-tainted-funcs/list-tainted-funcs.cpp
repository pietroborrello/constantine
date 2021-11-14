
#include <pass.h>

#include <iostream>
#include <fstream>
#include <iomanip>

#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/CFG.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Analysis/LoopPass.h"
#include "llvm/Analysis/LoopInfo.h"

using namespace llvm;

#define DEBUG_TYPE "list-tainted-funcs"
#define oprint(s) outs() << s << "\n"

static cl::opt<std::string>
DumpFilename("list-out-file",
    cl::desc("The file where to list tainted funcs names"),
    cl::init("functions.list"), cl::NotHidden);

static cl::list<std::string>
Functions("list-as-tainted",
    cl::desc("Consider tainted all functions matching the regex"),
    cl::ZeroOrMore, cl::CommaSeparated, cl::NotHidden);

static cl::opt<bool>
OnlyBranches("list-only-branches",
    cl::desc("Consider only branches for taint informations"),
    cl::init(false), cl::NotHidden);

typedef long imd_t;

namespace {

  class ListTaintedFuncsPass : public ModulePass {

    std::ofstream dumpfile;
  public:
    static char ID;
    ListTaintedFuncsPass() : ModulePass(ID) {
        dumpfile.open(DumpFilename);
    }

    ~ListTaintedFuncsPass() {
        dumpfile.close();
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

    void dumpFunc(Function *F) {
        dumpfile << F->getName().str() << std::endl;
    }

    void dumpIfTainted(Function *F) {
        for(auto &BB: *F) {
            for(auto &I: BB) {
                if (getInstructionTaint(I)) {
                    if (OnlyBranches && !isa<BranchInst>(&I))
                        continue;
                    dumpFunc(F);
                    return;
                }
            }
        }
    }

    virtual bool runOnModule(Module &M) {

        std::vector<Regex*> FunctionRegexes;
        if (Functions.empty())
            Functions.push_back(" NO FUNCTION ");
        passListRegexInit(FunctionRegexes, Functions);

        /* Iterate all functions in the module */
        for (auto &F : M.getFunctionList()) {
            if (F.isDeclaration())
                continue;
            const std::string &FName = F.getName();
            if (passListRegexMatch(FunctionRegexes, FName)) {
                dumpFunc(&F);
                continue;
            }
            dumpIfTainted(&F);
        }
        return false;
    }

    void getAnalysisUsage(AnalysisUsage &AU) const {
    }

  };

}

char ListTaintedFuncsPass::ID = 0;
RegisterPass<ListTaintedFuncsPass> MP("list-tainted-funcs", "List Tainted Funcs Pass");
