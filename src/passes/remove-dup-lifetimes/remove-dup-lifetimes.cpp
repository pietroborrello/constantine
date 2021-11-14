
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

#define DEBUG_TYPE "remove-dup-lifetimes"
#define removeDupLifetimesPassLog(M) LLVM_DEBUG(dbgs() << "removeDupLifetimesPass: " << M << "\n")

#define oprint(s) outs() << s << "\n"
#define qprint(s) std::cout << s << std::endl

static cl::list<std::string>
Functions("remove-dup-lifetimes-funcs",
    cl::desc("Specify all the comma-separated function regexes for which to remove DupLifetimes statements"),
    cl::ZeroOrMore, cl::CommaSeparated, cl::NotHidden);

typedef long imd_t;

// This pass removes multiple lifetime.start for the same variable moving it into 
// the beginning of the function
namespace {

  class RemoveDupLifetimesPass : public ModulePass {

  public:
    static char ID;
    RemoveDupLifetimesPass() : ModulePass(ID) {
    }

    static bool isLifetimeStart(const Instruction *Inst) {
    if (const IntrinsicInst* II = dyn_cast<IntrinsicInst>(Inst))
        return II->getIntrinsicID() == Intrinsic::lifetime_start;
    return false;
    }

    void removeDupLifetimes(Function *F) {
        LLVMContext &Ctx = F->getContext();
        auto NegativeOne = ConstantInt::getSigned(Type::getInt64Ty(Ctx), -1);

        // search for all the lifetimes start in the function
        std::map<Value*, std::set<Instruction*>> LifetimesStarts;
        for (auto &BB : *F) {
            for(auto &I: BB) {
                if (isLifetimeStart(&I)) {
                    IntrinsicInst* II = dyn_cast<IntrinsicInst>(&I);
                    Value *Target = II->getArgOperand(1)->stripPointerCasts();
                    LifetimesStarts[Target].insert(&I);
                }
            }
        }

        // for each object that has multiple lifetime.start 
        // move it just after the variable declaration
        for (auto entry : LifetimesStarts) {
            Value *Target = entry.first;
            std::set<Instruction*> Lifetimes = entry.second;
            if (Lifetimes.size() > 1) {
                oprint("dup lifetime loop in " << F->getName().str());
                for (Instruction* Lifetime: Lifetimes) {
                    Lifetime->eraseFromParent();
                }
                Instruction* TargetI = dyn_cast<Instruction>(Target);
                assert(TargetI);
                Instruction* NI = TargetI->getNextNode();
                assert(NI);
                llvm::IRBuilder<> BuilderStart(NI);
                BuilderStart.CreateLifetimeStart(Target, NegativeOne);
            }
        }
    }

    virtual bool runOnModule(Module &M) override {
        removeDupLifetimesPassLog("Running...");
        std::vector<Regex*> FunctionRegexes;
        if (Functions.empty())
            Functions.push_back(".*");
        passListRegexInit(FunctionRegexes, Functions);

        /* Iterate all functions in the module to collect DupLifetimes*/
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
            removeDupLifetimes(F);
        }
        return true;
    }
 
   void getAnalysisUsage(AnalysisUsage &AU) const override {
    }
  };

}

char RemoveDupLifetimesPass::ID = 0;
RegisterPass<RemoveDupLifetimesPass> MP("remove-dup-lifetimes", "Remove Multiple Lifetimes Pass");
