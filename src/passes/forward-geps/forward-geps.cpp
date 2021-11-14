
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
#include "SVF-FE/GEPTypeBridgeIterator.h" // include bridge_gep_iterator
#include <set>
using namespace llvm;

#define DEBUG_TYPE "forward-geps"
#define forwardGEPsPassLog(M) LLVM_DEBUG(dbgs() << "forwardGEPsPass: " << M << "\n")

#define oprint(s) outs() << s << "\n"
#define qprint(s) std::cout << s << std::endl

typedef long imd_t;

static cl::list<std::string>
Functions("forward-geps-funcs",
    cl::desc("Specify all the comma-separated function regexes for which to forward GEP statements to their memory accesses"),
    cl::ZeroOrMore, cl::CommaSeparated, cl::NotHidden);

// This pass clones a GEP to be near the memory access using it
// it increases the locality of code to be analized, and makes it simpler for 
// pointer analysis to deal with it
namespace {

  class ForwardGEPsPass : public ModulePass {

  public:
    static char ID;
    ForwardGEPsPass() : ModulePass(ID) {
    }

    /// return true if the GEP accesses a constant offset in the object
    /// or if it accesses an array, as it is considered a unique field
    bool isConstGep(GetElementPtrInst* GEP) {
        for (bridge_gep_iterator gi = bridge_gep_begin(GEP), ge = bridge_gep_end(GEP);
            gi != ge; ++gi) {

            // Allow constant integers as GEP indexes
            if (isa<ConstantInt>(gi.getOperand()))
                continue;

            // Allow array accesses 
            if (isa<ArrayType>(*gi))
                continue;

            // All other cases are not "constant"
            return false;
        }
        return true;
    }

    void setPtrOperand(Instruction* I, Value *V) {
        if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
            LI->setOperand(0, V);
        }
        else if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
            SI->setOperand(1, V);
        } else {
            assert(false && "need a memory access");
        }
    }

    void forwardGEPs(Function *F) {
        // search for all the mem accesses in the function
        std::map<Instruction*, GetElementPtrInst*> MemAccess2GEP;
        for (auto &BB : *F) {
            for(auto &I: BB) {
                // for each memory access get the respective GEP if present
                if (LoadInst *LI = dyn_cast<LoadInst>(&I)) {
                    Value *ptr = LI->getPointerOperand();
                    // oprint("IS_GEP: " << isa<GetElementPtrInst>(ptr));
                    if (GetElementPtrInst* GEP = dyn_cast<GetElementPtrInst>(ptr))
                    {
                        // oprint("IS_CONST_GEP: " << isConstGep(GEP));
                        MemAccess2GEP[LI] = GEP;
                    }
                }
                else if (StoreInst *SI = dyn_cast<StoreInst>(&I)) {
                    Value *ptr = SI->getPointerOperand();
                    // oprint("IS_GEP: " << isa<GetElementPtrInst>(ptr));
                    if (GetElementPtrInst* GEP = dyn_cast<GetElementPtrInst>(ptr))
                    {
                        // oprint("IS_CONST_GEP: " << isConstGep(GEP));
                        MemAccess2GEP[SI] = GEP;
                    }
                }
            }
        }

        // for each memory access, clone its GEP near to it
        for (auto entry : MemAccess2GEP) {
            Instruction *memAccess = entry.first;
            GetElementPtrInst* GEP = entry.second;

            // skip if they are already in the same BB
            if(memAccess->getParent() == GEP->getParent())
                continue;

            Instruction* newGEP = GEP->clone();
            // oprint("memAcc: " << *memAccess);
            // oprint("GEP: "    << *GEP);
            // oprint("newGEP: " << *newGEP);

            newGEP->insertBefore(memAccess);
            newGEP->setName(GEP->getName());
            setPtrOperand(memAccess, newGEP);

            // oprint(*memAccess->getParent());
        }
    }

    virtual bool runOnModule(Module &M) override {
        forwardGEPsPassLog("Running...");
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
            forwardGEPs(F);
        }
        return true;
    }
 
   void getAnalysisUsage(AnalysisUsage &AU) const override {
    }
  };

}

char ForwardGEPsPass::ID = 0;
RegisterPass<ForwardGEPsPass> MP("forward-geps", "Forward GEP Pass");
