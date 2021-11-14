
#include <pass.h>

#include "WPA/WPAPass.h"
#include "WPA/Andersen.h"
#include "Util/SVFUtil.h"
#include "Util/SVFModule.h"
#include "SVF-FE/LLVMUtil.h"

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

#define DEBUG_TYPE "stack-vars-promotion"
#define stackVarsPromotionPassLog(M) LLVM_DEBUG(dbgs() << "stackVarsPromotionPass: " << M << "\n")

#define oprint(s) outs() << s << "\n"
#define qprint(s) std::cout << s << std::endl

#define STACK_PROM_DEBUG 0

static cl::list<std::string>
Functions("stack-vars-promotion-funcs",
    cl::desc("Specify all the comma-separated function regexes for which to promote stack vars"),
    cl::ZeroOrMore, cl::CommaSeparated, cl::NotHidden);

static cl::list<std::string>
CFLFunctions("stack-vars-promotion-cfl-funcs",
    cl::desc("Specify all the comma-separated function regexes that will be CFLed, so that we can promote all their stack vars"),
    cl::ZeroOrMore, cl::CommaSeparated, cl::NotHidden);

static cl::opt<bool>
AllVars("stack-vars-promote-all",
    cl::desc("Promote all stack variables"),
    cl::init(false), cl::NotHidden);

typedef long imd_t;

namespace {

  class StackVarsPromotionPass : public ModulePass {

  public:
    static char ID;
    unsigned long unique_id;
    StackVarsPromotionPass() : ModulePass(ID) {
        unique_id = 0;
    }

    unsigned long getUniqueID() {
        return unique_id++;
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

    bool hasTaintMetadata(Instruction *I) {
        MDNode* N;
        N = I->getMetadata("t");
        return N != NULL;
    }

    // promote static alloca to global variables
    void promoteStackVars(Module &M, std::set<AllocaInst*> allocas) {
        // DataLayout* DL = new DataLayout(&M);
        // iterate over all the allocas and promote them to global variables
        for (AllocaInst* AI: allocas) {
            Type* allocatedType = AI->getAllocatedType();
            Constant* const_init = Constant::getNullValue(allocatedType);
            Function *F = AI->getParent()->getParent();

            // if the function allocating the variable may recurse it is not safe to promote it
            if (!F->doesNotRecurse())
                continue;

            std::string globalName = "promoted_stack_var_" + F->getName().str() + "_" + std::to_string(getUniqueID());
            M.getOrInsertGlobal(globalName, allocatedType);
            GlobalVariable *promotedVar = M.getNamedGlobal(globalName);
            promotedVar->setLinkage(GlobalValue::InternalLinkage);
            // if (STACK_PROM_DEBUG)
                promotedVar->setAlignment(64);
            // else
                // promotedVar->setAlignment(AI->getAlignment());
            promotedVar->setInitializer(const_init);

            // oprint("Promoting " << *AI << " in " << F->getName().str() << " \n  to " << *promotedVar);
            // oprint("  of size: " << DL->getTypeAllocSize(allocatedType));

            AI->replaceAllUsesWith(promotedVar);
            AI->eraseFromParent();
        }
    }

    void collectPtsStackVars(PointerAnalysis* pta, Instruction* memoryAccess, Value* ptr, DataLayout* DL, std::set<AllocaInst*> &allocas){
        NodeID pNodeId = pta->getPAG()->getValueNode(ptr);
        NodeBS& pts = pta->getPts(pNodeId);
        // oprint("---------------");
        // oprint(*memoryAccess << "\n" << *ptr);
        // pta->dumpPts(pNodeId, pts);
        // Same check of DFL to avoid promoting vars we won't DFL
        // Avoid protecting any ptr which was not part of the original program as long
        // as can point to only one simple object
        // -> this means it has been introduced by the branch-extract pass to 
        // forward variables between extracted branches
        if (!hasTaintMetadata(memoryAccess)) {
            int objCount = 0;
            for (NodeBS::iterator ii = pts.begin(), ie = pts.end(); ii != ie; ii++) {
                PAGNode* targetObj = pta->getPAG()->getPAGNode(*ii);

                // Ensure we do not deal with dummy or const objects
                assert(targetObj->hasValue());
                const Value* targetObjVal = targetObj->getValue();

                // Ensure we only deal with primitive or ptr types
                if(!targetObjVal->getType()->isIntOrPtrTy()) {
                    objCount = -1;
                    // debug print to see what we do not manage
                    oprint("UNMANAGED COMPLEX OBJECT");
                    oprint("access: " << *memoryAccess << "\nptr: " << *ptr);
                    oprint("obj: " << *targetObjVal);
                    break;
                }
                ++objCount;
            }
            // objCount is 0 when the function is never called (e.g. cloned and substituted)
            if (objCount == 1 || objCount == 0) {
                // do not promote the object
                return;
            } else {
                // debug print to see what we do not manage
                oprint("UNMANAGED OBJECTS");
                oprint("access: " << *memoryAccess << "\nptr: " << *ptr);
                for (NodeBS::iterator ii = pts.begin(), ie = pts.end(); ii != ie; ii++) {
                    PAGNode* targetObj = pta->getPAG()->getPAGNode(*ii);

                    // Ensure we do not deal with dummy or const objects
                    assert(targetObj->hasValue());
                    const Value* targetObjVal = targetObj->getValue();
                    oprint("obj: " << *targetObjVal);
                }
            }
        }
        for (NodeBS::iterator ii = pts.begin(), ie = pts.end(); ii != ie; ii++) {
            // outs() << " " << *ii << " ";
            PAGNode* targetObj = pta->getPAG()->getPAGNode(*ii);

            // Ensure we do not deal with dummy or const objects
            assert(targetObj->hasValue());
            const Value* targetObjVal = targetObj->getValue();

            // Ensure we have a pointer to the object
            Type* T = targetObjVal->getType();
            assert(T->isPointerTy());

            if(const AllocaInst* v = SVFUtil::dyn_cast<AllocaInst>(targetObjVal)){
                // For now manage only static alloca
                assert(v->isStaticAlloca());
                if(!v->isStaticAlloca()) continue;
                // outs() << " (alloca inst: ";
                allocas.insert(const_cast<AllocaInst*>(v));
            }
        }
        return;
    }

    void collectStackVars(Module &M, Function &F, PointerAnalysis* pta, DataLayout* DL, std::set<AllocaInst*> &allocas, bool willCFL) {
        // avoid promoting stack vars of a function that may recurse
        // oprint("collecting stack vars in " << F.getName().str());
        // oprint("recurses? " << (F.doesNotRecurse()? "no" : "yes"));

        // collect all the stack vars which are accessed by a tainted mem operation
        for (auto &BB : F)
        for (auto &I : BB) {
            if (!AllVars && !getInstructionTaint(I) && !willCFL)
                continue;
            if (LoadInst *LI = dyn_cast<LoadInst>(&I)) {
                collectPtsStackVars(pta, &I, LI->getPointerOperand(), DL, allocas);
                continue;
            }
            if (StoreInst *SI = dyn_cast<StoreInst>(&I)) {
                collectPtsStackVars(pta, &I, SI->getPointerOperand(), DL, allocas);
                continue;
            }
        }
    }

    virtual bool runOnModule(Module &M) override {
        stackVarsPromotionPassLog("Running...");
        DataLayout* DL = new DataLayout(&M);
        SVFModule* svfModule = LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(M);
        PointerAnalysis* pta = new Andersen();
        pta->analyze(svfModule);

        std::vector<Regex*> FunctionRegexes;
        std::vector<Regex*> CFLFunctionRegexes;
        if (Functions.empty())
            Functions.push_back("main");
        passListRegexInit(FunctionRegexes, Functions);

        // Init also all the regexes which identify the functions that will be CFLed
        passListRegexInit(CFLFunctionRegexes, CFLFunctions);

        /* Iterate all functions in the module to collect which stack vars to promote */
        std::set<Function*> functionSet;
        std::set<AllocaInst*> allocas;
        for (auto &F : M.getFunctionList()) {
            if (F.isDeclaration())
                continue;
            const std::string &FName = F.getName();
            if (!passListRegexMatch(FunctionRegexes, FName) && !passListRegexMatch(CFLFunctionRegexes, FName))
                continue;
            if (F.getSection().equals("dfl_code") || F.getSection().equals("cfl_code") 
                || F.getSection().equals("cgc_code") || F.getSection().equals("icp_code"))
                continue;
            functionSet.insert(&F);
        }
        while (!functionSet.empty()) {
            Function *F = *functionSet.begin();
            functionSet.erase(functionSet.begin());
            bool willCFL = passListRegexMatch(CFLFunctionRegexes, F->getName());
            collectStackVars(M, *F, pta, DL, allocas, willCFL);
        }
        promoteStackVars(M, allocas);
        return true;
    }
 
   void getAnalysisUsage(AnalysisUsage &AU) const override {
        AU.addRequired<DominatorTreeWrapperPass>();
        AU.addRequired<PostDominatorTreeWrapperPass>();
    }
  };

}

char StackVarsPromotionPass::ID = 0;
RegisterPass<StackVarsPromotionPass> MP("stack-vars-promotion", "Stack Vars Promotion Pass");
