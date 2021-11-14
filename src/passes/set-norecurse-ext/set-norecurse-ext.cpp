
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

#define DEBUG_TYPE "set-norecurse-ext"
#define setNoRecursExtPassLog(M) LLVM_DEBUG(dbgs() << "setNoRecursExtPass: " << M << "\n")

#define oprint setNoRecursExtPassLog

typedef long imd_t;

// This pass sets the norecurse attribute to all the external functions that we
// can guess they not recurse back to the program in any way.
// Since we are calling an external function the only way they could recurse back 
// in the module, or call a recursive function in it, is by
// passing a callback pointer to them, so check that
namespace {

  class SetNoRecursExtPass : public ModulePass {

  public:
    static char ID;
    SetNoRecursExtPass() : ModulePass(ID) {
    }

    bool  isFunctionPointerType(Type *type){
        // Check the type here
        if(PointerType *pointerType=dyn_cast<PointerType>(type)){
            return isFunctionPointerType(pointerType->getElementType());
        }
            //Exit Condition
            else if(type->isFunctionTy()){
            return  true;
            }
        return false;
    }

    void setNoRecursExt(CallSite &CS, Function *F) {
        oprint("Checking " << *CS.getInstruction());
        
        // Check no parameter is a function pointer
        for (auto &arg: F->args()) {
            Type* argT = arg.getType();
            oprint("  " << *argT);
            if (isFunctionPointerType(argT)) {
                oprint("  [-] not adding attr norecurse");
                return;
            }
        }
        oprint(" Callsite " << F->getName().str());
        // Check also the callsite
        for (auto &arg: CS.args()) {
            Type* argT = (*arg).getType();
            oprint("  " << *argT);
            if (isFunctionPointerType(argT)) {
                oprint("  [-] not adding attr norecurse");
                return;
            }
        }
        oprint("  [+] adding attr norecurse");
        // if check ok set the norecurse attrs
        if (!CS.hasFnAttr(Attribute::NoRecurse))
            CS.addAttribute(AttributeList::FunctionIndex, Attribute::NoRecurse);
        if (!F->hasFnAttribute(Attribute::NoRecurse))
            F->addFnAttr(Attribute::NoRecurse);
    }

    virtual bool runOnModule(Module &M) override {
        setNoRecursExtPassLog("Running...");

        /* Iterate all functions in the module */
        for (auto &F : M.getFunctionList()) {
            if (F.isDeclaration())
                continue;
            for (auto &BB: F) {
                for (auto &I: BB) {
                    CallSite CS(&I);
                    if (!CS.getInstruction() || CS.isInlineAsm())
                        continue; // not a call
                    Function *Callee = dyn_cast<Function>(CS.getCalledValue()->stripPointerCasts());
                    if (!Callee)
                        continue; // not a direct call
                    
                    // if external function try to set the norecurse attr
                    if (Callee->isDeclaration())
                        setNoRecursExt(CS, Callee);
                }
            }
        }
        return true;
    }
 
   void getAnalysisUsage(AnalysisUsage &AU) const override {
    }
  };

}

char SetNoRecursExtPass::ID = 0;
RegisterPass<SetNoRecursExtPass> MP("set-norecurse-ext", "Set NoRecurse Attr to external functions Pass");
