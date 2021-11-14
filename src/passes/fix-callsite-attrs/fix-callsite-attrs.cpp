
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
#include "llvm/Transforms/Utils/FunctionComparator.h"
#include <set>
using namespace llvm;

#define DEBUG_TYPE "fix-callsite-attrs"
#define fixCallsiteAttrsPassLog(M) LLVM_DEBUG(dbgs() << "fixCallsiteAttrsPass: " << M << "\n")

#define oprint(s) outs() << s << "\n"
#define qprint(s) std::cout << s << std::endl

typedef long imd_t;

// This pass makes sure the attributes of a callsite match with the attributes of
// the called function, to fix a dfsan bug where wrappers do not update the callsite
// attributes, e.g.
// strlen -> __dfsw_strlen does keep the readonly attribute
namespace {

  class FixCallsiteAttrsPass : public ModulePass {


    std::set<std::string> FixedCalls;

  public:
    static char ID;
    FixCallsiteAttrsPass() : ModulePass(ID) {
    }

    /* BEGIN: Taken from FunctionComparator.cpp since it is private */
     int cmpNumbers(uint64_t L, uint64_t R) const {
        if (L < R)
            return -1;
        if (L > R)
            return 1;
        return 0;
    }
    
    // BEWARE: The function would have been much more complicated, but we need
    // just a simple comparison here, since types should be unique :)
    int cmpTypes(Type *TyL, Type *TyR) const {

        // Hello mum, can you explain to me what is a type confusion?
        return cmpNumbers((uint64_t)TyL, (uint64_t)TyR);
    }

    // This is sligtly changed to compare only function attributes, without 
    // considering param attributes, which may be different for callsites
    int cmpAttrs(const AttributeSet LAS, const AttributeSet RAS) const {
        AttributeSet::iterator LI = LAS.begin(), LE = LAS.end();
        AttributeSet::iterator RI = RAS.begin(), RE = RAS.end();
        for (; LI != LE && RI != RE; ++LI, ++RI) {
            Attribute LA = *LI;
            Attribute RA = *RI;
            if (LA.isTypeAttribute() && RA.isTypeAttribute()) {
                if (LA.getKindAsEnum() != RA.getKindAsEnum())
                    return cmpNumbers(LA.getKindAsEnum(), RA.getKindAsEnum());
        
                Type *TyL = LA.getValueAsType();
                Type *TyR = RA.getValueAsType();
                if (TyL && TyR) {
                    if (int Res = cmpTypes(TyL, TyR))
                        return Res;
                    continue;
                }
        
                // Two pointers, at least one null, so the comparison result is
                // independent of the value of a real pointer.
                if (int Res = cmpNumbers((uint64_t)TyL, (uint64_t)TyR))
                    return Res;
                continue;
            }
            if (LA < RA)
                return -1;
            if (RA < LA)
                return 1;
        }
        if (LI != LE)
            return 1;
        if (RI != RE)
            return -1;
        return 0;
    }
    /* END: Taken from FunctionComparator.cpp since it is private */

    bool fnAttrEquals(AttributeSet a1, AttributeSet a2) {
        return cmpAttrs(a1, a2) == 0;
    }


    // Creates a new AttributeSet which contains only the Enum attributes
    AttributeSet getEnumAttrs(LLVMContext &Ctx, const AttributeSet attrs) {
        AttrBuilder result;
        for (Attribute attr: attrs) {
            if (attr.isEnumAttribute())
                result.addAttribute(attr);
        }
        return AttributeSet::get(Ctx, result);
    }

    // Return the attribute list obtained from copying the Fn and ret attributes of the 
    // function, and the param attributes of the CS
    AttributeList copyFNAttributes(Function *F, LLVMContext &Ctx, CallSite& CS, bool onlyEnum) {
        // Construct a vector of AttributeSet for each param attr.
        std::vector<llvm::AttributeSet> ArgumentAttributes(
            CS.getNumArgOperands());

        // Copy attributes from the parameter of the CS
        for (unsigned i=0, ie = CS.getNumArgOperands(); i < ie; ++i) {
            ArgumentAttributes[i] = CS.getAttributes().getParamAttributes(i);
        }

        if (onlyEnum)
        {
            return AttributeList::get(
                Ctx,
                getEnumAttrs(Ctx, F->getAttributes().getFnAttributes()),
                F->getAttributes().getRetAttributes(),
                llvm::makeArrayRef(ArgumentAttributes));
        } else {
            return AttributeList::get(
                Ctx,
                F->getAttributes().getFnAttributes(),
                F->getAttributes().getRetAttributes(),
                llvm::makeArrayRef(ArgumentAttributes));
        }
    }

    void fixCallsiteAttrs(Function *F) {
        for (auto &BB : *F) {
            for(auto &I: BB) {
                CallSite CS(&I);
                if (!CS.getInstruction() || CS.isInlineAsm())
                    continue; // not a call
                Function *calledF = CS.getCalledFunction();
                if (!calledF) continue;

                // Assume llvm intrinsics are ok (maybe?)
                if (calledF->isIntrinsic())
                    continue;

                AttributeSet funcAttrs = getEnumAttrs(I.getContext(), calledF->getAttributes().getFnAttributes());
                AttributeSet csAttrs   = getEnumAttrs(I.getContext(), CS.getAttributes().getFnAttributes());

                // if the callsite has no attributes we can safely skip it
                if (csAttrs.getNumAttributes() == 0)
                    continue;

                if (fnAttrEquals(funcAttrs, csAttrs) == false) {
                    // if (calledF->getName().contains("strlen")) {
                    //     oprint("[WARNING] Attribute mismatch for: " << I);
                    //     oprint("    func attrs: ");
                    //     funcAttrs.dump();
                    //     oprint("    call attrs: ");
                    //     csAttrs.dump();
                    // }

                    CS.setAttributes(copyFNAttributes(calledF, I.getContext(), CS, /*onlyEnum=*/true));
                    FixedCalls.insert(calledF->getName().str());
                    // if (calledF->getName().contains("strlen")) {
                    //     oprint("    now: ");
                    //     CS.getAttributes().getFnAttributes().dump();
                    // }
                }
            }
        }

    }

    virtual bool runOnModule(Module &M) override {
        fixCallsiteAttrsPassLog("Running...");

        /* Iterate all functions in the module to check attributes */
        std::set<Function*> functionSet;
        for (auto &F : M.getFunctionList()) {
            if (F.isDeclaration())
                continue;
            fixCallsiteAttrs(&F);
        }
        
        oprint("------ [ " << FixedCalls.size() << " FIXED CALLS ] ------");
        // for (std::string name: FixedCalls) {
        //     oprint(name);
        // }
        return true;
    }
 
   void getAnalysisUsage(AnalysisUsage &AU) const override {
    }
  };

}

char FixCallsiteAttrsPass::ID = 0;
RegisterPass<FixCallsiteAttrsPass> MP("fix-callsite-attrs", "Make sure callsites match function attributes Pass");
