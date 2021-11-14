
#include <pass.h>

#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/CFG.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/IR/IRBuilder.h"

using namespace llvm;

#define DEBUG_TYPE "removeMemfuncs"
#define removeMemfuncsPassLog(M) LLVM_DEBUG(dbgs() << "RemoveMemfuncsPass: " << M << "\n")
#define eprint(s) (errs() << s << "\n")
#define oprint(s) (outs() << s << "\n")

static cl::opt<bool>
RemoveMemset("remove-memset",
    cl::desc("Substitute memset calls with call to utils_memset"),
    cl::init(false), cl::NotHidden);
static cl::opt<bool>
RemoveMemcpy("remove-memcpy",
    cl::desc("Substitute memcpy calls with call to utils_memcpy"),
    cl::init(false), cl::NotHidden);
static cl::opt<bool>
RemoveMemcpyOnlyNonconst("remove-memcpy-only-nonconst",
    cl::desc("If enabled will substitute only memcpy calls that have a non constant size"),
    cl::init(true), cl::NotHidden);
static cl::opt<bool>
RemoveMemmove("remove-memmove",
    cl::desc("Substitute memmove calls with call to utils_memmove"),
    cl::init(false), cl::NotHidden);

namespace {
  
  // Remove all the calls to memcpy, memmove or memset to simple wrappers that do
  // not call the stdlib
  class RemoveMemfuncsPass : public ModulePass {

  public:
    static char ID;
    unsigned long nmemset = 0;
    unsigned long nmemcpy = 0;
    unsigned long nmemmove = 0;
    RemoveMemfuncsPass() : ModulePass(ID) {}

    bool hasMemcpyConstSize(CallSite &CS) {
        Function *Callee = dyn_cast<Function>(CS.getCalledValue()->stripPointerCasts());
        assert(Callee);
        assert(Callee->getIntrinsicID() == Intrinsic::memcpy);
        // Get the memcpy size
        Value* nV = CS.getArgOperand(2);
        return isa<ConstantInt>(nV);
    }

    // substiture intrinsics call to memcpy, memmove or memset to calls to our 
    // simpler functions
    void wrapIntrinsicCall(CallSite &CS, Function *Callee) {
        const char *wrapper = NULL;
        switch(Callee->getIntrinsicID()) {
        case Intrinsic::memcpy:
            // bail out if should not substitute
            if (!RemoveMemcpy) return;
            // bail out if we should remove only non constant sized memcpy and this has constant size
            if (RemoveMemcpyOnlyNonconst && hasMemcpyConstSize(CS)) return;
            wrapper = "utils_memcpy";
            ++nmemcpy;
            break;
        case Intrinsic::memmove:
            // bail out if should not substitute
            if (!RemoveMemmove) return;
            wrapper = "utils_memmove";
            ++nmemmove;
            break;
        case Intrinsic::memset:
            // bail out if should not substitute
            if (!RemoveMemset) return;
            wrapper = "utils_memset";
            ++nmemset;
            break;
        default:
            return;
        }
        // eprint(*CS.getInstruction());
        Function *NewCallee = Callee->getParent()->getFunction(wrapper);
        // eprint(wrapper);
        assert(NewCallee && "utils function not found");
        CS.setCalledFunction(NewCallee);

        // inline the call to our intrinsic to improve perf and precision
        InlineFunctionInfo IFI;
        assert(InlineFunction(CS, IFI) && "Failed to inline call to util");
    }

    virtual bool runOnModule(Module &M) {
        removeMemfuncsPassLog("Running...");

        std::list<Instruction*> calls;
        for (Function &F: M) {
            for (auto &BB : F)
            for (auto &I : BB) {
                CallSite CS(&I);
                if (!CS.getInstruction() || CS.isInlineAsm())
                    continue; // not a call
                Function *Callee = dyn_cast<Function>(CS.getCalledValue()->stripPointerCasts());
                if (!Callee)
                    continue; // not a direct call
                if (Callee->isIntrinsic())
                    calls.push_back(&I);
            }
        }

        for (Instruction* call: calls) {
            CallSite CS(call);
            assert(CS.getInstruction() && !CS.isInlineAsm());
            Function *Callee = dyn_cast<Function>(CS.getCalledValue()->stripPointerCasts());
            assert(Callee);
            wrapIntrinsicCall(CS, Callee);
        }

        oprint("--------[ MEMFUNCS STATS ]--------");
        oprint("[+] Replaced memset:  " << nmemset);
        oprint("[+] Replaced memcpy:  " << nmemcpy);
        oprint("[+] Replaced memmove: " << nmemmove);
        return true;
    }
  };

}

char RemoveMemfuncsPass::ID = 0;
RegisterPass<RemoveMemfuncsPass> MP("remove-memfuncs", "RemoveMemfuncs Pass");

