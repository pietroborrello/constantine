
#include <pass.h>
#include "WPA/WPAPass.h"
#include "llvm/Transforms/Utils/CallPromotionUtils.h"

using namespace llvm;

#define DEBUG_TYPE "flatten"
#define flattenPassLog(M) LLVM_DEBUG(dbgs() << "FlattenPass: " << M << "\n")

static cl::list<std::string>
Functions("flatten-funcs",
    cl::desc("Specify all the comma-separated function regexes to flatten"),
    cl::ZeroOrMore, cl::CommaSeparated, cl::NotHidden);

static cl::opt<bool>
Recurse("flatten-recurse",
    cl::desc("Flatten recursively"),
    cl::init(true), cl::NotHidden);

static cl::opt<bool>
ICalls("flatten-icalls",
    cl::desc("Flatten indirect calls"),
    cl::init(false), cl::NotHidden);

namespace {

  class FlattenPass : public ModulePass {

  public:
    static char ID;
    FlattenPass() : ModulePass(ID) {}

    void flatten(Function *F, std::set<Function*> &flattenFunctionSet, WPAPass *wpa) {
        std::vector<Instruction*> directCalls;
        std::vector<Instruction*> indirectCalls;
        unsigned inlinedCalls=0;

        // Collect calls
        for (auto &BB : *F)
        for (auto &I : BB) {
            CallSite CS(&I);
            if (!CS.getInstruction() || CS.isInlineAsm())
                continue; // not a call
            if (!isa<Function>(CS.getCalledValue()->stripPointerCasts())) {
                if (ICalls)
                    indirectCalls.push_back(&I);
            }
            else {
                directCalls.push_back(&I);
            }
        }

        // Promote indirect calls to direct calls
        for (auto I : indirectCalls) {
            promoteIndirectCall(F, I, directCalls, wpa);
        }

        // Inline direct calls
        InlineFunctionInfo IFI;
        for (auto I : directCalls) {
            CallSite CS(I);
            Function *Callee = dyn_cast<Function>(CS.getCalledValue()->stripPointerCasts());
            assert(Callee);
            if (Callee->hasFnAttribute(Attribute::NoInline)
                || Callee->isDeclaration())
                continue; // not an inlineable direct call
            // XXX: Check for directly/indirectly recursive functions
            inlinedCalls++;
            InlineResult IR = InlineFunction(CS, IFI);
            assert(IR);
        }

        // Schedule more work as needed
        if (Recurse && inlinedCalls > 0)
            flattenFunctionSet.insert(F);
    }

    void getIndirectCallees(Module *M, CallSite &CS, std::vector<Function*> &callees, WPAPass *wpa) {
        Value *V = CS.getCalledValue()->stripPointerCasts();
        for (auto &F : M->getFunctionList()) {
            if (!F.hasAddressTaken())
                continue;
            if (wpa->alias(V, &F))
                callees.push_back(&F);
        }
    }

    void promoteIndirectCall(Function *F, Instruction *I, std::vector<Instruction*> &directCalls, WPAPass *wpa) {
        CallSite CS(I);
        std::vector<Function*> callees;
        getIndirectCallees(F->getParent(), CS, callees, wpa);
        if (callees.empty())
            return; // not a real indirect call

        Function *lastCallee = NULL;
        for (auto Callee : callees) {
            if (lastCallee)
                directCalls.push_back(promoteCallWithIfThenElse(CS, lastCallee));
            lastCallee = Callee;
        }
        directCalls.push_back(promoteCall(CS, lastCallee));
    }

    virtual bool runOnModule(Module &M) {
        flattenPassLog("Running...");
        SVFModule* svfModule = LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(M);
        WPAPass *wpa = NULL;
        if (ICalls) {
            wpa = new WPAPass();
            wpa->runOnModule(svfModule);
        }

        std::vector<Regex*> FunctionRegexes;
        if (Functions.empty())
            Functions.push_back("main");
        passListRegexInit(FunctionRegexes, Functions);

        /* Iterate all functions in the module to flatten */
        std::set<Function*> flattenFunctionSet;
        for (auto &F : M.getFunctionList()) {
            if (F.isDeclaration())
                continue;
            if (F.hasFnAttribute(Attribute::NoInline))
                continue;
            const std::string &FName = F.getName();
            if (!passListRegexMatch(FunctionRegexes, FName))
                continue;
            flattenFunctionSet.insert(&F);
        }
        while (!flattenFunctionSet.empty()) {
            Function *F = *flattenFunctionSet.begin();
            flattenFunctionSet.erase(flattenFunctionSet.begin());
            flatten(F, flattenFunctionSet, wpa);
        }

        return true;
    }
  };

}

char FlattenPass::ID = 0;
RegisterPass<FlattenPass> MP("flatten", "Flatten Pass");
