
#include <pass.h>
#include "WPA/WPAPass.h"
#include "llvm/Transforms/Utils/CallPromotionUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"

using namespace llvm;

#define DEBUG_TYPE "cgc"
#define cgcPassLog(M) LLVM_DEBUG(dbgs() << "CallgraphClonePass: " << M << "\n")
#define oprint(s) dbgs() << s << "\n"

static cl::list<std::string>
Functions("cgc-funcs",
    cl::desc("Specify all the comma-separated function regexes to cgc"),
    cl::ZeroOrMore, cl::CommaSeparated, cl::NotHidden);

static cl::opt<std::string>
ClonePrefix("cgc-clone-prefix",
    cl::desc("Specify the clone name prefix"),
    cl::init("__cgc_"), cl::NotHidden);

static cl::opt<bool>
Recurse("cgc-recurse",
    cl::desc("CallgraphClone recursively"),
    cl::init(true), cl::NotHidden);

static cl::opt<bool>
Unique("cgc-unique",
    cl::desc("CallgraphClone with a unique clone per callsite"),
    cl::init(false), cl::NotHidden);

static cl::opt<bool>
ICalls("cgc-icalls",
    cl::desc("CallgraphClone indirect calls"),
    cl::init(false), cl::NotHidden);

namespace {

  class CallgraphClonePass : public ModulePass {

  public:
    static char ID;
    unsigned long unique_id = 0;
    CallgraphClonePass() : ModulePass(ID) {}

    unsigned long getUniqueID() {
        return ++unique_id;
    }

    // Substitute all the trailings .x.y.z that llvm creates when having two functions
    // with the same name, with some uniqueIDs to avoid long names
    std::string compressName(std::string name) {
        // find the last .num
        std::string newName = name;
        std::string::size_type idx = newName.rfind('.');
        if (idx == std::string::npos || idx == newName.length())
            return newName;
        // ensure it is actually a number
        int random = atoi(newName.substr(idx+1).c_str());

        while (random) {
            newName = newName.substr(0, idx);
            idx = newName.rfind('.');
            if (idx == std::string::npos || idx == newName.length())
                return newName + "." + std::to_string(getUniqueID());
            random = atoi(newName.substr(idx+1).c_str());
        }
        return newName + "." + std::to_string(getUniqueID());
    }

    void mapIndirectlyCalledFunctionClone(Function *F, Function *clone) {
        static Function *PassInitF = F->getParent()->getFunction("cgc_pass_init");
        static Function *PassAddCloneF = F->getParent()->getFunction("cgc_pass_add_clone");
        static std::set<Function*> mappedFunctions;
        assert(PassInitF && PassAddCloneF);

        // If we have already mapped this function, just return.
        std::set<Function*>::iterator it = mappedFunctions.find(F);
        if (it != mappedFunctions.end())
            return;
        mappedFunctions.insert(F);

        // Tell the runtime to map this clone.
        Instruction *I = PassInitF->front().getTerminator();
        std::vector<Value*> args;
        args.push_back(CastInst::CreatePointerCast(F, PassAddCloneF->getParamByValType(0)->getPointerTo(), "", I));
        args.push_back(CastInst::CreatePointerCast(clone, PassAddCloneF->getParamByValType(1)->getPointerTo(), "", I));
        CallInst::Create(PassAddCloneF, args, "", I);
    }
    Function* addFunctionClone(std::set<Function*> &cgcFunctionSet, Function *F, Function *clone=NULL) {
        static std::map<Function*, Function*> cloneCache;

        bool forceNew = Unique && F->doesNotRecurse();

        // If we already have a clone for this function, just return it.
        std::map<Function*,Function*>::iterator it = cloneCache.find(F);
        if (!forceNew && it != cloneCache.end())
            return it->second;

        // Clone original function, unless the clone was already given.
        if (!clone) {
            ValueToValueMapTy VMap;
            clone = CloneFunction(F, VMap);
            // if the function name already contains the prefix do not add it
            if (F->getName().find(ClonePrefix) == std::string::npos)
                clone->setName(ClonePrefix + F->getName());
            // Compress the clone name to avoid .1452.3394.9208.13831.27566...
            // at the end
            clone->setName(compressName(clone->getName().str()));
            // oprint("    cloning " << F->getName().str() << " to " << clone->getName().str());
            assert(clone);
        }
        cloneCache.insert(std::pair<Function*,Function*>(F, clone));

        // If we need to recurse, add the target to the functions to process.
        if (Recurse && !clone->isDeclaration() && !clone->isIntrinsic())
            cgcFunctionSet.insert(clone);

        return clone;
    }
    void wrapIndirectCall(Function *Caller, CallSite &CS) {
        static Function *F = Caller->getParent()->getFunction("cgc_fptr_wrap");
        assert(F);
        std::vector<Value*> args;
        args.push_back(CastInst::CreatePointerCast(CS.getCalledValue(), F->getParamByValType(0)->getPointerTo(), "", CS.getInstruction()));
        CallInst *CI = CallInst::Create(F, args, "", CS.getInstruction());
        CS.setCalledFunction(CastInst::CreatePointerCast(CI, CS.getCalledValue()->getType(), "", CS.getInstruction()));
    }
    void cgc(std::vector<Function*> functions, Function *F, std::set<Function*> &cgcFunctionSet, WPAPass *wpa) {
        // oprint("CGC: " << F->getName().str());
        // For each call in the given function clone:
        for (auto &BB : *F)
        for (auto &I : BB) {
            CallSite CS(&I);
            if (!CS.getInstruction() || CS.isInlineAsm())
                continue;

            // For direct calls, simply redirect target to new clone
            Function *C = dyn_cast<Function>(CS.getCalledValue()->stripPointerCasts());
            if (C) {
                if (C->isDeclaration() || C->isIntrinsic())
                    continue;
                Function *clone = addFunctionClone(cgcFunctionSet, C);
                CS.setCalledFunction(clone);
                continue;
            }
            oprint("INDIRECT CALL: " << I);
            oprint("in func: " << F->getName().str());
            if (!ICalls)
                continue;


            // For indirect calls, find all the targets, clone and map them
            std::vector<Function*> callees;
            getIndirectCallees(functions, CS, callees, wpa);
            bool hasClonedTargets = false;
            for (Function *C : callees) {
                Function *clone = NULL;
                if (C->isDeclaration() || C->isIntrinsic())
                    clone = C;
                clone = addFunctionClone(cgcFunctionSet, C, clone);
                mapIndirectlyCalledFunctionClone(C, clone);
                hasClonedTargets=true;
            }

            // Wrap indirect calls to we can lookup the target clone at runtime
            if (hasClonedTargets)
                wrapIndirectCall(F, CS);
        }
    }

    void getIndirectCallees(std::vector<Function*> functions, CallSite &CS, std::vector<Function*> &callees, WPAPass *wpa) {
        // Get indirect call callees using the provided points-to analysis
        Value *V = CS.getCalledValue()->stripPointerCasts();
        for (auto F : functions) {
            if (!F->hasAddressTaken())
                continue;
            if (wpa->alias(V, F))
                callees.push_back(F);
        }
    }

    virtual bool runOnModule(Module &M) {
        cgcPassLog("Running...");
        SVFModule* svfModule = LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(M);
        WPAPass *wpa = NULL;
        if (ICalls) {
            wpa = new WPAPass();
            wpa->runOnModule(svfModule);
        }

        // Initialize regular expressions for functions to instrument.
        std::vector<Regex*> FunctionRegexes;
        if (Functions.empty())
            Functions.push_back("main");
        passListRegexInit(FunctionRegexes, Functions);

        // Collect all functions in the module and add root function clones.
        std::set<Function*> cgcFunctionSet;
        std::vector<Function*> functions;
        for (auto &F : M.getFunctionList()) {
            functions.push_back(&F);
            if (F.isDeclaration())
                continue;
            const std::string &FName = F.getName();
            if (!passListRegexMatch(FunctionRegexes, FName))
                continue;
            addFunctionClone(cgcFunctionSet, &F, &F);
        }

        // Start from root function clones and iteratively clone the callgraph.
        while (!cgcFunctionSet.empty()) {
            Function *F = *cgcFunctionSet.begin();
            cgcFunctionSet.erase(cgcFunctionSet.begin());
            cgc(functions, F, cgcFunctionSet, wpa);
        }

        return true;
    }
  };

}

char CallgraphClonePass::ID = 0;
RegisterPass<CallgraphClonePass> MP("cgc", "CallgraphClone Pass");
