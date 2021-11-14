
#include <pass.h>

using namespace llvm;

#define DEBUG_TYPE "coverage-id"
#define coverageidPassLog(M) LLVM_DEBUG(dbgs() << "CoverageIDPass: " << M << "\n")

static cl::list<std::string>
Functions("coverage-id-funcs",
    cl::desc("Specify all the comma-separated function regexes to coverage-id"),
    cl::ZeroOrMore, cl::CommaSeparated, cl::NotHidden);

static cl::opt<bool>
FuncGIDs("coverage-id-f-gids",
    cl::desc("Generate global function IDs."),
    cl::init(false), cl::NotHidden);

static cl::opt<bool>
BBGIDs("coverage-id-b-gids",
    cl::desc("Generate global basic block IDs."),
    cl::init(false), cl::NotHidden);

static cl::opt<bool>
InstGIDs("coverage-id-i-gids",
    cl::desc("Generate global instruction IDs."),
    cl::init(false), cl::NotHidden);

static cl::opt<bool>
BBFIDs("coverage-id-b-fids",
    cl::desc("Generate function-local basic block IDs."),
    cl::init(false), cl::NotHidden);

static cl::opt<bool>
InstFIDs("coverage-id-i-fids",
    cl::desc("Generate basic function-local instruction IDs."),
    cl::init(false), cl::NotHidden);

static cl::opt<bool>
InstBIDs("coverage-id-i-bids",
    cl::desc("Generate basic block-local instruction IDs."),
    cl::init(false), cl::NotHidden);

typedef long imd_t;

namespace {

  class CoverageIDPass : public ModulePass {

  public:
    static char ID;
    CoverageIDPass() : ModulePass(ID) {}

    void setIntMetadata(Value *V, const char *key, imd_t value) {
        LLVMContext& C = V->getContext();
        MDNode* N = MDNode::get(C, ConstantAsMetadata::get(ConstantInt::get(C, APInt(sizeof(imd_t)*8, value, true))));
        if (Instruction *I = dyn_cast<Instruction>(V))
            I->setMetadata(key, N);
        else if (BasicBlock *BB = dyn_cast<BasicBlock>(V))
            BB->getTerminator()->setMetadata(key, N);
        else if (Function *F = dyn_cast<Function>(V))
            F->setMetadata(key, N);
        else
            assert(0 && "Not implemented!");
    }

    virtual bool runOnModule(Module &M) {
        coverageidPassLog("Running...");

        // Initialize regular expressions for functions to instrument.
        std::vector<Regex*> FunctionRegexes;
        if (Functions.empty())
            Functions.push_back(".*");
        passListRegexInit(FunctionRegexes, Functions);

        // Go over all the functions and basic blocks and set ID metadata
        imd_t FuncGID = 0, BBGID = 0, InstGID = 0;
        for (auto &F : M.getFunctionList()) {
            if (F.isDeclaration())
                continue;
            const std::string &FName = F.getName();
            if (!passListRegexMatch(FunctionRegexes, FName))
                continue;
            if (FuncGIDs)
                setIntMetadata(&F, "f-gid", ++FuncGID);
            imd_t BBFID = 0, InstFID = 0;
            for (auto &BB : F) {
                if (BBGIDs)
                    setIntMetadata(&BB, "b-gid", ++BBGID);
                if (BBFIDs)
                    setIntMetadata(&BB, "b-fid", ++BBFID);
                imd_t InstBID = 0;
                for (auto &I : BB) {
                    if (InstGIDs)
                        setIntMetadata(&I, "i-gid", ++InstGID);
                    if (InstBIDs)
                        setIntMetadata(&I, "i-bid", ++InstBID);
                    if (InstFIDs)
                        setIntMetadata(&I, "i-fid", ++InstFID);
                }
            }
        }

        return true;
    }
  };

}

char CoverageIDPass::ID = 0;
RegisterPass<CoverageIDPass> MP("coverage-id", "CoverageID Pass");
