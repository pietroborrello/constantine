
#include <pass.h>

#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IRBuilder.h"

using namespace llvm;

#define DEBUG_TYPE "taintglb"
#define taintglbPassLog(M) LLVM_DEBUG(dbgs() << "TaintGlobalsPass: " << M << "\n")

static cl::list<std::string>
Variables("taintglb-vars",
    cl::desc("Specify all the comma-separated function regexes to taint"),
    cl::ZeroOrMore, cl::CommaSeparated, cl::NotHidden);

typedef long imd_t;

namespace {

  class TaintGlobalsPass : public ModulePass {

  public:
    static char ID;
    TaintGlobalsPass() : ModulePass(ID) {}

    virtual bool runOnModule(Module &M) {
        taintglbPassLog("Running...");

        //
        // Get required analysis passes.
        //
        const DataLayout &DL = M.getDataLayout();


        // Initialize regular expressions for variables to taint.
        std::vector<Regex*> VariableRegexes;
        if (Variables.empty())
            Variables.push_back(".*");
        passListRegexInit(VariableRegexes, Variables);

        // Get the dft_pass_init function to fill with lable initialization instrs
        Function* dft_pass_init = M.getFunction("dft_pass_init");
        assert(dft_pass_init);

        assert(dft_pass_init->arg_size() == 1);
        Argument *input_label = dft_pass_init->args().begin();

        Function* wrap_dft_set_label = M.getFunction("wrap_dft_set_label");
        assert(wrap_dft_set_label);
        // wrap_dft_set_label->dump();

        // Get the first BB and its first instruction
        BasicBlock &EntryBB = dft_pass_init->getEntryBlock();
        Instruction *EntryI = EntryBB.getFirstNonPHI();
        assert(EntryI);

        Type* size_t_Type = IntegerType::getInt64Ty(M.getContext());

        // Taint all the variables that match the regex
        for (GlobalVariable &G : M.getGlobalList()) {
            if (!passListRegexMatch(VariableRegexes, G.getName()))
                continue;

            Type * GlobalType = G.getType()->getElementType();
            unsigned VarSize = DL.getTypeAllocSize((GlobalType));

            taintglbPassLog("setting taint to: " << G.getName().str() << " - size: " << VarSize);
            // std::cout << "setting taint to: " << G.getName().str() << " - size: " << VarSize << std::endl;

            // setup parameters for the set_label call
            std::vector<Value*> args;
            args.push_back(input_label);
            args.push_back(CastInst::CreatePointerCast(&G, wrap_dft_set_label->
                getParamByValType(1)->getPointerTo(), "", EntryI));
            args.push_back(ConstantInt::get(size_t_Type, VarSize, false));

            // Insert the call at the beginning of the function
            CallInst::Create(wrap_dft_set_label, args, "", EntryI);
        }

        // dft_pass_init->dump();
        return true;
    }
  };

}

char TaintGlobalsPass::ID = 0;
RegisterPass<TaintGlobalsPass> MP("taintglb", "Taint Globals Pass");
