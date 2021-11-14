
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

#define DEBUG_TYPE "insert-compares"
#define insertComparesPassLog(M) LLVM_DEBUG(dbgs() << "insertComparesPass: " << M << "\n")

#define oprint(s) (outs() << s << "\n")
#define qprint(s) std::cout << s << std::endl

static cl::list<std::string>
Functions("insert-compares-funcs",
    cl::desc("Specify all the comma-separated function regexes for which to insert missing statements"),
    cl::ZeroOrMore, cl::CommaSeparated, cl::NotHidden);

typedef long imd_t;

// This pass makes sure that all the branches depends on conditions that are composition
// of compare instructions. This allows us to need only cmp instruction taint dump
// to identify tainted conditions using DFSAN.
// We dump branch taint as well, but we need taint for conditions since we are going
// to deal with implicit flows though phi nodes for which we have to analyze conditions
// Therefore we express non-standard `i1` values `%val` aways as `%val1 = cmp %val, true`
namespace {

  class InsertComparesPass : public ModulePass {

  public:
    static char ID;
    unsigned long insertedCMPs = 0;
    InsertComparesPass() : ModulePass(ID) {
    }

    // Recursively search for dependencies on non-cmp instructions for the value V
    // and insert the instruction found in the set, so that we will be able to insert
    // compare operations
    void collectInsertionPoints(Value *V, std::set<Instruction*> &insertionPoints) {
        if (!isa<Instruction>(V)) return;
        Instruction *I = dyn_cast<Instruction>(V);

        // We found the compare, so we are done
        if (isa<CmpInst>(I)) return;

        // We can accept only phi nodes, or binary/unary operations
        if (isa<PHINode>(I) || isa<BinaryOperator>(I) || isa<UnaryOperator>(I)) {
            for (auto op: I->operand_values()) {
                collectInsertionPoints(op, insertionPoints);
            }

        // Otherwise add the instruction to the insertion points to add compares later
        } else {
            insertionPoints.insert(I);
            return;
        }
    }

    void insertCompares(Function *F) {
        LLVMContext &Ctx = F->getContext();
        ConstantInt *BoolTrue = ConstantInt::getTrue(Ctx);

        // conditions on branches, that do not depend exclusively on compares
        std::set<Instruction*> insertionPoints;
        for (auto &BB : *F) {
            if (BranchInst *Term = dyn_cast<BranchInst>(BB.getTerminator())) {
                if (!Term->isConditional()) continue;

                Value *Cond = Term->getCondition();
                collectInsertionPoints(Cond, insertionPoints);
            }
        }

        // insert the missing compares
        for (Instruction *I : insertionPoints) {
            insertedCMPs++;
            Instruction* insertionPoint = I->getNextNode();
            ICmpInst *newI   = new ICmpInst(insertionPoint, ICmpInst::ICMP_EQ, 
                I, BoolTrue, "");
            I->replaceAllUsesWith(newI);
            newI->setOperand(0, I);
        }
    }

    virtual bool runOnModule(Module &M) override {
        insertComparesPassLog("Running...");
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
            insertCompares(F);
        }

        oprint("--------[ INSERT COMPARE STATS ]--------");
        oprint("[+] Inserted CMPs: " << insertedCMPs);
        return true;
    }
 
   void getAnalysisUsage(AnalysisUsage &AU) const override {
    }
  };

}

char InsertComparesPass::ID = 0;
RegisterPass<InsertComparesPass> MP("insert-compares", "Remove Multiple Lifetimes Pass");
