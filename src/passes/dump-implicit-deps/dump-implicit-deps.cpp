
#include <pass.h>
#include <iostream>
#include <fstream>
#include <iomanip>

#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/PatternMatch.h"


using namespace llvm;
using namespace llvm::PatternMatch;

#define DEBUG_TYPE "dumpImplicitDeps"
#define dumpImplicitDepsPassLog(M) LLVM_DEBUG(dbgs() << "DumpImplicitDepsPass: " << M << "\n")
#define oprint(s) (outs() << s << "\n")

typedef long imd_t;

static cl::list<std::string>
Functions("dump-funcs",
    cl::desc("Specify all the comma-separated function regexes to dump"),
    cl::ZeroOrMore, cl::CommaSeparated, cl::NotHidden);

namespace {

  // Dump the implicit dependencies of each branch, to counter structurizeCFG which 
  // introduces them
  // -> For each branch which depends on a phi node, gather all the incoming values
  // of such phi nodes and add them to the implicit dependencies
  // moreover add recursively the conditions of the branches that lead to the phi node
  // decision
  // NOTICE: this pass does just simple analyses and assumes it runs after structurize-cfg
  class DumpImplicitDepsPass : public ModulePass {

  public:
    static char ID;

    // Keep track of all the implicit dependencies of a particular instruction
    std::map<Instruction*, std::set<Instruction*>> DependencyMap;

    DumpImplicitDepsPass() : ModulePass(ID) {}

    // Given a value, recursively search for all its implicit dependencies
    // and save them to the provided set
    void searchDependencies(DominatorTree *DT, Value *V, std::set<Instruction*>&dependencies) {
        // First, if the value is an inverted one (usually created by stucturize-cfg)
        // unwrap it
        Value *NotCondition;
        if (match(V, m_Not(m_Value(NotCondition))))
            V = NotCondition;
        
        // If the value is not an instruction it cannot have implicit deps
        // and it is not itself a dependency
        if (Instruction *I = dyn_cast<Instruction>(V)) {
            BasicBlock *BB = I->getParent();

            // if the value is a phi node we should visit its incoming values
            if (PHINode *Phi = dyn_cast<PHINode>(I)) {

                for (unsigned int i = 0; i < Phi->getNumIncomingValues(); ++i) {
                    Value *IncomingVal = Phi->getIncomingValue(i);
                    BasicBlock *IncomingBlock = Phi->getIncomingBlock(i);
                    
                    // Add the dependencies of the incoming val
                    searchDependencies(DT, IncomingVal, dependencies);
                    
                    // And add the condition leading to the phi node decision to the
                    // implicit dependencies

                    // If the incoming block does not have a conditional branch
                    // we are looking at the wrong side of the structurized-cfg branch
                    // so skip the recursive call for this side and call for the next
                    // recall that the CFG will be in the form of:
                    ///
                    /// \verbatim
                    /// 1
                    /// ||
                    /// | |
                    /// 2 |
                    /// | /
                    /// |/
                    /// 3
                    /// ||   Where:
                    /// | |  1 = "If" block, calculates the condition
                    /// 4 |  2 = "Then" subregion, runs if the condition is true
                    /// | /  3 = "Flow" blocks, newly inserted flow blocks, rejoins the flow
                    /// |/   4 = "Else" optional subregion, runs if the condition is false
                    /// 5    5 = "End" block, also rejoins the control flow
                    /// \endverbatim
                    BranchInst *IncomingTerm = dyn_cast<BranchInst>(IncomingBlock->getTerminator());
                    assert(IncomingTerm);
                    if (!IncomingTerm->isConditional()) {
                        continue;
                    }

                    assert(DT->dominates(IncomingBlock, BB));
                    Value *IncomingCond = IncomingTerm->getCondition();
                    searchDependencies(DT, IncomingCond, dependencies);
                }

            // if the value is not a phi node, check if it is a compare
            // (i.e. found the origin of the implicit flow)
            } else if (isa<CmpInst>(I)){
                dependencies.insert(I);
            // otherwise visit all of the operands
            } else {
                for (Value * op: I->operand_values()) {
                    searchDependencies(DT, op, dependencies);
                }
            }
        }
    }

    void searchImplicitDeps(Function *F) {
        oprint(F->getName());
        DominatorTree *DT = &getAnalysis<DominatorTreeWrapperPass>(*F).getDomTree();

        // Dump the implicit depencencies of every branch that has as condition a 
        // phi node
        for (auto &BB : *F) {
            if (BranchInst *Term = dyn_cast<BranchInst>(BB.getTerminator())) {
                if (!Term->isConditional()) continue;

                Value *Cond = Term->getCondition();
                // We consider only phi nodes to find implicit dependencies
                if (PHINode *PhiCond = dyn_cast<PHINode>(Cond)) {
                    searchDependencies(DT, PhiCond, DependencyMap[Term]);
                }
            }
        }

        oprint("-------------- [ IMPLICIT DEPS ] --------------");
        for (auto IandDeps : DependencyMap) {
            Instruction *I = IandDeps.first;
            oprint(*I);
            for (Instruction *Dep : IandDeps.second) {
                oprint("    - " << *Dep);
            }
        }
        oprint("-----------------------------------------------");
    }

    virtual bool runOnModule(Module &M) override {

        std::vector<Regex*> FunctionRegexes;
        if (Functions.empty())
            Functions.push_back(".*");
        passListRegexInit(FunctionRegexes, Functions);

        for (auto &F : M.getFunctionList()) {
            if (F.isDeclaration())
                continue;
            const std::string &FName = F.getName();
            if (!passListRegexMatch(FunctionRegexes, FName))
                continue;
            if (F.getSection().equals("dfl_code") || F.getSection().equals("cfl_code") 
                || F.getSection().equals("cgc_code") || F.getSection().equals("icp_code"))
                continue;
            searchImplicitDeps(&F);
            DependencyMap.clear();
        }
        return false;
   }
 
   void getAnalysisUsage(AnalysisUsage &AU) const override {
        AU.addRequired<DominatorTreeWrapperPass>();
    }
  };

}

char DumpImplicitDepsPass::ID = 0;
RegisterPass<DumpImplicitDepsPass> MP("dump-implicit-deps", "Dump Implicit Deps Pass");
