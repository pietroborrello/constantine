
#include <pass.h>
#include <fstream>

#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/PatternMatch.h"

using namespace llvm;
using namespace llvm::PatternMatch;

#define DEBUG_TYPE "loadtainted"
#define loadtaintedPassLog(M) LLVM_DEBUG(dbgs() << "LoadTaintedPass: " << M << "\n")
#define oprint(s) (outs() << s << "\n")

static cl::opt<std::string>
TaintedFilename("tainted-file",
    cl::desc("The file to load taints from"),
    cl::init("dft.log"), cl::NotHidden);

static cl::opt<bool>
IgnoreFixed("taint-ignore-error-conditions",
    cl::desc("Avoid tainting branches or conditions that represent error handlings"),
    cl::init(true), cl::NotHidden);

static cl::opt<bool>
ImplicitFlows("taint-implicit-flows",
    cl::desc("Forward taint information through phi-based implicit flows"),
    cl::init(true), cl::NotHidden);

static cl::opt<bool>
TaintAll("taint-all",
    cl::desc("Artificially taint everything (for eval purposes)"),
    cl::init(false), cl::NotHidden);

typedef long imd_t;

namespace {

  class LoadTaintedPass : public ModulePass {

  public:
    static char ID;
    unsigned long totalBranches    = 0;
    unsigned long varyingBranches = 0;
    unsigned long uninterestingBranches = 0;

    unsigned long taintedBranches    = 0;
    unsigned long nonTaintedBranches = 0;

    // Keep track of all the implicit dependencies of a particular instruction
    std::map<Instruction*, std::set<Instruction*>> DependencyMap;

    LoadTaintedPass() : ModulePass(ID) {}

    // --------------- [BEGIN IMPLICIT TAINT CODE] ----------------
    // TAKEN FROM `dump-implicit-deps.cpp` PASS, PLS KEEP THEM COHERENT
    // Dump the implicit dependencies of each branch, to counter structurizeCFG which 
    // introduces them
    // -> For each branch which depends on a phi node, gather all the incoming values
    // of such phi nodes and add them to the implicit dependencies
    // moreover add recursively the conditions of the branches that lead to the phi node
    // decision
    // NOTICE: this pass does just simple analyses and assumes it runs after structurize-cfg

    // Given a value, recursively search for all its implicit dependencies
    // and save them to the provided set
    void searchDependencies(DominatorTree *DT, Value *V, std::set<Instruction*>&dependencies, std::set<Value*>&visited) {
        // First, if the value is an inverted one (usually created by stucturize-cfg)
        // unwrap it
        Value *NotCondition;
        if (match(V, m_Not(m_Value(NotCondition))))
            V = NotCondition;

        // Avoid visiting already visited values
        if(visited.find(V) != visited.end())
            return;
        visited.insert(V);
        
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
                    searchDependencies(DT, IncomingVal, dependencies, visited);
                    
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

                    // if(!DT->dominates(IncomingBlock, BB)) continue;
                    assert(DT->dominates(IncomingBlock, BB));
                    Value *IncomingCond = IncomingTerm->getCondition();
                    searchDependencies(DT, IncomingCond, dependencies, visited);
                }

            // if the value is not a phi node, check if it is a compare
            // (i.e. found the origin of the implicit flow)
            } else if (isa<CmpInst>(I)){
                dependencies.insert(I);
            // otherwise visit all of the operands
            } else {
                for (Value * op: I->operand_values()) {
                    searchDependencies(DT, op, dependencies, visited);
                }
            }
        }
    }

    void searchImplicitDeps(Function *F) {
        DominatorTree *DT = &getAnalysis<DominatorTreeWrapperPass>(*F).getDomTree();

        // Dump the implicit depencencies of every branch that has as condition a 
        // phi node
        for (auto &BB : *F) {
            if (BranchInst *Term = dyn_cast<BranchInst>(BB.getTerminator())) {
                if (!Term->isConditional()) continue;

                Value *Cond = Term->getCondition();
                // We consider only phi nodes to find implicit dependencies
                if (PHINode *PhiCond = dyn_cast<PHINode>(Cond)) {
                    std::set<Value*> visitedValues;
                    searchDependencies(DT, PhiCond, DependencyMap[Term], visitedValues);
                }
            }
        }
    }
    // --------------- [END IMPLICIT TAINT CODE] ----------------

    void setInstructionTaint(Instruction *I, bool taint) {
        LLVMContext& C = I->getContext();
        MDNode* N = MDNode::get(C, ConstantAsMetadata::get(ConstantInt::get(C, APInt(sizeof(imd_t)*8, taint, true))));
        I->setMetadata("t", N);
    }

    bool getInstructionTaint(const Instruction &I) {
        MDNode* N;
        Constant *val;
        N = I.getMetadata("t");
        if (N == NULL) return false;
        val = dyn_cast<ConstantAsMetadata>(N->getOperand(0))->getValue();
        assert(val);
        int taint = cast<ConstantInt>(val)->getSExtValue();
        return taint;
    }

    static bool isTainted(std::string& taint_str) {
        // Assume that if no taint information are present, we are dumping only
        // tainted instructions
        if (!taint_str.compare("000000")) return true;

        for(char c: taint_str) {
            if(c == '0' || c == 'B') continue;
            if(isupper(c)) return true;
        }
        return false;
    }

    // Check if we marked the instruction with an uninteresting direction that 
    // always takes
    bool isInstructionUninteresting(Instruction &I) {
        MDNode* N;
        N = I.getMetadata("uninteresting_direction");
        if (N == NULL) return false;
        return true;
    }

    // This is a bit ugly, but we want separate checks since a branch may also
    // report both flags at once, so we should differentiate between a branch that
    // always reports the same flag and a branch which may report different flag
    // combinations at different times
    static bool isTaken(std::string &taint_str) {
        // check that we are dealing with a branch/cmp instruction
        assert(taint_str.find('B') != std::string::npos || 
            taint_str.find('b') != std::string::npos);

        // return true if the branch is taken
        return taint_str.find('B') != std::string::npos;
    }
    static bool isNotTaken(std::string &taint_str) {
        // check that we are dealing with a branch/cmp instruction
        assert(taint_str.find('B') != std::string::npos || 
            taint_str.find('b') != std::string::npos);

        // return true if the branch is not taken
        return taint_str.find('b') != std::string::npos;
    }

    // Check if a taint string may be referred to a branch or cmp by checking if
    // it contains the flags b/B.
    static bool isBranchOrCmp(std::string &taint_str) {
        return (taint_str.find('B') != std::string::npos || 
            taint_str.find('b') != std::string::npos);
    }

    virtual bool runOnModule(Module &M) override {
        loadtaintedPassLog("Running...");

        // std::cout << TaintedFilename << std::endl;

        std::ifstream TaintedFile(TaintedFilename);

        std::map<std::pair<int,int>,bool> tainted;

        std::set<std::pair<int,int>> branchesAndCmp;
        std::set<std::pair<int,int>> takenBranchesAndCmp;
        std::set<std::pair<int,int>> nonTakenBranchesAndCmp;

        int b_gid,i_bid;
        std::string taint_str;
        while (TaintedFile >> taint_str >> b_gid >> i_bid)
        {
            // std::cout << b_gid << " " << i_bid << " " << taint_str << std::endl;
            tainted[std::pair<int,int>(b_gid, i_bid)] |= isTainted(taint_str);
            // if (isTainted(taint_str)) {
            //     std::cout << b_gid << " " << i_bid << " " << taint_str << std::endl;
            // }
            
            // If this is a branch/cmp we add the pair also to the branch/cmp taken-nontaken
            // tracking, we will check later if the pair actually refers to a branch/cmp
            // when we will have access to the actual instruction
            if (isBranchOrCmp(taint_str)) {
                branchesAndCmp.insert(std::make_pair(b_gid, i_bid));
                if (isTaken(taint_str)) takenBranchesAndCmp.insert(std::make_pair(b_gid, i_bid));
                if (isNotTaken(taint_str)) nonTakenBranchesAndCmp.insert(std::make_pair(b_gid, i_bid));
            }
        }

        TaintedFile.close();

        MDNode* N;
        Constant *val;
        for (auto &F : M.getFunctionList()) {
            if (F.isDeclaration())
                continue;
            for (llvm::BasicBlock &BB : F) {
                N = BB.getTerminator()->getMetadata("b-gid");
                assert(N);
                val = dyn_cast<ConstantAsMetadata>(N->getOperand(0))->getValue();
                assert(val);
                b_gid = cast<ConstantInt>(val)->getSExtValue();
                for (auto &I : BB) {
                    N = I.getMetadata("i-bid");
                    assert(N);
                    val = dyn_cast<ConstantAsMetadata>(N->getOperand(0))->getValue();
                    assert(val);
                    i_bid = cast<ConstantInt>(val)->getSExtValue();
                    // Artificially taint all if required
                    if (TaintAll) {
                        LLVMContext& C = I.getContext();
                        MDNode* N = MDNode::get(C, ConstantAsMetadata::get(ConstantInt::get(C, APInt(sizeof(imd_t)*8, true, true))));
                        I.setMetadata("t", N);
                        continue;
                    }
                    auto taint = tainted.find(std::pair<int,int>(b_gid, i_bid));
                    if (taint != tainted.end()) {
                        // if (taint->second) {
                        //     std::cout << b_gid << " " << i_bid << "," << taint->second << std::endl;
                        // }

                        bool taint_value = taint->second;

                        // if we have a branch, keep track if it is varying and 
                        // if it is not the case, keep track of the only direction seen
                        bool interesting = true;
                        // only valid if `interesting==false`. true->always_taken, false->always_nontaken
                        bool uninteresting_direction = 0;

                        // If the instruction is a conditional branch, we may have to check
                        // that the branch is actually both taken and non taken
                        // otherwise the branch may represent a special-case/error
                        // contition that the user may not be interested in protecting
                        if (BranchInst *BI = dyn_cast<BranchInst>(&I)) {
                            totalBranches++;
                            if (IgnoreFixed && BI->isConditional() &&
                                branchesAndCmp.find(std::make_pair(b_gid, i_bid)) != branchesAndCmp.end()) {
                                // if the branch is both on taken and not taken
                                // then it is a varying branch and it is ok
                                if (takenBranchesAndCmp.find(std::make_pair(b_gid, i_bid)) != takenBranchesAndCmp.end() &&
                                    nonTakenBranchesAndCmp.find(std::make_pair(b_gid, i_bid)) != nonTakenBranchesAndCmp.end()) {
                                    varyingBranches++;
                                // otherwise the branch is not interesting
                                } else {
                                    taint_value = false;
                                    interesting = false;
                                    uninteresting_direction = (takenBranchesAndCmp.find(std::make_pair(b_gid, i_bid)) != takenBranchesAndCmp.end());
                                }
                            }
                            if (taint_value) taintedBranches++;
                            else nonTaintedBranches++;
                        // Same for filtering taints on uninteresting cmp instructions
                        } else if (CmpInst *CI = dyn_cast<CmpInst>(&I)) {
                            if (IgnoreFixed && branchesAndCmp.find(std::make_pair(b_gid, i_bid)) != branchesAndCmp.end()) {
                                // if the condition is both true and false
                                // then it is a varying condition and it is ok
                                if (takenBranchesAndCmp.find(std::make_pair(b_gid, i_bid)) != takenBranchesAndCmp.end() &&
                                    nonTakenBranchesAndCmp.find(std::make_pair(b_gid, i_bid)) != nonTakenBranchesAndCmp.end()) {
                                // otherwise the condition is not interesting
                                } else {
                                    taint_value = false;
                                }
                            }
                        }

                        LLVMContext& C = I.getContext();
                        MDNode* N = MDNode::get(C, ConstantAsMetadata::get(ConstantInt::get(C, APInt(sizeof(imd_t)*8, taint_value, true))));
                        I.setMetadata("t", N);
                        if (!interesting) {
                            MDNode* N = MDNode::get(C, ConstantAsMetadata::get(ConstantInt::get(C, APInt(sizeof(imd_t)*8, uninteresting_direction, true))));
                            I.setMetadata("uninteresting_direction", N);
                            uninterestingBranches++;
                        }
                    } else {
                        // set any instruction without taint info as not tainted
                        LLVMContext& C = I.getContext();
                        MDNode* N = MDNode::get(C, ConstantAsMetadata::get(ConstantInt::get(C, APInt(sizeof(imd_t)*8, 0, true))));
                        I.setMetadata("t", N);
                    }
                }
            }
            if (ImplicitFlows) {
                // Search for implicit dependencies in the function
                searchImplicitDeps(&F);

                // For each branch instruction for which we have identified implicit 
                // dependencies, set its taint info as the `or` of all of them
                // unless the branch is uninteresting
                for (auto IandDeps : DependencyMap) {
                    Instruction *I = IandDeps.first;
                    auto Deps      = IandDeps.second;
                    bool taint_val = getInstructionTaint(*I);
                    if (isInstructionUninteresting(*I)) continue;
                    
                    for (Instruction *Dep : Deps) {
                        taint_val |= getInstructionTaint(*Dep);
                    }
                    if (taint_val != getInstructionTaint(*I)) {
                        nonTaintedBranches--;
                        taintedBranches++;
                        assert(taint_val);
                    }
                    setInstructionTaint(I, taint_val);
                }

                DependencyMap.clear();
            }
        }

        oprint("--------[ LOAD-TAINTED STATS ]--------");
        oprint("[+] Seen Branches: " << totalBranches);
        oprint("    [+] Varying:       " << varyingBranches);
        oprint("    [+] Uninteresting: " << uninterestingBranches);
        oprint("    [+] Tainted:       " << taintedBranches);
        oprint("    [+] NonTainted:    " << nonTaintedBranches);
        return false;
    }

    void getAnalysisUsage(AnalysisUsage &AU) const override {
        AU.addRequired<DominatorTreeWrapperPass>();
    }
  };

}

char LoadTaintedPass::ID = 0;
RegisterPass<LoadTaintedPass> MP("loadtainted", "Load Tainted Pass");
