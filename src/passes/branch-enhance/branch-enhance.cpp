
#include <pass.h>
#include <iostream>
#include <fstream>
#include <iomanip>

#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Analysis/LoopPass.h"
#include "llvm/IR/PatternMatch.h"

using namespace llvm;
using namespace llvm::PatternMatch;

#define DEBUG_TYPE "branch-enhance"
#define loopenhancePassLog(M) LLVM_DEBUG(dbgs() << "BranchEnhancePass: " << M << "\n")
#define oprint(s) (outs() << s << "\n")

typedef long imd_t;

namespace {

  // Structurize CFG leaves if conditions in the form of:
  // if: 
  //   if (cond) goto then, otherwise goto Flow
  // then:
  //   [... then body ...]
  // Flow:
  //   else_cond = phi(True from if, False from then)
  //   if (else_cond) goto else, otherwise goto end
  // else:
  //   [... else body ...]
  // end:
  // This makes if conditions suboptimal: we need the pass to have a nice CFG,
  // but it is unnecessary to have the if/else stament split in two flows. So 
  // the goal of this pass is to get back a sane condition handling like:
  //
  // if: 
  //   if (cond) goto then, otherwise goto else
  // then:
  //   [... then body ...]
  //   goto end
  // else:
  //   [... else body ...]
  // end:
  //
  // NOTICE: the only check performed to understand if two branches represent
  // an if/else couple is on the set of dependencies. This means that if two consecutive
  // branches have the same dependencies we will mark them as a couple and destroy
  // the world. So please use only with optimized bc, as the compiler will be smart
  // enough to avoid this situation and save ourselves from ethernal damnation.
  class BranchEnhancePass : public ModulePass {

  public:
    static char ID;
    unsigned long NumifElseCouples = 0;
    BranchEnhancePass() : ModulePass(ID) {}

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


    void enhanceBranches(Function *F) {
        DominatorTree *DT      = &getAnalysis<DominatorTreeWrapperPass>(*F).getDomTree();
        PostDominatorTree *PDT = &getAnalysis<PostDominatorTreeWrapperPass>(*F).getPostDomTree();

        std::set<BranchInst*> seenBranches;
        std::set<std::pair<BranchInst*, BranchInst*>> ifElseCouples;
        for (BasicBlock &BB : *F) {
            BranchInst *BI = dyn_cast<BranchInst>(BB.getTerminator());
            if (!BI)
                continue;
            if (!BI->isConditional()) continue;

            // get the successors and the branch condition
            Value *Cond = BI->getCondition();
            assert(BI->getNumSuccessors()==2);
            BasicBlock* TrueBB = BI->getSuccessor(0);
            BasicBlock* FalseBB = BI->getSuccessor(1);


            // structurize CFG should put the Flow block in the `false` side
            // ensure that by checking that either the false side postdominates the true
            // side, or the false side dominates the BB itself (in case of loops)
            assert(PDT->dominates(FalseBB, TrueBB) || DT->dominates(FalseBB, &BB));

            // in the case of a loop we are not interested
            if (DT->dominates(FalseBB, &BB)) continue;

            // if the FalseBB has no conditional branch it cannot be
            BranchInst *FalseBI = dyn_cast<BranchInst>(FalseBB->getTerminator());
            if (!FalseBI)
                continue;
            if (!FalseBI->isConditional()) continue;
            Value *FalseCond = FalseBI->getCondition();

            // now we have to check the dependencies of the condition of BB and the 
            // condition of the FalseBB, if they match, they are part of a pair 
            // of if/else blocks
            std::set<Instruction*> BBdeps;
            searchDependencies(DT, Cond, BBdeps);

            std::set<Instruction*> FalseBBdeps;
            searchDependencies(DT, FalseCond, FalseBBdeps);

            // check if the dependencies are the same
            // N.B: we define dependencies as the variable the branch depends on,
            //      once the phi nodes have been resolved
            if (FalseBBdeps != BBdeps) continue;

            // avoid couples intersection
            if (seenBranches.find(BI) != seenBranches.end() ||
                seenBranches.find(FalseBI) != seenBranches.end()) continue;

            // if the FalseBB contains instructions other than phis and the branch
            // it is not safe to move it
            bool invalidBB = false;
            for (Instruction &I: *FalseBB) {
                if (!isa<PHINode>(&I) && !isa<BranchInst>(&I)) {
                    // oprint(I);
                    invalidBB = true;
                }
            }
            if (invalidBB) continue;

            // Check the merge point, which is the false side of the FalseBI branch
            BasicBlock *MergeBlock = FalseBI->getSuccessor(1);
            // if the merge points is a loop header we are not interested
            if(!PDT->dominates(MergeBlock, FalseBI->getSuccessor(0))) continue;

            // keep track of which couples will have to rewire
            seenBranches.insert(BI);
            seenBranches.insert(FalseBI);
            ifElseCouples.insert(std::make_pair(BI, FalseBI));
            NumifElseCouples++;
        }

        for (auto IfElseBIs : ifElseCouples) {
            BranchInst *IfBI   = IfElseBIs.first;
            BasicBlock *IfHeader = IfBI->getParent();
            BranchInst *ElseBI = IfElseBIs.second;
            BasicBlock *FlowBB = ElseBI->getParent();

            // Get the headers/footers for the if/else sides
            BasicBlock *IfBlock = IfBI->getSuccessor(0);
            BasicBlock *ElseBlock = ElseBI->getSuccessor(0);

            // Get the merge point, which is the false side of the ElseBI branch
            BasicBlock *MergeBlock = ElseBI->getSuccessor(1);

            // The end of the if region is the predecessor of the elseBIBB
            // which is not the IfBIBB
            BasicBlock *IfEnd = nullptr;
            for (BasicBlock *pred : predecessors(FlowBB)) {
                if (pred != IfHeader) {
                    assert(!IfEnd);
                    IfEnd = pred;
                }
            }
            assert(IfEnd);

            // The end of the else region is the predecessor of the merge point
            // which is not the elseBIBB
            BasicBlock *ElseEnd = nullptr;
            for (BasicBlock *pred : predecessors(MergeBlock)) {
                if (pred != FlowBB) {
                    assert(!ElseEnd);
                    ElseEnd = pred;
                }
            }
            assert(ElseEnd);

            // rewire the IFBranch to go to the else block when false
            IfBI->setSuccessor(1, ElseBlock);

            // rewire the end of the if region to go to the merge block
            BranchInst *IfEndBI = dyn_cast<BranchInst>(IfEnd->getTerminator());
            assert(IfEndBI);
            assert(IfEndBI->isUnconditional());
            IfEndBI->setSuccessor(0, MergeBlock);

            // fix phi nodes in the ElseBIBB (which is the block where the else
            // branch was and that will be removed)
            std::set<PHINode*> toMove;
            for (PHINode &phi : ElseBI->getParent()->phis()) {
                // for each phi in the ElseBIBB find the corresponding phi in the
                // merge point that uses it, and take the value of the phi coming from the 
                // IF side and put in the mergePHI coming from the ElseBIBB
                std::set<PHINode*> elseUsers;
                std::set<PHINode*> mergeUsers;
                for (User *user: phi.users()) {
                    // skip the phi node used for the else branch
                    if (user == ElseBI) continue;
                    PHINode *userPHI = dyn_cast<PHINode>(user);
                    assert(userPHI);
                    // if the value is used in the Else side, use the value of the
                    // phi node coming from the header
                    if (DT->dominates(ElseBlock, userPHI->getParent()) && PDT->dominates(ElseEnd, userPHI->getParent())) {
                        elseUsers.insert(userPHI);
                    // if it is used in the merge point we should deal with it
                    } else if (userPHI->getParent() == MergeBlock) {
                        mergeUsers.insert(userPHI);
                    // otherwise insert in the set of phi nodes to be moved at the merge point
                    } else
                        toMove.insert(&phi);

                }

                // fix the elseUsers, using the correct value
                for (PHINode *userPHI: elseUsers) {
                    userPHI->replaceUsesOfWith(&phi, phi.getIncomingValueForBlock(IfHeader));
                }

                // fix the mergeUsers, using the correct value
                for (PHINode *userPHI: mergeUsers) {
                    userPHI->replaceUsesOfWith(&phi, phi.getIncomingValueForBlock(IfEnd));
                }
            }

            // fix the phinodes in the MergeBlock
            for (PHINode &phi : MergeBlock->phis()) {
                Value *val = phi.getIncomingValueForBlock(FlowBB);
                assert(val);
                phi.addIncoming(val, IfEnd);
                phi.removeIncomingValue(FlowBB);
            }

            // move the phi nodes outside the Flow Block, to the merge point
            Instruction *insertionPoint = &*MergeBlock->getInstList().begin();
            for (PHINode *phi: toMove) {
                phi->moveBefore(insertionPoint);
                Value *val = phi->getIncomingValueForBlock(IfHeader);
                assert(val);
                phi->addIncoming(val, ElseEnd);
                phi->removeIncomingValue(IfHeader);
            }

            // oprint("MATCH:");
            // oprint(*IfBI);
            // oprint(*ElseBI);

            // oprint(*MergeBlock);

            // finally remove the Flow Block
            FlowBB->eraseFromParent();
        }
    }

    bool runOnModule(Module &M) override {
        for (auto &F : M.getFunctionList()) {
            if (F.isDeclaration())
                continue;
            enhanceBranches(&F);
        }
        oprint("IF/ELSE DETECTED: " << NumifElseCouples);
        return true;
   }
 
   void getAnalysisUsage(AnalysisUsage &AU) const override {
        AU.addRequired<DominatorTreeWrapperPass>();
        AU.addRequired<PostDominatorTreeWrapperPass>();
   }
  };

}

char BranchEnhancePass::ID = 0;
RegisterPass<BranchEnhancePass> MP("branch-enhance", "Loop Enhance Pass");
