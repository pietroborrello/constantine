//===- UnifyLoopExits.cpp - Redirect exiting edges to one block -*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// For each natural loop with multiple exit blocks, this pass creates a new
// block N such that all exiting blocks now branch to N, and then control flow
// is redistributed to all the original exit blocks.
//
// Limitation: This assumes that all terminators in the CFG are direct branches
//             (the "br" instruction). The presence of any other control flow
//             such as indirectbr, switch or callbr will cause an assert.
//
//===----------------------------------------------------------------------===//

#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/PatternMatch.h"
#include "llvm/InitializePasses.h"
#include "llvm/Transforms/Utils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/ADT/SetVector.h"

#define DEBUG_TYPE "unify-loop-exits"

using namespace llvm;
using namespace llvm::PatternMatch;

namespace {
struct UnifyLoopExits : public FunctionPass {
  static char ID;
  UnifyLoopExits() : FunctionPass(ID) {
    // initializeUnifyLoopExitsPass(*PassRegistry::getPassRegistry());
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequiredID(LowerSwitchID);
    AU.addRequired<LoopInfoWrapperPass>();
    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addPreservedID(LowerSwitchID);
    AU.addPreserved<LoopInfoWrapperPass>();
    AU.addPreserved<DominatorTreeWrapperPass>();
  }

  bool runOnFunction(Function &F) override;
};
} // namespace

char UnifyLoopExits::ID = 0;

// FunctionPass *llvm::createUnifyLoopExitsPass() { return new UnifyLoopExits(); }

// INITIALIZE_PASS_BEGIN(UnifyLoopExits, "unify-loop-exits",
//                       "Fixup each natural loop to have a single exit block",
//                       false /* Only looks at CFG */, false /* Analysis Pass */)
// INITIALIZE_PASS_DEPENDENCY(LowerSwitch)
// INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
// INITIALIZE_PASS_DEPENDENCY(LoopInfoWrapperPass)
// INITIALIZE_PASS_END(UnifyLoopExits, "unify-loop-exits",
//                     "Fixup each natural loop to have a single exit block",
//                     false /* Only looks at CFG */, false /* Analysis Pass */)

using BBPredicates = DenseMap<BasicBlock *, PHINode *>;
using BBSetVector = SetVector<BasicBlock *>;

Value *invertCondition(Value *Condition) {
  // First: Check if it's a constant
  if (Constant *C = dyn_cast<Constant>(Condition))
    return ConstantExpr::getNot(C);

  // Second: If the condition is already inverted, return the original value
  Value *NotCondition;
  if (match(Condition, m_Not(m_Value(NotCondition))))
    return NotCondition;

  BasicBlock *Parent = nullptr;
  Instruction *Inst = dyn_cast<Instruction>(Condition);
  if (Inst)
    Parent = Inst->getParent();
  else if (Argument *Arg = dyn_cast<Argument>(Condition))
    Parent = &Arg->getParent()->getEntryBlock();
  assert(Parent && "Unsupported condition to invert");

  // Third: Check all the users for an invert
  for (User *U : Condition->users())
    if (Instruction *I = dyn_cast<Instruction>(U))
      if (I->getParent() == Parent && match(I, m_Not(m_Specific(Condition))))
        return I;

  // Last option: Create a new instruction
  auto *Inverted =
      BinaryOperator::CreateNot(Condition, Condition->getName() + ".inv");
  if (Inst && !isa<PHINode>(Inst))
    Inverted->insertAfter(Inst);
  else
    Inverted->insertBefore(&*Parent->getFirstInsertionPt());
  return Inverted;
}

// After creating a control flow hub, the operands of PHINodes in an outgoing
// block Out no longer match the predecessors of that block. Predecessors of Out
// that are incoming blocks to the hub are now replaced by just one edge from
// the hub. To match this new control flow, the corresponding values from each
// PHINode must now be moved a new PHINode in the first guard block of the hub.
//
// This operation cannot be performed with SSAUpdater, because it involves one
// new use: If the block Out is in the list of Incoming blocks, then the newly
// created PHI in the Hub will use itself along that edge from Out to Hub.
static void reconnectPhis(BasicBlock *Out, BasicBlock *GuardBlock,
                          const SetVector<BasicBlock *> &Incoming,
                          BasicBlock *FirstGuardBlock) {
  auto I = Out->begin();
  while (I != Out->end() && isa<PHINode>(I)) {
    auto Phi = cast<PHINode>(I);
    auto NewPhi =
        PHINode::Create(Phi->getType(), Incoming.size(),
                        Phi->getName() + ".moved", &FirstGuardBlock->back());
    for (auto In : Incoming) {
      Value *V = UndefValue::get(Phi->getType());
      if (In == Out) {
        V = NewPhi;
      } else if (Phi->getBasicBlockIndex(In) != -1) {
        V = Phi->removeIncomingValue(In, false);
      }
      NewPhi->addIncoming(V, In);
    }
    assert(NewPhi->getNumIncomingValues() == Incoming.size());
    if (Phi->getNumOperands() == 0) {
      Phi->replaceAllUsesWith(NewPhi);
      I = Phi->eraseFromParent();
      continue;
    }
    Phi->addIncoming(NewPhi, GuardBlock);
    ++I;
  }
}

// Redirects the terminator of the incoming block to the first guard
// block in the hub. The condition of the original terminator (if it
// was conditional) and its original successors are returned as a
// tuple <condition, succ0, succ1>. The function additionally filters
// out successors that are not in the set of outgoing blocks.
//
// - condition is non-null iff the branch is conditional.
// - Succ1 is non-null iff the sole/taken target is an outgoing block.
// - Succ2 is non-null iff condition is non-null and the fallthrough
//         target is an outgoing block.
static std::tuple<Value *, BasicBlock *, BasicBlock *>
redirectToHub(BasicBlock *BB, BasicBlock *FirstGuardBlock,
              const BBSetVector &Outgoing) {
  auto Branch = cast<BranchInst>(BB->getTerminator());
  auto Condition = Branch->isConditional() ? Branch->getCondition() : nullptr;

  BasicBlock *Succ0 = Branch->getSuccessor(0);
  BasicBlock *Succ1 = nullptr;
  Succ0 = Outgoing.count(Succ0) ? Succ0 : nullptr;

  if (Branch->isUnconditional()) {
    Branch->setSuccessor(0, FirstGuardBlock);
    assert(Succ0);
  } else {
    Succ1 = Branch->getSuccessor(1);
    Succ1 = Outgoing.count(Succ1) ? Succ1 : nullptr;
    assert(Succ0 || Succ1);
    if (Succ0 && !Succ1) {
      Branch->setSuccessor(0, FirstGuardBlock);
    } else if (Succ1 && !Succ0) {
      Branch->setSuccessor(1, FirstGuardBlock);
    } else {
      Branch->eraseFromParent();
      BranchInst::Create(FirstGuardBlock, BB);
    }
  }

  assert(Succ0 || Succ1);
  return std::make_tuple(Condition, Succ0, Succ1);
}

// Capture the existing control flow as guard predicates, and redirect
// control flow from every incoming block to the first guard block in
// the hub.
//
// There is one guard predicate for each outgoing block OutBB. The
// predicate is a PHINode with one input for each InBB which
// represents whether the hub should transfer control flow to OutBB if
// it arrived from InBB. These predicates are NOT ORTHOGONAL. The Hub
// evaluates them in the same order as the Outgoing set-vector, and
// control branches to the first outgoing block whose predicate
// evaluates to true.
static void convertToGuardPredicates(
    BasicBlock *FirstGuardBlock, BBPredicates &GuardPredicates,
    SmallVectorImpl<WeakVH> &DeletionCandidates, const BBSetVector &Incoming,
    const BBSetVector &Outgoing) {
  auto &Context = Incoming.front()->getContext();
  auto BoolTrue = ConstantInt::getTrue(Context);
  auto BoolFalse = ConstantInt::getFalse(Context);

  // The predicate for the last outgoing is trivially true, and so we
  // process only the first N-1 successors.
  for (int i = 0, e = Outgoing.size() - 1; i != e; ++i) {
    auto Out = Outgoing[i];
    LLVM_DEBUG(dbgs() << "Creating guard for " << Out->getName() << "\n");
    auto Phi =
        PHINode::Create(Type::getInt1Ty(Context), Incoming.size(),
                        StringRef("Guard.") + Out->getName(), FirstGuardBlock);
    GuardPredicates[Out] = Phi;
  }

  for (auto In : Incoming) {
    Value *Condition;
    BasicBlock *Succ0;
    BasicBlock *Succ1;
    std::tie(Condition, Succ0, Succ1) =
        redirectToHub(In, FirstGuardBlock, Outgoing);

    // Optimization: Consider an incoming block A with both successors
    // Succ0 and Succ1 in the set of outgoing blocks. The predicates
    // for Succ0 and Succ1 complement each other. If Succ0 is visited
    // first in the loop below, control will branch to Succ0 using the
    // corresponding predicate. But if that branch is not taken, then
    // control must reach Succ1, which means that the predicate for
    // Succ1 is always true.
    bool OneSuccessorDone = false;
    for (int i = 0, e = Outgoing.size() - 1; i != e; ++i) {
      auto Out = Outgoing[i];
      auto Phi = GuardPredicates[Out];
      if (Out != Succ0 && Out != Succ1) {
        Phi->addIncoming(BoolFalse, In);
        continue;
      }
      // Optimization: When only one successor is an outgoing block,
      // the predicate is always true.
      if (!Succ0 || !Succ1 || OneSuccessorDone) {
        Phi->addIncoming(BoolTrue, In);
        continue;
      }
      assert(Succ0 && Succ1);
      OneSuccessorDone = true;
      if (Out == Succ0) {
        Phi->addIncoming(Condition, In);
        continue;
      }
      auto Inverted = invertCondition(Condition);
      DeletionCandidates.push_back(Condition);
      Phi->addIncoming(Inverted, In);
    }
  }
}

// For each outgoing block OutBB, create a guard block in the Hub. The
// first guard block was already created outside, and available as the
// first element in the vector of guard blocks.
//
// Each guard block terminates in a conditional branch that transfers
// control to the corresponding outgoing block or the next guard
// block. The last guard block has two outgoing blocks as successors
// since the condition for the final outgoing block is trivially
// true. So we create one less block (including the first guard block)
// than the number of outgoing blocks.
static void createGuardBlocks(SmallVectorImpl<BasicBlock *> &GuardBlocks,
                              Function *F, const BBSetVector &Outgoing,
                              BBPredicates &GuardPredicates, StringRef Prefix) {
  for (int i = 0, e = Outgoing.size() - 2; i != e; ++i) {
    GuardBlocks.push_back(
        BasicBlock::Create(F->getContext(), Prefix + ".guard", F));
  }
  assert(GuardBlocks.size() == GuardPredicates.size());

  // To help keep the loop simple, temporarily append the last
  // outgoing block to the list of guard blocks.
  GuardBlocks.push_back(Outgoing.back());

  for (int i = 0, e = GuardBlocks.size() - 1; i != e; ++i) {
    auto Out = Outgoing[i];
    assert(GuardPredicates.count(Out));
    BranchInst::Create(Out, GuardBlocks[i + 1], GuardPredicates[Out],
                       GuardBlocks[i]);
  }

  // Remove the last block from the guard list.
  GuardBlocks.pop_back();
}

// For each outgoing block OutBB, create a guard block in the Hub. The
// first guard block was already created outside, and available as the
// first element in the vector of guard blocks.
//
// Each guard block terminates in a conditional branch that transfers
// control to the corresponding outgoing block or the next guard
// block. The last guard block has two outgoing blocks as successors
// since the condition for the final outgoing block is trivially
// true. So we create one less block (including the first guard block)
// than the number of outgoing blocks.
BasicBlock *CreateControlFlowHub(
    DomTreeUpdater *DTU, SmallVectorImpl<BasicBlock *> &GuardBlocks,
    const BBSetVector &Incoming, const BBSetVector &Outgoing,
    const StringRef Prefix) {
  auto F = Incoming.front()->getParent();
  auto FirstGuardBlock =
      BasicBlock::Create(F->getContext(), Prefix + ".guard", F);

  SmallVector<DominatorTree::UpdateType, 16> Updates;
  if (DTU) {
    for (auto In : Incoming) {
      for (auto Succ : successors(In)) {
        if (Outgoing.count(Succ))
          Updates.push_back({DominatorTree::Delete, In, Succ});
      }
      Updates.push_back({DominatorTree::Insert, In, FirstGuardBlock});
    }
  }

  BBPredicates GuardPredicates;
  SmallVector<WeakVH, 8> DeletionCandidates;
  convertToGuardPredicates(FirstGuardBlock, GuardPredicates, DeletionCandidates,
                           Incoming, Outgoing);

  GuardBlocks.push_back(FirstGuardBlock);
  createGuardBlocks(GuardBlocks, F, Outgoing, GuardPredicates, Prefix);

  // Update the PHINodes in each outgoing block to match the new control flow.
  for (int i = 0, e = GuardBlocks.size(); i != e; ++i) {
    reconnectPhis(Outgoing[i], GuardBlocks[i], Incoming, FirstGuardBlock);
  }
  reconnectPhis(Outgoing.back(), GuardBlocks.back(), Incoming, FirstGuardBlock);

  if (DTU) {
    int NumGuards = GuardBlocks.size();
    assert((int)Outgoing.size() == NumGuards + 1);
    for (int i = 0; i != NumGuards - 1; ++i) {
      Updates.push_back({DominatorTree::Insert, GuardBlocks[i], Outgoing[i]});
      Updates.push_back(
          {DominatorTree::Insert, GuardBlocks[i], GuardBlocks[i + 1]});
    }
    Updates.push_back({DominatorTree::Insert, GuardBlocks[NumGuards - 1],
                       Outgoing[NumGuards - 1]});
    Updates.push_back({DominatorTree::Insert, GuardBlocks[NumGuards - 1],
                       Outgoing[NumGuards]});
    DTU->applyUpdates(Updates);
  }

  for (auto I : DeletionCandidates) {
    if (I->use_empty())
      if (auto Inst = dyn_cast_or_null<Instruction>(I))
        Inst->eraseFromParent();
  }

  return FirstGuardBlock;
}

// The current transform introduces new control flow paths which may break the
// SSA requirement that every def must dominate all its uses. For example,
// consider a value D defined inside the loop that is used by some instruction
// U outside the loop. It follows that D dominates U, since the original
// program has valid SSA form. After merging the exits, all paths from D to U
// now flow through the unified exit block. In addition, there may be other
// paths that do not pass through D, but now reach the unified exit
// block. Thus, D no longer dominates U.
//
// Restore the dominance by creating a phi for each such D at the new unified
// loop exit. But when doing this, ignore any uses U that are in the new unified
// loop exit, since those were introduced specially when the block was created.
//
// The use of SSAUpdater seems like overkill for this operation. The location
// for creating the new PHI is well-known, and also the set of incoming blocks
// to the new PHI.
static void restoreSSA(const DominatorTree &DT, const Loop *L,
                       const SetVector<BasicBlock *> &Incoming,
                       BasicBlock *LoopExitBlock) {
  using InstVector = SmallVector<Instruction *, 8>;
  using IIMap = DenseMap<Instruction *, InstVector>;
  IIMap ExternalUsers;
  for (auto BB : L->blocks()) {
    for (auto &I : *BB) {
      for (auto &U : I.uses()) {
        auto UserInst = cast<Instruction>(U.getUser());
        auto UserBlock = UserInst->getParent();
        if (UserBlock == LoopExitBlock)
          continue;
        if (L->contains(UserBlock))
          continue;
        LLVM_DEBUG(dbgs() << "added ext use for " << I.getName() << "("
                          << BB->getName() << ")"
                          << ": " << UserInst->getName() << "("
                          << UserBlock->getName() << ")"
                          << "\n");
        ExternalUsers[&I].push_back(UserInst);
      }
    }
  }

  for (auto II : ExternalUsers) {
    // For each Def used outside the loop, create NewPhi in
    // LoopExitBlock. NewPhi receives Def only along exiting blocks that
    // dominate it, while the remaining values are undefined since those paths
    // didn't exist in the original CFG.
    auto Def = II.first;
    LLVM_DEBUG(dbgs() << "externally used: " << Def->getName() << "\n");
    auto NewPhi = PHINode::Create(Def->getType(), Incoming.size(),
                                  Def->getName() + ".moved",
                                  LoopExitBlock->getTerminator());
    for (auto In : Incoming) {
      LLVM_DEBUG(dbgs() << "predecessor " << In->getName() << ": ");
      if (Def->getParent() == In || DT.dominates(Def, In)) {
        LLVM_DEBUG(dbgs() << "dominated\n");
        NewPhi->addIncoming(Def, In);
      } else {
        LLVM_DEBUG(dbgs() << "not dominated\n");
        NewPhi->addIncoming(UndefValue::get(Def->getType()), In);
      }
    }

    LLVM_DEBUG(dbgs() << "external users:");
    for (auto U : II.second) {
      LLVM_DEBUG(dbgs() << " " << U->getName());
      U->replaceUsesOfWith(Def, NewPhi);
    }
    LLVM_DEBUG(dbgs() << "\n");
  }
}

static bool unifyLoopExits(DominatorTree &DT, LoopInfo &LI, Loop *L) {
  // To unify the loop exits, we need a list of the exiting blocks as
  // well as exit blocks. The functions for locating these lists both
  // traverse the entire loop body. It is more efficient to first
  // locate the exiting blocks and then examine their successors to
  // locate the exit blocks.
  SetVector<BasicBlock *> ExitingBlocks;
  SetVector<BasicBlock *> Exits;

  // We need SetVectors, but the Loop API takes a vector, so we use a temporary.
  SmallVector<BasicBlock *, 8> Temp;
  L->getExitingBlocks(Temp);
  for (auto BB : Temp) {
    ExitingBlocks.insert(BB);
    for (auto S : successors(BB)) {
      auto SL = LI.getLoopFor(S);
      // A successor is not an exit if it is directly or indirectly in the
      // current loop.
      if (SL == L || L->contains(SL))
        continue;
      Exits.insert(S);
    }
  }

  LLVM_DEBUG(
      dbgs() << "Found exit blocks:";
      for (auto Exit : Exits) {
        dbgs() << " " << Exit->getName();
      }
      dbgs() << "\n";

      dbgs() << "Found exiting blocks:";
      for (auto EB : ExitingBlocks) {
        dbgs() << " " << EB->getName();
      }
      dbgs() << "\n";);

  if (Exits.size() <= 1) {
    LLVM_DEBUG(dbgs() << "loop does not have multiple exits; nothing to do\n");
    return false;
  }

  SmallVector<BasicBlock *, 8> GuardBlocks;
  DomTreeUpdater DTU(DT, DomTreeUpdater::UpdateStrategy::Eager);
  auto LoopExitBlock = CreateControlFlowHub(&DTU, GuardBlocks, ExitingBlocks,
                                            Exits, "loop.exit");

  restoreSSA(DT, L, ExitingBlocks, LoopExitBlock);

#if defined(EXPENSIVE_CHECKS)
  assert(DT.verify(DominatorTree::VerificationLevel::Full));
#else
  assert(DT.verify(DominatorTree::VerificationLevel::Fast));
#endif // EXPENSIVE_CHECKS
  L->verifyLoop();

  // The guard blocks were created outside the loop, so they need to become
  // members of the parent loop.
  if (auto ParentLoop = L->getParentLoop()) {
    for (auto G : GuardBlocks) {
      ParentLoop->addBasicBlockToLoop(G, LI);
    }
    ParentLoop->verifyLoop();
  }

#if defined(EXPENSIVE_CHECKS)
  LI.verify(DT);
#endif // EXPENSIVE_CHECKS

  return true;
}

bool UnifyLoopExits::runOnFunction(Function &F) {
  LLVM_DEBUG(dbgs() << "===== Unifying loop exits in function " << F.getName()
                    << "\n");
  auto &LI = getAnalysis<LoopInfoWrapperPass>().getLoopInfo();
  auto &DT = getAnalysis<DominatorTreeWrapperPass>().getDomTree();

  bool Changed = false;
  auto Loops = LI.getLoopsInPreorder();
  for (auto L : Loops) {
    LLVM_DEBUG(dbgs() << "Loop: " << L->getHeader()->getName() << " (depth: "
                      << LI.getLoopDepth(L->getHeader()) << ")\n");
    Changed |= unifyLoopExits(DT, LI, L);
  }
  return Changed;
}

RegisterPass<UnifyLoopExits> MP("unify-loop-exits", "UnifyLoopExits Pass");
