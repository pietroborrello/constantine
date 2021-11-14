//===- FixIrreducible.cpp - Convert irreducible control-flow into loops ---===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// An irreducible SCC is one which has multiple "header" blocks, i.e., blocks
// with control-flow edges incident from outside the SCC.  This pass converts a
// irreducible SCC into a natural loop by applying the following transformation:
//
// 1. Collect the set of headers H of the SCC.
// 2. Collect the set of predecessors P of these headers. These may be inside as
//    well as outside the SCC.
// 3. Create block N and redirect every edge from set P to set H through N.
//
// This converts the SCC into a natural loop with N as the header: N is the only
// block with edges incident from outside the SCC, and all backedges in the SCC
// are incident on N, i.e., for every backedge, the head now dominates the tail.
//
// INPUT CFG: The blocks A and B form an irreducible loop with two headers.
//
//                        Entry
//                       /     \
//                      v       v
//                      A ----> B
//                      ^      /|
//                       `----' |
//                              v
//                             Exit
//
// OUTPUT CFG: Edges incident on A and B are now redirected through a
// new block N, forming a natural loop consisting of N, A and B.
//
//                        Entry
//                          |
//                          v
//                    .---> N <---.
//                   /     / \     \
//                  |     /   \     |
//                  \    v     v    /
//                   `-- A     B --'
//                             |
//                             v
//                            Exit
//
// The transformation is applied to every maximal SCC that is not already
// recognized as a loop. The pass operates on all maximal SCCs found in the
// function body outside of any loop, as well as those found inside each loop,
// including inside any newly created loops. This ensures that any SCC hidden
// inside a maximal SCC is also transformed.
//
// The actual transformation is handled by function CreateControlFlowHub, which
// takes a set of incoming blocks (the predecessors) and outgoing blocks (the
// headers). The function also moves every PHINode in an outgoing block to the
// hub. Since the hub dominates all the outgoing blocks, each such PHINode
// continues to dominate its uses. Since every header in an SCC has at least two
// predecessors, every value used in the header (or later) but defined in a
// predecessor (or earlier) is represented by a PHINode in a header. Hence the
// above handling of PHINodes is sufficient and no further processing is
// required to restore SSA.
//
// Limitation: The pass cannot handle switch statements and indirect
//             branches. Both must be lowered to plain branches first.
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/SCCIterator.h"
#include "llvm/Analysis/LoopIterator.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/Utils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/IR/PatternMatch.h"

#define DEBUG_TYPE "fix-irreducible"

using namespace llvm;
using namespace llvm::PatternMatch;

namespace {
struct FixIrreducible : public FunctionPass {
  static char ID;
  FixIrreducible() : FunctionPass(ID) {
    // initializeFixIrreduciblePass(*PassRegistry::getPassRegistry());
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequiredID(LowerSwitchID);
    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addRequired<LoopInfoWrapperPass>();
    AU.addPreservedID(LowerSwitchID);
    AU.addPreserved<DominatorTreeWrapperPass>();
    AU.addPreserved<LoopInfoWrapperPass>();
  }

  bool runOnFunction(Function &F) override;
};
} // namespace

char FixIrreducible::ID = 0;

// FunctionPass *llvm::createFixIrreduciblePass() { return new FixIrreducible(); }

// INITIALIZE_PASS_BEGIN(FixIrreducible, "fix-irreducible",
//                       "Convert irreducible control-flow into natural loops",
//                       false /* Only looks at CFG */, false /* Analysis Pass */)
// INITIALIZE_PASS_DEPENDENCY(LowerSwitch)
// INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
// INITIALIZE_PASS_DEPENDENCY(LoopInfoWrapperPass)
// INITIALIZE_PASS_END(FixIrreducible, "fix-irreducible",
//                     "Convert irreducible control-flow into natural loops",
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

// When a new loop is created, existing children of the parent loop may now be
// fully inside the new loop. Reconnect these as children of the new loop.
static void reconnectChildLoops(LoopInfo &LI, Loop *ParentLoop, Loop *NewLoop,
                                SetVector<BasicBlock *> &Blocks,
                                SetVector<BasicBlock *> &Headers) {
  std::vector<llvm::Loop *> &CandidateLoops = ParentLoop ? ParentLoop->getSubLoopsVector()
                                    : LI.getTopLevelLoopsVector();
  // The new loop cannot be its own child, and any candidate is a
  // child iff its header is owned by the new loop. Move all the
  // children to a new vector.
  auto FirstChild = std::partition(
      CandidateLoops.begin(), CandidateLoops.end(), [&](Loop *L) {
        return L == NewLoop || Blocks.count(L->getHeader()) == 0;
      });
  SmallVector<Loop *, 8> ChildLoops(FirstChild, CandidateLoops.end());
  CandidateLoops.erase(FirstChild, CandidateLoops.end());

  for (auto II = ChildLoops.begin(), IE = ChildLoops.end(); II != IE; ++II) {
    auto Child = *II;
    LLVM_DEBUG(dbgs() << "child loop: " << Child->getHeader()->getName()
                      << "\n");
    // TODO: A child loop whose header is also a header in the current
    // SCC gets destroyed since its backedges are removed. That may
    // not be necessary if we can retain such backedges.
    if (Headers.count(Child->getHeader())) {
      for (auto BB : Child->blocks()) {
        LI.changeLoopFor(BB, NewLoop);
        LLVM_DEBUG(dbgs() << "moved block from child: " << BB->getName()
                          << "\n");
      }
      LI.destroy(Child);
      LLVM_DEBUG(dbgs() << "subsumed child loop (common header)\n");
      continue;
    }

    Child->setParentLoop(nullptr);
    NewLoop->addChildLoop(Child);
    LLVM_DEBUG(dbgs() << "added child loop to new loop\n");
  }
}

// Given a set of blocks and headers in an irreducible SCC, convert it into a
// natural loop. Also insert this new loop at its appropriate place in the
// hierarchy of loops.
static void createNaturalLoopInternal(LoopInfo &LI, DominatorTree &DT,
                                      Loop *ParentLoop,
                                      SetVector<BasicBlock *> &Blocks,
                                      SetVector<BasicBlock *> &Headers) {
#ifndef NDEBUG
  // All headers are part of the SCC
  for (auto H : Headers) {
    assert(Blocks.count(H));
  }
#endif

  SetVector<BasicBlock *> Predecessors;
  for (auto H : Headers) {
    for (auto P : predecessors(H)) {
      Predecessors.insert(P);
    }
  }

  LLVM_DEBUG(
      dbgs() << "Found predecessors:";
      for (auto P : Predecessors) {
        dbgs() << " " << P->getName();
      }
      dbgs() << "\n");

  // Redirect all the backedges through a "hub" consisting of a series
  // of guard blocks that manage the flow of control from the
  // predecessors to the headers.
  SmallVector<BasicBlock *, 8> GuardBlocks;
  DomTreeUpdater DTU(DT, DomTreeUpdater::UpdateStrategy::Eager);
  CreateControlFlowHub(&DTU, GuardBlocks, Predecessors, Headers, "irr");
#if defined(EXPENSIVE_CHECKS)
  assert(DT.verify(DominatorTree::VerificationLevel::Full));
#else
  assert(DT.verify(DominatorTree::VerificationLevel::Fast));
#endif

  // Create a new loop from the now-transformed cycle
  auto NewLoop = LI.AllocateLoop();
  if (ParentLoop) {
    ParentLoop->addChildLoop(NewLoop);
  } else {
    LI.addTopLevelLoop(NewLoop);
  }

  // Add the guard blocks to the new loop. The first guard block is
  // the head of all the backedges, and it is the first to be inserted
  // in the loop. This ensures that it is recognized as the
  // header. Since the new loop is already in LoopInfo, the new blocks
  // are also propagated up the chain of parent loops.
  for (auto G : GuardBlocks) {
    LLVM_DEBUG(dbgs() << "added guard block: " << G->getName() << "\n");
    NewLoop->addBasicBlockToLoop(G, LI);
  }

  // Add the SCC blocks to the new loop.
  for (auto BB : Blocks) {
    NewLoop->addBlockEntry(BB);
    if (LI.getLoopFor(BB) == ParentLoop) {
      LLVM_DEBUG(dbgs() << "moved block from parent: " << BB->getName()
                        << "\n");
      LI.changeLoopFor(BB, NewLoop);
    } else {
      LLVM_DEBUG(dbgs() << "added block from child: " << BB->getName() << "\n");
    }
  }
  LLVM_DEBUG(dbgs() << "header for new loop: "
                    << NewLoop->getHeader()->getName() << "\n");

  reconnectChildLoops(LI, ParentLoop, NewLoop, Blocks, Headers);

  NewLoop->verifyLoop();
  if (ParentLoop) {
    ParentLoop->verifyLoop();
  }
#if defined(EXPENSIVE_CHECKS)
  LI.verify(DT);
#endif // EXPENSIVE_CHECKS
}

namespace llvm {
// Enable the graph traits required for traversing a Loop body.
template <> struct GraphTraits<Loop> : LoopBodyTraits {};
} // namespace llvm

// Overloaded wrappers to go with the function template below.
static BasicBlock *unwrapBlock(BasicBlock *B) { return B; }
static BasicBlock *unwrapBlock(LoopBodyTraits::NodeRef &N) { return N.second; }

static void createNaturalLoop(LoopInfo &LI, DominatorTree &DT, Function *F,
                              SetVector<BasicBlock *> &Blocks,
                              SetVector<BasicBlock *> &Headers) {
  createNaturalLoopInternal(LI, DT, nullptr, Blocks, Headers);
}

static void createNaturalLoop(LoopInfo &LI, DominatorTree &DT, Loop &L,
                              SetVector<BasicBlock *> &Blocks,
                              SetVector<BasicBlock *> &Headers) {
  createNaturalLoopInternal(LI, DT, &L, Blocks, Headers);
}

// Convert irreducible SCCs; Graph G may be a Function* or a Loop&.
template <class Graph>
static bool makeReducible(LoopInfo &LI, DominatorTree &DT, Graph &&G) {
  bool Changed = false;
  for (auto Scc = scc_begin(G); !Scc.isAtEnd(); ++Scc) {
    if (Scc->size() < 2)
      continue;
    SetVector<BasicBlock *> Blocks;
    LLVM_DEBUG(dbgs() << "Found SCC:");
    for (auto N : *Scc) {
      auto BB = unwrapBlock(N);
      LLVM_DEBUG(dbgs() << " " << BB->getName());
      Blocks.insert(BB);
    }
    LLVM_DEBUG(dbgs() << "\n");

    // Minor optimization: The SCC blocks are usually discovered in an order
    // that is the opposite of the order in which these blocks appear as branch
    // targets. This results in a lot of condition inversions in the control
    // flow out of the new ControlFlowHub, which can be mitigated if the orders
    // match. So we discover the headers using the reverse of the block order.
    SetVector<BasicBlock *> Headers;
    LLVM_DEBUG(dbgs() << "Found headers:");
    for (auto BB : reverse(Blocks)) {
      for (const auto P : predecessors(BB)) {
        // Skip unreachable predecessors.
        if (!DT.isReachableFromEntry(P))
          continue;
        if (!Blocks.count(P)) {
          LLVM_DEBUG(dbgs() << " " << BB->getName());
          Headers.insert(BB);
          break;
        }
      }
    }
    LLVM_DEBUG(dbgs() << "\n");

    if (Headers.size() == 1) {
      assert(LI.isLoopHeader(Headers.front()));
      LLVM_DEBUG(dbgs() << "Natural loop with a single header: skipped\n");
      continue;
    }
    createNaturalLoop(LI, DT, G, Blocks, Headers);
    Changed = true;
  }
  return Changed;
}

bool FixIrreducible::runOnFunction(Function &F) {
  LLVM_DEBUG(dbgs() << "===== Fix irreducible control-flow in function: "
                    << F.getName() << "\n");
  auto &LI = getAnalysis<LoopInfoWrapperPass>().getLoopInfo();
  auto &DT = getAnalysis<DominatorTreeWrapperPass>().getDomTree();

  bool Changed = false;
  SmallVector<Loop *, 8> WorkList;

  LLVM_DEBUG(dbgs() << "visiting top-level\n");
  Changed |= makeReducible(LI, DT, &F);

  // Any SCCs reduced are now already in the list of top-level loops, so simply
  // add them all to the worklist.
  for (auto L : LI) {
    WorkList.push_back(L);
  }

  while (!WorkList.empty()) {
    auto L = WorkList.back();
    WorkList.pop_back();
    LLVM_DEBUG(dbgs() << "visiting loop with header "
                      << L->getHeader()->getName() << "\n");
    Changed |= makeReducible(LI, DT, *L);
    // Any SCCs reduced are now already in the list of child loops, so simply
    // add them all to the worklist.
    WorkList.append(L->begin(), L->end());
  }

  return Changed;
}

RegisterPass<FixIrreducible> MP("fix-irreducible", "FixIrreducible Pass");
