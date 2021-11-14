#ifndef SDAG_H
#define SDAG_H

#include "llvm/ADT/GraphTraits.h"
#include "llvm/ADT/iterator.h"
#include "llvm/ADT/iterator_range.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/type_traits.h"
#include "llvm/Analysis/MemorySSA.h"
#include "llvm/IR/IntrinsicInst.h"
#include <cassert>
#include <cstddef>
#include <iterator>
#include <set>

namespace llvm {

class SDAGNode;

class SDAG {
private:
	static std::map<Function*, SDAG*> objMap;
	static MemorySSA *MSSA;
	static AAResults *AA;
	
	Function *function;
	SDAGNode *root;
	std::set<SDAGNode*> nodes;
	std::map<Value*, SDAGNode*> nodeMap;
	SDAG(Function *F) { this->function = F; }
	
	void build();
	bool buildFromNode(SDAGNode* node);
	void reachingMemDefs(Instruction *I, std::vector<Value*> &reachingDefs);
	SDAGNode* newSuccNode(SDAGNode *parent, Value *V);
public:
	static SDAG* get(Function *F, MemorySSA *MSSA, AAResults *AA);
	
	void print(raw_ostream &OS, SDAGNode *node, bool verbFmt=false) const;
	void print(raw_ostream &OS, bool verbFmt=false) const { print(OS, root, verbFmt); }
	SDAGNode *getRoot() const { return root; }
	Function *getFunction() const { return function; }
	const std::set<SDAGNode*>& getNodes() const { return nodes; }
	void foldNodesByOpcode(unsigned opcode);
};

class SDAGNode {
protected:
	SDAG *sdag;
	Value *value;
	std::vector<SDAGNode*> successors;
	std::vector<SDAGNode*> parents;

public:
	SDAGNode(SDAG *sdag, Value *value) {
		this->sdag = sdag;
		this->value = value;
	}
	void addSuccessor(SDAGNode *node);
	void delSuccessor(SDAGNode *node);
	void fold();

	std::string getLabel(bool verbFmt=false) const;
	bool isSpecial() const;
	Value *getValue() const { return value; }
	SDAG *getSDAG() const { return sdag; }
	Function *getFunction() const { return sdag->getFunction(); }
	unsigned getNumSuccessors() const { return successors.size(); };
	unsigned getNumParents() const { return getParents().size(); };
	const std::vector<SDAGNode*>& getSuccessors() const { return successors; };
	const std::vector<SDAGNode*>& getParents() const { return parents; };
};

//===----------------------------------------------------------------------===//
// SDAGNode succ_iterator helpers
//===----------------------------------------------------------------------===//
 
template <class NodeT, class SuccNodeT>
class SuccIteratorx
    : public iterator_facade_base<SuccIteratorx<NodeT, SuccNodeT>,
                                  std::random_access_iterator_tag, SuccNodeT, int,
                                  SuccNodeT *, SuccNodeT *> {
public:
  using difference_type = int;
  using pointer = SuccNodeT *;
  using reference = SuccNodeT *;

private:
  NodeT *Node;
  int Idx;
  using Self = SuccIteratorx<NodeT, SuccNodeT>;

  inline bool index_is_valid(int Idx) {
    return Idx >= 0 && Idx <= (int)Node->getNumSuccessors();
  }

  /// Proxy object to allow write access in operator[]
  class SuccessorProxy {
    Self It;

  public:
    explicit SuccessorProxy(const Self &It) : It(It) {}

    SuccessorProxy(const SuccessorProxy &) = default;

    SuccessorProxy &operator=(SuccessorProxy RHS) {
      *this = reference(RHS);
      return *this;
    }

    SuccessorProxy &operator=(reference RHS) {
      It.Node->setSuccessor(It.Idx, RHS);
      return *this;
    }

    operator reference() const { return *It; }
  };

public:
  // begin iterator
  explicit inline SuccIteratorx(NodeT *Node) : Node(Node), Idx(0) {}
  // end iterator
  inline SuccIteratorx(NodeT *Node, bool) : Node(Node) {
    Idx = Node->getNumSuccessors();
  }

  /// This is used to interface between code that wants to
  /// operate on terminator instructions directly.
  int getSuccessorIndex() const { return Idx; }

  inline bool operator==(const Self &x) const { return Idx == x.Idx; }

  inline SuccNodeT *operator*() const { return Node->getSuccessors()[Idx]; }

  inline SuccNodeT *operator->() const { return operator*(); }

  inline bool operator<(const Self &RHS) const {
    assert(Node == RHS.Node && "Cannot compare iterators of different nodes!");
    return Idx < RHS.Idx;
  }

  int operator-(const Self &RHS) const {
    assert(Node == RHS.Node && "Cannot compare iterators of different nodes!");
    return Idx - RHS.Idx;
  }

  inline Self &operator+=(int RHS) {
    int NewIdx = Idx + RHS;
    assert(index_is_valid(NewIdx) && "Iterator index out of bound");
    Idx = NewIdx;
    return *this;
  }

  inline Self &operator-=(int RHS) { return operator+=(-RHS); }

  // Specially implement the [] operation using a proxy object to support
  // assignment.
  inline SuccessorProxy operator[](int Offset) {
    Self TmpIt = *this;
    TmpIt += Offset;
    return SuccessorProxy(TmpIt);
  }

  /// Get the source NodeT of this iterator.
  inline SuccNodeT *getSource() {
    return Node;
  }
};

//===----------------------------------------------------------------------===//
// SDAGNode succ_iterator helpers
//===----------------------------------------------------------------------===//

using sdagn_succ_iterator =
    SuccIteratorx<SDAGNode, SDAGNode>;
using sdagn_succ_const_iterator =
    SuccIteratorx<const SDAGNode, const SDAGNode>;

inline sdagn_succ_iterator sdagn_succ_begin(SDAGNode *N) {
  return sdagn_succ_iterator(N);
}
inline sdagn_succ_const_iterator sdagn_succ_begin(const SDAGNode *N) {
  return sdagn_succ_const_iterator(N);
}
inline sdagn_succ_iterator sdagn_succ_end(SDAGNode *N) {
  return sdagn_succ_iterator(N, true);
}
inline sdagn_succ_const_iterator sdagn_succ_end(const SDAGNode *N) {
  return sdagn_succ_const_iterator(N, true);
}

//===--------------------------------------------------------------------===//
// GraphTraits specializations for SDAGs
//===--------------------------------------------------------------------===//

// Provide specializations of GraphTraits to be able to treat a function as a
// graph of SDAG Nodes...

template <> struct GraphTraits<SDAGNode*> {
  using NodeRef = SDAGNode *;
  using ChildIteratorType = sdagn_succ_iterator;

  static NodeRef getEntryNode(NodeRef N) { return N; }
  static ChildIteratorType child_begin(NodeRef N) { return sdagn_succ_begin(N); }
  static ChildIteratorType child_end(NodeRef N) { return sdagn_succ_end(N); }
};

template <> struct GraphTraits<const SDAGNode*> {
  using NodeRef = const SDAGNode *;
  using ChildIteratorType = sdagn_succ_const_iterator;

  static NodeRef getEntryNode(const NodeRef N) { return N; }

  static ChildIteratorType child_begin(NodeRef N) { return sdagn_succ_begin(N); }
  static ChildIteratorType child_end(NodeRef N) { return sdagn_succ_end(N); }
};

//===--------------------------------------------------------------------===//
// GraphTraits specializations for function SDAGs
//===--------------------------------------------------------------------===//

// Provide specializations of GraphTraits to be able to treat a SDAG as a
// graph of SDAG nodes...
//
template <> struct GraphTraits<SDAG*> : public GraphTraits<SDAGNode*> {
  static NodeRef getEntryNode(SDAG *sdag) { return sdag->getRoot(); }

  // nodes_iterator/begin/end - Allow iteration over all nodes in the graph
  using nodes_iterator = std::set<SDAGNode*>::iterator;

  static nodes_iterator nodes_begin(SDAG *sdag) {
    return nodes_iterator(sdag->getNodes().begin());
  }

  static nodes_iterator nodes_end(SDAG *sdag) {
    return nodes_iterator(sdag->getNodes().end());
  }

  static size_t size(SDAG *sdag) { return sdag->getNodes().size(); }
};

template <> struct GraphTraits<const SDAG*> :
  public GraphTraits<const SDAGNode*> {
  static NodeRef getEntryNode(const SDAG *sdag) { return sdag->getRoot(); }

  // nodes_iterator/begin/end - Allow iteration over all nodes in the graph
  using nodes_iterator = std::set<SDAGNode*>::iterator;

  static nodes_iterator nodes_begin(const SDAG *sdag) {
    return nodes_iterator(sdag->getNodes().begin());
  }

  static nodes_iterator nodes_end(const SDAG *sdag) {
    return nodes_iterator(sdag->getNodes().end());
  }

  static size_t size(const SDAG *sdag) { return sdag->getNodes().size(); }
};

class SDAGWrapperPass : public FunctionPass {
public:
  static char ID;
  SDAGWrapperPass() : FunctionPass(ID) {}

  bool runOnFunction(Function &F) override {
  	auto MSSA = &getAnalysis<MemorySSAWrapperPass>().getMSSA();
  	auto AAResults = &getAnalysis<AAResultsWrapperPass>().getAAResults();
  	sdag = SDAG::get(&F, MSSA, AAResults);
    return false;
  }
  void print(raw_ostream &OS, const Module* = nullptr) const override {}
  SDAG *getSDAG() const { return sdag; }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<MemorySSAWrapperPass>();
    AU.addRequired<AAResultsWrapperPass>();
    AU.setPreservesAll();
  }
private:
  SDAG *sdag;
};

} // end namespace llvm

#endif // SDAG_H
