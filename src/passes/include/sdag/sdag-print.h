#ifndef SDAG_PRINT_H
#define SDAG_PRINT_H

#include "sdag.h"

#include <pass.h>

#include "llvm/Support/GraphWriter.h"

namespace llvm {

template<>
struct DOTGraphTraits<const SDAG*> : public DefaultDOTGraphTraits {

  DOTGraphTraits (bool isSimple=false) : DefaultDOTGraphTraits(isSimple) {}

  static std::string getGraphName(const SDAG *sdag) {
    return "SDAG for '" + sdag->getFunction()->getName().str() + "' function";
  }

  std::string getNodeLabel(const SDAGNode *Node,
                           const SDAG *Graph) {
	return Node->getLabel(!isSimple());
  }

  std::string getNodeAttributes(const SDAGNode *Node,
                           const SDAG *Graph) {
    std::string str;
    if (!Node->isSpecial())
    	return str;
    raw_string_ostream OS(str);
    OS << "color=\"red\"";
    return OS.str();
  }

};
} // End llvm namespace

#endif
