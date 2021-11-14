#include <pass.h>

#include <fstream>

using namespace llvm;

static cl::opt<std::string>
DBGFuncName("dbg-func",
    cl::desc("The name of a function (or substring) to print"),
    cl::init("main"), cl::NotHidden);

std::string getSourceLine(StringRef &dir, StringRef &file, unsigned int line)
{
	static std::map<std::string, std::string> sourceMap;
	static std::set<std::string> fileMap;
	
	std::string fileName = dir.str()+"/"+file.str();
	std::ostringstream oss;
	oss << fileName << ":" << line;
	auto it = sourceMap.find(oss.str());
	if (it != sourceMap.end())
		return it->second;

	auto it2 = fileMap.find(fileName);
	if (it2 != fileMap.end())
		return "???";
	fileMap.insert(fileName);

	std::ifstream F(fileName);
	if (!F.is_open())
		return "?!?";

	std::string fileLineStr;
	unsigned fileLine = 1;
	while (getline(F, fileLineStr)) {
		std::ostringstream oss2;
		oss2 << fileName << ":" << fileLine;
	    sourceMap.insert(std::pair<std::string, std::string>(oss2.str(), fileLineStr));
	    fileLine++;
	}
	F.close();

	return getSourceLine(dir, file, line);
}

static void printDBG(Function *F) {
  DILocation *lastLoc = NULL;
  F->printAsOperand(errs());
  errs() << "\n";
  for (auto &I : instructions(F)) {
		Instruction *inst = &I;
		Function *Callee = passGetCalledFunction(inst);
		if (Callee && Callee->getName().startswith("llvm."))
			continue;
		DILocation *loc = inst->getDebugLoc();
		if (!loc || (lastLoc && loc->getLine() == lastLoc->getLine() && loc->getFilename() == lastLoc->getFilename())) {
			errs() << *inst << "\n";
			continue;
		}
		lastLoc = loc;
		unsigned int line = loc->getLine();
		StringRef file = loc->getFilename();
		StringRef dir = loc->getDirectory();
		
		errs() << "; " << getSourceLine(dir, file, line) << "\n";
		errs() << *inst << "\n";
  }
}

namespace {
  class DBGPrintPass : public FunctionPass {
  public:
    static char ID; // Pass identification, replacement for typeid
    DBGPrintPass() : FunctionPass(ID) {
    }

    bool runOnFunction(Function &F) override {
      if (!DBGFuncName.empty() && !F.getName().contains(DBGFuncName))
      	  return false;
      printDBG(&F);
      return false;
    }
    void print(raw_ostream &OS, const Module* = nullptr) const override {}

    void getAnalysisUsage(AnalysisUsage &AU) const override {
      AU.setPreservesAll();
    }
  };
}

char DBGPrintPass::ID = 0;
RegisterPass<DBGPrintPass> DBGPP("dbg", "Dump debug info of function");
