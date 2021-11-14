
#include <pass.h>
#include <iostream>
#include <fstream>
#include <iomanip>

#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IRBuilder.h"

using namespace llvm;

#define DEBUG_TYPE "findInstruction"
#define findInstructionPassLog(M) LLVM_DEBUG(dbgs() << "FindInstructionPass: " << M << "\n")
#define oprint(s) (outs() << s << "\n")

typedef long imd_t;

static cl::opt<int>
BGID("BGID",
    cl::desc("BasicBlock Global ID"),
    cl::init(0), cl::NotHidden);

static cl::opt<int>
IBID("IBID",
    cl::desc("Instruction BasicBlock-local ID"),
    cl::init(0), cl::NotHidden);

namespace {

  // Find a specific instruction given a BasicBlock ID and an instruction ID, and
  // dump it, along the possible call graph to reach that instruction
  class FindInstructionPass : public ModulePass {

  public:
    static char ID;
    FindInstructionPass() : ModulePass(ID) {}

    int getBGID(Instruction &I) {
        MDNode* N;
        Constant *val;
        BasicBlock *BB = I.getParent();
        N = BB->getTerminator()->getMetadata("b-gid");
        if(!N) return 0;
        val = dyn_cast<ConstantAsMetadata>(N->getOperand(0))->getValue();
        if(!val) return 0;
        int b_gid = cast<ConstantInt>(val)->getSExtValue();
        return b_gid;
    }

    int getIBID(Instruction &I) {
        MDNode* N;
        Constant *val;
        N = I.getMetadata("i-bid");
        if(!N) return 0;
        val = dyn_cast<ConstantAsMetadata>(N->getOperand(0))->getValue();
        if(!val) return 0;
        int i_bid = cast<ConstantInt>(val)->getSExtValue();
        return i_bid;
    }

    std::string getLocation(Instruction &I) {

        if (DILocation *Loc = I.getDebugLoc()) {
            unsigned Line = Loc->getLine();
            unsigned Col  = Loc->getColumn();
            StringRef File = Loc->getFilename();
            DILocation *InlineLoc = Loc->getInlinedAt();
            // not worth
            if (Line == 0 && Col == 0) return "";
            if (!InlineLoc)
                return "file: " + File.str() + ", line: " + std::to_string(Line) + ", col:" + std::to_string(Col);
            else {
                unsigned InLine = InlineLoc->getLine();
                unsigned InCol  = InlineLoc->getColumn();
                StringRef InFile = InlineLoc->getFilename();
                return "file: " + File.str() + ", line: " + std::to_string(Line) + ", col:" + std::to_string(Col) +
                    ", inlined at: " + InFile.str() + ", line: " + std::to_string(InLine) + ", col:" + std::to_string(InCol);
            }
        } else {
            // No location metadata available
            return "";
        }
    }

    // Get the nearest possible location that we can find
    // returns the location string and the respective instruction of that location
    // string
    std::pair<std::string, Instruction*> getNearestLocation(Instruction &I) {
        // try to get the location of the instruction itself
        std::string loc = getLocation(I);
        if (loc != "") return std::make_pair(loc, &I);
        BasicBlock *BB = I.getParent();

        // if the instruction is a conditional branch, try to get the location of the condition
        // it is referring to
        if (BranchInst *BI = dyn_cast<BranchInst>(&I)) {
            if (BI->isConditional() && isa<Instruction>(BI->getCondition())) {
                Instruction *Cond = dyn_cast<Instruction>(BI->getCondition());
                assert(Cond);
                std::string loc = getLocation(*Cond);
                if (loc != "") return std::make_pair(loc, Cond);
            }
        }

        // try previous instructions first
        Instruction *PrevI = I.getPrevNode();
        while (PrevI) {
            std::string loc = getLocation(*PrevI);
            if (loc != "") return std::make_pair(loc, PrevI);
            PrevI = PrevI->getPrevNode();
        }

        // try to search in the instructions of the same basic block
        for (Instruction &II: *BB) {
            std::string loc = getLocation(II);
            if (loc != "") return std::make_pair(loc, &II);
        }

        // try in the predecessors
        for (BasicBlock *_BB : predecessors(BB)){
            for (Instruction &II: *_BB) {
                std::string loc = getLocation(II);
                if (loc != "") return std::make_pair(loc, &II);
            }
        }

        // try in the successors
        for (BasicBlock *_BB : successors(BB)){
            for (Instruction &II: *_BB) {
                std::string loc = getLocation(II);
                if (loc != "") return std::make_pair(loc, &II);
            }
        }

        // giveup
        return std::make_pair("", nullptr);

    }

    void dumpCallgraph(Function *F, int level) {
        oprint(std::string(level, ' ') << "|_" << F->getName().str());
        for (User* use: F->users()) {
            CallInst *CI = dyn_cast<CallInst>(use);
            if (!CI) continue;
            oprint(std::string(level, ' ') << "  (" << getLocation(*CI) << ")");
            dumpCallgraph(CI->getParent()->getParent(), level + 1);
        }
    }

    virtual bool runOnModule(Module &M) override {

        for (auto &F : M.getFunctionList()) {
            if (F.isDeclaration())
                continue;
            for (auto &BB: F) {
                for (auto &I : BB) {
                    if (getIBID(I) == IBID && getBGID(I) == BGID) {
                        oprint("\n--- info ---");
                        oprint("Function: " << F.getName().str());
                        oprint("    in:   " << BB.getName().str());
                        oprint("    instr: " << I);
                        oprint("");
                        auto pair = getNearestLocation(I);
                        if (pair.second == &I) {
                            oprint("    location:    " << pair.first);
                        } else if (pair.second != nullptr) {
                            oprint("    near location:    " << pair.first);
                            oprint("    for: " << *pair.second);
                            oprint("    in:          " << pair.second->getParent()->getName().str());

                        } else {
                            oprint("LOCATION: not found");
                        }

                        oprint("\n--- callgraph ---");
                        dumpCallgraph(&F, 0);
                        return false;
                    }
                }
            }
        }
        return false;
   }
 
   void getAnalysisUsage(AnalysisUsage &AU) const override {
    }
  };

}

char FindInstructionPass::ID = 0;
RegisterPass<FindInstructionPass> MP("find-instruction", "Find Instruction Pass");
