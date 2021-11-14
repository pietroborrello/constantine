
#include <pass.h>

#include "llvm/IR/Module.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/CFG.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Transforms/Utils/CodeExtractor.h"
#include "llvm/Analysis/LoopPass.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/ToolOutputFile.h"
#include <set>
using namespace llvm;

#define DEBUG_TYPE "branchextract"
#define branchExtractPassLog(M) LLVM_DEBUG(dbgs() << "BranchExtractPass: " << M << "\n")

#define qprint(s) LLVM_DEBUG(std::cout << s << std::endl)
#define oprint(s) outs() << s << "\n"

static cl::opt<bool>
SimpleBranches("extract-simple-branches",
    cl::desc("Extract only simple branches"),
    cl::init(false), cl::NotHidden);

static cl::opt<bool>
AllBranches("taint-all-branches",
    cl::desc("Taint all extracted branches"),
    cl::init(false), cl::NotHidden);

static cl::list<std::string>
Functions("branch-extract-funcs",
    cl::desc("Specify all the comma-separated function regexes for which to extract branches"),
    cl::ZeroOrMore, cl::CommaSeparated, cl::NotHidden);

typedef long imd_t;

namespace {

    class IfCondition {
    public:
        BranchInst *Branch;
        BasicBlock *MergePoint;
        BasicBlock *IfTrue;
        BasicBlock *IfFalse;
        BasicBlock *IfTruePred;
    };

    static std::unique_ptr<raw_fd_ostream> openFile(StringRef file) {
        std::error_code ec;
        auto ret =
            llvm::make_unique<raw_fd_ostream>(file, ec, sys::fs::OpenFlags::F_None);
        if (ec) {
            return nullptr;
        }
        return ret;
    }

  class BranchExtractPass : public ModulePass {

    unsigned long totalFunctions     = 0;
    unsigned long processedFunctions = 0;
    unsigned long extractedBranches  = 0;
    unsigned long extractedIFCs      = 0;
    unsigned long extractedLoops     = 0;
    unsigned long taintedBranches    = 0;
    unsigned long taintedIFCs        = 0;
    unsigned long taintedLoops       = 0;
  public:
    static char ID;
    // Every time we modify the CFG we have to keep track that we invalidated all
    // the information we have on basic block, branches, and loops
    // so that we need to gather them again
    bool ValidInfo = true;
    BranchExtractPass() : ModulePass(ID) {}

    BasicBlock *getImmediatePostdominator(PostDominatorTree *PDT, BasicBlock* BB) {
        auto SuccIt = ++df_begin(BB);
        auto SuccEnd = df_end(BB);
        while (SuccIt != SuccEnd) {
            BasicBlock *SuccBB = *SuccIt;
            if (PDT->dominates(SuccBB, BB)) {
                return SuccBB;
            }
            SuccIt++;
        }
        return NULL;
    }

    IfCondition *getIfCondition(DominatorTree *DT, PostDominatorTree *PDT, BranchInst *BI) {
        static IfCondition IFC;

        // Only conditional branches
        if (!BI->isConditional() || BI->getNumSuccessors()!=2)
            return NULL;

        // Look for i-postdominator with 2 or more predecessors (will fix the "more" later)
        BasicBlock *BB = BI->getParent();
        BasicBlock *IPD = getImmediatePostdominator(PDT, BB);
        if (!IPD || !IPD->hasNPredecessorsOrMore(2))
            return NULL;

        // Found candidate merge point, ensure it isn't someone else's point
        auto SuccIt = ++df_begin(BB);
        auto SuccEnd = df_end(BB);
        while (SuccIt != SuccEnd) {
            BasicBlock *SuccBB = *SuccIt;
            if (SuccBB == IPD)
                break;
            BranchInst *BI = dyn_cast<BranchInst>(SuccBB->getTerminator());
            if (BI && BI->isConditional() && DT->dominates(SuccBB, IPD))
                return NULL;
            SuccIt++;
        }

        // Found the merge point block, fill info and return
        IFC.Branch = BI;
        IFC.MergePoint = IPD;
        IFC.IfTrue = BI->getSuccessor(0);
        IFC.IfFalse = BI->getSuccessor(1);
        IFC.IfTruePred = NULL;
        for (BasicBlock *Pred : predecessors(IFC.MergePoint)) {
            if (!DT->dominates(IFC.IfTrue, Pred))
                continue;
            // if we found a second IfTruePred it means we may be an outer branch
            // of an inner branch
            if(IFC.IfTruePred) {
                return NULL;
            }
            IFC.IfTruePred = Pred;
        }
        // if no predecessor of the MergePoint is dominated by the IFTrue Block
        // it means IFTrue == MergePoint, so we set IFTruePred = BranchBB
        if(!IFC.IfTruePred) {
            IFC.IfTruePred = IFC.Branch->getParent();
        }
        return &IFC;
    }

    Loop *getNaturalLoop(DominatorTree *DT, PostDominatorTree *PDT, LoopInfo* LI, BranchInst *BI) {
        // Only conditional branches
        if (!BI->isConditional() || BI->getNumSuccessors()!=2)
            return NULL;

        BasicBlock *BB = BI->getParent();
        Loop* L = LI->getLoopFor(BB);

        // get only the loop if the branch is the exiting block for
        if (!L || L->getExitingBlock() != BB)
            return NULL;

        return L;
    }

    bool getInstructionTaint(Instruction &I) {
        MDNode* N;
        Constant *val;
        N = I.getMetadata("t");
        if (N == NULL) return false;
        val = dyn_cast<ConstantAsMetadata>(N->getOperand(0))->getValue();
        assert(val);
        int taint = cast<ConstantInt>(val)->getSExtValue();
        return taint;
    }

    void setInstructionTaint(Instruction &I, bool taint) {
       LLVMContext& C = I.getContext();
        MDNode* N = MDNode::get(C, ConstantAsMetadata::get(ConstantInt::get(C, APInt(sizeof(imd_t)*8, taint, true))));
        I.setMetadata("t", N);
    }

    bool doExtract(Function &F, IfCondition &IFC, DominatorTree &DT, PostDominatorTree &PDT, LoopInfo *LI, const char* name) {
        // If the branch is owned by the function header we should split it
        // oprint("\ntrying branch: " << IFC.Branch->getParent()->getName().str() << " => " << IFC.MergePoint->getName().str());
        if(IFC.Branch->getParent() == &F.getEntryBlock()) {
            // qprint("Splitting " << IFCHeader->getName().str());
            // BasicBlock* BB = IFCHeader->splitBasicBlock(IFC.Branch);
            BasicBlock* newHeader = SplitBlock(IFC.Branch->getParent(), IFC.Branch, &DT, LI);
            assert(newHeader);
            PDT.recalculate(F);
            ValidInfo = false;
        }
        
        // Split the IFC merge point if has multiple terminators
        if (IFC.MergePoint->getTerminator()->getNumSuccessors() > 1) {
            // qprint("Splitting merge point " << IFC.MergePoint->getName().str());
            // BasicBlock* BB = IFC.MergePoint->splitBasicBlock(IFC.MergePoint->getTerminator());
            BasicBlock* BB = SplitBlock(IFC.MergePoint, IFC.MergePoint->getTerminator(), &DT, LI);
            assert(BB);
            PDT.recalculate(F);
            ValidInfo = false;
        }

        // now before proceeding we should check if the branch is the innermost
        // otherwise we are just modifying the CFG for nothing
        // note that the transformations we may have done before have no impact
        // on CFG shape since they only split the block at the terminator with a
        // direct branch
        // So let's visit the whole if<->merge region
        { // new region so we can redefine vars due to dev lazyness
        auto SuccIt = ++df_begin(IFC.Branch->getParent());
        auto SuccEnd = df_end(IFC.Branch->getParent());
        while (SuccIt != SuccEnd) {
            BasicBlock *SuccBB = *SuccIt;
            // Ensure we are in the region (who knows)
            if (PDT.dominates(IFC.MergePoint, SuccBB) && DT.dominates(IFC.Branch->getParent(), SuccBB)) {
                // Ensure no nested branches in the region
                if (SuccBB->getTerminator()->getNumSuccessors() > 1) {
                    // Allow only the IFC.Branch itself
                    if(SuccBB != IFC.Branch->getParent()) {
                        // oprint("Failure: the branch is not the innermost");
                        return false;
                    }
                }
            }
            SuccIt++;
        }
        }

        // If the merge point has more than 2 predecessors we should isolate the
        // two that compose our branch
        if (IFC.MergePoint->hasNPredecessorsOrMore(3)) {
            std::set<BasicBlock*> Preds;
            // Search the two predecessors we need: all the predecessors of the 
            // merge point, that are dominated by the branch
            for (BasicBlock *PredBB : predecessors(IFC.MergePoint)) {
                if (DT.dominates(IFC.Branch->getParent(), PredBB)) {
                    Preds.insert(PredBB);
                }
            }
            // if the predecessors would still be more than 2, fail
            if (Preds.size() != 2) {
                // oprint("Failure: merge point predecessors would still be not 2: " << Preds.size());
                return false;
            }
            std::vector<BasicBlock*> PredsVec(Preds.begin(), Preds.end());
            BasicBlock * newMergeBB = SplitBlockPredecessors(IFC.MergePoint, PredsVec, ".splitted", &DT, LI);
            assert(newMergeBB);
            // set the new merge BB
            // oprint("Split " << IFC.MergePoint->getName().str() <<" into " << newMergeBB->getName().str());
            IFC.MergePoint = newMergeBB;
            ValidInfo = false;
        }

        // if the branch does not dominate the merge point this is an invalid branch to extract
        if (!DT.dominates(IFC.Branch->getParent(), IFC.MergePoint)) {
            // oprint("Failure: branch does not dominate merge point");
            return false;
        }

        if (!ValidInfo) {
            // recompute the DT since we modified BBs
            DT.recalculate(F);
            PDT.recalculate(F);
            LI->releaseMemory();
            LI->analyze(DT);
            // oprint("Failure: invalid info");
            return false;
        }

        std::vector<BasicBlock*> BasicBlocks;
        std::set   <BasicBlock*> addedBBs;
        // qprint("EXTRACTING");
        // IFC.Branch->dump();
        // Code Extractor needs header to be first in the vector
        BasicBlocks.push_back(IFC.Branch->getParent());

        // Visit the whole if<->merge region
        auto SuccIt = ++df_begin(IFC.Branch->getParent());
        auto SuccEnd = df_end(IFC.Branch->getParent());
        while (SuccIt != SuccEnd) {
            BasicBlock *SuccBB = *SuccIt;
            // Ensure no nested branches (for safety, but we already checked)
            // MergeBB already splitted if needed
            if (SuccBB->getTerminator()->getNumSuccessors() <= 1) {
                if (PDT.dominates(IFC.MergePoint, SuccBB) && DT.dominates(IFC.Branch->getParent(), SuccBB)) {
                    if(addedBBs.find(SuccBB) == addedBBs.end()) {
                        BasicBlocks.push_back(SuccBB);
                        // SuccBB->dump();
                        addedBBs.insert(SuccBB);
                    }
                }
            }
            SuccIt++;
        }

        AssumptionCache *AC = nullptr;
        if (auto *ACT = getAnalysisIfAvailable<AssumptionCacheTracker>()) {
            AC = ACT->lookupAssumptionCache(F);
        }

        CodeExtractor Extractor(BasicBlocks, &DT, false, nullptr, nullptr, AC);

        // qprint("is eligible? " << Extractor.isEligible());
        Function* extractedFunc = Extractor.extractCodeRegion();
        if (extractedFunc != nullptr) {
            if (name)
                extractedFunc->setName(name);
            extractedFunc->addFnAttr(Attribute::AlwaysInline);
            // If the parent function is noinline, the extracted function would 
            // inherit the attribute, so remove it
            if(extractedFunc->hasFnAttribute(Attribute::NoInline))
                extractedFunc->removeFnAttr(Attribute::NoInline);
            for(BasicBlock *BB: BasicBlocks) {
                LI->removeBlock(BB);
            }
            ValidInfo = false;
            return true;
        }
        // oprint("Failure: failed to extract");
        return false;
    }

    bool doExtractLoop(Function &F, Loop *L, DominatorTree &DT, PostDominatorTree &PDT, LoopInfo *LI, const char* name) {
        // If the (pre)header is owned by the function header we should split it
        BasicBlock* LPreheader = L->getLoopPreheader();
        BasicBlock* LHeader = L->getHeader();
        if (LPreheader == &F.getEntryBlock()) {
            // qprint("Splitting " << LPreheader->getName().str());
            // BasicBlock* BB = LPreheader->splitBasicBlock(LPreheader->getTerminator());
            BasicBlock* BB = SplitBlock(LPreheader, LPreheader->getTerminator(), &DT, LI);
            assert(BB);
            ValidInfo = false;
        }
        else if(LHeader == &F.getEntryBlock()) {
            // qprint("Splitting " << LHeader->getName().str());
            // BasicBlock* BB = LHeader->splitBasicBlock(LHeader->getTerminator());
            BasicBlock* BB = SplitBlock(LHeader, LHeader->getTerminator(), &DT, LI);
            assert(BB);
            ValidInfo = false;
        }
        
        // Split the L exit block if has multiple terminators
        if (L->getExitBlock()->getTerminator()->getNumSuccessors() > 1) {
            // qprint("Splitting exit block" << L->getExitBlock()->getName().str());
            // BasicBlock* BB = L->getExitBlock()->splitBasicBlock(L->getExitBlock()->getTerminator());
            BasicBlock* BB = SplitBlock(L->getExitBlock(), L->getExitBlock()->getTerminator(), &DT, LI);
            assert(BB);
            LI->removeBlock(BB);
            ValidInfo = false;
        }
        if (!ValidInfo) {
            // recompute the DT since we modified BBs
            DT.recalculate(F);
            PDT.recalculate(F);
            // Better being on the safe side and make loop being reanalyzed since
            // we modified them, and may have made L invalid
            LI->releaseMemory();
            LI->analyze(DT);
            // try next iteration since now L is invalid as we have just released it
            return false;
        }

        std::vector<BasicBlock*> BasicBlocks;
        std::set   <BasicBlock*> addedBBs;
        // Code Extractor needs header to be first in the vector
        if (L->getLoopPreheader()) {
            BasicBlocks.push_back(L->getLoopPreheader());
            // L->getLoopPreheader()->dump();
        }
        BasicBlocks.push_back(L->getHeader());
        // L->getHeader()->dump();

        // Visit the whole header<->exit region
        auto SuccIt = ++df_begin(L->getHeader());
        auto SuccEnd = df_end(L->getHeader());
        while (SuccIt != SuccEnd) {
            BasicBlock *SuccBB = *SuccIt;
            // Ensure no nested branches
            // ExitBlock already splitted if needed
            if (SuccBB == L->getExitingBlock() || SuccBB->getTerminator()->getNumSuccessors() <= 1) {
                if (PDT.dominates(L->getExitBlock(), SuccBB) && DT.dominates(L->getHeader(), SuccBB)) {
                    if(addedBBs.find(SuccBB) == addedBBs.end()) {
                        BasicBlocks.push_back(SuccBB);
                        // SuccBB->dump();
                        addedBBs.insert(SuccBB);
                    }
                }
            }
            // if (SuccBB != L->getExitingBlock() && SuccBB->getTerminator()->getNumSuccessors() > 1) {
            //     return false;
            // }
            SuccIt++;
        }

        AssumptionCache *AC = nullptr;
        if (auto *ACT = getAnalysisIfAvailable<AssumptionCacheTracker>()) {
            AC = ACT->lookupAssumptionCache(F);
        }

        // CodeExtractor Extractor(DT, *L, false, nullptr, nullptr, AC);
        CodeExtractor Extractor(BasicBlocks, &DT, false, nullptr, nullptr, AC);

        // qprint("is eligible? " << Extractor.isEligible());
        Function* extractedFunc = Extractor.extractCodeRegion();
        if (extractedFunc != nullptr) {
            if (name)
                extractedFunc->setName(name);
            extractedFunc->addFnAttr(Attribute::AlwaysInline);
            // If the parent function is noinline, the extracted function would 
            // inherit the attribute, so remove it
            if(extractedFunc->hasFnAttribute(Attribute::NoInline))
                extractedFunc->removeFnAttr(Attribute::NoInline);
            // oprint("\rextracted loop: ");
            for(BasicBlock *BB: BasicBlocks) {
                LI->removeBlock(BB);
            }
            // LI->erase(L);
            ValidInfo = false;
            return true;
        }
        return false;
    }

    bool branchNeedsCFL(BasicBlock *IFCBB, std::vector<IfCondition> ifConditions, std::vector<Loop*> loops,DominatorTree &DT, PostDominatorTree &PDT) {
        // Set to apply CFL on tainted branches + nested of a tainted branch
        bool isTainted = getInstructionTaint(*IFCBB->getTerminator());
        if (isTainted)
            return true;
        
        // search all the if conditions
        for (IfCondition &otherIFC : ifConditions) {
            BasicBlock* otherBB = otherIFC.Branch->getParent();
            // if inner branch of a tainted if condition
            if(DT.dominates(otherBB, IFCBB) && PDT.dominates(otherIFC.MergePoint, IFCBB)) {
                if(getInstructionTaint(*otherIFC.Branch)) {
                    return true;
                }
            }
        }

        // search for all the loops
        for (Loop* L: loops) {
            BasicBlock* otherBB = L->getHeader();
            // if inner branch of a tainted loop
            if(DT.dominates(otherBB, IFCBB) && PDT.dominates(L->getExitingBlock(), IFCBB)) {
                if(getInstructionTaint(*L->getExitingBlock()->getTerminator())) {
                    return true;
                }
            }
        }
        return false;
    }

    void extractBranches(Function& F) { 
        branchExtractPassLog("Extracting branches in " << F.getName());
        qprint("Extracting branches in " << F.getName().str());
        DominatorTree *DT = &getAnalysis<DominatorTreeWrapperPass>(F).getDomTree();
        PostDominatorTree *PDT = &getAnalysis<PostDominatorTreeWrapperPass>(F).getPostDomTree();
        LoopInfo *LI = &getAnalysis<LoopInfoWrapperPass>(F).getLoopInfo();

        bool extracted;
        int count = 0, tot_branches = 0, tainted_branches = 0;
        for (BasicBlock &BB : F) {
            BranchInst *BI = dyn_cast<BranchInst>(BB.getTerminator());
            if (!BI)
                continue;
            if (!BI->isConditional()) continue;
            tot_branches++;
        }

        BasicBlock* unidentified_branch = NULL;
        do {
            DT->recalculate(F);
            PDT->recalculate(F);
            LI->releaseMemory();
            LI->analyze(*DT);
            extracted = 0;
            // Find all the branches to extract
            std::vector<IfCondition> ifConditions;
            std::vector<Loop*> loops;
            for (BasicBlock &BB : F) {
                BranchInst *BI = dyn_cast<BranchInst>(BB.getTerminator());
                if (!BI)
                    continue;
                if (!BI->isConditional()) continue;
                IfCondition *IFC = getIfCondition(DT, PDT, BI);
                Loop *Loop = getNaturalLoop(DT, PDT, LI, BI);
                if (!IFC && !Loop) {
                    // qprint("FAILED: " << BB.getName().str());
                    // BB.dump();
                    unidentified_branch = &BB;
                    continue;
                }
                if (SimpleBranches) {
                    // Only simple branches LLVM's GetIfCondition can handle
                    BasicBlock *IfTrue, *IfFalse;
                    if (!GetIfCondition(IFC->MergePoint, IfTrue, IfFalse))
                        continue;
                }
                if(IFC) {
                    ifConditions.push_back(*IFC);
                } else {
                    loops.push_back(Loop);
                }
                unidentified_branch = NULL;
            }
            // We just gathered the info
            ValidInfo = true;

            for (IfCondition &IFC : ifConditions) {
                if(!ValidInfo) break;
                bool needsCFL = AllBranches || branchNeedsCFL(IFC.Branch->getParent(), ifConditions, loops, *DT, *PDT);
                if (needsCFL)
                    extracted = doExtract(F, IFC, *DT, *PDT, LI, ("__cfl_branch_"+F.getName().str()).c_str());
                else
                    extracted = doExtract(F, IFC, *DT, *PDT, LI, ("branch_"+F.getName().str()).c_str());
                // Do one at a time, since we modify BBs in doExtract
                // qprint("extraction of ifc " << IFC.Branch->getParent()->getName().str() << (extracted? " success":" failed"));
                if (extracted) {
                    ++extractedBranches;
                    ++extractedIFCs;
                    if (needsCFL) {
                        ++taintedBranches;
                        ++taintedIFCs;
                        tainted_branches++;
                    }
                    count++;
                    dbgs() << "\r  extracting branches: " << count << "/" << tot_branches;
                    break;
                }
            }
            // Try to extract loop only when no branch to extract
            if (!extracted) {
                for (Loop *Loop : loops) {
                    if(!ValidInfo) break;
                    bool needsCFL = AllBranches || branchNeedsCFL(Loop->getExitingBlock(), ifConditions, loops, *DT, *PDT);
                    if (needsCFL)
                        extracted = doExtractLoop(F, Loop, *DT, *PDT, LI, ("__cfl_loop_"+F.getName().str()).c_str());
                    else
                        extracted = doExtractLoop(F, Loop, *DT, *PDT, LI, ("loop_"+F.getName().str()).c_str());
                    // Do one at a time, since we modify BBs in doExtract
                    // qprint("extraction of loop " << (extracted? " success":" failed"));
                    if (extracted) {
                        ++extractedBranches;
                        ++extractedLoops;
                        if (needsCFL) {
                            ++taintedBranches;
                            ++taintedLoops;
                            tainted_branches++;
                        }
                        count++;
                        dbgs() << "\r  extracting branches: " << count << "/" << tot_branches;
                        break;
                    }
                }
            }
        // Repeat if we extracted something or if we invalidated some info
        } while (extracted || !ValidInfo);
        qprint("\rExtracted branches: " << count << "/" << tot_branches << " (" << tainted_branches << " tainted) in " << F.getName().str());
        if(count != tot_branches) {
            if (unidentified_branch) {
                qprint("-- UNIDENTIFIED BRANCH --");
                unidentified_branch->dump();
            }
            qprint("Failed to extract all branches: dumping in failed.bc");
            std::error_code EC;
            if (std::unique_ptr<raw_fd_ostream> os = openFile("./failed.bc")) {
                WriteBitcodeToFile(*F.getParent(), *os);
                (*os).close();
            }
            exit(1);
        }
    }

    virtual bool runOnModule(Module &M) override {
        branchExtractPassLog("Running...");

        std::vector<Regex*> FunctionRegexes;
        if (Functions.empty())
            Functions.push_back(".*");
        passListRegexInit(FunctionRegexes, Functions);

        // Find all functions to analyze
        std::set<Function*> functionSet;
        for (auto &F : M.getFunctionList()) {
            if (F.isDeclaration())
                continue;
            ++totalFunctions;
            const std::string &FName = F.getName();
            if (!passListRegexMatch(FunctionRegexes, FName))
                continue;
            functionSet.insert(&F);
        }

        while (!functionSet.empty()) {
            ++processedFunctions;
            Function *F = *functionSet.begin();
            functionSet.erase(functionSet.begin());
            extractBranches(*F);
        }
        oprint("\r--------[ BRANCH EXTRACT STATS ]--------");
        oprint("[+] Total Functions:    " << totalFunctions    );
        oprint("[+] Processed Functions:" << processedFunctions);
        oprint("[+] Extracted Branches :" << extractedBranches );
        oprint("    [+] Extracted IFCs:     " << extractedIFCs     );
        oprint("    [+] Extracted Loops:    " << extractedLoops    );
        oprint("[+] Extracted Tainted Branches:  " << taintedBranches    );
        oprint("    [+] Extracted Tainted IFCs:       " << taintedIFCs       );
        oprint("    [+] Extracted Tainted Loops:      " << taintedLoops      );
        return true;
    }
 
   void getAnalysisUsage(AnalysisUsage &AU) const override {
        AU.addRequired<DominatorTreeWrapperPass>();
        AU.addRequired<PostDominatorTreeWrapperPass>();
        AU.addRequired<LoopInfoWrapperPass>();
        AU.addUsedIfAvailable<AssumptionCacheTracker>();
    }
  };

}

char BranchExtractPass::ID = 0;
RegisterPass<BranchExtractPass> MP("branch-extract", "Branch Extract Pass");
