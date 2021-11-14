#include <pass.h>
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/CFG.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionExpressions.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "SVF-FE/GEPTypeBridgeIterator.h" // include bridge_gep_iterator
#include "llvm/IR/IRBuilder.h"

using namespace llvm;
#define oprint(s) (outs() << s << "\n")
typedef long imd_t;

static cl::opt<bool>
SimpleVars("mark-only-simple-vars",
    cl::desc("Mark only simple variables that start from constant values"),
    cl::init(false), cl::NotHidden);

static cl::opt<bool>
Convert("convert-ptr-to-indexes",
    cl::desc("Convert pointer accesses into array-indexed accesses"),
    cl::init(true), cl::NotHidden);

namespace {
  // This pass (tentatively) marks all the loop induction
  // variables. This will be leveraged in DFL since it will avoid striding accesses that depend on such 
  // variables, since the offset cannot depend on tainted data
  // Optionally, it can convert induction variable expressed as pointers to array-
  // indexed form. Similarly to the LoopStrengthReduce pass, but with a nicer form,
  // keeping the right types, and for all values which are actually used in memory accesses
  class MarkInductionVariablesPass : public FunctionPass {

    unsigned long ConvertedInstructions = 0;
    unsigned long TotToConvert          = 0;
    unsigned long nInductionVars        = 0;
    
  public:
    static char ID; // Pass identification, replacement for typeid
    MarkInductionVariablesPass() : FunctionPass(ID) {
    }

    ~MarkInductionVariablesPass() {
        // We should not be allowed to keep info between runOnLoop invocations,
        // but we like living dangerously
        oprint("--------[ MARK INDVAR STATS ]--------");
        oprint("[+] Total to Convert:       " << TotToConvert);
        oprint("[+] Converted Instructions: " << ConvertedInstructions);
        oprint("[+] Num Induction Vars:     " << nInductionVars);
    }

    bool hasNullInit(PHINode *PHI) {
        for (Value* val : PHI->incoming_values()) {
            if (ConstantInt* CI = dyn_cast<ConstantInt>(val)) {
                unsigned long v = CI->getZExtValue();
                if (v == 0) return true;
            }
        }
        return false;
    }

    bool hasConstInit(PHINode *PHI) {
        for (Value* val : PHI->incoming_values()) {
            if (isa<Constant>(val)) return true;
        }
        return false;
    }

    void markInstruction(Instruction *I) {
        assert(I);
        LLVMContext& C = I->getContext();
        MDNode* N = MDNode::get(C, ConstantAsMetadata::get(ConstantInt::get(C, APInt(sizeof(imd_t)*8, 1, true))));
        I->setMetadata("indvar", N);

        ++nInductionVars;
    }

    // Return the value which represents the GEP variant index, and the type it 
    // indexes on
    // check there is one and only one of such value
    std::pair<Value*, Type*> getVariantIndex(GetElementPtrInst* GEP) {
        Value *res      = nullptr;
        Type  *res_type = nullptr;
        for (bridge_gep_iterator gi = bridge_gep_begin(GEP), ge = bridge_gep_end(GEP);
            gi != ge; ++gi) {

            // Allow only constant integers as GEP indexes
            if (isa<ConstantInt>(gi.getOperand())) {
                continue;
            }

            assert(!res && "The GEP operation has multiple variable indexes");
            res = gi.getOperand();
            res_type = *gi;
        }
        assert(res && "The GEP operation has no variable indexes");

        return std::make_pair(res, res_type);
    }

    Value* getLastIndex(GetElementPtrInst *GEP) {
        assert(GEP);
        return GEP->getOperand(GEP->getNumIndices());
    }

    void setLastIndex(GetElementPtrInst *GEP, Value *V) {
        assert(GEP);
        GEP->setOperand(GEP->getNumIndices(), V);
    }

    ConstantInt* makeConstI32(LLVMContext &C, int value) {
        return ConstantInt::get(C, APInt(sizeof(int)*8, value, true));
    }

    ConstantInt* makeConstI64(LLVMContext &C, unsigned long value) {
        return ConstantInt::get(C, APInt(sizeof(unsigned long)*8, value, /*isSigned=*/true));
    }

    ConstantInt *getStepForType(Type* T, long step) {
        assert(T->isPointerTy());
        if(T->getPointerElementType()->isPointerTy())
            return makeConstI64(T->getContext(), sizeof(void*));
        long typeWidth = T->getPointerElementType()->getScalarSizeInBits()/8;
        return makeConstI64(T->getContext(), step/typeWidth);
    }

    void setPtrOperand(Instruction* I, Value *V) {
        if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
            LI->setOperand(0, V);
        }
        else if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
            SI->setOperand(1, V);
        } else {
            assert(false && "need a memory access");
        }
    }

    /// Convert all the induction variable pointers that are accessed in the loop
    /// to array based accesses such that:
    /// Transform each pointer such that:
    /// base:
    ///   p_start = gep [N x i64] obj, start_idx
    /// for:
    ///   p = phi(p_start from `base`, p_next from `for`)
    ///   [...]
    ///   load *p
    ///   p_next = gep i64 p, 1
    ///   [...]
    ///   brcc for, exit
    /// exit:
    ///
    /// --> becomes
    ///
    ///   p_start = gep [N x i64] obj, start_idx
    /// for:
    ///   p = phi(p_start from `base`, p_next from `for`)
    ///   i = phi(start_idx from `base`, i_next from `for`)
    ///   [...]
    ///   a = gep [N x i64] obj, i 
    ///   load *a
    ///   p_next = gep i64 p, 1
    ///   i_next = add i, 1
    ///   [...]
    ///   brcc for, exit
    /// exit:
    ///
    /// notice that no instruction gets removed as others may use the ptr values
    void convertPointers(Function *F, Loop *L, ScalarEvolution &SE, std::map<Value*, std::tuple<Value*, int, int> > IndVarMap) {
        std::set<Instruction*> ins;
        // collect all the instructions to convert
        for (BasicBlock *BB: L->getBlocks()) {
            for (Instruction &I : *BB) {
                // Get the pointer operand of the memory access
                Value *ptr = nullptr;
                if (LoadInst *LI = dyn_cast<LoadInst>(&I)) {
                    ptr = LI->getPointerOperand();
                }
                if (StoreInst *SI = dyn_cast<StoreInst>(&I)) {
                    ptr = SI->getPointerOperand();
                }
                if (!ptr) continue;

                // Ignore if the pointer is not an induction variable
                if (IndVarMap.find(ptr) == IndVarMap.end()) continue;

                // If the instruction is a gep with already an invariant index continue
                if (isa<GetElementPtrInst>(ptr)) {
                    // make sure asserts will succeed
                    getVariantIndex(dyn_cast<GetElementPtrInst>(ptr));
                    continue;
                }

                // Convert the instruction
                TotToConvert++;
                ins.insert(&I);
            }
        }
        for (Instruction *I: ins) {
            Value *ptr = nullptr;
            if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
                ptr = LI->getPointerOperand();
            }
            if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
                ptr = SI->getPointerOperand();
            }
            assert(ptr);

            const SCEV *_ptrSCEV = SE.getSCEVAtScope(ptr, L);
            if (isa<SCEVCouldNotCompute>(_ptrSCEV)) continue;

            // Just deal with simple operations
            const SCEVAddRecExpr *ptrSCEV = dyn_cast<SCEVAddRecExpr>(_ptrSCEV);
            if(!ptrSCEV || !ptrSCEV->isAffine()) continue;

            const SCEVConstant   *stepSCEV = dyn_cast<SCEVConstant>(ptrSCEV->getStepRecurrence(SE));
            if(!stepSCEV) continue;

            // Get the stepping value
            long step = stepSCEV->getAPInt().getSExtValue();
            Value *stepV = getStepForType(ptr->getType(), step);

            // We try to stay simple here and assume the induction variable is a phi node
            PHINode *PHI = dyn_cast<PHINode>(ptr);
            if (!PHI) continue;

            // Get the base value for the phi node
            if (PHI->getParent() != L->getHeader() || !L->getLoopPreheader()) continue;

            Value *baseValue = PHI->getIncomingValueForBlock(L->getLoopPreheader());
            assert(PHI->getIncomingValueForBlock(L->getExitingBlock()));

            // We only accept GEP or function parameters
            // We avoid dealing with bitcasts changing the pointer type to avoid
            // introducing invalid GEPs which would incorrectly index the object
            if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(baseValue)) {
                Type *baseType = GEP->getSourceElementType();
                // Value *baseObj = GEP->getOperand(0);
                Value *startIndex = getLastIndex(GEP);

                // only accept indexing on structures or arrays, otherwise should
                // recursively find the right index for the pointer expression
                if(!isa<StructType>(baseType) && !isa<ArrayType>(baseType)) {
                    continue;
                }

                // insert the phi node to update the index
                PHINode* Index = PHINode::Create(startIndex->getType(), 2, 
                "index", &*(PHI->getParent()->getFirstInsertionPt()));
                Index->addIncoming(startIndex, L->getLoopPreheader());

                // insert the add instruction to update the index
                Value *nextIndex = BinaryOperator::CreateAdd(Index, stepV, 
                                "", &*(PHI->getParent()->getFirstInsertionPt()));
                Index->addIncoming(nextIndex, L->getExitingBlock());

                // insert the GEP to retrieve the right pointer at runtime
                Instruction* newGEP = GEP->clone();
                newGEP->insertBefore(I);
                newGEP->setName(GEP->getName() + ".idx");
                setLastIndex(dyn_cast<GetElementPtrInst>(newGEP), Index);

                // mark the GEP as an induction variable
                markInstruction(newGEP);

                // set the pointer for the memory access
                setPtrOperand(I, newGEP);

            } else if (Argument *ARG = dyn_cast<Argument>(baseValue)) {
                // Value *startIndex = makeConstI64(F->getContext(), 0);
                // How can we be sure that the function argument indexes on the start of an object?
                // so for now avoid this. Otherwise should check that in every caller of the function
                continue;
            } else {
                continue;
            }
            ConvertedInstructions++;
        }
    }

    bool runOnFunction(Function &F) override {
        LoopInfo &LI = getAnalysis<LoopInfoWrapperPass>().getLoopInfo();
        ScalarEvolution &SE = getAnalysis<ScalarEvolutionWrapperPass>().getSE();

        // oprint("-----------------");
        // oprint("Function: " << F.getName());

        // EDITED from https://www.cs.cornell.edu/courses/cs6120/2019fa/blog/strength-reduction-pass-in-llvm/
        // find all loop induction variables within a loop
        for(Loop* L : LI.getLoopsInPreorder()) {
            // IndVarMap = {indvar: indvar tuple}
            // indvar tuple = (basic_indvar, scale, const)
            // indvar = basic_indvar * scale + const
            std::map<Value*, std::tuple<Value*, int, int> > IndVarMap;

            // all induction variables should have phi nodes in the header
            // notice that this might add additional variables, they are treated as basic induction
            // variables for now

            // the header block
            BasicBlock* b_header = L->getHeader();

            for (auto &I : *b_header) {
                if (PHINode *PN = dyn_cast<PHINode>(&I)) {
                    // EDIT: we only want simple induction variables starting from zero
                    if (SimpleVars == true && hasNullInit(PN) == false) continue;
                    IndVarMap[&I] = std::make_tuple(&I, 1, 0);
                }
            }
            
            // get the total number of blocks as well as the block list
            //cout << L->getNumBlocks() << "\n";
            auto blks = L->getBlocks();

            // find all indvars
            // keep modifying the set until the size does not change
            // notice that over here, our set of induction variables is not precise
            while (true) {
                std::map<Value*, std::tuple<Value*, int, int> > NewMap = IndVarMap;
                // iterate through all blocks in the loop
                for (auto B: blks) {
                    // iterate through all its instructions
                    for (auto &I : *B) {
                        // EDIT accept also GEPs, as they represent striding pointers
                        // e.g. `while(*s++)`
                        if (GetElementPtrInst* GEP = dyn_cast<GetElementPtrInst>(&I)) {
                            // check if one of the operands belongs to indvars
                            bool found = false;
                            Value *op = nullptr;
                            for (bridge_gep_iterator gi = bridge_gep_begin(GEP), ge = bridge_gep_end(GEP);
                                gi != ge; ++gi) {
                                // accept only GEP which depends on IndVars, and do
                                // non contain any other non constant value
                                if (IndVarMap.count(gi.getOperand())) {
                                    found = true;
                                    op    = gi.getOperand();
                                } else if(isa<ConstantInt>(gi.getOperand()) == false) {
                                    found = false;
                                    break;
                                }
                            }
                            if (found) {
                                std::tuple<Value*, int, int> t = IndVarMap[op];
                                // NOTICE: WE DO NOT USE THE MEDATADA IN THE MAP
                                //         SO NO EFFORT HAS BEEN MADE TO COMPUTE
                                //         THE CORRESPONDING GEP OFFSET, HERE 0 INSTEAD
                                int new_val = 0 + std::get<2>(t);
                                NewMap[&I] = std::make_tuple(std::get<0>(t), std::get<1>(t), new_val);
                            }
                        }
                        // we only accept multiplication, addition, and subtraction
                        // we only accept constant integer as one of theoperands
                        else if (auto *op = dyn_cast<BinaryOperator>(&I)) {
                            Value *lhs = op->getOperand(0);
                            Value *rhs = op->getOperand(1);
                            // check if one of the operands belongs to indvars
                            if (IndVarMap.count(lhs) || IndVarMap.count(rhs)) {
                                // case: Add
                                if (I.getOpcode() == Instruction::Add) {
                                    ConstantInt* CIL = dyn_cast<ConstantInt>(lhs);
                                    ConstantInt* CIR = dyn_cast<ConstantInt>(rhs);
                                    if (IndVarMap.count(lhs) && CIR) {
                                        std::tuple<Value*, int, int> t = IndVarMap[lhs];
                                        int new_val = CIR->getSExtValue() + std::get<2>(t);
                                        NewMap[&I] = std::make_tuple(std::get<0>(t), std::get<1>(t), new_val);
                                    } else if (IndVarMap.count(rhs) && CIL) {
                                        std::tuple<Value*, int, int> t = IndVarMap[rhs];
                                        int new_val = CIL->getSExtValue() + std::get<2>(t);
                                        NewMap[&I] = std::make_tuple(std::get<0>(t), std::get<1>(t), new_val);
                                    }
                                // case: Sub
                                } else if (I.getOpcode() == Instruction::Sub) {
                                    ConstantInt* CIL = dyn_cast<ConstantInt>(lhs);
                                    ConstantInt* CIR = dyn_cast<ConstantInt>(rhs);
                                    if (IndVarMap.count(lhs) && CIR) {
                                        std::tuple<Value*, int, int> t = IndVarMap[lhs];
                                        int new_val = std::get<2>(t) - CIR->getSExtValue();
                                        NewMap[&I] = std::make_tuple(std::get<0>(t), std::get<1>(t), new_val);
                                    } else if (IndVarMap.count(rhs) && CIL) {
                                        std::tuple<Value*, int, int> t = IndVarMap[rhs];
                                        int new_val = std::get<2>(t) - CIL->getSExtValue();
                                        NewMap[&I] = std::make_tuple(std::get<0>(t), std::get<1>(t), new_val);
                                    }
                                // case: Mul
                                } else if (I.getOpcode() == Instruction::Mul) {
                                    ConstantInt* CIL = dyn_cast<ConstantInt>(lhs);
                                    ConstantInt* CIR = dyn_cast<ConstantInt>(rhs);
                                    if (IndVarMap.count(lhs) && CIR) {
                                        std::tuple<Value*, int, int> t = IndVarMap[lhs];
                                        int new_val = CIR->getSExtValue() * std::get<1>(t);
                                        NewMap[&I] = std::make_tuple(std::get<0>(t), new_val, std::get<2>(t));
                                    } else if (IndVarMap.count(rhs) && CIL) {
                                        std::tuple<Value*, int, int> t = IndVarMap[rhs];
                                        int new_val = CIL->getSExtValue() * std::get<1>(t);
                                        NewMap[&I] = std::make_tuple(std::get<0>(t), new_val, std::get<2>(t));
                                    }
                                }
                            } // if operand in indvar
                        } // if op is binop
                    } // auto &I: B
                } // auto &B: blks
                if (NewMap.size() == IndVarMap.size()) break;
                else IndVarMap = NewMap;
            }

            // oprint("Loop: " << L->getExitingBlock()->getName());
            for (auto indvar : IndVarMap) {
                markInstruction(dyn_cast<Instruction>(indvar.first));
                // oprint(*indvar.first);
            }

            if (Convert)
                convertPointers(&F, L, SE, IndVarMap);
        }
        return true;
    }

    void getAnalysisUsage(AnalysisUsage &AU) const override {
        AU.addRequired<ScalarEvolutionWrapperPass>();
        AU.addRequired<LoopInfoWrapperPass>();
        AU.addRequired<TargetLibraryInfoWrapperPass>();
    }
  };
}

char MarkInductionVariablesPass::ID = 0;
RegisterPass<MarkInductionVariablesPass> DBGPP("mark-induction-variables", "Mark induction variables in loops");
