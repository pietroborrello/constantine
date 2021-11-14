
#include <pass.h>
#include "WPA/WPAPass.h"
#include "llvm/Transforms/Utils/CallPromotionUtils.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/IRBuilder.h"

using namespace llvm;

#define DEBUG_TYPE "icp"
#define icpPassLog(M) LLVM_DEBUG(dbgs() << "ICPPass: " << M << "\n")
#define oprint(s) dbgs() << s << "\n"

static cl::list<std::string>
Functions("icp-funcs",
    cl::desc("Specify all the comma-separated function regexes to icp"),
    cl::ZeroOrMore, cl::CommaSeparated, cl::NotHidden);

static cl::opt<bool>
VarArgOnly("icp-vararg-only",
    cl::desc("ICP only variadic calls"),
    cl::init(false), cl::NotHidden);

static cl::opt<bool>
Fallback("icp-fallback",
    cl::desc("Leave a fallback indirect call behind"),
    cl::init(false), cl::NotHidden);

static cl::opt<bool>
Abort("icp-abort",
    cl::desc("Leave an abort call for the default case"),
    cl::init(false), cl::NotHidden);

static cl::opt<bool>
TypeAnalysis("icp-type",
    cl::desc("Use faster type-based points-to analysis."),
    cl::init(false), cl::NotHidden);

static cl::opt<bool>
TypeAnalysisOpaquePtrs("icp-type-opaque-ptrs",
    cl::desc("Allow arbitrary ptr casts in type-based points-to analysis."),
    cl::init(true), cl::NotHidden);

static cl::opt<bool>
AliasSVFAnalysis("icp-alias",
    cl::desc("Use slower alias-based points-to analysis."),
    cl::init(false), cl::NotHidden);

namespace {

  class ICPPass : public ModulePass {

  public:
    static char ID;
    ICPPass() : ModulePass(ID) {}

    bool isCompatibleType(Type *T1, Type *T2) {
        // Check if 2 types are the same, tolerating void* (i8*) pointer casts.
        if (T1 == T2)
            return true;
        if (!T1->isPointerTy() || !T2->isPointerTy())
            return false;
        // If requested, be even more conservative (any pointer cast will do).
        if (TypeAnalysisOpaquePtrs)
            return true;
        Type *CT1 = T1->getContainedType(0);
        Type *CT2 = T2->getContainedType(0);
        if (CT1->isIntegerTy() && CT1->getPrimitiveSizeInBits() == 8)
            return true;
        if (CT2->isIntegerTy() && CT2->getPrimitiveSizeInBits() == 8)
            return true;

        return false;
    }

    bool csTypeAlias(CallSite &CS, Function *F) {
        Value *V = CS.getCalledValue()->stripPointerCasts();
        FunctionType *FT= F->getFunctionType();
        FunctionType *CT= cast<FunctionType>(V->getType()->getContainedType(0));

        // Fast path: perfect type match.
        if (FT == CT)
            return true;

        // Return types have to match, unless the callsite doesn't care.
        if (!CT->getReturnType()->isVoidTy()
            && !isCompatibleType(CT->getReturnType(), FT->getReturnType()))
            return false;

        // Match #arguments and #parameters (account for variadic functions).
        if (CS.arg_size() < FT->getNumParams())
            return false;
        if (CS.arg_size() > FT->getNumParams() && !F->isVarArg())
            return false;

        // Make sure each argument has compatible type with corresponding param.
        for (unsigned i=0; i<CS.arg_size(); i++) {
            Type *PT = i < FT->getNumParams() ? FT->getParamType(i) : NULL;
            if (!PT)
                break;
            if (!isCompatibleType(PT, CS.getArgument(i)->getType()))
                return false;
        }

        return true;
    }

    void getIndirectCallees(Module *M, CallSite &CS, std::vector<Function*> &callees, WPAPass *wpa) {
        // Grab functions that may alias value at the callsite
        Value *V = CS.getCalledValue()->stripPointerCasts();
        for (auto &F : M->getFunctionList()) {
            if (!F.hasAddressTaken())
                continue;
            if (VarArgOnly && Fallback && !F.isVarArg())
                continue;

            if (AliasSVFAnalysis && TypeAnalysis) {
                if (csTypeAlias(CS, &F) && wpa->alias(V, &F))
                    callees.push_back(&F);
            }

            // Use points-to analysis if requested
            if (!TypeAnalysis) {
                if (wpa->alias(V, &F))
                    callees.push_back(&F);
                continue;
            }

            // Or faster callsite type-based analysis otherwise
            if (csTypeAlias(CS, &F))
                callees.push_back(&F);
        }
    }

    void promoteIndirectCall(Function *F, Instruction *I, WPAPass *wpa) {
        Module* M = F->getParent();
        LLVMContext& C = M->getContext();

        // retrieve the errx function
        std::vector<Type *> args;
        args.push_back(Type::getInt32Ty(C));
        args.push_back(Type::getInt8PtrTy(C));
        FunctionType *FT = FunctionType::get(Type::getVoidTy(C), args, true);
        FunctionCallee _errx = M->getOrInsertFunction("errx", FT);
        assert(_errx);
        Function *ErrxF = dyn_cast<Function>(_errx.getCallee());
        assert(ErrxF);

        oprint("Promoting indirect call: " << *I << " in " << F->getName().str());
        // Get indirect callees
        CallSite CS(I);
        std::vector<Function*> callees;
        getIndirectCallees(F->getParent(), CS, callees, wpa);
        if (callees.empty()) {
            // For now we fail if we are not using the type analysis, since we may
            // are using SVF wrongly:
            // https://github.com/SVF-tools/SVF/issues/280
            assert(TypeAnalysis);
            if (Abort) {
                // insert an abort call in place of the indirect default call
                Instruction *OldCall = CS.getInstruction();
                BasicBlock* ThisBB = CS.getInstruction()->getParent();
                Instruction* LastI = ThisBB->getTerminator();
                UnreachableInst* UI = new UnreachableInst(C, LastI);

                // remove the values coming from the phi nodes of the successors
                for (BasicBlock* SuccBB: successors(ThisBB)) {
                    for (PHINode &Phi: SuccBB->phis()) {
                        Phi.removeIncomingValue(ThisBB);
                    }
                }

                // replace the return value of the call with undefined
                OldCall->replaceAllUsesWith(UndefValue::get(OldCall->getType()));

                // add the call to the errx function
                std::vector<Value*> args;
                args.push_back( ConstantInt::get(Type::getInt32Ty(C), 0));
                std::string str = "ICP UNREACHABLE";
                llvm::IRBuilder<> builder(ThisBB);
                static Value* error_string = builder.CreateGlobalStringPtr(StringRef(str));
                args.push_back(error_string);
                CallInst *CI = CallInst::Create(ErrxF, args, "",OldCall);
                CI->addAttribute(AttributeList::FunctionIndex, Attribute::NoReturn);

                // remove the old call and the branch to leave unreachable instr
                OldCall->eraseFromParent();
                LastI->eraseFromParent();
                assert(ThisBB->getTerminator() == UI);
            }
            oprint("No callees available");
            return;
        }
        oprint(callees.size() << " callees possible");

        // Check if we should only promote indirect calls to variadic functions.
        if (VarArgOnly) {
            bool hasVarArgCallee = false;
            for (auto Callee : callees) {
                if (Callee->isVarArg())
                    hasVarArgCallee = true;
            }
            if (!hasVarArgCallee)
                return;
        }

        // Promote with or without indirect call fallback.
        Function *lastCallee = NULL;
        for (auto Callee : callees) {
            oprint("possible callee: " << Callee->getName().str());
            if (lastCallee)
                promoteCallWithIfThenElse(CS, lastCallee);
            lastCallee = Callee;
        }
        if (Fallback)
            promoteCallWithIfThenElse(CS, lastCallee);
        else if (Abort) {
            // create the last branch with the remaining indirect call
            promoteCallWithIfThenElse(CS, lastCallee);

            // insert an abort call in place of the indirect default call
            Instruction *OldCall = CS.getInstruction();
            BasicBlock* ThisBB = CS.getInstruction()->getParent();
            Instruction* LastI = ThisBB->getTerminator();
            UnreachableInst* UI = new UnreachableInst(C, LastI);

            // remove the values coming from the phi nodes of the successors
            for (BasicBlock* SuccBB: successors(ThisBB)) {
                for (PHINode &Phi: SuccBB->phis()) {
                    Phi.removeIncomingValue(ThisBB);
                }
            }

            // replace the return value of the call with undefined
            OldCall->replaceAllUsesWith(UndefValue::get(OldCall->getType()));

            // add the call to the errx function
            std::vector<Value*> args;
            args.push_back( ConstantInt::get(Type::getInt32Ty(C), 0));
            std::string str = "ICP UNREACHABLE";
            llvm::IRBuilder<> builder(ThisBB);
            static Value* error_string = builder.CreateGlobalStringPtr(StringRef(str));
            args.push_back(error_string);
            CallInst *CI = CallInst::Create(ErrxF, args, "",OldCall);
            CI->addAttribute(AttributeList::FunctionIndex, Attribute::NoReturn);

            // remove the old call and the branch to leave unreachable instr
            OldCall->eraseFromParent();
            LastI->eraseFromParent();
            assert(ThisBB->getTerminator() == UI);
        } else {
            promoteCall(CS, lastCallee);
        }
    }

    void icp(Function *F, WPAPass *wpa) {
        std::vector<Instruction *> indirectCalls;

        // Collect indirect calls.
        for (auto &BB : *F)
        for (auto &I : BB) {
            CallSite CS(&I);
            if (!CS.getInstruction() || CS.isInlineAsm())
                continue;
            if (isa<Function>(CS.getCalledValue()->stripPointerCasts()))
                continue;
            indirectCalls.push_back(&I);
        }

        // Promote.
        for (auto I : indirectCalls) {
            promoteIndirectCall(F, I, wpa);
        }
    }

    virtual bool runOnModule(Module &M) {
        icpPassLog("Running...");
        assert(!(Abort && Fallback) && 
            "Only a mode between icp-unreachable and icp-fallback can be selected");
        SVFModule* svfModule = LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(M);
        WPAPass *wpa = NULL;
        assert(AliasSVFAnalysis || TypeAnalysis);
        if (AliasSVFAnalysis) {
            wpa = new WPAPass();
            wpa->runOnModule(svfModule);
        }

        std::vector<Regex*> FunctionRegexes;
        if (Functions.empty())
            Functions.push_back(".*");
        passListRegexInit(FunctionRegexes, Functions);

        // ICP all the functions in the module.
        for (auto &F : M.getFunctionList()) {
            if (F.isDeclaration())
                continue;
            const std::string &FName = F.getName();
            if (!passListRegexMatch(FunctionRegexes, FName))
                continue;
            icp(&F, wpa);
        }

        return true;
    }
  };

}

char ICPPass::ID = 0;
RegisterPass<ICPPass> MP("icp", "ICP Pass");
