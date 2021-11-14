
#include <pass.h>

#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IRBuilder.h"

using namespace llvm;

#define DEBUG_TYPE "hook"
#define hookPassLog(M) LLVM_DEBUG(dbgs() << "HookPass: " << M << "\n")
#define oprint(s) LLVM_DEBUG(outs() << s << "\n")

static cl::list<std::string>
Functions("hook-funcs",
    cl::desc("Specify all the comma-separated function regexes to hook"),
    cl::ZeroOrMore, cl::CommaSeparated, cl::NotHidden);

static cl::opt<std::string>
HookPrefix("hook-prefix",
    cl::desc("Specify the hook function prefix"),
    cl::init("__hook_"), cl::NotHidden);

static cl::list<std::string>
HookBaseArgs("hook-base-args",
    cl::desc("Specify all the comma-separated metadata IDs for the arguments"),
    cl::ZeroOrMore, cl::CommaSeparated, cl::NotHidden);

static cl::opt<bool>
HookBaseArgsTLS("hook-base-args-tls",
    cl::desc("Use TLS for base arguments storage as needed"),
    cl::init(true), cl::NotHidden);

static cl::opt<bool>
PreHookEnabled("hook-pre",
    cl::desc("Enable pre hooks"),
    cl::init(true), cl::NotHidden);

static cl::opt<bool>
WrapHookEnabled("hook-wrap",
    cl::desc("Enable wrap hooks"),
    cl::init(true), cl::NotHidden);

static cl::opt<bool>
PostHookEnabled("hook-post",
    cl::desc("Enable post hooks"),
    cl::init(true), cl::NotHidden);

static cl::opt<bool>
Inline("hook-inline",
    cl::desc("Inline hooks"),
    cl::init(false), cl::NotHidden);

typedef long imd_t;

namespace {

  class HookPass : public ModulePass {

  public:
    static char ID;
    HookPass() : ModulePass(ID) {}

    class Hooks {
    public:
        Function *Pre;
        Function *Wrap;
        Function *Post;
        std::map<Type*, Function*> PreTypeMap;
        std::map<Type*, Function*> WrapTypeMap;
        std::map<Type*, Function*> PostTypeMap;
        Hooks(Function *x, Function *y, Function *z) { Pre=x; Wrap=y; Post=z; }

        static void cast_i128_to_i64_i64(Value *V, Instruction *InsertBefore, Value** low, Value **high) {
            LLVMContext& C = V->getContext();
            Type* type   = V->getType();
            Type* i128Ty = Type::getInt128Ty(C);
            Type* i64Ty  = Type::getInt64Ty(C);

            assert(type == i128Ty);

            // extract the low and high part of the i128
            *low      = CastInst::CreateTruncOrBitCast(V, i64Ty, "", InsertBefore);
            Value* shiftedV =  BinaryOperator::CreateLShr(V, 
                ConstantInt::get(Type::getInt128Ty(C), 64), "", InsertBefore);
            *high     = CastInst::CreateTruncOrBitCast(shiftedV, i64Ty, "", InsertBefore);
        }

        // Check if the type is a {i64, i64}, since it usually corresponds to an i128 return type
        static bool is_i64_i64_type(Type *_type) {
            LLVMContext& C = _type->getContext();
            if (!_type || !_type->isStructTy())
                return false;
            StructType *type = dyn_cast<StructType>(_type);
            assert(type);
            Type* i64Ty  = Type::getInt64Ty(C);
            return type->getNumElements() == 2 && 
                type->getElementType(0) == i64Ty && type->getElementType(1) == i64Ty;
        }

        static Value *cast_i64_i64_to_i128(Value *V, Instruction *InsertBefore) {
            LLVMContext& C = V->getContext();

            Type* i128Ty = Type::getInt128Ty(C);
            SmallVector<unsigned, 1> EVIndexes;

            assert(is_i64_i64_type(V->getType()));

            // Extract the elements from the {i64, i64} struct
            EVIndexes.push_back(0);
            Value* low = ExtractValueInst::Create(V, EVIndexes, "", InsertBefore);
            EVIndexes.clear();
            EVIndexes.push_back(1);
            Value* high = ExtractValueInst::Create(V, EVIndexes, "", InsertBefore);

            // `shift left` the high part by 64
            Value *high128 = CastInst::CreateZExtOrBitCast(high, i128Ty, "", InsertBefore);
            Value *shiftedHigh = BinaryOperator::CreateShl(high128, 
                ConstantInt::get(Type::getInt128Ty(C), 64), "", InsertBefore);

            // `or` with the low part
            Value *low128 = CastInst::CreateZExtOrBitCast(low, i128Ty, "", InsertBefore);
            Value *final128 = BinaryOperator::CreateOr(low128, shiftedHigh, "", InsertBefore);
            return final128;
        }

        static Hooks* get(Module *M, std::string &pre, std::string &wrap, std::string &post) {
            Hooks *H;
            Function *Pre = PreHookEnabled ? M->getFunction(pre) : NULL;
            Function *Wrap = WrapHookEnabled ? M->getFunction(wrap) : NULL;
            Function *Post = PostHookEnabled ? M->getFunction(post) : NULL;
            H = Pre || Wrap || Post ? new Hooks(Pre, Wrap, Post) : NULL;
            if (PreHookEnabled)
                addTypeFunctions(M, pre, H->PreTypeMap);
            if (WrapHookEnabled)
                addTypeFunctions(M, wrap, H->WrapTypeMap);
            if (PostHookEnabled)
                addTypeFunctions(M, post, H->PostTypeMap);
            return H;
        }

        static Function* getFunction(Function *F, Type *T, std::map<Type*, Function*> &typeMap) {
            auto it = typeMap.find(T);
            return it == typeMap.end() ? F : it->second;
        }

        static void addTypeFunctions(Module *M, std::string &prefix, std::map<Type*, Function*> &typeMap) {
            unsigned id=1;
            char snum[16];
            while(1) {
                sprintf(snum, "%u", id++);
                Function *F = M->getFunction(prefix + "_t" + snum);
                if (!F)
                    break;
                Type *retType = F->getReturnType();
                // check if it is a packed i128
                if (is_i64_i64_type(retType))
                    retType = Type::getInt128Ty(M->getContext());
                typeMap.insert(std::pair<Type*, Function*>(retType, F));
            }
        }
    };

    Constant* getIntMetadata(Value *V, const char *key, imd_t &value) {
        MDNode* N;
        if (Instruction *I = dyn_cast<Instruction>(V))
            N = I->getMetadata(key);
        else if (BasicBlock *BB = dyn_cast<BasicBlock>(V))
            N = BB->getTerminator()->getMetadata(key);
        else if (Function *F = dyn_cast<Function>(V))
            N = F->getMetadata(key);
        else
            assert(0 && "Not implemented!");
        if (!N) {
            value = 0;
            return NULL;
        }
        Constant *val = dyn_cast<ConstantAsMetadata>(N->getOperand(0))->getValue();
        assert(val);
        value = cast<ConstantInt>(val)->getSExtValue();

        return val;
    }

    Value* createCast(Value *V, Type *T, Instruction *I) {
        LLVMContext& C = I->getContext();
        if (V->getType() == T)
            return V;
        if (V->getType()->isLabelTy() && T->isIntegerTy())
            return ConstantInt::get(C, APInt(T->getIntegerBitWidth(), 0, false));
        if (T->isFloatingPointTy() ^ V->getType()->isFloatingPointTy()) {
            if (V->getType()->isFloatingPointTy())
                return new FPToSIInst(V, T, "", I);
            else
                return new SIToFPInst(V, T, "", I);
        }
        if (T->isPointerTy() || V->getType()->isPointerTy())
            return CastInst::CreateBitOrPointerCast(V, T, "", I);
        if (T->isIntegerTy())
            return CastInst::CreateIntegerCast(V, T, true, "", I);
        if (T->isFloatingPointTy())
            return CastInst::CreateFPCast(V, T, "", I);
        assert(0 && "Unhandled cast!");
        return NULL;
    }

    unsigned initHookBaseArgs(Instruction *I, Function *F, std::vector<Value*> &args, unsigned offset=0) {
        LLVMContext& C = I->getContext();
        Constant *ZeroValue = ConstantInt::get(C, APInt(sizeof(imd_t)*8, 0, true));
        for (auto arg : HookBaseArgs) {
            imd_t value;
            Constant *ConstantValue = getIntMetadata(I, arg.c_str(), value);
            if (!ConstantValue)
                ConstantValue = getIntMetadata(I->getParent(), arg.c_str(), value);
            if (!ConstantValue)
                ConstantValue = getIntMetadata(F, arg.c_str(), value);
            if (!ConstantValue)
                ConstantValue = ZeroValue;
            Type *T = F->getFunctionType()->getParamType(offset);
            if (!T->isPointerTy()) {
                args.push_back(createCast(ConstantValue, T, I));
                offset++;
                continue;
            }
            GlobalVariable *GV = new GlobalVariable(*(F->getParent()), T->getContainedType(0),
                false, GlobalValue::LinkageTypes::InternalLinkage, ConstantValue,
                HookPrefix + "arg." + arg, nullptr, HookBaseArgsTLS ? GlobalValue::ThreadLocalMode::GeneralDynamicTLSModel : GlobalValue::ThreadLocalMode::NotThreadLocal);
            GV->setSection(HookPrefix + "sec");
            args.push_back(GV);
            offset++;
        }
        return offset;
    }

    unsigned initHookArgs(Instruction *I, Function *F, std::vector<Value*> &args, unsigned offset=0) {
        LLVMContext& C = I->getContext();
        Type* i128Ty = Type::getInt128Ty(C);
        Type* i64Ty = Type::getInt64Ty(C);
        for (auto V : I->operand_values()) {
            FunctionType *FT = F->getFunctionType();
            Type *T = offset < FT->getNumParams() ? FT->getParamType(offset) : NULL;
            if (!T) {
                if (F->isVarArg())
                    args.push_back(V);
                break;
            }
            else if( V->getType() == i128Ty) {
                // special case for passing i128 according to llvm ABI
                Value* low;
                Value* high;
                assert(T == i64Ty);
                Hooks::cast_i128_to_i64_i64(V, I, &low, &high);
                args.push_back(low);
                args.push_back(high);
                offset+=2;
            } else {
                args.push_back(createCast(V, T, I));
                offset++;
            }
        }
        return offset;
    }

    void hookInlineAsNeeded(CallInst *CI) {
        static InlineFunctionInfo IFI;
        if (!Inline)
            return;
        CallSite CS(CI);
        InlineFunction(CS, IFI);
    }

    void preHook(Instruction *I, Function *F) {
        if (!F)
            return;
        oprint("[+] preHook: " << F->getName().str());
        oprint("    on: " << *I);
        std::vector<Value*> args;
        unsigned offset = initHookBaseArgs(I, F, args);
        initHookArgs(I, F, args, offset);
        CallInst *CI = CallInst::Create(F, args, "", I);
        hookInlineAsNeeded(CI);
    }

    void wrapHook(Instruction *I, Function *F) {
        if (!F)
            return;
        LLVMContext& C = I->getContext();
        Type* i128Ty = Type::getInt128Ty(C);
        oprint("[+] wrapHook: " << F->getName().str());
        oprint("    on: " << *I);
        std::vector<Value*> args;
        unsigned offset = initHookBaseArgs(I, F, args);
        initHookArgs(I, F, args, offset);
        CallInst *CI = CallInst::Create(F, args, "", I);
        if (I->getType() == i128Ty) {
            Value *CstI = Hooks::cast_i64_i64_to_i128(CI, I);
            I->replaceAllUsesWith(CstI);
        }
        else if (!I->getType()->isVoidTy())
            I->replaceAllUsesWith(createCast(CI, I->getType(), I));
        I->eraseFromParent();
        hookInlineAsNeeded(CI);
    }

    void postHook(Instruction *I, Function *F) {
        if (!F)
            return;
        Instruction *NextI = I->getNextNonDebugInstruction();
        if (!NextI)
            return;
        oprint("[+] postHook: " << F->getName().str());
        oprint("    on: " << *I);
        std::vector<Value*> args;
        unsigned i = initHookBaseArgs(I, F, args);
        FunctionType *FT = F->getFunctionType();
        Type *T = i < FT->getNumParams() ? FT->getParamType(i) : NULL;
        if (!I->getType()->isVoidTy() && T) {
            args.push_back(createCast(I, T, NextI));
            i++;
        }
        initHookArgs(I, F, args, i);
        CallInst *CI = CallInst::Create(F, args, "", NextI);
        hookInlineAsNeeded(CI);
    }

    void hook(Instruction *I) {
        static std::map< std::string, Hooks* > functionMap;
        static const char * const IntrinsicNameTable[] = {
          "not_intrinsic",
          #define GET_INTRINSIC_NAME_TABLE
          #include "llvm/IR/IntrinsicImpl.inc"
          #undef GET_INTRINSIC_NAME_TABLE
          NULL
        };
        static std::string IntrinsicFuncNameTable[sizeof(IntrinsicNameTable)/sizeof(const char* const)];

        // Initialize intrinsic function name table the first time
        if (IntrinsicFuncNameTable[0].size() == 0) {
            for (unsigned i=0;IntrinsicNameTable[i];i++) {
                IntrinsicFuncNameTable[i] = IntrinsicNameTable[i];
                std::replace(IntrinsicFuncNameTable[i].begin(),
                    IntrinsicFuncNameTable[i].end(), '.', '_');
            }
        }

        // Determine hook name suffix. Also handle regular and intrinsic calls.
        Hooks *H;
        CallSite CS(I);
        std::string suffix = I->getOpcodeName();
        if (CS.getInstruction() && !CS.isInlineAsm()) {
            Function *Callee = dyn_cast<Function>(CS.getCalledValue()->stripPointerCasts());
            if (Callee) {
                if (CS.getIntrinsicID() == Intrinsic::ID::not_intrinsic)
                    suffix = "call_" + Callee->getName().str();
                else // always starts with llvm_, e.g., llvm_memcpy
                    suffix = IntrinsicFuncNameTable[CS.getIntrinsicID()];
            }
            else {
                suffix = "icall";
            }
        }
        auto it = functionMap.find(suffix);
        if (it != functionMap.end()) {
           H = it->second;
        }

        // Build Hooks object
        std::string preHookName(HookPrefix + "pre_" + suffix);
        std::string wrapHookName(HookPrefix + "wrap_" + suffix);
        std::string postHookName(HookPrefix + "post_" + suffix);
        Module *M = I->getParent()->getParent()->getParent();
        H = Hooks::get(M, preHookName, wrapHookName, postHookName);
        functionMap.insert(std::pair< std::string, Hooks* >(suffix, H));

        // Instrument
        if (!H)
            return;
        preHook(I, Hooks::getFunction(H->Pre, I->getType(), H->PreTypeMap));
        postHook(I, Hooks::getFunction(H->Post, I->getType(), H->PostTypeMap));
        wrapHook(I, Hooks::getFunction(H->Wrap, I->getType(), H->WrapTypeMap));
    }

    Function* createWrapperFunction(Function *F, const char *name) {
        Module *M = F->getParent();
        FunctionType *FT = F->getFunctionType();
        Function *wrapper = Function::Create(FT, F->getLinkage(), name, M);

        BasicBlock *BB = BasicBlock::Create(M->getContext(), "entry", wrapper);
        IRBuilder<> builder(BB);

        std::vector<Value*> args;
        for (auto &arg : wrapper->args())
          args.push_back(&arg);

        Value *result = builder.CreateCall(F, args);
        if (FT->getReturnType() == builder.getVoidTy())
          builder.CreateRetVoid();
        else
          builder.CreateRet(result);
        return wrapper;
    }

    virtual bool runOnModule(Module &M) {
        hookPassLog("Running...");

        // Initialize regular expressions for functions to instrument.
        std::vector<Regex*> FunctionRegexes;
        if (Functions.empty())
            Functions.push_back(".*");
        passListRegexInit(FunctionRegexes, Functions);

        // Wrap main just in case we want to hook it
        Function *F = M.getFunction("main");
        assert(F);
        F->setName("__main");
        createWrapperFunction(F, "main");

        // Try to hook all the instructions
        for (auto &F : M.getFunctionList()) {
            if (F.isDeclaration() || F.getName().startswith(HookPrefix))
                continue;
            const std::string &FName = F.getName();
            if (!passListRegexMatch(FunctionRegexes, FName))
                continue;
            for (auto &BB : F) {
                Instruction *lastI = NULL;
                for (auto &I : BB) {
                    if (lastI)
                        hook(lastI);
                    lastI = &I;
                }
                hook(lastI);
            }
        }

        return true;
    }
  };

}

char HookPass::ID = 0;
RegisterPass<HookPass> MP("hook", "Hook Pass");
