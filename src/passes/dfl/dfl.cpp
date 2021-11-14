
#include <pass.h>
#include "WPA/WPAPass.h"
#include "WPA/Andersen.h"
#include "Util/SVFUtil.h"
#include "Util/SVFModule.h"
#include "SVF-FE/LLVMUtil.h"
#include "SVF-FE/GEPTypeBridgeIterator.h" // include bridge_gep_iterator
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"

#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/CFG.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <tuple>

using namespace llvm;

#define DEBUG_TYPE "dfl"
#define dflPassLog(M) LLVM_DEBUG(dbgs() << "DFLPass: " << M << "\n")
#define qprint(s) std::cout << s << std::endl
#define dprint(s) LLVM_DEBUG(outs() << s << "\n")
#define oprint(s) (outs() << s << "\n")
#define eprint(s) (errs() << s << "\n")

#define CACHE_LINE_ALIGNMENT (64uL)
#define DEFAULT_STACK_ALIGNMENT (16uL)

#define DFL_STRIDE (CACHE_LINE_ALIGNMENT)
#define DFL_OBJ_DATA_OFFSET (6)

static cl::list<std::string>
Functions("dfl-funcs",
    cl::desc("Specify all the comma-separated function regexes to dfl"),
    cl::ZeroOrMore, cl::CommaSeparated, cl::NotHidden);

static cl::list<std::string>
CFLFunctions("dfl-cfl-funcs",
    cl::desc("Specify all the comma-separated function regexes that will be CFLed"),
    cl::ZeroOrMore, cl::CommaSeparated, cl::NotHidden);

static cl::opt<bool>
AllAccesses("dfl-all-accesses",
    cl::desc("Linearize all memory accesses"),
    cl::init(false), cl::NotHidden);

static cl::opt<bool>
DFLRelaxed("dfl-relaxed",
    cl::desc("Avoid striding non tainted memory accesses for which we may prove they are safe"),
    cl::init(false), cl::NotHidden);

static cl::opt<bool>
DFLInductionOpt("dfl-induction-vars",
    cl::desc("Optimize striding induction variables in a loop"),
    cl::init(true), cl::NotHidden);

static cl::opt<bool>
DFL_AVX512("dfl-avx512",
    cl::desc("Enable avx512 optimizations"),
    cl::init(false), cl::NotHidden);

static cl::opt<bool>
DFL_AVX2("dfl-avx2",
    cl::desc("Enable avx2 optimizations"),
    cl::init(false), cl::NotHidden);

namespace {

  class DFLObject {
  public:
      const Value *targetObj;
      const Value *targetSize;
  };

  class DFLPass : public ModulePass {

                                      /*  offset, size     */
    using OffsetAndSize    = std::pair< uint64_t, uint64_t >;
    using ObjectWithFields = std::pair< const Value*, std::set< OffsetAndSize >>;

    /* STATS */
    unsigned long totalAccesses     = 0;
    unsigned long taintedAccesses   = 0;
    unsigned long numCFLedAccesses  = 0;
    unsigned long protectedAccesses = 0;
    unsigned long protectedReads    = 0;
    unsigned long protectedWrites   = 0;
    unsigned long totObjAccesses    = 0;
    unsigned long protectedAVX      = 0;
    unsigned long protectedSingle   = 0;
    unsigned long protectedLinear   = 0;
    unsigned long bytesAccessed     = 0;
    unsigned long unsupportedSingle = 0;

    unsigned long nmemset = 0;
    unsigned long nmemcpy = 0;

    // bytesProtected is just an approximation, since we statically do not know how many
    // objects an `OBJ DFL HELPER` may access
    unsigned long bytesProtected    = 0;
    unsigned long nUglyGEPS         = 0;

    bool DFL_DEBUG = false;

  public:
    static char ID;
    // All objects this pointer may refer to, along with their offset and 
    // size of the access
    std::map<Value*,std::set<ObjectWithFields>> ptrToObjs;
    // All memory accesses to protect
    std::set<Instruction*> memAccesses;

    // Map an alloc site to its respective objects list head global (or tls) var
    std::map<const Value*, GlobalVariable*> allocToObjListHead;

    // Cache to old object sizes without researching it
    std::map<const Value*, Value*> objSizeCache;

    // Set of all the deallocation sites for heap objects
    std::set<CallInst*> deallocCalls;

    GlobalVariable *CFL_dummy_ref;
    std::set<Instruction*> CFLedAccesses;


    unsigned long unique_id;

    DFLPass() : ModulePass(ID) {
        unique_id = 0;
    }

    unsigned long getUniqueID() {
        return unique_id++;
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

    bool hasTaintMetadata(Instruction *I) {
        MDNode* N;
        N = I->getMetadata("t");
        return N != NULL;
    }

    int getBGID(Instruction &I) {
        MDNode* N;
        Constant *val;
        BasicBlock *BB = I.getParent();
        N = BB->getTerminator()->getMetadata("b-gid");
        if (!N) return 0;
        val = dyn_cast<ConstantAsMetadata>(N->getOperand(0))->getValue();
        assert(val);
        int b_gid = cast<ConstantInt>(val)->getSExtValue();
        return b_gid;
    }

    int getIBID(Instruction &I) {
        MDNode* N;
        Constant *val;
        N = I.getMetadata("i-bid");
        if (!N) return 0;
        val = dyn_cast<ConstantAsMetadata>(N->getOperand(0))->getValue();
        assert(val);
        int i_bid = cast<ConstantInt>(val)->getSExtValue();
        return i_bid;
    }

    // check if the instruction has been marked as an induction variable by the 
    // mark-induction-variables pass
    bool isInductionVar(Value *V) {
        MDNode* N;
        Instruction *I = dyn_cast<Instruction>(V);
        if (!I) return false;
        N = I->getMetadata("indvar");
        if (N == NULL) return false;
        return true;
    }

    // Get the type size given a target and a data layout
    uint32_t getTypeSizeInBytes(DataLayout* DL, const Type* type) {
        // if the type has size then simply return it
        assert(type->isSized());
        return  DL->getTypeAllocSize(const_cast<Type*>(type));
    }

    // Get the size of an object based on its type
    // assume we have a pointer to the object, so we will dereference it
    // also check that the object may be obtained by a malloc instruction, and
    // try to get the size parameter if constant
    uint64_t getObjectSizeInBytes(DataLayout* DL, const Value* obj) {
        // if the type has size then simply return it
        Type* T = obj->getType();
        assert(T->isPointerTy());
        uint64_t objSize = DL->getTypeAllocSize(SVFUtil::dyn_cast<llvm::PointerType>(T)->getElementType());

        if(const Instruction* I = SVFUtil::dyn_cast<Instruction>(obj)) {
            // just consider case 1: ret = new obj
            if (SVFUtil::isHeapAllocOrStaticExtCall(I) && SVFUtil::isHeapAllocExtCallViaRet(I)) {
                CallSite CS(const_cast<Instruction*>(I));

                // accept malloc() or `_Znwm`=`operator new(unsigned long)`
                assert(CS.getCalledFunction()->getName().equals("malloc") || CS.getCalledFunction()->getName().equals("_Znwm"));
                Value* allocSize = CS.getArgument(0);
                
                // ensure it is actually a constant size allocation
                if (const ConstantInt* CI = dyn_cast<ConstantInt>(allocSize)) {
                    objSize = CI->getZExtValue();
                }
            }
        }
        return  objSize;
    }

    // Guess the type of an object based on its size (yolo): try to match with a
    // struct, oterwise this is probably an array
    // assume this is not a primitive type
    Type* guessType(Module* M, DataLayout *DL, const Value * obj) {

        // if the object already has a StructType, honor it
        Type* objT = obj->getType();
        assert(objT->isPointerTy() && "an object must have pointer type");
        if (PointerType* ptrT = dyn_cast<PointerType>(objT)) {
            if (StructType *structT = dyn_cast<StructType>(ptrT->getElementType()))
                return structT;
            if (ArrayType *arrayT = dyn_cast<ArrayType>(ptrT->getElementType()))
                return arrayT;
        }

        // A cache to avoid computing the same query multiple times
        // size -> type
        static std::map<uint64_t, Type*> type_cache;

        uint64_t obj_size = getObjectSizeInBytes(DL, obj);

        Type *cached_type = type_cache[obj_size];
        if (cached_type != nullptr)
            return cached_type;

        for (StructType *type: M->getIdentifiedStructTypes()) {
            if (getTypeSizeInBytes(DL, type) == obj_size) {
                type_cache[obj_size] = type;
                return type;
            }
        }

        assert(false && "No type guessed for the given object");
        return nullptr;
    }

    // Get the byte offset of a field inside a struct
    uint32_t getFieldOffset(DataLayout* DL, const StructType *sty, u32_t field_idx){
        const StructLayout *stTySL = DL->getStructLayout( const_cast<StructType *>(sty) );
        // if this struct type does not have any element, i.e., opaque
        assert(!sty->isOpaque());
        return stTySL->getElementOffset(field_idx);
    }

    // Return true if the GEP accesses a constant offset in the object
    bool isConstGep(GetElementPtrInst* GEP) {
        for (bridge_gep_iterator gi = bridge_gep_begin(GEP), ge = bridge_gep_end(GEP);
            gi != ge; ++gi) {

            // Allow only constant integers as GEP indexes
            if (isa<ConstantInt>(gi.getOperand()))
                continue;

            // All other cases are not "constant"
            return false;
        }
        return true;
    }

    /// Return true if the GEP accesses an array, as it is considered a single field
    bool isArrayGep(GetElementPtrInst* GEP) {
        for (bridge_gep_iterator gi = bridge_gep_begin(GEP), ge = bridge_gep_end(GEP);
            gi != ge; ++gi) {

            // Allow constant integers as GEP indexes
            if (isa<ConstantInt>(gi.getOperand()))
                continue;

            // Search array accesses 
            if (isa<ArrayType>(*gi))
                return true;

            // All other cases will not lead to a simple array access
            return false;
        }
        return false;
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

    // Analyze a GEP accesses to recover which fields of the object may be accessed
    // using the pointer that it produces.
    std::pair<uint32_t, uint32_t> parseGEPAccess(DataLayout *DL, GetElementPtrInst *GEP) {

        uint64_t objSize = getTypeSizeInBytes(DL, GEP->getSourceElementType());
        uint32_t offset = 0;
        uint32_t innermostSize = objSize;

        // Visit the gep to restrict the access to the innermost field that is accessed
        // returning its offset and size
        for (bridge_gep_iterator gi = bridge_gep_begin(GEP), ge = bridge_gep_end(GEP);
            gi != ge; ++gi) {
            // oprint("offset: " << offset << " size: " << innermostSize);
            if (SVFUtil::isa<ConstantInt>(gi.getOperand()) == false) {
                /// non constant offset
                if(const ArrayType* at = SVFUtil::dyn_cast<ArrayType>(*gi)) {
                    // consider the whole array to be accessed
                    uint64_t size = getTypeSizeInBytes(DL, at);
                    return std::pair<uint32_t, uint32_t>(offset, size);
                }
                // oprint("Variable index on non array type");

                return std::pair<uint32_t, uint32_t>(offset, objSize - offset);
            }
            // constant offset
            else {
                assert(SVFUtil::isa<ConstantInt>(gi.getOperand()) && "expecting a constant");

                ConstantInt *op = SVFUtil::cast<ConstantInt>(gi.getOperand());

                //The actual index
                Size_t idx = op->getSExtValue();

                // Handling pointer types
                // These GEP instructions are simply making address computations from the base pointer address
                // e.g. idx1 = (char*) &MyVar + 4,  at this case gep only one offset index (idx)
                if (const PointerType* pty = SVFUtil::dyn_cast<PointerType>(*gi)) {
                    const Type* et = pty->getElementType();
                    Size_t sz = getTypeSizeInBytes(DL, et);
                    offset += idx * sz;
                    innermostSize = getTypeSizeInBytes(DL, et);
                }
                // Calculate the size of the array element
                else if(const ArrayType* at = SVFUtil::dyn_cast<ArrayType>(*gi)) {
                    const Type* et = at->getElementType();
                    Size_t sz = getTypeSizeInBytes(DL, et);
                    offset += idx * sz;
                    innermostSize = getTypeSizeInBytes(DL, et);
                }
                // Handling struct here
                else if (const StructType *ST = SVFUtil::dyn_cast<StructType>(*gi)) {
                    assert(op && "non-const struct index in GEP");
                    offset += getFieldOffset(DL, ST, idx);
                    innermostSize = getTypeSizeInBytes(DL, ST->getTypeAtIndex(idx));
                }
                else
                    assert(false && "what other types?");
            }
        }
        return std::pair<uint32_t, uint32_t>(offset, innermostSize);
    }


    // Visit the `haystack` type to find occurrences of the `needle` type, adding
    // all the possible occurrences offsets wrt the `haystack` in `result`
    void searchTypeInType(DataLayout *DL, int current_offset, Type *haystack, Type *needle, std::set<uint64_t> &result) {
        
        // oprint("current offset: " << current_offset << " haystack: " << *haystack);
        // did we find it?
        if(haystack == needle) {
            result.insert(current_offset);
            return;
        }

        // Vist all the fields of the struct
        if (StructType* sty = dyn_cast<StructType>(haystack)) {
            for (unsigned idx = 0; idx < sty->getNumElements(); ++idx) {
                uint64_t offset = getFieldOffset(DL, sty, idx);
                Type *   type   = sty->getTypeAtIndex(idx);
                searchTypeInType(DL, current_offset + offset, type, needle, result);
            }
        // Visit all the array elements
        } else if (ArrayType* aty = dyn_cast<ArrayType>(haystack)) {
            Type*    elemTy   = aty->getElementType();
            uint64_t elemNum  = aty->getNumElements();
            uint64_t elemSize = getTypeSizeInBytes(DL, elemTy);

            // Unpack nested arrays
            while (ArrayType* aty = dyn_cast<ArrayType>(elemTy)) {

                // Stop unpacking if we found the type
                if (elemTy == needle)
                    break;
                elemNum *= aty->getNumElements();
                elemTy   = aty->getElementType();
            }

            // If the type is not right, and it is not a struct to visit, there is no point into visiting it
            if (!isa<StructType>(elemTy) && elemTy != needle)
                return;
            for (unsigned idx = 0; idx < elemNum; ++idx) {
                searchTypeInType(DL, current_offset + (elemSize * idx), elemTy, needle, result);
            }
        }
    }

    void fillAccessInfo(DataLayout *DL, GetElementPtrInst *GEP, const Value *obj, std::set<OffsetAndSize> &access_info) {
        uint64_t objSize = getObjectSizeInBytes(DL, obj);

        // parse the field that is accessed by the GEP
        std::pair<uint32_t, uint32_t> offsetAndSize = parseGEPAccess(DL, GEP);
        // oprint("GEP type: " << *GEP->getSourceElementType() << " size: " << getTypeSizeInBytes(DL, GEP->getSourceElementType()));
        // oprint("OBJ type: " << *obj->getType() << " size: " << objSize);

        // if the object-accessed-size agrees with what the GEP sees, we have the 
        // simple case where the GEP directly accesses an address taken object
        if(getTypeSizeInBytes(DL, GEP->getSourceElementType()) == objSize) {
            // simply fill the access_info and return
            access_info.insert(offsetAndSize);
            return;
        }

        // do not trust primitive elem pointers as they are used for uglygeps
        if (!isa<StructType>(GEP->getSourceElementType()) && !isa<ArrayType>(GEP->getSourceElementType())) {
        // if (GEP->getPointerOperandType() == Type::getInt8PtrTy(GEP->getContext())) {
            // oprint("uglygep? " << *GEP);
            ++nUglyGEPS;
            access_info.insert(OffsetAndSize(0, objSize));
            return;
        }

        Type *guessedType = guessType(GEP->getModule(), DL, obj);
        assert(guessedType);
        // oprint("Guessed type: " << *guessedType);

        // now visit the guessed type to match the GEP accessed type
        // if no match we fucked up
        std::set<uint64_t> possible_offsets;
        // TODO: add cache!
        searchTypeInType(DL, 0, guessedType, GEP->getSourceElementType(), possible_offsets);
        assert(possible_offsets.size() > 0 && "did not found any possible offset");

        for(auto possible_offset : possible_offsets) {
            // TODO: check the first index of the GEP instruction to understand if 
            // we are indexing inside the struct or outside
            access_info.insert(OffsetAndSize(offsetAndSize.first + possible_offset, offsetAndSize.second));
        }

        return;
    }

    size_t getTotalSize(std::set<OffsetAndSize> &offsetAndSizes) {
        size_t res = 0;
        for (OffsetAndSize offAndSize: offsetAndSizes) {
            // interval [off, off+sz)
            // uint64_t off = offAndSize.first;
            uint64_t sz  = offAndSize.second;
            res += sz;
        }
        return res;
    }

    // Compact all the consecutive fields into a smaller representation
    void compactAccessInfo(std::set<OffsetAndSize> &offsetAndSizes) {

        std::vector<OffsetAndSize> fields(offsetAndSizes.begin(), offsetAndSizes.end());
        offsetAndSizes.clear();

        // sort the vector based on the offset
        std::sort(fields.begin(), fields.end());

        // construct the compact representation of [curr_off, curr_off + curr_sz)
        uint64_t current_offset = 0;
        uint64_t current_size   = 0;
        // oprint("Compacting: " << fields.size());
        for (OffsetAndSize offAndSize: fields) {
            // interval [off, off+sz)
            uint64_t off = offAndSize.first;
            uint64_t sz  = offAndSize.second;
            // oprint("parsing: " << off << " size: " << sz);

            uint64_t end = current_offset + current_size;
            // if the new interval is included and extends the current one
            if (end >= off) {
                uint64_t new_end = off + sz;
                if (new_end > end) {
                    current_size += (new_end - end);
                }
            } else {
                if (current_size != 0) {
                    offsetAndSizes.insert(OffsetAndSize(current_offset, current_size));
                }
                current_offset = off;
                current_size   = sz;
            }
        }
        // insert the last if present
        if (current_size != 0) {
            offsetAndSizes.insert(OffsetAndSize(current_offset, current_size));
        }
        // for (OffsetAndSize offAndSize: offsetAndSizes) {
        //     // interval [off, off+sz)
        //     uint64_t off = offAndSize.first;
        //     uint64_t sz  = offAndSize.second;
        //     oprint("got: " << off << " size: " << sz);
        // }
    }

    // Visit the `current_type` type to find occurrences of the type indexed by `target_svf_idx`, adding
    // all the possible occurrences offsets and sizes in `result`
    // The `target_type` is indexed flattened
    // -> returns the number of elements the flattened type has, to propagate the info
    // BEWARE: this method eavily relies on how SVF parses a type to map it to LocationSets offsets
    //         in the default memory model
    // e.g. 1) an array type is transparent, and all the offsets are considered the same object
    //         Treat whole array as one, then they can distinguish different field of an array of struct
    //         e.g. s[1].f1 is differet from s[0].f2
    //      2) a struct type is correctly parsed
    //      3) for pointers types go read `SymbolTableInfo::computeGepOffset` comments
    int searchSVFField(DataLayout *DL, int current_offset, int current_svf_idx, Type *current_type, int target_svf_idx, std::set<OffsetAndSize> &result) {
        int flattened_idx = 0;
        // oprint("current offset: " << current_offset << " current_idx: " << current_svf_idx << " type: " << *current_type);
        // did we find it?
        // check current type is not an array or struct, otherwise we may not be nested enough
        if(current_svf_idx == target_svf_idx && !isa<ArrayType>(current_type) && !isa<StructType>(current_type)) {
            uint64_t current_size = getTypeSizeInBytes(DL, current_type);
            result.insert(OffsetAndSize(current_offset, current_size));
            return 1;
        }

        // Vist all the fields of the struct
        if (StructType* sty = dyn_cast<StructType>(current_type)) {
            for (unsigned idx = 0; idx < sty->getNumElements(); ++idx) {
                uint64_t offset = getFieldOffset(DL, sty, idx);
                Type *   type   = sty->getTypeAtIndex(idx);
                // advance the flattened_idx to the number of elements in the flattened struct
                flattened_idx += searchSVFField(DL, current_offset + offset, 
                                    current_svf_idx + flattened_idx, type, 
                                    target_svf_idx, result);
            }
        // Visit all the array elements
        } else if (ArrayType* aty = dyn_cast<ArrayType>(current_type)) {
            Type*    elemTy   = aty->getElementType();
            uint64_t elemNum  = aty->getNumElements();
            uint64_t elemSize = getTypeSizeInBytes(DL, elemTy);

            // Unpack nested arrays
            while (ArrayType* aty = dyn_cast<ArrayType>(elemTy)) {
                elemNum *= aty->getNumElements();
                elemTy   = aty->getElementType();
                elemSize = getTypeSizeInBytes(DL, elemTy);
            }
            for (unsigned idx = 0; idx < elemNum; ++idx) {
                // do not advance the current_svf_idx as SVF does
                // but advance the current offset index, and update the type
                // this effectively collapses all array cells into one like SVF
                flattened_idx = searchSVFField(DL, current_offset + (elemSize * idx), 
                    current_svf_idx, elemTy, target_svf_idx, result);
            }
        } else {
            // we saw a generic element
            flattened_idx = 1;
        }
        return flattened_idx;
    }

    void parseSVFLocationSet(Module *M, DataLayout *DL, LocationSet &ls, const Value *obj, std::set<OffsetAndSize> &access_info) {
        Size_t field_idx = ls.getOffset();
        Type *guessedType = guessType(M, DL, obj);
        assert(guessedType);
        // oprint("Guessed type: " << *guessedType);

        // TODO: pls pls add a cache here
        searchSVFField(DL, 0, 0, guessedType, field_idx, access_info);
    }

    void printObjWithFieldsSet(DataLayout *DL, std::set<ObjectWithFields> &objWithFieldsSet) {
        oprint("num_objects: " << objWithFieldsSet.size());
        for( const ObjectWithFields& objWithFields : objWithFieldsSet ) {
            const Value* obj = objWithFields.first;
            uint64_t objSize = getObjectSizeInBytes(DL, obj);
            oprint(*obj);
            uint64_t tot_size = 0;
            std::set<OffsetAndSize> fields = objWithFields.second;
            uint64_t num_fields = fields.size();
            for (const OffsetAndSize& field : fields) {
                oprint("offset: " << field.first << " size: " << field.second);
                tot_size += field.second;
            }
            oprint("obj_size: " << objSize << " tot_size: " << tot_size << " num_fields: " << num_fields);
        }
    }

    // Visit the set to find multiple instances of the same object accessed on different
    // fields, and merges them together
    size_t dedupObjWithFieldsSet(std::set<ObjectWithFields> &objWithFieldsSet) {

        std::map<const Value*, std::set<ObjectWithFields>> dedupObjsMap;
        size_t dedup_size = 0;

        // Build a map to identify duplicated objects
        for( ObjectWithFields objWithFields : objWithFieldsSet ) {
            const Value* obj = objWithFields.first;

            // if (dedupObjsMap.find(obj) != dedupObjsMap.end())
            //     oprint("DEDUPING!!!");

            dedupObjsMap[obj].insert(objWithFields);
        }

        // clear the original set
        objWithFieldsSet.clear();

        for ( auto objAndAllFields : dedupObjsMap ) {
            const Value* obj = objAndAllFields.first;

            // all the ObjectWithFields which have the object in common
            std::set<ObjectWithFields> allFields = objAndAllFields.second;

            // the new set to build
            std::set<OffsetAndSize> newFieldSet = std::set<OffsetAndSize>();

            for(ObjectWithFields existingObjectWithFields : allFields) {

                // insert all the fields of the object in the new set to dedup them
                std::set<OffsetAndSize> fields = existingObjectWithFields.second;
                newFieldSet.insert(fields.begin(), fields.end());
            }

            compactAccessInfo(newFieldSet);
            dedup_size += getTotalSize(newFieldSet);
                dprint("\n" << *obj);
                for (const OffsetAndSize& field : newFieldSet) {
                    dprint("offset: " << field.first << " size: " << field.second);
                }
            objWithFieldsSet.insert(ObjectWithFields(obj, newFieldSet));
        }
        return dedup_size;
    }

    ConstantInt* makeConstI64(LLVMContext &C, unsigned long value) {
        return ConstantInt::get(C, APInt(sizeof(unsigned long)*8, value));
    }

    // Gather metadata about the objects that the memory access may touch
    void collectPts(PointerAnalysis* pta, Instruction* memoryAccess, Value* ptr, DataLayout* DL, bool willCFL){
        LLVMContext& C = memoryAccess->getContext();
        Module *M = memoryAccess->getModule();
        NodeID pNodeId = pta->getPAG()->getValueNode(ptr);
        NodeBS& pts = pta->getPts(pNodeId);
        Value *noCastPtr = ptr;
        while(isa<CastInst>(noCastPtr))
            noCastPtr = dyn_cast<CastInst>(ptr)->getOperand(0);
        int BGID = getBGID(*memoryAccess);
        int IBID = getIBID(*memoryAccess);

        dprint("-------------------------");
        dprint("func: " << memoryAccess->getParent()->getParent()->getName().str());
        dprint("access: " << *memoryAccess);
        dprint("" << BGID << " " << IBID);
        dprint("ptr: " << *ptr->stripPointerCasts());
        // pta->dumpPts(pNodeId, pts);

        // Avoid protecting any ptr which was not part of the original program as long
        // as can point to only one simple object
        // -> this means it has been introduced by the branch-extract pass to
        // forward variables between extracted branches
        if (!AllAccesses &&  !hasTaintMetadata(memoryAccess)) {
            int objCount = 0;
            for (NodeBS::iterator ii = pts.begin(), ie = pts.end(); ii != ie; ii++) {
                PAGNode* targetObj = pta->getPAG()->getPAGNode(*ii);

                // Ensure we do not deal with dummy or const objects
                assert(targetObj->hasValue());
                const Value* targetObjVal = targetObj->getValue();

                // Ensure we only deal with primitive or ptr types
                if(!targetObjVal->getType()->isIntOrPtrTy()) {
                    objCount = -1;
                    // debug print to see what we do not manage
                    oprint("UNMANAGED COMPLEX OBJECT");
                    oprint("access: " << *memoryAccess << "\nptr: " << *ptr->stripPointerCasts());
                    oprint("obj: " << *targetObjVal);
                    break;
                }
                ++objCount;
            }
            // objCount is 0 when the function is never called (e.g. cloned and substituted)
            if (objCount == 1 || objCount == 0) {
                // TODO: If we are inside a loop, we are going
                // to leave a write operation unprotected, we should add a check.
                // Do not wrap the memory access with DFL, but protect it in CFL style
                // CFLedAccesses.insert(memoryAccess); <- nope, higher overhead, no gainz
                return;
            } else {
                // debug print to see what we do not manage
                oprint("UNMANAGED OBJECTS");
                oprint("access: " << *memoryAccess << "\nptr: " << *ptr->stripPointerCasts());
                for (NodeBS::iterator ii = pts.begin(), ie = pts.end(); ii != ie; ii++) {
                    PAGNode* targetObj = pta->getPAG()->getPAGNode(*ii);

                    // Ensure we do not deal with dummy or const objects
                    assert(targetObj->hasValue());
                    const Value* targetObjVal = targetObj->getValue();
                    oprint("obj: " << *targetObjVal);
                }
            }
        }
        int count = 0;
        ++protectedAccesses;
        if (isa<LoadInst>(memoryAccess)) ++protectedReads;
        else ++protectedWrites;

        if(getInstructionTaint(*memoryAccess)) ++taintedAccesses;
        else if (willCFL) ++numCFLedAccesses;
        for (NodeBS::iterator ii = pts.begin(), ie = pts.end(); ii != ie; ii++) {
            ++count;
            // outs() << " " << *ii << " ";
            PAGNode* targetObj = pta->getPAG()->getPAGNode(*ii);

            // Ensure we do not deal with dummy or const objects
            assert(targetObj->hasValue());
            const Value* targetObjVal = targetObj->getValue();

            ObjectWithFields objWithFields = ObjectWithFields(targetObjVal, std::set<OffsetAndSize>());
            if (GepObjPN* targetGepObj = dyn_cast<GepObjPN>(targetObj)) {
                LLVM_DEBUG(outs() << "1");
                // Try to rely on SVF LocationSet info
                LocationSet ls = targetGepObj->getLocationSet();
                // oprint("ls: " << ls.dump());
                parseSVFLocationSet(M, DL, ls, targetObjVal, objWithFields.second);
                compactAccessInfo(objWithFields.second);

            } else if (isa<ObjPN>(targetObj) 
                    /* (we ensure the only FIobjPn are the first field ones) NOPE*/
                    && !isa<FIObjPN>(targetObj)
                ) {
                LLVM_DEBUG(outs() << "2");
                // This path will never be hit, since SVF base object are FI, so
                // we cannot distinguish between a FIgep and a base object (which
                // collides with the first field)

                // Assume a memory objects represents its first field, as it is 
                // the default in SVF
                LocationSet ls = LocationSet(0);
                parseSVFLocationSet(M, DL, ls, targetObjVal, objWithFields.second);
                compactAccessInfo(objWithFields.second);
            } else if (GetElementPtrInst* GEP = dyn_cast<GetElementPtrInst>(noCastPtr)) {
                LLVM_DEBUG(outs() << "3");
                // Here we do not use the locationSet info from SVF since it recedes
                // object to field insensitive ones too aggressively, so we may be
                // able to reason on simple accesses better

                // In particular SVF does not distinguish from an access to the first
                // element of the object and a field insensitive access, so we are
                // interested in reconstructing accesses to obj[0] here

                fillAccessInfo(DL, GEP, targetObjVal, objWithFields.second);
                compactAccessInfo(objWithFields.second);
            } else {
                LLVM_DEBUG(outs() << "4");
                uint64_t objOffset = 0;
                uint64_t objSize   = getObjectSizeInBytes(DL, targetObjVal);
                objWithFields.second.insert(OffsetAndSize(objOffset, objSize));
            }
            // for(OffsetAndSize offAndSize : objWithFields.second)
            //     oprint("offset: " << offAndSize.first << " size: " << offAndSize.second);

            // Insert in the set of ptrs that point-to the object
            // oprint("+ ptr: " << *ptr << "\n  obj: " << *targetObjVal << "\n  mem access: " << *memoryAccess);
            ptrToObjs[ptr].insert(objWithFields);
            allocToObjListHead[targetObjVal] = nullptr;

            // insert among the protected memory accesses only if SVF returned the pts set
            memAccesses.insert(memoryAccess);

            // Ensure we have a pointer to the object
            Type* T = targetObjVal->getType();
            assert(T->isPointerTy());

            uint64_t objSize = DL->getTypeAllocSize(SVFUtil::dyn_cast<llvm::PointerType>(T)->getElementType());
            Value* allocSize = makeConstI64(C, objSize);

            // For now manage only static alloca
            if(const AllocaInst* v = SVFUtil::dyn_cast<AllocaInst>(targetObjVal))
                assert(v->isStaticAlloca());

            // Explicitly deal with global vars, local vars, and heap vars
            if(const GlobalVariable* v = SVFUtil::dyn_cast<GlobalVariable>(targetObjVal)){
                // outs() << " (global var: ";
            } else if(const AllocaInst* v = SVFUtil::dyn_cast<AllocaInst>(targetObjVal)){
                // outs() << " (alloca inst: ";
            } else {
                // should be an external call which allocates the object

                // outs() << " (malloc-like inst: ";
                const Instruction* I = SVFUtil::dyn_cast<Instruction>(targetObjVal);
                assert(I);
                // just consider case 1: ret = new obj
                assert(SVFUtil::isHeapAllocOrStaticExtCall(I) && SVFUtil::isHeapAllocExtCallViaRet(I));
                // const SVFFunction* callee = SVFUtil::getCallee(I);
                CallSite CS(const_cast<Instruction*>(I));

                // Stay simple man
                // oprint("Alloc Call: " << CS.getCalledFunction()->getName().str() << " for access in " << memoryAccess->getParent()->getParent()->getName().str());
                // oprint("access: " << *memoryAccess << "\nptr: " << *ptr);
                // oprint("obj: " << *targetObjVal);

                // accept malloc() or `_Znwm`=`operator new(unsigned long)`
                assert(CS.getCalledFunction()->getName().equals("malloc") || CS.getCalledFunction()->getName().equals("_Znwm"));
                allocSize = CS.getArgument(0);
            }
            // oprint(targetObjVal->getName() << " size: " << *allocSize << ")");

            objSizeCache[targetObjVal] = allocSize;
        }
        // accept no objects only if the access is not tainted
        if (!(count > 0 || !getInstructionTaint(*memoryAccess))) {
            oprint(memoryAccess->getParent()->getParent()->getName());
            oprint(*memoryAccess);
        }
        assert(count > 0 || !getInstructionTaint(*memoryAccess));
        totObjAccesses += count;

        // oprint("-> inserted " << count << " objects");
        // if the memory access is in a function that will be CFLed we have to:
        //  nope, DFL will filter the accesses -> X) insert DUMMY into the set of objects that may be pointed
        // 2) insert the access into the set of instructions that will be wrapped
        if (willCFL) {
            // insert DUMMY into the set
            // ptrToObjs[ptr].insert(CFL_dummy_ref);
            // allocToObjListHead[CFL_dummy_ref] = nullptr;
            // objSizeCache[CFL_dummy_ref] = ConstantInt::get(C, APInt(sizeof(unsigned long)*8, DFL_STRIDE));
            // oprint("Adding DUMMY to the set");

            // insert the instruction into the to-be-wrapped set
            CFLedAccesses.insert(memoryAccess);
        }

        if (count) {
            // check that no object was added twice, in that case merge the fields
            size_t deduped_size = dedupObjWithFieldsSet(ptrToObjs[ptr]);
            dprint("access size: " << deduped_size);
            // oprint("access: " << *memoryAccess);
            // printObjWithFieldsSet(DL, ptrToObjs[ptr]);
        }
        return;
    }

    Function *getFunction(Module *M, llvm::StringRef Name) {
        Function* res = M->getFunction(Name);
        if (!res) {
            eprint("FUNCTION NOT FOUND: " << Name);
            assert(false && "No function found");
        }
        return res;
    }

    Function* getBestDFLObjLoad(Module *M, uint64_t bitsAccessed, uint64_t accessSize, bool singleAccess) {
        // single access if relaxed, or the accessSize is compatible
        if ((singleAccess) || accessSize <= (bitsAccessed/8)) {
            bytesProtected++;
            protectedSingle++;
            return getFunction(M, "uint" + std::to_string(bitsAccessed) + "_t_dfl_single_obj_load");
        }
        if (!DFL_AVX2 && !DFL_AVX512) {
            // assert(false && "WTF where is my AVX");
            bytesProtected += (accessSize / DFL_STRIDE);
            protectedLinear++;
            return getFunction(M, "uint" + std::to_string(bitsAccessed) + "_t_dfl_obj_load");
        } else {
            const char *AVX_STRING = DFL_AVX512 ? "avx512" : "avx2";
            // lower strides mean lots of accesses to the same cache line, so fixed loads best
            if (DFL_STRIDE < 16) {
                bytesProtected += (accessSize / (DFL_AVX512? (8*DFL_STRIDE) : (4*DFL_STRIDE)));
                protectedAVX++;
                return getFunction(M, "uint" + std::to_string(bitsAccessed) + "_t_" +AVX_STRING+ "_linear_dfl_obj_load");
            }

            // if to access the whole obj only few iterations are required, this is better than avx setupping
            if ((accessSize / DFL_STRIDE) < 8) {
                bytesProtected += (accessSize / DFL_STRIDE);
                protectedLinear++;
                return getFunction(M, "uint" + std::to_string(bitsAccessed) + "_t_dfl_obj_load");
            }
            bytesProtected += (accessSize / (DFL_AVX512? (8*DFL_STRIDE) : (4*DFL_STRIDE)));
            protectedAVX++;
            // otherwise use avx gather instructions to quickly load multiple cache lines
            return getFunction(M, "uint" + std::to_string(bitsAccessed) + "_t_" +AVX_STRING+ "_gather_dfl_obj_load");
        }
    }

    Function* getBestDFLGlobLoad(Module *M, uint64_t bitsAccessed, uint64_t accessSize, bool singleAccess) {
        // single access if relaxed, or the accessSize is compatible
        if ((singleAccess) || accessSize <= (bitsAccessed/8)) {
            bytesProtected++;
            protectedSingle++;
            return getFunction(M, "uint" + std::to_string(bitsAccessed) + "_t_dfl_single_glob_load");
        }
        if (!DFL_AVX2 && !DFL_AVX512) {
            // assert(false && "WTF where is my AVX");
            bytesProtected += (accessSize / DFL_STRIDE);
            protectedLinear++;
            return getFunction(M, "uint" + std::to_string(bitsAccessed) + "_t_dfl_glob_load");
        } else {
            const char *AVX_STRING = DFL_AVX512 ? "avx512" : "avx2";
            // lower strides mean lots of accesses to the same cache line, so fixed loads best
            if (DFL_STRIDE < 16) {
                bytesProtected += (accessSize / (DFL_AVX512? (8*DFL_STRIDE) : (4*DFL_STRIDE)));
                protectedAVX++;
                return getFunction(M, "uint" + std::to_string(bitsAccessed) + "_t_" +AVX_STRING+ "_linear_dfl_glob_load");
            }

            // if to access the whole obj only few iterations are required, this is better than avx setupping
            if ((accessSize / DFL_STRIDE) < 8) {
                bytesProtected += (accessSize / DFL_STRIDE);
                protectedLinear++;
                return getFunction(M, "uint" + std::to_string(bitsAccessed) + "_t_dfl_glob_load");
            }

            bytesProtected += (accessSize / (DFL_AVX512? (8*DFL_STRIDE) : (4*DFL_STRIDE)));
            protectedAVX++;
            // otherwise use avx gather instructions to quickly load multiple cache lines
            return getFunction(M, "uint" + std::to_string(bitsAccessed) + "_t_" +AVX_STRING+ "_gather_dfl_glob_load");
        }
    }

    Function* getBestDFLObjStore(Module *M, uint64_t bitsAccessed, uint64_t accessSize, bool singleAccess) {
        // single access if relaxed, or the accessSize is compatible
        if ((singleAccess) || accessSize <= (bitsAccessed/8)) {
            bytesProtected++;
            protectedSingle++;
            return getFunction(M, "uint" + std::to_string(bitsAccessed) + "_t_dfl_single_obj_store");
        }
        // TODO: implement the others
        bytesProtected += (accessSize / DFL_STRIDE);
        protectedLinear++;
        return getFunction(M, "uint" + std::to_string(bitsAccessed) + "_t_dfl_obj_store");
    }

    Function* getBestDFLGlobStore(Module *M, uint64_t bitsAccessed, uint64_t accessSize, bool singleAccess) {
        // single access if relaxed, or the accessSize is compatible
        if ((singleAccess) || accessSize <= (bitsAccessed/8)) {
            bytesProtected++;
            protectedSingle++;
            return getFunction(M, "uint" + std::to_string(bitsAccessed) + "_t_dfl_single_glob_store");
        }
        if (!DFL_AVX2 && !DFL_AVX512) {
            // assert(false && "WTF where is my AVX");
            bytesProtected += (accessSize / DFL_STRIDE);
            protectedLinear++;
            return getFunction(M, "uint" + std::to_string(bitsAccessed) + "_t_dfl_glob_store");
        } else {
            const char *AVX_STRING = DFL_AVX512 ? "avx512" : "avx2";
            // lower strides mean lots of accesses to the same cache line, so fixed stores best
            if (DFL_STRIDE < 16) {
                bytesProtected += (accessSize / (DFL_AVX512? (8*DFL_STRIDE) : (4*DFL_STRIDE)));
                protectedAVX++;
                return getFunction(M, "uint" + std::to_string(bitsAccessed) + "_t_" +AVX_STRING+ "_linear_dfl_glob_store");
            }

            // if to access the whole obj only few iterations are required, this is better than avx setupping
            if ((accessSize / DFL_STRIDE) < 8) {
                bytesProtected += (accessSize / DFL_STRIDE);
                protectedLinear++;
                return getFunction(M, "uint" + std::to_string(bitsAccessed) + "_t_dfl_glob_store");
            }
        
            // avx scatter requires avx512 support
            if (DFL_AVX512) {
                bytesProtected += (accessSize / (DFL_AVX512? (8*DFL_STRIDE) : (4*DFL_STRIDE)));
                protectedAVX++;
                // otherwise use avx scatter instructions to quickly store multiple cache lines
                return getFunction(M, "uint" + std::to_string(bitsAccessed) + "_t_" +AVX_STRING+ "_scatter_dfl_glob_store");
            } else {
                bytesProtected += (accessSize / DFL_STRIDE);
                protectedLinear++;
                return getFunction(M, "uint" + std::to_string(bitsAccessed) + "_t_dfl_glob_store");
            }
        }
    }

    Function* getBestDFLObjMemset(Module *M, uint64_t accessSize) {
        ++nmemset;
        if (DFL_AVX2) {
            return getFunction(M, "dfl_memset_obj_avx");
        }
        return getFunction(M, "dfl_memset_obj");
    }

    Function* getBestDFLGlobMemset(Module *M, uint64_t accessSize) {
        ++nmemset;
        if (DFL_AVX2) {
            return getFunction(M, "dfl_memset_glob_avx");
        }
        return getFunction(M, "dfl_memset_glob");
    }

    Function* getBestDFLGlobMemcpy(Module *M, uint64_t dAccessSize, uint64_t sAccessSize, uint64_t n) {
        ++nmemcpy;
        // if this is a constant memcpy of a field
        if (dAccessSize == sAccessSize && sAccessSize == n) {
            if (DFL_AVX2) {
                return getFunction(M, "dfl_memcpy_field_glob_avx");
            }
            return getFunction(M, "dfl_memcpy_field_glob");
        }
        // if (DFL_AVX2) {
        //     return getFunction(M, "dfl_memcpy_glob_avx");
        // }
        return getFunction(M, "dfl_memcpy_glob");
    }

    // dest: glob, src: obj
    Function* getBestDFLGlobObjMemcpy(Module *M, uint64_t dAccessSize, uint64_t sAccessSize, uint64_t n) {
        ++nmemcpy;
        // if this is a constant memcpy of a field
        if (dAccessSize == sAccessSize && sAccessSize == n) {
            if (DFL_AVX2) {
                return getFunction(M, "dfl_memcpy_field_glob_obj_avx");
            }
            return getFunction(M, "dfl_memcpy_field_glob_obj");
        }
        // if (DFL_AVX2) {
        //     return getFunction(M, "dfl_memcpy_glob_avx");
        // }
        return getFunction(M, "dfl_memcpy_glob_obj");
    }
    
    // Avoid further optimizations on function F
    void setOptnone(Function *F) {
        if (F->hasFnAttribute(Attribute::OptimizeNone)) return;

        F->addFnAttr(Attribute::OptimizeNone);
    }

    void cast_i128_to_i64_i64(Value *V, Instruction *InsertBefore, Value** low, Value **high) {
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
    bool is_i64_i64_type(Type *_type) {
        LLVMContext& C = _type->getContext();
        if (!_type || !_type->isStructTy())
            return false;
        StructType *type = dyn_cast<StructType>(_type);
        assert(type);
        Type* i64Ty  = Type::getInt64Ty(C);
        return type->getNumElements() == 2 && 
            type->getElementType(0) == i64Ty && type->getElementType(1) == i64Ty;
    }

    Value *cast_i64_i64_to_i128(Value *V, Instruction *InsertBefore) {
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

    void wrapLoad(LoadInst *LI, DataLayout* DL, bool singleAccess) {
        LLVMContext& C = LI->getContext();
        Value* memoryPointer = LI->getPointerOperand();
        PointerType* pointerType = cast<PointerType>(LI->getPointerOperand()->getType());
        Type* type = pointerType->getPointerElementType();
        Type* longType = IntegerType::get( LI->getContext(), sizeof( unsigned long ) * 8 );
        // LLVM IR no signedness information
        uint64_t memoryeSizeBits = DL->getTypeStoreSize(type) * 8;
        bytesAccessed++;

        // Wrap the pointer if needed
        if (CFLedAccesses.find(LI) != CFLedAccesses.end()) {
            // not necessary to wrap since we will manage the access transparently
            // wrapLoadCFL(LI);
            CFLedAccesses.erase(LI);
        }

        // if (!singleAccess){
        //     oprint("-------------");
        //     oprint(*LI);
        //     oprint(*memoryPointer);
        // }

        // If the memory operation is marked as single access we have to retrieve
        // the index where to perform such access, for all the possible objects
        // The value 0, will be used for all other cases (e.g. small stride sizes)
        Value *Index = makeConstI64(C, 0);
        if (singleAccess) {
            Value *realPtr = memoryPointer;
            while(isa<CastInst>(realPtr))
                realPtr = dyn_cast<CastInst>(realPtr)->getOperand(0);
            GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(realPtr);
            if (GEP) {
                Index = getVariantIndex(GEP).first;
            } else {
                // oprint(*realPtr);
                unsupportedSingle++;
                singleAccess = false;
            }
        }


        Value* loadResult = nullptr;
        // Ensure there is at least another obj other than dummy
        // if (ptrToObjs[memoryPointer].find(CFL_dummy_ref) == ptrToObjs[memoryPointer].end())
        //     assert(ptrToObjs[memoryPointer].size());
        // else
        //     assert(ptrToObjs[memoryPointer].size() > 1);

        // We are indexing ptrToObjs by pointers, so better check that the pointers
        // still has not changed
        assert(ptrToObjs.find(memoryPointer) != ptrToObjs.end());
        for( ObjectWithFields objWithFields :  ptrToObjs[memoryPointer]) {
            const Value* obj = objWithFields.first;
            std::set<OffsetAndSize> fields = objWithFields.second;
            for( OffsetAndSize field : fields) {
                Value* fieldOff  = makeConstI64(C, field.first);
                Value* fieldSize = makeConstI64(C, field.second);
                // if (!singleAccess)
                // {
                //     oprint(*LI);
                //     oprint(" - may access:" << obj->getName().str());
                //     oprint(" - at: " << *fieldOff << " size: " << *fieldSize);
                // }
                GlobalVariable* listHead = allocToObjListHead[obj];
                assert(listHead);
                LoadInst* loadedListHead = new LoadInst(listHead, "", LI);
                Value* lastI = nullptr;

                if (const GlobalVariable* Gobj = dyn_cast<const GlobalVariable>(obj)) {
                    Value* globSize = objSizeCache[Gobj];
                    assert(globSize);

                    // uint64_t rawObjSize = dyn_cast<ConstantInt>(globSize)->getZExtValue();

                    Function *Fglob = getBestDFLGlobLoad(LI->getParent()->getParent()->getParent(), memoryeSizeBits, field.second, singleAccess);
                    assert(Fglob);

                    std::vector<Value*> args;
                    args.push_back(CastInst::CreatePointerCast(const_cast<GlobalVariable*>(Gobj), Fglob->getParamByValType(0)->getPointerTo(), "", LI));
                    args.push_back(CastInst::CreatePointerCast(memoryPointer, Fglob->getParamByValType(1)->getPointerTo(), "", LI));
                    args.push_back(CastInst::CreateIntegerCast(fieldOff, Fglob->getFunctionType()->getParamType(2), false, "", LI));
                    args.push_back(CastInst::CreateIntegerCast(fieldSize, Fglob->getFunctionType()->getParamType(3), false, "", LI));
                    // insert the index value if necessary
                    if (Fglob->arg_size() > args.size()) {
                        args.push_back(CastInst::CreateIntegerCast(Index, Fglob->getFunctionType()->getParamType(4), false, "", LI));
                    }
                    CallInst *CI = CallInst::Create(Fglob, args, "", LI);
                    Value *CstI;
                    if(type == Type::getInt128Ty(C)) {
                        // special case to convert from i128 llvm ABI
                        assert(is_i64_i64_type(CI->getType()));
                        CstI = cast_i64_i64_to_i128(CI, LI);
                    }
                    else if (type->isIntegerTy()) {
                        CstI = CastInst::CreateIntegerCast(CI, type, false, "", LI);
                    } else {
                        CstI = CastInst::CreateBitOrPointerCast(CI, type, "", LI);
                    }
                    lastI = CstI;
                } else {
                    // Value* globSize = objSizeCache[obj];
                    // assert(globSize);
                    // assert(isa<ConstantInt>(globSize));

                    // uint64_t rawObjSize = dyn_cast<ConstantInt>(globSize)->getZExtValue();

                    Function *Fobj = getBestDFLObjLoad(LI->getParent()->getParent()->getParent(), memoryeSizeBits, field.second, singleAccess);
                    assert(Fobj);

                    std::vector<Value*> args;
                    args.push_back(CastInst::CreatePointerCast(loadedListHead, Fobj->getParamByValType(0)->getPointerTo(), "", LI));
                    args.push_back(CastInst::CreatePointerCast(memoryPointer, Fobj->getParamByValType(1)->getPointerTo(), "", LI));
                    args.push_back(CastInst::CreateIntegerCast(fieldOff, Fobj->getFunctionType()->getParamType(2), false, "", LI));
                    args.push_back(CastInst::CreateIntegerCast(fieldSize, Fobj->getFunctionType()->getParamType(3), false, "", LI));
                    // insert the index value if necessary
                    if (Fobj->arg_size() > args.size()) {
                        args.push_back(CastInst::CreateIntegerCast(Index, Fobj->getFunctionType()->getParamType(4), false, "", LI));
                    }
                    CallInst *CI = CallInst::Create(Fobj, args, "", LI);
                    Value *CstI;
                    if(type == Type::getInt128Ty(C)) {
                        // special case to convert from i128 llvm ABI
                        assert(is_i64_i64_type(CI->getType()));
                        CstI = cast_i64_i64_to_i128(CI, LI);
                    }
                    else if (type->isIntegerTy()) {
                        CstI = CastInst::CreateIntegerCast(CI, type, false, "", LI);
                    } else {
                        CstI = CastInst::CreateBitOrPointerCast(CI, type, "", LI);
                    }
                    // ReplaceInstWithInst(LI, CstI);
                    lastI = CstI;
                }

                // Is this the first call?
                if (loadResult == nullptr) {
                    // if so just assign the result
                    loadResult = lastI;
                } else {
                    // otherwise is the or with the previous result
                    if (type->isPointerTy()) {
                        loadResult = CastInst::CreateBitOrPointerCast(
                            BinaryOperator::CreateOr(
                                CastInst::CreateBitOrPointerCast(loadResult, longType, "", LI), 
                                CastInst::CreateBitOrPointerCast(lastI, longType, "", LI), 
                                "", LI), type, "", LI);
                    }
                    else {
                        loadResult = BinaryOperator::CreateOr(loadResult, lastI, "", LI);
                    }
                }
            }
        }
        assert(loadResult);
        // if in debug mode, insert the check for pointer match
        if (DFL_DEBUG) {
            static Function *Fcheck = LI->getParent()->getParent()->getParent()->getFunction("dfl_debug_check_matched");
            assert(Fcheck);
            CallInst::Create(Fcheck, {}, "", LI);
        }

        LI->replaceAllUsesWith(loadResult);
        LI->eraseFromParent();
    }

    void wrapStore(StoreInst *SI, DataLayout* DL, bool singleAccess) {
        LLVMContext& C = SI->getContext();
        Value* memoryPointer = SI->getPointerOperand();
        Value* storedValue = SI->getValueOperand();
        PointerType* pointerType = cast<PointerType>(SI->getPointerOperand()->getType());
        Type* type = pointerType->getPointerElementType();
        // LLVM IR no signedness information
        uint64_t memoryeSizeBits = DL->getTypeStoreSize(type) * 8;
        bytesAccessed++;

        // Wrap the pointer if needed
        if (CFLedAccesses.find(SI) != CFLedAccesses.end()) {
            // necessary to wrap since we may write to memory otherwise
            // unless it is SingleAccess (no stride) as the handler itself
            // will check the taken `value`
            if (!singleAccess) {
                wrapStoreCFL(SI);
                CFLedAccesses.erase(SI);
            }
        }

        // if (!singleAccess){
        //     oprint("-------------");
        //     oprint(*SI);
        //     oprint(*memoryPointer);
        // }

        // If the memory operation is marked as single access we have to retrieve
        // the index where to perform such access, for all the possible objects
        // The value 0, will be used for all other cases (e.g. small stride sizes)
        Value *Index = makeConstI64(C, 0);
        if (singleAccess) {
            Value *realPtr = memoryPointer;
            while(isa<CastInst>(realPtr))
                realPtr = dyn_cast<CastInst>(realPtr)->getOperand(0);
            GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(realPtr);
            if (GEP) {
                Index = getVariantIndex(GEP).first;
            } else {
                // oprint(*realPtr);
                unsupportedSingle++;
                singleAccess = false;
                // wrap the access as we didn't
                if (CFLedAccesses.find(SI) != CFLedAccesses.end()) {
                    wrapStoreCFL(SI);
                    CFLedAccesses.erase(SI);
                }
            }
            // still remove SI from CFLedAccesses if needed
            if (CFLedAccesses.find(SI) != CFLedAccesses.end()) {
                CFLedAccesses.erase(SI);
            }
        }

        // Ensure there is at least another obj other than dummy
        // if (ptrToObjs[memoryPointer].find(CFL_dummy_ref) == ptrToObjs[memoryPointer].end())
        //     assert(ptrToObjs[memoryPointer].size());
        // else
        //     assert(ptrToObjs[memoryPointer].size() > 1);

        // We are indexing ptrToObjs by pointers, so better check that the pointers
        // still has not changed
        assert(ptrToObjs.find(memoryPointer) != ptrToObjs.end());
        for( ObjectWithFields objWithFields :  ptrToObjs[memoryPointer]) {
            const Value* obj = objWithFields.first;
            std::set<OffsetAndSize> fields = objWithFields.second;
            for( OffsetAndSize field : fields) {
                Value* fieldOff  = makeConstI64(C, field.first);
                Value* fieldSize = makeConstI64(C, field.second);
                // if (!singleAccess) {
                //     oprint(" - may access:");
                //     obj->print(outs());
                //     oprint(" - at: " << *fieldOff << " size: " << *fieldSize);
                // }
                GlobalVariable* listHead = allocToObjListHead[obj];
                assert(listHead);
                LoadInst* loadedListHead = new LoadInst(listHead, "", SI);

                if (const GlobalVariable* Gobj = dyn_cast<const GlobalVariable>(obj)) {
                    Value* globSize = objSizeCache[Gobj];
                    assert(globSize);

                    // uint64_t rawObjSize = dyn_cast<ConstantInt>(globSize)->getZExtValue();

                    Function *Fglob = getBestDFLGlobStore(SI->getParent()->getParent()->getParent(), memoryeSizeBits, field.second, singleAccess);
                    assert(Fglob);

                    std::vector<Value*> args;
                    args.push_back(CastInst::CreatePointerCast(const_cast<GlobalVariable*>(Gobj), Fglob->getParamByValType(0)->getPointerTo(), "", SI));
                    // refetch pointer operand since it may have changed
                    args.push_back(CastInst::CreatePointerCast(SI->getPointerOperand(), Fglob->getParamByValType(1)->getPointerTo(), "", SI));
                    args.push_back(CastInst::CreateIntegerCast(fieldOff, Fglob->getFunctionType()->getParamType(2), false, "", SI));
                    args.push_back(CastInst::CreateIntegerCast(fieldSize, Fglob->getFunctionType()->getParamType(3), false, "", SI));

                    if(storedValue->getType() == Type::getInt128Ty(C)) {
                        // special case for passing i128 according to llvm ABI
                        Value* low;
                        Value* high;
                        cast_i128_to_i64_i64(storedValue, SI, &low, &high);
                        args.push_back(low);
                        args.push_back(high);
                    }
                    else if(storedValue->getType()->isIntegerTy())
                        args.push_back(CastInst::CreateIntegerCast(storedValue, Fglob->getFunctionType()->getParamType(4), false, "", SI));
                    else // pointer type
                        args.push_back(CastInst::CreateBitOrPointerCast(storedValue, Fglob->getFunctionType()->getParamType(4), "", SI));

                    // insert the index value if necessary
                    if (Fglob->arg_size() > args.size()) {
                        args.push_back(CastInst::CreateIntegerCast(Index, Fglob->getFunctionType()->getParamType(args.size()), false, "", SI));
                    }
                    CallInst::Create(Fglob, args, "", SI);
                } else {
                    Function *Fobj = getBestDFLObjStore(SI->getParent()->getParent()->getParent(), memoryeSizeBits, field.second, singleAccess);
                    assert(Fobj);

                    std::vector<Value*> args;
                    args.push_back(CastInst::CreatePointerCast(loadedListHead, Fobj->getParamByValType(0)->getPointerTo(), "", SI));
                    // refetch pointer operand since it may have changed
                    args.push_back(CastInst::CreatePointerCast(SI->getPointerOperand(), Fobj->getParamByValType(1)->getPointerTo(), "", SI));
                    args.push_back(CastInst::CreateIntegerCast(fieldOff, Fobj->getFunctionType()->getParamType(2), false, "", SI));
                    args.push_back(CastInst::CreateIntegerCast(fieldSize, Fobj->getFunctionType()->getParamType(3), false, "", SI));

                    if(storedValue->getType() == Type::getInt128Ty(C)) {
                        // special case for passing i128 according to llvm ABI
                        Value* low;
                        Value* high;
                        cast_i128_to_i64_i64(storedValue, SI, &low, &high);
                        args.push_back(low);
                        args.push_back(high);
                    }
                    else if(storedValue->getType()->isIntegerTy())
                        args.push_back(CastInst::CreateIntegerCast(storedValue, Fobj->getFunctionType()->getParamType(4), false, "", SI));
                    else // pointer type
                        args.push_back(CastInst::CreateBitOrPointerCast(storedValue, Fobj->getFunctionType()->getParamType(4), "", SI));

                    // insert the index value if necessary
                    if (Fobj->arg_size() > args.size()) {
                        args.push_back(CastInst::CreateIntegerCast(Index, Fobj->getFunctionType()->getParamType(args.size()), false, "", SI));
                    }

                    CallInst::Create(Fobj, args, "", SI);
                }
            }
        }
        // if in debug mode, insert the check for pointer match
        if (DFL_DEBUG) {
            static Function *Fcheck = SI->getParent()->getParent()->getParent()->getFunction("dfl_debug_check_matched");
            assert(Fcheck);
            CallInst::Create(Fcheck, {}, "", SI);
        }
        SI->eraseFromParent();
    }

    void wrapMemset(Instruction *I, DataLayout* DL) {
        LLVMContext& C = I->getContext();
        CallSite CS(I);
        assert(CS.getInstruction() && !CS.isInlineAsm());
        Function *Callee = dyn_cast<Function>(CS.getCalledValue()->stripPointerCasts());
        assert(Callee);
        assert(CS.getIntrinsicID() == Intrinsic::memset);
        Value* memoryPointer = CS.getArgOperand(0);

        // Wrap the pointer
        wrapCallArgPtrCFL(CS, 0);
        wrapCallArgValCFL(CS, 2);

        // Ensure there is at least another obj other than dummy
        // if (ptrToObjs[memoryPointer].find(CFL_dummy_ref) == ptrToObjs[memoryPointer].end())
        //     assert(ptrToObjs[memoryPointer].size());
        // else
        //     assert(ptrToObjs[memoryPointer].size() > 1);

        // We are indexing ptrToObjs by pointers, so better check that the pointers
        // still has not changed
        assert(ptrToObjs.find(memoryPointer) != ptrToObjs.end());
        for( ObjectWithFields objWithFields :  ptrToObjs[memoryPointer]) {
            const Value* obj = objWithFields.first;
            std::set<OffsetAndSize> fields = objWithFields.second;
            for( OffsetAndSize field : fields) {
                Value* fieldOff  = makeConstI64(C, field.first);
                Value* fieldSize = makeConstI64(C, field.second);
                // if (!singleAccess) {
                //     oprint(" - may access:");
                //     obj->print(outs());
                //     oprint(" - at: " << *fieldOff << " size: " << *fieldSize);
                // }
                GlobalVariable* listHead = allocToObjListHead[obj];
                assert(listHead);
                LoadInst* loadedListHead = new LoadInst(listHead, "", I);

                if (const GlobalVariable* Gobj = dyn_cast<const GlobalVariable>(obj)) {
                    Value* globSize = objSizeCache[Gobj];
                    assert(globSize);

                    // uint64_t rawObjSize = dyn_cast<ConstantInt>(globSize)->getZExtValue();

                    Function *Fglob = getBestDFLGlobMemset(I->getParent()->getParent()->getParent(), field.second);
                    assert(Fglob);
                    // Avoid that the wrapper will be optimized further
                    setOptnone(Fglob);

                    std::vector<Value*> args;
                    for (Value* arg: CS.args())
                        args.push_back(arg);

                    args.push_back(CastInst::CreatePointerCast(const_cast<GlobalVariable*>(Gobj), Fglob->getParamByValType(CS.getNumArgOperands() + 0)->getPointerTo(), "", I));
                    args.push_back(CastInst::CreateIntegerCast(fieldOff, Fglob->getFunctionType()->getParamType(CS.getNumArgOperands() + 1), false, "", I));
                    args.push_back(CastInst::CreateIntegerCast(fieldSize, Fglob->getFunctionType()->getParamType(CS.getNumArgOperands() + 2), false, "", I));

                    CallInst::Create(Fglob, args, "", I);
                } else {
                    Function *Fobj = getBestDFLObjMemset(I->getParent()->getParent()->getParent(), field.second);
                    assert(Fobj);
                    // Avoid that the wrapper will be optimized further
                    setOptnone(Fobj);

                    std::vector<Value*> args;
                    for (Value* arg: CS.args())
                        args.push_back(arg);

                    args.push_back(CastInst::CreatePointerCast(loadedListHead, Fobj->getParamByValType(CS.getNumArgOperands() + 0)->getPointerTo(), "", I));
                    args.push_back(CastInst::CreateIntegerCast(fieldOff, Fobj->getFunctionType()->getParamType(CS.getNumArgOperands() + 1), false, "", I));
                    args.push_back(CastInst::CreateIntegerCast(fieldSize, Fobj->getFunctionType()->getParamType(CS.getNumArgOperands() + 2), false, "", I));

                    CallInst::Create(Fobj, args, "", I);
                }
            }
        }
        // if in debug mode, insert the check for pointer match
        // if (DFL_DEBUG) {
        //     static Function *Fcheck = I->getParent()->getParent()->getParent()->getFunction("dfl_debug_check_matched");
        //     assert(Fcheck);
        //     CallInst::Create(Fcheck, {}, "", I);
        // }
        I->eraseFromParent();
    }

    void wrapMemcpy(Instruction *I, DataLayout* DL) {
        LLVMContext& C = I->getContext();
        CallSite CS(I);
        assert(CS.getInstruction() && !CS.isInlineAsm());
        Function *Callee = dyn_cast<Function>(CS.getCalledValue()->stripPointerCasts());
        assert(Callee);
        assert(CS.getIntrinsicID() == Intrinsic::memcpy || CS.getIntrinsicID() == Intrinsic::memmove);
        Value* destPointer = CS.getArgOperand(0);
        Value* srcPointer = CS.getArgOperand(1);

        // Get the original memcpy size
        Value* nV = CS.getArgOperand(2);
        unsigned long n = 0;
        if (ConstantInt* nCI = dyn_cast<ConstantInt>(nV)) {
            n = nCI->getZExtValue();
        }

        // Wrap the arguments
        wrapCallArgPtrCFL(CS, 0);
        wrapCallArgPtrCFL(CS, 1);
        wrapCallArgValCFL(CS, 2);

        // Ensure there is at least another obj other than dummy
        // if (ptrToObjs[memoryPointer].find(CFL_dummy_ref) == ptrToObjs[memoryPointer].end())
        //     assert(ptrToObjs[memoryPointer].size());
        // else
        //     assert(ptrToObjs[memoryPointer].size() > 1);

        // We are indexing ptrToObjs by pointers, so better check that the pointers
        // still has not changed
        assert(ptrToObjs.find(destPointer) != ptrToObjs.end());
        assert(ptrToObjs.find(srcPointer) != ptrToObjs.end());

        // For every combination of dest/src field that can be accessed produce
        // a call to DFL memcpy helper
        for( ObjectWithFields dObjWithFields :  ptrToObjs[destPointer]) {

            // Destination object and fields
            const Value* dObj = dObjWithFields.first;
            std::set<OffsetAndSize> dFields = dObjWithFields.second;

            for(ObjectWithFields sObjWithFields :  ptrToObjs[srcPointer]) {

                // Source object and fields
                const Value* sObj = sObjWithFields.first;
                std::set<OffsetAndSize> sFields = sObjWithFields.second;

                GlobalVariable* sListHead = allocToObjListHead[sObj];
                assert(sListHead);
                LoadInst* sLoadedListHead = new LoadInst(sListHead, "", I);

                // All field combinations
                for( OffsetAndSize dField : dFields) {
                    Value* dFieldOff  = makeConstI64(C, dField.first);
                    Value* dFieldSize = makeConstI64(C, dField.second);

                    for( OffsetAndSize sField : sFields) {
                        Value* sFieldOff  = makeConstI64(C, sField.first);
                        Value* sFieldSize = makeConstI64(C, sField.second);

                        if (const GlobalVariable* dGobj = dyn_cast<const GlobalVariable>(dObj)) {
                            if (const GlobalVariable* sGobj = dyn_cast<const GlobalVariable>(sObj)) {

                                Function *Fglob = getBestDFLGlobMemcpy(I->getParent()->getParent()->getParent(), dField.second, sField.second, n);
                                assert(Fglob);
                                // Avoid that the wrapper will be optimized further
                                setOptnone(Fglob);

                                std::vector<Value*> args;
                                for (Value* arg: CS.args())
                                    args.push_back(arg);

                                args.push_back(CastInst::CreatePointerCast(const_cast<GlobalVariable*>(dGobj), Fglob->getParamByValType(CS.getNumArgOperands() + 0)->getPointerTo(), "", I));
                                args.push_back(CastInst::CreateIntegerCast(dFieldOff, Fglob->getFunctionType()->getParamType(CS.getNumArgOperands() + 1), false, "", I));
                                args.push_back(CastInst::CreateIntegerCast(dFieldSize, Fglob->getFunctionType()->getParamType(CS.getNumArgOperands() + 2), false, "", I));

                                args.push_back(CastInst::CreatePointerCast(const_cast<GlobalVariable*>(sGobj), Fglob->getParamByValType(CS.getNumArgOperands() + 3)->getPointerTo(), "", I));
                                args.push_back(CastInst::CreateIntegerCast(sFieldOff, Fglob->getFunctionType()->getParamType(CS.getNumArgOperands() + 4), false, "", I));
                                args.push_back(CastInst::CreateIntegerCast(sFieldSize, Fglob->getFunctionType()->getParamType(CS.getNumArgOperands() + 5), false, "", I));

                                CallInst::Create(Fglob, args, "", I);
                            } else {
                                Function *Fobj = getBestDFLGlobObjMemcpy(I->getParent()->getParent()->getParent(), dField.second, sField.second, n);
                                assert(Fobj);
                                // Avoid that the wrapper will be optimized further
                                setOptnone(Fobj);

                                std::vector<Value*> args;
                                for (Value* arg: CS.args())
                                    args.push_back(arg);

                                args.push_back(CastInst::CreatePointerCast(const_cast<GlobalVariable*>(dGobj), Fobj->getParamByValType(CS.getNumArgOperands() + 0)->getPointerTo(), "", I));
                                args.push_back(CastInst::CreateIntegerCast(dFieldOff, Fobj->getFunctionType()->getParamType(CS.getNumArgOperands() + 1), false, "", I));
                                args.push_back(CastInst::CreateIntegerCast(dFieldSize, Fobj->getFunctionType()->getParamType(CS.getNumArgOperands() + 2), false, "", I));

                                args.push_back(CastInst::CreatePointerCast(sLoadedListHead, Fobj->getParamByValType(CS.getNumArgOperands() + 3)->getPointerTo(), "", I));
                                args.push_back(CastInst::CreateIntegerCast(sFieldOff, Fobj->getFunctionType()->getParamType(CS.getNumArgOperands() + 4), false, "", I));
                                args.push_back(CastInst::CreateIntegerCast(sFieldSize, Fobj->getFunctionType()->getParamType(CS.getNumArgOperands() + 5), false, "", I));

                                CallInst::Create(Fobj, args, "", I);
                            }
                        } else {
                            assert(false && "memcpy with non-global dest still not implemented");
                        }
                    }
                }
            }
        }
        // if in debug mode, insert the check for pointer match
        // if (DFL_DEBUG) {
        //     static Function *Fcheck = I->getParent()->getParent()->getParent()->getFunction("dfl_debug_check_matched");
        //     assert(Fcheck);
        //     CallInst::Create(Fcheck, {}, "", I);
        // }
        I->eraseFromParent();
    }

    Type* wrapType(AllocaInst* AI) {
        Type* T = AI->getAllocatedType();
        LLVMContext& C = AI->getContext();
        vector<Type*> members;

        StructType* objListType = AI->getParent()->getParent()->getParent()->getTypeByName("struct.dfl_obj_list");
        assert(objListType);
        PointerType* headType = objListType->getPointerTo();

        members.push_back( headType ); // next ptr field
        members.push_back( headType ); // prev ptr field
        members.push_back( headType->getPointerTo() ); // head ptr field
        members.push_back( IntegerType::get( C, sizeof( unsigned long ) * 8 ) ); // size field
        members.push_back( IntegerType::get( C, sizeof( unsigned long ) * 8 ) ); // padding
        members.push_back( IntegerType::get( C, sizeof( unsigned long ) * 8 ) ); // magic
        assert(members.size() == DFL_OBJ_DATA_OFFSET);

        members.push_back( T );

        // if debugging pad the structure up to the next cache line
        if (DFL_DEBUG) {
            const DataLayout &DL = AI->getParent()->getParent()->getParent()->getDataLayout();
            // current size is the metadata size plus the type size
            int current_size = (DFL_OBJ_DATA_OFFSET * sizeof( unsigned long )) + DL.getTypeAllocSize(T);
            int padded_size  = ((current_size + DFL_STRIDE - 1) / DFL_STRIDE) * DFL_STRIDE;

            int padding_elements = padded_size - current_size;
            if (padding_elements)
                members.push_back( ArrayType::get(IntegerType::get( C, sizeof( unsigned char ) * 8 ), padding_elements) );
        }

        StructType *wrappingStruct = StructType::create( C, members, "dfl_struct_wrapper_" + std::to_string(getUniqueID()));
        return wrappingStruct;
    }

    void removeLifetimes(Value *target, Function *F) {
        std::set<Instruction*> to_remove;
        // oprint("-------------------");
        // oprint("seraching for: " << *target);
        // Visit all the instruction searching for lifetime intrinsics
        for (auto &BB : *F) {
            for (auto &I : BB) {
                if (IntrinsicInst* II = dyn_cast<IntrinsicInst>(&I)) {
                    Intrinsic::ID ID = II->getIntrinsicID();
                    if (ID == Intrinsic::lifetime_start || ID == Intrinsic::lifetime_end ) {
                        Value *OP = II->getArgOperand(1)->stripPointerCasts();
                        // // Dereference all the bitcasts
                        // while (BitCastInst* BI = dyn_cast<BitCastInst>(OP)) {
                        //     OP = BI->getOperand(0);
                        // }
                        if (OP == target) {
                            to_remove.insert(&I);
                        }
                    }
                }
            }
        }
        for (Instruction *I: to_remove) {
            // oprint(*I);
            I->eraseFromParent();
        }
    }

    Value *wrapCFLPtr(Value *ptr, Instruction *insertBefore) {
        assert(ptr->getType()->isPointerTy());
        static Function *F = insertBefore->getParent()->getParent()->getParent()->getFunction("dfl_ptr_wrap");
        assert(F);
        std::vector<Value*> args;
        args.push_back(CastInst::CreatePointerCast(ptr, F->getParamByValType(0)->getPointerTo(), "", insertBefore));
        CallInst *CI = CallInst::Create(F, args, "", insertBefore);
        return CI;
    }

    void wrapStackAlloc(const AllocaInst* AI, bool willCFL) {
        // oprint("Stack Alloc\n" << *AI);
        LLVMContext& C = AI->getContext();
        static Function *DFLAddFunc = AI->getParent()->getParent()->getParent()->getFunction("dfl_obj_list_add");
        static Function *DFLObjPrintFunc = AI->getParent()->getParent()->getParent()->getFunction("dfl_obj_print");
        static Function *DFLUnlinkFunc = AI->getParent()->getParent()->getParent()->getFunction("dfl_obj_list_unlink");
        assert(DFLAddFunc && DFLUnlinkFunc && DFLObjPrintFunc);

        Instruction *NI = const_cast<Instruction*>(AI->getNextNode());
        assert(NI);
        AllocaInst *mutAI = const_cast<AllocaInst*>(AI);
        assert(mutAI);

        // Set the allocation type to the wrapped struct
        Type *wrappedType = wrapType(mutAI);
        const DataLayout &DL = AI->getParent()->getParent()->getParent()->getDataLayout();
        unsigned AddrSpace = DL.getAllocaAddrSpace();
        Value *ArraySize = ConstantInt::get(Type::getInt32Ty(C), 1);

        // if debugging set the allocation alignment to cache line size
        AllocaInst* newAI;
        if (DFL_DEBUG)
            newAI = new AllocaInst(wrappedType, AddrSpace, ArraySize, DFL_STRIDE, "", NI);
        else
            newAI = new AllocaInst(wrappedType, AddrSpace, ArraySize, DEFAULT_STACK_ALIGNMENT, "", NI);

        // Still produce the right type
        std::vector<Value*> index_vector;
        index_vector.push_back( ConstantInt::get(Type::getInt32Ty(C), 0));
        index_vector.push_back( ConstantInt::get(Type::getInt32Ty(C), DFL_OBJ_DATA_OFFSET)); // data field of the struct
        Value* allocatedVariable = GetElementPtrInst::Create(wrappedType, newAI, index_vector, "", NI);
        mutAI->replaceAllUsesWith(allocatedVariable);

        GlobalVariable *objListHead = allocToObjListHead[AI];
        assert(objListHead);

        Value* objSize = objSizeCache[AI];
        assert(objSize);
        mutAI->eraseFromParent();

        // Set the new lifetime start information
        llvm::IRBuilder<> BuilderStart(NI);
        BuilderStart.CreateLifetimeStart(newAI, ConstantInt::get(Type::getInt64Ty(C), DL.getTypeAllocSize(newAI->getAllocatedType()))); // byte size of the metadata
        removeLifetimes(allocatedVariable, newAI->getParent()->getParent());

        // if the function we are in will be CFLed, we have to wrap the calls arguments
        // to avoid crashes
        Value * wrappedAI;
        Value * wrappedeListHead;
        // if we pass a different address to the constructor we leak we are in dummy mode
        // so for stack allocations always insert/remove even in dummy mode, since
        // addresses will be valid
        // if (willCFL) {
        //     wrappedAI        = wrapCFLPtr(newAI, NI);
        //     wrappedeListHead = wrapCFLPtr(objListHead, NI);
        // } else
        {
            wrappedAI        = newAI;
            wrappedeListHead = objListHead;
        }

        // Add debug print for the managed object (empty function if DFL_DEBUG set to 0)
        std::vector<Value*> args;
        args.push_back(CastInst::CreatePointerCast(wrappedAI, DFLObjPrintFunc->getParamByValType(0)->getPointerTo(), "", NI));
        args.push_back(CastInst::CreateIntegerCast(objSize, DFLObjPrintFunc->getFunctionType()->getParamType(1), false, "", NI));
        CallInst::Create(DFLObjPrintFunc, args, "", NI);

        // Create a lifetime end for the metadata in each return block
        // + Remove the node from list when exiting
        for (auto &BB : *(newAI->getParent()->getParent())) {
            if (ReturnInst *RI = dyn_cast<ReturnInst> (BB.getTerminator())) {
                // if (willCFL) {
                //     allocatedVariable = wrapCFLPtr(allocatedVariable, RI);
                // }
                std::vector<Value*> args;
                args.push_back(CastInst::CreatePointerCast(allocatedVariable, DFLUnlinkFunc->getParamByValType(0)->getPointerTo(), "", RI));
                CallInst::Create(DFLUnlinkFunc, args, "", RI);

                llvm::IRBuilder<> BuilderEnd(RI);
                BuilderEnd.CreateLifetimeEnd(newAI, ConstantInt::get(Type::getInt64Ty(C), DL.getTypeAllocSize(newAI->getAllocatedType())));
            }
        }

        // Call the dlf_add function to add the object to the managed ones at runtime
        args.clear();
        args.push_back(CastInst::CreatePointerCast(wrappedeListHead, DFLAddFunc->getParamByValType(0)->getPointerTo(), "", NI));
        args.push_back(CastInst::CreatePointerCast(wrappedAI, DFLAddFunc->getParamByValType(1)->getPointerTo(), "", NI));
        args.push_back(CastInst::CreateIntegerCast(objSize, DFLAddFunc->getFunctionType()->getParamType(2), false, "", NI));
        CallInst::Create(DFLAddFunc, args, "", NI);

        // oprint(*AI->getParent());
    }

    void wrapGlobalAlloc(const GlobalVariable* globalDecl) {
        // Global variables are managed at access time, here we just have to 
        // insert the call to the dfl_print function to keep track of managed global
        // objects while debugging
        static Function *DFLObjPrintFunc = globalDecl->getParent()->getFunction("dfl_glob_obj_print");
        static Function *DFLInitFunc = globalDecl->getParent()->getFunction("dfl_init");
        assert(DFLObjPrintFunc && DFLInitFunc);

        BasicBlock *EntryBB = &DFLInitFunc->getEntryBlock();
        Instruction *EntryI = EntryBB->getFirstNonPHI();
        assert(EntryI);

        Value* objSize = objSizeCache[globalDecl];
        assert(objSize);

        // Add debug print for the managed object (empty function if DFL_DEBUG set to 0)
        std::vector<Value*> args;
        args.push_back(CastInst::CreatePointerCast(const_cast<GlobalVariable*>(globalDecl), DFLObjPrintFunc->getParamByValType(0)->getPointerTo(), "", EntryI));
        args.push_back(CastInst::CreateIntegerCast(objSize, DFLObjPrintFunc->getFunctionType()->getParamType(1), false, "", EntryI));
        CallInst::Create(DFLObjPrintFunc, args, "", EntryI);
    }

    void wrapHeapAlloc(const Instruction* AI, bool willCFL) {
        // oprint("Heap Alloc\n" << *AI);
        LLVMContext& C = AI->getContext();
        static Function *DFLAddFunc = AI->getParent()->getParent()->getParent()->getFunction("dfl_obj_list_add");
        static Function *DFLObjPrintFunc = AI->getParent()->getParent()->getParent()->getFunction("dfl_obj_print");
        assert(DFLAddFunc && DFLObjPrintFunc);

        Instruction *NI = const_cast<Instruction*>(AI->getNextNode());
        assert(NI);
        Instruction *mutAI = const_cast<Instruction*>(AI);
        assert(mutAI);

        // TODO, may it vary?
        Value* objSize = objSizeCache[AI];
        assert(objSize);

        // Set the allocation size to the size of the wrapped struct
        Value *additionalSize = ConstantInt::get(Type::getInt64Ty(C), DFL_OBJ_DATA_OFFSET * sizeof(void*)); // sizeof metadata
        Value* newSize = BinaryOperator::CreateAdd(objSize, additionalSize, "", mutAI);

        CallSite CS(const_cast<Instruction*>(mutAI));
        // oprint(CS.getCalledFunction()->getName().str());
        // accept malloc() or `_Znwm`=`operator new(unsigned long)`
        assert(CS.getCalledFunction()->getName().equals("malloc") || CS.getCalledFunction()->getName().equals("_Znwm")); // Still stay simple man
        CS.setArgument(0, newSize);

        // Still produce the right type
        std::vector<Value*> index_vector;
        index_vector.push_back( ConstantInt::get(Type::getInt32Ty(C), 0));
        index_vector.push_back( ConstantInt::get(Type::getInt32Ty(C), DFL_OBJ_DATA_OFFSET)); // data field of the struct
        Type* wrappedType = mutAI->getParent()->getParent()->getParent()->getTypeByName("struct.dfl_obj_list");

        // Here we are introducing a use that we will have to recover after RAUW
        // Cast the variable to the right struct ptr type
        CastInst *castedVar = CastInst::CreatePointerCast(mutAI, wrappedType->getPointerTo(), "", NI);

        // Get the real allocated variable
        GetElementPtrInst* allocatedVariable = GetElementPtrInst::Create(wrappedType, castedVar, index_vector, "", NI);
        mutAI->replaceAllUsesWith(CastInst::CreatePointerCast(allocatedVariable, mutAI->getType(), "", NI));

        //recover the casting instruction
        castedVar->setOperand(0, mutAI);

        GlobalVariable *objListHead = allocToObjListHead[AI];
        assert(objListHead);

        // if the function we are in will be CFLed, we have to wrap the calls arguments
        // to avoid crashes
        Value * wrappedAI;
        Value * wrappedeListHead;
        if (willCFL) {
            wrappedAI        = wrapCFLPtr(mutAI, NI);
            wrappedeListHead = wrapCFLPtr(objListHead, NI);
        } else
        {
            wrappedAI        = mutAI;
            wrappedeListHead = objListHead;
        }

        // Add debug print for the managed object (empty function if DFL_DEBUG set to 0)
        std::vector<Value*> args;
        args.push_back(CastInst::CreatePointerCast(wrappedAI, DFLObjPrintFunc->getParamByValType(0)->getPointerTo(), "", NI));
        args.push_back(CastInst::CreateIntegerCast(objSize, DFLObjPrintFunc->getFunctionType()->getParamType(1), false, "", NI));
        CallInst::Create(DFLObjPrintFunc, args, "", NI);

        // Call the dlf_add function to add the object to the managed ones at runtime
        args.clear();
        args.push_back(CastInst::CreatePointerCast(wrappedeListHead, DFLAddFunc->getParamByValType(0)->getPointerTo(), "", NI));
        args.push_back(CastInst::CreatePointerCast(wrappedAI, DFLAddFunc->getParamByValType(1)->getPointerTo(), "", NI));
        args.push_back(CastInst::CreateIntegerCast(objSize, DFLAddFunc->getFunctionType()->getParamType(2), false, "", NI));
        CallInst::Create(DFLAddFunc, args, "", NI);

        // oprint(*AI->getParent());
    }

    void wrapHeapDealloc(CallInst* CI, bool willCFL) {
        // oprint("Heap Dealloc\n" << *CI);
        // Remember to stay simple man: manage only free or `operator delete(void*)`
        // oprint("Dealloc Call: " << CI->getCalledFunction()->getName().str());
        assert(CI->getCalledFunction()->getName().equals("free") || CI->getCalledFunction()->getName().equals("_ZdlPv"));

        static Function *DFLUnlinkFunc = CI->getParent()->getParent()->getParent()->getFunction("dfl_obj_list_unlink");
        assert(DFLUnlinkFunc);

        Value* ptr = CI->getArgOperand(0);
        // ptr->dump();

        if (willCFL) {
            ptr = wrapCFLPtr(ptr, CI);
        }

        std::vector<Value*> args;
        args.push_back(CastInst::CreatePointerCast(ptr, DFLUnlinkFunc->getParamByValType(0)->getPointerTo(), "", CI));
        CallInst* unlinkCI = CallInst::Create(DFLUnlinkFunc, args, "", CI);

        CI->setArgOperand(0, unlinkCI);
    }

    void wrapLoadCFL(LoadInst *LI) {
        // oprint("wrapping for CFL: " << *LI);
        static Function *F = LI->getParent()->getParent()->getParent()->getFunction("dfl_ptr_wrap");
        assert(F);
        std::vector<Value*> args;
        args.push_back(CastInst::CreatePointerCast(LI->getPointerOperand(), F->getParamByValType(0)->getPointerTo(), "", LI));
        CallInst *CI = CallInst::Create(F, args, "", LI);
        LI->setOperand(0, CastInst::CreatePointerCast(CI, LI->getPointerOperandType(), "", LI));
    }

    void wrapStoreCFL(StoreInst *SI) {
        // oprint("wrapping for CFL: " << *SI);
        static Function *F = SI->getParent()->getParent()->getParent()->getFunction("dfl_ptr_wrap");
        assert(F);
        std::vector<Value*> args;
        args.push_back(CastInst::CreatePointerCast(SI->getPointerOperand(), F->getParamByValType(0)->getPointerTo(), "", SI));
        CallInst *CI = CallInst::Create(F, args, "", SI);
        SI->setOperand(1, CastInst::CreatePointerCast(CI, SI->getPointerOperandType(), "", SI));
    }

    void wrapCallArgPtrCFL(CallSite &CS, int argNo) {
        // oprint("wrapping for CFL: " << *SI);
        Instruction *I = CS.getInstruction();
        assert(I);
        static Function *F = I->getParent()->getParent()->getParent()->getFunction("dfl_ptr_wrap");
        assert(F);
        std::vector<Value*> args;
        args.push_back(CastInst::CreatePointerCast(CS.getArgOperand(argNo), F->getParamByValType(0)->getPointerTo(), "", I));
        CallInst *CI = CallInst::Create(F, args, "", I);
        CS.setArgument(argNo, CastInst::CreatePointerCast(CI, CS.getArgOperand(argNo)->getType(), "", I));
    }

    void wrapCallArgValCFL(CallSite &CS, int argNo) {
        // oprint("wrapping for CFL: " << *SI);
        Instruction *I = CS.getInstruction();
        assert(I);
        static Function *F = I->getParent()->getParent()->getParent()->getFunction("dfl_val_wrap");
        assert(F);
        std::vector<Value*> args;
        args.push_back(CastInst::CreateIntegerCast(CS.getArgOperand(argNo), F->getFunctionType()->getParamType(0), /*isSigned=*/ false, "", I));
        CallInst *CI = CallInst::Create(F, args, "", I);
        CS.setArgument(argNo, CastInst::CreateIntegerCast(CI, CS.getArgOperand(argNo)->getType(), /*isSigned=*/ false, "", I));
    }

    void gatherDeallocCalls(Function *F) {
        for (auto &BB : *F)
        for (auto &I : BB) {
            // Collect all deallocation functions
            if (CallInst *CI = dyn_cast<CallInst>(&I)) {

                if (SVFUtil::isDeallocExtCall(CI)) {
                    // Stay simple man: manage only free or `operator delete(void*)`
                    // oprint("Dealloc Call: " << CI->getCalledFunction()->getName().str());
                    assert(CI->getCalledFunction()->getName().equals("free") || CI->getCalledFunction()->getName().equals("_ZdlPv"));
                    deallocCalls.insert(CI);
                    continue;
                }

                // TODO: realloc not currently supported
                assert (!SVFUtil::isReallocExtCall(CI));
                continue;
            }
        }
    }

    void dfl_prepare(Function *F, PointerAnalysis* pta, DataLayout* DL, bool willCFL) {
        dflPassLog("DFLing " << F->getName());
        // oprint("DFLing " << F->getName().str());

        // Collect points-to information
        for (auto &BB : *F)
        for (auto &I : BB) {
            if (isa<LoadInst>(I) || isa<StoreInst>(I)) {
                ++totalAccesses;
            }
            if (!AllAccesses && !getInstructionTaint(I) && !willCFL)
                continue;
            if (LoadInst *LI = dyn_cast<LoadInst>(&I)) {
                collectPts(pta, &I, LI->getPointerOperand(), DL, willCFL);
                continue;
            }
            if (StoreInst *SI = dyn_cast<StoreInst>(&I)) {
                collectPts(pta, &I, SI->getPointerOperand(), DL, willCFL);
                continue;
            }

            // Collect info on calls to memcpy/memset/memmove
            CallSite CS(&I);
            if (!CS.getInstruction() || CS.isInlineAsm())
                continue; // not a call
            Function *Callee = dyn_cast<Function>(CS.getCalledValue()->stripPointerCasts());
            if (!Callee)
                continue; // not a direct call
            if (Callee->isIntrinsic()) {
                switch(Callee->getIntrinsicID()) {
                    case Intrinsic::memcpy:
                    case Intrinsic::memmove:
                        collectPts(pta, &I, CS.getArgOperand(0), DL, willCFL);
                        collectPts(pta, &I, CS.getArgOperand(1), DL, willCFL);
                        break;
                    case Intrinsic::memset:
                        collectPts(pta, &I, CS.getArgOperand(0), DL, willCFL);
                        break;
                    default:
                        break;
                }
            }
        }
    }

    void insertPrintIds(Instruction *I) {
        LLVMContext& C = I->getContext();
        static Function *F = I->getModule()->getFunction("dfl_id_print");
        assert(F);
        std::vector<Value*> args;
        args.push_back(makeConstI64(C, (unsigned long) getBGID(*I)));
        args.push_back(makeConstI64(C, (unsigned long) getIBID(*I)));
        CallInst::Create(F, args, "", I);
    }

    void dfl(Module* M, DataLayout* DL, std::set<const Function*> &cflFunctionSet) {

        // For each alloca instruction declare a global (tls) variable to hold obj list head
        for(auto const& alloc :  allocToObjListHead) {
            const Value* allocSite = alloc.first;
            StructType* objListType = M->getTypeByName("struct.dfl_obj_list");
            assert(objListType);
            PointerType* headType = objListType->getPointerTo();
            ConstantPointerNull* const_ptr_init = ConstantPointerNull::get(headType);
            std::string globalName = "dfl_glob_obj_head_" + std::to_string(getUniqueID());

            M->getOrInsertGlobal(globalName, headType);
            GlobalVariable *objListHead = M->getNamedGlobal(globalName);
            objListHead->setLinkage(GlobalValue::InternalLinkage);
            objListHead->setAlignment(8);
            objListHead->setInitializer(const_ptr_init);

            allocToObjListHead[alloc.first] = objListHead;
            if (const AllocaInst* allocInstr = SVFUtil::dyn_cast<AllocaInst>(allocSite)) {
                bool willCFL = cflFunctionSet.find(allocInstr->getParent()->getParent()) != cflFunctionSet.end();
                wrapStackAlloc(allocInstr, willCFL);
            } else if (const Instruction* allocInstr = SVFUtil::dyn_cast<Instruction>(allocSite)) {
                bool willCFL = cflFunctionSet.find(allocInstr->getParent()->getParent()) != cflFunctionSet.end();
                wrapHeapAlloc(allocInstr, willCFL);
            } else if (const GlobalVariable* globalDecl = SVFUtil::dyn_cast<GlobalVariable>(allocSite)) {
                wrapGlobalAlloc(globalDecl);
            } else {
                assert(false && "alloc site should be either an instruction or a global variable declaration");
            }
        }

        // Wrap heap frees to manage unlinking and correctly pass the ptr to free
        for (auto *deallocInstr: deallocCalls) {
            bool willCFL = cflFunctionSet.find(deallocInstr->getParent()->getParent()) != cflFunctionSet.end();
            wrapHeapDealloc(deallocInstr, willCFL);
        }

        // Wrap loads and stores
        // manage also CFL preparation
        for(Instruction* memAccess :  memAccesses) {
            if (StoreInst *SI = dyn_cast<StoreInst>(memAccess)) {
                // if not tainted not necessary to stride the obj
                // if the memory pointer is an induction variable, as will not depend on input
                Value *realPtr = SI->getPointerOperand();
                bool singleAccess = (getInstructionTaint(*SI) == false) && (DFLRelaxed || (DFLInductionOpt && isInductionVar(realPtr)));

                // if debug, print the instruction ids
                if(DFL_DEBUG) insertPrintIds(memAccess);
                wrapStore(SI, DL, singleAccess);
                continue;
            }
            if (LoadInst *LI = dyn_cast<LoadInst>(memAccess)) {
                // if not tainted not necessary to stride the obj
                // if the memory pointer is an induction variable, as will not depend on input
                Value *realPtr = LI->getPointerOperand();
                bool singleAccess = (getInstructionTaint(*LI) == false) && (DFLRelaxed || (DFLInductionOpt && isInductionVar(realPtr)));

                // if debug, print the instruction ids
                if(DFL_DEBUG) insertPrintIds(memAccess);
                wrapLoad(LI, DL, singleAccess);
                continue;
            }

            // Wrap calls to memcpy/memset/memmove
            CallSite CS(memAccess);
            if (!CS.getInstruction() || CS.isInlineAsm())
                continue; // not a call
            Function *Callee = dyn_cast<Function>(CS.getCalledValue()->stripPointerCasts());
            if (!Callee)
                continue; // not a direct call
            if (Callee->isIntrinsic()) {
                switch(Callee->getIntrinsicID()) {
                    case Intrinsic::memcpy:
                    case Intrinsic::memmove:
                        // if debug, print the instruction ids
                        if(DFL_DEBUG) insertPrintIds(memAccess);
                        wrapMemcpy(memAccess, DL);
                        break;
                    case Intrinsic::memset:
                        // if debug, print the instruction ids
                        if(DFL_DEBUG) insertPrintIds(memAccess);
                        wrapMemset(memAccess, DL);
                        break;
                    default:
                        break;
                }
            }
        }

        // Wrap the remaining CFL accesses 
        // (as a memory access may have no points-to set assigned by SVF,
        // thus may not appear in `memAccesses`)
        for(auto *I: CFLedAccesses){
            if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
                wrapStoreCFL(SI);
                continue;
            }
            if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
                wrapLoadCFL(LI);
                continue;
            }
        }
    }

    virtual bool runOnModule(Module &M) {
        dflPassLog("Running...");

        // Check that if debug is enabled in the dfl library we are properly configured
        if (M.getFunction("dfl_debug_is_enabled")) {
            // Check that AVX is disabled
            // oprint("-------------- DEBUG CHECKS DISABLED --------------");
            assert(!DFL_AVX2 && !DFL_AVX512 && "Disable AVX to make sure DFL debug works");

            // Check lib and pass are coherent
            // assert(DFL_DEBUG && "DFL Pass DEBUG is disabled while DFL lib debug not");

            // enable debug mode
            DFL_DEBUG = true;
        } else {
            // just to avoid forgetting to enable AVX
            // assert(DFL_AVX2 || DFL_AVX512);
        }

        DataLayout* DL = new DataLayout(&M);
        SVFModule* svfModule = LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(M);
        PointerAnalysis* pta = new Andersen();
        pta->analyze(svfModule);
        oprint("[+] Done with SVF analysis");

        // Get the CFL dummy variable reference
        CFL_dummy_ref = M.getNamedGlobal("CFL_DUMMY_ADDR");
        assert(CFL_dummy_ref);

        std::vector<Regex*> FunctionRegexes;
        std::vector<Regex*> CFLFunctionRegexes;
        if (Functions.empty())
            Functions.push_back("main");
        passListRegexInit(FunctionRegexes, Functions);

        // Init also all the regexes which identify the functions that will be CFLed
        if (CFLFunctions.empty())
            CFLFunctions.push_back("-----------------");
        passListRegexInit(CFLFunctionRegexes, CFLFunctions);

        /* Iterate all functions in the module to dfl */
        std::set<Function*> dflFunctionSet;
        std::set<const Function*>cflFunctionSet;
        for (auto &F : M.getFunctionList()) {
            if (F.isDeclaration())
                continue;
            // We have to collect all the possible dealloc calls to wrap them
            gatherDeallocCalls(&F);
            const std::string &FName = F.getName();
            if (!passListRegexMatch(FunctionRegexes, FName) && !passListRegexMatch(CFLFunctionRegexes, FName))
                continue;
            if (F.getSection().equals("dfl_code") || F.getSection().equals("cfl_code") 
                || F.getSection().equals("cgc_code") || F.getSection().equals("icp_code"))
                continue;
            // Add the functions to DFL
            if (passListRegexMatch(FunctionRegexes, FName))
                dflFunctionSet.insert(&F);

            // keep track of which function will be also CFLed
            if (passListRegexMatch(CFLFunctionRegexes, FName))
                cflFunctionSet.insert(&F);
        }
        while (!dflFunctionSet.empty()) {
            Function *F = *dflFunctionSet.begin();
            dflFunctionSet.erase(dflFunctionSet.begin());
            // prepare the metadata for DFL taking into account if the function will be CFLed
            dfl_prepare(F, pta, DL, passListRegexMatch(CFLFunctionRegexes, F->getName()));
        }
        oprint("[+] Done with DFL preparation");
        dfl(&M, DL, cflFunctionSet);

        // if debug change all global var alignment to at least DFL_STRIDE
        if (DFL_DEBUG) {
            for (GlobalVariable& glob : M.getGlobalList()) {
                glob.setAlignment(max((unsigned int)DFL_STRIDE, glob.getAlignment()));
            }
        }

        oprint("--------[ DFL STATS ]--------");
        oprint("[+] Total Accesses:     " << totalAccesses    );
        oprint("    [+] Tainted Accesses: " << taintedAccesses );
        oprint("    [+] CFLed Accesses:   " << numCFLedAccesses);
        oprint("[+] Total Obj Accessed: " << totObjAccesses);
        oprint("[+] Protected Reads:  " << protectedReads);
        oprint("[+] Protected Writes: " << protectedWrites);
        oprint("[+] Protected Accesses: " << protectedAccesses);
        oprint("    [+] AVX:    " << protectedAVX     );
        oprint("    [+] Single: " << protectedSingle  );
        oprint("    [+] Linear: " << protectedLinear  );
        oprint("[+] Original Bytes Accessed:  " << bytesAccessed    );
        oprint("[+] Protected Bytes Accessed: " << bytesProtected   );
        oprint("[+] Num uglyGEPs: " << nUglyGEPS        );

        oprint("\n--------[ DFL MORE STATS ]--------");
        oprint("[+] Unsupported Single Accesses: " << unsupportedSingle );
        oprint("[+] Replaced memset:  " << nmemset);
        oprint("[+] Replaced memcpy:  " << nmemcpy);
        oprint("");
        return true;
    }

    void getAnalysisUsage(AnalysisUsage &AU) const {
        AU.addRequired<DominatorTreeWrapperPass>();
        AU.addRequired<PostDominatorTreeWrapperPass>();
    }

  };

}

char DFLPass::ID = 0;
RegisterPass<DFLPass> MP("dfl", "DFL Pass");
