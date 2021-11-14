#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <stdbool.h>
#include <inttypes.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <immintrin.h>

#include <dfl.h>
// I know it is ugly... will reference cfl.h from the dfl.h directory
#include <../cfl/cfl.h>
extern volatile bool taken;

// DFL debug level:
// 1: print objects and debug checks
// 2: print all accesses

// We have three types of access helpers:
// 1) plain     : just accesses an element of the right size every DFL_STRIDE bytes
// 2) avx gather: use gathering instructions to access multiple elements with a single load
// 3) avx loads : use a vector load to access a whole cache line 
//                (best if DFL_STRIDE should be like every 4 bytes, we touch all)
// 2 and 3 are both AVX2 and AVX512
// TODO: fixme - 2 and 3 may access the objects OOB of a lot, however masked access
//               will prevent it segfaulting
//      -> known issue: multiple byte loads on page boundary may crash if mask=1

#define DFL_DEBUG 0
#define DPRINT(f_, ...) fprintf(stderr, (f_), __VA_ARGS__)


#if DFL_DEBUG == 2
#define DEBUG(f_, ...) fprintf(stderr, (f_), __VA_ARGS__)
#define DEBUG_ASSERT(a) assert(a)
#define DEBUG_STMT(s) s
#elif DFL_DEBUG == 1
#define DEBUG(f_, ...) 
#define DEBUG_ASSERT(a)
#define DEBUG_STMT(s) s
#else
#define DEBUG(f_, ...) 
#define DEBUG_ASSERT(a)
#define DEBUG_STMT(s)
#endif

#ifdef __SIZEOF_INT128__
    typedef __uint128_t uint128_t;
    typedef __int128_t int128_t;
#else
    typedef unsigned long uint128_t __attribute__ ((mode(TI)));
    typedef long int128_t __attribute__ ((mode(TI)));
#endif

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	_Static_assert(!__builtin_types_compatible_p(typeof(*(ptr)), typeof(((type *)0)->member)) &&	\
			 !__builtin_types_compatible_p(typeof(*(ptr)), void),			\
			 "pointer type mismatch in container_of()");	\
	((type *)(__mptr - offsetof(type, member))); })

typedef struct dfl_obj_list {
    struct dfl_obj_list* next;
    struct dfl_obj_list* prev;
    struct dfl_obj_list** head_ptr;
    unsigned long size;
    unsigned long padding;
    unsigned long magic;
    unsigned char data[];
} dfl_obj_list_t;

typedef dfl_obj_list_t* dfl_obj_list_head;

// Should be power of two
#define DFL_STRIDE (64uL)

// `head -c 8 /dev/urandom | xxd -p`
#define DFL_MAGIC  (0x3aa6bd228ae62271uL)

DFL_FUNC DFL_CONSTRUCTOR __attribute__((used)) __attribute__((noinline)) void dfl_init()
{
    asm volatile ("");
    return;
}

#if DFL_DEBUG >= 1
DFL_FUNC __attribute__((used)) __attribute__((noinline)) void dfl_debug_is_enabled(void) {
}

bool __dfl_matched = false;
// check that either we are not in a taken branch or that the DFL helpers matched
// at least a pointer read/write
DFL_FUNC __attribute__((used)) __attribute__((noinline)) void dfl_debug_check_matched(void) {
    if (taken) assert(__dfl_matched);
    else       assert(!__dfl_matched);
    __dfl_matched = false;
}

#endif

DFL_FUNC_INLINE void dfl_obj_print(dfl_obj_list_t* new_obj, unsigned long size) {
#if DFL_DEBUG >= 1
    // objs are DFL_STRIDE aligned
    unsigned char* ptr = (unsigned char*)(((unsigned long)new_obj->data) & ~(DFL_STRIDE - 1));
    // take into account the size increase due to alignment
    unsigned long orig_size = size;
    size += (new_obj->data - ptr);
    size = ((size + DFL_STRIDE - 1) / DFL_STRIDE) * DFL_STRIDE; // ((n + 9) / 10) * 10
    fprintf(stderr, "DFL OBJ - aligned ptr: %p - obj: %p - size: %lu - orig_size: %lu\n", ptr, new_obj->data, size, orig_size);
#endif
}

DFL_FUNC_INLINE void dfl_glob_obj_print(unsigned char* obj, unsigned long size) {
#if DFL_DEBUG >= 1
    // objs are DFL_STRIDE aligned
    unsigned char* ptr = (unsigned char*)(((unsigned long)obj) & ~(DFL_STRIDE - 1));
    // take into account the size increase due to alignment
    unsigned long orig_size = size;
    size += (obj - ptr);
    size = ((size + DFL_STRIDE - 1) / DFL_STRIDE) * DFL_STRIDE; // ((n + 9) / 10) * 10
    fprintf(stderr, "DFL OBJ - aligned ptr: %p - obj: %p - size: %lu - orig_size: %lu\n", ptr, obj, size, orig_size);
#endif
}

DFL_FUNC __attribute__((used)) __attribute__((noinline)) void dfl_id_print(unsigned long bgid, unsigned long ibid) {
    DEBUG("(%lu, %lu) ", bgid, ibid);
}

DFL_FUNC_INLINE void dfl_obj_list_add(dfl_obj_list_head* head, dfl_obj_list_t* new_obj, unsigned long size) {
    DEBUG("OBJ ADD - head: %p - obj: %p - size: %lu -", head, new_obj, size);

    // objs are DFL_STRIDE aligned
    unsigned char* ptr = (unsigned char*)(((unsigned long)new_obj->data) & ~(DFL_STRIDE - 1));
    // take into account the size increase due to alignment
    size += (new_obj->data - ptr);
    new_obj->size = ((size + DFL_STRIDE - 1) / DFL_STRIDE) * DFL_STRIDE; // ((n + 9) / 10) * 10
    DEBUG(" new size: %lu\n", new_obj->size);

    // Fill obj ptrs
    new_obj->next = *head;
    new_obj->prev = NULL;
    new_obj->head_ptr = head;

    // Set the magic of the object struct
    new_obj->magic = DFL_MAGIC;

    // Set the prev of the head if node present
    if ( (*head) != NULL )
        (*head)->prev = new_obj;

    // Insert object at the head
    *head = new_obj;

    return;
}

DFL_FUNC_INLINE unsigned char* dfl_obj_list_unlink(unsigned char* ptr) {
    DEBUG("OBJ UNLINK - obj: %p -", ptr);
    dfl_obj_list_t* obj = container_of(ptr, dfl_obj_list_t, data);

    // If the magic does not match, this is not a DFL object
    // N.B. this may crash if we get a page aligned address
    // as magic field is before the data field and may result 
    // in an unallocated region, but for ptmalloc should never be the case
    if (obj->magic != DFL_MAGIC)
        return ptr;
    DEBUG(" next: %p - prev: %p -", obj->next, obj->prev);
    
    // Get the head of the linked list
    dfl_obj_list_head* head = obj->head_ptr;
    DEBUG(" head: %p\n", head);

    // if obj is first node of list
    if(obj->prev == NULL)
        *head = obj->next; //the next node will be front of list
    else
        obj->prev->next = obj->next; // otherwise unlink from prev

    // if next is not null change its prev
    if (obj->next != NULL)
        obj->next->prev = obj->prev;

    return (unsigned char*) obj;
}

#define DFL_OBJ_LOAD(type) DFL_FUNC_INLINE type type ## _dfl_obj_load(dfl_obj_list_head head, unsigned char* ptr, unsigned long field_off, unsigned long field_size) {  \
    DEBUG("OBJ LOAD - ptr: %p - sizeof: %lu\n", ptr, sizeof(type)); \
    register type res = 0; \
    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL); \
    DEBUG_STMT(int found = 0); \
    while (head) \
    { \
        unsigned char* aligned_ptr = (unsigned char*)(((unsigned long)head->data + field_off) & ~(DFL_STRIDE - 1)); \
        field_size += (((unsigned long)head->data + field_off) - (unsigned long)aligned_ptr); \
        field_size = ((field_size + DFL_STRIDE - 1) / DFL_STRIDE) * DFL_STRIDE; \
        unsigned char* _end =  aligned_ptr + field_size; \
        DEBUG("  obj: %p - field_off: %lu - size: %lu ", head->data, field_off, field_size); \
        for(volatile unsigned char* _ptr = aligned_ptr + cache_off; _ptr < _end; _ptr = _ptr + DFL_STRIDE) { \
            DEBUG("%s", "."); \
            type _res = *(volatile type*)_ptr; \
            res = (_ptr == ptr)? _res : res; \
            DEBUG_STMT(if(!found) found = (_ptr == ptr && taken)); \
        } \
        head = head->next; \
        DEBUG("%s", "\n"); \
    } \
    DEBUG("  returned: %lx - %s\n", (unsigned long) res, found != 0? "MATCH": "NO MATCH"); \
    DEBUG_STMT(if (found) assert(!__dfl_matched)); /*assert no multiple matches*/ \
    DEBUG_STMT(__dfl_matched |= found); \
    return res; \
}

#define DFL_SINGLE_OBJ_LOAD(type) DFL_FUNC_INLINE type type ## _dfl_single_obj_load(dfl_obj_list_head head, unsigned char* ptr, unsigned int field_off, unsigned int field_size, unsigned int index) { \
    DEBUG("SINGLE LOAD: %p - head: %p - sizeof: %lu - off: %u - size: %u ", ptr, head, sizeof(type), field_off, field_size); \
    register type res = 0; \
    DEBUG_STMT(int found = 0); \
    while (head) \
    { \
        unsigned char* start = head->data + field_off; \
        unsigned long _ptr = (unsigned long)&((volatile type*)start)[(index % (field_size/sizeof(type)))]; \
        type _res = *(volatile type*)_ptr; \
        res = (taken && _ptr == (unsigned long)ptr)? _res : res; \
        DEBUG_STMT(if(!found) found = (_ptr == (unsigned long)ptr  && taken)); \
        head = head->next; \
    } \
    DEBUG("%s", "\n"); \
    DEBUG("  returned: %lx - %s\n", (unsigned long) res, found != 0? "MATCH": "NO MATCH"); \
    DEBUG_STMT(if (found) assert(!__dfl_matched)); /*assert no multiple matches*/ \
    DEBUG_STMT(__dfl_matched |= found); \
    return res; \
}

#define DFL_SINGLE_GLOB_LOAD(type) DFL_FUNC_INLINE type type ## _dfl_single_glob_load(unsigned char* obj, unsigned char* ptr, unsigned int field_off, unsigned int field_size, unsigned int index) { \
    DEBUG("SINGLE LOAD: %p - obj: %p - sizeof: %lu - off: %u - size: %u ", ptr, obj, sizeof(type), field_off, field_size); \
    unsigned char* start = obj + field_off; \
    unsigned long _ptr = (unsigned long)&((volatile type*)start)[(index % (field_size/sizeof(type)))]; \
    const type _res = *(volatile type*)_ptr; \
    const type res = (taken && _ptr == (unsigned long)ptr)? _res : 0; \
    DEBUG("%s", "\n"); \
    DEBUG("  returned: %lx - %s\n", (unsigned long) res, (_ptr == (unsigned long)ptr && taken)? "MATCH": "NO MATCH"); \
    DEBUG_STMT(if (_ptr == (unsigned long)ptr && taken) assert(!__dfl_matched)); /*assert no multiple matches*/ \
    DEBUG_STMT(__dfl_matched |= (_ptr == (unsigned long)ptr && taken)); \
    return res; \
}

#define DFL_GLOB_LOAD(type) DFL_FUNC_INLINE type type ## _dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size) {  \
    register type res = 0; \
    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL); \
    unsigned char* aligned_obj = (unsigned char*)(((unsigned long)obj + field_off) & ~(DFL_STRIDE - 1)); \
    field_size += (((unsigned long)obj + field_off) - (unsigned long)aligned_obj); \
    field_size = ((field_size + DFL_STRIDE - 1) / DFL_STRIDE) * DFL_STRIDE; \
    unsigned char* _end =  aligned_obj + field_size; \
    DEBUG("GLOB LOAD: %p - size: %lu - ptr: %p - sizeof: %lu ", obj, field_size, ptr, sizeof(type)); \
    DEBUG_STMT(int found = 0); \
    for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + DFL_STRIDE) { \
        DEBUG("%s", "."); \
        type _res = *(volatile type*)_ptr; \
        res = (_ptr == ptr)? _res : res; \
        DEBUG_STMT(if(!found) found = (_ptr == ptr && taken)); \
    } \
    DEBUG("%s", "\n"); \
    DEBUG("  returned: %lx - %s\n", (unsigned long) res, found != 0? "MATCH": "NO MATCH"); \
    DEBUG_STMT(if (found) assert(!__dfl_matched)); /*assert no multiple matches*/ \
    DEBUG_STMT(__dfl_matched |= found); \
    return res; \
}

#define DFL_OBJ_STORE(type) DFL_FUNC_INLINE void type ## _dfl_obj_store(dfl_obj_list_head head, unsigned char* ptr, unsigned long field_off, unsigned long field_size, type value) {  \
    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL); \
    DEBUG("OBJ STORE - ptr: %p - val: %lx - sizeof: %lu\n", ptr, (unsigned long) value, sizeof(type)); \
    DEBUG_STMT(int found = 0); \
    while (head) \
    { \
        unsigned char* aligned_ptr = (unsigned char*)(((unsigned long)head->data + field_off) & ~(DFL_STRIDE - 1)); \
        field_size += (((unsigned long)head->data + field_off) - (unsigned long)aligned_ptr); \
        field_size = ((field_size + DFL_STRIDE - 1) / DFL_STRIDE) * DFL_STRIDE; \
        unsigned char* _end =  aligned_ptr + field_size; \
        DEBUG("  obj: %p - field_off: %lu - size: %lu ", head->data, field_off, field_size); \
        for(volatile unsigned char* _ptr = aligned_ptr + cache_off; _ptr < _end; _ptr = _ptr + DFL_STRIDE) { \
            DEBUG("%s", "."); \
            type _prev_val = *(volatile type*)_ptr; \
            *(volatile type*)_ptr = (_ptr == ptr)? value : _prev_val; \
            DEBUG_STMT(if(!found) found = (_ptr == ptr && taken)); \
        } \
        DEBUG("%s", "\n"); \
        DEBUG("%s\n", found != 0? "MATCH": "NO MATCH"); \
        head = head->next; \
    } \
    DEBUG_STMT(if (found) assert(!__dfl_matched)); /*assert no multiple matches*/ \
    DEBUG_STMT(__dfl_matched |= found); \
}

#define DFL_GLOB_STORE(type) DFL_FUNC_INLINE void type ## _dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, type value) {  \
    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL); \
    unsigned char* aligned_obj = (unsigned char*)(((unsigned long)obj + field_off) & ~(DFL_STRIDE - 1)); \
    field_size += (((unsigned long)obj + field_off) - (unsigned long)aligned_obj); \
    field_size = ((field_size + DFL_STRIDE - 1) / DFL_STRIDE) * DFL_STRIDE; \
    unsigned char* _end =  aligned_obj + field_size; \
    DEBUG("GLOB STORE: %p - size: %lu - ptr: %p - val: %lx - sizeof: %lu ", obj, field_size, ptr, (unsigned long) value, sizeof(type)); \
    DEBUG_STMT(int found = 0); \
    for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + DFL_STRIDE) { \
        DEBUG("%s", "."); \
        type _prev_val = *(volatile type*)_ptr; \
        *(volatile type*)_ptr = (_ptr == ptr)? value : _prev_val; \
        DEBUG_STMT(if(!found) found = (_ptr == ptr && taken)); \
    } \
    DEBUG("%s", "\n"); \
    DEBUG("%s\n", found != 0? "MATCH": "NO MATCH"); \
    DEBUG_STMT(if (found) assert(!__dfl_matched)); /*assert no multiple matches*/ \
    DEBUG_STMT(__dfl_matched |= found); \
}

// The following two are the only handlers in DFL that actually check the `taken`
// variable value. This violates the common DFL_API which only takes a target pointer
// and the objects to stride, but allows to optimize accesses based on loop induction
// variables to touch memory and not writing it. Moreover it does not slow down accesses
// on single variables since it just moves the `taken` check from the cfl_wrap_ptr function
// (which will not be called) to this function.
#define DFL_SINGLE_OBJ_STORE(type) DFL_FUNC_INLINE void type ## _dfl_single_obj_store(dfl_obj_list_head head, unsigned char* ptr, unsigned int field_off, unsigned int field_size, type value, unsigned int index) { \
    DEBUG("SINGLE STORE: %p - head: %p - sizeof: %lu - off: %u - size: %u - value: %lu ", ptr, head, sizeof(type), field_off, field_size, (unsigned long) value); \
    DEBUG_STMT(int found = 0); \
    while (head) \
    { \
        unsigned char* start = head->data + field_off; \
        unsigned long _ptr = (unsigned long)&((volatile type*)start)[(index % (field_size/sizeof(type)))]; \
        const type _prev_val = *(volatile type*)_ptr; \
        *(volatile type*)_ptr = (taken && _ptr == (unsigned long)ptr)? value : _prev_val; \
        DEBUG_STMT(if(!found) found = (_ptr == (unsigned long)ptr && taken)); \
        head = head->next; \
    } \
    DEBUG("%s", "\n"); \
    DEBUG("%s\n", found? "MATCH": "NO MATCH"); \
    DEBUG_STMT(if (found) assert(!__dfl_matched)); /*assert no multiple matches*/ \
    DEBUG_STMT(__dfl_matched |= found); \
}

#define DFL_SINGLE_GLOB_STORE(type) DFL_FUNC_INLINE void type ## _dfl_single_glob_store(unsigned char* obj, unsigned char* ptr, unsigned int field_off, unsigned int field_size, type value, unsigned int index) { \
    DEBUG("SINGLE STORE: %p - obj: %p - sizeof: %lu - off: %u - size: %u - value: %lu ", ptr, obj, sizeof(type), field_off, field_size, (unsigned long) value); \
    unsigned char* start = obj + field_off; \
    unsigned long _ptr = (unsigned long)&((volatile type*)start)[(index % (field_size/sizeof(type)))]; \
    const type _prev_val = *(volatile type*)_ptr; \
    *(volatile type*)_ptr = (taken && _ptr == (unsigned long)ptr)? value : _prev_val; \
    DEBUG("%s", "\n"); \
    DEBUG("%s\n", (_ptr == (unsigned long)ptr && taken)? "MATCH": "NO MATCH"); \
    DEBUG_STMT(if (_ptr == (unsigned long)ptr && taken) assert(!__dfl_matched)); /*assert no multiple matches*/ \
    DEBUG_STMT(__dfl_matched |= (_ptr == (unsigned long)ptr && taken)); \
}

#if defined(__AVX2__)
// ------------------------- AVX2 FUNCTIONS -------------------------

// horizontally sum all 64bit values to obtain a 64 bit value
DFL_FUNC_INLINE uint64_t mm256_hadd_to_64(__m256i v) {
    __m128i vlow    = _mm256_castsi256_si128(v);
    __m128i vhigh   = _mm256_extracti128_si256(v, 1);
            vlow    = _mm_add_epi64(vlow, vhigh);
    __m128i vhigh64 = _mm_unpackhi_epi64(vlow, vlow);
    return _mm_cvtsi128_si64(_mm_add_epi64(vlow, vhigh64));
}

DFL_FUNC_INLINE uint32_t hsum_epi32_avx(__m128i x)
{
    __m128i hi64  = _mm_unpackhi_epi64(x, x); // 3-operand non-destructive AVX lets us save a byte without needing a movdqa
    __m128i sum64 = _mm_add_epi32(hi64, x);
    __m128i hi32  = _mm_shuffle_epi32(sum64, _MM_SHUFFLE(2, 3, 0, 1)); // Swap the low two elements
    __m128i sum32 = _mm_add_epi32(sum64, hi32);
    return _mm_cvtsi128_si32(sum32);       // movd
}

// horizontally sum all 32bit values to obtain a 32 bit value
DFL_FUNC_INLINE uint32_t mm256_hadd_to_32(__m256i v)
{
    __m128i sum128 = _mm_add_epi32( 
                 _mm256_castsi256_si128(v),
                 _mm256_extracti128_si256(v, 1));
    return hsum_epi32_avx(sum128);
}

DFL_FUNC uint64_t uint64_t_avx2_gather_dfl_obj_load(dfl_obj_list_head head, unsigned char* ptr, unsigned long field_off, unsigned long field_size) { 
    // set the index vector to 0,1,2,3 "little" endian
    // so that 0 is in index[0:31], ecc
    __m256i index = _mm256_setr_epi64x(0*DFL_STRIDE, 1*DFL_STRIDE, 2*DFL_STRIDE, 3*DFL_STRIDE);
    __m256i res   = _mm256_setzero_si256();

    __m256i target    = _mm256_set1_epi64x((unsigned long) ptr);
    __m256i increment = _mm256_set1_epi64x(4*DFL_STRIDE);

    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL);

    while(head) {
        unsigned char* aligned_obj = (unsigned char*)(((unsigned long)head->data + field_off) & ~(DFL_STRIDE - 1));
        field_size += (((unsigned long)head->data + field_off) - (unsigned long)aligned_obj);
        field_size = ((field_size + 4*DFL_STRIDE - 1) / (4*DFL_STRIDE)) * 4*DFL_STRIDE;
        unsigned char* _end =  aligned_obj + field_size;

        // initialize the current avx ptrs for each iteration
        __m256i current = _mm256_set1_epi64x((unsigned long) aligned_obj + cache_off);
        current  = _mm256_add_epi64(current, index);

        for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + 4*DFL_STRIDE) {
            // the mask will select which value will get actually loaded
            __m256i mask = _mm256_cmpeq_epi64(target, current);
            current = _mm256_add_epi64(current, increment);
            __m256i loaded = _mm256_i64gather_epi64(_ptr, index, 1);
            res = _mm256_blendv_epi8(res, loaded, mask);
        }
        head = head->next;
    }
    return mm256_hadd_to_64(res);
}

DFL_FUNC uint64_t uint64_t_avx2_gather_dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size) { 
    // set the index vector to 0,1,2,3 "little" endian
    // so that 0 is in index[0:31], ecc
    __m256i index = _mm256_setr_epi64x(0*DFL_STRIDE, 1*DFL_STRIDE, 2*DFL_STRIDE, 3*DFL_STRIDE);
    __m256i res   = _mm256_setzero_si256();

    __m256i target    = _mm256_set1_epi64x((unsigned long) ptr);
    __m256i increment = _mm256_set1_epi64x(4*DFL_STRIDE);

    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL);

    unsigned char* aligned_obj = (unsigned char*)(((unsigned long)obj + field_off) & ~(DFL_STRIDE - 1));

    field_size += (((unsigned long)obj + field_off) - (unsigned long)aligned_obj);
    field_size = ((field_size + 4*DFL_STRIDE - 1) / (4*DFL_STRIDE)) * 4*DFL_STRIDE;
    unsigned char* _end =  aligned_obj + field_size;

    DEBUG("GLOB AVX2 LOAD: %p - size: %lu - ptr: %p - sizeof: %lu\n", obj, field_size, ptr, sizeof(unsigned long));

    // initialize the current avx ptrs for each iteration
    __m256i current = _mm256_set1_epi64x((unsigned long) aligned_obj + cache_off);
    current  = _mm256_add_epi64(current, index);

    for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + 4*DFL_STRIDE) {
        // the mask will select which value will get actually loaded
        __m256i mask = _mm256_cmpeq_epi64(target, current);
        current = _mm256_add_epi64(current, increment);
        __m256i loaded = _mm256_i64gather_epi64(_ptr, index, 1);
        res = _mm256_blendv_epi8(res, loaded, mask);
    }
    return mm256_hadd_to_64(res);
}

DFL_FUNC uint32_t uint32_t_avx2_gather_dfl_obj_load(dfl_obj_list_head head, unsigned char* ptr, unsigned long field_off, unsigned long field_size) { 
    uint32_t partial_res = 0;

    // if the ptr is 64 bit wide we must use the slow version since it does not fit 8 times in the vectors
    if (((unsigned long) ptr != (unsigned int) ptr))
        return (uint32_t) uint64_t_avx2_gather_dfl_obj_load(head, ptr, field_off, field_size);
        
    // set the index vector to 0,1,2,3 "little" endian
    // so that 0 is in index[0:31], ecc
    __m256i index = _mm256_setr_epi32(0*DFL_STRIDE, 1*DFL_STRIDE, 2*DFL_STRIDE, 3*DFL_STRIDE,
                                       4*DFL_STRIDE, 5*DFL_STRIDE, 6*DFL_STRIDE, 7*DFL_STRIDE);
    __m256i res   = _mm256_setzero_si256();

    __m256i target    = _mm256_set1_epi32((unsigned long) ptr);
    __m256i increment = _mm256_set1_epi32(8*DFL_STRIDE);

    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL);

    while(head) {
        unsigned char* aligned_obj = (unsigned char*)(((unsigned long)head->data + field_off) & ~(DFL_STRIDE - 1));
        field_size += (((unsigned long)head->data + field_off) - (unsigned long)aligned_obj);
        field_size = ((field_size + 8*DFL_STRIDE - 1) / (8*DFL_STRIDE)) * 8*DFL_STRIDE;
        unsigned char* _end =  aligned_obj + field_size;

        // 64-bit size check as at the beginning on obj;
        if (((unsigned long) aligned_obj != (unsigned int) aligned_obj)) {
            partial_res |= uint64_t_avx2_gather_dfl_glob_load(aligned_obj, ptr, field_off, field_size);
            head = head->next;
            continue;
        }

        // initialize the current avx ptrs for each iteration
        __m256i current = _mm256_set1_epi32((unsigned long) aligned_obj + cache_off);
        current  = _mm256_add_epi32(current, index);

        for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + 8*DFL_STRIDE) {
            // the mask will select which value will get actually loaded
            __m256i mask = _mm256_cmpeq_epi32(target, current);
            current = _mm256_add_epi32(current, increment);
            __m256i loaded = _mm256_i32gather_epi32(_ptr, index, 1);
            res = _mm256_blendv_epi8(res, loaded, mask);
        }
        head = head->next;
    }
    return partial_res | mm256_hadd_to_32(res);
}

DFL_FUNC uint32_t uint32_t_avx2_gather_dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size) { 

    // if the ptr is 64 bit wide we must use the slow version since it does not fit 8 times in the vectors
    if (((unsigned long) ptr != (unsigned int) ptr) || ((unsigned long) obj != (unsigned int) obj))
        return (uint32_t) uint64_t_avx2_gather_dfl_glob_load(obj, ptr, field_off, field_size);
        
    // set the index vector to 0,1,2,3 "little" endian
    // so that 0 is in index[0:31], ecc
    __m256i index = _mm256_setr_epi32(0*DFL_STRIDE, 1*DFL_STRIDE, 2*DFL_STRIDE, 3*DFL_STRIDE,
                                       4*DFL_STRIDE, 5*DFL_STRIDE, 6*DFL_STRIDE, 7*DFL_STRIDE);
    __m256i res   = _mm256_setzero_si256();

    __m256i target    = _mm256_set1_epi32((unsigned long) ptr);
    __m256i increment = _mm256_set1_epi32(8*DFL_STRIDE);

    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL);

    unsigned char* aligned_obj = (unsigned char*)(((unsigned long)obj + field_off) & ~(DFL_STRIDE - 1));

    field_size += (((unsigned long)obj + field_off) - (unsigned long)aligned_obj);
    field_size = ((field_size + 8*DFL_STRIDE - 1) / (8*DFL_STRIDE)) * 8*DFL_STRIDE;
    unsigned char* _end =  aligned_obj + field_size;

    // initialize the current avx ptrs for each iteration
    __m256i current = _mm256_set1_epi32((unsigned long) aligned_obj + cache_off);
    current  = _mm256_add_epi32(current, index);

    for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + 8*DFL_STRIDE) {
        // the mask will select which value will get actually loaded
        __m256i mask = _mm256_cmpeq_epi32(target, current);
        current = _mm256_add_epi32(current, increment);
        __m256i loaded = _mm256_i32gather_epi32(_ptr, index, 1);
        res = _mm256_blendv_epi8(res, loaded, mask);
    }
    return mm256_hadd_to_32(res);
}

#define AVX2_LINESIZE 32
#define AVX_INCREMENT (8uL)
#if DFL_STRIDE > AVX2_LINESIZE
 #define DFL_FIXED_AVX_STRIDE DFL_STRIDE
#else
 #define DFL_FIXED_AVX_STRIDE AVX2_LINESIZE
#endif
DFL_FUNC uint64_t uint64_t_avx2_linear_dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size) { 
    // set the index vector to 0,8,16,24 "little" endian
    // so that 0 is in index[0:31], ecc
    __m256i index = _mm256_setr_epi64x(AVX_INCREMENT*0, AVX_INCREMENT*1, AVX_INCREMENT*2, AVX_INCREMENT*3);
    __m256i res   = _mm256_setzero_si256();

#if DFL_STRIDE < AVX_INCREMENT
    // if DFL_STRIDE is lower than the index granularity, we should align the target properly.
    // this masks the relevant bits for AVX_INCREMENT, but not the ones that will be reintroduced while adding `cache_off`
    __m256i target    = _mm256_set1_epi64x(((unsigned long) ptr & ~(AVX_INCREMENT-DFL_STRIDE)));
#else
    __m256i target    = _mm256_set1_epi64x(((unsigned long) ptr));
#endif
    __m256i increment = _mm256_set1_epi64x(DFL_FIXED_AVX_STRIDE);

    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL);

    unsigned char* aligned_obj = (unsigned char*)(((unsigned long)obj + field_off) & ~(DFL_STRIDE - 1));

    field_size += (((unsigned long)obj + field_off) - (unsigned long)aligned_obj);
    field_size = ((field_size + DFL_FIXED_AVX_STRIDE - 1) / (DFL_FIXED_AVX_STRIDE)) * DFL_FIXED_AVX_STRIDE;
    unsigned char* _end =  aligned_obj + field_size;

    // initialize the current avx ptrs for each iteration
    __m256i current = _mm256_set1_epi64x((unsigned long) aligned_obj + cache_off);
    current  = _mm256_add_epi64(current, index);

    for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + DFL_FIXED_AVX_STRIDE) {
        // the mask will select which value will get actually loaded
        __m256i mask = _mm256_cmpeq_epi64(target, current);
        current = _mm256_add_epi64(current, increment);
        res = _mm256_blendv_epi8(res, _mm256_loadu_si256((__m256i *)_ptr), mask);
    }
    // if the target was aligned, shift the result to get the right value
    // NOTICE: this assumes that accesses to `TYPE` are aligned to `sizeof(TYPE)`
#if DFL_STRIDE < AVX_INCREMENT
    return mm256_hadd_to_64(res) >> (8*(((unsigned long) ptr) & (AVX_INCREMENT-DFL_STRIDE)));
#else
    return mm256_hadd_to_64(res);
#endif
}

DFL_FUNC void uint64_t_avx2_linear_dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, uint64_t value) { 
    // set the index vector to 0,8,16,24 "little" endian
    // so that 0 is in index[0:31], ecc
    __m256i index = _mm256_setr_epi64x(AVX_INCREMENT*0, AVX_INCREMENT*1, AVX_INCREMENT*2, AVX_INCREMENT*3);

    __m256i target    = _mm256_set1_epi64x((unsigned long) ptr);
    __m256i increment = _mm256_set1_epi64x(DFL_FIXED_AVX_STRIDE);
    __m256i writev = _mm256_setr_epi64x(value, value, value, value);

    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL);

    unsigned char* aligned_obj = (unsigned char*)(((unsigned long)obj + field_off) & ~(DFL_STRIDE - 1));

    field_size += (((unsigned long)obj + field_off) - (unsigned long)aligned_obj);
    field_size = ((field_size + DFL_FIXED_AVX_STRIDE - 1) / (DFL_FIXED_AVX_STRIDE)) * DFL_FIXED_AVX_STRIDE;
    unsigned char* _end =  aligned_obj + field_size;

    // initialize the current avx ptrs for each iteration
    __m256i current = _mm256_set1_epi64x((unsigned long) aligned_obj + cache_off);
    current  = _mm256_add_epi64(current, index);

    for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + DFL_FIXED_AVX_STRIDE) {
        __m256i mask = _mm256_cmpeq_epi64(target, current);
        current = _mm256_add_epi64(current, increment);
        _mm256_storeu_si256((__m256i *)_ptr, _mm256_blendv_epi8(_mm256_loadu_si256((__m256i *)_ptr), writev, mask));
    }
}

#if DFL_STRIDE < AVX_INCREMENT
    // if DFL_STRIDE is lower than the index granularity, we should align the target properly.
    // this masks the relevant bits for AVX_INCREMENT, but not the ones that will be reintroduced while adding `cache_off`
    #define DFL_CORRECTION (AVX_INCREMENT-DFL_STRIDE)
#else
    #define DFL_CORRECTION (0uL)
#endif
#define DFL_AVX2_LINEAR_GLOB_STORE(type) DFL_FUNC void type ## _avx2_linear_dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, type value) { \
    __m256i index = _mm256_setr_epi64x(AVX_INCREMENT*0, AVX_INCREMENT*1, AVX_INCREMENT*2, AVX_INCREMENT*3); \
    __m256i target    = _mm256_set1_epi64x((unsigned long) ptr & ~DFL_CORRECTION); \
    __m256i increment = _mm256_set1_epi64x(DFL_FIXED_AVX_STRIDE); \
    uint64_t write_mask_ = ((1uL << (sizeof(value) * 8)) - 1uL) << (8*(((unsigned long) ptr) & (DFL_CORRECTION))); \
    __m256i write_mask   = _mm256_set1_epi64x(write_mask_); \
    uint64_t shifted_value = ((uint64_t)value) << (8*(((unsigned long) ptr) & (DFL_CORRECTION))); \
    __m256i writev = _mm256_setr_epi64x(shifted_value, shifted_value, shifted_value, shifted_value); \
    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL); \
    unsigned char* aligned_obj = (unsigned char*)(((unsigned long)obj + field_off) & ~(DFL_STRIDE - 1)); \
    field_size += (((unsigned long)obj + field_off) - (unsigned long)aligned_obj); \
    field_size = ((field_size + DFL_FIXED_AVX_STRIDE - 1) / (DFL_FIXED_AVX_STRIDE)) * DFL_FIXED_AVX_STRIDE; \
    unsigned char* _end =  aligned_obj + field_size; \
    __m256i current = _mm256_set1_epi64x((unsigned long) aligned_obj + cache_off); \
    current  = _mm256_add_epi64(current, index); \
    for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + DFL_FIXED_AVX_STRIDE) { \
        __m256i mask = _mm256_and_si256(_mm256_cmpeq_epi64(target, current), write_mask); \
        current = _mm256_add_epi64(current, increment); \
        _mm256_storeu_si256((__m256i *)_ptr, _mm256_blendv_epi8(_mm256_loadu_si256((__m256i *)_ptr), writev, mask)); \
    } \
}

DFL_FUNC uint64_t uint64_t_avx2_linear_dfl_obj_load(dfl_obj_list_head head, unsigned char* ptr, unsigned long field_off, unsigned long field_size) { 
    // set the index vector to 0,8,16,24 "little" endian
    // so that 0 is in index[0:31], ecc
    __m256i index = _mm256_setr_epi64x(AVX_INCREMENT*0, AVX_INCREMENT*1, AVX_INCREMENT*2, AVX_INCREMENT*3);
    __m256i res   = _mm256_setzero_si256();

#if DFL_STRIDE < AVX_INCREMENT
    // if DFL_STRIDE is lower than the index granularity, we should align the target properly.
    // this masks the relevant bits for AVX_INCREMENT, but not the ones that will be reintroduced while adding `cache_off`
    __m256i target    = _mm256_set1_epi64x(((unsigned long) ptr & ~(AVX_INCREMENT-DFL_STRIDE)));
#else
    __m256i target    = _mm256_set1_epi64x(((unsigned long) ptr));
#endif
    __m256i increment = _mm256_set1_epi64x(DFL_FIXED_AVX_STRIDE);

    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL);

    while(head) {
        unsigned char* aligned_obj = (unsigned char*)(((unsigned long)head->data + field_off) & ~(DFL_STRIDE - 1));

        field_size += (((unsigned long)head->data + field_off) - (unsigned long)aligned_obj);
        field_size = ((field_size + DFL_FIXED_AVX_STRIDE - 1) / (DFL_FIXED_AVX_STRIDE)) * DFL_FIXED_AVX_STRIDE;
        unsigned char* _end =  aligned_obj + field_size;

        // initialize the current avx ptrs for each iteration
        __m256i current = _mm256_set1_epi64x((unsigned long) aligned_obj + cache_off);
        current  = _mm256_add_epi64(current, index);

        for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + DFL_FIXED_AVX_STRIDE) {
            // the mask will select which value will get actually loaded
            __m256i mask = _mm256_cmpeq_epi64(target, current);
            current = _mm256_add_epi64(current, increment);
            res = _mm256_blendv_epi8(res, _mm256_loadu_si256((__m256i *)_ptr), mask);
        }
        head = head->next;
    }
    // if the target was aligned, shift the result to get the right value
    // NOTICE: this assumes that accesses to `TYPE` are aligned to `sizeof(TYPE)`
#if DFL_STRIDE < AVX_INCREMENT
    return mm256_hadd_to_64(res) >> (8*(((unsigned long) ptr) & (AVX_INCREMENT-DFL_STRIDE)));
#else
    return mm256_hadd_to_64(res);
#endif
}

#endif /* __AVX2__ */

#if defined(__AVX512F__)
DFL_FUNC uint64_t uint64_t_avx512_gather_dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size) { 
    // set the index vector to 0,1,2,3... "little" endian
    // so that 0 is in index[0:31], ecc
    __m512i index = _mm512_setr_epi64(0*DFL_STRIDE, 1*DFL_STRIDE, 2*DFL_STRIDE, 3*DFL_STRIDE,
                                      4*DFL_STRIDE, 5*DFL_STRIDE, 6*DFL_STRIDE, 7*DFL_STRIDE);
    __m512i res   = _mm512_setzero_si512();

    __m512i target    = _mm512_set1_epi64((unsigned long) ptr);
    __m512i increment = _mm512_set1_epi64(8*DFL_STRIDE);

    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL);

    unsigned char* aligned_obj = (unsigned char*)(((unsigned long)obj + field_off) & ~(DFL_STRIDE - 1));

    field_size += (((unsigned long)obj + field_off) - (unsigned long)aligned_obj);
    field_size = ((field_size + 8*DFL_STRIDE - 1) / (8*DFL_STRIDE)) * 8*DFL_STRIDE;
    unsigned char* _end =  aligned_obj + field_size;
    __m512i endv    = _mm512_set1_epi64((unsigned long) _end);

    // initialize the current avx ptrs for each iteration
    __m512i current = _mm512_set1_epi64((unsigned long) aligned_obj + cache_off);
    current  = _mm512_add_epi64(current, index);

    for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + 8*DFL_STRIDE) {
        // the mask will select which value will get actually loaded
        __mmask8 mask = _mm512_cmpeq_epi64_mask(target, current);
        /* we use an oob mask to avoid making accesses outside the object */
        __mmask8 oob_mask = _mm512_cmplt_epi64_mask(current, endv);
        current = _mm512_add_epi64(current, increment);
        __m512i loaded = _mm512_mask_i64gather_epi64(res, oob_mask, index, _ptr, 1);
        res = _mm512_mask_blend_epi64(mask, res, loaded);
    }
    return _mm512_reduce_add_epi64(res);
}

DFL_FUNC uint32_t uint32_t_avx512_gather_dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size) { 

    // if the ptr is 64 bit wide we must use the slow version since it does not fit 8 times in the vectors
    if (((unsigned long) ptr != (unsigned int) ptr) || ((unsigned long) obj != (unsigned int) obj))
        return (uint32_t) uint64_t_avx512_gather_dfl_glob_load(obj, ptr, field_off, field_size);
        
    // set the index vector to 0,1,2,3... "little" endian
    // so that 0 is in index[0:31], ecc
    __m512i index = _mm512_setr_epi32(0*DFL_STRIDE, 1*DFL_STRIDE, 2*DFL_STRIDE, 3*DFL_STRIDE,
                                       4*DFL_STRIDE, 5*DFL_STRIDE, 6*DFL_STRIDE, 7*DFL_STRIDE,
                                       8*DFL_STRIDE, 9*DFL_STRIDE, 10*DFL_STRIDE, 11*DFL_STRIDE,
                                       12*DFL_STRIDE, 13*DFL_STRIDE, 14*DFL_STRIDE, 15*DFL_STRIDE);
    __m512i res   = _mm512_setzero_si512();

    __m512i target    = _mm512_set1_epi32((unsigned long) ptr);
    __m512i increment = _mm512_set1_epi32(16*DFL_STRIDE);

    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL);

    unsigned char* aligned_obj = (unsigned char*)(((unsigned long)obj + field_off) & ~(DFL_STRIDE - 1));

    field_size += (((unsigned long)obj + field_off) - (unsigned long)aligned_obj);
    // Align the real end to DFL_STRIDE
    __m512i endv    = _mm512_set1_epi32((unsigned long) aligned_obj + (((field_size + DFL_STRIDE - 1) / (DFL_STRIDE)) * DFL_STRIDE));

    field_size = ((field_size + 16*DFL_STRIDE - 1) / (16*DFL_STRIDE)) * 16*DFL_STRIDE;
    unsigned char* _end =  aligned_obj + field_size;

    // initialize the current avx ptrs for each iteration
    __m512i current = _mm512_set1_epi32((unsigned long) aligned_obj + cache_off);
    current  = _mm512_add_epi32(current, index);

    for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + 16*DFL_STRIDE) {
        // the mask will select which value will get actually loaded
        __mmask16 mask = _mm512_cmpeq_epi32_mask(target, current);
        /* we use an oob mask to avoid making accesses outside the object */
        __mmask16 oob_mask = _mm512_cmplt_epi32_mask(current, endv);
        current = _mm512_add_epi32(current, increment);
        __m512i loaded = _mm512_mask_i32gather_epi32(res, oob_mask, index, _ptr, 1);
        res = _mm512_mask_blend_epi32(mask, res, loaded);
    }
    return _mm512_reduce_add_epi32(res);
}

DFL_FUNC uint64_t uint64_t_avx512_gather_dfl_obj_load(dfl_obj_list_head head, unsigned char* ptr, unsigned long field_off, unsigned long field_size) { 
    // set the index vector to 0,1,2,3... "little" endian
    // so that 0 is in index[0:31], ecc
    __m512i index = _mm512_setr_epi64(0*DFL_STRIDE, 1*DFL_STRIDE, 2*DFL_STRIDE, 3*DFL_STRIDE,
                                      4*DFL_STRIDE, 5*DFL_STRIDE, 6*DFL_STRIDE, 7*DFL_STRIDE);
    __m512i res   = _mm512_setzero_si512();

    __m512i target    = _mm512_set1_epi64((unsigned long) ptr);
    __m512i increment = _mm512_set1_epi64(8*DFL_STRIDE);

    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL);

    while(head) {
        unsigned char* aligned_obj = (unsigned char*)(((unsigned long)head->data + field_off) & ~(DFL_STRIDE - 1));

        field_size += (((unsigned long)head->data + field_off) - (unsigned long)aligned_obj);
        field_size = ((field_size + 8*DFL_STRIDE - 1) / (8*DFL_STRIDE)) * 8*DFL_STRIDE;
        unsigned char* _end =  aligned_obj + field_size;
        __m512i endv    = _mm512_set1_epi64((unsigned long) _end);

        // initialize the current avx ptrs for each iteration
        __m512i current = _mm512_set1_epi64((unsigned long) aligned_obj + cache_off);
        current  = _mm512_add_epi64(current, index);

        for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + 8*DFL_STRIDE) {
            // the mask will select which value will get actually loaded
            __mmask8 mask = _mm512_cmpeq_epi64_mask(target, current);
            /* we use an oob mask to avoid making accesses outside the object */
            __mmask8 oob_mask = _mm512_cmplt_epi64_mask(current, endv);
            current = _mm512_add_epi64(current, increment);
            __m512i loaded = _mm512_mask_i64gather_epi64(res, oob_mask, index, _ptr, 1);
            res = _mm512_mask_blend_epi64(mask, res, loaded);
        }
        head = head->next;
    }
    return _mm512_reduce_add_epi64(res);
}

DFL_FUNC uint32_t uint32_t_avx512_gather_dfl_obj_load(dfl_obj_list_head head, unsigned char* ptr, unsigned long field_off, unsigned long field_size) { 
    uint32_t partial_res = 0;

    // if the ptr is 64 bit wide we must use the slow version since it does not fit 8 times in the vectors
    if (((unsigned long) ptr != (unsigned int) ptr))
        return (uint32_t) uint64_t_avx512_gather_dfl_obj_load(head, ptr, field_off, field_size);
        
    // set the index vector to 0,1,2,3... "little" endian
    // so that 0 is in index[0:31], ecc
    __m512i index = _mm512_setr_epi32(0*DFL_STRIDE, 1*DFL_STRIDE, 2*DFL_STRIDE, 3*DFL_STRIDE,
                                       4*DFL_STRIDE, 5*DFL_STRIDE, 6*DFL_STRIDE, 7*DFL_STRIDE,
                                       8*DFL_STRIDE, 9*DFL_STRIDE, 10*DFL_STRIDE, 11*DFL_STRIDE,
                                       12*DFL_STRIDE, 13*DFL_STRIDE, 14*DFL_STRIDE, 15*DFL_STRIDE);
    __m512i res   = _mm512_setzero_si512();

    __m512i target    = _mm512_set1_epi32((unsigned long) ptr);
    __m512i increment = _mm512_set1_epi32(16*DFL_STRIDE);

    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL);

    while(head) {
        unsigned char* aligned_obj = (unsigned char*)(((unsigned long)head->data + field_off) & ~(DFL_STRIDE - 1));

        field_size += (((unsigned long)head->data + field_off) - (unsigned long)aligned_obj);
        // Align the real end to DFL_STRIDE
        __m512i endv    = _mm512_set1_epi32((unsigned long) aligned_obj + (((field_size + DFL_STRIDE - 1) / (DFL_STRIDE)) * DFL_STRIDE));

        field_size = ((field_size + 16*DFL_STRIDE - 1) / (16*DFL_STRIDE)) * 16*DFL_STRIDE;
        unsigned char* _end =  aligned_obj + field_size;

        // 64-bit size check as at the beginning on obj;
        if (((unsigned long) aligned_obj != (unsigned int) aligned_obj)) {
            partial_res |= uint64_t_avx512_gather_dfl_glob_load(aligned_obj, ptr, field_off, field_size);
            head = head->next;
            continue;
        }

        // initialize the current avx ptrs for each iteration
        __m512i current = _mm512_set1_epi32((unsigned long) aligned_obj + cache_off);
        current  = _mm512_add_epi32(current, index);

        for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + 16*DFL_STRIDE) {
            // the mask will select which value will get actually loaded
            __mmask16 mask = _mm512_cmpeq_epi32_mask(target, current);
            /* we use an oob mask to avoid making accesses outside the object */
            __mmask16 oob_mask = _mm512_cmplt_epi32_mask(current, endv);
            current = _mm512_add_epi32(current, increment);
            __m512i loaded = _mm512_mask_i32gather_epi32(res, oob_mask, index, _ptr, 1);
            res = _mm512_mask_blend_epi32(mask, res, loaded);
        }
        head = head->next;
    }
    return partial_res | _mm512_reduce_add_epi32(res);
}

#define AVX512_LINESIZE 64
#if DFL_STRIDE > AVX512_LINESIZE
 #define DFL_FIXED_AVX512_STRIDE DFL_STRIDE
#else
 #define DFL_FIXED_AVX512_STRIDE AVX512_LINESIZE
#endif
DFL_FUNC uint64_t uint64_t_avx512_linear_dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size) { 
    // set the index vector to 0,8,16,24... "little" endian
    // so that 0 is in index[0:31], ecc
    __m512i index = _mm512_setr_epi64(AVX_INCREMENT*0, AVX_INCREMENT*1, AVX_INCREMENT*2, AVX_INCREMENT*3, AVX_INCREMENT*4, AVX_INCREMENT*5, AVX_INCREMENT*6, AVX_INCREMENT*7);
    __m512i res   = _mm512_setzero_si512();

#if DFL_STRIDE < AVX_INCREMENT
    // if DFL_STRIDE is lower than the index granularity, we should align the target properly.
    // this masks the relevant bits for AVX_INCREMENT, but not the ones that will be reintroduced while adding `cache_off`
    __m512i target    = _mm512_set1_epi64(((unsigned long) ptr & ~(AVX_INCREMENT-DFL_STRIDE)));
#else
    __m512i target    = _mm512_set1_epi64(((unsigned long) ptr));
#endif
    __m512i increment = _mm512_set1_epi64(DFL_FIXED_AVX512_STRIDE);

    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL);

    unsigned char* aligned_obj = (unsigned char*)(((unsigned long)obj + field_off) & ~(DFL_STRIDE - 1));

    field_size += (((unsigned long)obj + field_off) - (unsigned long)aligned_obj);
    field_size = ((field_size + DFL_FIXED_AVX512_STRIDE - 1) / (DFL_FIXED_AVX512_STRIDE)) * DFL_FIXED_AVX512_STRIDE;
    unsigned char* _end =  aligned_obj + field_size;

    // initialize the current avx ptrs for each iteration
    __m512i current = _mm512_set1_epi64((unsigned long) aligned_obj + cache_off);
    current  = _mm512_add_epi64(current, index);

    for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + DFL_FIXED_AVX512_STRIDE) {
        // the mask will select which value will get actually loaded
        __mmask8 mask = _mm512_cmpeq_epi64_mask(target, current);
        current = _mm512_add_epi64(current, increment);
        res = _mm512_mask_blend_epi64(mask, res, _mm512_loadu_si512((__m512i *)_ptr));
    }
    // if the target was aligned, shift the result to get the right value
    // NOTICE: this assumes that accesses to `TYPE` are aligned to `sizeof(TYPE)`
#if DFL_STRIDE < AVX_INCREMENT
    return _mm512_reduce_add_epi64(res) >> (8*(((unsigned long) ptr) & (AVX_INCREMENT-DFL_STRIDE)));
#else
    return _mm512_reduce_add_epi64(res);
#endif
}

DFL_FUNC uint64_t uint64_t_avx512_linear_dfl_obj_load(dfl_obj_list_head head, unsigned char* ptr, unsigned long field_off, unsigned long field_size) { 
    // set the index vector to 0,8,16,24... "little" endian
    // so that 0 is in index[0:31], ecc
    __m512i index = _mm512_setr_epi64(AVX_INCREMENT*0, AVX_INCREMENT*1, AVX_INCREMENT*2, AVX_INCREMENT*3, AVX_INCREMENT*4, AVX_INCREMENT*5, AVX_INCREMENT*6, AVX_INCREMENT*7);
    __m512i res   = _mm512_setzero_si512();

#if DFL_STRIDE < AVX_INCREMENT
    // if DFL_STRIDE is lower than the index granularity, we should align the target properly.
    // this masks the relevant bits for AVX_INCREMENT, but not the ones that will be reintroduced while adding `cache_off`
    __m512i target    = _mm512_set1_epi64(((unsigned long) ptr & ~(AVX_INCREMENT-DFL_STRIDE)));
#else
    __m512i target    = _mm512_set1_epi64(((unsigned long) ptr));
#endif
    __m512i increment = _mm512_set1_epi64(DFL_FIXED_AVX512_STRIDE);

    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL);

    while(head) {
        unsigned char* aligned_obj = (unsigned char*)(((unsigned long)head->data + field_off) & ~(DFL_STRIDE - 1));

        field_size += (((unsigned long)head->data + field_off) - (unsigned long)aligned_obj);
        field_size = ((field_size + DFL_FIXED_AVX512_STRIDE - 1) / (DFL_FIXED_AVX512_STRIDE)) * DFL_FIXED_AVX512_STRIDE;
        unsigned char* _end =  aligned_obj + field_size;

        // initialize the current avx ptrs for each iteration
        __m512i current = _mm512_set1_epi64((unsigned long) aligned_obj + cache_off);
        current  = _mm512_add_epi64(current, index);

        for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + DFL_FIXED_AVX512_STRIDE) {
            // the mask will select which value will get actually loaded
            __mmask8 mask = _mm512_cmpeq_epi64_mask(target, current);
            current = _mm512_add_epi64(current, increment);
            res = _mm512_mask_blend_epi64(mask, res, _mm512_loadu_si512((__m512i *)_ptr));
        }
        head = head->next;
    }
    // if the target was aligned, shift the result to get the right value
    // NOTICE: this assumes that accesses to `TYPE` are aligned to `sizeof(TYPE)`
#if DFL_STRIDE < AVX_INCREMENT
    return _mm512_reduce_add_epi64(res) >> (8*(((unsigned long) ptr) & (AVX_INCREMENT-DFL_STRIDE)));
#else
    return _mm512_reduce_add_epi64(res);
#endif
}

DFL_FUNC void uint64_t_avx_scatter_dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, uint64_t value) { 
        
    // set the index vector to 0,1,2,3 "little" endian
    // so that 0 is in index[0:31], ecc
    __m256i index = _mm256_setr_epi64x(0*DFL_STRIDE, 1*DFL_STRIDE, 2*DFL_STRIDE, 3*DFL_STRIDE);

    __m256i target    = _mm256_set1_epi64x((unsigned long) ptr);
    __m256i increment = _mm256_set1_epi64x(4*DFL_STRIDE);

    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL);

    unsigned char* aligned_obj = (unsigned char*)(((unsigned long)obj + field_off) & ~(DFL_STRIDE - 1));

    field_size += (((unsigned long)obj + field_off) - (unsigned long)aligned_obj);
    field_size = ((field_size + 4*DFL_STRIDE - 1) / (4*DFL_STRIDE)) * 4*DFL_STRIDE;
    unsigned char* _end =  aligned_obj + field_size;

    // initialize the current avx ptrs for each iteration
    __m256i current = _mm256_set1_epi64x((unsigned long) aligned_obj + cache_off);
    current  = _mm256_add_epi64(current, index);

    __m256i valuev = _mm256_set1_epi64x(value);

    for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + 4*DFL_STRIDE) {
        // the mask will select which value will get actually loaded
        __mmask8 mask = _mm256_cmpeq_epi64_mask(target, current);
        current = _mm256_add_epi64(current, increment);

        _mm256_mask_i64scatter_epi64((long long *)_ptr, mask, index, valuev, 1);
    }
}

DFL_FUNC void uint32_t_avx_scatter_dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, uint64_t value) { 

    // if the ptr is 64 bit wide we must use the slow version since it does not fit 8 times in the vectors
    if (((unsigned long) ptr != (unsigned int) ptr) || ((unsigned long) obj != (unsigned int) obj))
        return uint64_t_avx_scatter_dfl_glob_store(obj, ptr, field_off, field_size, value);
        
    // set the index vector to 0,1,2,3 "little" endian
    // so that 0 is in index[0:31], ecc
    __m256i index = _mm256_setr_epi32(0*DFL_STRIDE, 1*DFL_STRIDE, 2*DFL_STRIDE, 3*DFL_STRIDE,
                                       4*DFL_STRIDE, 5*DFL_STRIDE, 6*DFL_STRIDE, 7*DFL_STRIDE);

    __m256i target    = _mm256_set1_epi32((unsigned long) ptr);
    __m256i increment = _mm256_set1_epi32(8*DFL_STRIDE);

    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL);

    unsigned char* aligned_obj = (unsigned char*)(((unsigned long)obj + field_off) & ~(DFL_STRIDE - 1));

    field_size += (((unsigned long)obj + field_off) - (unsigned long)aligned_obj);
    field_size = ((field_size + 8*DFL_STRIDE - 1) / (8*DFL_STRIDE)) * 8*DFL_STRIDE;
    unsigned char* _end =  aligned_obj + field_size;

    // initialize the current avx ptrs for each iteration
    __m256i current = _mm256_set1_epi32((unsigned long) aligned_obj + cache_off);
    current  = _mm256_add_epi32(current, index);

    __m256i valuev = _mm256_set1_epi32(value);

    for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + 8*DFL_STRIDE) {
        // the mask will select which value will get actually loaded
        __mmask8 mask = _mm256_cmpeq_epi32_mask(target, current);
        current = _mm256_add_epi32(current, increment);

        _mm256_mask_i32scatter_epi32((long long *)_ptr, mask, index, valuev, 1);
    }
}

#define DFL_AVX2_SCATTER_GLOB_STORE(type) DFL_FUNC void type ## _avx_scatter_dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, type value) { \
    if (((unsigned long) ptr != (unsigned int) ptr) || ((unsigned long) obj != (unsigned int) obj))\
        return uint64_t_avx_scatter_dfl_glob_store(obj, ptr, field_off, field_size, value);\
    __m256i index = _mm256_setr_epi32(0*DFL_STRIDE, 1*DFL_STRIDE, 2*DFL_STRIDE, 3*DFL_STRIDE,\
                                       4*DFL_STRIDE, 5*DFL_STRIDE, 6*DFL_STRIDE, 7*DFL_STRIDE);\
    __m256i target    = _mm256_set1_epi32((unsigned long) ptr);\
    __m256i increment = _mm256_set1_epi32(8*DFL_STRIDE);\
    unsigned long cache_off = ((unsigned long) ptr) & (8*DFL_STRIDE-1uL);\
    unsigned char* aligned_obj = (unsigned char*)(((unsigned long)obj + field_off) & ~(8*DFL_STRIDE - 1));\
    field_size += (((unsigned long)obj + field_off) - (unsigned long)aligned_obj); \
    field_size = ((field_size + 8*DFL_STRIDE - 1) / (8*DFL_STRIDE)) * 8*DFL_STRIDE;\
    unsigned char* _end =  aligned_obj + field_size;\
    __m256i current = _mm256_set1_epi32((unsigned long) aligned_obj + cache_off);\
    current  = _mm256_add_epi32(current, index);\
    uint64_t write_mask = (1uL << (sizeof(value) * 8)) - 1uL; \
    for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + 8*DFL_STRIDE) {\
        __mmask8 mask = _mm256_cmpeq_epi32_mask(target, current);\
        current = _mm256_add_epi32(current, increment);\
        uint64_t writev_ = (*((unsigned long *)_ptr) & (~write_mask)) | value; \
        __m256i writev = _mm256_setr_epi32(writev_, 0, 0, 0, 0, 0, 0, 0); \
        _mm256_mask_i32scatter_epi32((long long *)_ptr, mask, index, writev, 1);\
    }\
}

DFL_FUNC void uint64_t_avx512_scatter_dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, uint64_t value) { 
    // set the index vector to 0,1,2,3 "little" endian
    // so that 0 is in index[0:31], ecc
    __m512i index = _mm512_setr_epi64(0*DFL_STRIDE, 1*DFL_STRIDE, 2*DFL_STRIDE, 3*DFL_STRIDE,
                                       4*DFL_STRIDE, 5*DFL_STRIDE, 6*DFL_STRIDE, 7*DFL_STRIDE);

    __m512i target    = _mm512_set1_epi64((unsigned long) ptr);
    __m512i increment = _mm512_set1_epi64(8*DFL_STRIDE);

    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL);
    unsigned char* aligned_obj = (unsigned char*)(((unsigned long)obj + field_off) & ~(DFL_STRIDE - 1));

    field_size += (((unsigned long)obj + field_off) - (unsigned long)aligned_obj);
    field_size = ((field_size + 8*DFL_STRIDE - 1) / (8*DFL_STRIDE)) * 8*DFL_STRIDE;
    unsigned char* _end =  aligned_obj + field_size;

    __m512i current = _mm512_set1_epi64((unsigned long) aligned_obj + cache_off);
    current  = _mm512_add_epi64(current, index);

    __m512i valuev = _mm512_set1_epi64(value);

    for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + 8*DFL_STRIDE) {
        __mmask16 mask = _mm512_cmpeq_epi64_mask(target, current);
        current = _mm512_add_epi64(current, increment);

        _mm512_mask_i64scatter_epi64((long long *)_ptr, mask, index, valuev, 1);
    }
}

DFL_FUNC void uint32_t_avx512_scatter_dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, uint64_t value) { 
    // if the ptr is 64 bit wide we must use the slow version since it does not fit 8 times in the vectors
    if (((unsigned long) ptr != (unsigned int) ptr) || ((unsigned long) obj != (unsigned int) obj))
        return uint64_t_avx512_scatter_dfl_glob_store(obj, ptr, field_off, field_size, value);
    
    // set the index vector to 0,1,2,3 "little" endian
    // so that 0 is in index[0:31], ecc
    __m512i index = _mm512_setr_epi32(0*DFL_STRIDE, 1*DFL_STRIDE, 2*DFL_STRIDE, 3*DFL_STRIDE,
                                       4*DFL_STRIDE, 5*DFL_STRIDE, 6*DFL_STRIDE, 7*DFL_STRIDE,
                                       8*DFL_STRIDE, 9*DFL_STRIDE, 10*DFL_STRIDE, 11*DFL_STRIDE,
                                       12*DFL_STRIDE, 13*DFL_STRIDE, 14*DFL_STRIDE, 15*DFL_STRIDE);

    __m512i target    = _mm512_set1_epi32((unsigned long) ptr);
    __m512i increment = _mm512_set1_epi32(16*DFL_STRIDE);

    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL);
    unsigned char* aligned_obj = (unsigned char*)(((unsigned long)obj + field_off) & ~(DFL_STRIDE - 1));
    
    field_size += (((unsigned long)obj + field_off) - (unsigned long)aligned_obj);
    field_size = ((field_size + 16*DFL_STRIDE - 1) / (16*DFL_STRIDE)) * 16*DFL_STRIDE;
    unsigned char* _end =  aligned_obj + field_size;

    __m512i current = _mm512_set1_epi32((unsigned long) aligned_obj + cache_off);
    current  = _mm512_add_epi32(current, index);

    __m512i valuev = _mm512_set1_epi32(value);

    for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + 16*DFL_STRIDE) {
        __mmask16 mask = _mm512_cmpeq_epi32_mask(target, current);
        current = _mm512_add_epi32(current, increment);

        _mm512_mask_i32scatter_epi32((long long *)_ptr, mask, index, valuev, 1);
    }
}

#define DFL_AVX512_SCATTER_GLOB_STORE(type) DFL_FUNC void type ## _avx512_scatter_dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, type value) { \
    if (((unsigned long) ptr != (unsigned int) ptr) || ((unsigned long) obj != (unsigned int) obj))\
        return uint64_t_avx512_scatter_dfl_glob_store(obj, ptr, field_off, field_size, value);\
    __m512i index = _mm512_setr_epi32(0*DFL_STRIDE, 1*DFL_STRIDE, 2*DFL_STRIDE, 3*DFL_STRIDE,\
                                       4*DFL_STRIDE, 5*DFL_STRIDE, 6*DFL_STRIDE, 7*DFL_STRIDE,\
                                       8*DFL_STRIDE, 9*DFL_STRIDE, 10*DFL_STRIDE, 11*DFL_STRIDE,\
                                       12*DFL_STRIDE, 13*DFL_STRIDE, 14*DFL_STRIDE, 15*DFL_STRIDE);\
    __m512i target    = _mm512_set1_epi32((unsigned long) ptr);\
    __m512i increment = _mm512_set1_epi32(16*DFL_STRIDE);\
    uint64_t write_mask_ = (1uL << sizeof(value)) - 1uL; \
    write_mask_ |= ((write_mask_ << 4) | (write_mask_ << 8) | (write_mask_ << 12) | (write_mask_ << 16) | (write_mask_ << 20) | (write_mask_ << 24) | (write_mask_ << 28) | (write_mask_ << 32) | (write_mask_ << 36) | (write_mask_ << 40) | (write_mask_ << 44) | (write_mask_ << 48) | (write_mask_ << 52) | (write_mask_ << 56)| (write_mask_ << 60)); \
    __mmask64 write_mask   = _cvtu64_mask64(write_mask_); \
    __m512i valuev = _mm512_set1_epi32(value); \
    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL);\
    unsigned char* aligned_obj = (unsigned char*)(((unsigned long)obj + field_off) & ~(DFL_STRIDE - 1));\
    field_size += (((unsigned long)obj + field_off) - (unsigned long)aligned_obj);\
    field_size = ((field_size + 16*DFL_STRIDE - 1) / (16*DFL_STRIDE)) * 16*DFL_STRIDE;\
    unsigned char* _end =  aligned_obj + field_size;\
    __m512i current = _mm512_set1_epi32((unsigned long) aligned_obj + cache_off);\
    current  = _mm512_add_epi32(current, index);\
    for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + 16*DFL_STRIDE) {\
        __mmask16 idx_mask = _mm512_cmpeq_epi32_mask(target, current); \
        __m512i   loaded   = _mm512_i32gather_epi32(index, _ptr, 1); \
        __m512i writev     = _mm512_mask_blend_epi32(idx_mask, loaded, valuev); \
        writev             = _mm512_mask_blend_epi8(write_mask, loaded, writev); \
        current = _mm512_add_epi32(current, increment);\
        _mm512_i32scatter_epi32((long long *)_ptr, index, writev, 1);\
    }\
}

DFL_FUNC void uint64_t_avx512_linear_dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, uint64_t value) { 
    // set the index vector to 0,8,16,24 "little" endian
    // so that 0 is in index[0:31], ecc
    __m512i index = _mm512_setr_epi64(AVX_INCREMENT*0, AVX_INCREMENT*1, AVX_INCREMENT*2, AVX_INCREMENT*3, 
        AVX_INCREMENT*4, AVX_INCREMENT*5, AVX_INCREMENT*6, AVX_INCREMENT*7);

    __m512i target    = _mm512_set1_epi64((unsigned long) ptr);
    __m512i increment = _mm512_set1_epi64(DFL_FIXED_AVX512_STRIDE);
    __m512i writev = _mm512_setr_epi64(value, value, value, value, value, value, value, value);

    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL);

    unsigned char* aligned_obj = (unsigned char*)(((unsigned long)obj + field_off) & ~(DFL_STRIDE - 1));

    field_size += (((unsigned long)obj + field_off) - (unsigned long)aligned_obj);
    field_size = ((field_size + DFL_FIXED_AVX512_STRIDE - 1) / (DFL_FIXED_AVX512_STRIDE)) * DFL_FIXED_AVX512_STRIDE;
    unsigned char* _end =  aligned_obj + field_size;

    // initialize the current avx ptrs for each iteration
    __m512i current = _mm512_set1_epi64((unsigned long) aligned_obj + cache_off);
    current  = _mm512_add_epi64(current, index);

    for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + DFL_FIXED_AVX512_STRIDE) {
        __mmask8 mask = _mm512_cmpeq_epi64_mask(target, current);
        current = _mm512_add_epi64(current, increment);
        _mm512_storeu_si512((long long *)_ptr, _mm512_mask_blend_epi64(mask, _mm512_loadu_si512((long long *)_ptr), writev));
    }
}

#define DFL_AVX512_LINEAR_GLOB_STORE(type) DFL_FUNC void type ## _avx512_linear_dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, type value) { \
    __m512i index = _mm512_setr_epi64(AVX_INCREMENT*0, AVX_INCREMENT*1, AVX_INCREMENT*2, AVX_INCREMENT*3, AVX_INCREMENT*4, AVX_INCREMENT*5, AVX_INCREMENT*6, AVX_INCREMENT*7); \
    __m512i target    = _mm512_set1_epi64((unsigned long) ptr & ~DFL_CORRECTION); \
    __m512i increment = _mm512_set1_epi64(DFL_FIXED_AVX512_STRIDE); \
    uint64_t write_mask_ = ((1uL << sizeof(value)) - 1uL) << ((((unsigned long) ptr) & (DFL_CORRECTION))); \
    write_mask_ |= ((write_mask_ << 8) | (write_mask_ << 16) | (write_mask_ << 24) | (write_mask_ << 32) | (write_mask_ << 40) | (write_mask_ << 48) | (write_mask_ << 56)); \
    __mmask64 write_mask   = _cvtu64_mask64(write_mask_); \
    uint64_t shifted_value = ((uint64_t)value) << (8*(((unsigned long) ptr) & (DFL_CORRECTION))); \
    __m512i valuev = _mm512_set1_epi64(shifted_value); \
    unsigned long cache_off = ((unsigned long) ptr) & (DFL_STRIDE-1uL); \
    unsigned char* aligned_obj = (unsigned char*)(((unsigned long)obj + field_off) & ~(DFL_STRIDE - 1)); \
    field_size += (((unsigned long)obj + field_off) - (unsigned long)aligned_obj); \
    field_size = ((field_size + DFL_FIXED_AVX512_STRIDE - 1) / (DFL_FIXED_AVX512_STRIDE)) * DFL_FIXED_AVX512_STRIDE; \
    unsigned char* _end =  aligned_obj + field_size; \
    __m512i current = _mm512_set1_epi64((unsigned long) aligned_obj + cache_off); \
    current  = _mm512_add_epi64(current, index); \
    for(volatile unsigned char* _ptr = aligned_obj + cache_off; _ptr < _end; _ptr = _ptr + DFL_FIXED_AVX512_STRIDE) { \
        __mmask8 idx_mask = _mm512_cmpeq_epi64_mask(target, current); \
        __m512i  loaded   = _mm512_loadu_si512((long long *)_ptr); \
        __m512i writev    = _mm512_mask_blend_epi64(idx_mask, loaded, valuev); \
        writev            = _mm512_mask_blend_epi8(write_mask, loaded, writev); \
        current = _mm512_add_epi64(current, increment); \
        _mm512_storeu_si512((long long *)_ptr, writev); \
    } \
}

#define DFL_AVX512_GATHER_GLOB_LOAD(type) DFL_FUNC type type ## _avx512_gather_dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size) {  \
    return (type) uint32_t_avx512_gather_dfl_glob_load(obj, ptr, field_off, field_size); \
}

#define DFL_AVX512_GATHER_OBJ_LOAD(type) DFL_FUNC type type ## _avx512_gather_dfl_obj_load(dfl_obj_list_head head, unsigned char* ptr, unsigned long field_off, unsigned long field_size) {  \
    return (type) uint32_t_avx512_gather_dfl_obj_load(head, ptr, field_off, field_size); \
}

#define DFL_AVX512_LINEAR_GLOB_LOAD(type) DFL_FUNC type type ## _avx512_linear_dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size) {  \
    return (type) uint64_t_avx512_linear_dfl_glob_load(obj, ptr, field_off, field_size); \
}

#define DFL_AVX512_LINEAR_OBJ_LOAD(type) DFL_FUNC type type ## _avx512_linear_dfl_obj_load(dfl_obj_list_head head, unsigned char* ptr, unsigned long field_off, unsigned long field_size) {  \
    return (type) uint64_t_avx512_linear_dfl_obj_load(head, ptr, field_off, field_size); \
}

DFL_AVX512_GATHER_GLOB_LOAD(uint16_t)
DFL_AVX512_GATHER_GLOB_LOAD(uint8_t)

DFL_AVX512_GATHER_OBJ_LOAD(uint16_t)
DFL_AVX512_GATHER_OBJ_LOAD(uint8_t)

DFL_AVX512_LINEAR_GLOB_LOAD(uint32_t)
DFL_AVX512_LINEAR_GLOB_LOAD(uint16_t)
DFL_AVX512_LINEAR_GLOB_LOAD(uint8_t)

DFL_AVX512_LINEAR_OBJ_LOAD(uint32_t)
DFL_AVX512_LINEAR_OBJ_LOAD(uint16_t)
DFL_AVX512_LINEAR_OBJ_LOAD(uint8_t)

DFL_AVX2_SCATTER_GLOB_STORE(uint16_t)
DFL_AVX2_SCATTER_GLOB_STORE(uint8_t)

DFL_AVX512_SCATTER_GLOB_STORE(uint16_t)
DFL_AVX512_SCATTER_GLOB_STORE(uint8_t)

DFL_AVX512_LINEAR_GLOB_STORE(uint32_t)
DFL_AVX512_LINEAR_GLOB_STORE(uint16_t)
DFL_AVX512_LINEAR_GLOB_STORE(uint8_t)

#endif /* __AVX512F__ */

#if defined(__AVX2__)
#define DFL_AVX2_GATHER_GLOB_LOAD(type) DFL_FUNC type type ## _avx2_gather_dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size) {  \
    return (type) uint32_t_avx2_gather_dfl_glob_load(obj, ptr, field_off, field_size); \
}
#define DFL_AVX2_LINEAR_GLOB_LOAD(type) DFL_FUNC type type ## _avx2_linear_dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size) {  \
    return (type) uint64_t_avx2_linear_dfl_glob_load(obj, ptr, field_off, field_size); \
}

#define DFL_AVX2_LINEAR_OBJ_LOAD(type) DFL_FUNC type type ## _avx2_linear_dfl_obj_load(dfl_obj_list_head head, unsigned char* ptr, unsigned long field_off, unsigned long field_size) {  \
    return (type) uint64_t_avx2_linear_dfl_obj_load(head, ptr, field_off, field_size); \
}

#define DFL_AVX2_GATHER_OBJ_LOAD(type) DFL_FUNC type type ## _avx2_gather_dfl_obj_load(dfl_obj_list_head head, unsigned char* ptr, unsigned long field_off, unsigned long field_size) {  \
    return (type) uint32_t_avx2_gather_dfl_obj_load(head, ptr, field_off, field_size); \
}

DFL_AVX2_GATHER_GLOB_LOAD(uint16_t)
DFL_AVX2_GATHER_GLOB_LOAD(uint8_t)

DFL_AVX2_GATHER_OBJ_LOAD(uint16_t)
DFL_AVX2_GATHER_OBJ_LOAD(uint8_t)

DFL_AVX2_LINEAR_GLOB_LOAD(uint32_t)
DFL_AVX2_LINEAR_GLOB_LOAD(uint16_t)
DFL_AVX2_LINEAR_GLOB_LOAD(uint8_t)

DFL_AVX2_LINEAR_OBJ_LOAD(uint32_t)
DFL_AVX2_LINEAR_OBJ_LOAD(uint16_t)
DFL_AVX2_LINEAR_OBJ_LOAD(uint8_t)

DFL_AVX2_LINEAR_GLOB_STORE(uint32_t)
DFL_AVX2_LINEAR_GLOB_STORE(uint16_t)
DFL_AVX2_LINEAR_GLOB_STORE(uint8_t)
#endif /* __AVX2__ */

DFL_OBJ_LOAD(uint128_t)
DFL_OBJ_LOAD(uint64_t)
DFL_OBJ_LOAD(uint32_t)
DFL_OBJ_LOAD(uint16_t)
DFL_OBJ_LOAD(uint8_t)

DFL_OBJ_STORE(uint128_t)
DFL_OBJ_STORE(uint64_t)
DFL_OBJ_STORE(uint32_t)
DFL_OBJ_STORE(uint16_t)
DFL_OBJ_STORE(uint8_t)

DFL_GLOB_LOAD(uint128_t)
DFL_GLOB_LOAD(uint64_t)
DFL_GLOB_LOAD(uint32_t)
DFL_GLOB_LOAD(uint16_t)
DFL_GLOB_LOAD(uint8_t)

DFL_GLOB_STORE(uint128_t)
DFL_GLOB_STORE(uint64_t)
DFL_GLOB_STORE(uint32_t)
DFL_GLOB_STORE(uint16_t)
DFL_GLOB_STORE(uint8_t)

DFL_SINGLE_GLOB_LOAD(uint64_t)
DFL_SINGLE_GLOB_LOAD(uint32_t)
DFL_SINGLE_GLOB_LOAD(uint16_t)
DFL_SINGLE_GLOB_LOAD(uint8_t)

DFL_SINGLE_OBJ_LOAD(uint64_t)
DFL_SINGLE_OBJ_LOAD(uint32_t)
DFL_SINGLE_OBJ_LOAD(uint16_t)
DFL_SINGLE_OBJ_LOAD(uint8_t)

DFL_SINGLE_GLOB_STORE(uint64_t)
DFL_SINGLE_GLOB_STORE(uint32_t)
DFL_SINGLE_GLOB_STORE(uint16_t)
DFL_SINGLE_GLOB_STORE(uint8_t)

DFL_SINGLE_OBJ_STORE(uint64_t)
DFL_SINGLE_OBJ_STORE(uint32_t)
DFL_SINGLE_OBJ_STORE(uint16_t)
DFL_SINGLE_OBJ_STORE(uint8_t)

// DFL_FUNC_NOINLINE void dfl_memcpy(void *dest, void *src, size_t n, bool isvolatile) 
// {
//     DEBUG("INTRINSICS memcpy(%p, %p, %ld) taken: %d\n", dest, src, n, taken);
// #if CFL_EXPAND_INTRINSCS
//     // Typecast src and dest addresses to (char *)
//     char *csrc = (char *)src;
//     char *cdest = (char *)dest;

//     // Copy contents of src[] to dest[]
//     for (int i=0; i<n; i++)
//         cdest[i] = csrc[i];
// #else
//     size_t new_size = taken? n : (n>2048? 0 : n);
//     memcpy(cfl_ptr_wrap(dest), cfl_ptr_wrap(src), new_size);
// #endif
//     CFL_UNUSED(isvolatile);
// }

// Optimized version of memcpy to transfer a single field from an object to another
// assumes: dfield_size == sfield_size == n (before being wrapped with dfl_wrap_var) and src/dest == s/dobj + s/dfield_off
DFL_FUNC_NOINLINE void dfl_memcpy_field_glob(void *dest, void *src, volatile size_t n, bool isvolatile, unsigned char* dobj, unsigned long dfield_off, unsigned long dfield_size, unsigned char* sobj, unsigned long sfield_off, unsigned long sfield_size)
{
    DEBUG("INTRINSICS memcpy_field(%p, %p, %ld) - dobj: %p - doff:%lu, dsize:%lu - sobj: %p - soff:%lu, ssize:%lu - taken: %d\n", dest, src, n, dobj, dfield_off, dfield_size, sobj, sfield_off, sfield_size, taken);
    unsigned char* _dptr =  dobj + dfield_off;
    unsigned char* _sptr =  sobj + sfield_off;

    // Copy contents of src[] to dest[]
    #pragma nounroll
    for (unsigned long i = 0; i < dfield_size; ++i) {
        // n is zero when taken == 0
        bool condition = (n > 0);
        volatile unsigned char _prev_val = *(volatile unsigned char*)_dptr;
        volatile unsigned char _new_val = *(volatile unsigned char*)_sptr;
        *(volatile unsigned char*)_dptr = condition? _new_val : _prev_val;
        ++_dptr;
        ++_sptr;
    }
}

// dest: glob, src: obj
DFL_FUNC_NOINLINE void dfl_memcpy_field_glob_obj(void *dest, void *src, volatile size_t n, bool isvolatile, unsigned char* dobj, unsigned long dfield_off, unsigned long dfield_size, dfl_obj_list_head shead, unsigned long sfield_off, unsigned long sfield_size)
{
    unsigned char* _dptr =  dobj + dfield_off;

    while (shead) {
        unsigned char* sobj = (unsigned char*)shead->data;
        unsigned char* _sptr =  sobj + sfield_off;
        DEBUG("INTRINSICS memcpy_field(%p, %p, %ld) - dobj: %p - doff:%lu, dsize:%lu - sobj: %p - soff:%lu, ssize:%lu - taken: %d\n", dest, src, n, dobj, dfield_off, dfield_size, sobj, sfield_off, sfield_size, taken);

        // Copy contents of src[] to dest[]
        #pragma nounroll
        for (unsigned long i = 0; i < dfield_size; ++i) {
            // n is zero when taken == 0
            bool condition = (n > 0);
            volatile unsigned char _prev_val = *(volatile unsigned char*)_dptr;
            volatile unsigned char _new_val = *(volatile unsigned char*)_sptr;
            *(volatile unsigned char*)_dptr = condition? _new_val : _prev_val;
            ++_dptr;
            ++_sptr;
        }
        shead = shead->next;
    }
}

#if defined(__AVX2__)
// Optimized version of memcpy to transfer a single field from an object to another
// assumes: dfield_size == sfield_size == n (before being wrapped with dfl_wrap_var) and src/dest == s/dobj + s/dfield_off
DFL_FUNC_NOINLINE void dfl_memcpy_field_glob_avx(void *dest, void *src, volatile size_t n, bool isvolatile, unsigned char* dobj, unsigned long dfield_off, unsigned long dfield_size, unsigned char* sobj, unsigned long sfield_off, unsigned long sfield_size)
{
    DEBUG("INTRINSICS memcpy_field(%p, %p, %ld) - dobj: %p - doff:%lu, dsize:%lu - sobj: %p - soff:%lu, ssize:%lu - taken: %d\n", dest, src, n, dobj, dfield_off, dfield_size, sobj, sfield_off, sfield_size, taken);
    unsigned char* _dptr =  dobj + dfield_off;
    unsigned char* _sptr =  sobj + sfield_off;

    // Copy contents of src[] to dest[]
    unsigned long i = 0;
    for (; i < dfield_size-AVX2_LINESIZE; i+= AVX2_LINESIZE) {
        // n is zero when taken == 0
        __m256i mask = _mm256_set1_epi8((n > 0)? 0xff : 0);
        __m256i _prev_val = _mm256_loadu_si256((__m256i *)_dptr);
        __m256i _new_val = _mm256_loadu_si256((__m256i *)_sptr);
        _new_val = _mm256_blendv_epi8(_prev_val, _new_val, mask);
        _mm256_storeu_si256((__m256i *)_dptr, _new_val);
        _dptr += AVX2_LINESIZE;
        _sptr += AVX2_LINESIZE;
    }

    // copy the remaining (can do this since dfield_size is not secret)
    #pragma nounroll
    for (; i < dfield_size; ++i) {
        // n is zero when taken == 0
        bool condition = (n > 0);
        volatile unsigned char _prev_val = *(volatile unsigned char*)_dptr;
        volatile unsigned char _new_val = *(volatile unsigned char*)_sptr;
        *(volatile unsigned char*)_dptr = condition? _new_val : _prev_val;
        ++_dptr;
        ++_sptr;
    }
}

// dst: glob, src: obj
DFL_FUNC_NOINLINE void dfl_memcpy_field_glob_obj_avx(void *dest, void *src, volatile size_t n, bool isvolatile, unsigned char* dobj, unsigned long dfield_off, unsigned long dfield_size, dfl_obj_list_head shead, unsigned long sfield_off, unsigned long sfield_size)
{
    while (shead) {
        unsigned char* sobj = (unsigned char*)shead->data;

        DEBUG("INTRINSICS memcpy_field(%p, %p, %ld) - dobj: %p - doff:%lu, dsize:%lu - sobj: %p - soff:%lu, ssize:%lu - taken: %d\n", dest, src, n, dobj, dfield_off, dfield_size, sobj, sfield_off, sfield_size, taken);
        unsigned char* _dptr =  dobj + dfield_off;
        unsigned char* _sptr =  sobj + sfield_off;

        // Copy contents of src[] to dest[]
        unsigned long i = 0;
        for (; i < dfield_size-AVX2_LINESIZE; i+= AVX2_LINESIZE) {
            // n is zero when taken == 0
            __m256i mask = _mm256_set1_epi8((n > 0)? 0xff : 0);
            __m256i _prev_val = _mm256_loadu_si256((__m256i *)_dptr);
            __m256i _new_val = _mm256_loadu_si256((__m256i *)_sptr);
            _new_val = _mm256_blendv_epi8(_prev_val, _new_val, mask);
            _mm256_storeu_si256((__m256i *)_dptr, _new_val);
            _dptr += AVX2_LINESIZE;
            _sptr += AVX2_LINESIZE;
        }

        // copy the remaining (can do this since dfield_size is not secret)
        #pragma nounroll
        for (; i < dfield_size; ++i) {
            // n is zero when taken == 0
            bool condition = (n > 0);
            volatile unsigned char _prev_val = *(volatile unsigned char*)_dptr;
            volatile unsigned char _new_val = *(volatile unsigned char*)_sptr;
            *(volatile unsigned char*)_dptr = condition? _new_val : _prev_val;
            ++_dptr;
            ++_sptr;
        }
        shead = shead->next;
    }
}
#endif /* __AVX2__ */

DFL_FUNC_NOINLINE void dfl_memcpy_glob(void *dest, void *src, size_t n, bool isvolatile, unsigned char* dobj, unsigned long dfield_off, unsigned long dfield_size, unsigned char* sobj, unsigned long sfield_off, unsigned long sfield_size)
{
    DEBUG("INTRINSICS memcpy(%p, %p, %ld) - dobj: %p - doff:%lu, dsize:%lu - sobj: %p - soff:%lu, ssize:%lu - taken: %d\n", dest, src, n, dobj, dfield_off, dfield_size, sobj, sfield_off, sfield_size, taken);
    //type cast from void* to char*
    unsigned char *sptr = (unsigned char*) src;
    unsigned char *dptr = (unsigned char*) dest;

    unsigned char* _dstart =  dobj + dfield_off;
    unsigned char* _dend =  dobj + dfield_off + dfield_size;

    unsigned char* _sstart =  sobj + sfield_off;
    unsigned char* _send =  sobj + sfield_off + sfield_size;

    // Copy contents of src[] to dest[]
    for(volatile unsigned char* _sptr = _sstart; _sptr < _send; ++_sptr) {
        volatile unsigned char _new_val = *(volatile unsigned char*)_sptr;
        for(volatile unsigned char* _dptr = _dstart; _dptr < _dend; ++_dptr) {
            volatile unsigned char _prev_val = *(volatile unsigned char*)_dptr;

            // Check if we should write here
            bool condition = (_dptr == dptr) && (_sptr == sptr) && (n > 0);

            *(volatile unsigned char*)_dptr = condition? _new_val : _prev_val;
            dptr = condition? dptr + 1 : dptr;
            sptr = condition? sptr + 1 : sptr;
            n    = condition? n - 1 : n;
        }
    }
    DFL_UNUSED(isvolatile);
}

// dst: glob, src: obj
DFL_FUNC_NOINLINE void dfl_memcpy_glob_obj(void *dest, void *src, size_t n, bool isvolatile, unsigned char* dobj, unsigned long dfield_off, unsigned long dfield_size, dfl_obj_list_head shead, unsigned long sfield_off, unsigned long sfield_size)
{
    //type cast from void* to char*
    unsigned char *sptr = (unsigned char*) src;
    unsigned char *dptr = (unsigned char*) dest;

    unsigned char* _dstart =  dobj + dfield_off;
    unsigned char* _dend =  dobj + dfield_off + dfield_size;

    while (shead) {
        unsigned char* sobj = (unsigned char*)shead->data;
        unsigned char* _sstart =  sobj + sfield_off;
        unsigned char* _send =  sobj + sfield_off + sfield_size;

        DEBUG("INTRINSICS memcpy(%p, %p, %ld) - dobj: %p - doff:%lu, dsize:%lu - sobj: %p - soff:%lu, ssize:%lu - taken: %d\n", dest, src, n, dobj, dfield_off, dfield_size, sobj, sfield_off, sfield_size, taken);

        // Copy contents of src[] to dest[]
        for(volatile unsigned char* _sptr = _sstart; _sptr < _send; ++_sptr) {
            volatile unsigned char _new_val = *(volatile unsigned char*)_sptr;
            for(volatile unsigned char* _dptr = _dstart; _dptr < _dend; ++_dptr) {
                volatile unsigned char _prev_val = *(volatile unsigned char*)_dptr;

                // Check if we should write here
                bool condition = (_dptr == dptr) && (_sptr == sptr) && (n > 0);

                *(volatile unsigned char*)_dptr = condition? _new_val : _prev_val;
                dptr = condition? dptr + 1 : dptr;
                sptr = condition? sptr + 1 : sptr;
                n    = condition? n - 1 : n;
            }
        }
        shead = shead->next;
    }
    DFL_UNUSED(isvolatile);
}

DFL_FUNC_NOINLINE void dfl_memset_glob(void* str, unsigned char ch, size_t n, bool isvolatile, unsigned char* obj, unsigned long field_off, unsigned long field_size)
{
    DEBUG("INTRINSICS memset(%p, %hhd, %ld) - obj: %p - off:%lu, size:%lu - taken: %d\n", str, ch, n, obj, field_off, field_size, taken);
    //type cast the str from void* to char*
    unsigned char *ptr = (unsigned char*) str;
    unsigned char* _end =  obj + field_off + field_size;
    volatile unsigned char _ch = ch;
    //fill "n" elements/blocks with ch
    for(volatile unsigned char* _ptr = obj + field_off; _ptr < _end; ++_ptr) {
        volatile unsigned char _prev_val = *(volatile unsigned char*)_ptr;
        bool condition = (_ptr >= ptr) && (_ptr < ptr + n);
        *(volatile unsigned char*)_ptr = condition? _ch : _prev_val;
    }
    DFL_UNUSED(isvolatile);
}

#if defined(__AVX2__)
DFL_VAR __attribute__ (( __aligned__(64) )) unsigned char masks_pre[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};
DFL_VAR __attribute__ (( __aligned__(64) )) unsigned char masks_post[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
};
void print256_num(char* s, __m256i var)
{
    uint64_t val[4];
    memcpy(val, &var, sizeof(val));
    printf("%s: %lx %lx %lx %lx \n", s, 
           val[0], val[1], val[2], val[3]);
}
DFL_FUNC_NOINLINE void dfl_memset_glob_avx(void* str, unsigned char ch, size_t n, bool isvolatile, unsigned char* obj, unsigned long field_off, unsigned long field_size)
{
    DEBUG("INTRINSICS memset(%p, %hhd, %ld) - obj: %p - off:%lu, size:%lu - taken: %d\n", str, ch, n, obj, field_off, field_size, taken);
    // DPRINT("INTRINSICS memset(%p, %hhd, %ld) - obj: %p - off:%lu, size:%lu\n", str, ch, n, obj, field_off, field_size);
    //type cast the str from void* to char*
    unsigned char* ptr = (unsigned char*) str;
    // first and last AVX2 line to fill
    unsigned char* _start =  (unsigned char*)(((unsigned long)obj + field_off) & ~(AVX2_LINESIZE-1uL));
    unsigned char* _end =  (unsigned char*)(((unsigned long)_start + field_size+AVX2_LINESIZE-1) & ~(AVX2_LINESIZE-1uL));

    // `line_ptr_start` is the first AVX2 line where the ptr resides, either full or partial
    unsigned char* line_ptr_start = (unsigned char*) (((unsigned long) ptr) & ~(AVX2_LINESIZE-1uL));
    // `line_ptr_end` is the ending AVX2 line that should be partially filled. If 
    // ptr+n is aligned to a line, line_ptr_end will point to an empty line that will not be filled
    unsigned char* line_ptr_end   = (unsigned char*) (((unsigned long)(ptr+n+AVX2_LINESIZE)) & ~(AVX2_LINESIZE-1uL));

    // masks
    // __m256i vnone = _mm256_setzero_si256();
    // __m256i vfull = _mm256_set1_epi8(0xff);
    
    __m256i chv = _mm256_set1_epi8(ch);

    // Build masks to mask the first and last write that will not take a whole AVX2 line
    // We will load the mask from memory to efficiently build it since AVX2 does 
    // not support horizontal shifts of arbitrary amounts
    // This is oblivious only with respect to an attacker which obseves cache line 
    // accesses, since the variables span a single cache line each.
    // In case DFL_STRIDE<64 we should load the mask using striding helpers
    __m256i mask_pre  = _mm256_loadu_si256((__m256i *) &masks_pre[32 - (((unsigned long) ptr) & (AVX2_LINESIZE-1uL))]); // avx2_shift_right(mask_full, xxx);
    __m256i mask_post = _mm256_loadu_si256((__m256i *)&masks_post[32 - (((unsigned long) ptr+n) & (AVX2_LINESIZE-1uL))]); // avx2_shift_left(mask_full, xxx);

    //fill the blocks with ch
    for(volatile unsigned char* _ptr = _start; _ptr < _end; _ptr += AVX2_LINESIZE) {
        __m256i _prev_val = _mm256_load_si256((__m256i *)_ptr);

        // Generate the masks conditions to select the right mask
        // The masks will select the cells that have to be written or left unchanged
        // mask_condition will be 0xff..ff when the mask must not have any effect in the final `mask`
        __m256i mask_none_condition = _mm256_set1_epi8((_ptr < line_ptr_start || _ptr >= line_ptr_end)? 0 : 0xff);
        __m256i mask_pre_condition = _mm256_set1_epi8(((_ptr >= line_ptr_start) && (_ptr < line_ptr_start + AVX2_LINESIZE))? 0 : 0xff);
        // __m256i mask_full_condition = _mm256_set1_epi8(((_ptr >= line_ptr_start + AVX2_LINESIZE) && (_ptr < line_ptr_end - AVX2_LINESIZE))? 0 : 0xff);
        __m256i mask_post_condition = _mm256_set1_epi8(((_ptr >= line_ptr_end - AVX2_LINESIZE) && (_ptr < line_ptr_end))? 0 : 0xff);

        // Reset masks to 0xff.ff when they should not be applied (so default is full write)
        __m256i mask_none_filtered = mask_none_condition; // mask_none is always zero
        __m256i mask_pre_filtered  = _mm256_or_si256(mask_pre_condition, mask_pre);
        __m256i mask_post_filtered = _mm256_or_si256(mask_post_condition, mask_post);

        // Combine all the masks together to create the mask we will apply to the blend.
        // By default we perform a full write and the filtered masks select which bytes
        // should not be updated
        __m256i mask = _mm256_and_si256(mask_none_filtered, mask_pre_filtered);
        mask         = _mm256_and_si256(mask, mask_post_filtered);

        __m256i _new_val = _mm256_blendv_epi8(_prev_val, chv, mask);

        _mm256_store_si256((__m256i *)_ptr, _new_val);
    }
    DFL_UNUSED(isvolatile);
}
#endif /* __AVX2__ */

DFL_FUNC_NOINLINE void dfl_memset_obj(void* str, unsigned char ch, size_t n, bool isvolatile, dfl_obj_list_head head, unsigned long field_off, unsigned long field_size)
{
    //type cast the str from void* to char*
    unsigned char *ptr = (unsigned char*) str;
    volatile unsigned char _ch = ch;
    while (head) {
        unsigned char* obj = (unsigned char*)head->data;
        DEBUG("INTRINSICS memset(%p, %hhd, %ld) - obj: %p - off:%lu, size:%lu - taken: %d\n", str, ch, n, obj, field_off, field_size, taken);
        unsigned char* _end =  obj + field_off + field_size;
        //fill "n" elements/blocks with ch
        for(volatile unsigned char* _ptr = obj + field_off; _ptr < _end; ++_ptr) {
            volatile unsigned char _prev_val = *(volatile unsigned char*)_ptr;
            bool condition = (_ptr >= ptr) && (_ptr < ptr + n);
            *(volatile unsigned char*)_ptr = condition? _ch : _prev_val;
        }
        head = head->next;
    }
    DFL_UNUSED(isvolatile);
}

#if defined(__AVX2__)
DFL_FUNC_NOINLINE void dfl_memset_obj_avx(void* str, unsigned char ch, size_t n, bool isvolatile, dfl_obj_list_head head, unsigned long field_off, unsigned long field_size)
{
    DEBUG("INTRINSICS memset(%p, %hhd, %ld) - obj: %p - off:%lu, size:%lu - taken: %d\n", str, ch, n, obj, field_off, field_size, taken);
    // DPRINT("INTRINSICS memset(%p, %hhd, %ld) - obj: %p - off:%lu, size:%lu\n", str, ch, n, obj, field_off, field_size);
    //type cast the str from void* to char*
    unsigned char* ptr = (unsigned char*) str;

    // `line_ptr_start` is the first AVX2 line where the ptr resides, either full or partial
    unsigned char* line_ptr_start = (unsigned char*) (((unsigned long) ptr) & ~(AVX2_LINESIZE-1uL));
    // `line_ptr_end` is the ending AVX2 line that should be partially filled. If 
    // ptr+n is aligned to a line, line_ptr_end will point to an empty line that will not be filled
    unsigned char* line_ptr_end   = (unsigned char*) (((unsigned long)(ptr+n+AVX2_LINESIZE)) & ~(AVX2_LINESIZE-1uL));

    // masks
    // __m256i vnone = _mm256_setzero_si256();
    // __m256i vfull = _mm256_set1_epi8(0xff);
    
    __m256i chv = _mm256_set1_epi8(ch);

    // Build masks to mask the first and last write that will not take a whole AVX2 line
    // We will load the mask from memory to efficiently build it since AVX2 does 
    // not support horizontal shifts of arbitrary amounts
    // This is oblivious only with respect to an attacker which obseves cache line 
    // accesses, since the variables span a single cache line each.
    // In case DFL_STRIDE<64 we should load the mask using striding helpers
    __m256i mask_pre  = _mm256_loadu_si256((__m256i *) &masks_pre[32 - (((unsigned long) ptr) & (AVX2_LINESIZE-1uL))]); // avx2_shift_right(mask_full, xxx);
    __m256i mask_post = _mm256_loadu_si256((__m256i *)&masks_post[32 - (((unsigned long) ptr+n) & (AVX2_LINESIZE-1uL))]); // avx2_shift_left(mask_full, xxx);

    while (head) {
        unsigned char* obj = (unsigned char*)head->data;
        // first and last AVX2 line to fill
        unsigned char* _start =  (unsigned char*)(((unsigned long)obj + field_off) & ~(AVX2_LINESIZE-1uL));
        unsigned char* _end =  (unsigned char*)(((unsigned long)_start + field_size+AVX2_LINESIZE-1) & ~(AVX2_LINESIZE-1uL));

        //fill the blocks with ch
        for(volatile unsigned char* _ptr = _start; _ptr < _end; _ptr += AVX2_LINESIZE) {
            __m256i _prev_val = _mm256_load_si256((__m256i *)_ptr);

            // Generate the masks conditions to select the right mask
            // The masks will select the cells that have to be written or left unchanged
            // mask_condition will be 0xff..ff when the mask must not have any effect in the final `mask`
            __m256i mask_none_condition = _mm256_set1_epi8((_ptr < line_ptr_start || _ptr >= line_ptr_end)? 0 : 0xff);
            __m256i mask_pre_condition = _mm256_set1_epi8(((_ptr >= line_ptr_start) && (_ptr < line_ptr_start + AVX2_LINESIZE))? 0 : 0xff);
            // __m256i mask_full_condition = _mm256_set1_epi8(((_ptr >= line_ptr_start + AVX2_LINESIZE) && (_ptr < line_ptr_end - AVX2_LINESIZE))? 0 : 0xff);
            __m256i mask_post_condition = _mm256_set1_epi8(((_ptr >= line_ptr_end - AVX2_LINESIZE) && (_ptr < line_ptr_end))? 0 : 0xff);

            // Reset masks to 0xff.ff when they should not be applied (so default is full write)
            __m256i mask_none_filtered = mask_none_condition; // mask_none is always zero
            __m256i mask_pre_filtered  = _mm256_or_si256(mask_pre_condition, mask_pre);
            __m256i mask_post_filtered = _mm256_or_si256(mask_post_condition, mask_post);

            // Combine all the masks together to create the mask we will apply to the blend.
            // By default we perform a full write and the filtered masks select which bytes
            // should not be updated
            __m256i mask = _mm256_and_si256(mask_none_filtered, mask_pre_filtered);
            mask         = _mm256_and_si256(mask, mask_post_filtered);

            __m256i _new_val = _mm256_blendv_epi8(_prev_val, chv, mask);

            _mm256_store_si256((__m256i *)_ptr, _new_val);
        }
        head = head->next;
    }
    DFL_UNUSED(isvolatile);
}
#endif /* __AVX2__ */

// DFL_FUNC_NOINLINE void dfl_memmove(void *dest, void *src, size_t n, bool isvolatile)
// {
//     DEBUG("INTRINSICS memmove(%p, %p, %ld) taken: %d\n", dest, src, n, taken);
// #if CFL_EXPAND_INTRINSCS
//     register char *dp = dest;
//     register char const *sp = src;
//     if(dp < sp) {
//         while(n-- > 0)
//             *dp++ = *sp++;
//     } else {
//         dp += n;
//         sp += n;
//         while(n-- > 0)
//             *--dp = *--sp;
//     }
// #else
//     size_t new_size = taken? n : (n>2048? 0 : n);
//     memmove(cfl_ptr_wrap(dest), cfl_ptr_wrap(src), new_size);
// #endif
//     CFL_UNUSED(isvolatile);
// }