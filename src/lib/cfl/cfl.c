#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#include <inttypes.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <cfl.h>

#define CFL_DEBUG 0

#if CFL_DEBUG == 2
#define DEBUG(f_, ...) fprintf(stderr, (f_), __VA_ARGS__)
#define DEBUG_ASSERT(a) assert(a)
#define DEBUG_STMT(s) s
#elif CFL_DEBUG == 1
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

unsigned char CFL_DUMMY_ADDR[4096] __attribute__ (( __aligned__(4096) ));
CFL_TAKEN_VAR bool taken = 1;

CFL_FUNC CFL_CONSTRUCTOR void cfl_init()
{
}

#if CFL_DEBUG == 2
CFL_FUNC_INLINE void cfl_br_cond(bool *tmp, int b_gid, int i_bid)
#else
CFL_FUNC_INLINE void cfl_br_cond(bool *tmp)
#endif
{
    DEBUG("Branching - tmp: %p - saving taken: %d (%d, %d)\n", tmp, taken, b_gid, i_bid);
    *tmp = taken;
}

#if CFL_DEBUG == 2
CFL_FUNC_NOINLINE bool cfl_br_get_fixed(bool cmp, bool fixed_res, int b_gid, int i_bid)
#else
CFL_FUNC_NOINLINE bool cfl_br_get_fixed(bool cmp, bool fixed_res)
#endif
{
    DEBUG("Branching fixed - cmp: %d - taken: %d (%d, %d)\n", cmp, taken, b_gid, i_bid);
    DEBUG_STMT(if(taken) assert(cmp == fixed_res));
    return taken? cmp : fixed_res;
}

CFL_FUNC_INLINE void cfl_br_iftrue(bool *tmp, bool cmp)
{
    taken = (*tmp)*(cmp);
    DEBUG("IfTrue - tmp: %p=%d - cmp: %d - new_taken: %d\n", tmp, *tmp, cmp, taken);
}

CFL_FUNC_INLINE void cfl_br_iffalse(bool *tmp, bool cmp)
{
    taken = (*tmp)*(!cmp);
    DEBUG("IfFalse - tmp: %p=%d - cmp: %d - new_taken: %d\n", tmp, *tmp, cmp, taken);
}

CFL_FUNC_INLINE void cfl_br_merge(bool *tmp)
{
    DEBUG("Merging - tmp: %p=%d - old_taken: %d\n", tmp, *tmp, taken);
    taken = *tmp;
}

CFL_FUNC_INLINE void cfl_loop_preheader(bool *tmp, unsigned long *count, int b_gid, int i_bid)
{
    // tmp --> per-loop stack variable (was I in dummy mode or not, before executing this)
    *count = 0;
    *tmp = taken;
    DEBUG("Loop preheader - %p: %d (%d, %d)\n", tmp, *tmp, b_gid, i_bid);
}

CFL_FUNC_NOINLINE bool cfl_loop_exiting(unsigned long *count, unsigned long *max_count, bool would_exit)
{
    // count, max_count --> per-exiting block global variables
    // update cont, max_count, count, and always continue max_count times, using linearized code

    // 4 cases:
    //     1) not taken, would_exit: continue up to max_count, preserve taken
    //     2) not taken, not would_exit    : continue up to max_count, preserve taken
    //     3) taken, not would_exit        : update max_count
    //     4) taken, would_exit    : continue up to max_count, -> not taken (enter dummy mode)

    // TODO: reason on cmp condition: true if exit? For now asserted in the pass
    DEBUG("Loop taken: %d, would_exit: %d, max_count: %p=%lu, count: %lu, ", taken, would_exit, max_count, *max_count, *count);

    // Was the branch continuing?
    // Take into account if the branch evaluates to would_exit, but later to cont
    // (e.g. i++; i != 10 vs i < 10)
    // by multiplying with taken value itself
    taken = (!would_exit)*(taken);
    ++(*count);

    // if(taken && *count >= *max_count)
    //     *max_count = *count;
    DEBUG_STMT(if(taken) assert(!(taken && *count > *max_count)));
    *max_count = (taken && *count > *max_count)? *count : *max_count;
    DEBUG("new_max_count: %lu, ", *max_count);

    // // here !taken if dummy mode or would have exited
    // if (!taken && *count < *max_count)
    //     would_exit = false;
    // if (!taken && *count >= *max_count)
    //     would_exit = true;

    // would_exit = taken ? would_exit : (*count > *max_count);
    bool taken_local = taken;
    would_exit = (taken_local * would_exit) + (!taken_local * (*count > *max_count));
    DEBUG("will_exit: %d\n", would_exit);

    return would_exit;
}

CFL_FUNC_INLINE void cfl_loop_exit(bool *tmp, unsigned long *count)
{
    DEBUG("Loop exit - %p: %d\n", tmp, *tmp);
    taken = *tmp;
}

CFL_FUNC_INLINE void cfl_loop_dump_count(unsigned long *count, bool will_exit, int b_gid, int i_bid) {
    if (!will_exit)
        ++(*count);
    assert(taken);
    assert(CFL_DEBUG == 0 && "dump loop count will not work in debug mode, as stderr will be used for dbg prints");
    fprintf(stderr, "%lu %d %d\n", *count, b_gid, i_bid);
}

// #define ISSTA
CFL_FUNC_INLINE void* cfl_ptr_wrap(void* ptr)
{
    uintptr_t uiptr = (uintptr_t) ptr;
    uintptr_t dummy_ptr = (uintptr_t) CFL_DUMMY_ADDR;
#ifdef ISSTA
    asm volatile (
        "test %2, %2\n"
        "cmove %1, %0\n"
        :"+r"(uiptr)
        :"r"(dummy_ptr), "r"(taken)
        : "cc"
        );
#else
    // uiptr = (uiptr - dummy_ptr)*taken + dummy_ptr;
    DEBUG("PTR_WRAP(0x%lx) - taken: %d\n", uiptr, taken);
    uiptr = taken ? uiptr : dummy_ptr;
#endif
    return (void*) uiptr;
}

// We define a DFL helper here since DFL code sees `taken` as volatile, while for
// this helper this is not necessary
__attribute__((section("dfl_code"))) __attribute__((always_inline)) void* dfl_ptr_wrap(void* ptr)
{
    return (void*) ((unsigned long)ptr * taken);
}
__attribute__((section("dfl_code"))) __attribute__((always_inline)) unsigned long dfl_val_wrap(unsigned long val)
{
    return (val * taken);
}

CFL_FUNC void cfl_dummy_ext_func()
{
}

CFL_FUNC_NOINLINE void* cfl_fptr_wrap(void* ptr)
{
    return taken ? ptr : (void*)cfl_dummy_ext_func;
}

// TODO: manage memcpy in DFL, since we may leak through the `n` param if in
// dummy mode, since it may have unpredictable values
CFL_FUNC void cfl_memcpy(void *dest, void *src, size_t n, bool isvolatile) 
{
    DEBUG("INTRINSICS memcpy(%p, %p, %ld) taken: %d\n", dest, src, n, taken);
#if CFL_EXPAND_INTRINSCS
    // Typecast src and dest addresses to (char *)
    char *csrc = (char *)src;
    char *cdest = (char *)dest;

    // Copy contents of src[] to dest[]
    for (int i=0; i<n; i++)
        cdest[i] = csrc[i];
#else
    size_t new_size = taken? n : (n>2048? 0 : n);
    memcpy(cfl_ptr_wrap(dest), cfl_ptr_wrap(src), new_size);
#endif
    CFL_UNUSED(isvolatile);
}

// TODO: manage memset in DFL, since we may leak through the `n` param if in
// dummy mode, since it may have unpredictable values
CFL_FUNC void cfl_memset(void* str, char ch, size_t n, bool isvolatile)
{
    DEBUG("INTRINSICS memset(%p, %hhd, %ld) taken: %d\n", str, ch, n, taken);
#if CFL_EXPAND_INTRINSCS
    int i;
    //type cast the str from void* to char*
    char *s = (char*) str;
    //fill "n" elements/blocks with ch
    for(i=0; i<n; i++)
        s[i]=ch;
#else
    size_t new_size = taken? n : (n>2048? 0 : n);
    memset(cfl_ptr_wrap(str), ch, new_size);
#endif
    CFL_UNUSED(isvolatile);
}

// TODO: manage memmove in DFL, since we may leak through the `n` param if in
// dummy mode, since it may have unpredictable values
CFL_FUNC void cfl_memmove(void *dest, void *src, size_t n, bool isvolatile)
{
    DEBUG("INTRINSICS memmove(%p, %p, %ld) taken: %d\n", dest, src, n, taken);
#if CFL_EXPAND_INTRINSCS
    register char *dp = dest;
    register char const *sp = src;
    if(dp < sp) {
        while(n-- > 0)
            *dp++ = *sp++;
    } else {
        dp += n;
        sp += n;
        while(n-- > 0)
            *--dp = *--sp;
    }
#else
    size_t new_size = taken? n : (n>2048? 0 : n);
    memmove(cfl_ptr_wrap(dest), cfl_ptr_wrap(src), new_size);
#endif
    CFL_UNUSED(isvolatile);
}

/* DIV wrappers. */
CFL_FUNC_INLINE unsigned long long cfl_udiv(
    unsigned long long dividend, unsigned long long divisor, size_t size) {
    unsigned long long quotient = 0, temp = 0;

    // test down from the highest bit and
    // accumulate the tentative value for
    // valid bit
    for (int i = size*8-1; i >= 0; --i) {
        temp = (temp << 1uLL) | ((dividend >> i) & 1);
        bool cmp = (temp >= divisor);
        temp -= cmp? divisor : 0;
        quotient |= cmp ? 1uLL << i : 0;
    }
    DEBUG("CFL_DIV: 0x%llx / 0x%llx = 0x%llx %% 0x%llx - taken: %d\n", dividend, divisor, quotient, temp, taken);
    DEBUG_ASSERT((dividend / divisor) == quotient);
    return quotient;
}

CFL_FUNC_INLINE uint128_t cfl_udiv_i128(uint128_t dividend, uint128_t divisor, size_t size) {
    uint128_t quotient = 0, temp = 0;

    // test down from the highest bit and
    // accumulate the tentative value for
    // valid bit
    for (int i = size*8-1; i >= 0; --i) {
        temp = (uint128_t)(temp << 1uLL) | (uint128_t)((dividend >> i) & 1);
		bool cmp = (temp >= divisor);
		temp -= cmp? divisor : (uint128_t)0;
		quotient |= cmp ? ((uint128_t)1uLL) << i : (uint128_t)0;
    }
    DEBUG("CFL_DIV: 0x%lx%016lx / 0x%lx%016lx = 0x%lx%016lx %% 0x%lx%016lx  - taken: %d\n", 
        (unsigned long)(dividend>>64uL), (unsigned long)dividend, 
        (unsigned long)(divisor>>64uL), (unsigned long)divisor, 
        (unsigned long)(quotient>>64uL), (unsigned long)quotient, 
        (unsigned long)(temp>>64uL), (unsigned long)temp, taken);
    DEBUG_ASSERT((dividend / divisor) == quotient);
    return quotient;
}

CFL_FUNC_INLINE signed long long cfl_sdiv(
    signed long long dividend, signed long long divisor, size_t size) {
    int sign = ((dividend < 0) ^ (divisor < 0)) ? -1 : 1;

    // remove sign of operands
    dividend = dividend < 0 ? -dividend : dividend;
    divisor = divisor < 0 ? -divisor : divisor;

    return sign*cfl_udiv((unsigned long long)dividend, (unsigned long long)divisor, size);
}

CFL_FUNC_INLINE long double cfl_fdiv(
    long double dividend, long double divisor, size_t size) {
    assert(0 && "Not implemented");
    return 0;
}

#define CFL_SAFE_DIV(D) ((D)*taken+(1-taken))
#define CFL_DECLARE_DIV_WRAPPER(T, F, X) \
    CFL_FUNC_NOINLINE T X(T a, T b) { b=CFL_SAFE_DIV(b); return CFL_CT ? F(a,b,sizeof(T)) : a/b; }

#define CFL_REM(T, F, A, B) ((A)-F(A,B,sizeof(T))*(B))
#define CFL_DECLARE_REM_WRAPPER(T, F, X) \
    CFL_FUNC_NOINLINE T X(T a, T b) { b=CFL_SAFE_DIV(b); return CFL_CT ? CFL_REM(T,F,a,b) : a%b; }

CFL_DECLARE_DIV_WRAPPER(signed char,        cfl_sdiv, __hook_wrap_sdiv_t1)
CFL_DECLARE_DIV_WRAPPER(signed short,       cfl_sdiv, __hook_wrap_sdiv_t2)
CFL_DECLARE_DIV_WRAPPER(signed int,         cfl_sdiv, __hook_wrap_sdiv_t3)
CFL_DECLARE_DIV_WRAPPER(signed long long,   cfl_sdiv, __hook_wrap_sdiv)

CFL_DECLARE_DIV_WRAPPER(unsigned char,      cfl_udiv, __hook_wrap_udiv_t1)
CFL_DECLARE_DIV_WRAPPER(unsigned short,     cfl_udiv, __hook_wrap_udiv_t2)
CFL_DECLARE_DIV_WRAPPER(unsigned int,       cfl_udiv, __hook_wrap_udiv_t3)
CFL_DECLARE_DIV_WRAPPER(uint128_t,     cfl_udiv_i128, __hook_wrap_udiv_t4)
CFL_DECLARE_DIV_WRAPPER(unsigned long long, cfl_udiv, __hook_wrap_udiv)

CFL_DECLARE_DIV_WRAPPER(long double,        cfl_fdiv, __hook_wrap_fdiv)

CFL_DECLARE_REM_WRAPPER(signed char,        cfl_sdiv, __hook_wrap_srem_t1)
CFL_DECLARE_REM_WRAPPER(signed short,       cfl_sdiv, __hook_wrap_srem_t2)
CFL_DECLARE_REM_WRAPPER(signed int,         cfl_sdiv, __hook_wrap_srem_t3)
CFL_DECLARE_REM_WRAPPER(signed long long,   cfl_sdiv, __hook_wrap_srem)

CFL_DECLARE_REM_WRAPPER(unsigned char,      cfl_udiv, __hook_wrap_urem_t1)
CFL_DECLARE_REM_WRAPPER(unsigned short,     cfl_udiv, __hook_wrap_urem_t2)
CFL_DECLARE_REM_WRAPPER(unsigned int,       cfl_udiv, __hook_wrap_urem_t3)
CFL_DECLARE_REM_WRAPPER(unsigned long long, cfl_udiv, __hook_wrap_urem)

CFL_DECLARE_DIV_WRAPPER(long double,        cfl_fdiv, __hook_wrap_frem)
