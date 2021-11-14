#define _GNU_SOURCE

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <dlfcn.h>
#include <sys/mman.h>

#include <sanitizer/dfsan_interface.h>

typedef long imd_t;

/* Configuration. */
#ifndef DFT_DUMP_UNTAINTED
#define DFT_SKIP_ON_TAINT_STATUS(L) (!(L))
#else
#define DFT_SKIP_ON_TAINT_STATUS(L) (L)
#endif

#ifndef DFT_DUMP_FIRST_SINK
#define DFT_SKIP_AFTER_FIRST_SINK 0
#else
#define DFT_SKIP_AFTER_FIRST_SINK 1
#endif

#ifndef DFT_VERBOSE
#define DFT_EXTRA_INFO            0
#else
#define DFT_EXTRA_INFO            1
#endif

/* Definitions. */
#define DFT_ARG_PREFIX imd_t ID1, imd_t *ID2,
#define DFT_LAB_PREFIX dfsan_label ID1L, dfsan_label ID2L,
#define DFT_VAL_PREFIX ID1, ID2,

typedef union guard_u {
    struct guard_s {
        unsigned long id : 56;
        unsigned f1      : 1;
        unsigned nf1     : 1;
        unsigned f2      : 1;
        unsigned nf2     : 1;
        unsigned f3      : 1;
        unsigned nf3     : 1;
        unsigned padding : 2;
    } s;
    unsigned long v;
} guard_t;

#define DFT_FLAGS_IS_NEW(G, F) (((G).v | (F).v) != (G).v)
#define DFT_FLAGS_ADD(G, F)    ((G).v |= (F).v)
#define DFT_FLAGS_OK(G, M)     (((G).v & (M).v) == (M).v)
#define DFT_CH(G, B, C)        ((G).s.B && DFT_EXTRA_INFO ? C : '0')

#define _B(F,I) (((unsigned long)(!!(F))) << (56+(I)))
#define DFT_FLAGS_V(F1, NF1, F2, NF2, F3, NF3) \
    (_B(F1,0) | _B(NF1,1) | _B(F2,2) | _B(NF2,3) | _B(F3,4) | _B(NF3,5))
#define DFT_FLAGS_LIST(...) { .v = DFT_FLAGS_V(__VA_ARGS__) }

#define DFT_FLAGS1(X)                             DFT_FLAGS_V(X,!X, 0, 0, 0, 0)
#define DFT_FLAGS2(X, Y)                          DFT_FLAGS_V(X,!X, Y,!Y, 0, 0)
#define DFT_FLAGS3(X, Y, Z)                       DFT_FLAGS_V(X,!X, Y,!Y, Z,!Z)

__attribute__((weak)) const guard_t DFT_MASK1= DFT_FLAGS_LIST(1, 1, 0, 0, 0, 0);
__attribute__((weak)) const guard_t DFT_MASK2= DFT_FLAGS_LIST(1, 1, 1, 1, 0, 0);
__attribute__((weak)) const guard_t DFT_MASK3= DFT_FLAGS_LIST(1, 1, 1, 1, 1, 1);

#define DFT_SINK_EXT(...) __DFT_SINK_EXT(__VA_ARGS__)
#define __DFT_SINK_EXT(ID1, ID2, L, FILE, BASE, NAME, FLAGS, MASK, CHARS) do { \
    if (!(*ID2)) return; \
    if (!DFT_EXTRA_INFO && DFT_SKIP_ON_TAINT_STATUS(L)) return; \
    guard_t *__guard = (guard_t*) ID2; \
    guard_t __flags = { .v = FLAGS }; \
    if (!DFT_FLAGS_IS_NEW(*__guard, __flags)) return; \
    DFT_FLAGS_ADD(*__guard, __flags); \
    char *PC = __builtin_return_address(0); \
    char *__c = CHARS; \
    char __str[] = { DFT_CH(*__guard, f1, __c[0]), DFT_CH(*__guard, nf1, __c[1]), \
        DFT_CH(*__guard, f2, __c[2]), DFT_CH(*__guard, nf2, __c[3]), \
        DFT_CH(*__guard, f3, __c[4]), DFT_CH(*__guard, nf3, __c[5]), '\0' }; \
    fprintf(FILE, "%6s:%s:%08ld:%04ld:%p\n", NAME, __str, ID1, __guard->s.id, (void*)(PC-BASE)); \
    if (DFT_SKIP_AFTER_FIRST_SINK || !DFT_EXTRA_INFO || DFT_FLAGS_OK(*__guard, MASK)) *ID2=0; \
} while(0)

#define DFT_SINK(...) __DFT_SINK(__VA_ARGS__)
#define __DFT_SINK(ID1, ID2, L, FILE, BASE, NAME) do { \
    __DFT_SINK_EXT(ID1, ID2, L, FILE, BASE, NAME, DFT_FLAGS1(L), DFT_MASK1, "Tt"); \
} while(0)
