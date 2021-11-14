#include <dft.h>

static dfsan_label input_label;
static char *base;
static FILE *file;

/*
 * Trace instructions and dump taint information in a log file.
 * Heavily relies on the -hook pass, -coverage-id pass, and DFSan.
 *
 * For more information, see:
 * - https://clang.llvm.org/docs/DataFlowSanitizer.html
*/

/* Use this function to inject initialization steps: in hook.c */
extern void __attribute__((used)) __attribute__((noinline)) dft_pass_init(dfsan_label);

/* Initialize. */
void dft_init()
{
    // Compute base address of code section
    Dl_info info;
    dladdr(dft_init, &info);
    base = (void*)info.dli_fbase;

    // Initialize input label
    input_label = dfsan_create_label("input", 0);

    // Open log file
    file = fopen("dft.log", "w");

    assert(base && file);

    dft_pass_init(input_label);
}

/* Wrap compare instructions to dump taint information. */
#ifndef DFT_SKIP_CMP
void __dfsw___dft_cmp(DFT_ARG_PREFIX bool cmp,
    DFT_LAB_PREFIX dfsan_label l) {
    DFT_SINK_EXT(DFT_VAL_PREFIX l, file, base, "cmp", DFT_FLAGS2(l, cmp), DFT_MASK2, "CcBb");
}
void __dfsw___dft_switch(DFT_ARG_PREFIX unsigned long long value,
    DFT_LAB_PREFIX dfsan_label l)  {
    DFT_SINK(DFT_VAL_PREFIX l, file, base, "switch");
}
void __dfsw___dft_br(DFT_ARG_PREFIX bool taken,
    DFT_LAB_PREFIX dfsan_label l)  {
    DFT_SINK_EXT(DFT_VAL_PREFIX l, file, base, "branch", DFT_FLAGS2(l, taken), DFT_MASK2, "CcBb");
}
#endif

/* Wrap indirect calls to dump taint information. */
#ifndef DFT_SKIP_ICALL
void __dfsw___dft_icall(DFT_ARG_PREFIX void *fptr,
    DFT_LAB_PREFIX dfsan_label l) {
    DFT_SINK(DFT_VAL_PREFIX l, file, base, "icall");
}
#endif

/* Wrap pointer arithmetic instructions to dump taint information. */
#ifndef DFT_SKIP_GEP
void __dfsw___dft_getelementptr(DFT_ARG_PREFIX void *gep, void *ptr,
    DFT_LAB_PREFIX dfsan_label l1, dfsan_label l2) {
    DFT_SINK_EXT(DFT_VAL_PREFIX (l1 && !l2), file, base, "gep", DFT_FLAGS2((l1 && !l2), l2), DFT_MASK2, "OoPp");
}
#endif

/* Wrap memory accessing instructions to dump taint information. */
#ifndef DFT_SKIP_MEM
void __dfsw___dft_load(DFT_ARG_PREFIX void *ptr,
    DFT_LAB_PREFIX dfsan_label l) {
    DFT_SINK(DFT_VAL_PREFIX l, file, base, "load");
}

#ifdef DFT_STORE_TAINT_VAL_IF_PTR_ONLY
extern char etext;
extern char edata;
extern char** environ;
#define ADDRESS_RANGE 0xffffuL
#define in_range(_addr, _base) (((_addr) >= (_base)) && ((_addr) < ((_base) + (ADDRESS_RANGE))))
#endif
void __dfsw___dft_store(DFT_ARG_PREFIX long long value, void *ptr,
    DFT_LAB_PREFIX dfsan_label l1, dfsan_label l2) {
#ifdef DFT_STORE_TAINT_VAL_IF_PTR_ONLY
    unsigned long text  = (unsigned long)(&etext)  & ~ADDRESS_RANGE;
    unsigned long data  = (unsigned long)(&edata)  & ~ADDRESS_RANGE;
    unsigned long stack = (unsigned long)(environ) & ~ADDRESS_RANGE;
    unsigned long heap  = (unsigned long)(sbrk(0)) & ~ADDRESS_RANGE;
    if(!in_range(value, text) && !in_range(value, data) && !in_range(value, stack) && !in_range(value, heap)) {
        l1 = 0;
    }
    DFT_SINK_EXT(DFT_VAL_PREFIX (l1 || l2), file, base, "store", DFT_FLAGS2(l2, l1), DFT_MASK2, "TtVv");
#endif
    DFT_SINK(DFT_VAL_PREFIX l2, file, base, "store");
}
void __dfsw___dft_memcpy(DFT_ARG_PREFIX void *dst, void *src, size_t len,
    DFT_LAB_PREFIX dfsan_label l1, dfsan_label l2, dfsan_label l3) {
    DFT_SINK_EXT(DFT_VAL_PREFIX (l1 || l2 || l3), file, base, "memcpy", DFT_FLAGS3(l1, l2, l3), DFT_MASK3, "DdSsLl");
}
void __dfsw___dft_memmove(DFT_ARG_PREFIX void *dst, void *src, size_t len,
    DFT_LAB_PREFIX dfsan_label l1, dfsan_label l2, dfsan_label l3) {
    DFT_SINK_EXT(DFT_VAL_PREFIX (l1 || l2 || l3), file, base, "memmov", DFT_FLAGS3(l1, l2, l3), DFT_MASK3, "DdSsLl");
}
void __dfsw___dft_memset(DFT_ARG_PREFIX void *dst, char val, size_t len,
    DFT_LAB_PREFIX dfsan_label l1, dfsan_label l2, dfsan_label l3) {
    DFT_SINK_EXT(DFT_VAL_PREFIX (l1 || l3), file, base, "memset", DFT_FLAGS2(l1, l3), DFT_MASK2, "DdLl");
}
#endif

/* Wrap div and rem instructions to dump taint information. */
#ifndef DFT_SKIP_DIV
void __dfsw___dft_div(DFT_ARG_PREFIX signed long long value,
    DFT_LAB_PREFIX dfsan_label l) {
    DFT_SINK(DFT_VAL_PREFIX l, file, base, "div");
}
void __dfsw___dft_rem(DFT_ARG_PREFIX signed long long value,
    DFT_LAB_PREFIX dfsan_label l) {
    DFT_SINK(DFT_VAL_PREFIX l, file, base, "rem");
}
#endif

/* Wrap selected symbols to tag taint sources. */
int __dfsw___dft_main(int argc, char** argv,
    dfsan_label l1, dfsan_label l2)
{
    extern int __main(int argc, char** argv);

    // Initialize
    dft_init();

#ifdef DFT_WRAP_SOURCES
    for (int i=0;i<argc;i++) {
        dfsan_set_label(input_label, argv[i], strlen(argv[i])+1);
    }
    dfsan_set_label(input_label, &argc, sizeof(argc));
#endif

    return __main(argc, argv);
}

#ifdef DFT_WRAP_SOURCES
ssize_t __dfsw___dft_read(void *buf, ssize_t size,
    dfsan_label l1, dfsan_label l2)
{
    if(size<=0)
        return size;
    dfsan_set_label(input_label, buf, size);
    return size;
}
#endif
