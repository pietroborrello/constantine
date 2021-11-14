#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <inttypes.h>
#include <assert.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dlfcn.h>

static unsigned long shadow_offset;

#define CGC_FUNC __attribute__((used)) __attribute__((section("cgc_code")))
#define CGC_FUNC_NOINLINE __attribute__((noinline)) CGC_FUNC
#define CGC_FPTR_TO_SHADOW_ENTRY(P) ((void**)(((char*)P) + shadow_offset))

#ifdef CGC_DEBUG
#define debugf printf
#else
#define debugf(...)
#endif

CGC_FUNC void* cgc_fptr_wrap(void* fptr)
{
    void *clone_fptr = *CGC_FPTR_TO_SHADOW_ENTRY(fptr);
    debugf("cgc_fptr_wrap: %p -> %p\n", fptr, clone_fptr);
    return clone_fptr;
}

CGC_FUNC void cgc_pass_add_clone(void *fptr, void *clone_fptr)
{
    *CGC_FPTR_TO_SHADOW_ENTRY(fptr) = clone_fptr;
    debugf("cgc_pass_add_clone: %p -> %p\n", fptr, clone_fptr);
}
CGC_FUNC_NOINLINE void cgc_pass_init()
{
    // filled by the -cgc pass
    asm("");
}

CGC_FUNC __attribute__((constructor)) void cgc_init()
{
    // Compute base address and size of code section
    extern int etext;
    Dl_info info;
    dladdr(cgc_init, &info);
    char *code_base = (char*)info.dli_fbase;
    size_t code_size = ((char*)&etext) - code_base;
    assert(code_base && code_size > 0);

    // Clone code section to create a shadow region-based lookup table
    int flags = MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE;
    char *shadow_base = (char*) mmap(code_base, code_size, PROT_READ|PROT_WRITE,
        flags, 0, 0);
    assert(shadow_base != MAP_FAILED);
    assert(shadow_base > code_base);
    shadow_offset = shadow_base-code_base;
    debugf("cgc_init: Code at %p, shadow region at %p, size is %lu (pp=%lu)\n",
        code_base, shadow_base, code_size,
        code_size%4096 ? code_size/4096+1 : code_size/4096);

    // Initialize table
    cgc_pass_init();
    int ret = mprotect(shadow_base, code_size, PROT_READ);
    assert(ret == 0);
}
