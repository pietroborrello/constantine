#include <unistd.h>
#include <stdbool.h>

#define UTILS_DEBUG 0

#if UTILS_DEBUG == 2
#define DEBUG(f_, ...) fprintf(stderr, (f_), __VA_ARGS__)
#define DEBUG_ASSERT(a) assert(a)
#define DEBUG_STMT(s) s
#elif UTILS_DEBUG == 1
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

void utils_memcpy(void *dest, void *src, size_t n, bool isvolatile) 
{
    DEBUG("INTRINSICS memcpy(%p, %p, %ld)\n", dest, src, n);
    // Typecast src and dest addresses to (char *)
    char *csrc = (char *)src;
    char *cdest = (char *)dest;

    // Copy contents of src[] to dest[]
    for (int i=0; i<n; i++)
        cdest[i] = csrc[i];
    
    (void)(isvolatile);
}

void utils_memset(void* str, char ch, size_t n, bool isvolatile)
{
    DEBUG("INTRINSICS memset(%p, %hhd, %ld)\n", str, ch, n);
    int i;
    //type cast the str from void* to char*
    char *s = (char*) str;
    //fill "n" elements/blocks with ch
    for(i=0; i<n; i++)
        s[i]=ch;
    (void)(isvolatile);
}

void utils_memmove(void *dest, void *src, size_t n, bool isvolatile)
{
    DEBUG("INTRINSICS memmove(%p, %p, %ld)\n", dest, src, n);
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
    (void)(isvolatile);
}
