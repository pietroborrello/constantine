#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/ssl.h>
#include <assert.h>
#include <unistd.h>

#define KEY32 32

#define check(ret) assert(!(ret))

mp_int my_key;
static wcchar fp_s_rmap = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                     "abcdefghijklmnopqrstuvwxyz+/";

static __attribute_noinline__ int my_s_is_power_of_two(fp_digit b, int *p)
{
   int x;

   /* fast return if no power of two */
   if ((b==0) || (b & (b-1))) {
      return FP_NO;
   }

   for (x = 0; x < DIGIT_BIT; x++) {
      if (b == (((fp_digit)1)<<x)) {
         *p = x;
         return FP_YES;
      }
   }
   return FP_NO;
}

static __always_inline int my2_s_is_power_of_two(fp_digit b, int *p)
{
   int x;

   /* fast return if no power of two */
   if ((b==0) || (b & (b-1))) {
      return FP_NO;
   }

   for (x = 0; x < DIGIT_BIT; x++) {
      if (b == (((fp_digit)1)<<x)) {
         *p = x;
         return FP_YES;
      }
   }
   return FP_NO;
}

static int my2_fp_div_d(fp_int *a, fp_digit b, fp_int *c, fp_digit *d)
{
#ifndef WOLFSSL_SMALL_STACK
  fp_int   q[1];
#else
  fp_int   *q;
#endif
  fp_word  w;
  fp_digit t;
  int      ix;
  int ix1, ix2;

  /* cannot divide by zero */
  if (b == 0) {
     return FP_VAL;
  }

  /* quick outs */
  if (b == 1 || fp_iszero(a) == FP_YES) {
     if (d != NULL) {
        *d = 0;
     }
     if (c != NULL) {
        fp_copy(a, c);
     }
     return FP_OKAY;
  }
  printf("b2 : %d\n", my2_s_is_power_of_two(b, &ix));

  /* power of two ? */
  if (my2_s_is_power_of_two(b, &ix) == FP_YES) {
  printf("c2\n");
     if (d != NULL) {
        *d = a->dp[0] & ((((fp_digit)1)<<ix) - 1);
     }
     if (c != NULL) {
        fp_div_2d(a, ix, c, NULL);
     }
     return FP_OKAY;
  }

#ifdef WOLFSSL_SMALL_STACK
  q = (fp_int*)XMALLOC(sizeof(fp_int), NULL, DYNAMIC_TYPE_BIGINT);
  if (q == NULL)
      return FP_MEM;
#endif

  fp_init(q);

  if (c != NULL) {
    q->used = a->used;
    q->sign = a->sign;
  }

  w = 0;
  for (ix = a->used - 1; ix >= 0; ix--) {
     w = (w << ((fp_word)DIGIT_BIT)) | ((fp_word)a->dp[ix]);

     if (w >= b) {
        t = (fp_digit)(w / b);
        w -= ((fp_word)t) * ((fp_word)b);
      } else {
        t = 0;
      }
      if (c != NULL)
        q->dp[ix] = (fp_digit)t;
  }

  if (d != NULL) {
     *d = (fp_digit)w;
  }

  if (c != NULL) {
     fp_clamp(q);
     fp_copy(q, c);
  }

#ifdef WOLFSSL_SMALL_STACK
  XFREE(q, NULL, DYNAMIC_TYPE_BIGINT);
#endif
  return FP_OKAY;
}

static int my_fp_div_d(fp_int *a, fp_digit b, fp_int *c, fp_digit *d)
{
#ifndef WOLFSSL_SMALL_STACK
  fp_int   q[1];
#else
  fp_int   *q;
#endif
  fp_word  w;
  fp_digit t;
  int      ix;
  int ix1, ix2;

  /* cannot divide by zero */
  if (b == 0) {
     return FP_VAL;
  }

  /* quick outs */
  if (b == 1 || fp_iszero(a) == FP_YES) {
     if (d != NULL) {
        *d = 0;
     }
     if (c != NULL) {
        fp_copy(a, c);
     }
     return FP_OKAY;
  }
  printf("b1 : %d\n", my_s_is_power_of_two(b, &ix));

  /* power of two ? */
  if (my_s_is_power_of_two(b, &ix) == FP_YES) {
  printf("c1\n");
     if (d != NULL) {
        *d = a->dp[0] & ((((fp_digit)1)<<ix) - 1);
     }
     if (c != NULL) {
        fp_div_2d(a, ix, c, NULL);
     }
     return FP_OKAY;
  }

#ifdef WOLFSSL_SMALL_STACK
  q = (fp_int*)XMALLOC(sizeof(fp_int), NULL, DYNAMIC_TYPE_BIGINT);
  if (q == NULL)
      return FP_MEM;
#endif

  fp_init(q);

  if (c != NULL) {
    q->used = a->used;
    q->sign = a->sign;
  }

  w = 0;
  for (ix = a->used - 1; ix >= 0; ix--) {
     w = (w << ((fp_word)DIGIT_BIT)) | ((fp_word)a->dp[ix]);

     if (w >= b) {
        t = (fp_digit)(w / b);
        w -= ((fp_word)t) * ((fp_word)b);
      } else {
        t = 0;
      }
      if (c != NULL)
        q->dp[ix] = (fp_digit)t;
  }

  if (d != NULL) {
     *d = (fp_digit)w;
  }

  if (c != NULL) {
     fp_clamp(q);
     fp_copy(q, c);
  }

#ifdef WOLFSSL_SMALL_STACK
  XFREE(q, NULL, DYNAMIC_TYPE_BIGINT);
#endif
  return FP_OKAY;
}

int my_mp_toradix (mp_int *a, char *str, int radix)
{
    int      res, digs;
    fp_digit d;
    fp_digit d1=0, d2=0;
    char     *_s = str;
#ifndef WOLFSSL_SMALL_STACK
    fp_int   t[1];
    fp_int   t1[1]={0};
    fp_int   t2[1]={0};
#else
    fp_int   *t;
#endif

    /* check range of the radix */
    if (radix < 2 || radix > 64) {
        return FP_VAL;
    }

    /* quick out if its zero */
    if (fp_iszero(a) == FP_YES) {
        *str++ = '0';
        *str = '\0';
        return FP_OKAY;
    }

#ifdef WOLFSSL_SMALL_STACK
    t = (fp_int*)XMALLOC(sizeof(fp_int), NULL, DYNAMIC_TYPE_BIGINT);
    if (t == NULL)
        return FP_MEM;
#endif

    /* init a copy of the input */
    fp_init_copy (t, a);

    /* if it is negative output a - */
    if (t->sign == FP_NEG) {
        ++_s;
        *str++ = '-';
        t->sign = FP_ZPOS;
    }

    digs = 0;
    while (fp_iszero (t) == FP_NO) {
        my_fp_div_d(t, (fp_digit) radix, t1, &d1);
        my2_fp_div_d(t, (fp_digit) radix, t2, &d2);
        printf("%3llx==%llx && %16llx==%16llx\n", d1, d2, t1->dp[0], t2->dp[0]);
        assert(d1==d2);
        assert(t1->dp[0] == t2->dp[0]);
        if ((res = my_fp_div_d (t, (fp_digit) radix, t, &d)) != FP_OKAY) {
            fp_zero (t);
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(t, NULL, DYNAMIC_TYPE_BIGINT);
        #endif
            return res;
        }
        *str++ = fp_s_rmap[d];
        ++digs;
    }
#ifndef WC_DISABLE_RADIX_ZERO_PAD
    /* For hexadecimal output, add zero padding when number of digits is odd */
    if ((digs & 1) && (radix == 16)) {
        *str++ = fp_s_rmap[0];
        ++digs;
    }
#endif
    /* reverse the digits of the string.  In this case _s points
     * to the first digit [excluding the sign] of the number]
     */
    fp_reverse ((unsigned char *)_s, digs);

    /* append a NULL so the string is properly terminated */
    *str = '\0';

    fp_zero (t);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(t, NULL, DYNAMIC_TYPE_BIGINT);
#endif
    return FP_OKAY;
}

void my_mp_dump(const char* desc, mp_int* a, byte verbose)
{
  char buffer[FP_SIZE * sizeof(fp_digit) * 2];
  int size;

#if defined(ALT_ECC_SIZE) || defined(HAVE_WOLF_BIGINT)
  size = a->size;
#else
  size = FP_SIZE;
#endif

  printf("%s: ptr=%p, used=%d, sign=%d, size=%d, fpd=%d\n",
    desc, a, a->used, a->sign, size, (int)sizeof(fp_digit));

  my_mp_toradix(a, buffer, 16);
  printf("  %s\n  ", buffer);

  if (verbose) {
    int i;
    for(i=0; i<size * (int)sizeof(fp_digit); i++) {
      printf("%x ", *(((byte*)a->dp) + i));
    }
    printf("\n");
  }
}

int main(int argc, char* argv[])
{
    int     ret = 0;
    ecc_key     key1, key2, key3;
    WC_RNG      rng;
    ecc_point G, R;
    mp_int a, mod;


    check(wc_ecc_init(&key1));
    check(wc_ecc_init(&key2));
    check(wc_ecc_init(&key3));

    char* Gx = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
    char* Gy = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";
    char* Af = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC";
    char* prime = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";

    check(wc_ecc_import_raw_ex(&key2, Gx, Gy, Af, ECC_SECP256R1));
    check(wc_ecc_import_raw_ex(&key3, Gx, Gy, prime, ECC_SECP256R1));

    // check(mp_read_radix(&key, "1F44D5DE4E57AA94B5AA515E0D98EE0A7DCC3FE69DCF96FF101A6A230DBD7CB3", 16));
#define INPUT_SIZE 32
    read(0, ((unsigned char*)my_key.dp), INPUT_SIZE);
    my_key.sign = 0;
    my_key.used = INPUT_SIZE/sizeof(unsigned long);

    // for(int i = 0; i < sizeof(key.dp); ++i)
    //     printf("%02x ", ((unsigned char*)key.dp)[i]);
    // printf("\n %lu, %lu\n", (unsigned long)key.sign, (unsigned long)key.used);

    // my_mp_dump("\necc2: x", key2.pubkey.x, 0);
    // mp_dump("\necc2: y", key2.pubkey.y, 0);
    // mp_dump("\necc2: z", key2.pubkey.z, 0);
    // mp_dump("\necc2: k", &key2.k, 0);

    /* initialize all the points to smaller structures to optimize SVF field analysis */
    mp_init_copy(G.x, key2.pubkey.x);
    mp_init_copy(G.y, key2.pubkey.y);
    mp_init_copy(G.z, key2.pubkey.z);

    mp_init_copy(R.x, key3.pubkey.x);
    mp_init_copy(R.y, key3.pubkey.y);
    mp_init_copy(R.z, key3.pubkey.z);

    mp_init_copy(&a,   &key2.k);
    mp_init_copy(&mod, &key3.k);

    check(wc_ecc_mulmod(&my_key, &G, &R, &a, &mod, 0));

    write(1, ((unsigned char*)R.x[0].dp), INPUT_SIZE);
    write(1, ((unsigned char*)R.y[0].dp), INPUT_SIZE);
    write(1, ((unsigned char*)R.z[0].dp), INPUT_SIZE);

    // mp_dump("\necc3: x", key3.pubkey.x, 0);
    // mp_dump("\necc3: y", key3.pubkey.y, 0);
    // mp_dump("\necc3: z", key3.pubkey.z, 0);
    
    wc_ecc_free(&key1);
    wc_ecc_free(&key2);
    wc_ecc_free(&key3);
    return ret;
}
