#include <stdint.h>
#include <unistd.h>


#define EN0 0 /* MODE == encrypt */
#define DE1 1 /* MODE == decrypt */
typedef struct {
    uint32_t ek[32];
    uint32_t dk[32];
} des_ctx;
/* hexkey[8] MODE
* Sets the internal key register according to the hexadecimal
* key contained in the 8 bytes of hexkey, according to the DES,
* for encryption or decryption according to MODE.
*/

/* cookedkey[32]
* Loads the internal key register with the data in cookedkey.
*/

/* cookedkey[32]
* Copies the contents of the internal key register into the storage
* located at &cookedkey[0].
*/

/* from[8] to[8]
* Encrypts/Decrypts (according to the key currently loaded in the
* internal key register) one block of eight bytes at address 鈥榝rom->* into the block at address 鈥榯o-> They can be the same.
*/
static void desfunc(uint32_t *, uint32_t *);
static void cookey(uint32_t *);
static uint32_t KnL[32] __attribute__((aligned(64))) = { 0L };
static uint32_t KnR[32] __attribute__((aligned(64))) = { 0L };
static uint32_t Kn3[32] __attribute__((aligned(64))) = { 0L };
static unsigned char Df_Key[24] __attribute__((aligned(64))) = {
0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67 };
static unsigned short bytebit[8] __attribute__((aligned(64))) = {
0200, 0100, 040, 020, 010, 04, 02, 01 };
static uint32_t bigbyte[24] __attribute__((aligned(64))) = {
0x800000L, 0x400000L, 0x200000L, 0x100000L,
0x80000L, 0x40000L, 0x20000L, 0x10000L,
0x8000L, 0x4000L, 0x2000L, 0x1000L,
0x800L, 0x400L, 0x200L, 0x100L,
0x80L, 0x40L, 0x20L, 0x10L,
0x8L, 0x4L, 0x2L, 0x1L };
/* Use the key schedule specified in the Standard (ANSI X3.92->981). */
static unsigned char pc1[56] __attribute__((aligned(64))) = {
56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17,
9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35,
62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3 };
static unsigned char totrot[16] __attribute__((aligned(64))) = {
1,2,4,6,8,10,12,14,15,17,19,21,23,25,27,28 };
static unsigned char pc2[48] __attribute__((aligned(64))) = {
13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9,
22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1,
40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31 };

inline void cpkey(register uint32_t *into) __attribute__((always_inline))
{
    // register uint32_t *from, *endp;
    // from = KnL, endp = &KnL[32];
    // while( from < endp ) *into++ = *from++;
    int i;
    for(i=0; i<32; i++)
        into[i] = KnL[i];
    return;
}
inline void usekey(register uint32_t *from) __attribute__((always_inline))
{
    // register uint32_t *to, *endp;
    // to = KnL, endp = &KnL[32];
    // while( to < endp ) *to++ = *from++;
    int i;
    for(i=0; i<32; i++)
        KnL[i] = from[i];
    return;
}

static void cookey(register uint32_t *raw1)
{
    register uint32_t *cook, *raw0;
    uint32_t dough[32];
    register int i;
    cook = dough;
    for( i = 0; i < 16; i++, raw1++ ) {
        raw0 = raw1++;
        *cook = (*raw0 & 0x00fc0000L) << 6;
        *cook |= (*raw0 & 0x00000fc0L) << 10;
        *cook |= (*raw1 & 0x00fc0000L) >> 10;
        *cook++ |= (*raw1 & 0x00000fc0L) >> 6;
        *cook = (*raw0 & 0x0003f000L) << 12;
        *cook |= (*raw0 & 0x0000003fL) << 16;
        *cook |= (*raw1 & 0x0003f000L) >> 4;
        *cook++ |= (*raw1 & 0x0000003fL);
    }
    usekey(dough);
    return;
}

void deskey(unsigned char *key, short edf) /* Thanks to James Gillogly & Phil Karn! */
{
    register int i, j, l, m, n;
    unsigned char pc1m[56], pcr[56];
    uint32_t kn[32];
    for ( j = 0; j < 56; j++ ) {
        l = pc1[j];
        m = l & 07;
        pc1m[j] = (key[l >> 3] & bytebit[m]) ? 1 : 0;
    }
    for( i = 0; i < 16; i++ ) {
        if( edf == DE1 ) m = (15 - i) << 1;
        else m = i << 1;
        n = m + 1;
        kn[m] = kn[n] = 0L;
        for( j = 0; j < 28; j++ ) {
            l = j + totrot[i];
            if( l < 28 ) pcr[j] = pc1m[l];
            else pcr[j] = pc1m[l - 28];
        }
        for( j = 28; j < 56; j++ ) {
            l = j + totrot[i];
            if( l < 56 ) pcr[j] = pc1m[l];
            else pcr[j] = pc1m[l - 28];
        }
        for( j = 0; j < 24; j++ ) {
            if( pcr[pc2[j]] ) kn[m] |= bigbyte[j];
            if( pcr[pc2[j+24]] ) kn[n] |= bigbyte[j];
        }
    }
    cookey(kn);
    return;
}

inline void scrunch(register unsigned char *outof, register uint32_t *into) __attribute__((always_inline))
{
    *into = (*outof++ & 0xffL) << 24;
    *into |= (*outof++ & 0xffL) << 16;
    *into |= (*outof++ & 0xffL) << 8;
    *into++ |= (*outof++ & 0xffL);
    *into = (*outof++ & 0xffL) << 24;
    *into |= (*outof++ & 0xffL) << 16;
    *into |= (*outof++ & 0xffL) << 8;
    *into |= (*outof & 0xffL);
    return;
}
void unscrun(register uint32_t *outof, register unsigned char *into)
{
    *into++ = (*outof >> 24) & 0xffL;
    *into++ = (*outof >> 16) & 0xffL;
    *into++ = (*outof >> 8) & 0xffL;
    *into++ = *outof++ & 0xffL;
    *into++ = (*outof >> 24) & 0xffL;
    *into++ = (*outof >> 16) & 0xffL;
    *into++ = (*outof >> 8) & 0xffL;
    *into = *outof & 0xffL;
    return;
}

void des(unsigned char *inblock, unsigned char *outblock)
{
    uint32_t work[2];
    scrunch(inblock, work);
    desfunc(KnL, work);
    unscrun(work, outblock);
    return;
}



static uint32_t SP1[64]  __attribute__((aligned(64))) = {
    0x01010400L, 0x00000000L, 0x00010000L, 0x01010404L,
    0x01010004L, 0x00010404L, 0x00000004L, 0x00010000L,
    0x00000400L, 0x01010400L, 0x01010404L, 0x00000400L,
    0x01000404L, 0x01010004L, 0x01000000L, 0x00000004L,
    0x00000404L, 0x01000400L, 0x01000400L, 0x00010400L,
    0x00010400L, 0x01010000L, 0x01010000L, 0x01000404L,
    0x00010004L, 0x01000004L, 0x01000004L, 0x00010004L,
    0x00000000L, 0x00000404L, 0x00010404L, 0x01000000L,
    0x00010000L, 0x01010404L, 0x00000004L, 0x01010000L,
    0x01010400L, 0x01000000L, 0x01000000L, 0x00000400L,
    0x01010004L, 0x00010000L, 0x00010400L, 0x01000004L,
    0x00000400L, 0x00000004L, 0x01000404L, 0x00010404L,
    0x01010404L, 0x00010004L, 0x01010000L, 0x01000404L,
    0x01000004L, 0x00000404L, 0x00010404L, 0x01010400L,
    0x00000404L, 0x01000400L, 0x01000400L, 0x00000000L,
    0x00010004L, 0x00010400L, 0x00000000L, 0x01010004L };
static uint32_t SP2[64]  __attribute__((aligned(64))) = {
    0x80108020L, 0x80008000L, 0x00008000L, 0x00108020L,
    0x00100000L, 0x00000020L, 0x80100020L, 0x80008020L,
    0x80000020L, 0x80108020L, 0x80108000L, 0x80000000L,
    0x80008000L, 0x00100000L, 0x00000020L, 0x80100020L,
    0x00108000L, 0x00100020L, 0x80008020L, 0x00000000L,
    0x80000000L, 0x00008000L, 0x00108020L, 0x80100000L,
    0x00100020L, 0x80000020L, 0x00000000L, 0x00108000L,
    0x00008020L, 0x80108000L, 0x80100000L, 0x00008020L,
    0x00000000L, 0x00108020L, 0x80100020L, 0x00100000L,
    0x80008020L, 0x80100000L, 0x80108000L, 0x00008000L,
    0x80100000L, 0x80008000L, 0x00000020L, 0x80108020L,
    0x00108020L, 0x00000020L, 0x00008000L, 0x80000000L,
    0x00008020L, 0x80108000L, 0x00100000L, 0x80000020L,
    0x00100020L, 0x80008020L, 0x80000020L, 0x00100020L,
    0x00108000L, 0x00000000L, 0x80008000L, 0x00008020L,
    0x80000000L, 0x80100020L, 0x80108020L, 0x00108000L };
static uint32_t SP3[64]  __attribute__((aligned(64))) = {
    0x00000208L, 0x08020200L, 0x00000000L, 0x08020008L,
    0x08000200L, 0x00000000L, 0x00020208L, 0x08000200L,
    0x00020008L, 0x08000008L, 0x08000008L, 0x00020000L,
    0x08020208L, 0x00020008L, 0x08020000L, 0x00000208L,
    0x08000000L, 0x00000008L, 0x08020200L, 0x00000200L,
    0x00020200L, 0x08020000L, 0x08020008L, 0x00020208L,
    0x08000208L, 0x00020200L, 0x00020000L, 0x08000208L,
    0x00000008L, 0x08020208L, 0x00000200L, 0x08000000L,
    0x08020200L, 0x08000000L, 0x00020008L, 0x00000208L,
    0x00020000L, 0x08020200L, 0x08000200L, 0x00000000L,
    0x00000200L, 0x00020008L, 0x08020208L, 0x08000200L,
    0x08000008L, 0x00000200L, 0x00000000L, 0x08020008L,
    0x08000208L, 0x00020000L, 0x08000000L, 0x08020208L,
    0x00000008L, 0x00020208L, 0x00020200L, 0x08000008L,
    0x08020000L, 0x08000208L, 0x00000208L, 0x08020000L,
    0x00020208L, 0x00000008L, 0x08020008L, 0x00020200L };
static uint32_t SP4[64]  __attribute__((aligned(64))) = {
    0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
    0x00802080L, 0x00800081L, 0x00800001L, 0x00002001L,
    0x00000000L, 0x00802000L, 0x00802000L, 0x00802081L,
    0x00000081L, 0x00000000L, 0x00800080L, 0x00800001L,
    0x00000001L, 0x00002000L, 0x00800000L, 0x00802001L,
    0x00000080L, 0x00800000L, 0x00002001L, 0x00002080L,
    0x00800081L, 0x00000001L, 0x00002080L, 0x00800080L,
    0x00002000L, 0x00802080L, 0x00802081L, 0x00000081L,
    0x00800080L, 0x00800001L, 0x00802000L, 0x00802081L,
    0x00000081L, 0x00000000L, 0x00000000L, 0x00802000L,
    0x00002080L, 0x00800080L, 0x00800081L, 0x00000001L,
    0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
    0x00802081L, 0x00000081L, 0x00000001L, 0x00002000L,
    0x00800001L, 0x00002001L, 0x00802080L, 0x00800081L,
    0x00002001L, 0x00002080L, 0x00800000L, 0x00802001L,
    0x00000080L, 0x00800000L, 0x00002000L, 0x00802080L };
static uint32_t SP5[64]  __attribute__((aligned(64))) = {
    0x00000100L, 0x02080100L, 0x02080000L, 0x42000100L,
    0x00080000L, 0x00000100L, 0x40000000L, 0x02080000L,
    0x40080100L, 0x00080000L, 0x02000100L, 0x40080100L,
    0x42000100L, 0x42080000L, 0x00080100L, 0x40000000L,
    0x02000000L, 0x40080000L, 0x40080000L, 0x00000000L,
    0x40000100L, 0x42080100L, 0x42080100L, 0x02000100L,
    0x42080000L, 0x40000100L, 0x00000000L, 0x42000000L,
    0x02080100L, 0x02000000L, 0x42000000L, 0x00080100L,
    0x00080000L, 0x42000100L, 0x00000100L, 0x02000000L,
    0x40000000L, 0x02080000L, 0x42000100L, 0x40080100L,
    0x02000100L, 0x40000000L, 0x42080000L, 0x02080100L,
    0x40080100L, 0x00000100L, 0x02000000L, 0x42080000L,
    0x42080100L, 0x00080100L, 0x42000000L, 0x42080100L,
    0x02080000L, 0x00000000L, 0x40080000L, 0x42000000L,
    0x00080100L, 0x02000100L, 0x40000100L, 0x00080000L,
    0x00000000L, 0x40080000L, 0x02080100L, 0x40000100L };
static uint32_t SP6[64]  __attribute__((aligned(64))) = {
    0x20000010L, 0x20400000L, 0x00004000L, 0x20404010L,
    0x20400000L, 0x00000010L, 0x20404010L, 0x00400000L,
    0x20004000L, 0x00404010L, 0x00400000L, 0x20000010L,
    0x00400010L, 0x20004000L, 0x20000000L, 0x00004010L,
    0x00000000L, 0x00400010L, 0x20004010L, 0x00004000L,
    0x00404000L, 0x20004010L, 0x00000010L, 0x20400010L,
    0x20400010L, 0x00000000L, 0x00404010L, 0x20404000L,
    0x00004010L, 0x00404000L, 0x20404000L, 0x20000000L,
    0x20004000L, 0x00000010L, 0x20400010L, 0x00404000L,
    0x20404010L, 0x00400000L, 0x00004010L, 0x20000010L,
    0x00400000L, 0x20004000L, 0x20000000L, 0x00004010L,
    0x20000010L, 0x20404010L, 0x00404000L, 0x20400000L,
    0x00404010L, 0x20404000L, 0x00000000L, 0x20400010L,
    0x00000010L, 0x00004000L, 0x20400000L, 0x00404010L,
    0x00004000L, 0x00400010L, 0x20004010L, 0x00000000L,
    0x20404000L, 0x20000000L, 0x00400010L, 0x20004010L };
static uint32_t SP7[64]  __attribute__((aligned(64))) = {
    0x00200000L, 0x04200002L, 0x04000802L, 0x00000000L,
    0x00000800L, 0x04000802L, 0x00200802L, 0x04200800L,
    0x04200802L, 0x00200000L, 0x00000000L, 0x04000002L,
    0x00000002L, 0x04000000L, 0x04200002L, 0x00000802L,
    0x04000800L, 0x00200802L, 0x00200002L, 0x04000800L,
    0x04000002L, 0x04200000L, 0x04200800L, 0x00200002L,
    0x04200000L, 0x00000800L, 0x00000802L, 0x04200802L,
    0x00200800L, 0x00000002L, 0x04000000L, 0x00200800L,
    0x04000000L, 0x00200800L, 0x00200000L, 0x04000802L,
    0x04000802L, 0x04200002L, 0x04200002L, 0x00000002L,
    0x00200002L, 0x04000000L, 0x04000800L, 0x00200000L,
    0x04200800L, 0x00000802L, 0x00200802L, 0x04200800L,
    0x00000802L, 0x04000002L, 0x04200802L, 0x04200000L,
    0x00200800L, 0x00000000L, 0x00000002L, 0x04200802L,
    0x00000000L, 0x00200802L, 0x04200000L, 0x00000800L,
    0x04000002L, 0x04000800L, 0x00000800L, 0x00200002L };
static uint32_t SP8[64]  __attribute__((aligned(64))) = {
    0x10001040L, 0x00001000L, 0x00040000L, 0x10041040L,
    0x10000000L, 0x10001040L, 0x00000040L, 0x10000000L,
    0x00040040L, 0x10040000L, 0x10041040L, 0x00041000L,
    0x10041000L, 0x00041040L, 0x00001000L, 0x00000040L,
    0x10040000L, 0x10000040L, 0x10001000L, 0x00001040L,
    0x00041000L, 0x00040040L, 0x10040040L, 0x10041000L,
    0x00001040L, 0x00000000L, 0x00000000L, 0x10040040L,
    0x10000040L, 0x10001000L, 0x00041040L, 0x00040000L,
    0x00041040L, 0x00040000L, 0x10041000L, 0x00001000L,
    0x00000040L, 0x10040040L, 0x00001000L, 0x00041040L,
    0x10001000L, 0x00000040L, 0x10000040L, 0x10040000L,
    0x10040040L, 0x10000000L, 0x00040000L, 0x10001040L,
    0x00000000L, 0x10041040L, 0x00040040L, 0x10000040L,
    0x10040000L, 0x10001000L, 0x10001040L, 0x00000000L,
    0x10041040L, 0x00041000L, 0x00041000L, 0x00001040L,
    0x00001040L, 0x00040040L, 0x10000000L, 0x10041000L };
static void desfunc(register uint32_t *keys, register uint32_t *block)
{
    register uint32_t fval, work, right, leftt;
    register int round;
    leftt = block[0];
    right = block[1];
    work = ((leftt >> 4) ^ right) & 0x0f0f0f0fL;
    right ^= work;
    leftt ^= (work << 4);
    work = ((leftt >> 16) ^ right) & 0x0000ffffL;
    right ^= work;
    leftt ^= (work << 16);
    work = ((right >> 2) ^ leftt) & 0x33333333L;
    leftt ^= work;
    right ^= (work << 2);
    work = ((right >> 8) ^ leftt) & 0x00ff00ffL;
    leftt ^= work;
    right ^= (work << 8);
    right = ((right << 1) | ((right >> 31) & 1L)) & 0xffffffffL;
    work = (leftt ^ right) & 0xaaaaaaaaL;
    leftt ^= work;
    right ^= work;
    leftt = ((leftt << 1) | ((leftt >> 31) & 1L)) & 0xffffffffL;

    #pragma unroll
    for( round = 0; round < 8; round++ ) {
        work = (right << 28) | (right >> 4);
        work ^= *keys++;
        fval = SP7[ work & 0x3fL];
        fval |= SP5[(work >> 8) & 0x3fL];
        fval |= SP3[(work >> 16) & 0x3fL];
        fval |= SP1[(work >> 24) & 0x3fL];
        work = right ^ *keys++;
        fval |= SP8[ work & 0x3fL];
        fval |= SP6[(work >> 8) & 0x3fL];
        fval |= SP4[(work >> 16) & 0x3fL];
        fval |= SP2[(work >> 24) & 0x3fL];
        leftt ^= fval;
        work = (leftt << 28) | (leftt >> 4);
        work ^= *keys++;
        fval = SP7[ work & 0x3fL];
        fval |= SP5[(work >> 8) & 0x3fL];
        fval |= SP3[(work >> 16) & 0x3fL];
        fval |= SP1[(work >> 24) & 0x3fL];
        work = leftt ^ *keys++;
        fval |= SP8[ work & 0x3fL];
        fval |= SP6[(work >> 8) & 0x3fL];
        fval |= SP4[(work >> 16) & 0x3fL];
        fval |= SP2[(work >> 24) & 0x3fL];
        right ^= fval;
    }
    
    right = (right << 31) | (right >> 1);
    work = (leftt ^ right) & 0xaaaaaaaaL;
    leftt ^= work;
    right ^= work;
    leftt = (leftt << 31) | (leftt >> 1);
    work = ((leftt >> 8) ^ right) & 0x00ff00ffL;
    right ^= work;
    leftt ^= (work << 8);
    work = ((leftt >> 2) ^ right) & 0x33333333L;
    right ^= work;
    leftt ^= (work << 2);
    work = ((right >> 16) ^ leftt) & 0x0000ffffL;
    leftt ^= work;
    right ^= (work << 16);
    work = ((right >> 4) ^ leftt) & 0x0f0f0f0fL;
    leftt ^= work;
    right ^= (work << 4);
    *block++ = right;
    *block = leftt;
    return;
}
/* Validation sets:
*
* Single鈥搇ength key, single鈥搇ength plaintext ->* Key : 0123 4567 89ab cdef
* Plain : 0123 4567 89ab cde7
* Cipher : c957 4425 6a5e d31d
*
**********************************************************************/
inline void des_key(des_ctx *dc, unsigned char *key) __attribute__((always_inline))
{
    deskey(key,EN0);
    cpkey(dc->ek);
    //deskey(key,DE1);
    // cpkey(dc->dk);
}
/* Encrypt several blocks in ECB mode. Caller is responsible for
short blocks. */
void des_enc(des_ctx *dc, unsigned char *data, int blocks){
    uint32_t work[2];
    int i;
    unsigned char *cp;
    cp = data;
    for(i=0;i<blocks;i++){
        scrunch(cp,work);
        desfunc(dc->ek, work);
        unscrun(work,cp);
        cp+=8;
    }
}
void des_dec(des_ctx *dc, unsigned char *data, int blocks){
    uint32_t work[2];
    int i;
    unsigned char *cp;
    cp = data;
    for(i=0;i<blocks;i++){
        scrunch(cp,work);
        desfunc(dc->dk,work);
        unscrun(work,cp);
        cp+=8;
    }
}


static uint8_t in_key[32]  __attribute__((aligned(64)))= {21, 135, 185, 105, 110, 132, 146, 231, 225, 45, 146, 19, 138, 13, 31, 42, 43, 135, 184, 109, 27, 69, 99, 68, 119, 3, 147, 103, 42, 162, 54, 82};
static char in[8] __attribute__((aligned(64)))= {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xe7};
static char out[8] __attribute__((aligned(64))) = {0};
int main(int argc, char *argv[])
{
	read(0, in_key, 32);
	read(0, in, 8);
    des_ctx dc = {0};
    uint32_t work[2] = {0};

    //des_key(&dc,key);
    deskey(in_key,EN0);
    cpkey(dc.ek);
    scrunch(in,work);
    desfunc(dc.ek, work);
    unscrun(work,out);
	write(1, out, 8);
}

// int main(int argc, char *argv[]){
//     des_ctx dc;
//     int i;
//     uint32_t data[10];
//     char *cp,key[8] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
//     char x[8] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xe7};
//     cp = x;
//     des_key(&dc,key);
//     des_enc(&dc,cp,1);
//     printf("Enc(0..7,0..7) = ");
//     for(i=0;i<8;i++) printf("%02x ", ((unsigned int) cp[i])&0x00ff);
//     printf("\n");
//     des_dec(&dc,cp,1);
//     printf("Dec(above,0..7) = ");
//     for(i=0;i<8;i++) printf("%02x ",((unsigned int)cp[i])&0x00ff);
//     printf("\n");
//     cp = (char *) data;
//     for(i=0;i<10;i++)data[i]=i;
//     des_enc(&dc,cp,5); /* Enc 5 blocks. */
//     for(i=0;i<10;i+=2) printf("Block %01d = %08lx %08lx.\n", i/2,data[i],data[i+1]);
//     des_dec(&dc,cp,1);
//     des_dec(&dc,cp+8,4);
//     for(i=0;i<10;i+=2) printf("Block %01d = %08lx %08lx.\n", i/2,data[i],data[i+1]);
// }

