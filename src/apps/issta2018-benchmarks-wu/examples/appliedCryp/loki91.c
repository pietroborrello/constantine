#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

#define LOKIBLK 8 /* No of bytes in a LOKI data-block */
#define ROUNDS 16 /* No of LOKI rounds */

// extern int32_t lokikey[2]; /* 64-bit key used by LOKI routines */
// extern char *loki_lib_ver; /* String with version no. & copyright */


char P[32] __attribute__((aligned(64))) = {
	31, 23, 15, 7, 30, 22, 14, 6,
	29, 21, 13, 5, 28, 20, 12, 4,
	27, 19, 11, 3, 26, 18, 10, 2,
	25, 17, 9, 1, 24, 16, 8, 0
};

typedef struct {
	short gen; /* irreducible polynomial used in this field */
	short exp; /* exponent used to generate this s function */
} sfn_desc;

sfn_desc sfn[] __attribute__((aligned(64)))= {
	{ /* 101110111 */ 375, 31}, { /* 101111011 */ 379, 31},
	{ /* 110000111 */ 391, 31}, { /* 110001011 */ 395, 31},
	{ /* 110001101 */ 397, 31}, { /* 110011111 */ 415, 31},
	{ /* 110100011 */ 419, 31}, { /* 110101001 */ 425, 31},
	{ /* 110110001 */ 433, 31}, { /* 110111101 */ 445, 31},
	{ /* 111000011 */ 451, 31}, { /* 111001111 */ 463, 31},
	{ /* 111010111 */ 471, 31}, { /* 111011101 */ 477, 31},
	{ /* 111100111 */ 487, 31}, { /* 111110011 */ 499, 31},
	{ 00, 00} };

typedef struct {
	int32_t loki_subkeys[ROUNDS];
	} loki_ctx;

static int32_t f(); /* declare LOKI function f */
static short s(); /* declare LOKI S-box fn s */

#define ROL12(b) b = ((b << 12) | (b >> 20));
#define ROL13(b) b = ((b << 13) | (b >> 19));
	
#ifdef LITTLE_ENDIAN	
#define bswap(cb) { \
	register char c; \
	c = cb[0]; cb[0] = cb[3]; cb[3] = c; \
	c = cb[1]; cb[1] = cb[2]; cb[2] = c; \
	c = cb[4]; cb[4] = cb[7]; cb[7] = c; \
	c = cb[5]; cb[5] = cb[6]; cb[6] = c; \
}
#endif

void setlokikey(char *key, loki_ctx *c)
{
	register i;
	register int32_t KL, KR;
	#ifdef LITTLE_ENDIAN
	bswap(key); /* swap bytes round if little-endian */
	#endif
	KL = ((int32_t *)key)[0];
	KR = ((int32_t *)key)[1];
	for (i=0; i<ROUNDS; i+=4) { /* Generate the 16 subkeys */
		c->loki_subkeys[i] = KL;
		ROL12 (KL);
		c->loki_subkeys[i+1] = KL;
		ROL13 (KL);
		c->loki_subkeys[i+2] = KR;
		ROL12 (KR);
		c->loki_subkeys[i+3] = KR;
		ROL13 (KR);
	}
	#ifdef LITTLE_ENDIAN
	bswap(key); /* swap bytes back if little-endian */
	#endif
}

void enloki (loki_ctx *c, char *b)
{
	register i;
	register int32_t L, R; /* left & right data halves */
	#ifdef LITTLE_ENDIAN
	bswap(b); /* swap bytes round if little-endian */
	#endif
	L = ((int32_t *)b)[0];
	R = ((int32_t *)b)[1];
	for (i=0; i<ROUNDS; i+=2) { /* Encrypt with the 16 subkeys */
		L ^= f(R, c->loki_subkeys[i]);
		R ^= f(L, c->loki_subkeys[i+1]);
	}
	((int32_t *)b)[0] = R; /* Y = swap(LR) */
	((int32_t *)b)[1] = L;
	#ifdef LITTLE_ENDIAN
	bswap(b); /* swap bytes round if little-endian */
	#endif
}

void deloki(loki_ctx *c, char *b)
{
	register i;
	register int32_t L, R; /* left & right data halves */
	
	#ifdef LITTLE_ENDIAN
	bswap(b); /* swap bytes round if little-endian */
	#endif
	
	L = ((int32_t *)b)[0]; /* LR = X XOR K */
	R = ((int32_t *)b)[1];
	for (i=ROUNDS; i>0; i-=2) { /* subkeys in reverse order */
		L ^= f(R, c->loki_subkeys[i-1]);
		R ^= f(L, c->loki_subkeys[i-2]);
	}
	((int32_t *)b)[0] = R; /* Y = LR XOR K */
	((int32_t *)b)[1] = L;
}


#define MSB 0x80000000L /* MSB of 32-bit word */

void perm32(int32_t *in, /* Input 32-bit block after permutation */
			int32_t *out, /* Output 32-bit block to be permuted */	   
		    char perm[32]) /* Permutation array */
{
	int32_t mask = MSB; /* mask used to set bit in output */
	register int i, o, b; /* input bit no, output bit no, value */
	register char *p = perm; /* ptr to permutation array */
	*out = 0; /* clear output block */

	for (o=0; o<32; o++) { /* For each output bit position o */
		i =(int)*p++; /* get input bit permuted to output o */
		b = (*in >> i) & 01; /* value of input bit i */
		if (b) /* If the input bit i is set */
			*out |= mask; /* OR in mask to output i */
		mask >>= 1; /* Shift mask to next bit */
	}
}

#define MASK12 0x0fff /* 12 bit mask for expansion E */

static int32_t	f( register int32_t r, /* Data value R(i-1) */
				int32_t k) /* Key K(i) */
{
	int32_t a, b, c; /* 32 bit S-box output, & P output */
	a = r ^ k; /* A = R(i-1) XOR K(i) */
	/* want to use slow speed/small size version */
	b = ((int32_t)s((a & MASK12)) ) | /* B = S(E(R(i-1))^K(i)) */
	((int32_t)s(((a >> 8) & MASK12)) << 8) |
	((int32_t)s(((a >> 16) & MASK12)) << 16) |
	((int32_t)s((((a >> 24) | (a << 8)) & MASK12)) << 24);
	perm32(&b, &c, P); /* C = P(S( E(R(i-1)) XOR K(i))) */
	return(c); /* f returns the result C */
}


#define SIZE 256 /* 256 elements in GF(2^8) */

short mult8(short a, short b, /* operands for multiply */
			short gen /* irreducible polynomial generating Galois Field */)
{
	short product = 0; /* result of multiplication */
	// while(b != 0) 
	for(int i=0; i<16; i++) //use for loop instead of undeterministic while loop
	{ /* while multiplier is non-zero */
		if (b & 01)
			product ^= a; /* add multiplicand if LSB of b set */
		a <<= 1; /* shift multiplicand one place */
		if (a >= SIZE)
			a ^= gen; /* and modulo reduce if needed */
			b >>= 1; /* shift multiplier one place */
	}
	return(product);
}

short exp8(short base, /* base of exponentiation */ 
			short exponent, /* exponent */
			short gen /* irreducible polynomial generating Galois Field */)
{
	short accum = base; /* superincreasing sequence of base */
	short result = 1; /* result of exponentiation */
	if (base == 0) /* if zero base specified then */
		return(0); /* the result is "0" if base = 0 */
	
	//while (exponent != 0) 
	for(int i=0; i<16; i++) //use for loop instead of undeterministic while loop
	{ /* repeat while exponent non-zero */
		if (( exponent & 0x0001) == 0x0001) /* multiply if exp 1 */
			result = mult8(result, accum, gen);
		exponent >>= 1; /* shift exponent to next digit */
		accum = mult8(accum, accum, gen); /* & square */
	}
	return(result);
}

static short s(register int32_t i) /* return S-box value for input i */
{
	register short r, c, v, t;
	r = ((i>>8) & 0xc) | (i & 0x3); /* row value-top 2 & bottom 2 */
	c = (i>>2) & 0xff; /* column value-middle 8 bits */
	t = (c + ((r * 17) ^ 0xff)) & 0xff; /* base value for Sfn */
	v = exp8(t, sfn[r].exp, sfn[r].gen); /* Sfn[r] = t ^ exp mod gen */
	return(v);
}

// void loki_key(loki_ctx *c, unsigned char *key){
// 		setlokikey(c,key);
// }

// void loki_enc(loki_ctx *c, unsigned char *data, int blocks){
// 	unsigned char *cp;
// 	int i;
// 	cp = data;
// 	for(i=0;i<blocks;i++){
// 		enloki(c,cp);
// 		cp+=8;
// 	}
// }

// void loki_dec(loki_ctx *c, unsigned char *data, int blocks){
// 	unsigned char *cp;
// 	int i;
// 	cp = data;
// 	for(i=0;i<blocks;i++){
// 		deloki(c,cp);
// 		cp+=8;
// 	}
// }

static uint8_t in_key[24]  __attribute__((aligned(64))) = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
static char in[8] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xe7};
int main(int argc, char *argv[]){
	read(0, in_key, 24);
	read(0, in, 8);
	loki_ctx lc;
	setlokikey(in_key, &lc);
	enloki(&lc,in);
	write(1, in, 8);
}