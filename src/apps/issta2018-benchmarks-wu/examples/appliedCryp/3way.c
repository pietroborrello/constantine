#include <stdint.h>
#include <unistd.h>


#define STRT_E 0x0b0b /* round constant of first encryption round */
#define STRT_D 0xb1b1 /* round constant of first decryption round */
#define NMBR 11 /* number of rounds is 11 */

typedef struct {
	uint32_t k[3],ki[3] , ercon[NMBR+1] ,drcon[NMBR+1];
} twy_ctx;
/* Note: encrypt and decrypt expect full blocks--padding blocks is
caller’s responsibility. All bulk encryption is done in
ECB mode by these calls. Other modes may be added easily
enough. */
/* destroy: Context. */
/* Scrub context of all sensitive data. */
void twy_destroy(twy_ctx *);
/* encrypt: Context, ptr to data block, # of blocks. */
void twy_enc(twy_ctx *, uint32_t *, int);
/* decrypt: Context, ptr to data block, # of blocks. */
void twy_dec(twy_ctx *, uint32_t *, int);
/* key: Context, ptr to key data. */
void twy_key(uint32_t *, twy_ctx *);
/* ACCODE----------------------------------------------------------- */
/* End of AC code prototypes and structures. */
/* ----------------------------------------------------------------- */
void mu(int32_t *a) /* inverts the order of the bits of a */
{
	int i ;
	int32_t b[3] ;
	b[0] = b[1] = b[2] = 0 ;
	for( i=0 ; i<32 ; i++ )
	{
		b[0] <<= 1 ; b[1] <<= 1 ; b[2] <<= 1 ;
		if(a[0]&1) b[2] |= 1 ;
		if(a[1]&1) b[1] |= 1 ;
		if(a[2]&1) b[0] |= 1 ;
		a[0] >>= 1 ; a[1] >>= 1 ; a[2] >>= 1 ;
	}
	a[0] = b[0] ; a[1] = b[1] ; a[2] = b[2] ;
}
void gamma(int32_t *a) /* the nonlinear step */
{
	int32_t b[3] ;
	b[0] = a[0] ^ (a[1]|(~a[2])) ;
	b[1] = a[1] ^ (a[2]|(~a[0])) ;
	b[2] = a[2] ^ (a[0]|(~a[1])) ;
	a[0] = b[0] ; a[1] = b[1] ; a[2] = b[2] ;
}
void theta(int32_t *a) /* the linear step */
{
	int32_t b[3];
	b[0] = a[0] ^ (a[0]>>16) ^ (a[1]<<16) ^ (a[1]>>16) ^ (a[2]<<16) ^
	(a[1]>>24) ^ (a[2]<<8) ^ (a[2]>>8) ^ (a[0]<<24) ^
	(a[2]>>16) ^ (a[0]<<16) ^ (a[2]>>24) ^ (a[0]<<8) ;
	b[1] = a[1] ^ (a[1]>>16) ^ (a[2]<<16) ^ (a[2]>>16) ^ (a[0]<<16) ^
	(a[2]>>24) ^ (a[0]<<8) ^ (a[0]>>8) ^ (a[1]<<24) ^
	(a[0]>>16) ^ (a[1]<<16) ^ (a[0]>>24) ^ (a[1]<<8) ;
	b[2] = a[2] ^ (a[2]>>16) ^ (a[0]<<16) ^ (a[0]>>16) ^ (a[1]<<16) ^
	(a[0]>>24) ^ (a[1]<<8) ^ (a[1]>>8) ^ (a[2]<<24) ^
	(a[1]>>16) ^ (a[2]<<16) ^ (a[1]>>24) ^ (a[2]<<8) ;
	a[0] = b[0] ; a[1] = b[1] ; a[2] = b[2] ;
}
void pi_1(int32_t *a)
{
	a[0] = (a[0]>>10) ^ (a[0]<<22);
	a[2] = (a[2]<<1) ^ (a[2]>>31);
}
void pi_2(int32_t *a)
{
	a[0] = (a[0]<<1) ^ (a[0]>>31);
	a[2] = (a[2]>>10) ^ (a[2]<<22);
}

void rho(int32_t *a) /* the round function */
{
	theta(a) ;
	pi_1(a) ;
	gamma(a) ;
	pi_2(a) ;
}

void rndcon_gen(int32_t strt,int32_t *rtab)
{ /* generates the round constants */
	int i ;
	for(i=0 ; i<=NMBR ; i++ )
	{
		rtab[i] = strt ;
		strt <<= 1 ;
		if( strt&0x10000 ) strt ^= 0x11011 ;
	}
}
/* Modified slightly to fit the caller’s needs. */
void encrypt(twy_ctx *c, int32_t *a)
{
	char i ;
	for( i=0 ; i<NMBR ; i++ )
	{
		a[0] ^= c->k[0] ^ (c->ercon[i]<<16) ;
		a[1] ^= c->k[1] ;
		a[2] ^= c->k[2] ^ c->ercon[i] ;
		rho(a) ;
	}

	a[0] ^= c->k[0] ^ (c->ercon[NMBR]<<16) ;
	a[1] ^= c->k[1] ;
	a[2] ^= c->k[2] ^ c->ercon[NMBR] ;
	theta(a) ;
}
/* Modified slightly to meet caller’s needs. */
void decrypt(twy_ctx *c, int32_t *a)
{
	char i ;
	mu(a) ;
	
	for( i=0 ; i<NMBR ; i++ )
	{
		a[0] ^= c->ki[0] ^ (c->drcon[i]<<16) ;
		a[1] ^= c->ki[1] ;
		a[2] ^= c->ki[2] ^ c->drcon[i] ;
		rho(a) ;
	}
	
	a[0] ^= c->ki[0] ^ (c->drcon[NMBR]<<16) ;
	a[1] ^= c->ki[1] ;
	a[2] ^= c->ki[2] ^ c->drcon[NMBR] ;
	theta(a) ;
	mu(a) ;
}

void twy_key(uint32_t *key, twy_ctx *c){
	c->ki[0] = c->k[0] = key[0];
	c->ki[1] = c->k[1] = key[1];
	c->ki[2] = c->k[2] = key[2];
	theta(c->ki);
	mu(c->ki);
	rndcon_gen(STRT_E,c->ercon);
	rndcon_gen(STRT_D,c->drcon);
}
/* Encrypt in ECB mode. */
void twy_enc(twy_ctx *c, uint32_t *data, int blkcnt){
	uint32_t *d;
	int i;
	d = data;
	for(i=0;i<blkcnt;i++) {
		encrypt(c,d);
		d +=3;
	}
}
/* Decrypt in ECB mode. */
void twy_dec(twy_ctx *c, uint32_t *data, int blkcnt){
	uint32_t *d;
	int i;
	d = data;
	for(i=0;i<blkcnt;i++){
		decrypt(c,d);
		d+=3;
	}	
}
/* Scrub sensitive values from memory before deallocating. */
// void twy_destroy(twy_ctx *c){
// 	int i;
// 	for(i=0;i<3;i++) c->k[i] = c->ki[i] = 0;
// 	}
// 	void printvec(char *chrs, int32_t *d){
// 	printf("%20s : %08lx %08lx %08lx \n",chrs,d[2],d[1],d[0]);
// }


static uint32_t in_key[3] __attribute__((aligned(64))) = {0xffffffff, 0xffffffff, 0xffffffff};
static uint32_t in[3] __attribute__((aligned(64))) = {0};

int main(int argc, char *argv[])
{
	read(0, in_key, 12);
	read(0, in, 12);
	twy_ctx gc;
	twy_key(in_key, &gc);	
	encrypt(&gc,in);
	write(1, in, 12);
}