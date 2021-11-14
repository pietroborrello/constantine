/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Yann Le Corre <yann.lecorre@uni.lu>
 *
 * This file is part of FELICS.
 *
 * FELICS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * FELICS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

/****************************************************************************** 
 *
 * Piccolo common functions
 *
 ******************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#ifdef gem5
#include "../util/m5/m5op.h"
#endif


#define NUMBER_OF_ROUNDS 25
/* SBOX */
uint8_t SBOX[] __attribute__((aligned(64)))=
{
    0x0e, 0x04, 0x0b, 0x02,
    0x03, 0x08, 0x00, 0x09,
    0x01, 0x0a, 0x07, 0x0f,
    0x06, 0x0c, 0x05, 0x0d
};

/* GF[2^4] multiplication by 2 */
uint8_t GF16_MUL2[] __attribute__((aligned(64)))=
{
	0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e,
	0x03, 0x01, 0x07, 0x05, 0x0b, 0x09, 0x0f, 0x0d
};

/* GF[2^4] multiplication by 3 */
uint8_t GF16_MUL3[] __attribute__((aligned(64)))=
{
	0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09,
	0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02
};

uint32_t CON80[] __attribute__((aligned(64)))=
{
    0x293d071c,
    0x253e1f1a,
    0x213f1718,
    0x3d382f16,
    0x39392714,
    0x353a3f12,
    0x313b3710,
    0x0d344f0e,
    0x0935470c,
    0x05365f0a,
    0x01375708,
    0x1d306f06,
    0x19316704,
    0x15327f02,
    0x11337700,
    0x6d2c8f3e,
    0x692d873c,
    0x652e9f3a,
    0x612f9738,
    0x7d28af36,
    0x7929a734,
    0x752abf32,
    0x712bb730,
    0x4d24cf2e,
    0x4925c72c
};


/* calculate p0 + p1 + 2*p2 + 3*p3 in GF[2^4] with caract. poly = x^4 + x + 1 */
inline uint8_t polyEval(uint8_t p0, uint8_t p1, uint8_t p2, uint8_t p3) __attribute__((always_inline))
{
	/* uint8_t y = p0 ^ p1 ^ gf16_mul2(p2) ^ gf16_mul3(p3); */
	uint8_t y = p0 ^ p1 ^ (GF16_MUL2[p2]) ^ (GF16_MUL3[p3]);
	
	return y;
}

inline uint16_t F(uint16_t x) __attribute__((always_inline))
{
    uint8_t x0;
    uint8_t x1;
    uint8_t x2;
    uint8_t x3;
    uint8_t y0;
    uint8_t y1;
    uint8_t y2;
    uint8_t y3;
	

    x3 = (x >>  0) & 0x0f;
    x2 = (x >>  4) & 0x0f;
    x1 = (x >>  8) & 0x0f;
    x0 = (x >> 12) & 0x0f;

    x3 = (SBOX[x3]);
    x2 = (SBOX[x2]);
    x1 = (SBOX[x1]);
    x0 = (SBOX[x0]);

    y0 = polyEval(x2, x3, x0, x1);
    y1 = polyEval(x3, x0, x1, x2);
    y2 = polyEval(x0, x1, x2, x3);
    y3 = polyEval(x1, x2, x3, x0);
    y0 = (SBOX[y0]);
    y1 = (SBOX[y1]);
    y2 = (SBOX[y2]);
    y3 = (SBOX[y3]);

	return (y0 << 12) | (y1 << 8) | (y2 << 4) | y3;
}

inline void RP(uint16_t *x0, uint16_t *x1, uint16_t *x2, uint16_t *x3) __attribute__((always_inline))
{
    uint16_t y0;
    uint16_t y1;
    uint16_t y2;
    uint16_t y3;
	

    y0 = (*x1 & 0xff00) | (*x3 & 0x00ff);
    y1 = (*x2 & 0xff00) | (*x0 & 0x00ff);
    y2 = (*x3 & 0xff00) | (*x1 & 0x00ff);
    y3 = (*x0 & 0xff00) | (*x2 & 0x00ff);
	
    *x0 = y0;
    *x1 = y1;
    *x2 = y2;
    *x3 = y3;
}

void Piccolo_encrypt(uint8_t *roundKeys, uint8_t *block)
{
    uint8_t i;
    uint16_t *x3 = (uint16_t *)block;
    uint16_t *x2 = x3 + 1;
    uint16_t *x1 = x3 + 2;
    uint16_t *x0 = x3 + 3;
    uint16_t *rk = (uint16_t *)roundKeys;

    *x2 ^= (rk[51]);
    *x0 ^= (rk[50]);

    #pragma unroll
    for (i = 0; i < NUMBER_OF_ROUNDS - 1; ++i)
    {
        *x1 = *x1 ^ F(*x0) ^ (rk[2 * i]);
        *x3 = *x3 ^ F(*x2) ^ (rk[2 * i + 1]);
        RP(x0, x1, x2, x3);
    }

    *x1 = *x1 ^ F(*x0) ^ (rk[2*NUMBER_OF_ROUNDS - 2]);
    *x3 = *x3 ^ F(*x2) ^ (rk[2*NUMBER_OF_ROUNDS - 1]);
    *x0 ^= (rk[52]);
    *x2 ^= (rk[53]);
}



void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    uint8_t i;
    uint8_t m;
    uint16_t *mk = (uint16_t *)key;
    uint32_t _rk;
    uint16_t *rk = (uint16_t *)roundKeys;
    uint16_t *wk = (uint16_t *)(&roundKeys[100]);

    wk[0] = (mk[0] & 0xff00) | (mk[1] & 0x00ff);
    wk[1] = (mk[1] & 0xff00) | (mk[0] & 0x00ff);
    wk[2] = (mk[4] & 0xff00) | (mk[3] & 0x00ff);
    wk[3] = (mk[3] & 0xff00) | (mk[4] & 0x00ff);

    m = 0;
    for (i = 0; i < NUMBER_OF_ROUNDS; ++i)
    {
        _rk = CON80[i];
        switch (m)
        {
            case 0:
            case 2:
                _rk ^= *(uint32_t *)(&mk[2]);
                break;
            case 3:
                _rk ^= ((uint32_t)(mk[4]) << 16) | (uint32_t)(mk[4]);
                break;
            case 1:
            case 4:
                _rk ^= *(uint32_t *)(&mk[0]);
                break;
        }
        *(uint32_t *)&rk[2*i] = _rk;
        if (m == 4)
        {
            m = 0;
        }
        else
        {
            m++;
        }
    }
}

static uint8_t in_key[24] = {0xf8, 0x12, 0x7e, 0x00, 0x00, 0x00, 0x6c, 0x7e, 0x81, 0x93, 0xa5, 0xb7, 0xc9, 0xda, 0xec, 0xfe, 0x11, 0x32, 0x53, 0x74, 0x95, 0xb6, 0xd7, 0xf8};
static uint8_t in[64] = {0x00};
static  uint8_t out[64] = {0};

int main(int argc, char *argv[])
{
    uint8_t roundKeys[108];
	read(0, in_key, 24);
	read(0, in, 64);

    // printf("Key is: ");
    // for (i=0;i < key_len;i++) {
    //     if(i>0) printf(", ");
    //     printf("%02X",in_key[i]);
    // }

    // printf("\nInput is: ");
    // for (i=0;i < in_len;i++) {
    //     if(i>0) printf(", ");
    //     printf("%02X",in[i]);
    // }

    RunEncryptionKeySchedule(in_key, roundKeys);
#ifdef gem5            
  
    m5_reset_stats(0, 0);
#endif
    Piccolo_encrypt(roundKeys, in);
#ifdef gem5
    m5_dumpreset_stats(0, 0);
 
#endif  


    // printf("\nCipher text is: ");
    // for (i=0;i < in_len;i++) {
    //     if(i>0) printf(", ");
    //     printf("%02X",in[i]);
    // }
	write(1, in, 64);

    return 0;
}