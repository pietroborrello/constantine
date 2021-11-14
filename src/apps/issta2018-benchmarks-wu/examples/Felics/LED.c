/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Johann Großschädl <johann.groszschaedl@uni.lu>
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

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#define NUMBER_OF_ROUNDS 48
#define ROUND_KEYS_SIZE 20

uint8_t sbox[16] __attribute__((aligned(64)))= {12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2};
uint8_t MixColMatrix[4][4] __attribute__((aligned(64)))= {
	{  4,  1,  2,  2 },
	{  8,  6,  5,  6 },
	{ 11, 14, 10,  9 },
	{  2,  2, 15, 11 },
};
uint8_t RC[48] __attribute__((aligned(64)))= {
		0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
		0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
		0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
		0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
		0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04
};

uint8_t FieldMult(uint8_t b, uint8_t a)
{
	const uint8_t ReductionPoly = 0x3;
	uint8_t x = a, ret = 0;
	uint8_t i =1;
	
	
	//for(i = 0; i < 4; i++) 
	{
		if((b >> i) & 1) 
		{
			ret ^= x;
		}
		// if(x & 0x8) 
		{
			x <<= 1;
			x ^= ReductionPoly;
		}
		// else
		// {
		// 	x <<= 1;
		// }
	}

	return ret&0xF;
}

void SubCell(uint8_t state[4][4]) 
{
	uint8_t i, j;
	
	for(i = 0; i < 4; i++)
	{
		for(j = 0; j <  4; j++)
		{
			state[i][j] = sbox[state[i][j]];
		}
	}
}

void ShiftRow(uint8_t state[4][4])
{
	uint8_t i, j;
	uint8_t tmp[4];

	
	for(i = 1; i < 4; i++) 
	{
		for(j = 0; j < 4; j++)
		{
			tmp[j] = state[i][j];
		}
		
		for(j = 0; j < 4; j++)
		{
			/* Modified from tmp[(j + i) % 4] */
			state[i][j] = tmp[(j+i)&3];
		}
	}
}

void MixColumn(uint8_t state[4][4])
{
	uint8_t i, j, k;
	uint8_t sum, tmp[4];

	for(j = 0; j < 4; j++)
	{
		for(i = 0; i < 4; i++) 
		{
			sum = 0;
			for(k = 0; k < 4; k++)
			{
				sum ^= FieldMult(state[k][j], MixColMatrix[i][k]);
			}
			tmp[i] = sum;
		}
		for(i = 0; i < 4; i++)
		{
			state[i][j] = tmp[i];
		}
	}
}

inline void AddKey(uint8_t state[4][4], uint8_t* keyBytes, uint8_t half) __attribute__((always_inline))
{
	uint8_t i, j;

	for(i = 0; i < 4; i++)
	{
		for(j = 0; j < 4; j++)
		{
			state[i][j] ^= (keyBytes[(4 * i + j + half * 16) % ROUND_KEYS_SIZE]);
		}
	}
}

void AddConstants(uint8_t state[4][4], uint8_t r)
{
	uint8_t tmp;
  
	/* Added from reference implementation and merged with the above code */
	state[0][0] ^= 5;   /* (    ((KEY_SIZE>>1) & 0xf)); */
	state[1][0] ^= 4;   /* (1 ^ ((KEY_SIZE>>1) & 0xf)); */
	state[2][0] ^= 2;   /* (2 ^ ((KEY_SIZE<<3) & 0xf)); */
	state[3][0] ^= 3;   /* (3 ^ ((KEY_SIZE<<3) & 0xf)); */
  
	tmp = (RC[r] >> 3) & 7;
	state[0][1] ^= tmp;
	state[2][1] ^= tmp;

	tmp = RC[r] & 7;
	state[1][1] ^= tmp;
	state[3][1] ^= tmp;
}



void LED_encrypt(uint8_t *keyBytes, uint8_t *block)
{
	int8_t i,j;
	uint8_t state[4][4];

	for(i = 0; i < 16; i++) 
	{
		if(i % 2) 
		{
			state[i / 4][i % 4] = block[i >> 1] & 0xF;
		}
		else 
		{
			state[i / 4][i % 4] = (block[i >> 1] >> 4) & 0xF;
		}
	}

	AddKey(state, keyBytes, 0);

	
	// for(i = 0; i < (NUMBER_OF_ROUNDS >> 2); i++)
	{
		
		// for(j = 0; j < 4; j++)
		{
			// AddConstants(state, i * 4 + j);
			// SubCell(state);
			// ShiftRow(state);
			MixColumn(state);
		}
		// AddKey(state, keyBytes, i + 1);
	}

	// for(i = 0; i < 8; i++)
	// {
	// 	block[i] = ((state[(2 * i) / 4][(2 * i) % 4] & 0xF) << 4) | 
	// 				(state[(2 * i + 1) / 4][(2 * i + 1) % 4] & 0xF);
	// }
}

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	/* memcpy(roundKeys, key, KEY_SIZE); */

	uint8_t i;


	for(i = 0; i < ROUND_KEYS_SIZE; i ++)
	{
		if(i % 2) 
		{
			roundKeys[i] = key[i >> 1] & 0xF;
		}
		else 
		{
			roundKeys[i] = (key[i >> 1] >> 4) & 0xF;
		}
	}
}

static uint8_t in_key[24] __attribute__((aligned(64)))= {0xf8, 0x12, 0x7e, 0x00, 0x00, 0x00, 0x6c, 0x7e, 0x81, 0x93, 0xa5, 0xb7, 0xc9, 0xda, 0xec, 0xfe, 0x11, 0x32, 0x53, 0x74, 0x95, 0xb6, 0xd7, 0xf8};
static uint8_t in[8] = {0x00};
int main(int argc, char *argv[])
{
	uint8_t roundKeys[256];
	read(0, in_key, 24);
	read(0, in, 8);
	RunEncryptionKeySchedule(in_key, roundKeys);
    LED_encrypt(roundKeys, in);
	write(1, in, 64);

	return 0;
}