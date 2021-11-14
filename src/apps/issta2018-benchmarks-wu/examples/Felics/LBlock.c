/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
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

#ifdef gem5
#include "../util/m5/m5op.h"
#endif

#define BLOCK_SIZE 8

#define KEY_SIZE 10
#define ROUND_KEYS_SIZE 128

#define NUMBER_OF_ROUNDS 32

uint8_t S0[16] __attribute__((aligned(64)))= {14, 9, 15, 0, 13, 4, 10, 11, 1, 2, 8, 3, 7, 6, 12, 5};
uint8_t S1[16] __attribute__((aligned(64)))= {4, 11, 14, 9, 15, 13, 0, 10, 7, 12, 5, 6, 2, 8, 1, 3};
uint8_t S2[16] __attribute__((aligned(64)))= {1, 14, 7, 12, 15, 13, 0, 6, 11, 5, 9, 3, 2, 4, 8, 10};
uint8_t S3[16] __attribute__((aligned(64)))= {7, 6, 8, 11, 0, 15, 3, 14, 9, 10, 12, 13, 5, 2, 4, 1};
uint8_t S4[16] __attribute__((aligned(64)))= {14, 5, 15, 0, 7, 2, 12, 13, 1, 8, 4, 9, 11, 10, 6, 3};
uint8_t S5[16] __attribute__((aligned(64)))= {2, 13, 11, 12, 15, 14, 0, 9, 7, 10, 6, 3, 1, 8, 4, 5};
uint8_t S6[16] __attribute__((aligned(64)))= {11, 9, 4, 14, 0, 15, 10, 13, 6, 12, 5, 7, 3, 8, 1, 2};
uint8_t S7[16] __attribute__((aligned(64)))= {13, 10, 15, 0, 14, 4, 9, 11, 2, 1, 8, 3, 7, 5, 12, 6};
uint8_t S8[16] __attribute__((aligned(64)))= {8, 7, 14, 5, 15, 13, 0, 6, 11, 12, 9, 10, 2, 4, 1, 3};
uint8_t S9[16] __attribute__((aligned(64)))= {11, 5, 15, 0, 7, 2, 9, 13, 4, 8, 1, 12, 14, 10, 3, 6};

inline void EncryptRound(uint8_t x[8], uint8_t k[4]) __attribute__((always_inline))
{
	uint8_t temp[4];
	uint8_t p[4];

	
	/* Save a copy of the left half of X */
	temp[3] = x[7];
	temp[2] = x[6];
	temp[1] = x[5];
	temp[0] = x[4];
		

	/* XOR X left half with the round key: X XOR K(i) */
	x[7] = x[7] ^ (k[3]);
	x[6] = x[6] ^ (k[2]); 
	x[5] = x[5] ^ (k[1]); 
	x[4] = x[4] ^ (k[0]); 

	
	/* (2) Confusion function S: S(X XOR K(i)) */
	x[7] = (((S7[((x[7] >> 4) & 0x0F)])) << 4) ^ (S6[(x[7] & 0x0F)]);
	x[6] = (((S5[((x[6] >> 4) & 0x0F)])) << 4) ^ (S4[(x[6] & 0x0F)]);
	x[5] = (((S3[((x[5] >> 4) & 0x0F)])) << 4) ^ (S2[(x[5] & 0x0F)]);
	x[4] = (((S1[((x[4] >> 4) & 0x0F)])) << 4) ^ (S0[(x[4] & 0x0F)]);


	/* (3) Diffusion function P: P(S(X XOR K(i))) */
	p[3] = ((x[7] & 0x0F) << 4) ^ (x[6] & 0x0F) ;
	p[2] = (x[7] & 0xF0) ^ ((x[6] >> 4) & 0x0F);
	p[1] = ((x[5] & 0x0F) << 4) ^ (x[4] & 0x0F);
	p[0] = (x[5] & 0xF0) ^ ((x[4] >> 4) & 0x0F);


	/* F(X(i-1), K(i-1)) XOR (X(i-2) <<< 8) */ 
	x[7] = x[2] ^ p[3]; 
	x[6] = x[1] ^ p[2]; 
	x[5] = x[0] ^ p[1]; 
	x[4] = x[3] ^ p[0]; 

	
	/* Put the copy of the left half of X in the right half of X */
	x[3] = temp[3];
	x[2] = temp[2];
	x[1] = temp[1];
	x[0] = temp[0];
}

void LBlock_encrypt(uint8_t *roundKeys, uint8_t *block)
{
	uint8_t i;
	uint8_t temp[4];

	#pragma unroll
	for(i = 0; i < NUMBER_OF_ROUNDS; i++)
	{
		EncryptRound(block, &roundKeys[4 * i]);        
	}
	

	temp[3] = block[3];
	temp[2] = block[2];
	temp[1] = block[1];
	temp[0] = block[0];

	block[3] = block[7];
	block[2] = block[6];
	block[1] = block[5];
	block[0] = block[4];

	block[7] = temp[3];
	block[6] = temp[2];
	block[5] = temp[1];
	block[4] = temp[0];
}



void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint16_t shiftedKey[2];
	uint8_t keyCopy[KEY_SIZE];


	uint16_t *Key = (uint16_t *)key;
	uint32_t *RoundKeys = (uint32_t *)roundKeys;


	uint16_t *KeyCopy = (uint16_t *)keyCopy;

	
	KeyCopy[4] = Key[4];
	KeyCopy[3] = Key[3];
	KeyCopy[2] = Key[2];
	KeyCopy[1] = Key[1];
	KeyCopy[0] = Key[0];

	
	/* Set round subkey K(1) */
	RoundKeys[0] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];

	
	/* Set round subkey K(2) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x00;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[1] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(2) - End */


	/* Set round subkey K(3) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x00;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[2] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(3) - End */


	/* Set round subkey K(4) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x00;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[3] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(4) - End */


	/* Set round subkey K(5) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x01;
	keyCopy[5] = keyCopy[5] ^ 0x00;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[4] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(5) - End */


	/* Set round subkey K(6) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x01;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[5] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(6) - End */


	/* Set round subkey K(7) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x01;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[6] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(7) - End */


	/* Set round subkey K(8) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x01;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[7] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(8) - End */


	/* Set round subkey K(9) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];;
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x02;
	keyCopy[5] = keyCopy[5] ^ 0x00;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[8] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(9) - End */


	/* Set round subkey K(10) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x02;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[9] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(10) - End */


	/* Set round subkey K(11) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x02;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[10] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(11) - End */


	/* Set round subkey K(12) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x02;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[11] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(12) - End */


	/* Set round subkey K(13) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x03;
	keyCopy[5] = keyCopy[5] ^ 0x00;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[12] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(13) - End */


	/* Set round subkey K(14) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x03;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[13] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(14) - End */


	/* Set round subkey K(15) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x03;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[14] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(15) - End */


	/* Set round subkey K(16) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x03;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[15] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(16) - End */


	/* Set round subkey K(17) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x04;
	keyCopy[5] = keyCopy[5] ^ 0x00;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[16] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(17) - End */


	/* Set round subkey K(18) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x04;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[17] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(18) - End */


	/* Set round subkey K(19) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x04;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[18] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(19) - End */


	/* Set round subkey K(20) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x04;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[19] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(20) - End */

	
	/* Set round subkey K(21) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x05;
	keyCopy[5] = keyCopy[5] ^ 0x00;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[20] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(21) - End */


	/* Set round subkey K(22) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x05;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[21] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(22) - End */


	/* Set round subkey K(23) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x05;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[22] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(23) - End */


	/* Set round subkey K(24) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x05;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[23] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(24) - End */


	/* Set round subkey K(25) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x06;
	keyCopy[5] = keyCopy[5] ^ 0x00;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[24] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(25) - End */


	/* Set round subkey K(26) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x06;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[25] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(26) - End */


	/* Set round subkey K(27) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x06;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[26] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(27) - End */


	/* Set round subkey K(28) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x06;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[27] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(28) - End */


	/* Set round subkey K(29) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x07;
	keyCopy[5] = keyCopy[5] ^ 0x00;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[28] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(29) - End */


	/* Set round subkey K(30) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x07;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[29] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(30) - End */


	/* Set round subkey K(31) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x07;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[30] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(31) - End */


	/* Set round subkey K(32) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = ((S9[keyCopy[9] >> 4]) << 4) ^ (S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x07;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[31] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	/* Set round subkey K(32) - End */
}

static uint8_t in_key[24] = {0xf8, 0x12, 0x7e, 0x00, 0x00, 0x00, 0x6c, 0x7e, 0x81, 0x93, 0xa5, 0xb7, 0xc9, 0xda, 0xec, 0xfe, 0x11, 0x32, 0x53, 0x74, 0x95, 0xb6, 0xd7, 0xf8};
static uint8_t in[64] = {0x00};
static 	uint8_t out[64] = {0};

int main(int argc, char *argv[])
{
	
	uint8_t roundKeys[128];
	read(0, in_key, 24);
	read(0, in, 64);
	
	RunEncryptionKeySchedule(in_key, roundKeys);
    LBlock_encrypt(roundKeys, in);
	write(1, in, 64);
	return 0;
}