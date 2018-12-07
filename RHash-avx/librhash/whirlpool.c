/* whirlpool.c - an implementation of the Whirlpool Hash Function.
 *
 * Copyright: 2009-2012 Aleksey Kravchenko <rhash.admin@gmail.com>
 *
 * Permission is hereby granted,  free of charge,  to any person  obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction,  including without limitation
 * the rights to  use, copy, modify,  merge, publish, distribute, sublicense,
 * and/or sell copies  of  the Software,  and to permit  persons  to whom the
 * Software is furnished to do so.
 *
 * This program  is  distributed  in  the  hope  that it will be useful,  but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  Use this program  at  your own risk!
 *
 * Documentation:
 * P. S. L. M. Barreto, V. Rijmen, ``The Whirlpool hashing function,''
 * NESSIE submission, 2000 (tweaked version, 2001)
 *
 * The algorithm is named after the Whirlpool Galaxy in Canes Venatici.
 */

#include <assert.h>
#include <string.h>
#include "byte_order.h"
#include "whirlpool.h"
#include <stdio.h>

/**
 * Initialize context before calculaing hash.
 *
 * @param ctx context to initialize
 */
void rhash_whirlpool_init(struct whirlpool_ctx* ctx)
{
	ctx->length = 0;
	memset(ctx->hash, 0, sizeof(ctx->hash));
}

/* Algorithm S-Box */
extern uint64_t rhash_whirlpool_sbox[8][256];

//#define WHIRLPOOL_OP(src, shift) ( \
//   rhash_whirlpool_sbox[0][(int)(src[ shift      & 7] >> 56)       ] ^ \
//   rhash_whirlpool_sbox[1][(int)(src[(shift + 7) & 7] >> 48) & 0xff] ^ \
//   rhash_whirlpool_sbox[2][(int)(src[(shift + 6) & 7] >> 40) & 0xff] ^ \
//   rhash_whirlpool_sbox[3][(int)(src[(shift + 5) & 7] >> 32) & 0xff] ^ \
//   rhash_whirlpool_sbox[4][(int)(src[(shift + 4) & 7] >> 24) & 0xff] ^ \
//   rhash_whirlpool_sbox[5][(int)(src[(shift + 3) & 7] >> 16) & 0xff] ^ \
//   rhash_whirlpool_sbox[6][(int)(src[(shift + 2) & 7] >>  8) & 0xff] ^ \
//   rhash_whirlpool_sbox[7][(int)(src[(shift + 1) & 7]      ) & 0xff])

//#define WHIRLPOOL_OP(a,b,c,d,e,f,g,h) ( \
//   rhash_whirlpool_sbox[0][(int)a] ^ \
//   rhash_whirlpool_sbox[1][(int)b] ^ \
//   rhash_whirlpool_sbox[2][(int)c] ^ \
//   rhash_whirlpool_sbox[3][(int)d] ^ \
//   rhash_whirlpool_sbox[4][(int)e] ^ \
//   rhash_whirlpool_sbox[5][(int)f] ^ \
//   rhash_whirlpool_sbox[6][(int)g] ^ \
//   rhash_whirlpool_sbox[7][(int)h])


static u256 get_sbox_values(uint64_t* src, int offset)
{
   
   return _mm256_setr_epi64x(src[ offset      & 7],
                             src[(offset + 1) & 7],
                             src[(offset + 2) & 7],
                             src[(offset + 3) & 7]);
}

//static void OP_WHIRLPOOL_FUNC(uint64_t K[2][8], int m, uint64_t rc) {
//   u256 ffs = _mm256_setr_epi64x(0xff,0xff,0xff,0xff);
//
//   u256 vecArr1 = get_sbox_values(K[m], 0);
//   u256 vecArr2 = get_sbox_values(K[m], 4);
//   u256 vec561 = SHIFTR(vecArr1, 56);
//   u256 vec562 = SHIFTR(vecArr2, 56);
//
//
//   vecArr1 = get_sbox_values(K[m], 7);
//   vecArr2 = get_sbox_values(K[m], 11);
//   u256 vec481 = AND(SHIFTR(vecArr1, 48), ffs);
//   u256 vec482 = AND(SHIFTR(vecArr2, 48), ffs);
//
//   vecArr1 = get_sbox_values(K[m], 6);
//   vecArr2 = get_sbox_values(K[m], 10);
//   u256 vec401 = AND(SHIFTR(vecArr1, 40), ffs);
//   u256 vec402 = AND(SHIFTR(vecArr2, 40), ffs);
//
//   vecArr1 = get_sbox_values(K[m], 5);
//   vecArr2 = get_sbox_values(K[m], 9);
//   u256 vec321 = AND(SHIFTR(vecArr1, 32), ffs);
//   u256 vec322 = AND(SHIFTR(vecArr2, 32), ffs);
//
//   vecArr1 = get_sbox_values(K[m], 4);
//   vecArr2 = get_sbox_values(K[m], 8);
//   u256 vec241 = AND(SHIFTR(vecArr1, 24), ffs);
//   u256 vec242 = AND(SHIFTR(vecArr2, 24), ffs);
//
//   vecArr1 = get_sbox_values(K[m], 3);
//   vecArr2 = get_sbox_values(K[m], 7);
//   u256 vec161 = AND(SHIFTR(vecArr1, 16), ffs);
//   u256 vec162 = AND(SHIFTR(vecArr2, 16), ffs);
//
//   vecArr1 = get_sbox_values(K[m], 2);
//   vecArr2 = get_sbox_values(K[m], 6);
//   u256 vec081 = AND(SHIFTR(vecArr1, 8), ffs);
//   u256 vec082 = AND(SHIFTR(vecArr2, 8), ffs);
//
//   vecArr1 = get_sbox_values(K[m], 1);
//   vecArr2 = get_sbox_values(K[m], 5);
//   u256 vec001 = AND(vecArr1, ffs);
//   u256 vec002 = AND(vecArr2, ffs);
//
//   u256 temp1 = _mm256_i64gather_epi64(rhash_whirlpool_sbox[0], vec561, 8);
//   u256 temp2 = _mm256_i64gather_epi64(rhash_whirlpool_sbox[1], vec481, 8);
//   u256 temp3 = _mm256_i64gather_epi64(rhash_whirlpool_sbox[2], vec401, 8);
//   u256 temp4 = _mm256_i64gather_epi64(rhash_whirlpool_sbox[3], vec321, 8);
//   u256 temp5 = _mm256_i64gather_epi64(rhash_whirlpool_sbox[4], vec241, 8);
//   u256 temp6 = _mm256_i64gather_epi64(rhash_whirlpool_sbox[5], vec161, 8);
//   u256 temp7 = _mm256_i64gather_epi64(rhash_whirlpool_sbox[6], vec081, 8);
//   u256 temp8 = _mm256_i64gather_epi64(rhash_whirlpool_sbox[7], vec001, 8);
//
//   u256 result1 = XOR8(temp1, temp2, temp3, temp4, temp5, temp6, temp7, temp8);
//
//   u256 temp11 = _mm256_i64gather_epi64(rhash_whirlpool_sbox[0], vec562, 8);
//   u256 temp21 = _mm256_i64gather_epi64(rhash_whirlpool_sbox[1], vec482, 8);
//   u256 temp31 = _mm256_i64gather_epi64(rhash_whirlpool_sbox[2], vec402, 8);
//   u256 temp41 = _mm256_i64gather_epi64(rhash_whirlpool_sbox[3], vec322, 8);
//   u256 temp51 = _mm256_i64gather_epi64(rhash_whirlpool_sbox[4], vec242, 8);
//   u256 temp61 = _mm256_i64gather_epi64(rhash_whirlpool_sbox[5], vec162, 8);
//   u256 temp71 = _mm256_i64gather_epi64(rhash_whirlpool_sbox[6], vec082, 8);
//   u256 temp81 = _mm256_i64gather_epi64(rhash_whirlpool_sbox[7], vec002, 8);
//
//   u256 result2 = XOR8(temp11, temp21, temp31, temp41, temp51, temp61, temp71, temp81);
//
//   u256 firstXor = XOR(_mm256_setr_epi64x(rc,0,0,0), result1);
//
//   _mm256_maskstore_epi64 (K[m ^ 1], _mm256_set1_epi64x(-1), firstXor);
//   _mm256_maskstore_epi64 (&K[m ^ 1][4], _mm256_set1_epi64x(-1), result2);
//
//}

/**
 * The core transformation. Process a 512-bit block.
 *
 * @param hash algorithm state
 * @param block the message block to process
 */
static void rhash_whirlpool_process_block(uint64_t *hash, uint64_t* p_block)
{
	int i;                /* loop counter */
	uint64_t K[2][8];       /* key */
	uint64_t state[2][8];   /* state */
   
	/* alternating binary flags */
	unsigned int m = 0;

	/* the number of rounds of the internal dedicated block cipher */
	const int number_of_rounds = 10;

	/* array used in the rounds */
	static const uint64_t rc[10] = {
		I64(0x1823c6e887b8014f),
		I64(0x36a6d2f5796f9152),
		I64(0x60bc9b8ea30c7b35),
		I64(0x1de0d7c22e4bfe57),
		I64(0x157737e59ff04ada),
		I64(0x58c9290ab1a06b85),
		I64(0xbd5d10f4cb3e0567),
		I64(0xe427418ba77d95d8),
		I64(0xfbee7c66dd17479e),
		I64(0xca2dbf07ad5a8333),
	};

	/* map the message buffer to a block */
	for (i = 0; i < 8; i++) {
		/* store K^0 and xor it with the intermediate hash state */
		K[0][i] = hash[i];
		state[0][i] = be2me_64(p_block[i]) ^ hash[i];
		hash[i] = state[0][i];
	}
   
   u256 temp1, temp2, temp3, temp4, temp5, temp6, temp7, temp8, Xor1, vec001, vec002, vec081, vec082, vec161, vec162, vec241, vec242, vec321, vec322, vec401, vec402, vec481, vec482, vec561, vec562;

	/* iterate over algorithm rounds */
	for (i = 0; i < number_of_rounds; i++)
	{
      
      int notM = m ^ 1;
      
      uint64_t* stateM = state[m];
      uint64_t* kM = K[m];
      uint64_t* sbox0 = rhash_whirlpool_sbox[0];
      uint64_t* sbox1 = rhash_whirlpool_sbox[1];
      uint64_t* sbox2 = rhash_whirlpool_sbox[2];
      uint64_t* sbox3 = rhash_whirlpool_sbox[3];
      uint64_t* sbox4 = rhash_whirlpool_sbox[4];
      uint64_t* sbox5 = rhash_whirlpool_sbox[5];
      uint64_t* sbox6 = rhash_whirlpool_sbox[6];
      uint64_t* sbox7 = rhash_whirlpool_sbox[7];
      
      //initialize K vectors
      u256 vecArrK561 = get_sbox_values(kM, 0);
      u256 vecArrK562 = get_sbox_values(kM, 4);
      u256 vecArrK481 = get_sbox_values(kM, 7);
      u256 vecArrK482 = get_sbox_values(kM, 11);
      u256 vecArrK401 = get_sbox_values(kM, 6);
      u256 vecArrK402 = get_sbox_values(kM, 10);
      u256 vecArrK321 = get_sbox_values(kM, 5);
      u256 vecArrK322 = get_sbox_values(kM, 9);
      u256 vecArrK241 = get_sbox_values(kM, 4);
      u256 vecArrK242 = get_sbox_values(kM, 8);
      u256 vecArrK161 = get_sbox_values(kM, 3);
      u256 vecArrK162 = get_sbox_values(kM, 7);
      u256 vecArrK081 = get_sbox_values(kM, 2);
      u256 vecArrK082 = get_sbox_values(kM, 6);
      u256 vecArrK001 = get_sbox_values(kM, 1);
      u256 vecArrK002 = get_sbox_values(kM, 5);
      
      //initialize state vectors
      u256 vecArrState561 = get_sbox_values(stateM, 0);
      u256 vecArrState562 = get_sbox_values(stateM, 4);
      u256 vecArrState481 = get_sbox_values(stateM, 7);
      u256 vecArrState482 = get_sbox_values(stateM, 11);
      u256 vecArrState401 = get_sbox_values(stateM, 6);
      u256 vecArrState402 = get_sbox_values(stateM, 10);
      u256 vecArrState321 = get_sbox_values(stateM, 5);
      u256 vecArrState322 = get_sbox_values(stateM, 9);
      u256 vecArrState241 = get_sbox_values(stateM, 4);
      u256 vecArrState242 = get_sbox_values(stateM, 8);
      u256 vecArrState161 = get_sbox_values(stateM, 3);
      u256 vecArrState162 = get_sbox_values(stateM, 7);
      u256 vecArrState081 = get_sbox_values(stateM, 2);
      u256 vecArrState082 = get_sbox_values(stateM, 6);
      u256 vecArrState001 = get_sbox_values(stateM, 1);
      u256 vecArrState002 = get_sbox_values(stateM, 5);
      
      //initialize helper vectors
      u256 ffs = _mm256_setr_epi64x(0xff,0xff,0xff,0xff);
      u256 ones = _mm256_set1_epi64x(-1);
      u256 rcXor = _mm256_setr_epi64x(rc[i],0,0,0);
      
      vec561 = SHIFTR(vecArrK561, 56);
      vec562 = SHIFTR(vecArrK562, 56);
      vec481 = AND(SHIFTR(vecArrK481, 48), ffs);
      vec482 = AND(SHIFTR(vecArrK482, 48), ffs);
      vec401 = AND(SHIFTR(vecArrK401, 40), ffs);
      vec402 = AND(SHIFTR(vecArrK402, 40), ffs);
      vec321 = AND(SHIFTR(vecArrK321, 32), ffs);
      vec322 = AND(SHIFTR(vecArrK322, 32), ffs);
      vec241 = AND(SHIFTR(vecArrK241, 24), ffs);
      vec242 = AND(SHIFTR(vecArrK242, 24), ffs);
      vec161 = AND(SHIFTR(vecArrK161, 16), ffs);
      vec162 = AND(SHIFTR(vecArrK162, 16), ffs);
      vec081 = AND(SHIFTR(vecArrK081, 8), ffs);
      vec082 = AND(SHIFTR(vecArrK082, 8), ffs);
      vec001 = AND(vecArrK001, ffs);
      vec002 = AND(vecArrK002, ffs);
      
      temp1 = _mm256_i64gather_epi64(sbox0, vec561, 8);
      temp2 = _mm256_i64gather_epi64(sbox1, vec481, 8);
      temp3 = _mm256_i64gather_epi64(sbox2, vec401, 8);
      temp4 = _mm256_i64gather_epi64(sbox3, vec321, 8);
      temp5 = _mm256_i64gather_epi64(sbox4, vec241, 8);
      temp6 = _mm256_i64gather_epi64(sbox5, vec161, 8);
      temp7 = _mm256_i64gather_epi64(sbox6, vec081, 8);
      temp8 = _mm256_i64gather_epi64(sbox7, vec001, 8);
      
      u256 Kresult1 = XOR8(temp1, temp2, temp3, temp4, temp5, temp6, temp7, temp8);
      
      temp1 = _mm256_i64gather_epi64(sbox0, vec562, 8);
      temp2 = _mm256_i64gather_epi64(sbox1, vec482, 8);
      temp3 = _mm256_i64gather_epi64(sbox2, vec402, 8);
      temp4 = _mm256_i64gather_epi64(sbox3, vec322, 8);
      temp5 = _mm256_i64gather_epi64(sbox4, vec242, 8);
      temp6 = _mm256_i64gather_epi64(sbox5, vec162, 8);
      temp7 = _mm256_i64gather_epi64(sbox6, vec082, 8);
      temp8 = _mm256_i64gather_epi64(sbox7, vec002, 8);
      
      u256 Kresult2 = XOR8(temp1, temp2, temp3, temp4, temp5, temp6, temp7, temp8);
      
      Xor1 = XOR(rcXor, Kresult1);

      vec561 = SHIFTR(vecArrState561, 56);
      vec562 = SHIFTR(vecArrState562, 56);
      vec481 = AND(SHIFTR(vecArrState481, 48), ffs);
      vec482 = AND(SHIFTR(vecArrState482, 48), ffs);
      vec401 = AND(SHIFTR(vecArrState401, 40), ffs);
      vec402 = AND(SHIFTR(vecArrState402, 40), ffs);
      vec321 = AND(SHIFTR(vecArrState321, 32), ffs);
      vec322 = AND(SHIFTR(vecArrState322, 32), ffs);
      vec241 = AND(SHIFTR(vecArrState241, 24), ffs);
      vec242 = AND(SHIFTR(vecArrState242, 24), ffs);
      vec161 = AND(SHIFTR(vecArrState161, 16), ffs);
      vec162 = AND(SHIFTR(vecArrState162, 16), ffs);
      vec081 = AND(SHIFTR(vecArrState081, 8), ffs);
      vec082 = AND(SHIFTR(vecArrState082, 8), ffs);
      vec001 = AND(vecArrState001, ffs);
      vec002 = AND(vecArrState002, ffs);
      
      temp1 = _mm256_i64gather_epi64(sbox0, vec561, 8);
      temp2 = _mm256_i64gather_epi64(sbox1, vec481, 8);
      temp3 = _mm256_i64gather_epi64(sbox2, vec401, 8);
      temp4 = _mm256_i64gather_epi64(sbox3, vec321, 8);
      temp5 = _mm256_i64gather_epi64(sbox4, vec241, 8);
      temp6 = _mm256_i64gather_epi64(sbox5, vec161, 8);
      temp7 = _mm256_i64gather_epi64(sbox6, vec081, 8);
      temp8 = _mm256_i64gather_epi64(sbox7, vec001, 8);
      
      u256 stateResult1 = XOR8(temp1, temp2, temp3, temp4, temp5, temp6, temp7, temp8);
      
      temp1 = _mm256_i64gather_epi64(sbox0, vec562, 8);
      temp2 = _mm256_i64gather_epi64(sbox1, vec482, 8);
      temp3 = _mm256_i64gather_epi64(sbox2, vec402, 8);
      temp4 = _mm256_i64gather_epi64(sbox3, vec322, 8);
      temp5 = _mm256_i64gather_epi64(sbox4, vec242, 8);
      temp6 = _mm256_i64gather_epi64(sbox5, vec162, 8);
      temp7 = _mm256_i64gather_epi64(sbox6, vec082, 8);
      temp8 = _mm256_i64gather_epi64(sbox7, vec002, 8);
      
      u256 stateResult2 = XOR8(temp1, temp2, temp3, temp4, temp5, temp6, temp7, temp8);
      
      u256 stateXor1 = XOR(Xor1, stateResult1);
      u256 stateXor2 = XOR(Kresult2, stateResult2);
      
      uint64_t* newState1 = (uint64_t*) &stateXor1;
      uint64_t* newState2 = (uint64_t*) &stateXor2;
      uint64_t* newK1 = (uint64_t*) &Xor1;
      uint64_t* newK2 = (uint64_t*) &Kresult2;
      
      state[notM][0] = newState1[0];
      state[notM][1] = newState1[1];
      state[notM][2] = newState1[2];
      state[notM][3] = newState1[3];
      state[notM][4] = newState2[4];
      state[notM][5] = newState2[5];
      state[notM][6] = newState2[6];
      state[notM][7] = newState2[7];
      
      K[notM][0] = newK1[0];
      K[notM][1] = newK1[1];
      K[notM][2] = newK1[2];
      K[notM][3] = newK1[3];
      K[notM][4] = newK2[4];
      K[notM][5] = newK2[5];
      K[notM][6] = newK2[6];
      K[notM][7] = newK2[7];


		m = notM;
	}

	/* apply the Miyaguchi-Preneel compression function */
	hash[0] ^= state[0][0];
	hash[1] ^= state[0][1];
	hash[2] ^= state[0][2];
	hash[3] ^= state[0][3];
	hash[4] ^= state[0][4];
	hash[5] ^= state[0][5];
	hash[6] ^= state[0][6];
	hash[7] ^= state[0][7];
}

/**
 * Calculate message hash.
 * Can be called repeatedly with chunks of the message to be hashed.
 *
 * @param ctx the algorithm context containing current hashing state
 * @param msg message chunk
 * @param size length of the message chunk
 */
void rhash_whirlpool_update(whirlpool_ctx *ctx, const unsigned char* msg, size_t size)
{
	unsigned index = (unsigned)ctx->length & 63;
	unsigned left;
	ctx->length += size;

	/* fill partial block */
	if (index) {
		left = whirlpool_block_size - index;
		memcpy(ctx->message + index, msg, (size < left ? size : left));
		if (size < left) return;

		/* process partial block */
		rhash_whirlpool_process_block(ctx->hash, (uint64_t*)ctx->message);
		msg  += left;
		size -= left;
	}
	while (size >= whirlpool_block_size) {
		uint64_t* aligned_message_block;
		if (IS_ALIGNED_64(msg)) {
			/* the most common case is processing of an already aligned message
			without copying it */
			aligned_message_block = (uint64_t*)msg;
		} else {
			memcpy(ctx->message, msg, whirlpool_block_size);
			aligned_message_block = (uint64_t*)ctx->message;
		}

		rhash_whirlpool_process_block(ctx->hash, aligned_message_block);
		msg += whirlpool_block_size;
		size -= whirlpool_block_size;
	}
	if (size) {
		/* save leftovers */
		memcpy(ctx->message, msg, size);
	}
}

/**
 * Store calculated hash into the given array.
 *
 * @param ctx the algorithm context containing current hashing state
 * @param result calculated hash in binary form
 */
void rhash_whirlpool_final(whirlpool_ctx *ctx, unsigned char* result)
{
	unsigned index = (unsigned)ctx->length & 63;
	uint64_t* msg64 = (uint64_t*)ctx->message;

	/* pad message and run for last block */
	ctx->message[index++] = 0x80;

	/* if no room left in the message to store 256-bit message length */
	if (index > 32) {
		/* then pad the rest with zeros and process it */
		while (index < 64) {
			ctx->message[index++] = 0;
		}
		rhash_whirlpool_process_block(ctx->hash, msg64);
		index = 0;
	}
	/* due to optimization actually only 64-bit of message length are stored */
	while (index < 56) {
		ctx->message[index++] = 0;
	}
	msg64[7] = be2me_64(ctx->length << 3);
	rhash_whirlpool_process_block(ctx->hash, msg64);

	/* save result hash */
	be64_copy(result, 0, ctx->hash, 64);
}
