/* whirlpool.h */
#ifndef WHIRLPOOL_H
#define WHIRLPOOL_H
#include "ustd.h"

#ifdef __cplusplus
extern "C" {
#endif
   
#include "immintrin.h"
   
#define u32 uint32_t
#define u256 __m256i
   
#define XOR _mm256_xor_si256
#define OR _mm256_or_si256
#define AND _mm256_and_si256
#define ADD32 _mm256_add_epi32
#define NOT(x) _mm256_xor_si256(x, _mm256_set_epi32(-1, -1, -1, -1, -1, -1, -1, -1))
   
#define SHIFTR(x, y) _mm256_srli_epi64(x, y)
#define SHIFTL(x, y) _mm256_slli_epi64(x, y)
   
#define XOR4(a,b,c,d) XOR(XOR(a,b),XOR(c,d))
#define XOR8(a,b,c,d,e,f,g,h) XOR(XOR4(a,b,c,d),XOR4(e,f,g,h))
   
#define ROTR(x, y) OR(SHIFTR32(x, y), SHIFTL32(x, 32 - y))

#define whirlpool_block_size 64

/* algorithm context */
typedef struct whirlpool_ctx
{
	uint64_t hash[8];    /* 512-bit algorithm internal hashing state */
	unsigned char message[whirlpool_block_size]; /* 512-bit buffer to hash */

	/* Note: original algorith uses 256-bit counter, allowing to hash up to
	   2^256 bits sized message. For optimization we use here 64-bit counter,
	   thus reducing maximal message size to 2^64 bits = 2 Exbibytes = 2^21 TiB) */
	uint64_t length;     /* number of processed bytes */
} whirlpool_ctx;

/* hash functions */

void rhash_whirlpool_init(whirlpool_ctx* ctx);
void rhash_whirlpool_update(whirlpool_ctx* ctx, const unsigned char* msg, size_t size);
void rhash_whirlpool_final(whirlpool_ctx* ctx, unsigned char* result);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* WHIRLPOOL_H */
