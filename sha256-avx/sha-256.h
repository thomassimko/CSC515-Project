#include "immintrin.h"

#define u32 uint32_t
#define u256 __m256i

#define XOR _mm256_xor_si256
#define OR _mm256_or_si256
#define AND _mm256_and_si256
#define ADD32 _mm256_add_epi32
#define NOT(x) _mm256_xor_si256(x, _mm256_set_epi32(-1, -1, -1, -1, -1, -1, -1, -1))

#define SHIFTR32(x, y) _mm256_srli_epi32(x, y)
#define SHIFTL32(x, y) _mm256_slli_epi32(x, y)

#define ROTR(x, y) OR(SHIFTR32(x, y), SHIFTL32(x, 32 - y))


void calc_sha_256(uint8_t hash[32], const void *input, size_t len);
