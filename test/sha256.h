#pragma once
#include "emp-sh2pc/emp-sh2pc.h"
using namespace emp;

#define MERCH ALICE
#define CUST BOB

const int BITS = 32;

/* implementation of SHA256 from FIPS PUB 180-4 
 * with the following modifications
 * - processes only a fixed length input. We've hardcoded it for 1, 2, or 3 blocks
 * - assumes padding already exists
 */

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHR32(x, n) ((x) >> (n))

#define SIGMA_UPPER_0(x) (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define SIGMA_UPPER_1(x) (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define SIGMA_LOWER_0(x) (ROR32(x, 7) ^ ROR32(x, 18) ^ SHR32(x, 3))
#define SIGMA_LOWER_1(x) (ROR32(x, 17) ^ ROR32(x, 19) ^ SHR32(x, 10))

Integer ROR32(Integer x, Integer n);
Integer ROR32(Integer x, uint n);
uint ROR32(uint x, uint n);

/* FIPS PUB 180-4 -- 4.2.2
 *
 * "These words represent the first thirty-two bits of the fractional parts of
 *  the cube roots of the first sixty-four prime numbers"
 */
static const uint32_t k_clear[64] = {
  0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
  0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
  0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
  0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
  0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
  0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
  0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
  0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};


/* FIPS PUB 180-4 -- 5.3.3
 *
 * Initial hash value
 * "These words were obtained by taking the first thirty-two bits of the fractional parts of the 
 *  square roots of the first eight prime numbers"
 */
static const uint32_t IV_clear[8] = {
  0x6A09E667 , 0xBB67AE85 , 0x3C6EF372 , 0xA54FF53A , 
  0x510E527F , 0x9B05688C , 0x1F83D9AB , 0x5BE0CD19
};


void initSHA256(Integer k[64], Integer H[8]); 
string get_bitstring(Integer x);
Integer composeSHA256result(Integer result[8]);


/* computes sha256 for a 2-block message
 * output is stored in result
 * composed of 8 32-bit Integers such that
 * sha256(message) = result[0] || result[1] || ... || result[7]
 */
void computeSHA256_2l(uint message[2][16], Integer result[8]);

/* computes sha256 for a 2-block message
 * output is stored in result
 * composed of 8 32-bit Integers such that
 * sha256(message) = result[0] || result[1] || ... || result[7]
 * this takes already distributed variables.
 */
void computeSHA256_1d(Integer message[1][16], Integer result[8]);
void computeSHA256_2d(Integer message[2][16], Integer result[8]);
void computeSHA256_3d(Integer message[3][16], Integer result[8]);

