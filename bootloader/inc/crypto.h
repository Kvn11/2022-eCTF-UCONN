#ifndef __UCONN_ECTF_CRYPTO_H_
#define __UCONN_ECTF_CRYPTO_H_

#include <stddef.h>
#include <stdint.h>

#include "bignum.h"

// SHA256

#define SHA256_BYTES 32

struct sha256_context{
    uint8_t buf[64];
    uint32_t hash[8];
    uint32_t bits[2];
    uint32_t len;
};

void sha256_init(struct sha256_context *ctx);
void sha256_hash(struct sha256_context *ctx, const void* data, size_t len);
void sha256_done(struct sha256_context *ctx, uint8_t *hash);

// PKCS1-v1.5

void pkcs_decode(const unsigned char* msg, unsigned long msglen, int block_type, unsigned long modulus_bitlen, char** out, int *is_valid);

// RSA

void montgomery(const struct bn* A, const struct bn* M, struct bn* C); // Returns: (A^65537 MOD M)
#define RSA_DECODE(cryptotext, modulus, result) montgomery(cryptotext, modulus, result)

#endif