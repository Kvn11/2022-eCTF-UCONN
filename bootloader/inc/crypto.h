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

typedef union {
    uint32_t u[16];
    uint8_t c[64];
} chacha_buf;

void sha256_init(struct sha256_context *ctx);
void sha256_hash(struct sha256_context *ctx, const void* data, size_t len);
void sha256_done(struct sha256_context *ctx, uint8_t *hash);

// PKCS1-v1.5

void pkcs_decode(const unsigned char* msg, unsigned long msglen, int block_type, unsigned long modulus_bitlen, char** out, int *is_valid);

// RSA

void montgomery(const struct bn* A, const struct bn* M, struct bn* C); // Returns: (A^65537 MOD M)

void rsa_decrypt(uint8_t* cipher_text, uint8_t* key, uint8_t** result);

// ChaCha20

void ChaCha20(uint8_t *out, const uint8_t *inp,
                size_t len, const uint32_t key[8],
                const uint32_t counter[4]);

void chacha20_core(chacha_buf *output, const uint32_t input[16]);

#endif