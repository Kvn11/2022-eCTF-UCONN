#ifndef __UCONN_ECTF_CRYPTO_H_
#define __UCONN_ECTF_CRYPTO_H_

#include <stddef.h>
#include <stdint.h>

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

// ChaCha20

void ChaCha20(uint8_t *out, const uint8_t *inp,
                size_t len, const uint32_t key[8],
                const uint32_t counter[4]);

void chacha20_core(chacha_buf *output, const uint32_t input[16]);

int verify_data(uint8_t *signature, size_t sig_len, uint8_t* data, size_t data_len, uint32_t data_key[8]);

#endif