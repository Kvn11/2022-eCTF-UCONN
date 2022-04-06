#ifndef __UCONN_SHA256_H_
#define __UCONN_SHA256_H_

#include <stdint.h>
#include <stddef.h>

struct sha256_context{
    uint8_t buf[64];
    uint32_t hash[8];
    uint32_t bits[2];
    uint32_t len;
};

void sha256_init(struct sha256_context *ctx);
void sha256_hash(struct sha256_context *ctx, const void* data, size_t len);
void sha256_done(struct sha256_context *ctx, uint8_t *hash);

#endif