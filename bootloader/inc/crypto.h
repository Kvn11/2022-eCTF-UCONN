#ifndef __UCONN_ECTF_CRYPTO_H_
#define __UCONN_ECTF_CRYPTO_H_

#include <stddef.h>
#include <stdint.h>

enum verify_t{
    VERIFY_FAIL = 0,
    VERIFY_OK,
    VERIFY_INT_FAIL
};

int verify_data_prehash(uint8_t *signature, size_t sig_len, uint8_t* hash, uint32_t* data_key);
int verify_data(uint8_t *signature, size_t sig_len, uint8_t* data, size_t data_len, uint32_t* data_key);
int verify_hash(uint8_t *data, size_t data_len, uint8_t *hash);

#endif