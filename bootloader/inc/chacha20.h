#ifndef __UCONN_CHACHA20_H_
#define __UCONN_CHACHA20_H_

#include <stdint.h>
#include <stddef.h>

enum err_t {
  ERR_OK = 0,
  ERR_KEY_SIZE,
  ERR_NONCE_SIZE,
  ERR_NULL,
  ERR_MAX_DATA,
  ERR_MAX_OFFSET
};

typedef struct {
    /** Initial state for the next iteration **/
    uint32_t h[16];
    size_t nonceSize;  /** in bytes **/

    /** How many bytes at the beginning of the key stream
      * have already been used.
      */
    unsigned usedKeyStream;

    uint8_t keyStream[sizeof(uint32_t)*16];
} stream_state;

int chacha20_init(stream_state *hs,
                             const uint8_t *key,
                             size_t keySize,
                             const uint8_t *nonce,
                             size_t nonceSize);

int chacha20_encrypt(stream_state *state,
                                const uint8_t in[],
                                uint8_t out[],
                                size_t len);

int chacha20_seek(stream_state *state,
                             unsigned long block_high,
                             unsigned long block_low,
                             unsigned offset);

#endif