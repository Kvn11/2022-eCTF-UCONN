#include "chacha20.h"

#include "common.h"

#define ROTL(q, n)  (((q) << (n)) | ((q) >> (32 - (n))))

#define QR(a, b, c, d) {\
    a+=b; d^=a; d=ROTL(d,16); \
    c+=d; b^=c; b=ROTL(b,12); \
    a+=b; d^=a; d=ROTL(d,8);  \
    c+=d; b^=c; b=ROTL(b,7);  \
}

int chacha20_init(stream_state *hs,
                             const uint8_t *key,
                             size_t keySize,
                             const uint8_t *nonce,
                             size_t nonceSize)
{
    unsigned i;

    if (NULL == hs || NULL == nonce)
        return ERR_NULL;

    if (NULL == key || keySize != 32)
        return ERR_KEY_SIZE;

    if (nonceSize != 8 && nonceSize != 12 && nonceSize != 16)
        return ERR_NONCE_SIZE;

    hs->h[0] = 0x61707865;
    hs->h[1] = 0x3320646e;
    hs->h[2] = 0x79622d32;
    hs->h[3] = 0x6b206574;

    /** Move 256-bit/32-byte key into h[4..11] **/
    for (i=0; i<32/4; i++) {
        hs->h[4+i] = LOAD_U32_LITTLE(key + 4*i);
    }

    switch (nonceSize) {
    case 8: {
                /*
                cccccccc  cccccccc  cccccccc  cccccccc
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                bbbbbbbb  BBBBBBBB  nnnnnnnn  nnnnnnnn
                c=constant k=key b=blockcount(low) B=blockcount(high) n=nonce
                */

                /** h[12] remains 0 (offset) **/
                /** h[13] remains 0 (offset) **/
                hs->h[14] = LOAD_U32_LITTLE(nonce + 0);
                hs->h[15] = LOAD_U32_LITTLE(nonce + 4);
                break;
                }
    case 12: {
                /*
                cccccccc  cccccccc  cccccccc  cccccccc
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn
                c=constant k=key b=blockcount n=nonce
                */

                hs->h[12] = 0;
                hs->h[13] = LOAD_U32_LITTLE(nonce + 0);
                hs->h[14] = LOAD_U32_LITTLE(nonce + 4);
                hs->h[15] = LOAD_U32_LITTLE(nonce + 8);
                break;
            }
    case 16: {
                /*
                cccccccc  cccccccc  cccccccc  cccccccc
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                nnnnnnnn  nnnnnnnn  nnnnnnnn  nnnnnnnn
                c=constant k=key n=nonce
                */

                hs->h[12] = LOAD_U32_LITTLE(nonce + 0);
                hs->h[13] = LOAD_U32_LITTLE(nonce + 4);
                hs->h[14] = LOAD_U32_LITTLE(nonce + 8);
                hs->h[15] = LOAD_U32_LITTLE(nonce + 12);
                break;
            }
    default:
             return ERR_NONCE_SIZE;
    }

    hs->nonceSize = nonceSize;
    hs->usedKeyStream = sizeof hs->keyStream;

    return 0;
}

static int chacha20_core(stream_state *state, uint32_t h[16])
{
    unsigned i;

    memory_copy(h, state->h, sizeof state->h);

    for (i=0; i<10; i++) {
        /** Column round **/
        QR(h[0], h[4], h[ 8], h[12]);
        QR(h[1], h[5], h[ 9], h[13]);
        QR(h[2], h[6], h[10], h[14]);
        QR(h[3], h[7], h[11], h[15]);
        /** Diagonal round **/
        QR(h[0], h[5], h[10], h[15]);
        QR(h[1], h[6], h[11], h[12]);
        QR(h[2], h[7], h[ 8], h[13]);
        QR(h[3], h[4], h[ 9], h[14]);
    }

    for (i=0; i<16; i++) {
        uint32_t sum;

        sum = h[i] + state->h[i];
        STORE_U32_LITTLE(state->keyStream + 4*i, sum);
    }

    state->usedKeyStream = 0;

    switch (state->nonceSize) {
    case 8: {
                /** Nonce is 64 bits, counter is two words **/
                if (++state->h[12] == 0) {
                    if (++state->h[13] == 0) {
                        return ERR_MAX_DATA;
                    }
                }
                break;
            }
    case 12: {
                /** Nonce is 96 bits, counter is one word **/
                if (++state->h[12] == 0) {
                    return ERR_MAX_DATA;
                }
                break;
            }
    case 16: {
                 /** Nonce is 192 bits, there is no counter as this is intended
                  * to be run once only (HChaCha20) **/
                 break;
            }
    }

    return 0;
}

int chacha20_encrypt(stream_state *state,
                                const uint8_t in[],
                                uint8_t out[],
                                size_t len)
{
    if (NULL == state || NULL == in || NULL == out)
        return ERR_NULL;

    if ((state->nonceSize != 8) && (state->nonceSize != 12))
        return ERR_NONCE_SIZE;

    while (len>0) {
        unsigned keyStreamToUse;
        unsigned i;
        uint32_t h[16];

        if (state->usedKeyStream == sizeof state->keyStream) {
            int result;

            result = chacha20_core(state, h);
            if (result)
                return result;
        }

        keyStreamToUse = (unsigned)MIN(len, sizeof state->keyStream - state->usedKeyStream);
        for (i=0; i<keyStreamToUse; i++)
            *out++ = *in++ ^ state->keyStream[i + state->usedKeyStream];

        len -= keyStreamToUse;
        state->usedKeyStream += keyStreamToUse;
    }

    return 0;
}

int chacha20_seek(stream_state *state,
                             unsigned long block_high,
                             unsigned long block_low,
                             unsigned offset)
{
    int result;
    uint32_t h[16];

    if (NULL == state)
        return ERR_NULL;

    if ((state->nonceSize != 8) && (state->nonceSize != 12))
        return ERR_NONCE_SIZE;

    if (offset >= sizeof state->keyStream)
        return ERR_MAX_OFFSET;

    if (state->nonceSize == 8) {
        /** Nonce is 64 bits, counter is two words **/
        state->h[12] = (uint32_t)block_low;
        state->h[13] = (uint32_t)block_high;
    } else {
        /** Nonce is 96 bits, counter is one word **/
        if (block_high > 0) {
            return ERR_MAX_OFFSET;
        }
        state->h[12] = (uint32_t)block_low;
    }

    result = chacha20_core(state, h);
    if (result)
        return result;

    state->usedKeyStream = offset;

    return 0;
}