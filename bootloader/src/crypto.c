#include "crypto.h"
#include "common.h"


/*
*   SHA 256
*
*/

// Use preallocated space inside data region
static const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* -------------------------------------------------------------------------- */
static inline uint8_t _shb(uint32_t x, uint32_t n)
{
	return ( (x >> (n & 31)) & 0xff );
} /* _shb */

/* -------------------------------------------------------------------------- */
static inline uint32_t _shw(uint32_t x, uint32_t n)
{
	return ( (x << (n & 31)) & 0xffffffff );
} /* _shw */

/* -------------------------------------------------------------------------- */
static inline uint32_t _r(uint32_t x, uint8_t n)
{
	return ( (x >> n) | _shw(x, 32 - n) );
} /* _r */

/* -------------------------------------------------------------------------- */
static inline uint32_t _Ch(uint32_t x, uint32_t y, uint32_t z)
{
	return ( (x & y) ^ ((~x) & z) );
} /* _Ch */

/* -------------------------------------------------------------------------- */
static inline uint32_t _Ma(uint32_t x, uint32_t y, uint32_t z)
{
	return ( (x & y) ^ (x & z) ^ (y & z) );
} /* _Ma */

/* -------------------------------------------------------------------------- */
static inline uint32_t _S0(uint32_t x)
{
	return ( _r(x, 2) ^ _r(x, 13) ^ _r(x, 22) );
} /* _S0 */

/* -------------------------------------------------------------------------- */
static inline uint32_t _S1(uint32_t x)
{
	return ( _r(x, 6) ^ _r(x, 11) ^ _r(x, 25) );
} /* _S1 */

/* -------------------------------------------------------------------------- */
static inline uint32_t _G0(uint32_t x)
{
	return ( _r(x, 7) ^ _r(x, 18) ^ (x >> 3) );
} /* _G0 */

/* -------------------------------------------------------------------------- */
static inline uint32_t _G1(uint32_t x)
{
	return ( _r(x, 17) ^ _r(x, 19) ^ (x >> 10) );
} /* _G1 */

/* -------------------------------------------------------------------------- */
static inline uint32_t _word(uint8_t *c)
{
	return ( _shw(c[0], 24) | _shw(c[1], 16) | _shw(c[2], 8) | (c[3]) );
} /* _word */

/* -------------------------------------------------------------------------- */
static inline void  _addbits(struct sha256_context *ctx, uint32_t n)
{
	if ( ctx->bits[0] > (0xffffffff - n) )
		ctx->bits[1] = (ctx->bits[1] + 1) & 0xFFFFFFFF;
	ctx->bits[0] = (ctx->bits[0] + n) & 0xFFFFFFFF;
} /* _addbits */

/* -------------------------------------------------------------------------- */
static void _hash(struct sha256_context *ctx)
{
	register uint32_t a, b, c, d, e, f, g, h, i;
	uint32_t t[2];
	static uint32_t W[64];

	// Take the current state from context
	a = ctx->hash[0];
	b = ctx->hash[1];
	c = ctx->hash[2];
	d = ctx->hash[3];
	e = ctx->hash[4];
	f = ctx->hash[5];
	g = ctx->hash[6];
	h = ctx->hash[7];

	// Perform the 64 SHA256 rounds
	for (i = 0; i < 64; i++) {
		if ( i < 16 )
			W[i] = _word(&ctx->buf[_shw(i, 2)]);
		else
			W[i] = _G1(W[i - 2]) + W[i - 7] + _G0(W[i - 15]) + W[i - 16];

		t[0] = h + _S1(e) + _Ch(e, f, g) + K[i] + W[i];
		t[1] = _S0(a) + _Ma(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t[0];
		d = c;
		c = b;
		b = a;
		a = t[0] + t[1];
	}

	// Replace the state from the local "context"
	ctx->hash[0] += a;
	ctx->hash[1] += b;
	ctx->hash[2] += c;
	ctx->hash[3] += d;
	ctx->hash[4] += e;
	ctx->hash[5] += f;
	ctx->hash[6] += g;
	ctx->hash[7] += h;
} /* _hash */

/* -------------------------------------------------------------------------- */
void sha256_init(struct sha256_context *ctx)
{
	// Initialize context state
	if ( ctx != NULL ) {
		ctx->bits[0]  = ctx->bits[1] = 0;
		ctx->len      = 0;
		ctx->hash[0] = 0x6a09e667;
		ctx->hash[1] = 0xbb67ae85;
		ctx->hash[2] = 0x3c6ef372;
		ctx->hash[3] = 0xa54ff53a;
		ctx->hash[4] = 0x510e527f;
		ctx->hash[5] = 0x9b05688c;
		ctx->hash[6] = 0x1f83d9ab;
		ctx->hash[7] = 0x5be0cd19;
	}
} /* sha256_init */

/* -------------------------------------------------------------------------- */
void sha256_hash(struct sha256_context *ctx, const void *data, size_t len)
{
	register size_t i;
	const uint8_t *bytes = (const uint8_t *)data;

	// Perform a hash on the given data stream
	if ( (ctx != NULL) && (bytes != NULL) )
		for (i = 0; i < len; i++) {
			ctx->buf[ctx->len] = bytes[i];
			ctx->len++;
			if (ctx->len == sizeof(ctx->buf) ) {
				_hash(ctx);
				_addbits(ctx, sizeof(ctx->buf) * 8);
				ctx->len = 0;
			}
		}
} /* sha256_hash */

/* -------------------------------------------------------------------------- */
void sha256_done(struct sha256_context *ctx, uint8_t *hash)
{
	register uint32_t i, j;

	// Final SHA256 rounds
	if ( ctx != NULL ) {
		j = ctx->len % sizeof(ctx->buf);
		ctx->buf[j] = 0x80;
		for (i = j + 1; i < sizeof(ctx->buf); i++)
			ctx->buf[i] = 0x00;

		if ( ctx->len > 55 ) {
			_hash(ctx);
			for (j = 0; j < sizeof(ctx->buf); j++)
				ctx->buf[j] = 0x00;
		}

		_addbits(ctx, ctx->len * 8);
		ctx->buf[63] = _shb(ctx->bits[0],  0);
		ctx->buf[62] = _shb(ctx->bits[0],  8);
		ctx->buf[61] = _shb(ctx->bits[0], 16);
		ctx->buf[60] = _shb(ctx->bits[0], 24);
		ctx->buf[59] = _shb(ctx->bits[1],  0);
		ctx->buf[58] = _shb(ctx->bits[1],  8);
		ctx->buf[57] = _shb(ctx->bits[1], 16);
		ctx->buf[56] = _shb(ctx->bits[1], 24);
		_hash(ctx);

		if ( hash != NULL )
			for (i = 0, j = 24; i < 4; i++, j -= 8) {
				hash[i     ] = _shb(ctx->hash[0], j);
				hash[i +  4] = _shb(ctx->hash[1], j);
				hash[i +  8] = _shb(ctx->hash[2], j);
				hash[i + 12] = _shb(ctx->hash[3], j);
				hash[i + 16] = _shb(ctx->hash[4], j);
				hash[i + 20] = _shb(ctx->hash[5], j);
				hash[i + 24] = _shb(ctx->hash[6], j);
				hash[i + 28] = _shb(ctx->hash[7], j);
			}
	}
}

/*
*   pkcs padding
*
*/

void pkcs_decode(const unsigned char* msg, unsigned long msglen, int block_type, unsigned long modulus_bitlen, char** out, int *is_valid)
{
    unsigned long modulus_len, ps_len, i;
    int result;

    *is_valid = 0;
    *out = 0;

    modulus_len = (modulus_bitlen >> 3) + ((modulus_bitlen & 7) ? 1 : 0);

    if((msglen > modulus_len) || (modulus_len < 11))
    {
        return;
    }

    if((msg[0] != 0x00) || (msg[1] != 0x01))
    {
        return;
    }

    for(i = 2; i < modulus_len - 1; i++)
    {
        if(msg[i] != 0xFF)
        {
            break;
        }
    }

    if(msg[i] != 0)
    {
        return;
    }

    ps_len = i - 2;

    if(ps_len < 8)
    {
        return;
    }

    *out = msg + (2 + ps_len + 1);

	if(is_valid)
	{
		*is_valid = 1;
	}
}

/*
*	Montgomery multiplication tree
*/
void montgomery(const struct bn* A, const struct bn* M, struct bn* C)
{
	uint32_t exponent = 65537;
	struct bn R0;
	struct bn R1;
	struct bn tmp;

	bignum_from_int(&R0, 1);
	bignum_assign(&R1, A);
	bignum_init(&tmp);

	for(int i = 16; i >= 0; i--)
	{
		if((exponent >> i) & 1)
		{
			bignum_mul(&R0, &R1, &tmp); // tmp = R0 * R1
			bignum_mod(&tmp, M, &R0);

			bignum_mul(&R1, &R1, &tmp);
			bignum_mod(&tmp, M, &R1);
		}
		else
		{
			bignum_mul(&R0, &R1, &tmp);
			bignum_mod(&tmp, M, &R1);

			bignum_mul(&R0, &R0, &tmp);
			bignum_mod(&tmp, M, &R0);
		}
	}

	bignum_assign(C, &R0);
}

void rsa_decrypt(uint8_t* cipher_text, uint8_t* key, uint8_t** result)
{
	struct bn cipher;
	struct bn modulus;
	struct bn tmp_result;

	bignum_from_ptr(&cipher, cipher_text, 256);
	bignum_from_ptr(&modulus, key, 256);

	montgomery(&cipher, &modulus, &tmp_result);
	pkcs_decode(&(cipher.array), 32, 0, 2048, result, 0);
}

/*
*	ChaCha20
*/

#define ROTATE(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

/*
 * You can notice that there is no key setup procedure. Because it's
 * as trivial as collecting bytes into 32-bit elements, it's reckoned
 * that below macro is sufficient.
 */
#define CHACHA_U8TOU32(p)  ( \
                ((uint32_t)(p)[0])     | ((uint32_t)(p)[1]<<8) | \
                ((uint32_t)(p)[2]<<16) | ((uint32_t)(p)[3]<<24)  )

#define CHACHA_KEY_SIZE         32
#define CHACHA_CTR_SIZE         16
#define CHACHA_BLK_SIZE         64

# define U32TO8_LITTLE(p, v) do { \
                                (p)[0] = (uint8_t)(v >>  0); \
                                (p)[1] = (uint8_t)(v >>  8); \
                                (p)[2] = (uint8_t)(v >> 16); \
                                (p)[3] = (uint8_t)(v >> 24); \
                                } while(0)

/* QUARTERROUND updates a, b, c, d with a ChaCha "quarter" round. */
# define QUARTERROUND(a,b,c,d) ( \
                x[a] += x[b], x[d] = ROTATE((x[d] ^ x[a]),16), \
                x[c] += x[d], x[b] = ROTATE((x[b] ^ x[c]),12), \
                x[a] += x[b], x[d] = ROTATE((x[d] ^ x[a]), 8), \
                x[c] += x[d], x[b] = ROTATE((x[b] ^ x[c]), 7)  )

/* chacha_core performs 20 rounds of ChaCha on the input words in
 * |input| and writes the 64 output bytes to |output|. */
void chacha20_core(chacha_buf *output, const uint32_t input[16])
{
    uint32_t x[16];
    int i;

    memory_copy(x, input, sizeof(x));

    for (i = 20; i > 0; i -= 2) {
        QUARTERROUND(0, 4, 8, 12);
        QUARTERROUND(1, 5, 9, 13);
        QUARTERROUND(2, 6, 10, 14);
        QUARTERROUND(3, 7, 11, 15);
        QUARTERROUND(0, 5, 10, 15);
        QUARTERROUND(1, 6, 11, 12);
        QUARTERROUND(2, 7, 8, 13);
        QUARTERROUND(3, 4, 9, 14);
    }

    for (i = 0; i < 16; ++i)
        output->u[i] = x[i] + input[i];
}

void ChaCha20(uint8_t *out, const uint8_t *inp,
                    size_t len, const uint32_t key[8],
                    const uint32_t counter[4])
{
    uint32_t input[16];
    chacha_buf buf;
    size_t todo, i;

    /* sigma constant "expand 32-byte k" in little-endian encoding */
    input[0] = ((uint32_t)'e' | ((uint32_t)'x' << 8)
               | ((uint32_t)'p' << 16)
               | ((uint32_t)'a' << 24));
    input[1] = ((uint32_t)'n') | ((uint32_t)'d' << 8)
               | ((uint32_t)' ' << 16)
               | ((uint32_t)'3' << 24);
    input[2] = ((uint32_t)'2') | ((uint32_t)'-' << 8)
               | ((uint32_t)'b' << 16)
               | ((uint32_t)'y' << 24);
    input[3] = ((uint32_t)'t') | ((uint32_t)'e' << 8)
               | ((uint32_t)' ' << 16)
               | ((uint32_t)'k' << 24);

    input[4] = key[0];
    input[5] = key[1];
    input[6] = key[2];
    input[7] = key[3];
    input[8] = key[4];
    input[9] = key[5];
    input[10] = key[6];
    input[11] = key[7];

    input[12] = counter[0];
    input[13] = counter[1];
    input[14] = counter[2];
    input[15] = counter[3];

    while (len > 0) {
        todo = sizeof(buf);
        if (len < todo)
            todo = len;

        chacha20_core(&buf, input);

        for (i = 0; i < todo; i++)
            out[i] = inp[i] ^ buf.c[i];
        out += todo;
        inp += todo;
        len -= todo;

        /*
         * Advance 32-bit counter. Note that as subroutine is so to
         * say nonce-agnostic, this limited counter width doesn't
         * prevent caller from implementing wider counter. It would
         * simply take two calls split on counter overflow...
         */
        input[12]++;
    }
}