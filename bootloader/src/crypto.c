#include "crypto.h"
#include "common.h"

#include "sha256.h"
#include "chacha20.h"

int verify_data_prehash(uint8_t *signature, size_t sig_len, uint8_t* hash, uint32_t data_key[8])
{
	stream_state chacha;
	uint8_t u8_sig_decrypt[76];
	uint8_t u8_sha_decrypt[32];

	if(chacha20_init(&chacha, (uint8_t*)data_key, 32, signature, 12))
	{
		return VERIFY_INT_FAIL;
	}

	if(chacha20_encrypt(&chacha, &signature[12], u8_sig_decrypt, 76))
	{
		return VERIFY_INT_FAIL;
	}

	if(chacha20_init(&chacha, &u8_sig_decrypt[44], 32, u8_sig_decrypt, 12))
	{
		return VERIFY_INT_FAIL;
	}

	if(chacha20_encrypt(&chacha, &u8_sig_decrypt[12], u8_sha_decrypt, 32))
	{
		return VERIFY_INT_FAIL;
	}

	for(int i = 0; i < 32; i++)
	{
		if(u8_sha_decrypt[i] != hash[i])
		{
			return VERIFY_FAIL;
		}
	}

	return VERIFY_OK;
}

int verify_data(uint8_t *signature, size_t sig_len, uint8_t* data, size_t data_len, uint32_t data_key[8])
{
	uint8_t u8_sha_out[32];

	sha256_init(&sha);
	sha256_hash(&sha, data, data_len);
	sha256_done(&sha, u8_sha_out);

	return verify_data_prehash(signature, sig_len, u8_sha_out, data_key);
}