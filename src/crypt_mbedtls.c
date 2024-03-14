/*
 * Copyright (c) Edward Thomson.  All rights reserved.
 *
 * This file is part of ntlmclient, distributed under the MIT license.
 * For full terms and copyright information, and for third-party
 * copyright information, see the included LICENSE.txt file.
 */

#include <stdlib.h>
#include <string.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/des.h"
#include "mbedtls/entropy.h"
#if MBEDTLS_VERSION_MAJOR < 3
	#include "mbedtls/md4.h"
#endif

#include "ntlm.h"
#include "crypt.h"

bool ntlm_crypt_init(ntlm_client *ntlm)
{
	const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);

	mbedtls_md_init(&ntlm->crypt_ctx.hmac);

	if (mbedtls_md_setup(&ntlm->crypt_ctx.hmac, info, 1) != 0) {
		ntlm_client_set_errmsg(ntlm, "could not setup mbedtls digest");
		return false;
	}

	return true;
}


bool ntlm_random_bytes(
	unsigned char *out,
	ntlm_client *ntlm,
	size_t len)
{
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	bool ret = true;

	const unsigned char personalization[] = {
		0xec, 0xb5, 0xd1, 0x0b, 0x8f, 0x15, 0x1f, 0xc2,
		0xe4, 0x8e, 0xec, 0x36, 0xf7, 0x0a, 0x45, 0x9a,
		0x1f, 0xe1, 0x35, 0x58, 0xb1, 0xcb, 0xfd, 0x8a,
		0x57, 0x5c, 0x75, 0x7d, 0x2f, 0xc9, 0x70, 0xac
	};

	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);

	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
		&entropy, personalization, sizeof(personalization)) ||
		mbedtls_ctr_drbg_random(&ctr_drbg, out, len)) {
		ntlm_client_set_errmsg(ntlm, "random generation failed");
		ret = false;
	}

	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);

	return ret;
}

bool ntlm_des_encrypt(
	ntlm_des_block *out,
	ntlm_client *ntlm,
	ntlm_des_block *plaintext,
	ntlm_des_block *key)
{
	mbedtls_des_context ctx;
	bool success = false;

	mbedtls_des_init(&ctx);

	if (mbedtls_des_setkey_enc(&ctx, *key) ||
	    mbedtls_des_crypt_ecb(&ctx, *plaintext, *out)) {
		ntlm_client_set_errmsg(ntlm, "DES encryption failed");
		goto done;
	}

	success = true;

done:
	mbedtls_des_free(&ctx);
	return success;
}


#if MBEDTLS_VERSION_MAJOR >= 3
	#define MBEDTLS_BYTE_0(x) ((uint8_t) ((x)         & 0xff))
	#define MBEDTLS_BYTE_1(x) ((uint8_t) (((x) >> 8) & 0xff))
	#define MBEDTLS_BYTE_2(x) ((uint8_t) (((x) >> 16) & 0xff))
	#define MBEDTLS_BYTE_3(x) ((uint8_t) (((x) >> 24) & 0xff))
	#define MBEDTLS_BYTE_4(x) ((uint8_t) (((x) >> 32) & 0xff))
	#define MBEDTLS_BYTE_5(x) ((uint8_t) (((x) >> 40) & 0xff))
	#define MBEDTLS_BYTE_6(x) ((uint8_t) (((x) >> 48) & 0xff))
	#define MBEDTLS_BYTE_7(x) ((uint8_t) (((x) >> 56) & 0xff))
	#define MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED -0x006E
	#ifndef MBEDTLS_GET_UINT32_LE
	#define MBEDTLS_GET_UINT32_LE(data, offset)                   \
		(                                                           \
			((uint32_t) (data)[(offset)])         \
			| ((uint32_t) (data)[(offset) + 1] <<  8)         \
			| ((uint32_t) (data)[(offset) + 2] << 16)         \
			| ((uint32_t) (data)[(offset) + 3] << 24)         \
		)
	#endif

	#ifndef MBEDTLS_PUT_UINT32_LE
	#define MBEDTLS_PUT_UINT32_LE(n, data, offset)                \
		{                                                               \
			(data)[(offset)] = MBEDTLS_BYTE_0(n);             \
			(data)[(offset) + 1] = MBEDTLS_BYTE_1(n);             \
			(data)[(offset) + 2] = MBEDTLS_BYTE_2(n);             \
			(data)[(offset) + 3] = MBEDTLS_BYTE_3(n);             \
		}
	#endif



	typedef struct mbedtls_md4_context {
		uint32_t total[2];          /*!< number of bytes processed  */
		uint32_t state[4];          /*!< intermediate digest state  */
		unsigned char buffer[64];   /*!< data block being processed */
	} mbedtls_md4_context;

	static void mbedtls_md4_init(mbedtls_md4_context *ctx)
	{
		memset(ctx, 0, sizeof(mbedtls_md4_context));
	}

	static void mbedtls_md4_free(mbedtls_md4_context *ctx)
	{
		if (ctx == NULL) {
			return;
		}

		mbedtls_platform_zeroize(ctx, sizeof(mbedtls_md4_context));
	}

	static int mbedtls_md4_starts(mbedtls_md4_context *ctx)
	{
		ctx->total[0] = 0;
		ctx->total[1] = 0;

		ctx->state[0] = 0x67452301;
		ctx->state[1] = 0xEFCDAB89;
		ctx->state[2] = 0x98BADCFE;
		ctx->state[3] = 0x10325476;

		return 0;
	}

	static int mbedtls_md4_process(mbedtls_md4_context *ctx,
									const unsigned char data[64])
	{
		struct {
			uint32_t X[16], A, B, C, D;
		} local;

		local.X[0] = MBEDTLS_GET_UINT32_LE(data,  0);
		local.X[1] = MBEDTLS_GET_UINT32_LE(data,  4);
		local.X[2] = MBEDTLS_GET_UINT32_LE(data,  8);
		local.X[3] = MBEDTLS_GET_UINT32_LE(data, 12);
		local.X[4] = MBEDTLS_GET_UINT32_LE(data, 16);
		local.X[5] = MBEDTLS_GET_UINT32_LE(data, 20);
		local.X[6] = MBEDTLS_GET_UINT32_LE(data, 24);
		local.X[7] = MBEDTLS_GET_UINT32_LE(data, 28);
		local.X[8] = MBEDTLS_GET_UINT32_LE(data, 32);
		local.X[9] = MBEDTLS_GET_UINT32_LE(data, 36);
		local.X[10] = MBEDTLS_GET_UINT32_LE(data, 40);
		local.X[11] = MBEDTLS_GET_UINT32_LE(data, 44);
		local.X[12] = MBEDTLS_GET_UINT32_LE(data, 48);
		local.X[13] = MBEDTLS_GET_UINT32_LE(data, 52);
		local.X[14] = MBEDTLS_GET_UINT32_LE(data, 56);
		local.X[15] = MBEDTLS_GET_UINT32_LE(data, 60);

	#define S(x, n) (((x) << (n)) | (((x) & 0xFFFFFFFF) >> (32 - (n))))

		local.A = ctx->state[0];
		local.B = ctx->state[1];
		local.C = ctx->state[2];
		local.D = ctx->state[3];

	#define F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
	#define P(a, b, c, d, x, s)                           \
		do                                           \
		{                                            \
			(a) += F((b), (c), (d)) + (x);             \
			(a) = S((a), (s));                        \
		} while (0)


		P(local.A, local.B, local.C, local.D, local.X[0],  3);
		P(local.D, local.A, local.B, local.C, local.X[1],  7);
		P(local.C, local.D, local.A, local.B, local.X[2], 11);
		P(local.B, local.C, local.D, local.A, local.X[3], 19);
		P(local.A, local.B, local.C, local.D, local.X[4],  3);
		P(local.D, local.A, local.B, local.C, local.X[5],  7);
		P(local.C, local.D, local.A, local.B, local.X[6], 11);
		P(local.B, local.C, local.D, local.A, local.X[7], 19);
		P(local.A, local.B, local.C, local.D, local.X[8],  3);
		P(local.D, local.A, local.B, local.C, local.X[9],  7);
		P(local.C, local.D, local.A, local.B, local.X[10], 11);
		P(local.B, local.C, local.D, local.A, local.X[11], 19);
		P(local.A, local.B, local.C, local.D, local.X[12],  3);
		P(local.D, local.A, local.B, local.C, local.X[13],  7);
		P(local.C, local.D, local.A, local.B, local.X[14], 11);
		P(local.B, local.C, local.D, local.A, local.X[15], 19);

	#undef P
	#undef F

	#define F(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
	#define P(a, b, c, d, x, s)                          \
		do                                          \
		{                                           \
			(a) += F((b), (c), (d)) + (x) + 0x5A827999;       \
			(a) = S((a), (s));                               \
		} while (0)

		P(local.A, local.B, local.C, local.D, local.X[0],  3);
		P(local.D, local.A, local.B, local.C, local.X[4],  5);
		P(local.C, local.D, local.A, local.B, local.X[8],  9);
		P(local.B, local.C, local.D, local.A, local.X[12], 13);
		P(local.A, local.B, local.C, local.D, local.X[1],  3);
		P(local.D, local.A, local.B, local.C, local.X[5],  5);
		P(local.C, local.D, local.A, local.B, local.X[9],  9);
		P(local.B, local.C, local.D, local.A, local.X[13], 13);
		P(local.A, local.B, local.C, local.D, local.X[2],  3);
		P(local.D, local.A, local.B, local.C, local.X[6],  5);
		P(local.C, local.D, local.A, local.B, local.X[10],  9);
		P(local.B, local.C, local.D, local.A, local.X[14], 13);
		P(local.A, local.B, local.C, local.D, local.X[3],  3);
		P(local.D, local.A, local.B, local.C, local.X[7],  5);
		P(local.C, local.D, local.A, local.B, local.X[11],  9);
		P(local.B, local.C, local.D, local.A, local.X[15], 13);

	#undef P
	#undef F

	#define F(x, y, z) ((x) ^ (y) ^ (z))
	#define P(a, b, c, d, x, s)                                  \
		do                                                  \
		{                                                   \
			(a) += F((b), (c), (d)) + (x) + 0x6ED9EBA1;       \
			(a) = S((a), (s));                               \
		} while (0)

		P(local.A, local.B, local.C, local.D, local.X[0],  3);
		P(local.D, local.A, local.B, local.C, local.X[8],  9);
		P(local.C, local.D, local.A, local.B, local.X[4], 11);
		P(local.B, local.C, local.D, local.A, local.X[12], 15);
		P(local.A, local.B, local.C, local.D, local.X[2],  3);
		P(local.D, local.A, local.B, local.C, local.X[10],  9);
		P(local.C, local.D, local.A, local.B, local.X[6], 11);
		P(local.B, local.C, local.D, local.A, local.X[14], 15);
		P(local.A, local.B, local.C, local.D, local.X[1],  3);
		P(local.D, local.A, local.B, local.C, local.X[9],  9);
		P(local.C, local.D, local.A, local.B, local.X[5], 11);
		P(local.B, local.C, local.D, local.A, local.X[13], 15);
		P(local.A, local.B, local.C, local.D, local.X[3],  3);
		P(local.D, local.A, local.B, local.C, local.X[11],  9);
		P(local.C, local.D, local.A, local.B, local.X[7], 11);
		P(local.B, local.C, local.D, local.A, local.X[15], 15);

	#undef F
	#undef P

		ctx->state[0] += local.A;
		ctx->state[1] += local.B;
		ctx->state[2] += local.C;
		ctx->state[3] += local.D;

		/* Zeroise variables to clear sensitive data from memory. */
		mbedtls_platform_zeroize(&local, sizeof(local));

		return 0;
	}

	static int mbedtls_md4_update(mbedtls_md4_context *ctx,
							const unsigned char *input,
							size_t ilen)
	{
		int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
		size_t fill;
		uint32_t left;

		if (ilen == 0) {
			return 0;
		}

		left = ctx->total[0] & 0x3F;
		fill = 64 - left;

		ctx->total[0] += (uint32_t) ilen;
		ctx->total[0] &= 0xFFFFFFFF;

		if (ctx->total[0] < (uint32_t) ilen) {
			ctx->total[1]++;
		}

		if (left && ilen >= fill) {
			memcpy((void *) (ctx->buffer + left),
				(void *) input, fill);

			if ((ret = mbedtls_md4_process(ctx, ctx->buffer)) != 0) {
				return ret;
			}

			input += fill;
			ilen  -= fill;
			left = 0;
		}

		while (ilen >= 64) {
			if ((ret = mbedtls_md4_process(ctx, input)) != 0) {
				return ret;
			}

			input += 64;
			ilen  -= 64;
		}

		if (ilen > 0) {
			memcpy((void *) (ctx->buffer + left),
				(void *) input, ilen);
		}

		return 0;
	}

	static const unsigned char md4_padding[64] =
	{
		0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};

	static int mbedtls_md4_finish(mbedtls_md4_context *ctx,
							unsigned char output[16])
	{
		int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
		uint32_t last, padn;
		uint32_t high, low;
		unsigned char msglen[8];

		high = (ctx->total[0] >> 29)
			| (ctx->total[1] <<  3);
		low  = (ctx->total[0] <<  3);

		MBEDTLS_PUT_UINT32_LE(low,  msglen, 0);
		MBEDTLS_PUT_UINT32_LE(high, msglen, 4);

		last = ctx->total[0] & 0x3F;
		padn = (last < 56) ? (56 - last) : (120 - last);

		ret = mbedtls_md4_update(ctx, (unsigned char *) md4_padding, padn);
		if (ret != 0) {
			return ret;
		}

		if ((ret = mbedtls_md4_update(ctx, msglen, 8)) != 0) {
			return ret;
		}


		MBEDTLS_PUT_UINT32_LE(ctx->state[0], output,  0);
		MBEDTLS_PUT_UINT32_LE(ctx->state[1], output,  4);
		MBEDTLS_PUT_UINT32_LE(ctx->state[2], output,  8);
		MBEDTLS_PUT_UINT32_LE(ctx->state[3], output, 12);

		return 0;
	}
#endif

bool ntlm_md4_digest(
	unsigned char out[CRYPT_MD4_DIGESTSIZE],
	ntlm_client *ntlm,
	const unsigned char *in,
	size_t in_len)
{
	mbedtls_md4_context ctx;

	NTLM_UNUSED(ntlm);

	mbedtls_md4_init(&ctx);
	mbedtls_md4_starts(&ctx);
	mbedtls_md4_update(&ctx, in, in_len);
	mbedtls_md4_finish(&ctx, out);
	mbedtls_md4_free(&ctx);
	return true;
}

bool ntlm_hmac_md5_init(
	ntlm_client *ntlm,
	const unsigned char *key,
	size_t key_len)
{
	if (ntlm->crypt_ctx.hmac_initialized) {
		if (mbedtls_md_hmac_reset(&ntlm->crypt_ctx.hmac))
			return false;
	}

	ntlm->crypt_ctx.hmac_initialized = !mbedtls_md_hmac_starts(&ntlm->crypt_ctx.hmac, key, key_len);
	return ntlm->crypt_ctx.hmac_initialized;
}

bool ntlm_hmac_md5_update(
	ntlm_client *ntlm,
	const unsigned char *in,
	size_t in_len)
{
	return !mbedtls_md_hmac_update(&ntlm->crypt_ctx.hmac, in, in_len);
}

bool ntlm_hmac_md5_final(
	unsigned char *out,
	size_t *out_len,
	ntlm_client *ntlm)
{
	if (*out_len < CRYPT_MD5_DIGESTSIZE)
		return false;

	return !mbedtls_md_hmac_finish(&ntlm->crypt_ctx.hmac, out);
}

void ntlm_crypt_shutdown(ntlm_client *ntlm)
{
	mbedtls_md_free(&ntlm->crypt_ctx.hmac);
}
