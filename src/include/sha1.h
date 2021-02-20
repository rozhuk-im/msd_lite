/*
 * Copyright (c) 2003 - 2016 Rozhuk Ivan <rozhuk.im@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

 
// see
// RFC 1321 - MD5 (code base!)
// RFC 3174 - SHA1
// RFC 4634, RFC6234 - SHA1, SHA2
// RFC 2104 - HMAC

/*
 *  Description:
 *      This file implements the Secure Hashing Algorithm 1 as
 *      defined in FIPS PUB 180-1 published April 17, 1995.
 *
 *      The SHA-1, produces a 160-bit message digest for a given
 *      data stream.  It should take about 2**n steps to find a
 *      message with the same digest as a given message and
 *      2**(n/2) to find any two messages with the same digest, 
 *      when n is the digest size in bits.  Therefore, this
 *      algorithm can serve as a means of providing a
 *      "fingerprint" for a message.
 *
 *  Portability Issues:
 *      SHA-1 is defined in terms of 32-bit "words".  This code
 *      uses <stdint.h> (included via "sha1.h" to define 32 and 8
 *      bit unsigned integer types.  If your C compiler does not
 *      support 32 bit unsigned integers, this code is not
 *      appropriate.
 *
 *  Caveats:
 *      SHA-1 is designed to work with messages less than 2^64 bits
 *      long.  Although SHA-1 allows a message digest to be generated
 *      for messages of any number of bits less than 2^64, this
 *      implementation only works with messages with a length that is
 *      a multiple of the size of an 8-bit character.
 */

#ifndef __SHA1_H__INCLUDED__
#define __SHA1_H__INCLUDED__


#ifndef _WINDOWS
#	include <sys/param.h>
#	ifdef __linux__ /* Linux specific code. */
#		define _GNU_SOURCE /* See feature_test_macros(7) */
#		define __USE_GNU 1
#		include <endian.h>
#	else
#		include <sys/endian.h>
#	endif /* Linux specific code. */
#	include <sys/types.h>
#	include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#	include <inttypes.h>
	static void *(*volatile sha1_memset_volatile)(void*, int, size_t) = memset;
#	define sha1_bzero(__mem, __size)	sha1_memset_volatile((__mem), 0x00, (__size))
#else
#	define uint8_t		unsigned char
#	define uint32_t		DWORD
#	define uint64_t		DWORDLONG
#	define size_t		SIZE_T
#	define sha1_bzero(__mem, __size)	SecureZeroMemory((__mem), (__size))
#endif

#if defined(_WINDOWS) && defined(UNICODE)
#	define sha1_hmac_get_digest_str		sha1_hmac_get_digest_strW
#	define sha1_get_digest_str		sha1_get_digest_strW
#	define sha1_cvt_str			sha1_cvt_strW
#else
#	define sha1_hmac_get_digest_str		sha1_hmac_get_digest_strA
#	define sha1_get_digest_str		sha1_get_digest_strA
#	define sha1_cvt_str			sha1_cvt_strA
#endif


/* HASH constants. */
#define SHA1_HASH_SIZE		20 /* 160 bit */
#define SHA1_HASH_STR_SIZE	(SHA1_HASH_SIZE * 2)
#define SHA1_MSG_BLK_SIZE	64 /* 512 bit */
#define SHA1_MSG_BLK_SIZE_MASK	(SHA1_MSG_BLK_SIZE - 1)
#define SHA1_MSG_BLK_64CNT	(SHA1_MSG_BLK_SIZE / sizeof(uint64_t)) /* 16 */


/* Define the SHA1 circular left shift macro. */
#define SHA1_ROTL(bits, word)	(((word) << (bits)) | ((word) >> (32 - (bits))))

#define SHA1_Ch(x, y, z)	(((x) & (y)) | ((~(x)) & (z)))
#define SHA1_Maj(x, y, z)	(((x) & (y)) | ((x) & (z)) | ((y) & (z)))
/* From RFC 4634. */
//#define SHA1_Ch(x, y, z)	(((x) & (y)) ^ ((~(x)) & (z)))
//#define SHA1_Maj(x, y, z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
/* The following definitions are equivalent and potentially faster. */
//#define SHA1_Ch(x, y, z)	(((x) & ((y) ^ (z))) ^ (z))
//#define SHA1_Maj(x, y, z)	(((x) & ((y) | (z))) | ((y) & (z)))
#define SHA1_Parity(x, y, z)	((x) ^ (y) ^ (z))


/* This structure will hold context information for the SHA-1 hashing operation. */
typedef struct sha1_ctx_s {
	uint32_t hash[(SHA1_HASH_SIZE / sizeof(uint32_t))]; /* State (ABCDE) / Message Digest. */
	uint64_t count; /* Number of bits, modulo 2^64 (lsb first). */
	uint64_t buffer[SHA1_MSG_BLK_64CNT]; /* Input buffer: 512-bit message blocks. */
	uint32_t W[80]; /* Temp buf for sha1_transform(). */
} sha1_ctx_t, *sha1_ctx_p;

typedef struct hmac_sha1_ctx_s {
	sha1_ctx_t ctx;
	uint64_t k_opad[SHA1_MSG_BLK_64CNT]; /* outer padding - key XORd with opad. */
} hmac_sha1_ctx_t, *hmac_sha1_ctx_p;



static inline void
sha1_memcpy_bswap(uint8_t *dst, const uint8_t *src, size_t size) {
	register size_t i;

#pragma unroll
	for (i = 0; i < size; i += 4) {
		dst[(i + 0)] = src[(i + 3)];
		dst[(i + 1)] = src[(i + 2)];
		dst[(i + 2)] = src[(i + 1)];
		dst[(i + 3)] = src[(i + 0)];
	}
}

/*
 *  sha1_init
 *
 *  Description:
 *      This function will initialize the sha1_ctx in preparation
 *      for computing a new SHA1 message digest.
 *
 *  Parameters:
 *      ctx: [in/out]
 *          The ctx to reset.
 */
static inline void
sha1_init(sha1_ctx_p ctx) {
	/* Initial Hash Values: magic initialization constants. */
	ctx->hash[0] = 0x67452301;
	ctx->hash[1] = 0xefcdab89;
	ctx->hash[2] = 0x98badcfe;
	ctx->hash[3] = 0x10325476;
	ctx->hash[4] = 0xc3d2e1f0;
	ctx->count = 0;
}

/*
 *  sha1_transform
 *
 *  Description:
 *      This function will process the next 512 bits of the message
 *      stored in the buffer array.
 *
 *  Parameters:
 *      None.
 *
 *  Comments:
 *      Many of the variable names in this code, especially the
 *      single character names, were used because those were the
 *      names used in the publication.
 */
static inline void
sha1_transform(sha1_ctx_p ctx, const uint8_t *block) {
	/* Constants defined in SHA-1. */
	const uint32_t K[] = {0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6};
	register uint32_t t; /* Loop counter. */
	register uint32_t temp; /* Temporary word value. */
	register uint32_t A, B, C, D, E; /* Word buffers. */
	uint32_t *W; /* Word sequence. */

	A = ctx->hash[0];
	B = ctx->hash[1];
	C = ctx->hash[2];
	D = ctx->hash[3];
	E = ctx->hash[4];
	W = ctx->W;

	/* Initialize the first 16 words in the array W */
	sha1_memcpy_bswap((uint8_t*)W, block, SHA1_MSG_BLK_SIZE);

#pragma unroll
	for (t = 16; t < 80; t ++) {
		W[t] = SHA1_ROTL(1, W[(t - 3)] ^ W[(t - 8)] ^ W[(t - 14)] ^ W[(t - 16)]);
	}

#pragma unroll
	for (t = 0; t < 20; t ++) {
		temp = SHA1_ROTL(5, A) + SHA1_Ch(B, C, D) + E + W[t] + K[0];
		E = D;
		D = C;
		C = SHA1_ROTL(30, B);
		B = A;
		A = temp;
	}

#pragma unroll
	for (t = 20; t < 40; t ++) {
		temp = SHA1_ROTL(5, A) + SHA1_Parity(B, C, D) + E + W[t] + K[1];
		E = D;
		D = C;
		C = SHA1_ROTL(30, B);
		B = A;
		A = temp;
	}

#pragma unroll
	for (t = 40; t < 60; t ++) {
		temp = SHA1_ROTL(5, A) + SHA1_Maj(B, C, D) + E + W[t] + K[2];
		E = D;
		D = C;
		C = SHA1_ROTL(30, B);
		B = A;
		A = temp;
	}

#pragma unroll
	for (t = 60; t < 80; t ++) {
		temp = SHA1_ROTL(5, A) + SHA1_Parity(B, C, D) + E + W[t] + K[3];
		E = D;
		D = C;
		C = SHA1_ROTL(30, B);
		B = A;
		A = temp;
	}

	ctx->hash[0] += A;
	ctx->hash[1] += B;
	ctx->hash[2] += C;
	ctx->hash[3] += D;
	ctx->hash[4] += E;
}

/*
 *  sha1_update
 *
 *  Description:
 *      This function accepts an array of octets as the next portion
 *      of the message.
 *
 *  Parameters:
 *      ctx: [in/out]
 *          The SHA ctx to update
 *      message_array: [in]
 *          An array of characters representing the next portion of
 *          the message.
 *      length: [in]
 *          The length of the message in message_array
 */
static inline void
sha1_update(sha1_ctx_p ctx, const uint8_t *data, size_t data_size) {
	size_t i, index, part_size;

	if (0 == data_size)
		return;
	/* Compute number of bytes mod 64. */
	index = (ctx->count & SHA1_MSG_BLK_SIZE_MASK);
	part_size = (SHA1_MSG_BLK_SIZE - index);
	/* Update number of bits. */
	ctx->count += data_size;
	/* Transform as many times as possible. */
	if (data_size >= part_size) {
		if (0 != index) { /* Add data to buffer and process it. */
			memcpy((((uint8_t*)ctx->buffer) + index), data, part_size);
			index = 0;
			sha1_transform(ctx, (uint8_t*)ctx->buffer);
		} else { /* Proccess all data in loop.  */
			part_size = 0;
		}
		for (i = part_size; (i + SHA1_MSG_BLK_SIZE_MASK) < data_size;
		    i += SHA1_MSG_BLK_SIZE) {
			sha1_transform(ctx, (data + i));
		}
	} else {
		i = 0;
	}
	/* Buffer remaining data. */
	memcpy((((uint8_t*)ctx->buffer) + index), (data + i), (data_size - i));
}

/*
 *  sha1_final
 *
 *  Description:
 *      According to the standard, the message must be padded to an even
 *      512 bits.  The first padding bit must be a '1'.  The last 64
 *      bits represent the length of the original message.  All bits in
 *      between should be 0.  This function will pad the message
 *      according to those rules by filling the buffer array
 *      accordingly.  It will also call the ProcessMessageBlock function
 *      provided appropriately.  When it returns, it can be assumed that
 *      the message digest has been computed.
 *      This function will return the 160-bit message digest into the
 *      digest array  provided by the caller.
 *      NOTE: The first octet of hash is stored in the 0th element, 
 *            the last octet of hash in the 19th element.
 *
 *  Parameters:
 *      ctx: [in/out]
 *          The ctx to use to calculate the SHA-1 hash.
 *      digest: [out]
 *          Where the digest is returned.
 */
static inline void
sha1_final(sha1_ctx_p ctx, uint8_t *digest) {
	size_t index;

	/* Compute number of bytes mod 64. */
	index = (ctx->count & SHA1_MSG_BLK_SIZE_MASK);
	((uint8_t*)ctx->buffer)[index ++] = 0x80; /* Padding... */
	if ((SHA1_MSG_BLK_SIZE - 8) < index) { /* Not enouth space for message length (8 bytes). */
		memset((((uint8_t*)ctx->buffer) + index), 0x00,
		    (SHA1_MSG_BLK_SIZE - index));
		sha1_transform(ctx, (uint8_t*)ctx->buffer);
		index = 0;
	}
	memset((((uint8_t*)ctx->buffer) + index), 0x00,
	    ((SHA1_MSG_BLK_SIZE - 8) - index));
	/* Store the message length as the last 8 octets. */
	ctx->buffer[(SHA1_MSG_BLK_64CNT - 1)] = bswap64((ctx->count << 3));
	sha1_transform(ctx, (uint8_t*)ctx->buffer);
	/* Store state in digest. */
	sha1_memcpy_bswap(digest, (uint8_t*)ctx->hash, SHA1_HASH_SIZE);
	/* Zeroize sensitive information. */
	sha1_bzero(ctx, sizeof(sha1_ctx_t));
}


/* RFC 2104 */
/*
 * the HMAC_SHA1 transform looks like:
 *
 * SHA1(K XOR opad, SHA1(K XOR ipad, data))
 *
 * where K is an n byte 'key'
 * ipad is the byte 0x36 repeated 64 times
 * opad is the byte 0x5c repeated 64 times
 * and 'data' is the data being protected
 */
/*
 * data - pointer to data stream
 * data_size - length of data stream
 * key - pointer to authentication key
 * key_len - length of authentication key
 * digest - caller digest to be filled in
 */
static inline void
hmac_sha1_init(const uint8_t *key, size_t key_len, hmac_sha1_ctx_p hctx) {
	register size_t i;
	uint64_t k_ipad[SHA1_MSG_BLK_64CNT]; /* inner padding - key XORd with ipad. */

	/* Start out by storing key in pads. */
	/* If key is longer than block_size bytes reset it to key = SHA1(key). */
	sha1_init(&hctx->ctx); /* Init context for 1st pass / Get hash params. */
	if (SHA1_MSG_BLK_SIZE < key_len) {
		sha1_update(&hctx->ctx, key, key_len);
		key_len = SHA1_HASH_SIZE;
		sha1_final(&hctx->ctx, (uint8_t*)k_ipad);
		sha1_init(&hctx->ctx); /* Reinit context for 1st pass. */
	} else {
		memcpy(k_ipad, key, key_len);
	}
	memset((((uint8_t*)k_ipad) + key_len), 0x00, (SHA1_MSG_BLK_SIZE - key_len));
	memcpy(hctx->k_opad, k_ipad, sizeof(k_ipad));

	/* XOR key with ipad and opad values. */
#pragma unroll
	for (i = 0; i < SHA1_MSG_BLK_64CNT; i ++) {
		k_ipad[i] ^= 0x3636363636363636ull;
		hctx->k_opad[i] ^= 0x5c5c5c5c5c5c5c5cull;
	}
	/* Perform inner SHA1. */
	sha1_update(&hctx->ctx, (uint8_t*)k_ipad, sizeof(k_ipad)); /* Start with inner pad. */
	/* Zeroize sensitive information. */
	sha1_bzero(k_ipad, sizeof(k_ipad));
}

static inline void
hmac_sha1_update(hmac_sha1_ctx_p hctx, const uint8_t *data, size_t data_size) {

	sha1_update(&hctx->ctx, data, data_size); /* Then data of datagram. */
}

static inline void
hmac_sha1_final(hmac_sha1_ctx_p hctx, uint8_t *digest) {

	sha1_final(&hctx->ctx, digest); /* Finish up 1st pass. */
	/* Perform outer SHA1. */
	sha1_init(&hctx->ctx); /* Init context for 2nd pass. */
	sha1_update(&hctx->ctx, (uint8_t*)hctx->k_opad, SHA1_MSG_BLK_SIZE); /* Start with outer pad. */
	sha1_update(&hctx->ctx, digest, SHA1_HASH_SIZE); /* Then results of 1st hash. */
	sha1_final(&hctx->ctx, digest); /* Finish up 2nd pass. */
	/* Zeroize sensitive information. */
	sha1_bzero(hctx->k_opad, SHA1_MSG_BLK_SIZE);
}

static inline void
hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *data,
    size_t data_size, uint8_t *digest) {
	hmac_sha1_ctx_t hctx;

	hmac_sha1_init(key, key_len, &hctx);
	hmac_sha1_update(&hctx, data, data_size);
	hmac_sha1_final(&hctx, digest);
}


static inline void
sha1_cvt_hex(const uint8_t *bin, uint8_t *hex) {
	static const uint8_t *hex_tbl = (const uint8_t*)"0123456789abcdef";
	register const uint8_t *bin_max;
	register uint8_t byte;

#pragma unroll
	for (bin_max = (bin + SHA1_HASH_SIZE); bin < bin_max; bin ++) {
		byte = (*bin);
		(*hex ++) = hex_tbl[((byte >> 4) & 0x0f)];
		(*hex ++) = hex_tbl[(byte & 0x0f)];
	}
	(*hex) = 0;
}


/* Other staff. */
static inline void
sha1_cvt_strA(const uint8_t *digest, char *digest_str) {

	sha1_cvt_hex(digest, (uint8_t*)digest_str);
}

#ifdef _WINDOWS
static inline void
sha1_cvt_strW(const uint8_t *digest, LPWSTR digest_str) {
	register size_t i, j;

	for (i = 0, j = 0; i < SHA1_HASH_SIZE; i ++, j += 2) {
		wsprintfW((LPWSTR)(digest_str + j), L"%02x", digest[i]);
	}
	digest_str[j] = 0;
}
#endif


static inline void
sha1_get_digest(const void *data, size_t data_size, uint8_t *digest) {
	sha1_ctx_t ctx;

	sha1_init(&ctx);
	sha1_update(&ctx, data, data_size);
	sha1_final(&ctx, digest);
}


static inline void
sha1_get_digest_strA(const char *data, size_t data_size, char *digest_str) {
	sha1_ctx_t ctx;
	uint8_t digest[SHA1_HASH_SIZE];

	sha1_init(&ctx);
	sha1_update(&ctx, (const uint8_t*)data, data_size);
	sha1_final(&ctx, digest);

	sha1_cvt_strA(digest, digest_str);
}

#ifdef _WINDOWS
static inline void
sha1_get_digest_strW(const LPWSTR data, size_t data_size, LPWSTR digest_str) {
	sha1_ctx_t ctx;
	uint8_t digest[SHA1_HASH_SIZE];

	sha1_init(&ctx);
	sha1_update(&ctx, (const uint8_t*)data, data_size);
	sha1_final(&ctx, digest);

	sha1_cvt_strW(digest, digest_str);
}
#endif


static inline void
sha1_hmac_get_digest(const void *key, size_t key_size,
    const void *data, size_t data_size, uint8_t *digest) {

	hmac_sha1(key, key_size, data, data_size, digest);
}


static inline void
sha1_hmac_get_digest_strA(const char *key, size_t key_size,
    const char *data, size_t data_size, char *digest_str) {
	uint8_t digest[SHA1_HASH_SIZE];

	hmac_sha1((const uint8_t*)key, key_size,
	    (const uint8_t*)data, data_size, digest);
	sha1_cvt_strA(digest, digest_str);
}

#ifdef _WINDOWS
static inline void
sha1_hmac_get_digest_strW(const LPWSTR key, size_t key_size,
    const LPWSTR data, size_t data_size, LPWSTR digest_str) {
	uint8_t digest[SHA1_HASH_SIZE];

	hmac_sha1((const uint8_t*)key, key_size,
	    (const uint8_t*)data, data_size, digest);
	sha1_cvt_strW(digest, digest_str);
}
#endif


#ifdef SHA1_SELF_TEST
/* 0 - OK, non zero - error */
static inline int
sha1_self_test(void) {
	size_t i, j;
	sha1_ctx_t ctx;
	uint8_t digest[SHA1_HASH_SIZE];
	char digest_str[SHA1_HASH_STR_SIZE + 1]; /* Calculated digest. */
	char *data[] = {
	    (char*)"",
	    (char*)"a",
	    (char*)"abc",
	    (char*)"message digest",
	    (char*)"abcdefghijklmnopqrstuvwxyz",
	    (char*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	    (char*)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	    (char*)"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
	    (char*)"01234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567",
	    (char*)"a",
	    (char*)"0123456701234567012345670123456701234567012345670123456701234567",
	    (char*)"012345670123456701234567012345670123456701234567012345",
	    (char*)"0123456701234567012345670123456701234567012345670123456",
	    (char*)"01234567012345670123456701234567012345670123456701234567",
	    (char*)"012345670123456701234567012345670123456701234567012345678",
	    (char*)"012345670123456701234567012345670123456701234567012345670123456",
	    NULL
	};
	size_t data_size[] = {
	    0, 1, 3, 14, 26, 56, 62, 80, 128, 1, 64, 54, 55, 56, 57, 63, 0
	};
	size_t repeat_count[] = {
	    1, 1, 1, 1, 1, 1, 1, 1, 1, 1000000, 10, 1, 1, 1, 1, 1, 0
	};
	char *result_digest[] = {
	    (char*)"da39a3ee5e6b4b0d3255bfef95601890afd80709",
	    (char*)"86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
	    (char*)"a9993e364706816aba3e25717850c26c9cd0d89d",
	    (char*)"c12252ceda8be8994d5fa0290a47231c1d16aae3",
	    (char*)"32d10c7b8cf96570ca04ce37f2a19d84240d3a89",
	    (char*)"84983e441c3bd26ebaae4aa1f95129e5e54670f1",
	    (char*)"761c457bf73b14d27e9e9265c46f4b4dda11f940",
	    (char*)"50abf5706a150990a08b2c5ea40fa0e585554732",
	    (char*)"2249bd93900b5cb32bd4714a2be11e4c18450623",
	    (char*)"34aa973cd4c4daa4f61eeb2bdbad27316534016f",
	    (char*)"dea356a2cddd90c7a7ecedc5ebb563934f460452",
	    (char*)"09325e9054f88d7340deeb8785c6f8455ad13c78",
	    (char*)"adfc128b4a89c560e754c1659a6a90968b55490e",
	    (char*)"e8db7ebaebb692565d590a48b1dc506b6f130950",
	    (char*)"f8331b7f064d5886f371c47d8912c04439f4290a",
	    (char*)"f50965cd66d5793b37291ec7afe090406f2b6115",
	    NULL
	};
	char *result_hdigest[] = {
	    (char*)"fbdb1d1b18aa6c08324b7d64b71fb76370690e1d",
	    (char*)"3902ed847ff28930b5f141abfa8b471681253673",
	    (char*)"5b333a389b4e9a2358ac5392bf2a64dc68e3c943",
	    (char*)"39729a5ace94cc349b79adffbd113a599ca59d47",
	    (char*)"d74df27e4293c4225813dd723007cfb8933bc70b",
	    (char*)"e977b6b86e9f1920f01be85e9cea1f5a15b89421",
	    (char*)"a70fe63deac3c18b9d36ba4ecd44bdaf07cf5548",
	    (char*)"3e9e3aeaa5c932036358071bfcc3755344e7e357",
	    (char*)"2993491f3989c24a1267a5a35c5de325e6ef5312",
	    (char*)"3902ed847ff28930b5f141abfa8b471681253673",
	    (char*)"96e41775f72e3b2c61dca03d5c767019bebcc335",
	    (char*)"4ba0fa8d31c37fcad8476eb4bdd64e62e843284f",
	    (char*)"84dccb278a7be4e7c4318849bf22fa42f44baccd",
	    (char*)"9698a0a5cda19c5f4266cd851f5a606dc7b85e91",
	    (char*)"bbf00e8e0ff7a4dcd1cff54080c516fab3692d6b",
	    (char*)"d5d9e4085429568f05a4ef8233f42722c4462d6c",
	    NULL
	};

	for (i = 0; NULL != data[i]; i ++) {
		sha1_init(&ctx);
		for (j = 0; j < repeat_count[i]; j ++) {
			sha1_update(&ctx, (uint8_t*)data[i], data_size[i]);
		}
		sha1_final(&ctx, digest);
		sha1_cvt_hex(digest, (uint8_t*)digest_str);
		if (0 != memcmp(digest_str, result_digest[i], SHA1_HASH_STR_SIZE))
			return (1);
	}
	/* HMAC test */
	for (i = 0; NULL != data[i]; i ++) {
		sha1_hmac_get_digest_strA(data[i], data_size[i], data[i], data_size[i],
		    (char*)digest_str);
		if (0 != memcmp(digest_str, result_hdigest[i], SHA1_HASH_STR_SIZE))
			return (2);
	}
	return (0);
}
#endif


#endif // __SHA1_H__INCLUDED__
