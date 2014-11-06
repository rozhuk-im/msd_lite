/*
 * Copyright (c) 2003 - 2014 Rozhuk Ivan <rozhuk.im@gmail.com>
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

/*
 * see
 * RFC 1321 - MD5
 * RFC 2104 - hmac_md5
 */


#ifndef AFX_MD5__H__INCLUDED_
#define AFX_MD5__H__INCLUDED_

#if _MSC_VER > 1000
#	pragma once
#endif // _MSC_VER > 1000


#ifndef _WINDOWS
#	include <sys/param.h>
#	ifndef BSD
#		define _GNU_SOURCE /* See feature_test_macros(7) */
#		define __USE_GNU 1
#	endif
#	include <sys/types.h>
#	include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#	include <inttypes.h>
#else
#	define uint8_t		unsigned char
#	define uint32_t		DWORD
#	define uint64_t		DWORDLONG
#	define size_t		SIZE_T
#endif

#if defined(_WINDOWS) && defined(UNICODE)
#	define md5_hmac_get_digest_str		md5_hmac_get_digest_strW
#	define md5_get_digest_str		md5_get_digest_strW
#	define md5_cvt_str			md5_cvt_strW
#else
#	define md5_hmac_get_digest_str		md5_hmac_get_digest_strA
#	define md5_get_digest_str		md5_get_digest_strA
#	define md5_cvt_str			md5_cvt_strA
#endif


#ifndef MD5_MAX_SPEED /* Max speed is insecure mode! */
#	ifdef SecureZeroMemory /* Windows version. */
#		define md5_bzero(mem, size)	SecureZeroMemory(mem, size)
#	else
		static void *(*volatile md5_memset_volatile)(void*, int, size_t) = memset;
#		define md5_bzero(mem, size)	md5_memset_volatile(mem, 0, size)
#	endif
#else
#	define md5_bzero(mem, size)
#endif


#define MD5_HASH_SIZE		16
#define MD5_HASH_STR_SIZE	(MD5_HASH_SIZE * 2)
#define MD5_MSG_BLK_SIZE	64
#define MD5_MSG_BLK_SIZE_MASK	(MD5_MSG_BLK_SIZE - 1)


#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

/* F, G, H and I are basic MD5 functions. */
#define F(x, y, z)	(((x) & (y)) | ((~x) & (z)))
/* From RFC 4634. */
//#define F(x, y, z)	(((x) & (y)) ^ ((~(x)) & (z)))
/* The following definitions are equivalent and potentially faster. */
//#define F(x, y, z)	(((x) & ((y) ^ (z))) ^ (z))
#define G(x, y, z)	(((x) & (z)) | ((y) & (~z)))
#define H(x, y, z)	((x) ^ (y) ^ (z))
#define I(x, y, z)	((y) ^ ((x) | (~z)))
/* ROTATE_LEFT rotates x left n bits. */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
 * Rotation is separate from addition to prevent recomputation. */
#define FF(a, b, c, d, x, s, ac) {				\
	(a) += F ((b), (c), (d)) + (x) + (uint32_t)(ac);	\
	(a) = ROTATE_LEFT ((a), (s));				\
	(a) += (b);						\
}
#define GG(a, b, c, d, x, s, ac) {				\
	(a) += G ((b), (c), (d)) + (x) + (uint32_t)(ac);	\
	(a) = ROTATE_LEFT ((a), (s));				\
	(a) += (b);						\
}
#define HH(a, b, c, d, x, s, ac) {				\
	(a) += H ((b), (c), (d)) + (x) + (uint32_t)(ac);	\
	(a) = ROTATE_LEFT ((a), (s));				\
	(a) += (b);						\
}
#define II(a, b, c, d, x, s, ac) {				\
	(a) += I ((b), (c), (d)) + (x) + (uint32_t)(ac);	\
	(a) = ROTATE_LEFT ((a), (s));				\
	(a) += (b);						\
}

/* MD5 context. */
typedef struct md5_ctx_s {
	uint32_t hash[(MD5_HASH_SIZE / sizeof(uint32_t))]; /* State (ABCD). */
	uint64_t count; /* Number of bits, modulo 2^64 (lsb first). */
	uint32_t buffer32[(MD5_MSG_BLK_SIZE / sizeof(uint32_t))]; /* Input buffer. */
} md5_ctx_t, *md5_ctx_p;

typedef struct hmac_md5_ctx_s {
	md5_ctx_t ctx;
	uint64_t k_opad[(MD5_MSG_BLK_SIZE / sizeof(uint64_t))]; /* Outer padding. */
} hmac_md5_ctx_t, *hmac_md5_ctx_p;



/* RFC 1321 */
/* MD5 initialization. Begins an MD5 operation, writing a new context. */
static inline void 
md5_init(md5_ctx_p ctx) {
	/* Load magic initialization constants. */
	ctx->hash[0] = 0x67452301;
	ctx->hash[1] = 0xefcdab89;
	ctx->hash[2] = 0x98badcfe;
	ctx->hash[3] = 0x10325476;
	ctx->count = 0;
}

/* MD5 basic transformation. Transforms state based on block. */
static inline void
md5_transform(md5_ctx_p ctx, uint8_t *block) {
	register uint32_t a, b, c, d;
	uint32_t *x;

	a = ctx->hash[0];
	b = ctx->hash[1];
	c = ctx->hash[2];
	d = ctx->hash[3];
	if (0 == (((size_t)block) & 3)) { /* 4 byte alligned. */
		x = (uint32_t*)(void*)block; /* Skeep alignment warning here. */
	} else {
		x = ctx->buffer32;
		memcpy(x, block, MD5_MSG_BLK_SIZE);
	}

	/* Round 1 */
	FF (a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
	FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
	FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
	FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
	FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
	FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
	FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
	FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
	FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
	FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
	FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
	FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
	FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
	FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
	FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
	FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

	/* Round 2 */
	GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
	GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
	GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
	GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
	GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
	GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
	GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
	GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
	GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
	GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
	GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
	GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
	GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
	GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
	GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
	GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

	/* Round 3 */
	HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
	HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
	HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
	HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
	HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
	HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
	HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
	HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
	HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
	HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
	HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
	HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
	HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
	HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
	HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
	HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

	/* Round 4 */
	II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
	II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
	II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
	II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
	II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
	II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
	II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
	II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
	II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
	II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
	II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
	II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
	II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
	II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
	II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
	II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

	ctx->hash[0] += a;
	ctx->hash[1] += b;
	ctx->hash[2] += c;
	ctx->hash[3] += d;
}

/* MD5 block update operation. Continues an MD5 message-digest operation,
 * processing another message block, and updating the context. */
static inline void
md5_update(md5_ctx_p ctx, uint8_t *data, size_t data_size) {
	register size_t i;
	uint8_t *buffer;
	uint32_t index, part_size;

	if (0 == data_size)
		return;
	buffer = (uint8_t*)ctx->buffer32;
	/* Compute number of bytes mod 64. */
	index = ((ctx->count >> 3) & MD5_MSG_BLK_SIZE_MASK);
	part_size = (MD5_MSG_BLK_SIZE - index);
	/* Update number of bits. */
	ctx->count += (((uint64_t)data_size) << 3);
	/* Transform as many times as possible. */
	if (data_size >= part_size) {
		if (0 != index) { /* Add data to buffer and process it. */
			memcpy(&buffer[index], data, part_size);
			md5_transform(ctx, buffer);
		} else { /* Proccess all data in loop.  */
			part_size = 0;
		}
		for (i = part_size; (i + MD5_MSG_BLK_SIZE_MASK) < data_size;
		    i += MD5_MSG_BLK_SIZE)
			md5_transform(ctx, &data[i]);
		index = 0;
	} else {
		i = 0;
	}
	/* Buffer remaining data. */
	memcpy(&buffer[index], &data[i], (data_size - i));
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the the
 * message digest and zeroizing the context. */
static inline void
md5_final(md5_ctx_p ctx, uint8_t *digest) {
	uint8_t *buffer;
	uint32_t index;

	buffer = (uint8_t*)ctx->buffer32;
	/* Compute number of bytes mod 64. */
	index = ((ctx->count >> 3) & MD5_MSG_BLK_SIZE_MASK);
	buffer[index ++] = 0x80; /* Padding... */
	if (56 < index) { /* Not enouth space for message length (8 bytes). */
		memset(&buffer[index], 0, (MD5_MSG_BLK_SIZE - index));
		md5_transform(ctx, buffer);
		index = 0;
	}
	memset(&buffer[index], 0, (56 - index));
	/* Store the message length as the last 8 octets. */
	memcpy(&buffer[56], &ctx->count, 8);
	md5_transform(ctx, buffer);
	/* Store state in digest. */
	memcpy(digest, ctx->hash, MD5_HASH_SIZE);
	/* Zeroize sensitive information. */
	md5_bzero(ctx, sizeof(md5_ctx_t));
}


/* RFC 2104 */
/*
 * the HMAC_MD5 transform looks like:
 *
 * MD5(K XOR opad, MD5(K XOR ipad, data))
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
hmac_md5_init(uint8_t *key, size_t key_len, hmac_md5_ctx_p hctx) {
	size_t i;
	uint64_t k_ipad[(MD5_MSG_BLK_SIZE / sizeof(uint64_t))]; /* inner padding. */

	/* Start out by storing key in pads. */
	/* If key is longer than block_size bytes reset it to key = MD5(key). */
	md5_init(&hctx->ctx); /* Init context for 1st pass / Get hash params. */
	if (MD5_MSG_BLK_SIZE < key_len) {
		md5_update(&hctx->ctx, key, key_len);
		key_len = MD5_HASH_SIZE;
		md5_final(&hctx->ctx, (uint8_t*)k_ipad);
		md5_init(&hctx->ctx); /* Reinit context for 1st pass. */
	} else {
		memcpy(k_ipad, key, key_len);
	}
	memset((((uint8_t*)k_ipad) + key_len), 0, (MD5_MSG_BLK_SIZE - key_len));
	memcpy(hctx->k_opad, k_ipad, MD5_MSG_BLK_SIZE);

	/* XOR key with ipad and opad values. */
	for (i = 0; i < (MD5_MSG_BLK_SIZE / sizeof(uint64_t)); i ++) {
		k_ipad[i] ^= 0x3636363636363636ll;
		hctx->k_opad[i] ^= 0x5c5c5c5c5c5c5c5cll;
	}
	/* Perform inner MD5. */
	/* Start with inner pad. */
	md5_update(&hctx->ctx, (uint8_t*)k_ipad, MD5_MSG_BLK_SIZE);
	/* Zeroize sensitive information. */
	md5_bzero(k_ipad, sizeof(k_ipad));
}

static inline void
hmac_md5_update(hmac_md5_ctx_p hctx, uint8_t *data, size_t data_size) {

	md5_update(&hctx->ctx, data, data_size); /* Then data of datagram. */
}

static inline void
hmac_md5_final(hmac_md5_ctx_p hctx, uint8_t *digest) {

	md5_final(&hctx->ctx, digest); /* Finish up 1st pass. */
	/* Perform outer MD5. */
	md5_init(&hctx->ctx); /* Init context for 2nd pass. */
	/* Start with outer pad. */
	md5_update(&hctx->ctx, (uint8_t*)hctx->k_opad, MD5_MSG_BLK_SIZE);
	/* Then results of 1st hash. */
	md5_update(&hctx->ctx, digest, MD5_HASH_SIZE);
	md5_final(&hctx->ctx, digest); /* Finish up 2nd pass. */
	/* Zeroize sensitive information. */
	md5_bzero(hctx->k_opad, sizeof(hctx->k_opad));
}

static inline void
hmac_md5(uint8_t *key, size_t key_len, uint8_t *data, size_t data_size,
    uint8_t *digest) {
	hmac_md5_ctx_t hctx;
	
	hmac_md5_init(key, key_len, &hctx);
	hmac_md5_update(&hctx, data, data_size);
	hmac_md5_final(&hctx, digest);
}


static inline void
md5_cvt_hex(uint8_t *bin, uint8_t *hex) {
	static uint8_t *hex_tbl = (uint8_t*)"0123456789abcdef";
	register uint8_t *bin_max, byte;

	for (bin_max = (bin + MD5_HASH_SIZE); bin < bin_max; bin ++) {
		byte = (*bin);
		(*hex ++) = hex_tbl[((byte >> 4) & 0x0f)];
		(*hex ++) = hex_tbl[(byte & 0x0f)];
	}
	(*hex) = 0;
};


/* Other staff. */
static inline void
md5_cvt_strA(uint8_t *digest, char *digest_str) {
	md5_cvt_hex(digest, (uint8_t*)digest_str);
};

#ifdef _WINDOWS
static inline void
md5_cvt_strW(uint8_t *digest, LPWSTR digest_str) {
	register size_t i, j;

	for (i = 0, j = 0; i < MD5_HASH_SIZE; i ++, j += 2)
		wsprintfW((LPWSTR)(digest_str + j), L"%02x", digest[i]);
	digest_str[j] = 0;
};
#endif


static inline void
md5_get_digest(void *data, size_t data_size, uint8_t *digest) {
	md5_ctx_t ctx;

	md5_init(&ctx);
	md5_update(&ctx, (uint8_t*)data, data_size);
	md5_final(&ctx, digest);
}


static inline void
md5_get_digest_strA(char *data, size_t data_size, char *digest_str) {
	md5_ctx_t ctx;
	uint8_t digest[MD5_HASH_SIZE];

	md5_init(&ctx);
	md5_update(&ctx, (uint8_t*)data, data_size);
	md5_final(&ctx, digest);

	md5_cvt_strA(digest, digest_str);
}

#ifdef _WINDOWS
static inline void
md5_get_digest_strW(LPWSTR data, size_t data_size, LPWSTR digest_str) {
	md5_ctx_t ctx;
	uint8_t digest[MD5_HASH_SIZE];

	md5_init(&ctx);
	md5_update(&ctx, (uint8_t*)data, data_size);
	md5_final(&ctx, digest);

	md5_cvt_strW(digest, digest_str);
}
#endif


static inline void
md5_hmac_get_digest(void *key, size_t key_size, void *data, size_t data_size,
    uint8_t *digest) {

	hmac_md5((uint8_t*)key, key_size, (uint8_t*)data, data_size, digest);
}


static inline void
md5_hmac_get_digest_strA(char *key, size_t key_size, char *data, size_t data_size,
    char *digest_str) {
	uint8_t digest[MD5_HASH_SIZE];

	hmac_md5((uint8_t*)key, key_size, (uint8_t*)data, data_size, digest);
	md5_cvt_strA(digest, digest_str);
}

#ifdef _WINDOWS
static inline void
md5_hmac_get_digest_strW(LPWSTR key, size_t key_size, LPWSTR data, size_t data_size,
    LPWSTR digest_str) {
	uint8_t digest[MD5_HASH_SIZE];

	hmac_md5((uint8_t*)key, key_size, (uint8_t*)data, data_size, digest);
	md5_cvt_strW(digest, digest_str);
}
#endif


#ifdef MD5_SELF_TEST
/* 0 - OK, non zero - error */
static inline int
md5_self_test() {
	size_t i;
	char digest_str[(MD5_HASH_STR_SIZE + 1)]; /* Calculated digest. */
	char *data[] = {
	    (char*)"",
	    (char*)"a",
	    (char*)"abc",
	    (char*)"message digest",
	    (char*)"abcdefghijklmnopqrstuvwxyz",
	    (char*)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	    (char*)"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
	    (char*)"0123456701234567012345670123456701234567012345670123456701234567",
	    (char*)"01234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456701234567",
	    (char*)"012345670123456701234567012345670123456701234567012345",
	    (char*)"0123456701234567012345670123456701234567012345670123456",
	    (char*)"01234567012345670123456701234567012345670123456701234567",
	    (char*)"012345670123456701234567012345670123456701234567012345678",
	    (char*)"012345670123456701234567012345670123456701234567012345670123456",
	    NULL
	};
	size_t data_size[] = {
	    0, 1, 3, 14, 26, 62, 80, 64, 128, 54, 55, 56, 57, 63, 0
	};
	char *result_digest[] = {
	    (char*)"d41d8cd98f00b204e9800998ecf8427e",
	    (char*)"0cc175b9c0f1b6a831c399e269772661",
	    (char*)"900150983cd24fb0d6963f7d28e17f72",
	    (char*)"f96b697d7cb7938d525a2f31aaf161d0",
	    (char*)"c3fcd3d76192e4007dfb496cca67e13b",
	    (char*)"d174ab98d277d9f5a5611c2c9f419d9f",
	    (char*)"57edf4a22be3c955ac49da2e2107b67a",
	    (char*)"520620de89e220f9b5850cc97cbff46c",
	    (char*)"f7361b2a9fc2652423988ab49742ebe4",
	    (char*)"5c63992176cbe2ad57e297a95e4dbcad",
	    (char*)"b8e22cd1914c0f0f56f28a4bd7868784",
	    (char*)"19e80817ef026edb4791f2ea7dd80d5c",
	    (char*)"ab212680fef75af03dd09c7dec2314fb",
	    (char*)"25c852e49158c8b622ad7735de232cde",
	    NULL
	};
	char *result_hdigest[] = {
	    (char*)"74e6f7298a9c2d168935f58c001bad88",
	    (char*)"06f30dc9049f859ea0ccb39fdc8fd5c2",
	    (char*)"f71cda1c893766a115234db7fdd59f63",
	    (char*)"7e6deb43db6f6bd41783eff5cb1f3fb6",
	    (char*)"71476855ae604156f3fde5914de1d665",
	    (char*)"364f3d9922d74bc1ae99fa2edba83000",
	    (char*)"579fe900785fe6f6cd219ee41eb363d5",
	    (char*)"41de6df1bc6560779e3acc63e0804f1b",
	    (char*)"d3ac5f1cf4da707fde93ba79bff4cf5f",
	    (char*)"8c864cb13e69473f01e58eab12eae7b4",
	    (char*)"fa9023d370b9cc49826f06cb0003dcb3",
	    (char*)"e8943ca04e9323a4592f4464418f63f0",
	    (char*)"1f7c7599c51c15e68f637700efe1f708",
	    (char*)"c038c3a3362207c74b94da805825ca73",
	    NULL
	};

	for (i = 0; NULL != data[i]; i ++) {
		md5_get_digest_strA(data[i], data_size[i], (char*)digest_str);
		if (0 != memcmp(digest_str, result_digest[i], MD5_HASH_STR_SIZE))
			return (1);
	}
	/* HMAC test */
	for (i = 0; NULL != data[i]; i ++) {
		md5_hmac_get_digest_strA(data[i], data_size[i], data[i],
		    data_size[i], (char*)digest_str);
		if (0 != memcmp(digest_str, result_hdigest[i], MD5_HASH_STR_SIZE)) {
			return (2);
		}
	}
	return (0);
}
#endif


#endif // AFX_MD5__H__INCLUDED_
