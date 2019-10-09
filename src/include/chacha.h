/*-
 * Copyright (c) 2015 Rozhuk Ivan <rozhuk.im@gmail.com>
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
 * Author: Rozhuk Ivan <rozhuk.im@gmail.com>
 *
 * chacha, hchacha and xchacha.
 *
 */

#ifndef __CHACHA_H__
#define __CHACHA_H__


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
#	ifdef _KERNEL
#		include <sys/systm.h>
#	else
#		include <string.h> /* memcpy, memmove, memset... */
#		include <inttypes.h>
#	endif
#	if __x86_64__ || __ppc64__ || __LP64__
#		define CHACHA_X64
#	else
#		define CHACHA_X32
#	endif
	static void *(*volatile chacha_memset_volatile)(void*, int, size_t) = memset;
#	define chacha_bzero(mem, size)	chacha_memset_volatile(mem, 0, size)
#else
#	include <stdlib.h>
#	define uint8_t		unsigned char
#	define uint32_t		DWORD
#	define size_t		SIZE_T
#	define chacha_bzero(mem, size)	SecureZeroMemory(mem, size)
#	define ROTL32(v, n)		_lrotl(v, n)
#	define htole64(n)		n
#	define le64toh(n)		n
#	if _WIN64
#		define CHACHA_X64
#	else
#		define CHACHA_X32
#	endif
#endif
#if defined(_MSC_VER) || defined(__INTEL_COMPILER)
#	define CHACHA_ALIGN(__n) __declspec(align(__n)) /* DECLSPEC_ALIGN() */
#else /* GCC/clang */
#	define CHACHA_ALIGN(__n) __attribute__((aligned(__n)))
#endif


#define CHACHA_BLOCK_LEN	64
#define CHACHA_KEY_128_LEN	16	/* 128 bit key */
#define CHACHA_KEY_256_LEN	32	/* 256 bit key, normal */
#define CHACHA_IV_LEN		8	/* 64 bit */
#define XCHACHA_IV_LEN		24	/* 192 bit */


/* Simple ChaCha context. */
typedef struct chacha_context_s {
	/* const(16) + key(32) + counter(8) + iv(8) */
	CHACHA_ALIGN(8) uint32_t state[(CHACHA_BLOCK_LEN / sizeof(uint32_t))];
	/* Temp buf for chacha transform block. */
	CHACHA_ALIGN(8) uint32_t x[(CHACHA_BLOCK_LEN / sizeof(uint32_t))];
	size_t rounds;
} chacha_context_t, *chacha_context_p;

/* ChaCha context for streams handle. */
typedef struct chacha_context_str_s {
	CHACHA_ALIGN(8) chacha_context_t c; /* Original ChaCha context. */
	/* Key stream. */
	size_t ks_len; /* Key stream num bytes. */
	CHACHA_ALIGN(8) uint32_t ks[(CHACHA_BLOCK_LEN / sizeof(uint32_t))];
} chacha_context_str_t, *chacha_context_str_p;


#define CHACHA_PTR_IS_ALIGNED4(p)	(0 == (((size_t)p) & 3))
#define CHACHA_PTR_IS_ALIGNED8(p)	(0 == (((size_t)p) & 7))
#define CHACHA_PTR_8TO32(ptr)		((uint32_t*)(void*)(size_t)(ptr))
#define CHACHA_PTR_8TO64(ptr)		((uint64_t*)(void*)(size_t)(ptr))

/* interpret four 8 bit unsigned integers as a 32 bit unsigned integer in little endian */
static inline uint32_t
U8TO32_LITTLE(const uint8_t *p) {
	return 
	    (((uint32_t)(p[0])      ) |
	     ((uint32_t)(p[1]) <<  8) |
	     ((uint32_t)(p[2]) << 16) |
	     ((uint32_t)(p[3]) << 24));
}

/* store a 32 bit unsigned integer as four 8 bit unsigned integers in little endian */
static inline void
U32TO8_LITTLE(uint8_t *p, uint32_t v) {
	p[0] = (uint8_t)(v      );
	p[1] = (uint8_t)(v >>  8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}


/* sigma = "expand 32-byte k", as 4 little endian 32-bit unsigned integers */
static const uint32_t chacha_constants_k256[4] = { 
	0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};
/* tau = "expand 16-byte k", as 4 little endian 32-bit unsigned integers */
static const uint32_t chacha_constants_k128[4] = { 
	0x61707865, 0x3120646e, 0x79622d36, 0x6b206574
};

/* 32 bit left rotate */
#ifndef ROTL32
#define ROTL32(__v, __n) ((((uint32_t)(__v)) << (__n)) | (((uint32_t)(__v)) >> (32 - (__n))))
#endif

#define CHACHA_QUARTERROUND(a, b, c, d) {				\
	a += b; d = ROTL32((d ^ a), 16);				\
	c += d; b = ROTL32((b ^ c), 12);				\
	a += b; d = ROTL32((d ^ a),  8);				\
	c += d; b = ROTL32((b ^ c),  7);				\
}

#define CHACHA_DOUBLEROUND(n) {						\
	CHACHA_QUARTERROUND(n[0], n[4], n[ 8], n[12])			\
	CHACHA_QUARTERROUND(n[1], n[5], n[ 9], n[13])			\
	CHACHA_QUARTERROUND(n[2], n[6], n[10], n[14])			\
	CHACHA_QUARTERROUND(n[3], n[7], n[11], n[15])			\
	CHACHA_QUARTERROUND(n[0], n[5], n[10], n[15])			\
	CHACHA_QUARTERROUND(n[1], n[6], n[11], n[12])			\
	CHACHA_QUARTERROUND(n[2], n[7], n[ 8], n[13])			\
	CHACHA_QUARTERROUND(n[3], n[4], n[ 9], n[14])			\
}

#define CHACHA_BLOCK_ADD32(dst, src) {					\
	((uint32_t*)(dst))[ 0] += ((uint32_t*)(src))[ 0];		\
	((uint32_t*)(dst))[ 1] += ((uint32_t*)(src))[ 1];		\
	((uint32_t*)(dst))[ 2] += ((uint32_t*)(src))[ 2];		\
	((uint32_t*)(dst))[ 3] += ((uint32_t*)(src))[ 3];		\
	((uint32_t*)(dst))[ 4] += ((uint32_t*)(src))[ 4];		\
	((uint32_t*)(dst))[ 5] += ((uint32_t*)(src))[ 5];		\
	((uint32_t*)(dst))[ 6] += ((uint32_t*)(src))[ 6];		\
	((uint32_t*)(dst))[ 7] += ((uint32_t*)(src))[ 7];		\
	((uint32_t*)(dst))[ 8] += ((uint32_t*)(src))[ 8];		\
	((uint32_t*)(dst))[ 9] += ((uint32_t*)(src))[ 9];		\
	((uint32_t*)(dst))[10] += ((uint32_t*)(src))[10];		\
	((uint32_t*)(dst))[11] += ((uint32_t*)(src))[11];		\
	((uint32_t*)(dst))[12] += ((uint32_t*)(src))[12];		\
	((uint32_t*)(dst))[13] += ((uint32_t*)(src))[13];		\
	((uint32_t*)(dst))[14] += ((uint32_t*)(src))[14];		\
	((uint32_t*)(dst))[15] += ((uint32_t*)(src))[15];		\
}

/* Src aligned to 4 byte, dst unligned. */
#define CHACHA_BLOCK_COPY_2UNALIGN4(dst, src) {				\
	U32TO8_LITTLE((((uint8_t*)(dst)) +  0), CHACHA_PTR_8TO32(src)[ 0]); \
	U32TO8_LITTLE((((uint8_t*)(dst)) +  4), CHACHA_PTR_8TO32(src)[ 1]); \
	U32TO8_LITTLE((((uint8_t*)(dst)) +  8), CHACHA_PTR_8TO32(src)[ 2]); \
	U32TO8_LITTLE((((uint8_t*)(dst)) + 12), CHACHA_PTR_8TO32(src)[ 3]); \
	U32TO8_LITTLE((((uint8_t*)(dst)) + 16), CHACHA_PTR_8TO32(src)[ 4]); \
	U32TO8_LITTLE((((uint8_t*)(dst)) + 20), CHACHA_PTR_8TO32(src)[ 5]); \
	U32TO8_LITTLE((((uint8_t*)(dst)) + 24), CHACHA_PTR_8TO32(src)[ 6]); \
	U32TO8_LITTLE((((uint8_t*)(dst)) + 28), CHACHA_PTR_8TO32(src)[ 7]); \
	U32TO8_LITTLE((((uint8_t*)(dst)) + 32), CHACHA_PTR_8TO32(src)[ 8]); \
	U32TO8_LITTLE((((uint8_t*)(dst)) + 36), CHACHA_PTR_8TO32(src)[ 9]); \
	U32TO8_LITTLE((((uint8_t*)(dst)) + 40), CHACHA_PTR_8TO32(src)[10]); \
	U32TO8_LITTLE((((uint8_t*)(dst)) + 44), CHACHA_PTR_8TO32(src)[11]); \
	U32TO8_LITTLE((((uint8_t*)(dst)) + 48), CHACHA_PTR_8TO32(src)[12]); \
	U32TO8_LITTLE((((uint8_t*)(dst)) + 52), CHACHA_PTR_8TO32(src)[13]); \
	U32TO8_LITTLE((((uint8_t*)(dst)) + 56), CHACHA_PTR_8TO32(src)[14]); \
	U32TO8_LITTLE((((uint8_t*)(dst)) + 60), CHACHA_PTR_8TO32(src)[15]); \
}

/* Src and dst aligned to 4 byte. */
#define CHACHA_BLOCK_COPY_ALIGN4(dst, src) {				\
	CHACHA_PTR_8TO32(dst)[ 0] = CHACHA_PTR_8TO32(src)[ 0];		\
	CHACHA_PTR_8TO32(dst)[ 1] = CHACHA_PTR_8TO32(src)[ 1];		\
	CHACHA_PTR_8TO32(dst)[ 2] = CHACHA_PTR_8TO32(src)[ 2];		\
	CHACHA_PTR_8TO32(dst)[ 3] = CHACHA_PTR_8TO32(src)[ 3];		\
	CHACHA_PTR_8TO32(dst)[ 4] = CHACHA_PTR_8TO32(src)[ 4];		\
	CHACHA_PTR_8TO32(dst)[ 5] = CHACHA_PTR_8TO32(src)[ 5];		\
	CHACHA_PTR_8TO32(dst)[ 6] = CHACHA_PTR_8TO32(src)[ 6];		\
	CHACHA_PTR_8TO32(dst)[ 7] = CHACHA_PTR_8TO32(src)[ 7];		\
	CHACHA_PTR_8TO32(dst)[ 8] = CHACHA_PTR_8TO32(src)[ 8];		\
	CHACHA_PTR_8TO32(dst)[ 9] = CHACHA_PTR_8TO32(src)[ 9];		\
	CHACHA_PTR_8TO32(dst)[10] = CHACHA_PTR_8TO32(src)[10];		\
	CHACHA_PTR_8TO32(dst)[11] = CHACHA_PTR_8TO32(src)[11];		\
	CHACHA_PTR_8TO32(dst)[12] = CHACHA_PTR_8TO32(src)[12];		\
	CHACHA_PTR_8TO32(dst)[13] = CHACHA_PTR_8TO32(src)[13];		\
	CHACHA_PTR_8TO32(dst)[14] = CHACHA_PTR_8TO32(src)[14];		\
	CHACHA_PTR_8TO32(dst)[15] = CHACHA_PTR_8TO32(src)[15];		\
}

/* Src and dst aligned to 8 bytes. */
#define CHACHA_BLOCK_COPY_ALIGN8(dst, src) {				\
	CHACHA_PTR_8TO64(dst)[0] = CHACHA_PTR_8TO64(src)[0];		\
	CHACHA_PTR_8TO64(dst)[1] = CHACHA_PTR_8TO64(src)[1];		\
	CHACHA_PTR_8TO64(dst)[2] = CHACHA_PTR_8TO64(src)[2];		\
	CHACHA_PTR_8TO64(dst)[3] = CHACHA_PTR_8TO64(src)[3];		\
	CHACHA_PTR_8TO64(dst)[4] = CHACHA_PTR_8TO64(src)[4];		\
	CHACHA_PTR_8TO64(dst)[5] = CHACHA_PTR_8TO64(src)[5];		\
	CHACHA_PTR_8TO64(dst)[6] = CHACHA_PTR_8TO64(src)[6];		\
	CHACHA_PTR_8TO64(dst)[7] = CHACHA_PTR_8TO64(src)[7];		\
}

/* Res and a unligned, b aligned to 4 byte. */
#define CHACHA_BLOCK_XOR_2UNALIGN4_LINE(res, a, b, offset)		\
	U32TO8_LITTLE((((uint8_t*)(res)) + (offset * 4)),		\
	    (U8TO32_LITTLE((((const uint8_t*)(a)) + (offset * 4))) ^	\
	     CHACHA_PTR_8TO32(b)[offset]))
#define CHACHA_BLOCK_XOR_2UNALIGN4(res, a, b) {				\
	CHACHA_BLOCK_XOR_2UNALIGN4_LINE(res, a, b,  0);			\
	CHACHA_BLOCK_XOR_2UNALIGN4_LINE(res, a, b,  1);			\
	CHACHA_BLOCK_XOR_2UNALIGN4_LINE(res, a, b,  2);			\
	CHACHA_BLOCK_XOR_2UNALIGN4_LINE(res, a, b,  3);			\
	CHACHA_BLOCK_XOR_2UNALIGN4_LINE(res, a, b,  4);			\
	CHACHA_BLOCK_XOR_2UNALIGN4_LINE(res, a, b,  5);			\
	CHACHA_BLOCK_XOR_2UNALIGN4_LINE(res, a, b,  6);			\
	CHACHA_BLOCK_XOR_2UNALIGN4_LINE(res, a, b,  7);			\
	CHACHA_BLOCK_XOR_2UNALIGN4_LINE(res, a, b,  8);			\
	CHACHA_BLOCK_XOR_2UNALIGN4_LINE(res, a, b,  9);			\
	CHACHA_BLOCK_XOR_2UNALIGN4_LINE(res, a, b, 10);			\
	CHACHA_BLOCK_XOR_2UNALIGN4_LINE(res, a, b, 11);			\
	CHACHA_BLOCK_XOR_2UNALIGN4_LINE(res, a, b, 12);			\
	CHACHA_BLOCK_XOR_2UNALIGN4_LINE(res, a, b, 13);			\
	CHACHA_BLOCK_XOR_2UNALIGN4_LINE(res, a, b, 14);			\
	CHACHA_BLOCK_XOR_2UNALIGN4_LINE(res, a, b, 15);			\
}

/* Res, a and b aligned to 4 byte. */
#define CHACHA_BLOCK_XOR_ALIGN4_LINE(res, a, b, offset)			\
	CHACHA_PTR_8TO32(res)[offset] =					\
	    (CHACHA_PTR_8TO32(a)[offset] ^ CHACHA_PTR_8TO32(b)[offset])
#define CHACHA_BLOCK_XOR_ALIGN4(res, a, b) {				\
	CHACHA_BLOCK_XOR_ALIGN4_LINE(res, a, b,  0);			\
	CHACHA_BLOCK_XOR_ALIGN4_LINE(res, a, b,  1);			\
	CHACHA_BLOCK_XOR_ALIGN4_LINE(res, a, b,  2);			\
	CHACHA_BLOCK_XOR_ALIGN4_LINE(res, a, b,  3);			\
	CHACHA_BLOCK_XOR_ALIGN4_LINE(res, a, b,  4);			\
	CHACHA_BLOCK_XOR_ALIGN4_LINE(res, a, b,  5);			\
	CHACHA_BLOCK_XOR_ALIGN4_LINE(res, a, b,  6);			\
	CHACHA_BLOCK_XOR_ALIGN4_LINE(res, a, b,  7);			\
	CHACHA_BLOCK_XOR_ALIGN4_LINE(res, a, b,  8);			\
	CHACHA_BLOCK_XOR_ALIGN4_LINE(res, a, b,  9);			\
	CHACHA_BLOCK_XOR_ALIGN4_LINE(res, a, b, 10);			\
	CHACHA_BLOCK_XOR_ALIGN4_LINE(res, a, b, 11);			\
	CHACHA_BLOCK_XOR_ALIGN4_LINE(res, a, b, 12);			\
	CHACHA_BLOCK_XOR_ALIGN4_LINE(res, a, b, 13);			\
	CHACHA_BLOCK_XOR_ALIGN4_LINE(res, a, b, 14);			\
	CHACHA_BLOCK_XOR_ALIGN4_LINE(res, a, b, 15);			\
}

/* Res, a and b aligned to 8 bytes. */
#define CHACHA_BLOCK_XOR_ALIGN8_LINE(res, a, b, offset)			\
	CHACHA_PTR_8TO64(res)[offset] =					\
	    (CHACHA_PTR_8TO64(a)[offset] ^ CHACHA_PTR_8TO64(b)[offset])
#define CHACHA_BLOCK_XOR_ALIGN8(res, a, b) {				\
	CHACHA_BLOCK_XOR_ALIGN8_LINE(res, a, b, 0);			\
	CHACHA_BLOCK_XOR_ALIGN8_LINE(res, a, b, 1);			\
	CHACHA_BLOCK_XOR_ALIGN8_LINE(res, a, b, 2);			\
	CHACHA_BLOCK_XOR_ALIGN8_LINE(res, a, b, 3);			\
	CHACHA_BLOCK_XOR_ALIGN8_LINE(res, a, b, 4);			\
	CHACHA_BLOCK_XOR_ALIGN8_LINE(res, a, b, 5);			\
	CHACHA_BLOCK_XOR_ALIGN8_LINE(res, a, b, 6);			\
	CHACHA_BLOCK_XOR_ALIGN8_LINE(res, a, b, 7);			\
}

#ifdef CHACHA_X64
#	define CHACHA_BLOCK_XOR_ALIGN	CHACHA_BLOCK_XOR_ALIGN8
#else
#	define CHACHA_BLOCK_XOR_ALIGN	CHACHA_BLOCK_XOR_ALIGN4
#endif



/* key - 16/32 bytes */
static inline void
chacha_key_set(chacha_context_p ctx, const uint8_t *key, const size_t key_size) {

	if (256 == key_size || CHACHA_KEY_256_LEN == key_size) { /* recommended */
		ctx->state[ 0] = chacha_constants_k256[0];
		ctx->state[ 1] = chacha_constants_k256[1];
		ctx->state[ 2] = chacha_constants_k256[2];
		ctx->state[ 3] = chacha_constants_k256[3];
		ctx->state[ 4] = U8TO32_LITTLE(key +  0);
		ctx->state[ 5] = U8TO32_LITTLE(key +  4);
		ctx->state[ 6] = U8TO32_LITTLE(key +  8);
		ctx->state[ 7] = U8TO32_LITTLE(key + 12);
		ctx->state[ 8] = U8TO32_LITTLE(key + 16);
		ctx->state[ 9] = U8TO32_LITTLE(key + 20);
		ctx->state[10] = U8TO32_LITTLE(key + 24);
		ctx->state[11] = U8TO32_LITTLE(key + 28);
	} else {
		ctx->state[ 0] = chacha_constants_k128[0];
		ctx->state[ 1] = chacha_constants_k128[1];
		ctx->state[ 2] = chacha_constants_k128[2];
		ctx->state[ 3] = chacha_constants_k128[3];
		ctx->state[ 4] = U8TO32_LITTLE(key +  0);
		ctx->state[ 5] = U8TO32_LITTLE(key +  4);
		ctx->state[ 6] = U8TO32_LITTLE(key +  8);
		ctx->state[ 7] = U8TO32_LITTLE(key + 12);
		ctx->state[ 8] = U8TO32_LITTLE(key +  0);
		ctx->state[ 9] = U8TO32_LITTLE(key +  4);
		ctx->state[10] = U8TO32_LITTLE(key +  8);
		ctx->state[11] = U8TO32_LITTLE(key + 12);
	}
}

/* counter - 8 bytes, optional */
static inline void
chacha_counter_set(chacha_context_p ctx, const uint8_t *counter) {

	if (counter == NULL) {
		ctx->state[12] = 0;
		ctx->state[13] = 0;
	} else {
		ctx->state[12] = U8TO32_LITTLE(counter + 0);
		ctx->state[13] = U8TO32_LITTLE(counter + 4);
	}
}
static inline void
chacha_counter_set_u64(chacha_context_p ctx, uint64_t counter) {

	counter = htole64(counter);
	ctx->state[12] = (uint32_t)counter;
	ctx->state[13] = (uint32_t)(counter >> 32);
}
static inline uint64_t
chacha_counter_get_u64(chacha_context_p ctx) {

	return le64toh(((uint64_t)ctx->state[12]) | (((uint64_t)ctx->state[13]) << 32));
}

/* iv - 8 bytes, optional */
static inline void
chacha_iv_set(chacha_context_p ctx, const uint8_t *iv) {

	if (iv == NULL) {
		ctx->state[14] = 0;
		ctx->state[15] = 0;
	} else {
		ctx->state[14] = U8TO32_LITTLE(iv + 0);
		ctx->state[15] = U8TO32_LITTLE(iv + 4);
	}
}

/* key - 16/32 bytes
 * iv - 16 bytes, optional
 * rounds - 8/12/20
 * dst - point to 32 bytes buf
 */
static inline void
hchacha(const uint8_t *key, const size_t key_size, const uint8_t *iv, size_t rounds,
    uint8_t *dst) {
	size_t i;
	chacha_context_t ctx;

	chacha_key_set(&ctx, key, key_size);
	/* Set IV. */
	if (NULL != iv) {
		ctx.state[12] = U8TO32_LITTLE(iv +  0); /* Counter. */
		ctx.state[13] = U8TO32_LITTLE(iv +  4);
		ctx.state[14] = U8TO32_LITTLE(iv +  8); /* IV. */
		ctx.state[15] = U8TO32_LITTLE(iv + 12);
	} else {
		ctx.state[12] = 0; /* Counter. */
		ctx.state[13] = 0;
		ctx.state[14] = 0; /* IV. */
		ctx.state[15] = 0;
	}

	for (i = 0; i < rounds; i += 2) {
		CHACHA_DOUBLEROUND(ctx.state);
	}

	/* Indices for the chacha constant. */
	U32TO8_LITTLE(dst +  0, ctx.state[ 0]);
	U32TO8_LITTLE(dst +  4, ctx.state[ 1]);
	U32TO8_LITTLE(dst +  8, ctx.state[ 2]);
	U32TO8_LITTLE(dst + 12, ctx.state[ 3]);
	/* Indices for the iv. */
	U32TO8_LITTLE(dst + 16, ctx.state[12]);
	U32TO8_LITTLE(dst + 20, ctx.state[13]);
	U32TO8_LITTLE(dst + 24, ctx.state[14]);
	U32TO8_LITTLE(dst + 28, ctx.state[15]);
	/* Zero only part of context. */
	chacha_bzero(ctx.state, CHACHA_BLOCK_LEN);
}

/* key - 16/32 bytes
 * iv - 24 bytes, optional
 * rounds - 8/12/20
 * xchacha(key, counter, iv, src) = chacha(hchacha(key, iv[0:15]), counter, iv[16:23], src)
 */
static inline void 
xchacha_set_key_iv_rounds(chacha_context_p ctx, const uint8_t *key, const size_t key_size,
    const uint8_t *iv, const size_t rounds) {

	/* Chacha key allways 256 bits after hchacha */
	ctx->state[0] = chacha_constants_k256[0];
	ctx->state[1] = chacha_constants_k256[1];
	ctx->state[2] = chacha_constants_k256[2];
	ctx->state[3] = chacha_constants_k256[3];
	/* Gen 256 bits key from key and first part of iv. */
	hchacha(key, key_size, iv, rounds, (uint8_t*)&ctx->state[4]);
	if (NULL != iv) {
		chacha_iv_set(ctx, (iv + 16));
	} else {
		chacha_iv_set(ctx, NULL);
	}
	ctx->rounds = rounds;
}

/* Block tranform. */
static inline void
chacha_block_aligned8(chacha_context_p ctx, const uint8_t *src, uint8_t *dst) {
	size_t i;

	/* Load state into temp x. */
	CHACHA_BLOCK_COPY_ALIGN8(ctx->x, ctx->state);
	/* Transform 1 temp x: rotl + add. */
	for (i = 0; i < ctx->rounds; i += 2) {
		CHACHA_DOUBLEROUND(ctx->x);
	}
	/* Transform 2 temp x: x += state. */
	CHACHA_BLOCK_ADD32(ctx->x, ctx->state);
	/* Load src data and xor with temp x and store to dst. */
	if (NULL != src) {
		CHACHA_BLOCK_XOR_ALIGN8(dst, src, ctx->x);
	} else {
		CHACHA_BLOCK_COPY_ALIGN8(dst, ctx->x);
	}
	/* Increment the 64 bit counter, split in to two 32 bit halves. */
	/* Stopping at 2^70 bytes per nonce is user's responsibility. */
	ctx->state[12] ++;
	if (0 == ctx->state[12]) {
		ctx->state[13] ++;
	}
}
static inline void
chacha_block_aligned4(chacha_context_p ctx, const uint8_t *src, uint8_t *dst) {
	size_t i;

	/* Load state into temp x. */
	CHACHA_BLOCK_COPY_ALIGN4(ctx->x, ctx->state);
	/* Transform 1 temp x: rotl + add. */
	for (i = 0; i < ctx->rounds; i += 2) {
		CHACHA_DOUBLEROUND(ctx->x);
	}
	/* Transform 2 temp x: x += state. */
	CHACHA_BLOCK_ADD32(ctx->x, ctx->state);
	/* Load src data and xor with temp x and store to dst. */
	if (NULL != src) {
		CHACHA_BLOCK_XOR_ALIGN4(dst, src, ctx->x);
	} else {
		CHACHA_BLOCK_COPY_ALIGN4(dst, ctx->x);
	}
	/* Increment the 64 bit counter, split in to two 32 bit halves. */
	/* Stopping at 2^70 bytes per nonce is user's responsibility. */
	ctx->state[12] ++;
	if (0 == ctx->state[12]) {
		ctx->state[13] ++;
	}
}
#ifdef CHACHA_X64
#	define chacha_block_aligned	chacha_block_aligned8
#else
#	define chacha_block_aligned	chacha_block_aligned4
#endif
static inline void
chacha_block_unaligneg(chacha_context_p ctx, const uint8_t *src, uint8_t *dst) {
	size_t i;

	/* Load state into temp x. */
	CHACHA_BLOCK_COPY_ALIGN4(ctx->x, ctx->state);
	/* Transform 1 temp x: rotl + add. */
	for (i = 0; i < ctx->rounds; i += 2) {
		CHACHA_DOUBLEROUND(ctx->x);
	}
	/* Transform 2 temp x: x += state. */
	CHACHA_BLOCK_ADD32(ctx->x, ctx->state);
	/* Load src data and xor with temp x and store to dst. */
	if (NULL != src) {
		CHACHA_BLOCK_XOR_2UNALIGN4(dst, src, ctx->x);
	} else {
		CHACHA_BLOCK_COPY_2UNALIGN4(dst, ctx->x);
	}
	/* Increment the 64 bit counter, split in to two 32 bit halves. */
	/* Stopping at 2^70 bytes per nonce is user's responsibility. */
	ctx->state[12] ++;
	if (0 == ctx->state[12]) {
		ctx->state[13] ++;
	}
}

/* Buf tranform. */
static inline void
chacha_blocks_transform(chacha_context_p ctx, const uint8_t *src, size_t blocks_count,
    uint8_t *dst) {

	if (0 == blocks_count)
		return;
#ifdef CHACHA_X64
	if ((CHACHA_PTR_IS_ALIGNED8(src) && CHACHA_PTR_IS_ALIGNED8(dst))) {
		for (; 0 != blocks_count; blocks_count --) {
			/* Load, transform and save block. */
			chacha_block_aligned8(ctx, src, dst);
			if (NULL != src)
				src += CHACHA_BLOCK_LEN;
			dst += CHACHA_BLOCK_LEN;
		}
	} else
#endif
	if ((CHACHA_PTR_IS_ALIGNED4(src) && CHACHA_PTR_IS_ALIGNED4(dst))) {
		for (; 0 != blocks_count; blocks_count --) {
			/* Load, transform and save block. */
			chacha_block_aligned4(ctx, src, dst);
			if (NULL != src)
				src += CHACHA_BLOCK_LEN;
			dst += CHACHA_BLOCK_LEN;
		}
	} else {
		for (; 0 != blocks_count; blocks_count --) {
			/* Load, transform and save block. */
			chacha_block_unaligneg(ctx, src, dst);
			if (NULL != src)
				src += CHACHA_BLOCK_LEN;
			dst += CHACHA_BLOCK_LEN;
		}
	}
}


/* key - 16/32 bytes
 * counter - 8 bytes, optional
 * iv - 8 bytes, optional
 * rounds - 8/12/20
 */
static inline void 
chacha_init(chacha_context_p ctx, const uint8_t *key, const size_t key_size,
    const uint8_t *counter, const uint8_t *iv, const size_t rounds) {

	chacha_key_set(ctx, key, key_size);
	chacha_counter_set(ctx, counter);
	chacha_iv_set(ctx, iv);
	ctx->rounds = rounds;
}
/* key - 16/32 bytes
 * counter - 8 bytes, optional
 * iv - 24 bytes, optional
 * rounds - 8/12/20
 * xchacha(key, counter, iv, src) = chacha(hchacha(key, iv[0:15]), counter, iv[16:23], src)
 */
static inline void 
xchacha_init(chacha_context_p ctx, const uint8_t *key, const size_t key_size,
    const uint8_t *counter, const uint8_t *iv, const size_t rounds) {

	xchacha_set_key_iv_rounds(ctx, key, key_size, iv, rounds);
	chacha_counter_set(ctx, counter);
}

static inline void
chacha_final(chacha_context_p ctx) {

	chacha_bzero(ctx, sizeof(chacha_context_t));
}


/* ChaCha partial messages process / stream. */
static inline void 
chacha_str_init(chacha_context_str_p ctx, const uint8_t *key, const size_t key_size,
    const uint8_t *counter, const uint8_t *iv, const size_t rounds) {

	chacha_init(&ctx->c, key, key_size, counter, iv, rounds);
	ctx->ks_len = 0;
}

static inline void 
xchacha_str_init(chacha_context_str_p ctx, const uint8_t *key, const size_t key_size,
    const uint8_t *counter, const uint8_t *iv, const size_t rounds) {

	xchacha_init(&ctx->c, key, key_size, counter, iv, rounds);
	ctx->ks_len = 0;
}

static inline void
chacha_str_data_crypt(chacha_context_str_p ctx, const uint8_t *src, size_t bytes,
    uint8_t *dst) {
	uint8_t *ptr;
	size_t i, count;

	if (0 == bytes)
		return;
	count = ctx->ks_len;
	if (0 != count) { /* Have saved key stream. */
		/* Key stream start point. */
		ptr = (((uint8_t*)ctx->ks) + (CHACHA_BLOCK_LEN - ctx->ks_len));
		/* Limit num of bytes to process. */
		if (count > bytes)
			count = bytes;
		if (NULL != src) {
			/* XOR with key stream. Slow. */
			for (i = 0; i < count; i ++)
				dst[i] = src[i] ^ ptr[i];
			src += count;
		} else {
			memcpy(dst, ptr, count);
		}
		ctx->ks_len -= count; /* Update key stream saved len. */
		dst += count;
		bytes -= count;
		if (0 == bytes)
			return;
	}
	if (bytes >= CHACHA_BLOCK_LEN) {
		count = (bytes / CHACHA_BLOCK_LEN); /* blocks_count */
		chacha_blocks_transform(&ctx->c, src, count, dst);
		count *= CHACHA_BLOCK_LEN; /* blocks_size */
		if (NULL != src)
			src += count;
		dst += count;
		bytes -= count;
	}
	/* Process tail. */
	if (0 != bytes) { /* Incomplete data block. */
		/* Replace src and dst buf with temp buf, copy src data to temp. */
		ctx->ks_len = (CHACHA_BLOCK_LEN - bytes);
		ptr = dst;
		dst = (uint8_t*)ctx->ks;
		if (NULL != src) {
			memcpy(dst, src, bytes);
			memset((dst + bytes), 0, ctx->ks_len);
			src = dst;
		}
		/* Transform block. */
		chacha_block_aligned(&ctx->c, src, dst);
		/* Copy result from temp buf to dst. */
		memcpy(ptr, dst, bytes);
	}
}

static inline void
chacha_str_final(chacha_context_str_p ctx) {

	chacha_bzero(ctx, sizeof(chacha_context_str_t));
}

/* One shot chacha. */
/* key - 16/32 bytes
 * counter - 8 bytes, optional
 * iv - 8 bytes, optional
 * rounds - 8/12/20
 */
static inline void
chacha(const uint8_t *key, const size_t key_size, const uint8_t *counter, const uint8_t *iv,
    const size_t rounds, const uint8_t *src, const size_t bytes, uint8_t *dst) {
	chacha_context_str_t ctx;

	if (0 == bytes)
		return;
	chacha_str_init(&ctx, key, key_size, counter, iv, rounds);
	chacha_str_data_crypt(&ctx, src, bytes, dst);
	chacha_str_final(&ctx);
}

/* One shot xchacha. */
/* key - 16/32 bytes
 * counter - 8 bytes, optional
 * iv - 24 bytes, optional
 * rounds - 8/12/20
 * xchacha(key, counter, iv, src) = chacha(hchacha(key, iv[0:15]), counter, iv[16:23], src)
 */
static inline void
xchacha(const uint8_t *key, const size_t key_size, const uint8_t *counter, const uint8_t *iv,
    const size_t rounds, const uint8_t *src, const size_t bytes, uint8_t *dst) {
	chacha_context_str_t ctx;

	if (0 == bytes)
		return;
	xchacha_str_init(&ctx, key, key_size, counter, iv, rounds);
	chacha_str_data_crypt(&ctx, src, bytes, dst);
	chacha_str_final(&ctx);
}




#ifdef CHACHA_SELF_TEST

typedef struct chacha_test1_vectors_s {
	size_t	rounds;
	uint8_t	*key;
	size_t	key_size;
	uint8_t	*count;
	uint8_t	*iv; /* nonce */
	size_t	data_size;
	uint8_t	*plain;
	uint8_t	*encrypted; /* key stream */
} chacha_tst1v_t, *chacha_tst1v_p;

static chacha_tst1v_t chacha_tst1v[] = {
	/* From: https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-00 */
	/* From: http://www.potaroo.net/ietf/idref/draft-nir-cfrg-chacha20-poly1305/#page-23 */
	{ /* A.1: Test_ Vector #2 */
		/*.rounds =*/		20,
		/*.key =*/ 	(uint8_t*)"0000000000000000000000000000000000000000000000000000000000000000",
		/*.key_size =*/		64,
		/*.count =*/ 	(uint8_t*)"0000000000000001",
		/*.iv =*/ 	(uint8_t*)"0000000000000000",
		/*.data_size =*/	128,
		/*.plain =*/	(uint8_t*)NULL,
		/*.encrypted =*/ (uint8_t*)"9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f",
	}, {
		/*.rounds =*/		20,
		/*.key =*/ 	(uint8_t*)"0000000000000000000000000000000000000000000000000000000000000001",
		/*.key_size =*/		64,
		/*.count =*/ 	(uint8_t*)NULL,
		/*.iv =*/ 	(uint8_t*)"0000000000000000",
		/*.data_size =*/	120,
		/*.plain =*/	(uint8_t*)NULL,
		/*.encrypted =*/ (uint8_t*)"4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275",
	}, { /* A.1: Test_ Vector #3 */
		/*.rounds =*/		20,
		/*.key =*/ 	(uint8_t*)"0000000000000000000000000000000000000000000000000000000000000001",
		/*.key_size =*/		64,
		/*.count =*/ 	(uint8_t*)"0000000000000001",
		/*.iv =*/ 	(uint8_t*)"0000000000000000",
		/*.data_size =*/	128,
		/*.plain =*/	(uint8_t*)NULL,
		/*.encrypted =*/ (uint8_t*)"3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0",
	}, {
		/*.rounds =*/		20,
		/*.key =*/ 	(uint8_t*)"0000000000000000000000000000000000000000000000000000000000000000",
		/*.key_size =*/		64,
		/*.count =*/ 	(uint8_t*)NULL,
		/*.iv =*/ 	(uint8_t*)"0000000000000001",
		/*.data_size =*/	120,
		/*.plain =*/	(uint8_t*)NULL,
		/*.encrypted =*/ (uint8_t*)"de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e3",
	}, {
		/*.rounds =*/		20,
		/*.key =*/ 	(uint8_t*)"0000000000000000000000000000000000000000000000000000000000000000",
		/*.key_size =*/		64,
		/*.count =*/ 	(uint8_t*)NULL,
		/*.iv =*/ 	(uint8_t*)"0100000000000000",
		/*.data_size =*/	120,
		/*.plain =*/	(uint8_t*)NULL,
		/*.encrypted =*/ (uint8_t*)"ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb004",
	}, {
		/*.rounds =*/		20,
		/*.key =*/ 	(uint8_t*)"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		/*.key_size =*/		64,
		/*.count =*/ 	(uint8_t*)NULL,
		/*.iv =*/ 	(uint8_t*)"0001020304050607",
		/*.data_size =*/	500,
		/*.plain =*/	(uint8_t*)NULL,
		/*.encrypted =*/ (uint8_t*)"f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb",
	}, { /* A.1: Test_ Vector #4 */
		/*.rounds =*/		20,
		/*.key =*/ 	(uint8_t*)"00ff000000000000000000000000000000000000000000000000000000000000",
		/*.key_size =*/		64,
		/*.count =*/ 	(uint8_t*)"0000000000000002",
		/*.iv =*/ 	(uint8_t*)"0000000000000000",
		/*.data_size =*/	128,
		/*.plain =*/	(uint8_t*)NULL,
		/*.encrypted =*/ (uint8_t*)"72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096",
	}, { /* A.1: Test_ Vector #5 */
		/*.rounds =*/		20,
		/*.key =*/ 	(uint8_t*)"0000000000000000000000000000000000000000000000000000000000000000",
		/*.key_size =*/		64,
		/*.count =*/ 	(uint8_t*)"0000000000000000",
		/*.iv =*/ 	(uint8_t*)"0000000000000002",
		/*.data_size =*/	128,
		/*.plain =*/	(uint8_t*)NULL,
		/*.encrypted =*/ (uint8_t*)"c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c78a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d",
	}, { /* A.2: Test_ Vector #2 */
		/*.rounds =*/		20,
		/*.key =*/ 	(uint8_t*)"0000000000000000000000000000000000000000000000000000000000000001",
		/*.key_size =*/		64,
		/*.count =*/ 	(uint8_t*)"0000000000000001",
		/*.iv =*/ 	(uint8_t*)"0000000000000002",
		/*.data_size =*/	750,
		/*.plain =*/	(uint8_t*)"416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
		/*.encrypted =*/ (uint8_t*)"a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221",
	}, { /* A.2: Test_ Vector #3 */
		/*.rounds =*/		20,
		/*.key =*/ 	(uint8_t*)"1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
		/*.key_size =*/		64,
		/*.count =*/ 	(uint8_t*)"000000000000002a",
		/*.iv =*/ 	(uint8_t*)"0000000000000002",
		/*.data_size =*/	254,
		/*.plain =*/	(uint8_t*)"2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
		/*.encrypted =*/ (uint8_t*)"62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1",
	},
	/* From: http://tools.ietf.org/html/draft-strombergson-chacha-test-vectors-00 */
	{ /* TC1: All zero key and IV. key: 128, rounds: 8. */
		/*.rounds =*/		8,
		/*.key =*/ 	(uint8_t*)"00000000000000000000000000000000",
		/*.key_size =*/		32,
		/*.count =*/ 	(uint8_t*)"0000000000000000",
		/*.iv =*/ 	(uint8_t*)"0000000000000000",
		/*.data_size =*/	128,
		/*.plain =*/	(uint8_t*)NULL,
		/*.encrypted =*/ (uint8_t*)"e28a5fa4a67f8c5defed3e6fb7303486aa8427d31419a729572d777953491120b64ab8e72b8deb85cd6aea7cb6089a101824beeb08814a428aab1fa2c816081b",
	}, { /* TC1: All zero key and IV. key: 128, rounds: 12. */
		/*.rounds =*/		12,
		/*.key =*/ 	(uint8_t*)"00000000000000000000000000000000",
		/*.key_size =*/		32,
		/*.count =*/ 	(uint8_t*)"0000000000000000",
		/*.iv =*/ 	(uint8_t*)"0000000000000000",
		/*.data_size =*/	128,
		/*.plain =*/	(uint8_t*)NULL,
		/*.encrypted =*/ (uint8_t*)"e1047ba9476bf8ff312c01b4345a7d8ca5792b0ad467313f1dc412b5fdce32410dea8b68bd774c36a920f092a04d3f95274fbeff97bc8491fcef37f85970b450",
	}, { /* TC1: All zero key and IV. key: 128, rounds: 20. */
		/*.rounds =*/		20,
		/*.key =*/ 	(uint8_t*)"00000000000000000000000000000000",
		/*.key_size =*/		32,
		/*.count =*/ 	(uint8_t*)"0000000000000000",
		/*.iv =*/ 	(uint8_t*)"0000000000000000",
		/*.data_size =*/	128,
		/*.plain =*/	(uint8_t*)NULL,
		/*.encrypted =*/ (uint8_t*)"89670952608364fd00b2f90936f031c8e756e15dba04b8493d00429259b20f46cc04f111246b6c2ce066be3bfb32d9aa0fddfbc12123d4b9e44f34dca05a103f",
	}, { /* TC1: All zero key and IV. key: 256, rounds: 8. */
		/*.rounds =*/		8,
		/*.key =*/ 	(uint8_t*)"0000000000000000000000000000000000000000000000000000000000000000",
		/*.key_size =*/		64,
		/*.count =*/ 	(uint8_t*)"0000000000000000",
		/*.iv =*/ 	(uint8_t*)"0000000000000000",
		/*.data_size =*/	128,
		/*.plain =*/	(uint8_t*)NULL,
		/*.encrypted =*/ (uint8_t*)"3e00ef2f895f40d67f5bb8e81f09a5a12c840ec3ce9a7f3b181be188ef711a1e984ce172b9216f419f445367456d5619314a42a3da86b001387bfdb80e0cfe42",
	}, { /* TC1: All zero key and IV. key: 256, rounds: 12. */
		/*.rounds =*/		12,
		/*.key =*/ 	(uint8_t*)"0000000000000000000000000000000000000000000000000000000000000000",
		/*.key_size =*/		64,
		/*.count =*/ 	(uint8_t*)"0000000000000000",
		/*.iv =*/ 	(uint8_t*)"0000000000000000",
		/*.data_size =*/	128,
		/*.plain =*/	(uint8_t*)NULL,
		/*.encrypted =*/ (uint8_t*)"9bf49a6a0755f953811fce125f2683d50429c3bb49e074147e0089a52eae155f0564f879d27ae3c02ce82834acfa8c793a629f2ca0de6919610be82f411326be",
	}, { /* TC1: All zero key and IV. key: 256, rounds: 20. */
		/*.rounds =*/		20,
		/*.key =*/ 	(uint8_t*)"0000000000000000000000000000000000000000000000000000000000000000",
		/*.key_size =*/		64,
		/*.count =*/ 	(uint8_t*)"0000000000000000",
		/*.iv =*/ 	(uint8_t*)"0000000000000000",
		/*.data_size =*/	128,
		/*.plain =*/	(uint8_t*)NULL,
		/*.encrypted =*/ (uint8_t*)"76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
	}, { /* TC8: Random key and IV. key: 128, rounds: 8. */
		/*.rounds =*/		8,
		/*.key =*/ 	(uint8_t*)"c46ec1b18ce8a878725a37e780dfb735",
		/*.key_size =*/		32,
		/*.count =*/ 	(uint8_t*)"0000000000000000",
		/*.iv =*/ 	(uint8_t*)"1ada31d5cf688221",
		/*.data_size =*/	128,
		/*.plain =*/	(uint8_t*)NULL,
		/*.encrypted =*/ (uint8_t*)"6a870108859f679118f3e205e2a56a6826ef5a60a4102ac8d4770059fcb7c7bae02f5ce004a6bfbbea53014dd82107c0aa1c7ce11b7d78f2d50bd3602bbd2594",
	}, { /* TC8: Random key and IV. key: 128, rounds: 12. */
		/*.rounds =*/		12,
		/*.key =*/ 	(uint8_t*)"c46ec1b18ce8a878725a37e780dfb735",
		/*.key_size =*/		32,
		/*.count =*/ 	(uint8_t*)"0000000000000000",
		/*.iv =*/ 	(uint8_t*)"1ada31d5cf688221",
		/*.data_size =*/	128,
		/*.plain =*/	(uint8_t*)NULL,
		/*.encrypted =*/ (uint8_t*)"b02bd81eb55c8f68b5e9ca4e307079bc225bd22007eddc6702801820709ce09807046a0d2aa552bfdbb49466176d56e32d519e10f5ad5f2746e241e09bdf9959",
	}, { /* TC8: Random key and IV. key: 128, rounds: 20. */
		/*.rounds =*/		20,
		/*.key =*/ 	(uint8_t*)"c46ec1b18ce8a878725a37e780dfb735",
		/*.key_size =*/		32,
		/*.count =*/ 	(uint8_t*)"0000000000000000",
		/*.iv =*/ 	(uint8_t*)"1ada31d5cf688221",
		/*.data_size =*/	128,
		/*.plain =*/	(uint8_t*)NULL,
		/*.encrypted =*/ (uint8_t*)"826abdd84460e2e9349f0ef4af5b179b426e4b2d109a9c5bb44000ae51bea90a496beeef62a76850ff3f0402c4ddc99f6db07f151c1c0dfac2e56565d6289625",
	}, { /* TC8: Random key and IV. key: 256, rounds: 8. */
		/*.rounds =*/		8,
		/*.key =*/ 	(uint8_t*)"c46ec1b18ce8a878725a37e780dfb7351f68ed2e194c79fbc6aebee1a667975d",
		/*.key_size =*/		64,
		/*.count =*/ 	(uint8_t*)"0000000000000000",
		/*.iv =*/ 	(uint8_t*)"1ada31d5cf688221",
		/*.data_size =*/	128,
		/*.plain =*/	(uint8_t*)NULL,
		/*.encrypted =*/ (uint8_t*)"838751b42d8ddd8a3d77f48825a2ba752cf4047cb308a5978ef274973be374c96ad848065871417b08f034e681fe46a93f7d5c61d1306614d4aaf257a7cff08b",
	}, { /* TC8: Random key and IV. key: 256, rounds: 12. */
		/*.rounds =*/		12,
		/*.key =*/ 	(uint8_t*)"c46ec1b18ce8a878725a37e780dfb7351f68ed2e194c79fbc6aebee1a667975d",
		/*.key_size =*/		64,
		/*.count =*/ 	(uint8_t*)"0000000000000000",
		/*.iv =*/ 	(uint8_t*)"1ada31d5cf688221",
		/*.data_size =*/	128,
		/*.plain =*/	(uint8_t*)NULL,
		/*.encrypted =*/ (uint8_t*)"1482072784bc6d06b4e73bdc118bc0103c7976786ca918e06986aa251f7e9cc1b2749a0a16ee83b4242d2e99b08d7c20092b80bc466c87283b61b1b39d0ffbab",
	}, { /* TC8: Random key and IV. key: 256, rounds: 20. */
		/*.rounds =*/		20,
		/*.key =*/ 	(uint8_t*)"c46ec1b18ce8a878725a37e780dfb7351f68ed2e194c79fbc6aebee1a667975d",
		/*.key_size =*/		64,
		/*.count =*/ 	(uint8_t*)"0000000000000000",
		/*.iv =*/ 	(uint8_t*)"1ada31d5cf688221",
		/*.data_size =*/	128,
		/*.plain =*/	(uint8_t*)NULL,
		/*.encrypted =*/ (uint8_t*)"f63a89b75c2271f9368816542ba52f06ed49241792302b00b5e8f80ae9a473afc25b218f519af0fdd406362e8d69de7f54c604a6e00f353f110f771bdca8ab92",
	}, { /* NULL */
		/*.rounds =*/		0,
		/*.key =*/ 		NULL,
		/*.key_size =*/		0,
		/*.count =*/ 		NULL,
		/*.iv =*/ 		NULL,
		/*.data_size =*/	0,
		/*.plain =*/		NULL,
		/*.encrypted =*/	NULL,
	}
};


#define CHACHA_TEST_LEN		2048
/*
 * hchacha/8 test
 * key [192,193,194,..223]
 * iv [16,17,18,..31]
 */
static const unsigned char expected_hchacha[32] = {
	0xe6, 0x19, 0x0f, 0x48, 0xf1, 0xc0, 0x2a, 0x68,
	0xb8, 0xf2, 0x2e, 0xf8, 0xbc, 0xfd, 0x41, 0x06,
	0x7b, 0xa9, 0x36, 0xf3, 0x63, 0x2f, 0x5c, 0x6d,
	0x40, 0x39, 0x24, 0xb3, 0x74, 0x68, 0xcb, 0xdd,
};

/*
 * oneshot chacha+xchacha/8 test
 * key [192,193,194,..223]
 * iv [16,17,18,..31]
 */
/* xor of all the blocks from the one-shot test sequence */
static const unsigned char expected_chacha_oneshot[CHACHA_BLOCK_LEN] = {
	0x21, 0x5b, 0x81, 0x79, 0x74, 0xef, 0x98, 0x89,
	0xc6, 0x40, 0x47, 0x53, 0x42, 0x01, 0x24, 0x88,
	0x21, 0xa3, 0xb6, 0xc8, 0x43, 0x62, 0x0b, 0x00,
	0x19, 0xd0, 0xd5, 0xee, 0x6c, 0x21, 0xf8, 0x51,
	0xa8, 0xb3, 0x45, 0x56, 0x72, 0xc1, 0x85, 0x0e,
	0xe1, 0x43, 0xbe, 0xd6, 0xa6, 0x8b, 0x3d, 0xdc,
	0x3d, 0xf7, 0x64, 0xfd, 0x80, 0x0c, 0xd9, 0x58,
	0xf8, 0x06, 0x40, 0xf4, 0xc2, 0x14, 0xba, 0x84,
};
/* xor of all the blocks from the one-shot test sequence */
static const unsigned char expected_xchacha_oneshot[CHACHA_BLOCK_LEN] = {
	0x01, 0xd1, 0x84, 0x26, 0x1b, 0x7d, 0x44, 0x4d,
	0x3a, 0x8f, 0xef, 0x3f, 0x1e, 0x11, 0xb5, 0xa0,
	0x07, 0x04, 0x46, 0x4c, 0xfb, 0x6b, 0xd0, 0x30,
	0x42, 0x3d, 0xfa, 0x56, 0x71, 0x33, 0x96, 0xdb,
	0xef, 0x0f, 0x09, 0xc1, 0xde, 0x41, 0xc5, 0xa8,
	0xba, 0x37, 0x59, 0x3f, 0x43, 0xc3, 0xf8, 0xc4,
	0xce, 0xd5, 0xf0, 0x51, 0x5f, 0x2c, 0x5e, 0xcf,
	0xe2, 0x5e, 0x68, 0x95, 0x7a, 0x5c, 0x02, 0xea,
};

/* Import from little-endian hex string (L->H). */
static inline int
chacha_import_le_hex(uint8_t *a, size_t count, uint8_t *buf, size_t buf_size) {
	register uint8_t *r_pos, *r_pos_max, *w_pos, *w_pos_max, cur_char, byte = 0;
	register size_t cnt;

	if (0 == count || 0 == buf_size)
		return (EINVAL);
	if ((count * sizeof(uint8_t)) < (buf_size / 2))
		return (EOVERFLOW);
	r_pos = buf;
	r_pos_max = (r_pos + buf_size);
	w_pos = (uint8_t*)a;
	w_pos_max = (w_pos + (count * sizeof(uint8_t)));

	for (cnt = 0; r_pos < r_pos_max; r_pos ++) {
		cur_char = (*r_pos);
		if ('0' <= cur_char && '9' >= cur_char)
			cur_char -= '0';
		else if ('a' <= cur_char && 'f' >= cur_char)
			cur_char -= ('a' - 10);
		else if ('A' <= cur_char && 'F' >= cur_char)
			cur_char -= ('A' - 10);
		else
			continue;
		byte = ((byte << 4) | cur_char);
		cnt ++;
		if (2 > cnt) /* Wait untill 4 + 4 bit before write a byte. */
			continue;
		if (w_pos == w_pos_max)
			return (EOVERFLOW);
		(*w_pos ++) = byte;
		byte = 0;
		cnt = 0;
	}
	memset(w_pos, 0, (w_pos_max - w_pos));
	return (0);
}
/* Import from big-endian hex string (H->L). */
static inline int
chacha_import_be_hex(uint8_t *a, size_t count, uint8_t *buf, size_t buf_size) {
	register uint8_t *r_pos, *w_pos, *w_pos_max, cur_char, byte = 0;
	register size_t cnt;

	if (0 == count || 0 == buf_size)
		return (EINVAL);
	if ((count * sizeof(uint8_t)) < (buf_size / 2))
		return (EOVERFLOW);
	r_pos = (buf + (buf_size - 1));
	w_pos = (uint8_t*)a;
	w_pos_max = (w_pos + (count * sizeof(uint8_t)));

	for (cnt = 0; r_pos >= buf; r_pos --) {
		cur_char = (*r_pos);
		if ('0' <= cur_char && '9' >= cur_char)
			cur_char -= '0';
		else if ('a' <= cur_char && 'f' >= cur_char)
			cur_char -= ('a' - 10);
		else if ('A' <= cur_char && 'F' >= cur_char)
			cur_char -= ('A' - 10);
		else
			continue;
		byte = ((byte >> 4) | (cur_char << 4));
		cnt ++;
		if (2 > cnt) /* Wait untill 4 + 4 bit before write a byte. */
			continue;
		if (w_pos == w_pos_max)
			return (EOVERFLOW);
		(*w_pos ++) = byte;
		byte = 0;
		cnt = 0;
	}
	memset(w_pos, 0, (w_pos_max - w_pos));
	return (0);
}

/* XOR all blocks into one block. */
static inline void
chacha_res_compact(const uint8_t *encrypted, const uint8_t *plain, const size_t len,
    uint8_t *dst) {
	size_t i, h;

	for (i = 0; i < CHACHA_BLOCK_LEN; i ++)
		dst[i] ^= plain[i];
	for (h = 1; h < (len / CHACHA_BLOCK_LEN); h ++) {
		for (i = 0; i < CHACHA_BLOCK_LEN; i ++)
			dst[i] ^= encrypted[(h * CHACHA_BLOCK_LEN) + i] ^ plain[(h * CHACHA_BLOCK_LEN) + i];
	}
}

/* 0 - OK, non zero - error */
static inline int
chacha_self_test(void) {
	int error = 0;
	size_t i, h;
	chacha_tst1v_t tst1v;
	uint8_t	key[CHACHA_KEY_256_LEN];
	uint8_t	count[8];
	uint8_t	iv[XCHACHA_IV_LEN];
	uint8_t	plain[CHACHA_TEST_LEN];
	uint8_t	encrypted[CHACHA_TEST_LEN];
	uint8_t	result[CHACHA_TEST_LEN];
	chacha_context_str_t ctx;

	for (i = 0; 0 != chacha_tst1v[i].rounds; i ++) {
		memset(&tst1v, 0, sizeof(tst1v));

		tst1v.rounds = chacha_tst1v[i].rounds;

		chacha_import_le_hex(key, sizeof(key), chacha_tst1v[i].key, chacha_tst1v[i].key_size);
		tst1v.key = key;
		tst1v.key_size = (chacha_tst1v[i].key_size / 2);

		if (NULL != chacha_tst1v[i].count) {
			//chacha_import_le_hex(count, sizeof(count), chacha_tst1v[i].count, 16);
			chacha_import_be_hex(count, sizeof(count), chacha_tst1v[i].count, 16);
			tst1v.count = count;
		}

		if (NULL != chacha_tst1v[i].iv) {
			chacha_import_le_hex(iv, sizeof(iv), chacha_tst1v[i].iv, 16);
			tst1v.iv = iv;
		}

		tst1v.data_size = (chacha_tst1v[i].data_size / 2);
		if (NULL != chacha_tst1v[i].plain) {
			chacha_import_le_hex(plain, sizeof(plain), chacha_tst1v[i].plain, chacha_tst1v[i].data_size);
			tst1v.plain = plain;
		}
		if (NULL != chacha_tst1v[i].encrypted) {
			chacha_import_le_hex(encrypted, sizeof(encrypted), chacha_tst1v[i].encrypted, chacha_tst1v[i].data_size);
			tst1v.encrypted = encrypted;
		}

		chacha(tst1v.key, tst1v.key_size, tst1v.count, tst1v.iv,
		    tst1v.rounds, tst1v.plain, tst1v.data_size, result);
		if (0 != memcmp(tst1v.encrypted, result, tst1v.data_size))
			error ++;
	}

	/* From: https://github.com/floodyberry/chacha-opt/blob/master/app/extensions/chacha/impl.c */
	/* key [192, 193, 194, ...223], iv [16, 17, 18, ...31], rounds = 8 */
	for (i = 0; i < sizeof(key); i ++) 
		key[i] = (uint8_t)(i + 192);
	for (i = 0; i < sizeof(iv); i ++)
		iv[i] = (uint8_t)(i + 16);
	/* Init src. */
	for (i = 0, h = 0; i < CHACHA_TEST_LEN; i ++) {
		h += (h + i + 0x55);
		h ^= (h >> 3);
		plain[i] = (uint8_t)h;
	}
	/* hchacha. */
	hchacha(key, 256, iv, 8, result);
	if (0 != memcmp(expected_hchacha, result, sizeof(expected_hchacha)))
		error ++;
	/* xchacha one-shot. */
	xchacha(key, 256, NULL, iv, 8, plain, CHACHA_TEST_LEN, result);
	chacha_res_compact(result, plain, CHACHA_TEST_LEN, result);
	if (0 != memcmp(expected_xchacha_oneshot, result, CHACHA_BLOCK_LEN))
		error ++;
	/* xchacha by blocks. */
	xchacha_str_init(&ctx, key, 256, NULL, iv, 8);
	for (i = 0; i < CHACHA_TEST_LEN; i ++) {
		chacha_str_data_crypt(&ctx, &plain[i], 1, &result[i]);
	}
	chacha_str_final(&ctx);
	chacha_res_compact(result, plain, CHACHA_TEST_LEN, result);
	if (0 != memcmp(expected_xchacha_oneshot, result, CHACHA_BLOCK_LEN))
		error ++;
	/* xchacha by blocks 2. */
	xchacha_str_init(&ctx, key, 256, NULL, iv, 8);
	chacha_str_data_crypt(&ctx, plain, 1, result);
	chacha_str_data_crypt(&ctx, &plain[1], (CHACHA_TEST_LEN - 1), &result[1]);
	chacha_str_final(&ctx);
	chacha_res_compact(result, plain, CHACHA_TEST_LEN, result);
	if (0 != memcmp(expected_xchacha_oneshot, result, CHACHA_BLOCK_LEN))
		error ++;
	/* xchacha by blocks 3. */
	xchacha_str_init(&ctx, key, 256, NULL, iv, 8);
	chacha_str_data_crypt(&ctx, plain, 63, result);
	chacha_str_data_crypt(&ctx, &plain[63], 130, &result[63]);
	chacha_str_data_crypt(&ctx, &plain[193], (CHACHA_TEST_LEN - 193), &result[193]);
	chacha_str_final(&ctx);
	chacha_res_compact(result, plain, CHACHA_TEST_LEN, result);
	if (0 != memcmp(expected_xchacha_oneshot, result, CHACHA_BLOCK_LEN))
		error ++;
	/* chacha one-shot. */
	chacha(key, 256, NULL, iv, 8, plain, CHACHA_TEST_LEN, result);
	chacha_res_compact(result, plain, CHACHA_TEST_LEN, result);
	if (0 != memcmp(expected_chacha_oneshot, result, CHACHA_BLOCK_LEN))
		error ++;

	return (error);
}
#endif

#endif /* __CHACHA_H__ */
