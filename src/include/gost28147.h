/*-
 * Copyright (c) 2015 - 2016 Rozhuk Ivan <rim@vedapro.ru>
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
 * magma: GOST 28147-89
 * http://certisfera.ru/uploads/28147-89.pdf
 * https://www.tc26.ru/standard/gost/GOST_R_3412-2015.pdf
 * rfc4357: Additional Cryptographic Algorithms for Use with GOST 28147-89,
 *  GOST R 34.10-94, GOST R 34.10-2001, and GOST R 34.11-94 Algorithms
 * rfc5830: GOST 28147-89: Encryption, Decryption, and Message Authentication Code (MAC) Algorithms
 *
 *
 */

#ifndef __GOST28147_89_H__
#define __GOST28147_89_H__


#ifndef _WINDOWS
#	include <sys/param.h>
#	ifdef __linux__ /* Linux specific code. */
#		define _GNU_SOURCE /* See feature_test_macros(7) */
#		define __USE_GNU 1
#	endif /* Linux specific code. */
#	include <sys/types.h>
#	ifdef _KERNEL
#		include <sys/systm.h>
#	else
#		include <string.h> /* memcpy, memmove, memset... */
#		include <inttypes.h>
#		include <netinet/in.h> /* ntohs(), htons(), ntohl(), htonl() */
#	endif
	static void *(*volatile gost28147_memset_volatile)(void*, int, size_t) = memset;
#	define gost28147_bzero(mem, size)	gost28147_memset_volatile(mem, 0, size)
#	define gost28147_print(__fmt, args...)	fprintf(stdout, (__fmt), ##args)
#else
#	include <stdlib.h>
#	include <string.h> /* memcpy, memmove, memset... */
#	include <stdint.h>
#	define uint8_t		unsigned char
#	define uint32_t		DWORD
#	define size_t		SIZE_T
#	define EINVAL		ERROR_INVALID_PARAMETER
#	define gost28147_bzero(mem, size)	SecureZeroMemory(mem, size)
#	define gost28147_print()
#endif
#if defined(_MSC_VER) || defined(__INTEL_COMPILER)
#	define GOST28147_ALIGN(__n) __declspec(align(__n)) /* DECLSPEC_ALIGN() */
#else /* GCC/clang */
#	define GOST28147_ALIGN(__n) __attribute__((aligned(__n)))
#endif


/* Tunables. */
/* Define to use cmall tables but do more calculations. */
//#define GOST28147_USE_SMALL_TABLES 1


/* Algo constants. */
#define GOST28147_BLK_SIZE	8	/* 64 bits */
#define GOST28147_KEY_SIZE	32	/* 256 bit key */
#define GOST28147_ROUNDS	32	/*  */
#define GOST28147_MAC_ROUNDS	16	/*  */
#define GOST28147_BLK_32CNT	(GOST28147_BLK_SIZE / sizeof(uint32_t)) /* 2 */
#define GOST28147_KEY_32CNT	(GOST28147_KEY_SIZE / sizeof(uint32_t)) /* 8 */


/* Constants and tables. */
/* id-GostR3411-94-TestParamSet 1.2.643.2.2.31.0 */
static const uint8_t id_gostr3411_94_testparamset_sbox[128] = {
	0x04, 0x0a, 0x09, 0x02, 0x0d, 0x08, 0x00, 0x0e, 0x06, 0x0b, 0x01, 0x0c, 0x07, 0x0f, 0x05, 0x03,
	0x0e, 0x0b, 0x04, 0x0c, 0x06, 0x0d, 0x0f, 0x0a, 0x02, 0x03, 0x08, 0x01, 0x00, 0x07, 0x05, 0x09,
	0x05, 0x08, 0x01, 0x0d, 0x0a, 0x03, 0x04, 0x02, 0x0e, 0x0f, 0x0c, 0x07, 0x06, 0x00, 0x09, 0x0b,
	0x07, 0x0d, 0x0a, 0x01, 0x00, 0x08, 0x09, 0x0f, 0x0e, 0x04, 0x06, 0x0c, 0x0b, 0x02, 0x05, 0x03,
	0x06, 0x0c, 0x07, 0x01, 0x05, 0x0f, 0x0d, 0x08, 0x04, 0x0a, 0x09, 0x0e, 0x00, 0x03, 0x0b, 0x02,
	0x04, 0x0b, 0x0a, 0x00, 0x07, 0x02, 0x01, 0x0d, 0x03, 0x06, 0x08, 0x05, 0x09, 0x0c, 0x0f, 0x0e,
	0x0d, 0x0b, 0x04, 0x01, 0x03, 0x0f, 0x05, 0x09, 0x00, 0x0a, 0x0e, 0x07, 0x06, 0x08, 0x02, 0x0c,
	0x01, 0x0f, 0x0d, 0x00, 0x05, 0x07, 0x0a, 0x04, 0x09, 0x02, 0x03, 0x0e, 0x06, 0x0b, 0x08, 0x0c
};
/* id-Gost28147-89-CryptoPro-A-ParamSet 1.2.643.2.2.31.1 */
static const uint8_t id_gost28147_89_cryptopro_a_paramset_sbox[128] = {
	0x09, 0x06, 0x03, 0x02, 0x08, 0x0b, 0x01, 0x07, 0x0a, 0x04, 0x0e, 0x0f, 0x0c, 0x00, 0x0d, 0x05,
	0x03, 0x07, 0x0e, 0x09, 0x08, 0x0a, 0x0f, 0x00, 0x05, 0x02, 0x06, 0x0c, 0x0b, 0x04, 0x0d, 0x01,
 	0x0e, 0x04, 0x06, 0x02, 0x0b, 0x03, 0x0d, 0x08, 0x0c, 0x0f, 0x05, 0x0a, 0x00, 0x07, 0x01, 0x09,
 	0x0e, 0x07, 0x0a, 0x0c, 0x0d, 0x01, 0x03, 0x09, 0x00, 0x02, 0x0b, 0x04, 0x0f, 0x08, 0x05, 0x06,
 	0x0b, 0x05, 0x01, 0x09, 0x08, 0x0d, 0x0f, 0x00, 0x0e, 0x04, 0x02, 0x03, 0x0c, 0x07, 0x0a, 0x06,
 	0x03, 0x0a, 0x0d, 0x0c, 0x01, 0x02, 0x00, 0x0b, 0x07, 0x05, 0x09, 0x04, 0x08, 0x0f, 0x0e, 0x06,
 	0x01, 0x0d, 0x02, 0x09, 0x07, 0x0a, 0x06, 0x00, 0x08, 0x0c, 0x04, 0x05, 0x0f, 0x03, 0x0b, 0x0e,
 	0x0b, 0x0a, 0x0f, 0x05, 0x00, 0x0c, 0x0e, 0x08, 0x06, 0x02, 0x03, 0x09, 0x01, 0x07, 0x0d, 0x04
};
/* id-Gost28147-89-CryptoPro-B-ParamSet 1.2.643.2.2.31.2 */
static const uint8_t id_gost28147_89_cryptopro_b_paramset_sbox[128] = {
	0x08, 0x04, 0x0b, 0x01, 0x03, 0x05, 0x00, 0x09, 0x02, 0x0e, 0x0a, 0x0c, 0x0d, 0x06, 0x07, 0x0f,
	0x00, 0x01, 0x02, 0x0a, 0x04, 0x0d, 0x05, 0x0c, 0x09, 0x07, 0x03, 0x0f, 0x0b, 0x08, 0x06, 0x0e,
	0x0e, 0x0c, 0x00, 0x0a, 0x09, 0x02, 0x0d, 0x0b, 0x07, 0x05, 0x08, 0x0f, 0x03, 0x06, 0x01, 0x04,
	0x07, 0x05, 0x00, 0x0d, 0x0b, 0x06, 0x01, 0x02, 0x03, 0x0a, 0x0c, 0x0f, 0x04, 0x0e, 0x09, 0x08,
	0x02, 0x07, 0x0c, 0x0f, 0x09, 0x05, 0x0a, 0x0b, 0x01, 0x04, 0x00, 0x0d, 0x06, 0x08, 0x0e, 0x03,
	0x08, 0x03, 0x02, 0x06, 0x04, 0x0d, 0x0e, 0x0b, 0x0c, 0x01, 0x07, 0x0f, 0x0a, 0x00, 0x09, 0x05,
	0x05, 0x02, 0x0a, 0x0b, 0x09, 0x01, 0x0c, 0x03, 0x07, 0x04, 0x0d, 0x00, 0x06, 0x0f, 0x08, 0x0e,
	0x00, 0x04, 0x0b, 0x0e, 0x08, 0x03, 0x07, 0x01, 0x0a, 0x02, 0x09, 0x06, 0x0f, 0x0d, 0x05, 0x0c
};
/* id-Gost28147-89-CryptoPro-C-ParamSet 1.2.643.2.2.31.3 */
static const uint8_t id_gost28147_89_cryptopro_c_paramset_sbox[128] = {
	0x01, 0x0b, 0x0c, 0x02, 0x09, 0x0d, 0x00, 0x0f, 0x04, 0x05, 0x08, 0x0e, 0x0a, 0x07, 0x06, 0x03,
	0x00, 0x01, 0x07, 0x0d, 0x0b, 0x04, 0x05, 0x02, 0x08, 0x0e, 0x0f, 0x0c, 0x09, 0x0a, 0x06, 0x03,
	0x08, 0x02, 0x05, 0x00, 0x04, 0x09, 0x0f, 0x0a, 0x03, 0x07, 0x0c, 0x0d, 0x06, 0x0e, 0x01, 0x0b,
	0x03, 0x06, 0x00, 0x01, 0x05, 0x0d, 0x0a, 0x08, 0x0b, 0x02, 0x09, 0x07, 0x0e, 0x0f, 0x0c, 0x04,
	0x08, 0x0d, 0x0b, 0x00, 0x04, 0x05, 0x01, 0x02, 0x09, 0x03, 0x0c, 0x0e, 0x06, 0x0f, 0x0a, 0x07,
	0x0c, 0x09, 0x0b, 0x01, 0x08, 0x0e, 0x02, 0x04, 0x07, 0x03, 0x06, 0x05, 0x0a, 0x00, 0x0f, 0x0d,
	0x0a, 0x09, 0x06, 0x08, 0x0d, 0x0e, 0x02, 0x00, 0x0f, 0x03, 0x05, 0x0b, 0x04, 0x01, 0x0c, 0x07,
	0x07, 0x04, 0x00, 0x05, 0x0a, 0x02, 0x0f, 0x0e, 0x0c, 0x06, 0x01, 0x0b, 0x0d, 0x09, 0x03, 0x08
};
/* id-Gost28147-89-CryptoPro-D-ParamSet 1.2.643.2.2.31.4 */
static const uint8_t id_gost28147_89_cryptopro_d_paramset_sbox[128] = {
	0x0f, 0x0c, 0x02, 0x0a, 0x06, 0x04, 0x05, 0x00, 0x07, 0x09, 0x0e, 0x0d, 0x01, 0x0b, 0x08, 0x03,
	0x0b, 0x06, 0x03, 0x04, 0x0c, 0x0f, 0x0e, 0x02, 0x07, 0x0d, 0x08, 0x00, 0x05, 0x0a, 0x09, 0x01,
	0x01, 0x0c, 0x0b, 0x00, 0x0f, 0x0e, 0x06, 0x05, 0x0a, 0x0d, 0x04, 0x08, 0x09, 0x03, 0x07, 0x02,
	0x01, 0x05, 0x0e, 0x0c, 0x0a, 0x07, 0x00, 0x0d, 0x06, 0x02, 0x0b, 0x04, 0x09, 0x03, 0x0f, 0x08,
	0x00, 0x0c, 0x08, 0x09, 0x0d, 0x02, 0x0a, 0x0b, 0x07, 0x03, 0x06, 0x05, 0x04, 0x0e, 0x0f, 0x01,
	0x08, 0x00, 0x0f, 0x03, 0x02, 0x05, 0x0e, 0x0b, 0x01, 0x0a, 0x04, 0x07, 0x0c, 0x09, 0x0d, 0x06,
	0x03, 0x00, 0x06, 0x0f, 0x01, 0x0e, 0x09, 0x02, 0x0d, 0x08, 0x0c, 0x04, 0x0b, 0x0a, 0x05, 0x07,
	0x01, 0x0a, 0x06, 0x08, 0x0f, 0x0b, 0x00, 0x04, 0x0c, 0x03, 0x05, 0x09, 0x07, 0x0d, 0x02, 0x0e
};
/* id-tc26-gost-28147-param-Z 1.2.643.7.1.2.5.1.1 */
/* WiKi / https://www.tc26.ru/methods/recommendation/ТК26УЗ.pdf */
static const uint8_t id_tc26_gost_28147_param_z_sbox[128] = {
	0x0c, 0x04, 0x06, 0x02, 0x0a, 0x05, 0x0b, 0x09, 0x0e, 0x08, 0x0d, 0x07, 0x00, 0x03, 0x0f, 0x01,
        0x06, 0x08, 0x02, 0x03, 0x09, 0x0a, 0x05, 0x0c, 0x01, 0x0e, 0x04, 0x07, 0x0b, 0x0d, 0x00, 0x0f,
        0x0b, 0x03, 0x05, 0x08, 0x02, 0x0f, 0x0a, 0x0d, 0x0e, 0x01, 0x07, 0x04, 0x0c, 0x09, 0x06, 0x00,
        0x0c, 0x08, 0x02, 0x01, 0x0d, 0x04, 0x0f, 0x06, 0x07, 0x00, 0x0a, 0x05, 0x03, 0x0e, 0x09, 0x0b,
        0x07, 0x0f, 0x05, 0x0a, 0x08, 0x01, 0x06, 0x0d, 0x00, 0x09, 0x03, 0x0e, 0x0b, 0x04, 0x02, 0x0c,
        0x05, 0x0d, 0x0f, 0x06, 0x09, 0x02, 0x0c, 0x0a, 0x0b, 0x07, 0x08, 0x01, 0x04, 0x03, 0x0e, 0x00,
        0x08, 0x0e, 0x02, 0x05, 0x06, 0x09, 0x01, 0x0c, 0x0f, 0x04, 0x0b, 0x00, 0x0d, 0x0a, 0x03, 0x07,
        0x01, 0x07, 0x0e, 0x0d, 0x00, 0x05, 0x08, 0x03, 0x04, 0x0f, 0x0a, 0x06, 0x09, 0x0c, 0x0b, 0x02
};


/* Simple gost28147 context. */
typedef struct gost28147_context_s {
	GOST28147_ALIGN(8) uint32_t	key[GOST28147_KEY_32CNT]; /* key(32) / = 8 = 256 bit. */
#ifndef GOST28147_USE_SMALL_TABLES
	GOST28147_ALIGN(8) uint32_t	sboxx[4][256]; /* Extended sbox. */
#else
	const uint8_t			*sbox; /* SBox Replace table pointer. */
#endif
	GOST28147_ALIGN(8) uint32_t	mac[GOST28147_BLK_32CNT]; /* Calculated MAC. */
} gost28147_context_t, *gost28147_context_p;


#define GOST28147_PTR_IS_ALIGNED4(__ptr) (0 == (((size_t)__ptr) & 3))
#define GOST28147_PTR_8TO32(__ptr)	((uint32_t*)(void*)(size_t)(__ptr))

/* interpret four 8 bit unsigned integers as a 32 bit unsigned integer in little endian */
static inline uint32_t
U8TO32_LITTLE(const uint8_t *p) {
	return 
	    (((uint32_t)(p[0])      ) |
	     ((uint32_t)(p[1]) <<  8) |
	     ((uint32_t)(p[2]) << 16) |
	     ((uint32_t)(p[3]) << 24));
}
static inline uint32_t
U8TO32_BIG(const uint8_t *p) {
	return 
	    (((uint32_t)(p[3])      ) |
	     ((uint32_t)(p[2]) <<  8) |
	     ((uint32_t)(p[1]) << 16) |
	     ((uint32_t)(p[0]) << 24));
}

/* store a 32 bit unsigned integer as four 8 bit unsigned integers in little endian */
static inline void
U32TO8_LITTLE(uint8_t *p, uint32_t v) {
	p[0] = (uint8_t)(v      );
	p[1] = (uint8_t)(v >>  8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}
static inline void
U32TO8_BIG(uint8_t *p, uint32_t v) {
	p[3] = (uint8_t)(v      );
	p[2] = (uint8_t)(v >>  8);
	p[1] = (uint8_t)(v >> 16);
	p[0] = (uint8_t)(v >> 24);
}

/* 32 bit left rotate */
#define GOST28147_ROTL32(__v, __n) ((((uint32_t)(__v)) << (__n)) | (((uint32_t)(__v)) >> (32 - (__n))))

#define SBOX_RC(__sbox, __row, __col) ((uint32_t)(__sbox[(((__row) << 4) + ((__col) & 0x0000000f))]))

/* 8 rounds = 1 key pass. */
/* Instead of swapping halves, swap names each round */
#define GOST28147_DIRECT_KEY_ROUND8(__ctx, __n1, __n2) {		\
	__n2 ^= gost28147_block32((__ctx), ((__n1) + (__ctx)->key[0]));	\
	__n1 ^= gost28147_block32((__ctx), ((__n2) + (__ctx)->key[1]));	\
	__n2 ^= gost28147_block32((__ctx), ((__n1) + (__ctx)->key[2]));	\
	__n1 ^= gost28147_block32((__ctx), ((__n2) + (__ctx)->key[3]));	\
	__n2 ^= gost28147_block32((__ctx), ((__n1) + (__ctx)->key[4]));	\
	__n1 ^= gost28147_block32((__ctx), ((__n2) + (__ctx)->key[5]));	\
	__n2 ^= gost28147_block32((__ctx), ((__n1) + (__ctx)->key[6]));	\
	__n1 ^= gost28147_block32((__ctx), ((__n2) + (__ctx)->key[7]));	\
}
#define GOST28147_REVERSE_KEY_ROUND8(__ctx, __n1, __n2) {		\
	__n2 ^= gost28147_block32((__ctx), ((__n1) + (__ctx)->key[7]));	\
	__n1 ^= gost28147_block32((__ctx), ((__n2) + (__ctx)->key[6]));	\
	__n2 ^= gost28147_block32((__ctx), ((__n1) + (__ctx)->key[5]));	\
	__n1 ^= gost28147_block32((__ctx), ((__n2) + (__ctx)->key[4]));	\
	__n2 ^= gost28147_block32((__ctx), ((__n1) + (__ctx)->key[3]));	\
	__n1 ^= gost28147_block32((__ctx), ((__n2) + (__ctx)->key[2]));	\
	__n2 ^= gost28147_block32((__ctx), ((__n1) + (__ctx)->key[1]));	\
	__n1 ^= gost28147_block32((__ctx), ((__n2) + (__ctx)->key[0]));	\
}



/* Half block tranform by sbox table. = funcG() */
static inline uint32_t
gost28147_block32(gost28147_context_p ctx, const uint32_t src) {
#ifndef GOST28147_USE_SMALL_TABLES
	return (ctx->sboxx[0][(src & 0x000000ff)] ^
		ctx->sboxx[1][(src & 0x0000ff00) >>  8] ^
		ctx->sboxx[2][(src & 0x00ff0000) >> 16] ^
		ctx->sboxx[3][src >> 24]);
#else
	register uint32_t res = 0;

	res ^= (uint32_t)(SBOX_RC(ctx->sbox, 0, (src >>  0)) <<  0);
	res ^= (uint32_t)(SBOX_RC(ctx->sbox, 1, (src >>  4)) <<  4);
	res ^= (uint32_t)(SBOX_RC(ctx->sbox, 2, (src >>  8)) <<  8);
	res ^= (uint32_t)(SBOX_RC(ctx->sbox, 3, (src >> 12)) << 12);
	res ^= (uint32_t)(SBOX_RC(ctx->sbox, 4, (src >> 16)) << 16);
	res ^= (uint32_t)(SBOX_RC(ctx->sbox, 5, (src >> 20)) << 20);
	res ^= (uint32_t)(SBOX_RC(ctx->sbox, 6, (src >> 24)) << 24);
	res ^= (uint32_t)(SBOX_RC(ctx->sbox, 7, (src >> 28)) << 28);
	return (GOST28147_ROTL32(res, 11));
#endif
}

static inline void
gost28147_mac_block(gost28147_context_p ctx, uint32_t n1, uint32_t n2) {

	ctx->mac[0] ^= n1;
	ctx->mac[1] ^= n2;

	/* First 16 rounds. */
	GOST28147_DIRECT_KEY_ROUND8(ctx, ctx->mac[0], ctx->mac[1]);
	GOST28147_DIRECT_KEY_ROUND8(ctx, ctx->mac[0], ctx->mac[1]);
}

/* Block encrypt. */
static inline void
gost28147_block_encrypt(gost28147_context_p ctx, uint32_t n1, uint32_t n2,
    uint32_t *dst_n1, uint32_t *dst_n2) {

	/* First 24 rounds. */
	GOST28147_DIRECT_KEY_ROUND8(ctx, n1, n2);
	GOST28147_DIRECT_KEY_ROUND8(ctx, n1, n2);
	GOST28147_DIRECT_KEY_ROUND8(ctx, n1, n2);
	/* Final reverce key order 8 rounds. */
	GOST28147_REVERSE_KEY_ROUND8(ctx, n1, n2);
	/* Store result. */
	(*dst_n1) = n2;
	(*dst_n2) = n1;
}
/* Block encrypt. */
static inline void
gost28147_block_decrypt(gost28147_context_p ctx, uint32_t n1, uint32_t n2,
    uint32_t *dst_n1, uint32_t *dst_n2) {

	/* First direct key order 8 rounds. */
	GOST28147_DIRECT_KEY_ROUND8(ctx, n1, n2);
	/* Last 24 rounds. */
	GOST28147_REVERSE_KEY_ROUND8(ctx, n1, n2);
	GOST28147_REVERSE_KEY_ROUND8(ctx, n1, n2);
	GOST28147_REVERSE_KEY_ROUND8(ctx, n1, n2);
	/* Store result. */
	(*dst_n1) = n2;
	(*dst_n2) = n1;
}


/* Buf mac. */
static inline void
gost28147_blocks_mac(gost28147_context_p ctx, const uint8_t *src, size_t blocks_count) {

	if (0 == blocks_count)
		return;
	if (GOST28147_PTR_IS_ALIGNED4(src)) {
		for (; 0 != blocks_count; blocks_count --) {
			/* Load, transform and save block. */
			gost28147_mac_block(ctx,
			    (*(GOST28147_PTR_8TO32(src))),
			    (*(GOST28147_PTR_8TO32(src + sizeof(uint32_t)))));
			src += GOST28147_BLK_SIZE;
		}
	} else {
		for (; 0 != blocks_count; blocks_count --) {
			/* Load, transform and save block. */
			gost28147_mac_block(ctx,
			    U8TO32_LITTLE(src),
			    U8TO32_LITTLE(src + sizeof(uint32_t)));
			src += GOST28147_BLK_SIZE;
		}
	}
}
static inline void
gost28147_blocks_mac_be(gost28147_context_p ctx, const uint8_t *src, size_t blocks_count) {

	if (0 == blocks_count)
		return;
	if (GOST28147_PTR_IS_ALIGNED4(src)) {
		for (; 0 != blocks_count; blocks_count --) {
			/* Load, transform and save block. */
			gost28147_mac_block(ctx,
			    ntohl(*(GOST28147_PTR_8TO32(src + sizeof(uint32_t)))),
			    ntohl(*(GOST28147_PTR_8TO32(src))));
			src += GOST28147_BLK_SIZE;
		}
	} else {
		for (; 0 != blocks_count; blocks_count --) {
			/* Load, transform and save block. */
			gost28147_mac_block(ctx,
			    ntohl(U8TO32_LITTLE(src + sizeof(uint32_t))),
			    ntohl(U8TO32_LITTLE(src)));
			src += GOST28147_BLK_SIZE;
		}
	}
}

/* Buf encrypt. */
static inline void
gost28147_blocks_encrypt(gost28147_context_p ctx, const uint8_t *src, size_t blocks_count,
    uint8_t *dst) {
	uint32_t n1, n2;

	if (0 == blocks_count)
		return;
	if (GOST28147_PTR_IS_ALIGNED4(src) &&
	    GOST28147_PTR_IS_ALIGNED4(dst)) {
		for (; 0 != blocks_count; blocks_count --) {
			/* Load, transform and save block. */
			gost28147_block_encrypt(ctx,
			    (*(GOST28147_PTR_8TO32(src))),
			    (*(GOST28147_PTR_8TO32(src + sizeof(uint32_t)))),
			    GOST28147_PTR_8TO32(dst),
			    GOST28147_PTR_8TO32((dst + sizeof(uint32_t))));
			src += GOST28147_BLK_SIZE;
			dst += GOST28147_BLK_SIZE;
		}
	} else {
		for (; 0 != blocks_count; blocks_count --) {
			/* Load, transform and save block. */
			gost28147_block_encrypt(ctx,
			    U8TO32_LITTLE(src), /* n1 */
			    U8TO32_LITTLE(src + sizeof(uint32_t)), /* n2 */
			    &n1,
			    &n2);
			/* Store result to dst. */
			U32TO8_LITTLE(dst, n1);
			U32TO8_LITTLE((dst + sizeof(uint32_t)), n2);
			src += GOST28147_BLK_SIZE;
			dst += GOST28147_BLK_SIZE;
		}
	}
}
static inline void
gost28147_blocks_encrypt_be(gost28147_context_p ctx, const uint8_t *src, size_t blocks_count,
    uint8_t *dst) {
	uint32_t n1, n2;

	if (0 == blocks_count)
		return;
	if (GOST28147_PTR_IS_ALIGNED4(src) &&
	    GOST28147_PTR_IS_ALIGNED4(dst)) {
		for (; 0 != blocks_count; blocks_count --) {
			/* Load, transform and save block. */
			gost28147_block_encrypt(ctx,
			    ntohl(*(GOST28147_PTR_8TO32(src + sizeof(uint32_t)))),
			    ntohl(*(GOST28147_PTR_8TO32(src))),
			    &n1,
			    &n2);
			(*GOST28147_PTR_8TO32(dst)) = htonl(n2);
			(*GOST28147_PTR_8TO32((dst + sizeof(uint32_t)))) = htonl(n1);
			src += GOST28147_BLK_SIZE;
			dst += GOST28147_BLK_SIZE;
		}
	} else {
		for (; 0 != blocks_count; blocks_count --) {
			/* Load, transform and save block. */
			gost28147_block_encrypt(ctx,
			    ntohl(U8TO32_LITTLE(src + sizeof(uint32_t))), /* n1 */
			    ntohl(U8TO32_LITTLE(src)), /* n2 */
			    &n1,
			    &n2);
			/* Store result to dst. */
			U32TO8_LITTLE(dst, htonl(n2));
			U32TO8_LITTLE((dst + sizeof(uint32_t)), htonl(n1));
			src += GOST28147_BLK_SIZE;
			dst += GOST28147_BLK_SIZE;
		}
	}
}

/* Buf decrypt. */
static inline void
gost28147_blocks_decrypt(gost28147_context_p ctx, const uint8_t *src, size_t blocks_count,
    uint8_t *dst) {
	uint32_t n1, n2;

	if (0 == blocks_count)
		return;
	if (GOST28147_PTR_IS_ALIGNED4(src) &&
	    GOST28147_PTR_IS_ALIGNED4(dst)) {
		for (; 0 != blocks_count; blocks_count --) {
			/* Load, transform and save block. */
			gost28147_block_decrypt(ctx,
			    (*(GOST28147_PTR_8TO32(src))),
			    (*(GOST28147_PTR_8TO32(src + sizeof(uint32_t)))),
			    GOST28147_PTR_8TO32(dst),
			    GOST28147_PTR_8TO32((dst + sizeof(uint32_t))));
			src += GOST28147_BLK_SIZE;
			dst += GOST28147_BLK_SIZE;
		}
	} else {
		for (; 0 != blocks_count; blocks_count --) {
			/* Load, transform and save block. */
			gost28147_block_decrypt(ctx,
			    ntohl(U8TO32_LITTLE(src + sizeof(uint32_t))),
			    ntohl(U8TO32_LITTLE(src)),
			    &n1,
			    &n2);
			/* Store result to dst. */
			U32TO8_LITTLE(dst, n1);
			U32TO8_LITTLE((dst + sizeof(uint32_t)), n2);
			src += GOST28147_BLK_SIZE;
			dst += GOST28147_BLK_SIZE;
		}
	}
}
static inline void
gost28147_blocks_decrypt_be(gost28147_context_p ctx, const uint8_t *src, size_t blocks_count,
    uint8_t *dst) {
	uint32_t n1, n2;

	if (0 == blocks_count)
		return;
	if (GOST28147_PTR_IS_ALIGNED4(src) &&
	    GOST28147_PTR_IS_ALIGNED4(dst)) {
		for (; 0 != blocks_count; blocks_count --) {
			/* Load, transform and save block. */
			gost28147_block_decrypt(ctx,
			    ntohl(*(GOST28147_PTR_8TO32(src + sizeof(uint32_t)))),
			    ntohl(*(GOST28147_PTR_8TO32(src))),
			    &n1,
			    &n2);
			(*GOST28147_PTR_8TO32(dst)) = htonl(n2);
			(*GOST28147_PTR_8TO32((dst + sizeof(uint32_t)))) = htonl(n1);
			src += GOST28147_BLK_SIZE;
			dst += GOST28147_BLK_SIZE;
		}
	} else {
		for (; 0 != blocks_count; blocks_count --) {
			/* Load, transform and save block. */
			gost28147_block_decrypt(ctx,
			    U8TO32_LITTLE(src), /* n1 */
			    U8TO32_LITTLE(src + sizeof(uint32_t)), /* n2 */
			    &n1,
			    &n2);
			/* Store result to dst. */
			U32TO8_LITTLE(dst, htonl(n2));
			U32TO8_LITTLE((dst + sizeof(uint32_t)), htonl(n1));
			src += GOST28147_BLK_SIZE;
			dst += GOST28147_BLK_SIZE;
		}
	}
}

/* key - 32 bytes
 * sbox - SBox table pointer
 */
static inline int 
gost28147_init(const uint8_t *key, const size_t key_size, const uint8_t *sbox,
    gost28147_context_p ctx) {

	if (NULL == ctx || NULL == key || NULL == sbox ||
	    (256 != key_size && GOST28147_KEY_SIZE != key_size))
		return (EINVAL);
	memcpy(ctx->key, key, GOST28147_KEY_SIZE);
#ifndef GOST28147_USE_SMALL_TABLES
	/* Unpack SBox. */
	register size_t i;
#pragma unroll
	for (i = 0; i < 256; i ++) {
		ctx->sboxx[0][i] = GOST28147_ROTL32(((SBOX_RC(sbox, 0, (i & 0x0f)) |
		    (SBOX_RC(sbox, 1, (i >> 4)) << 4)) <<  0), 11);
		ctx->sboxx[1][i] = GOST28147_ROTL32(((SBOX_RC(sbox, 2, (i & 0x0f)) |
		    (SBOX_RC(sbox, 3, (i >> 4)) << 4)) <<  8), 11);
		ctx->sboxx[2][i] = GOST28147_ROTL32(((SBOX_RC(sbox, 4, (i & 0x0f)) |
		    (SBOX_RC(sbox, 5, (i >> 4)) << 4)) << 16), 11);
		ctx->sboxx[3][i] = GOST28147_ROTL32(((SBOX_RC(sbox, 6, (i & 0x0f)) |
		    (SBOX_RC(sbox, 7, (i >> 4)) << 4)) << 24), 11);
	}
#else
	/* Save pointer to SBox. */
	ctx->sbox = sbox;
#endif
	ctx->mac[0] = 0;
	ctx->mac[1] = 0;

	return (0);
}
static inline int 
gost28147_init_be(const uint8_t *key, const size_t key_size, const uint8_t *sbox,
    gost28147_context_p ctx) {
	int error;
	register size_t i;

	error = gost28147_init(key, key_size, sbox, ctx);
	if (0 != error)
		return (error);
#pragma unroll
	for (i = 0; i < GOST28147_KEY_32CNT; i ++) {
		ctx->key[i] = ntohl(ctx->key[i]);	
	}

	return (0);
}

static inline void
gost28147_final(gost28147_context_p ctx, uint8_t *mac, size_t mac_size) {

	if (NULL != mac &&
	    0 != mac_size) {
		if (GOST28147_BLK_SIZE >= mac_size) {
			memcpy(mac, ctx->mac, mac_size);
		} else {
			memcpy(mac, ctx->mac, GOST28147_BLK_SIZE);
			memset((mac + GOST28147_BLK_SIZE), 0,
			    (mac_size - GOST28147_BLK_SIZE));
		}
	}
	gost28147_bzero(ctx, sizeof(gost28147_context_t));
}
static inline void
gost28147_final_be(gost28147_context_p ctx, uint8_t *mac, size_t mac_size) {

	if (NULL != mac &&
	    0 != mac_size) {
		/* Convert result from LE to BE */
		ctx->mac[0] = htonl(ctx->mac[0]);
		ctx->mac[1] = htonl(ctx->mac[1]);
		if (GOST28147_BLK_SIZE >= mac_size) {
			memcpy(mac, ctx->mac, mac_size);
		} else {
			memcpy(mac, ctx->mac, GOST28147_BLK_SIZE);
			memset((mac + GOST28147_BLK_SIZE), 0,
			    (mac_size - GOST28147_BLK_SIZE));
		}
	}
	gost28147_bzero(ctx, sizeof(gost28147_context_t));
}




#ifdef GOST28147_SELF_TEST

#define GOST28147_TEST_LEN 2048


/* ГОСТ Р 34.12-2015: A.2.2 Преобразование g */
typedef struct gost28147_testg_vectors_s {
	const uint8_t *sbox;
	uint32_t a;
	uint32_t k;
	uint32_t g_res;
} gost28147_tstgv_t, *gost28147_tstgv_p;

static gost28147_tstgv_t gost28147_tstgv[] = {
	{ /* 0. */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.a =*/ 		0x87654321,
		/*.k =*/		0xfedcba98,
		/*.g_res =*/		0xfdcbc20c,
	}, { /* 1. */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.a =*/ 		0xfdcbc20c,
		/*.k =*/		0x87654321,
		/*.g_res =*/		0x7e791a4b,
	}, { /* 2. */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.a =*/ 		0x7e791a4b,
		/*.k =*/		0xfdcbc20c,
		/*.g_res =*/		0xc76549ec,
	}, { /* 3. */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.a =*/ 		0xc76549ec,
		/*.k =*/		0x7e791a4b,
		/*.g_res =*/		0x9791c849,
	}, { /* NULL */
		/*.sbox =*/ 		NULL,
		/*.a =*/		0,
		/*.k =*/ 		0,
		/*.g_res =*/		0,
	}
};

/* ГОСТ Р 34.12-2015: A.2.4 Алгоритм зашифрования */
typedef struct gost28147_testgk_vectors_s {
	const uint8_t *sbox;
	uint32_t k;
	uint32_t a0;
	uint32_t a1;
	uint32_t a0_res;
} gost28147_tstgkv_t, *gost28147_tstgkv_p;

static gost28147_tstgkv_t gost28147_tstgkv[] = {
	{ /* 0. (a1, a0) = (fedcba98, 76543210) */
	  /* 1. G[K1](a1, a0) = (76543210, 28da3b14). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xffeeddcc,
		/*.a0 =*/ 		0xfedcba98,
		/*.a1 =*/ 		0x76543210,
		/*.a0_res =*/		0x28da3b14,
	}, { /* 2. G[K2]G[K1](a1, a0) = (28da3b14, b14337a5). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xbbaa9988,
		/*.a0 =*/ 		0x76543210,
		/*.a1 =*/ 		0x28da3b14,
		/*.a0_res =*/		0xb14337a5,
	}, { /* 3. G[K3]…G[K1](a1, a0) = (b14337a5, 633a7c68). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0x77665544,
		/*.a0 =*/ 		0x28da3b14,
		/*.a1 =*/ 		0xb14337a5,
		/*.a0_res =*/		0x633a7c68,
	}, { /* 4. G[K4]…G[K1](a1, a0) = (633a7c68, ea89c02c). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0x33221100,
		/*.a0 =*/ 		0xb14337a5,
		/*.a1 =*/ 		0x633a7c68,
		/*.a0_res =*/		0xea89c02c,
	}, { /* 5. G[K5]…G[K1](a1, a0) = (ea89c02c, 11fe726d). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xf0f1f2f3,
		/*.a0 =*/ 		0x633a7c68,
		/*.a1 =*/ 		0xea89c02c,
		/*.a0_res =*/		0x11fe726d,
	}, { /* 6. G[K6]…G[K1](a1, a0) = (11fe726d, ad0310a4). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xf4f5f6f7,
		/*.a0 =*/ 		0xea89c02c,
		/*.a1 =*/ 		0x11fe726d,
		/*.a0_res =*/		0xad0310a4,
	}, { /* 7. G[K7]…G[K1](a1, a0) = (ad0310a4, 37d97f25). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xf8f9fafb,
		/*.a0 =*/ 		0x11fe726d,
		/*.a1 =*/ 		0xad0310a4,
		/*.a0_res =*/		0x37d97f25,
	}, { /* 8. G[K8]…G[K1](a1, a0) = (37d97f25, 46324615). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xfcfdfeff,
		/*.a0 =*/ 		0xad0310a4,
		/*.a1 =*/ 		0x37d97f25,
		/*.a0_res =*/		0x46324615,
	}, { /* 9. G[K9]…G[K1](a1, a0) = (46324615, ce995f2a). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xffeeddcc,
		/*.a0 =*/ 		0x37d97f25,
		/*.a1 =*/ 		0x46324615,
		/*.a0_res =*/		0xce995f2a,
	}, { /* 10. G[K10]…G[K1](a1, a0) = (ce995f2a, 93c1f449). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xbbaa9988,
		/*.a0 =*/ 		0x46324615,
		/*.a1 =*/ 		0xce995f2a,
		/*.a0_res =*/		0x93c1f449,
	}, { /* 11. G[K11]…G[K1](a1, a0) = (93c1f449, 4811c7ad). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0x77665544,
		/*.a0 =*/ 		0xce995f2a,
		/*.a1 =*/ 		0x93c1f449,
		/*.a0_res =*/		0x4811c7ad,
	}, { /* 12. G[K12]…G[K1](a1, a0) = (4811c7ad, c4b3edca). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0x33221100,
		/*.a0 =*/ 		0x93c1f449,
		/*.a1 =*/ 		0x4811c7ad,
		/*.a0_res =*/		0xc4b3edca,
	}, { /* 13. G[K13]…G[K1](a1, a0) = (c4b3edca, 44ca5ce1). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xf0f1f2f3,
		/*.a0 =*/ 		0x4811c7ad,
		/*.a1 =*/ 		0xc4b3edca,
		/*.a0_res =*/		0x44ca5ce1,
	}, { /* 14. G[K14]…G[K1](a1, a0) = (44ca5ce1, fef51b68). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xf4f5f6f7,
		/*.a0 =*/ 		0xc4b3edca,
		/*.a1 =*/ 		0x44ca5ce1,
		/*.a0_res =*/		0xfef51b68,
	}, { /* 15. G[K15]…G[K1](a1, a0) = (fef51b68, 2098cd86). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xf8f9fafb,
		/*.a0 =*/ 		0x44ca5ce1,
		/*.a1 =*/ 		0xfef51b68,
		/*.a0_res =*/		0x2098cd86,
	}, { /* 16. G[K16]…G[K1](a1, a0) = (2098cd86, 4f15b0bb). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xfcfdfeff,
		/*.a0 =*/ 		0xfef51b68,
		/*.a1 =*/ 		0x2098cd86,
		/*.a0_res =*/		0x4f15b0bb,
	}, { /* 17. G[K17]…G[K1](a1, a0) = (4f15b0bb, e32805bc). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xffeeddcc,
		/*.a0 =*/ 		0x2098cd86,
		/*.a1 =*/ 		0x4f15b0bb,
		/*.a0_res =*/		0xe32805bc,
	}, { /* 18. G[K18]…G[K1](a1, a0) = (e32805bc, e7116722). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xbbaa9988,
		/*.a0 =*/ 		0x4f15b0bb,
		/*.a1 =*/ 		0xe32805bc,
		/*.a0_res =*/		0xe7116722,
	}, { /* 19. G[K19]…G[K1](a1, a0) = (e7116722, 89cadf21). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0x77665544,
		/*.a0 =*/ 		0xe32805bc,
		/*.a1 =*/ 		0xe7116722,
		/*.a0_res =*/		0x89cadf21,
	}, { /* 20. G[K20]…G[K1](a1, a0) = (89cadf21, bac8444d). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0x33221100,
		/*.a0 =*/ 		0xe7116722,
		/*.a1 =*/ 		0x89cadf21,
		/*.a0_res =*/		0xbac8444d,
	}, { /* 21. G[K21]…G[K1](a1, a0) = (bac8444d, 11263a21). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xf0f1f2f3,
		/*.a0 =*/ 		0x89cadf21,
		/*.a1 =*/ 		0xbac8444d,
		/*.a0_res =*/		0x11263a21,
	}, { /* 22. G[K22]…G[K1](a1, a0) = (11263a21, 625434c3). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xf4f5f6f7,
		/*.a0 =*/ 		0xbac8444d,
		/*.a1 =*/ 		0x11263a21,
		/*.a0_res =*/		0x625434c3,
	}, { /* 23. G[K23]…G[K1](a1, a0) = (625434c3, 8025c0a5). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xf8f9fafb,
		/*.a0 =*/ 		0x11263a21,
		/*.a1 =*/ 		0x625434c3,
		/*.a0_res =*/		0x8025c0a5,
	}, { /* 24. G[K24]…G[K1](a1, a0) = (8025c0a5, b0d66514). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xfcfdfeff,
		/*.a0 =*/ 		0x625434c3,
		/*.a1 =*/ 		0x8025c0a5,
		/*.a0_res =*/		0xb0d66514,
	}, { /* 25. G[K25]…G[K1](a1, a0) = (b0d66514, 47b1d5f4). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xfcfdfeff,
		/*.a0 =*/ 		0x8025c0a5,
		/*.a1 =*/ 		0xb0d66514,
		/*.a0_res =*/		0x47b1d5f4,
	}, { /* 26. G[K26]…G[K1](a1, a0) = (47b1d5f4, c78e6d50). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xf8f9fafb,
		/*.a0 =*/ 		0xb0d66514,
		/*.a1 =*/ 		0x47b1d5f4,
		/*.a0_res =*/		0xc78e6d50,
	}, { /* 27. G[K27]…G[K1](a1, a0) = (c78e6d50, 80251e99). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xf4f5f6f7,
		/*.a0 =*/ 		0x47b1d5f4,
		/*.a1 =*/ 		0xc78e6d50,
		/*.a0_res =*/		0x80251e99,
	}, { /* 28. G[K28]…G[K1](a1, a0) = (80251e99, 2b96eca6). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xf0f1f2f3,
		/*.a0 =*/ 		0xc78e6d50,
		/*.a1 =*/ 		0x80251e99,
		/*.a0_res =*/		0x2b96eca6,
	}, { /* 29. G[K29]…G[K1](a1, a0) = (2b96eca6, 05ef4401). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0x33221100,
		/*.a0 =*/ 		0x80251e99,
		/*.a1 =*/ 		0x2b96eca6,
		/*.a0_res =*/		0x05ef4401,
	}, { /* 30. G[K30]…G[K1](a1, a0) = (05ef4401, 239a4577). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0x77665544,
		/*.a0 =*/ 		0x2b96eca6,
		/*.a1 =*/ 		0x05ef4401,
		/*.a0_res =*/		0x239a4577,
	}, { /* 31. G[K31]…G[K1](a1, a0) = (239a4577, c2d8ca3d). */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xbbaa9988,
		/*.a0 =*/ 		0x05ef4401,
		/*.a1 =*/ 		0x239a4577,
		/*.a0_res =*/		0xc2d8ca3d,
	}, { /* 32. G[K32]G[K31]…G[K1](a1, a0) = 4ee901e5, c2d8ca3d. */
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.k =*/		0xffeeddcc,
		/*.a0 =*/ 		0x239a4577,
		/*.a1 =*/ 		0xc2d8ca3d,
		/*.a0_res =*/		0x4ee901e5,
	}, { /* NULL */
		/*.sbox =*/ 		NULL,
		/*.k =*/ 		0,
		/*.a0 =*/		0,
		/*.a1 =*/		0,
		/*.a0_res =*/		0,
	}
};


typedef struct gost28147_test1_vectors_s {
	uint8_t	*key;
	size_t	key_size;
	const uint8_t *sbox;
	size_t	data_size;
	uint8_t	*plain;
	uint8_t	*encrypted;
} gost28147_tst1v_t, *gost28147_tst1v_p;

static gost28147_tst1v_t gost28147_tst1v[] = {
	/* http://cryptomanager.com/tv.html */
	{ /* 0. GOST 28147-89 ECB encipher (no padding) */
		/*.key =*/ 	(uint8_t*)"75713134b60fec45a607bb83aa3746af4ff99da6d1b53b5b1b402a1baa030d1b",
		/*.key_size =*/		64,
		/*.sbox =*/		id_gostr3411_94_testparamset_sbox,
		/*.data_size =*/	16,
		/*.plain =*/	(uint8_t*)"1122334455667788",
		/*.encrypted =*/ (uint8_t*)"03251e14f9d28acb",
	},
	/* http://www.cryptopp.com/ Crypto++ 5.6.3 /TestData/gostval.dat */
	{ /* 1. */
		/*.key =*/ 	(uint8_t*)"be5ec2006cff9dcf52354959f1ff0cbfe95061b5a648c10387069c25997c0672",
		/*.key_size =*/		64,
		/*.sbox =*/		id_gostr3411_94_testparamset_sbox,
		/*.data_size =*/	16,
		/*.plain =*/	(uint8_t*)"0df82802b741a292",
		/*.encrypted =*/ (uint8_t*)"07f9027df7f7df89",
	}, { /* 2. */
		/*.key =*/ 	(uint8_t*)"b385272ac8d72a5a8b344bc80363ac4d09bf58f41f540624cbcb8fdcf55307d7",
		/*.key_size =*/		64,
		/*.sbox =*/		id_gostr3411_94_testparamset_sbox,
		/*.data_size =*/	16,
		/*.plain =*/	(uint8_t*)"1354ee9c0a11cd4c",
		/*.encrypted =*/ (uint8_t*)"4fb50536f960a7b1",
	}, { /* 3. */
		/*.key =*/ 	(uint8_t*)"aee02f609a35660e4097e546fd3026b032cd107c7d459977adf489bef2652262",
		/*.key_size =*/		64,
		/*.sbox =*/		id_gostr3411_94_testparamset_sbox,
		/*.data_size =*/	16,
		/*.plain =*/	(uint8_t*)"6693d492c4b0cc39",
		/*.encrypted =*/ (uint8_t*)"670034ac0fa811b5",
	}, { /* 4. */
		/*.key =*/ 	(uint8_t*)"320e9d8422165d58911dfc7d8bbb1f81b0ecd924023bf94d9df7dcf7801240e0",
		/*.key_size =*/		64,
		/*.sbox =*/		id_gostr3411_94_testparamset_sbox,
		/*.data_size =*/	16,
		/*.plain =*/	(uint8_t*)"99e2d13080928d79",
		/*.encrypted =*/ (uint8_t*)"8118ff9d3b3cfe7d",
	}, { /* 5. */
		/*.key =*/ 	(uint8_t*)"c9f703bbbfc63691bfa3b7b87ea8fd5e8e8ef384ef733f1a61aef68c8ffa265f",
		/*.key_size =*/		64,
		/*.sbox =*/		id_gostr3411_94_testparamset_sbox,
		/*.data_size =*/	16,
		/*.plain =*/	(uint8_t*)"d1e787749c72814c",
		/*.encrypted =*/ (uint8_t*)"a083826a790d3e0c",
	}, { /* 6. */
		/*.key =*/ 	(uint8_t*)"728fee32f04b4c654ad7f607d71c660c2c2670d7c999713233149a1c0c17a1f0",
		/*.key_size =*/		64,
		/*.sbox =*/		id_gostr3411_94_testparamset_sbox,
		/*.data_size =*/	16,
		/*.plain =*/	(uint8_t*)"d4c05323a4f7a7b5",
		/*.encrypted =*/ (uint8_t*)"4d1f2e6b0d9de2ce",
	}, { /* 7. */
		/*.key =*/ 	(uint8_t*)"35fc96402209500fcfdef5352d1abb038fe33fc0d9d58512e56370b22baa133b",
		/*.key_size =*/		64,
		/*.sbox =*/		id_gostr3411_94_testparamset_sbox,
		/*.data_size =*/	16,
		/*.plain =*/	(uint8_t*)"8742d9a05f6a3af6",
		/*.encrypted =*/ (uint8_t*)"2f3bb84879d11e52",
	}, { /* 8. */
		/*.key =*/ 	(uint8_t*)"d416f630be65b7fe150656183370e07018234ee5da3d89c4ce9152a03e5bfb77",
		/*.key_size =*/		64,
		/*.sbox =*/		id_gostr3411_94_testparamset_sbox,
		/*.data_size =*/	16,
		/*.plain =*/	(uint8_t*)"f86506da04e41cb8",
		/*.encrypted =*/ (uint8_t*)"96f0a5c77a04f5ce",
	}, { /* 9. https://www.tc26.ru/methods/recommendation/ТК26УЗ.pdf */
		/*.key =*/ 	(uint8_t*)"8182838485868788898a8b8c8d8e8f80d1d2d3d4d5d6d7d8d9dadbdcdddedfd0",
		/*.key_size =*/		64,
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.data_size =*/	32,
		/*.plain =*/	(uint8_t*)"0102030405060708f1f2f3f4f5f6f7f8",
		/*.encrypted =*/ (uint8_t*)"ce5a5ed7e0577a5fd0cc85ce31635b8b",
	}, { /* 10. ГОСТ Р 34.12-2015: A.2.4 Алгоритм зашифрования */
		/*.key =*/ 	(uint8_t*)"ccddeeff8899aabb4455667700112233f3f2f1f0f7f6f5f4fbfaf9f8fffefdfc", /* 32bit be->le */
		/*.key_size =*/		64,
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.data_size =*/	16,
		/*.plain =*/	(uint8_t*)"1032547698badcfe", /* 32bit be->le, 32bit blocks swap: fedcba9876543210 */
		/*.encrypted =*/ (uint8_t*)"3dcad8c2e501e94e", /* 32bit be->le, 32bit blocks swap: 4ee901e5c2d8ca3d */
	}, { /* 11. http://sourcecodebrowser.com/bouncycastle/1.39/jce_2provider_2test_2_g_o_s_t28147_test_8java_source.html */
		/*.key =*/ 	(uint8_t*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		/*.key_size =*/		64,
		/*.sbox =*/		id_gostr3411_94_testparamset_sbox,
		/*.data_size =*/	48,
		/*.plain =*/	(uint8_t*)"4e6f77206973207468652074696d6520666f7220616c6c20",
		/*.encrypted =*/ (uint8_t*)"281630d0d5770030068c252d841e84149ccc1912052dbc02",
	}, { /* NULL */
		/*.key =*/ 		NULL,
		/*.key_size =*/		0,
		/*.sbox =*/ 		NULL,
		/*.data_size =*/	0,
		/*.plain =*/		NULL,
		/*.encrypted =*/	NULL,
	}
};
static gost28147_tst1v_t gost28147_tst1v_be[] = {
	{ /* 0. ГОСТ Р 34.12-2015: A.2.4 Алгоритм зашифрования */
		/*.key =*/ 	(uint8_t*)"ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		/*.key_size =*/		64,
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.data_size =*/	16,
		/*.plain =*/	(uint8_t*)"fedcba9876543210",
		/*.encrypted =*/ (uint8_t*)"4ee901e5c2d8ca3d",
	}, { /* NULL */
		/*.key =*/ 		NULL,
		/*.key_size =*/		0,
		/*.sbox =*/ 		NULL,
		/*.data_size =*/	0,
		/*.plain =*/		NULL,
		/*.encrypted =*/	NULL,
	}
};

typedef struct gost28147_test2_vectors_s {
	uint8_t	*key;
	size_t	key_size;
	const uint8_t *sbox;
	size_t	data_size;
	uint8_t	*plain;
	uint8_t	*mac;
} gost28147_tst2v_t, *gost28147_tst2v_p;

static gost28147_tst2v_t gost28147_tst2v[] = {
	{ /* 0. http://sourcecodebrowser.com/bouncycastle/1.39/_g_o_s_t28147_mac_test_8java_source.html */
		/*.key =*/ 	(uint8_t*)"6d145dc993f4019e104280df6fcd8cd8e01e101e4c113d7ec4f469ce6dcd9e49",
		/*.key_size =*/		64,
		/*.sbox =*/		id_gost28147_89_cryptopro_a_paramset_sbox,
		/*.data_size =*/	64,
		/*.plain =*/	(uint8_t*)"7768617420646f2079612077616e7420666f72206e6f7468696e673f00000000",
		/*.mac =*/ 	(uint8_t*)"93468a46a662eb06",
	}, { /* 1. ГОСТ Р 34.12-2015: A.2.4 Алгоритм зашифрования step 16 */
		/*.key =*/ 	(uint8_t*)"ccddeeff8899aabb4455667700112233f3f2f1f0f7f6f5f4fbfaf9f8fffefdfc", /* 32bit be->le */
		/*.key_size =*/		64,
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.data_size =*/	16,
		/*.plain =*/	(uint8_t*)"1032547698badcfe", /* 32bit be->le, 32bit blocks swap: fedcba9876543210 */
		/*.mac =*/ 	(uint8_t*)"bbb0154f86cd9820", /* 32bit be->le: 4f15b0bb2098cd86 */
	}, { /* 2. From internal sources VedaPro */
		/*.key =*/ 	(uint8_t*)"ccddeeff8899aabb4455667700112233f3f2f1f0f7f6f5f4fbfaf9f8fffefdfc", /* 32bit be->le */
		/*.key_size =*/		64,
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.data_size =*/	16,
		/*.plain =*/	(uint8_t*)"8e8b28f02a81cadb", /* 32bit be->le, 32bit blocks swap: dbca812af0288b8e */
		/*.mac =*/ 	(uint8_t*)"353db1596d73d7bb", /* 32bit be->le: 59b13d35bbd7736d */
	}, { /* NULL */
		/*.key =*/ 		NULL,
		/*.key_size =*/		0,
		/*.sbox =*/ 		NULL,
		/*.data_size =*/	0,
		/*.plain =*/		NULL,
		/*.mac =*/		NULL,
	}
};
static gost28147_tst2v_t gost28147_tst2v_be[] = {
	{ /* 0. ГОСТ Р 34.12-2015: A.2.4 Алгоритм зашифрования step 16 */
		/*.key =*/ 	(uint8_t*)"ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		/*.key_size =*/		64,
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.data_size =*/	16,
		/*.plain =*/	(uint8_t*)"fedcba9876543210",
		/*.mac =*/ 	(uint8_t*)"4f15b0bb2098cd86",
	}, { /* 1. From internal sources VedaPro */
		/*.key =*/ 	(uint8_t*)"ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		/*.key_size =*/		64,
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.data_size =*/	16,
		/*.plain =*/	(uint8_t*)"dbca812af0288b8e",
		/*.mac =*/ 	(uint8_t*)"59b13d35bbd7736d",
	}, { /* 2. From internal sources VedaPro */
		/*.key =*/ 	(uint8_t*)"ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		/*.key_size =*/		64,
		/*.sbox =*/		id_tc26_gost_28147_param_z_sbox,
		/*.data_size =*/	16,
		/*.plain =*/	(uint8_t*)"b2e57ce7c5db8dba",
		/*.mac =*/ 	(uint8_t*)"c8194e554c6003e6",
	}, { /* NULL */
		/*.key =*/ 		NULL,
		/*.key_size =*/		0,
		/*.sbox =*/ 		NULL,
		/*.data_size =*/	0,
		/*.plain =*/		NULL,
		/*.mac =*/		NULL,
	}
};


static inline void
gost28147_cvt_hex(uint8_t *bin, size_t bin_size, uint8_t *hex) {
	static uint8_t *hex_tbl = (uint8_t*)"0123456789abcdef";
	register uint8_t *bin_max, byte;

	for (bin_max = (bin + bin_size); bin < bin_max; bin ++) {
		byte = (*bin);
		(*hex ++) = hex_tbl[((byte >> 4) & 0x0f)];
		(*hex ++) = hex_tbl[(byte & 0x0f)];
	}
	(*hex) = 0;
}

/* Import from little-endian hex string (L->H). */
static inline int
gost28147_import_le_hex(uint8_t *a, size_t count, uint8_t *buf, size_t buf_size) {
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
		if ('0' <= cur_char && '9' >= cur_char) {
			cur_char -= '0';
		} else if ('a' <= cur_char && 'f' >= cur_char) {
			cur_char -= ('a' - 10);
		} else if ('A' <= cur_char && 'F' >= cur_char) {
			cur_char -= ('A' - 10);
		} else {
			continue;
		}
		byte = (uint8_t)((byte << 4) | cur_char);
		cnt ++;
		if (2 > cnt) /* Wait untill 4 + 4 bit before write a byte. */
			continue;
		if (w_pos == w_pos_max)
			return (EOVERFLOW);
		(*w_pos ++) = byte;
		byte = 0;
		cnt = 0;
	}
	memset(w_pos, 0, (size_t)(w_pos_max - w_pos));
	return (0);
}


/* 0 - OK, non zero - error */
static inline int
gost28147_self_test(void) {
	int error = 0;
	size_t i, tm;
	gost28147_tst1v_t tst1v;
	gost28147_tst2v_t tst2v;
	uint8_t	key[GOST28147_KEY_SIZE+1];
	uint8_t	plain[GOST28147_TEST_LEN];
	uint8_t	encrypted[GOST28147_TEST_LEN];
	uint8_t	result[GOST28147_TEST_LEN];
	uint8_t	tmpbuf[GOST28147_TEST_LEN];
	uint8_t	tmpbuf2[GOST28147_TEST_LEN];
	gost28147_context_t ctx;

	/* Test 0: gost28147_block32 / funcG() */
	for (i = 0; NULL != gost28147_tstgv[i].sbox; i ++) {
		/* Fake init to setup SBox in context. */
		gost28147_init(tmpbuf, 256, gost28147_tstgv[i].sbox, &ctx);
		tm = gost28147_block32(&ctx,
		    (gost28147_tstgv[i].a + gost28147_tstgv[i].k));
		if (tm != gost28147_tstgv[i].g_res) {
			gost28147_cvt_hex((uint8_t*)&tm, 4, tmpbuf);
			gost28147_cvt_hex((uint8_t*)&gost28147_tstgv[i].g_res, 4, tmpbuf2);
			gost28147_print("test 0: gost28147_block32: %zu: %s != %s\n",
			    i, tmpbuf, tmpbuf2);
			error ++;
		}
	}
	for (i = 0; NULL != gost28147_tstgkv[i].sbox; i ++) {
		/* Fake init to setup SBox in context. */
		gost28147_init(tmpbuf, 256, gost28147_tstgkv[i].sbox, &ctx);
		tm = (gost28147_tstgkv[i].a0 ^ gost28147_block32(&ctx,
		    (gost28147_tstgkv[i].a1 + gost28147_tstgkv[i].k)));
		if (tm != gost28147_tstgkv[i].a0_res) {
			gost28147_cvt_hex((uint8_t*)&tm, 4, tmpbuf);
			gost28147_cvt_hex((uint8_t*)&gost28147_tstgkv[i].a0_res, 4, tmpbuf2);
			gost28147_print("test 0: gost28147_block32: %zu: %s != %s\n",
			    i, tmpbuf, tmpbuf2);
			error ++;
		}
	}

	/* Test 1: encrypt + decrypt. */
	for (i = 0; 0 != gost28147_tst1v[i].key_size; i ++) {
		memset(&tst1v, 0, sizeof(tst1v));

		if (0 != gost28147_import_le_hex(key, sizeof(key), gost28147_tst1v[i].key, gost28147_tst1v[i].key_size)) {
			gost28147_print("test 1: gost28147_import_le_hex(gost28147_tst1v[%zu].key) fail!\n",
			    i);
			error ++;
			continue;
		}
		tst1v.key = key;
		tst1v.key_size = (gost28147_tst1v[i].key_size / 2);

		tst1v.sbox = gost28147_tst1v[i].sbox;

		tst1v.data_size = (gost28147_tst1v[i].data_size / 2);
		if (NULL != gost28147_tst1v[i].plain) {
			if (0 != gost28147_import_le_hex(plain, sizeof(plain),
			    gost28147_tst1v[i].plain, gost28147_tst1v[i].data_size)) {
				gost28147_print("test 1: gost28147_import_le_hex(gost28147_tst1v[%zu].plain) fail!\n",
				    i);
				error ++;
				continue;
			}
			tst1v.plain = plain;
		}
		if (NULL != gost28147_tst1v[i].encrypted) {
			if (0 != gost28147_import_le_hex(encrypted, sizeof(encrypted),
			    gost28147_tst1v[i].encrypted, gost28147_tst1v[i].data_size)) {
				gost28147_print("test 1: gost28147_import_le_hex(gost28147_tst1v[%zu].encrypted) fail!\n",
				    i);
				error ++;
				continue;
			}
			tst1v.encrypted = encrypted;
		}

		/* encrypt test. */
		if (0 != gost28147_init(tst1v.key, tst1v.key_size, tst1v.sbox, &ctx)) {
			gost28147_print("test 1: gost28147_init([%zu]) fail!\n",
			    i);
			error ++;
			continue;
		}
		gost28147_blocks_encrypt(&ctx, tst1v.plain,
		    (tst1v.data_size / GOST28147_BLK_SIZE), result);
		gost28147_final(&ctx, NULL, 0);
		if (0 != memcmp(tst1v.encrypted, result, tst1v.data_size)) {
			gost28147_cvt_hex(result, tst1v.data_size, tmpbuf);
			gost28147_print("test 1: encrypt error: %zu: %s - %s\n",
			    i, gost28147_tst1v[i].encrypted, tmpbuf);
			error ++;
		}
		/* decrypt test. */
		if (0 != gost28147_init(tst1v.key, tst1v.key_size, tst1v.sbox, &ctx)) {
			gost28147_print("test 1: gost28147_init([%zu]) fail!\n",
			    i);
			error ++;
			continue;
		}
		gost28147_blocks_decrypt(&ctx, tst1v.encrypted,
		    (tst1v.data_size / GOST28147_BLK_SIZE), result);
		gost28147_final(&ctx, NULL, 0);
		if (0 != memcmp(tst1v.plain, result, tst1v.data_size)) {
			gost28147_cvt_hex(result, tst1v.data_size, tmpbuf);
			gost28147_print("test 1: decrypt error: %zu: %s - %s\n",
			    i, gost28147_tst1v[i].plain, tmpbuf);
			error ++;
		}
	}
	for (i = 0; 0 != gost28147_tst1v_be[i].key_size; i ++) {
		memset(&tst1v, 0, sizeof(tst1v));

		if (0 != gost28147_import_le_hex(key, sizeof(key), gost28147_tst1v_be[i].key, gost28147_tst1v_be[i].key_size)) {
			gost28147_print("test 1: gost28147_import_le_hex(gost28147_tst1v_be[%zu].key) fail!\n",
			    i);
			error ++;
			continue;
		}
		tst1v.key = key;
		tst1v.key_size = (gost28147_tst1v_be[i].key_size / 2);

		tst1v.sbox = gost28147_tst1v_be[i].sbox;

		tst1v.data_size = (gost28147_tst1v_be[i].data_size / 2);
		if (NULL != gost28147_tst1v_be[i].plain) {
			if (0 != gost28147_import_le_hex(plain, sizeof(plain),
			    gost28147_tst1v_be[i].plain, gost28147_tst1v_be[i].data_size)) {
				gost28147_print("test 1: gost28147_import_le_hex(gost28147_tst1v_be[%zu].plain) fail!\n",
				    i);
				error ++;
				continue;
			}
			tst1v.plain = plain;
		}
		if (NULL != gost28147_tst1v_be[i].encrypted) {
			if (0 != gost28147_import_le_hex(encrypted, sizeof(encrypted),
			    gost28147_tst1v_be[i].encrypted, gost28147_tst1v_be[i].data_size)) {
				gost28147_print("test 1: gost28147_import_le_hex(gost28147_tst1v_be[%zu].encrypted) fail!\n",
				    i);
				error ++;
				continue;
			}
			tst1v.encrypted = encrypted;
		}

		/* encrypt test. */
		if (0 != gost28147_init_be(tst1v.key, tst1v.key_size, tst1v.sbox, &ctx)) {
			gost28147_print("test 1: gost28147_init_be([%zu]) fail!\n",
			    i);
			error ++;
			continue;
		}
		gost28147_blocks_encrypt_be(&ctx, tst1v.plain,
		    (tst1v.data_size / GOST28147_BLK_SIZE), result);
		gost28147_final(&ctx, NULL, 0);
		if (0 != memcmp(tst1v.encrypted, result, tst1v.data_size)) {
			gost28147_cvt_hex(result, tst1v.data_size, tmpbuf);
			gost28147_print("test 1: encrypt_be error: %zu: %s - %s\n",
			    i, gost28147_tst1v_be[i].encrypted, tmpbuf);
			error ++;
		}
		/* decrypt test. */
		if (0 != gost28147_init_be(tst1v.key, tst1v.key_size, tst1v.sbox, &ctx)) {
			gost28147_print("test 1: gost28147_init_be([%zu]) fail!\n",
			    i);
			error ++;
			continue;
		}
		gost28147_blocks_decrypt_be(&ctx, tst1v.encrypted,
		    (tst1v.data_size / GOST28147_BLK_SIZE), result);
		gost28147_final(&ctx, NULL, 0);
		if (0 != memcmp(tst1v.plain, result, tst1v.data_size)) {
			gost28147_cvt_hex(result, tst1v.data_size, tmpbuf);
			gost28147_print("test 1: decrypt_be error: %zu: %s - %s\n",
			    i, gost28147_tst1v_be[i].plain, tmpbuf);
			error ++;
		}
	}

	/* Test 2: mac calc. */
	for (i = 0; 0 != gost28147_tst2v[i].key_size; i ++) {
		memset(&tst2v, 0, sizeof(tst2v));

		if (0 != gost28147_import_le_hex(key, sizeof(key), gost28147_tst2v[i].key, gost28147_tst2v[i].key_size)) {
			gost28147_print("test 2: gost28147_import_le_hex(gost28147_tst2v[%zu].key) fail!\n",
			    i);
			error ++;
			continue;
		}
		tst2v.key = key;
		tst2v.key_size = (gost28147_tst2v[i].key_size / 2);

		tst2v.sbox = gost28147_tst2v[i].sbox;

		tst2v.data_size = (gost28147_tst2v[i].data_size / 2);
		if (NULL != gost28147_tst2v[i].plain) {
			if (0 != gost28147_import_le_hex(plain, sizeof(plain),
			    gost28147_tst2v[i].plain, gost28147_tst2v[i].data_size)) {
				gost28147_print("test 2: gost28147_import_le_hex(gost28147_tst2v[%zu].plain) fail!\n",
				    i);
				error ++;
				continue;
			}
			tst2v.plain = plain;
		}
		if (NULL != gost28147_tst2v[i].mac) {
			if (0 != gost28147_import_le_hex(encrypted, sizeof(encrypted),
			    gost28147_tst2v[i].mac, 16)) {
				gost28147_print("test 2: gost28147_import_le_hex(gost28147_tst2v[%zu].mac) fail!\n",
				    i);
				error ++;
				continue;
			}
			tst2v.mac = encrypted;
		}

		/* mac test. */
		if (0 != gost28147_init(tst2v.key, tst2v.key_size, tst2v.sbox, &ctx)) {
			gost28147_print("test 2: gost28147_init([%zu]) fail!\n",
			    i);
			error ++;
			continue;
		}
		gost28147_blocks_mac(&ctx, tst2v.plain,
		    (tst2v.data_size / GOST28147_BLK_SIZE));
		gost28147_final(&ctx, result, 8);
		if (0 != memcmp(tst2v.mac, result, 8)) {
			gost28147_cvt_hex(result, 8, tmpbuf);
			gost28147_print("test 2: mac error: %zu: %s - %s\n",
			    i, gost28147_tst2v[i].mac, tmpbuf);
			error ++;
		}
	}
	for (i = 0; 0 != gost28147_tst2v_be[i].key_size; i ++) {
		memset(&tst2v, 0, sizeof(tst2v));

		if (0 != gost28147_import_le_hex(key, sizeof(key), gost28147_tst2v_be[i].key, gost28147_tst2v_be[i].key_size)) {
			gost28147_print("test 2: gost28147_import_le_hex(gost28147_tst2v_be[%zu].key) fail!\n",
			    i);
			error ++;
			continue;
		}
		tst2v.key = key;
		tst2v.key_size = (gost28147_tst2v_be[i].key_size / 2);

		tst2v.sbox = gost28147_tst2v_be[i].sbox;

		tst2v.data_size = (gost28147_tst2v_be[i].data_size / 2);
		if (NULL != gost28147_tst2v_be[i].plain) {
			if (0 != gost28147_import_le_hex(plain, sizeof(plain),
			    gost28147_tst2v_be[i].plain, gost28147_tst2v_be[i].data_size)) {
				gost28147_print("test 2: gost28147_import_le_hex(gost28147_tst2v_be[%zu].plain) fail!\n",
				    i);
				error ++;
				continue;
			}
			tst2v.plain = plain;
		}
		if (NULL != gost28147_tst2v_be[i].mac) {
			if (0 != gost28147_import_le_hex(encrypted, sizeof(encrypted),
			    gost28147_tst2v_be[i].mac, 16)) {
				gost28147_print("test 2: gost28147_import_le_hex(gost28147_tst2v_be[%zu].mac) fail!\n",
				    i);
				error ++;
				continue;
			}
			tst2v.mac = encrypted;
		}

		/* mac test. */
		if (0 != gost28147_init_be(tst2v.key, tst2v.key_size, tst2v.sbox, &ctx)) {
			gost28147_print("test 2: gost28147_init_be([%zu]) fail!\n",
			    i);
			error ++;
			continue;
		}
		gost28147_blocks_mac_be(&ctx, tst2v.plain,
		    (tst2v.data_size / GOST28147_BLK_SIZE));
		gost28147_final_be(&ctx, result, 8);
		if (0 != memcmp(tst2v.mac, result, 8)) {
			gost28147_cvt_hex(result, 8, tmpbuf);
			gost28147_print("test 2: mac error: %zu: %s - %s\n",
			    i, gost28147_tst2v_be[i].mac, tmpbuf);
			error ++;
		}
	}

	return (error);
}
#endif

#endif /* __GOST28147_89_H__ */
