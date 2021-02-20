/*-
 * Copyright (c) 2013 - 2016 Rozhuk Ivan <rozhuk.im@gmail.com>
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
 */

/* http://tools.ietf.org/html/rfc6090 */
/* RFC5639: Elliptic Curve Cryptography (ECC) Brainpool Standard Curves and Curve Generation */
/* http://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates */
/*
 * [1]: Guide to Elliptic Curve Cryptography
 * Darrel Hankerson, Alfred Menezes, Scott Vanstone
 * [2]: http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html
 */

/*
 * ec_point_*_proj requre fast multiplication
 * ec_point_*_affine spent many time in bn_mod_inv()
 * ec_self_test() execution time:
 * mult/div	fast		slow
 * affine	32s		40s
 * proj		9s		43s
 *
 * fast: BN_DIGIT_BIT_CNT = 32, BN_CC_MULL_DIV defined
 * slow: BN_DIGIT_BIT_CNT = 64, BN_CC_MULL_DIV undefined
 */

#ifndef __ECDSA_H__
#define __ECDSA_H__

#ifdef _WINDOWS
#	define EINVAL		ERROR_INVALID_PARAMETER
#else
#	include <sys/types.h>
#	include <inttypes.h>
#endif

#include "math_bn.h"
#include "math_ec.h"



/* Elliptic Curve Domain Parameters */
typedef struct elliptic_curve_curve_str_s {
	const char	*name;	/**/
	size_t		name_size;
	const char	*OID;	/**/
	size_t		OID_size;
	size_t		num_size; /* Size for: p, a, b, Gx, Gy and n numbers. */
	size_t		t;	/* security level: minimum length of symmetric keys */
	size_t		m;	/* Binary field F2m / bits count. */
	uint16_t	Fx[16];/* Binary field F2m */
	const char	*p;	/* Prime field Fp */
	const char	*SEED;	/* Seed. A bit string used to generate elliptic curve domain */
	size_t		SEED_size; /* parameter b via the method defined in [ANS-X9.62-2005]. */
	const char	*a;	/* An elliptic curve domain parameter, which is equal to */
			/* the integer q −3 for Suite B elliptic curves. */
	const char	*b;	/* An elliptic curve domain parameter, which for Suite B */
			/* curves is an integer in [0,q − 1], generated using the elliptic curve domain parameter SEED */
	const char	*Gx;	/* The base point on the elliptic curve. The coordinates */
	const char	*Gy;	/* xGand yGare integers in the interval [0,q − 1]. */
	const char	*n;	/* The order of the base point G of the elliptic curve; nG = O. */
	uint32_t	h;	/* The order of the elliptic curve group divided by the */
			/* order n of the base point G. */
	uint32_t	algo;	/* ECDSA, GOST */
	uint32_t	flags;	/* EC_CURVE_FLAG_* */
} ec_curve_str_t, *ec_curve_str_p;

static ec_curve_str_t ec_curve_str[] = {
	/* SEC 2: Curves over GF(p) prime-order fields. */
	{
		/*.name =*/	"secp112r1",
		/*.name_size =*/9,
		/*.OID =*/	"1.3.132.0.6",
		/*.OID_size =*/	11,
		/*.num_size =*/	28,
		/*.t =*/	56,
		/*.m =*/	112,
		/*.Fx =*/	{0},
		/*.p =*/	"db7c2abf62e35e668076bead208b",
		/*.SEED =*/	"00f50b028e4d696e676875615175290472783fb1",
		/*.SEED_size =*/40,
		/*.a =*/	"db7c2abf62e35e668076bead2088",
		/*.b =*/	"659ef8ba043916eede8911702b22",
		/*.Gx =*/	"09487239995a5ee76b55f9c2f098",
		/*.Gy =*/	"a89ce5af8724c0a23e0e0ff77500",
		/*.n =*/	"db7c2abf62e35e7628dfac6561c5",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_ECDSA,
		/*.flags =*/	EC_CURVE_FLAG_A_M3,
	}, {
		/*.name =*/	"secp112r2",
		/*.name_size =*/9,
		/*.OID =*/	"1.3.132.0.7",
		/*.OID_size =*/	11,
		/*.num_size =*/	28,
		/*.t =*/	56,
		/*.m =*/	112,
		/*.Fx =*/	{0},
		/*.p =*/	"db7c2abf62e35e668076bead208b",
		/*.SEED =*/	"002757a1114d696e6768756151755316c05e0bd4",
		/*.SEED_size =*/40,
		/*.a =*/	"6127c24c05f38a0aaaf65c0ef02c",
		/*.b =*/	"51def1815db5ed74fcc34c85d709",
		/*.Gx =*/	"4ba30ab5e892b4e1649dd0928643",
		/*.Gy =*/	"adcd46f5882e3747def36e956e97",
		/*.n =*/	"36df0aafd8b8d7597ca10520d04b",
		/*.h =*/	4,
		/*.algo =*/	EC_CURVE_ALGO_ECDSA,
		/*.flags =*/	0,
	}, {
		/*.name =*/	"secp128r1",
		/*.name_size =*/9,
		/*.OID =*/	"1.3.132.0.28",
		/*.OID_size =*/	12,
		/*.num_size =*/	32,
		/*.t =*/	64,
		/*.m =*/	128,
		/*.Fx =*/	{128, 97, 0},
		/*.p =*/	"fffffffdffffffffffffffffffffffff",
		/*.SEED =*/	"000e0d4d696e6768756151750cc03a4473d03679",
		/*.SEED_size =*/40,
		/*.a =*/	"fffffffdfffffffffffffffffffffffc",
		/*.b =*/	"e87579c11079f43dd824993c2cee5ed3",
		/*.Gx =*/	"161ff7528b899b2d0c28607ca52c5b86",
		/*.Gy =*/	"cf5ac8395bafeb13c02da292dded7a83",
		/*.n =*/	"fffffffe0000000075a30d1b9038a115",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_ECDSA,
		/*.flags =*/	EC_CURVE_FLAG_A_M3,
	}, {
		/*.name =*/	"secp128r2",
		/*.name_size =*/9,
		/*.OID =*/	"1.3.132.0.29",
		/*.OID_size =*/	12,
		/*.num_size =*/	32,
		/*.t =*/	64,
		/*.m =*/	128,
		/*.Fx =*/	{128, 97, 0},
		/*.p =*/	"fffffffdffffffffffffffffffffffff",
		/*.SEED =*/	"004d696e67687561517512d8f03431fce63b88f4",
		/*.SEED_size =*/40,
		/*.a =*/	"d6031998d1b3bbfebf59cc9bbff9aee1",
		/*.b =*/	"5eeefca380d02919dc2c6558bb6d8a5d",
		/*.Gx =*/	"7b6aa5d85e572983e6fb32a7cdebc140",
		/*.Gy =*/	"27b6916a894d3aee7106fe805fc34b44",
		/*.n =*/	"3fffffff7fffffffbe0024720613b5a3",
		/*.h =*/	4,
		/*.algo =*/	EC_CURVE_ALGO_ECDSA,
		/*.flags =*/	0,
	}, {
		/*.name =*/	"secp160k1",
		/*.name_size =*/9,
		/*.OID =*/	"1.3.132.0.9",
		/*.OID_size =*/	11,
		/*.num_size =*/	40,
		/*.t =*/	80,
		/*.m =*/	160,
		/*.Fx =*/	{160, 32, 14, 12, 9, 8, 7, 3, 2, 0},
		/*.p =*/	"fffffffffffffffffffffffffffffffeffffac73",
		/*.SEED =*/	NULL,
		/*.SEED_size =*/0,
		/*.a =*/	"0000000000000000000000000000000000000000",
		/*.b =*/	"0000000000000000000000000000000000000007",
		/*.Gx =*/	"3b4c382ce37aa192a4019e763036f4f5dd4d7ebb",
		/*.Gy =*/	"938cf935318fdced6bc28286531733c3f03c4fee",
		/*.n =*/	"0100000000000000000001b8fa16dfab9aca16b6b3",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_ECDSA,
		/*.flags =*/	0,
	}, {
		/*.name =*/	"secp160r1",
		/*.name_size =*/9,
		/*.OID =*/	"1.3.132.0.8",
		/*.OID_size =*/	11,
		/*.num_size =*/	40,
		/*.t =*/	80,
		/*.m =*/	160,
		/*.Fx =*/	{160, 31, 0},
		/*.p =*/	"ffffffffffffffffffffffffffffffff7fffffff",
		/*.SEED =*/	"1053cde42c14d696e67687561517533bf3f83345",
		/*.SEED_size =*/40,
		/*.a =*/	"ffffffffffffffffffffffffffffffff7ffffffc",
		/*.b =*/	"1c97befc54bd7a8b65acf89f81d4d4adc565fa45",
		/*.Gx =*/	"4a96b5688ef573284664698968c38bb913cbfc82",
		/*.Gy =*/	"23a628553168947d59dcc912042351377ac5fb32",
		/*.n =*/	"0100000000000000000001f4c8f927aed3ca752257",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_ECDSA,
		/*.flags =*/	EC_CURVE_FLAG_A_M3,
	}, {
		/*.name =*/	"secp160r2",
		/*.name_size =*/9,
		/*.OID =*/	"1.3.132.0.30",
		/*.OID_size =*/	12,
		/*.num_size =*/	40,
		/*.t =*/	80,
		/*.m =*/	160,
		/*.Fx =*/	{160, 32, 14, 12, 9, 8, 7, 3, 2, 0},
		/*.p =*/	"fffffffffffffffffffffffffffffffeffffac73",
		/*.SEED =*/	"b99b99b099b323e02709a4d696e6768756151751",
		/*.SEED_size =*/40,
		/*.a =*/	"fffffffffffffffffffffffffffffffeffffac70",
		/*.b =*/	"b4e134d3fb59eb8bab57274904664d5af50388ba",
		/*.Gx =*/	"52dcb034293a117e1f4ff11b30f7199d3144ce6d",
		/*.Gy =*/	"feaffef2e331f296e071fa0df9982cfea7d43f2e",
		/*.n =*/	"0100000000000000000000351ee786a818f3a1a16b",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_ECDSA,
		/*.flags =*/	EC_CURVE_FLAG_A_M3,
	}, {
		/*.name =*/	"brainpoolP160r1",
		/*.name_size =*/15,
		/*.OID =*/	"1.3.36.3.3.2.8.1.1.1",
		/*.OID_size =*/	12,
		/*.num_size =*/	40,
		/*.t =*/	80,
		/*.m =*/	160,
		/*.Fx =*/	{0},
		/*.p =*/	"e95e4a5f737059dc60dfc7ad95b3d8139515620f",
		/*.SEED =*/	"3243f6a8885a308d313198a2e03707344a409382",
		/*.SEED_size =*/40,
		/*.a =*/	"340e7be2a280eb74e2be61bada745d97e8f7c300",
		/*.b =*/	"1e589a8595423412134faa2dbdec95c8d8675e58",
		/*.Gx =*/	"bed5af16ea3f6a4f62938c4631eb5af7bdbcdbc3",
		/*.Gy =*/	"1667cb477a1a8ec338f94741669c976316da6321",
		/*.n =*/	"e95e4a5f737059dc60df5991d45029409e60fc09",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_ECDSA,
		/*.flags =*/	0,
	}, {
		/*.name =*/	"secp192k1",
		/*.name_size =*/9,
		/*.OID =*/	"1.3.132.0.31",
		/*.OID_size =*/	12,
		/*.num_size =*/	48,
		/*.t =*/	96,
		/*.m =*/	192,
		/*.Fx =*/	{192, 32, 12, 8, 7, 6, 3, 0},
		/*.p =*/	"fffffffffffffffffffffffffffffffffffffffeffffee37",
		/*.SEED =*/	NULL,
		/*.SEED_size =*/0,
		/*.a =*/	"000000000000000000000000000000000000000000000000",
		/*.b =*/	"000000000000000000000000000000000000000000000003",
		/*.Gx =*/	"db4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d",
		/*.Gy =*/	"9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d",
		/*.n =*/	"fffffffffffffffffffffffe26f2fc170f69466a74defd8d",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_ECDSA,
		/*.flags =*/	0,
	}, {
		/*.name =*/	"secp192r1",
		/*.name_size =*/9,
		/*.OID =*/	"1.2.840.10045.3.1.1",
		/*.OID_size =*/	20,
		/*.num_size =*/	48,
		/*.t =*/	96,
		/*.m =*/	192,
		/*.Fx =*/	{192, 64, 0},
		/*.p =*/	"fffffffffffffffffffffffffffffffeffffffffffffffff",
		/*.SEED =*/	"3045ae6fc8422f64ed579528d38120eae12196d5",
		/*.SEED_size =*/40,
		/*.a =*/	"fffffffffffffffffffffffffffffffefffffffffffffffc",
		/*.b =*/	"64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
		/*.Gx =*/	"188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
		/*.Gy =*/	"07192b95ffc8da78631011ed6b24cdd573f977a11e794811",
		/*.n =*/	"ffffffffffffffffffffffff99def836146bc9b1b4d22831",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_ECDSA,
		/*.flags =*/	EC_CURVE_FLAG_A_M3,
	}, {
		/*.name =*/	"brainpoolP192r1",
		/*.name_size =*/15,
		/*.OID =*/	"1.3.36.3.3.2.8.1.1.3",
		/*.OID_size =*/	20,
		/*.num_size =*/	48,
		/*.t =*/	96,
		/*.m =*/	192,
		/*.Fx =*/	{0},
		/*.p =*/	"c302f41d932a36cda7a3463093d18db78fce476de1a86297",
		/*.SEED =*/	"2299f31d0082efa98ec4e6c89452821e638d0137",
		/*.SEED_size =*/40,
		/*.a =*/	"6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef",
		/*.b =*/	"469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9",
		/*.Gx =*/	"c0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd6",
		/*.Gy =*/	"14b690866abd5bb88b5f4828c1490002e6773fa2fa299b8f",
		/*.n =*/	"c302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_ECDSA,
		/*.flags =*/	0,
	}, {
		/*.name =*/	"secp224k1",
		/*.name_size =*/9,
		/*.OID =*/	"1.3.132.0.32",
		/*.OID_size =*/	12,
		/*.num_size =*/	56,
		/*.t =*/	112,
		/*.m =*/	224,
		/*.Fx =*/	{224, 32, 12, 11, 9, 7, 4, 1, 0},
		/*.p =*/	"fffffffffffffffffffffffffffffffffffffffffffffffeffffe56d",
		/*.SEED =*/	NULL,
		/*.SEED_size =*/ 0,
		/*.a =*/	"00000000000000000000000000000000000000000000000000000000",
		/*.b =*/	"00000000000000000000000000000000000000000000000000000005",
		/*.Gx =*/	"a1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c",
		/*.Gy =*/	"7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5",
		/*.n =*/	"010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_ECDSA,
		/*.flags =*/	0,
	}, {
		/*.name =*/	"secp224r1",
		/*.name_size =*/9,
		/*.OID =*/	"1.3.132.0.33",
		/*.OID_size =*/	12,
		/*.num_size =*/	56,
		/*.t =*/	112,
		/*.m =*/	224,
		/*.Fx =*/	{224, 96, 0},
		/*.p =*/	"ffffffffffffffffffffffffffffffff000000000000000000000001",
		/*.SEED =*/	"bd71344799d5c7fcdc45b59fa3b9ab8f6a948bc5",
		/*.SEED_size =*/40,
		/*.a =*/	"fffffffffffffffffffffffffffffffefffffffffffffffffffffffe",
		/*.b =*/	"b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
		/*.Gx =*/	"b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
		/*.Gy =*/	"bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
		/*.n =*/	"ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_ECDSA,
		/*.flags =*/	0,
	}, {
		/*.name =*/	"brainpoolP224r1",
		/*.name_size =*/15,
		/*.OID =*/	"1.3.36.3.3.2.8.1.1.5",
		/*.OID_size =*/	12,
		/*.num_size =*/	56,
		/*.t =*/	112,
		/*.m =*/	224,
		/*.Fx =*/	{0},
		/*.p =*/	"d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff",
		/*.SEED =*/	"7be5466cf34e90c6cc0ac29b7c97c50dd3f84d5b",
		/*.SEED_size =*/40,
		/*.a =*/	"68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43",
		/*.b =*/	"2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b",
		/*.Gx =*/	"0d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d",
		/*.Gy =*/	"58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd",
		/*.n =*/	"d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_ECDSA,
		/*.flags =*/	0,
	}, {
		/*.name =*/	"secp256k1",
		/*.name_size =*/9,
		/*.OID =*/	"1.3.132.0.10",
		/*.OID_size =*/	12,
		/*.num_size =*/	64,
		/*.t =*/	128,
		/*.m =*/	256,
		/*.Fx =*/	{256, 32, 9, 8, 7, 6, 4, 0},
		/*.p =*/	"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
		/*.SEED =*/	NULL,
		/*.SEED_size =*/0,
		/*.a =*/	"0000000000000000000000000000000000000000000000000000000000000000",
		/*.b =*/	"0000000000000000000000000000000000000000000000000000000000000007",
		/*.Gx =*/	"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		/*.Gy =*/	"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
		/*.n =*/	"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_ECDSA,
		/*.flags =*/	0,
	}, {
		/*.name =*/	"secp256r1",
		/*.name_size =*/9,
		/*.OID =*/	"1.2.840.10045.3.1.7",
		/*.OID_size =*/	19,
		/*.num_size =*/	64,
		/*.t =*/	128,
		/*.m =*/	256,
		/*.Fx =*/	{0},
		/*.p =*/	"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
		/*.SEED =*/	"c49d360886e704936a6678e1139d26b7819f7e90",
		/*.SEED_size =*/40,
		/*.a =*/	"ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
		/*.b =*/	"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
		/*.Gx =*/	"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
		/*.Gy =*/	"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
		/*.n =*/	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_ECDSA,
		/*.flags =*/	EC_CURVE_FLAG_A_M3,
	}, {
		/*.name =*/	"brainpoolP256r1",
		/*.name_size =*/15,
		/*.OID =*/	"1.3.36.3.3.2.8.1.1.7",
		/*.OID_size =*/	19,
		/*.num_size =*/	64,
		/*.t =*/	128,
		/*.m =*/	256,
		/*.Fx =*/	{0},
		/*.p =*/	"a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
		/*.SEED =*/	"5b54709179216d5d98979fb1bd1310ba698dfb5a",
		/*.SEED_size =*/40,
		/*.a =*/	"7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9",
		/*.b =*/	"26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6",
		/*.Gx =*/	"8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262",
		/*.Gy =*/	"547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997",
		/*.n =*/	"a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_ECDSA,
		/*.flags =*/	0,
	}, {
		/*.name =*/	"id-GostR3410-2001-ParamSet-cc",
		/*.name_size =*/29,
		/*.OID =*/	"1.2.643.2.9.1.8.1",
		/*.OID_size =*/	17,
		/*.num_size =*/	64,
		/*.t =*/	128,
		/*.m =*/	256,
		/*.Fx =*/	{0},
		/*.p =*/	"c0000000000000000000000000000000000000000000000000000000000003c7",
		/*.SEED =*/	NULL,
		/*.SEED_size =*/0,
		/*.a =*/	"c0000000000000000000000000000000000000000000000000000000000003c4",
		/*.b =*/	"2d06b4265ebc749ff7d0f1f1f88232e81632e9088fd44b7787d5e407e955080c",
		/*.Gx =*/	"0000000000000000000000000000000000000000000000000000000000000002",
		/*.Gy =*/	"a20e034bf8813ef5c18d01105e726a17eb248b264ae9706f440bedc8ccb6b22c",
		/*.n =*/	"5fffffffffffffffffffffffffffffff606117a2f4bde428b7458a54b6e87b85",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_GOST20XX,
		/*.flags =*/	EC_CURVE_FLAG_A_M3,
	}, {
		/*.name =*/	"id-gostR3410-2001-Test_ParamSet",
		/*.name_size =*/30,
		/*.OID =*/	"1.2.643.2.2.35.0",
		/*.OID_size =*/	16,
		/*.num_size =*/	64,
		/*.t =*/	128,
		/*.m =*/	256,
		/*.Fx =*/	{0},
		/*.p =*/	"8000000000000000000000000000000000000000000000000000000000000431",
		/*.SEED =*/	NULL,
		/*.SEED_size =*/0,
		/*.a =*/	"0000000000000000000000000000000000000000000000000000000000000007",
		/*.b =*/	"5fbff498aa938ce739b8e022fbafef40563f6e6a3472fc2a514c0ce9dae23b7e",
		/*.Gx =*/	"0000000000000000000000000000000000000000000000000000000000000002",
		/*.Gy =*/	"08e2a8a0e65147d4bd6316030e16d19c85c97f0a9ca267122b96abbcea7e8fc8",
		/*.n =*/	"8000000000000000000000000000000150fe8a1892976154c59cfc193accf5b3",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_GOST20XX,
		/*.flags =*/	0,
	}, {
		/*.name =*/	"id-gostR3410-2001-CryptoPro-A-ParamSet",
		/*.name_size =*/38,
		/*.OID =*/	"1.2.643.2.2.35.1",
		/*.OID_size =*/	16,
		/*.num_size =*/	64,
		/*.t =*/	128,
		/*.m =*/	256,
		/*.Fx =*/	{0},
		/*.p =*/	"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97",
		/*.SEED =*/	NULL,
		/*.SEED_size =*/0,
		/*.a =*/	"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd94",
		/*.b =*/	"00000000000000000000000000000000000000000000000000000000000000a6",
		/*.Gx =*/	"0000000000000000000000000000000000000000000000000000000000000001",
		/*.Gy =*/	"8d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14",
		/*.n =*/	"ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_GOST20XX,
		/*.flags =*/	EC_CURVE_FLAG_A_M3,
	}, {
		/*.name =*/	"id-gostR3410-2001-CryptoPro-B-ParamSet",
		/*.name_size =*/38,
		/*.OID =*/	"1.2.643.2.2.35.2",
		/*.OID_size =*/	16,
		/*.num_size =*/	64,
		/*.t =*/	128,
		/*.m =*/	256,
		/*.Fx =*/	{0},
		/*.p =*/	"8000000000000000000000000000000000000000000000000000000000000c99",
		/*.SEED =*/	NULL,
		/*.SEED_size =*/0,
		/*.a =*/	"8000000000000000000000000000000000000000000000000000000000000c96",
		/*.b =*/	"3e1af419a269a5f866a7d3c25c3df80ae979259373ff2b182f49d4ce7e1bbc8b",
		/*.Gx =*/	"0000000000000000000000000000000000000000000000000000000000000001",
		/*.Gy =*/	"3fa8124359f96680b83d1c3eb2c070e5c545c9858d03ecfb744bf8d717717efc",
		/*.n =*/	"800000000000000000000000000000015f700cfff1a624e5e497161bcc8a198f",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_GOST20XX,
		/*.flags =*/	EC_CURVE_FLAG_A_M3,
	}, {
		/*.name =*/	"id-gostR3410-2001-CryptoPro-C-ParamSet",
		/*.name_size =*/38,
		/*.OID =*/	"1.2.643.2.2.35.3",
		/*.OID_size =*/	16,
		/*.num_size =*/	64,
		/*.t =*/	128,
		/*.m =*/	256,
		/*.Fx =*/	{0},
		/*.p =*/	"9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d759b",
		/*.SEED =*/	NULL,
		/*.SEED_size =*/0,
		/*.a =*/	"9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d7598",
		/*.b =*/	"000000000000000000000000000000000000000000000000000000000000805a",
		/*.Gx =*/	"0000000000000000000000000000000000000000000000000000000000000000",
		/*.Gy =*/	"41ece55743711a8c3cbf3783cd08c0ee4d4dc440d4641a8f366e550dfdb3bb67",
		/*.n =*/	"9b9f605f5a858107ab1ec85e6b41c8aa582ca3511eddfb74f02f3a6598980bb9",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_GOST20XX,
		/*.flags =*/	EC_CURVE_FLAG_A_M3,
	}, {
		/*.name =*/	"id-gostR3410-2001-CryptoPro-XchA-ParamSet",
		/*.name_size =*/41,
		/*.OID =*/	"1.2.643.2.2.36.0",
		/*.OID_size =*/	16,
		/*.num_size =*/	64,
		/*.t =*/	128,
		/*.m =*/	256,
		/*.Fx =*/	{0},
		/*.p =*/	"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97",
		/*.SEED =*/	NULL,
		/*.SEED_size =*/0,
		/*.a =*/	"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd94",
		/*.b =*/	"00000000000000000000000000000000000000000000000000000000000000a6",
		/*.Gx =*/	"0000000000000000000000000000000000000000000000000000000000000001",
		/*.Gy =*/	"8d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14",
		/*.n =*/	"ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_GOST20XX,
		/*.flags =*/	EC_CURVE_FLAG_A_M3,
	}, {
		/*.name =*/	"id-gostR3410-2001-CryptoPro-XchB-ParamSet",
		/*.name_size =*/41,
		/*.OID =*/	"1.2.643.2.2.36.1",
		/*.OID_size =*/	16,
		/*.num_size =*/	64,
		/*.t =*/	128,
		/*.m =*/	256,
		/*.Fx =*/	{0},
		/*.p =*/	"9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d759b",
		/*.SEED =*/	NULL,
		/*.SEED_size =*/0,
		/*.a =*/	"9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d7598",
		/*.b =*/	"000000000000000000000000000000000000000000000000000000000000805a",
		/*.Gx =*/	"0000000000000000000000000000000000000000000000000000000000000000",
		/*.Gy =*/	"41ece55743711a8c3cbf3783cd08c0ee4d4dc440d4641a8f366e550dfdb3bb67",
		/*.n =*/	"9b9f605f5a858107ab1ec85e6b41c8aa582ca3511eddfb74f02f3a6598980bb9",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_GOST20XX,
		/*.flags =*/	EC_CURVE_FLAG_A_M3,
	}, {
		/*.name =*/	"brainpoolP320r1",
		/*.name_size =*/15,
		/*.OID =*/	"1.3.36.3.3.2.8.1.1.9",
		/*.OID_size =*/	19,
		/*.num_size =*/	80,
		/*.t =*/	160,
		/*.m =*/	320,
		/*.Fx =*/	{0},
		/*.p =*/	"d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27",
		/*.SEED =*/	"c2ffd72dbd01adfb7b8e1afed6a267e96ba7c904",
		/*.SEED_size =*/40,
		/*.a =*/	"3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4",
		/*.b =*/	"520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a6",
		/*.Gx =*/	"43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611",
		/*.Gy =*/	"14fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1",
		/*.n =*/	"d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_ECDSA,
		/*.flags =*/	0,
	}, {
		/*.name =*/	"secp384r1",
		/*.name_size =*/9,
		/*.OID =*/	"1.3.132.0.34",
		/*.OID_size =*/	12,
		/*.num_size =*/	96,
		/*.t =*/	192,
		/*.m =*/	384,
		/*.Fx =*/	{384, 128, 96, 32, 0},
		/*.p =*/	"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
		/*.SEED =*/	"a335926aa319a27a1d00896a6773a4827acdac73",
		/*.SEED_size =*/40,
		/*.a =*/	"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
		/*.b =*/	"b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
		/*.Gx =*/	"aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
		/*.Gy =*/	"3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
		/*.n =*/	"ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_ECDSA,
		/*.flags =*/	EC_CURVE_FLAG_A_M3,
	}, {
		/*.name =*/	"brainpoolP384r1",
		/*.name_size =*/15,
		/*.OID =*/	"1.3.36.3.3.2.8.1.1.11",
		/*.OID_size =*/	19,
		/*.num_size =*/	96,
		/*.t =*/	192,
		/*.m =*/	384,
		/*.Fx =*/	{0},
		/*.p =*/	"8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53",
		/*.SEED =*/	"5f12c7f9924a19947b3916cf70801f2e2858efc1",
		/*.SEED_size =*/40,
		/*.a =*/	"7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826",
		/*.b =*/	"04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11",
		/*.Gx =*/	"1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e",
		/*.Gy =*/	"8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315",
		/*.n =*/	"8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_ECDSA,
		/*.flags =*/	0,
	}, {
		/*.name =*/	"brainpoolP512r1",
		/*.name_size =*/15,
		/*.OID =*/	"1.3.36.3.3.2.8.1.1.13",
		/*.OID_size =*/	19,
		/*.num_size =*/	128,
		/*.t =*/	254,
		/*.m =*/	512,
		/*.Fx =*/	{0},
		/*.p =*/	"aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3",
		/*.SEED =*/	"6636920d871574e69a458fea3f4933d7e0d95748",
		/*.SEED_size =*/40,
		/*.a =*/	"7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca",
		/*.b =*/	"3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723",
		/*.Gx =*/	"81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822",
		/*.Gy =*/	"7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
		/*.n =*/	"aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_ECDSA,
		/*.flags =*/	0,
	}, { /* GOST R 34.10-2012 - 512 */
		/*.name =*/	"id-tc26-gost-3410-12-512-paramSetA",
		/*.name_size =*/34,
		/*.OID =*/	"1.2.643.7.1.2.1.2.1",
		/*.OID_size =*/	19,
		/*.num_size =*/	128,
		/*.t =*/	254,
		/*.m =*/	512,
		/*.Fx =*/	{0},
		/*.p =*/	"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7",
		/*.SEED =*/	NULL,
		/*.SEED_size =*/0,
		/*.a =*/	"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc4",
		/*.b =*/	"e8c2505dedfc86ddc1bd0b2b6667f1da34b82574761cb0e879bd081cfd0b6265ee3cb090f30d27614cb4574010da90dd862ef9d4ebee4761503190785a71c760",
		/*.Gx =*/	"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003",
		/*.Gy =*/	"7503cfe87a836ae3a61b8816e25450e6ce5e1c93acf1abc1778064fdcbefa921df1626be4fd036e93d75e6a50e3a41e98028fe5fc235f5b889a589cb5215f2a4",
		/*.n =*/	"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff27e69532f48d89116ff22b8d4e0560609b4b38abfad2b85dcacdb1411f10b275",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_GOST20XX,
		/*.flags =*/	EC_CURVE_FLAG_A_M3,
	}, { /* GOST R 34.10-2012 - 512 */
		/*.name =*/	"id-tc26-gost-3410-12-512-paramSetB",
		/*.name_size =*/34,
		/*.OID =*/	"1.2.643.7.1.2.1.2.2",
		/*.OID_size =*/	19,
		/*.num_size =*/	128,
		/*.t =*/	254,
		/*.m =*/	512,
		/*.Fx =*/	{0},
		/*.p =*/	"8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006f",
		/*.SEED =*/	NULL,
		/*.SEED_size =*/0,
		/*.a =*/	"8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006c",
		/*.b =*/	"687d1b459dc841457e3e06cf6f5e2517b97c7d614af138bcbf85dc806c4b289f3e965d2db1416d217f8b276fad1ab69c50f78bee1fa3106efb8ccbc7c5140116",
		/*.Gx =*/	"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002",
		/*.Gy =*/	"1a8f7eda389b094c2c071e3647a8940f3c123b697578c213be6dd9e6c8ec7335dcb228fd1edf4a39152cbcaaf8c0398828041055f94ceeec7e21340780fe41bd",
		/*.n =*/	"800000000000000000000000000000000000000000000000000000000000000149a1ec142565a545acfdb77bd9d40cfa8b996712101bea0ec6346c54374f25bd",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_GOST20XX,
		/*.flags =*/	EC_CURVE_FLAG_A_M3,
	}, {
		/*.name =*/	"secp521r1",
		/*.name_size =*/9,
		/*.OID =*/	"1.3.132.0.35",
		/*.OID_size =*/	12,
		/*.num_size =*/	132,
		/*.t =*/	256,
		/*.m =*/	521,
		/*.Fx =*/	{521, 0},
		/*.p =*/	"01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		/*.SEED =*/	"d09e8800291cb85396cc6717393284aaa0da64ba",
		/*.SEED_size =*/40,
		/*.a =*/	"01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
		/*.b =*/	"0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
		/*.Gx =*/	"00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
		/*.Gy =*/	"011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
		/*.n =*/	"01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
		/*.h =*/	1,
		/*.algo =*/	EC_CURVE_ALGO_ECDSA,
		/*.flags =*/	EC_CURVE_FLAG_A_M3,
	}, {
		/*.name =*/	NULL,
		/*.name_size =*/0,
		/*.OID =*/	NULL,
		/*.OID_size =*/	0,
		/*.num_size =*/	0,
		/*.t =*/	0,
		/*.m =*/	0,
		/*.Fx =*/	{0},
		/*.p =*/	NULL,
		/*.SEED =*/	NULL,
		/*.SEED_size =*/0,
		/*.a =*/	NULL,
		/*.b =*/	NULL,
		/*.Gx =*/	NULL,
		/*.Gy =*/	NULL,
		/*.n =*/	NULL,
		/*.h =*/	0,
		/*.algo =*/	0,
		/*.flags =*/	0,
	}
};

/*
 * SEC 1 Ver. 2.0: 3.11 Security Levels and Protection Lifetimes (p.42):
 * Based on current approximations, this document requires that data that
 * needs protection beyond the year 2010 must be protected with 112-bit security
 * or higher.
 * Data that needs protection beyond the year 2030 must be protected with 128-bit
 * security or higher.
 * Data that needs protection beyond the year 2040 should be protected with 192-bit
 * security or higher.
 * Data that needs protection beyond 2080 should be protected with 256-bit security
 * or higher.
 */


static inline ec_curve_str_p
ecdsa_curve_str_get_by_name(const char *name, size_t name_size) {
	size_t i;

	for (i = 0; NULL != ec_curve_str[i].name; i ++) {
		if (name_size == ec_curve_str[i].name_size &&
		    0 == memcmp(ec_curve_str[i].name, name, name_size))
			return (&ec_curve_str[i]);
	}
	return (NULL);
}

static inline int
ecdsa_curve_from_str(ec_curve_str_p curve_str, ec_curve_p curve) {
	size_t bits, n_len;

	if (NULL == curve_str || NULL == curve)
		return (EINVAL);
	memset(curve, 0, sizeof(ec_curve_t));
	n_len = strlen((const char*)curve_str->n);

	/* Normal size + 1 digit in special cases. */
	bits = EC_CURVE_CALC_BYTES(curve_str);
	if (n_len != curve_str->num_size) {
		bits ++;
	}
	bits *= 8;
	/* Init. */
	BN_RET_ON_ERR(bn_init(&curve->p, bits));
	BN_RET_ON_ERR(bn_init(&curve->a, bits));
	BN_RET_ON_ERR(bn_init(&curve->b, bits));
	BN_RET_ON_ERR(ec_point_init(&curve->G, bits));
	BN_RET_ON_ERR(bn_init(&curve->n, bits));
	//curve->h = 0;

	/* Assign values. */
	curve->t = curve_str->t;
	curve->m = curve_str->m;
	BN_RET_ON_ERR(bn_import_be_hex(&curve->p,
	    (const uint8_t*)curve_str->p, curve_str->num_size));
	BN_RET_ON_ERR(bn_import_be_hex(&curve->a,
	    (const uint8_t*)curve_str->a, curve_str->num_size));
	BN_RET_ON_ERR(bn_import_be_hex(&curve->b,
	    (const uint8_t*)curve_str->b, curve_str->num_size));
	BN_RET_ON_ERR(bn_import_be_hex(&curve->G.x,
	    (const uint8_t*)curve_str->Gx, curve_str->num_size));
	BN_RET_ON_ERR(bn_import_be_hex(&curve->G.y,
	    (const uint8_t*)curve_str->Gy, curve_str->num_size));
	BN_RET_ON_ERR(bn_import_be_hex(&curve->n,
	    (const uint8_t*)curve_str->n, n_len));
	curve->h = curve_str->h;
	curve->algo = curve_str->algo;
	curve->flags = curve_str->flags;

	BN_RET_ON_ERR(bn_mod_rd_data_init(&curve->p, &curve->p_mod_rd_data));
	BN_RET_ON_ERR(bn_mod_rd_data_init(&curve->n, &curve->n_mod_rd_data));

#if EC_PF_FXP_MULT_ALGO != EC_PF_FXP_MULT_ALGO_BIN
	BN_RET_ON_ERR(ec_point_fpx_mult_precompute(EC_PF_FXP_MULT_WIN_BITS,
	    &curve->G, curve, &curve->G_fpx_mult_data));
#endif
	return (0);
}


/* ECDSA */
/* Require big-endian data. */

/* Key compress. */
/* http://tools.ietf.org/html/draft-jivsov-ecc-compact-00 */
/* SEC 1 Ver. 2.0, p.10: 2.3.3 Elliptic-Curve-Point-to-Octet-String Conversion */
/* 
 * Input:
 *  curve - EC domain parameters
 *  compress - 0 - do not compress, != 0 compress pub key
 *  point - EC public key
 * Output:
 *  pub_key_x - compressed or packed pub key data
 *  pub_key_y - if != NULL and compress = 0 then it reveice Y of pub key data
 *  pub_key_size - pub key size
 * Return: 0 on no error, -1 if some algorim error, >0 on other error.
 */
static inline int
ecdsa_pub_key_export_be(ec_curve_p curve, int compress, ec_point_p point,
    uint8_t *pub_key_x, uint8_t *pub_key_y, size_t *pub_key_size) {
	size_t bytes;

	if (NULL == curve || NULL == point || NULL == pub_key_x ||
	    NULL == pub_key_size)
		return (EINVAL);
	if (0 != ec_point_is_at_infinity(point)) {
		pub_key_x[0] = 0;
		(*pub_key_size) = 1;
		return (0);
	}
	/* Calc bytes count for numbers. */
	bytes = EC_CURVE_CALC_BYTES(curve);
	if (0 == compress) { /* Do not compress. */
		if (NULL != pub_key_y) { /* Separeted x and y */
			BN_RET_ON_ERR(bn_export_be_bin(&point->x, 0,
			    pub_key_x, bytes, NULL));
			BN_RET_ON_ERR(bn_export_be_bin(&point->y, 0,
			    pub_key_y, bytes, NULL));
			(*pub_key_size) = bytes;
			return (0);
		}
		/* Packed x and y. */
		pub_key_x[0] = 4;
		BN_RET_ON_ERR(bn_export_be_bin(&point->x, 0,
		    (pub_key_x + 1), bytes, NULL));
		BN_RET_ON_ERR(bn_export_be_bin(&point->y, 0,
		    (pub_key_x + 1 + bytes), bytes, NULL));
		(*pub_key_size) = (1 + (bytes * 2));
		return (0);
	}
	/* Compress. */
	if (0 == bn_is_odd(&point->y)) {
		pub_key_x[0] = 2;
	} else {
		pub_key_x[0] = 3;
	}
	BN_RET_ON_ERR(bn_export_be_bin(&point->x, 0,
	    (pub_key_x + 1), bytes, NULL));
	(*pub_key_size) = (1 + bytes);
	return (0);
}
static inline int
ecdsa_pub_key_export_le(ec_curve_p curve, int compress, ec_point_p point,
    uint8_t *pub_key_x, uint8_t *pub_key_y, size_t *pub_key_size) {
	size_t bytes;

	if (NULL == curve || NULL == point || NULL == pub_key_x ||
	    NULL == pub_key_size)
		return (EINVAL);
	if (0 != ec_point_is_at_infinity(point)) {
		pub_key_x[0] = 0;
		(*pub_key_size) = 1;
		return (0);
	}
	/* Calc bytes count for numbers. */
	bytes = EC_CURVE_CALC_BYTES(curve);
	if (0 == compress) { /* Do not compress. */
		if (NULL != pub_key_y) { /* Separeted x and y */
			BN_RET_ON_ERR(bn_export_le_bin(&point->x, 0,
			    pub_key_x, bytes, NULL));
			BN_RET_ON_ERR(bn_export_le_bin(&point->y, 0,
			    pub_key_y, bytes, NULL));
			(*pub_key_size) = bytes;
			return (0);
		}
		/* Packed x and y. */
		pub_key_x[0] = 4;
		BN_RET_ON_ERR(bn_export_le_bin(&point->x, 0,
		    (pub_key_x + 1), bytes, NULL));
		BN_RET_ON_ERR(bn_export_le_bin(&point->y, 0,
		    (pub_key_x + 1 + bytes), bytes, NULL));
		(*pub_key_size) = (1 + (bytes * 2));
		return (0);
	}
	/* Compress. */
	if (0 == bn_is_odd(&point->y)) {
		pub_key_x[0] = 2;
	} else {
		pub_key_x[0] = 3;
	}
	BN_RET_ON_ERR(bn_export_le_bin(&point->x, 0,
	    (pub_key_x + 1), bytes, NULL));
	(*pub_key_size) = (1 + bytes);
	return (0);
}

/* Key uncompress. */
/* http://tools.ietf.org/html/draft-jivsov-ecc-compact-00 */
/* SEC 1 Ver. 2.0, p.11: 2.3.4 Octet-String-to-Elliptic-Curve-Point Conversion */
/* 
 * Input:
 *  curve - EC domain parameters
 *  pub_key_x - compressed or packed pub key data
 *  pub_key_y - optional, Y of pub key data
 *  pub_key_size - pub key size
 * Output:
 *  point - EC public key
 * Return: 0 on no error, -1 if some algorim error, >0 on other error.
 */
static inline int
ecdsa_pub_key_import_be(ec_curve_p curve,
    uint8_t *pub_key_x, uint8_t *pub_key_y, size_t pub_key_size,
    ec_point_p point) {
	size_t bytes;

	if (NULL == curve || NULL == pub_key_x || 0 == pub_key_size ||
	    NULL == point)
		return (EINVAL);
	/* Calc bytes count for numbers. */
	bytes = EC_CURVE_CALC_BYTES(curve);

	/* 00 -> point = O */
	if (1 == pub_key_size) {
		if (0 != pub_key_x[0])
			return (EINVAL);
		point->infinity = 1;
		return (0);
	}
	/* Uncompressed, (x, y) specified. */
	if (bytes == pub_key_size) {
		if (NULL == pub_key_y)
			return (EINVAL);
		BN_RET_ON_ERR(bn_import_be_bin(&point->x, pub_key_x,
		    pub_key_size));
		BN_RET_ON_ERR(bn_import_be_bin(&point->y, pub_key_y,
		    pub_key_size));
		BN_RET_ON_ERR(ec_point_check_as_pub_key__int(point, curve));
		return (0);
	}
	/* Try uncompress or unpack... */
	/* Is compressed? */
	if ((1 + bytes) == pub_key_size) {
		if (2 != pub_key_x[0] &&
		    3 != pub_key_x[0])
			return (-1);
		BN_RET_ON_ERR(bn_import_be_bin(&point->x,
		    (pub_key_x + 1), bytes));
		/* y ≡ pub_key_x[0] (mod 2) */
		BN_RET_ON_ERR(ec_point_restore_y_by_x(
		    ((0 != (pub_key_x[0] & 1)) ? 1 : 0), point, curve));
		return (0);
	}
	/* Is packed? */
	if ((1 + (bytes * 2)) == pub_key_size) {
		if (4 != pub_key_x[0] &&
		    6 != pub_key_x[0] &&
		    7 != pub_key_x[0])
			return (-1);
		BN_RET_ON_ERR(bn_import_be_bin(&point->x,
		    (pub_key_x + 1), bytes));
		BN_RET_ON_ERR(bn_import_be_bin(&point->y,
		    (pub_key_x + 1 + bytes), bytes));
		BN_RET_ON_ERR(ec_point_check_as_pub_key__int(point, curve));
		return (0);
	}
	if ((bytes * 2) == pub_key_size) {
		BN_RET_ON_ERR(bn_import_be_bin(&point->x, pub_key_x, bytes));
		BN_RET_ON_ERR(bn_import_be_bin(&point->y,
		    (pub_key_x + bytes), bytes));
		BN_RET_ON_ERR(ec_point_check_as_pub_key__int(point, curve));
		return (0);
	}
	/* Unknown format. */
	return (-1);
}
static inline int
ecdsa_pub_key_import_le(ec_curve_p curve,
    uint8_t *pub_key_x, uint8_t *pub_key_y, size_t pub_key_size,
    ec_point_p point) {
	size_t bytes;

	if (NULL == curve || NULL == pub_key_x || 0 == pub_key_size ||
	    NULL == point)
		return (EINVAL);
	/* Calc bytes count for numbers. */
	bytes = EC_CURVE_CALC_BYTES(curve);

	/* 00 -> point = O */
	if (1 == pub_key_size) {
		if (0 != pub_key_x[0])
			return (EINVAL);
		point->infinity = 1;
		return (0);
	}
	/* Uncompressed, (x, y) specified. */
	if (bytes == pub_key_size) {
		if (NULL == pub_key_y)
			return (EINVAL);
		BN_RET_ON_ERR(bn_import_le_bin(&point->x, pub_key_x,
		    pub_key_size));
		BN_RET_ON_ERR(bn_import_le_bin(&point->y, pub_key_y,
		    pub_key_size));
		BN_RET_ON_ERR(ec_point_check_as_pub_key__int(point, curve));
		return (0);
	}
	/* Try uncompress or unpack... */
	/* Is compressed? */
	if ((1 + bytes) == pub_key_size) {
		if (2 != pub_key_x[0] &&
		    3 != pub_key_x[0])
			return (-1);
		BN_RET_ON_ERR(bn_import_le_bin(&point->x,
		    (pub_key_x + 1), bytes));
		/* y ≡ pub_key_x[0] (mod 2) */
		BN_RET_ON_ERR(ec_point_restore_y_by_x(
		    ((0 != (pub_key_x[0] & 1)) ? 1 : 0), point, curve));
		return (0);
	}
	/* Is packed? */
	if ((1 + (bytes * 2)) == pub_key_size) {
		if (4 != pub_key_x[0] &&
		    6 != pub_key_x[0] &&
		    7 != pub_key_x[0])
			return (-1);
		BN_RET_ON_ERR(bn_import_le_bin(&point->x,
		    (pub_key_x + 1), bytes));
		BN_RET_ON_ERR(bn_import_le_bin(&point->y,
		    (pub_key_x + 1 + bytes), bytes));
		BN_RET_ON_ERR(ec_point_check_as_pub_key__int(point, curve));
		return (0);
	}
	if ((bytes * 2) == pub_key_size) {
		BN_RET_ON_ERR(bn_import_le_bin(&point->x,
		    pub_key_x, bytes));
		BN_RET_ON_ERR(bn_import_le_bin(&point->y,
		    (pub_key_x + bytes), bytes));
		BN_RET_ON_ERR(ec_point_check_as_pub_key__int(point, curve));
		return (0);
	}
	/* Unknown format. */
	return (-1);
}


/* If function return error then generate another rnd and recall. */
/* 
 * Input:
 *  curve - EC domain parameters
 *  d - private key = random
 * Output:
 *  Q - pub key
 * Return: 0 on no error, -1 if some algorim error, >0 on other error.
 */
static inline int
ecdsa_key_gen(ec_curve_p curve, bn_p d, ec_point_p Q) {

	if (NULL == curve || NULL == d || NULL == Q)
		return (EINVAL);
	/* Reduce random number. */
	/*  d = (c mod (n − 1)) + 1 */
	BN_RET_ON_ERR(bn_mod_reduce(d, &curve->n, &curve->n_mod_rd_data));
	/* Q = dG */
	ec_point_mult_bp(d, curve, Q);
	BN_RET_ON_ERR(ec_point_check_as_pub_key(Q, curve));
	return (0);
}
/* 
 * Input:
 *  curve - EC domain parameters
 *  rnd - point to random data
 *  rnd_size - random data size
 *  pub_key_compress - 0 - do not compress, != 0 compress pub key
 * Output:
 *  priv_key - private key data
 *  priv_key_size - private key size
 *  pub_key_x - compressed or packed pub key data
 *  pub_key_y - if != NULL and compress = 0 then it reveice Y of pub key data
 *  pub_key_size - pub key size
 * Return: 0 on no error, -1 if some algorim error, >0 on other error.
 */
static inline int
ecdsa_key_gen_be(ec_curve_p curve, uint8_t *rnd, size_t rnd_size,
    int pub_key_compress,
    uint8_t *priv_key, size_t *priv_key_size,
    uint8_t *pub_key_x, uint8_t *pub_key_y, size_t *pub_key_size) {
	size_t bits, bytes;
	bn_t d;
	ec_point_t Q;

	if (NULL == curve || NULL == rnd || 0 == rnd_size || NULL == priv_key ||
	    NULL == pub_key_x || NULL == pub_key_y || NULL == pub_key_size)
		return (EINVAL);
	/* Calc bytes count for numbers. */
	bytes = EC_CURVE_CALC_BYTES(curve);
	if (rnd_size < bytes)
		return (EINVAL);
	/* Double size + 1 digit. */
	bits = EC_CURVE_CALC_BITS_DBL(curve);
	/* Init */
	BN_RET_ON_ERR(bn_init(&d, bits));
	BN_RET_ON_ERR(ec_point_init(&Q, bits));
	/* Random number. */
	BN_RET_ON_ERR(bn_import_be_bin(&d, rnd, bytes));
	/* Get keys. */
	BN_RET_ON_ERR(ecdsa_key_gen(curve, &d, &Q));
	/* Export result. */
	BN_RET_ON_ERR(bn_export_be_bin(&d, 0, priv_key, bytes, NULL));
	if (NULL != priv_key_size) {
		(*priv_key_size) = bytes;
	}
	BN_RET_ON_ERR(ecdsa_pub_key_export_be(curve, pub_key_compress,
	    &Q, pub_key_x, pub_key_y, pub_key_size));
	return (0);
}
static inline int
ecdsa_key_gen_le(ec_curve_p curve, uint8_t *rnd, size_t rnd_size,
    int pub_key_compress,
    uint8_t *priv_key, size_t *priv_key_size,
    uint8_t *pub_key_x, uint8_t *pub_key_y, size_t *pub_key_size) {
	size_t bits, bytes;
	bn_t d;
	ec_point_t Q;

	if (NULL == curve || NULL == rnd || 0 == rnd_size || NULL == priv_key ||
	    NULL == pub_key_x || NULL == pub_key_y || NULL == pub_key_size)
		return (EINVAL);
	/* Calc bytes count for numbers. */
	bytes = EC_CURVE_CALC_BYTES(curve);
	if (rnd_size < bytes)
		return (EINVAL);
	/* Double size + 1 digit. */
	bits = EC_CURVE_CALC_BITS_DBL(curve);
	/* Init */
	BN_RET_ON_ERR(bn_init(&d, bits));
	BN_RET_ON_ERR(ec_point_init(&Q, bits));
	/* Random number. */
	BN_RET_ON_ERR(bn_import_le_bin(&d, rnd, bytes));
	/* Get keys. */
	BN_RET_ON_ERR(ecdsa_key_gen(curve, &d, &Q));
	/* Export result. */
	BN_RET_ON_ERR(bn_export_le_bin(&d, 0, priv_key, bytes, NULL));
	if (NULL != priv_key_size) {
		(*priv_key_size) = bytes;
	}
	BN_RET_ON_ERR(ecdsa_pub_key_export_le(curve, pub_key_compress,
	    &Q, pub_key_x, pub_key_y, pub_key_size));
	return (0);
}

/* Signing */
/* 
 * Input:
 *  curve - EC domain parameters
 *  hash - hash of message (e)
 *  priv_key - private key (d)
 *  rnd - random
 * DJB: replace rnd by HASH(s; message)
 * Output:
 *  sign_r - signature r (can point to hash)
 *  sign_s - signature s (can point to rnd)
 * Return: 0 on no error, -1 if some algorim error, >0 on other error.
 */
static inline int
ecdsa_sign(ec_curve_p curve, bn_p hash, bn_p priv_key, bn_p rnd,
    bn_p sign_r, bn_p sign_s) {
	size_t bits;
	ec_point_t R;

	if (NULL == curve || NULL == hash || NULL == priv_key ||
	    NULL == rnd || NULL == sign_r || NULL == sign_s)
		return (EINVAL);
	if (bn_cmp(priv_key, &curve->n) >= 0) /* Key check. */
		return (EINVAL);

	/* Double size + 1 digit. */
	bits = EC_CURVE_CALC_BITS_DBL(curve);
	/* Init */
	BN_RET_ON_ERR(ec_point_init(&R, bits)); /* Also use point to store temp vars. */
	/* Reduce random number (k). */
	/* k = (c mod (n − 1)) + 1 */
	BN_RET_ON_ERR(bn_assign(sign_s, rnd));
	BN_RET_ON_ERR(bn_mod_reduce(sign_s, &curve->n,
	    &curve->n_mod_rd_data));
	/* R = rnd*G */
	/* Slow operation. */
	ec_point_mult_bp(sign_s, curve, &R);
	/* r = Rx mod n */
	BN_RET_ON_ERR(bn_mod(&R.x, &curve->n, &curve->n_mod_rd_data));
	if (0 != bn_is_zero(&R.x))
		return (-1);
	/* HASH reduce (e). */
	BN_RET_ON_ERR(bn_assign(&R.y, hash));
	BN_RET_ON_ERR(bn_mod_reduce(&R.y, &curve->n,
	    &curve->n_mod_rd_data));

	/* Store result. (Possible sign_r == hash so do it here). */
	BN_RET_ON_ERR(bn_assign(sign_r, &R.x));

	/* ECDSA: s = (rnd^−1 * (hash + priv_key * r)) mod n */
	/* GOST: s = ((rnd * hash) + (priv_key * r))) mod n */
	/* calc... */
	/* (priv_key * r) */
	BN_RET_ON_ERR(bn_mod_mult(&R.x, priv_key, &curve->n,
	    &curve->n_mod_rd_data));
	switch (curve->algo) {
	case EC_CURVE_ALGO_ECDSA:
		BN_RET_ON_ERR(bn_mod_add(&R.y, &R.x, &curve->n,
		    &curve->n_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_inv(sign_s, &curve->n,
		    &curve->n_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_mult(sign_s, &R.y, &curve->n,
		    &curve->n_mod_rd_data));
		break;
	case EC_CURVE_ALGO_GOST20XX:
		if (0 == bn_is_zero(&R.y)) { /* GOST step 2: if hash == 0 then hash = 1. */
			BN_RET_ON_ERR(bn_mod_mult(sign_s, &R.y, &curve->n,
			    &curve->n_mod_rd_data));
		}
		BN_RET_ON_ERR(bn_mod_add(sign_s, &R.x, &curve->n,
		    &curve->n_mod_rd_data));
		break;
	default:
		return (EINVAL);
	}
	if (0 != bn_is_zero(sign_s))
		return (-1);
	/* Return (r, s) */
	return (0);
}
/* 
 * Input:
 *  curve - EC domain parameters
 *  hash - point to hash of message
 *  hash_size - hash size
 *  priv_key - private key data
 *  priv_key_size - private key size
 *  rnd - point to random data
 *  rnd_size - random data size
 * Output:
 *  sign_r - signature r data
 *  sign_s - signature s data
 *  sign_size - signature size
 * Return: 0 on no error, -1 if some algorim error, >0 on other error.
 */
static inline int
ecdsa_sign_be(ec_curve_p curve, uint8_t *hash, size_t hash_size,
    uint8_t *priv_key, size_t priv_key_size,
    uint8_t *rnd, size_t rnd_size,
    uint8_t *sign_r, uint8_t *sign_s, size_t *sign_size) {
	size_t bits, bytes;
	bn_t r, s, d;

	if (NULL == curve || NULL == hash || 0 == hash_size ||
	    NULL == priv_key || 0 == priv_key_size ||
	    NULL == rnd || 0 == rnd_size)
		return (EINVAL);
	/* Calc bytes count for numbers. */
	bytes = EC_CURVE_CALC_BYTES(curve);
	if (rnd_size < priv_key_size || priv_key_size > bytes)
		return (EINVAL); /* Random number too short / Private key too long. */
	/* Double size + 1 digit. */
	bits = EC_CURVE_CALC_BITS_DBL(curve);
	/* Init */
	BN_RET_ON_ERR(bn_init(&r, bits));
	BN_RET_ON_ERR(bn_init(&s, bits));
	BN_RET_ON_ERR(bn_init(&d, bits));
	/* HASH import. */
	BN_RET_ON_ERR(bn_import_be_bin(&r, hash, min(hash_size, bytes)));
	/* Random number. */
	BN_RET_ON_ERR(bn_import_be_bin(&s, rnd, bytes));
	/* Key import. */
	BN_RET_ON_ERR(bn_import_be_bin(&d, priv_key, priv_key_size));
	/* Get sign. */
	BN_RET_ON_ERR(ecdsa_sign(curve, &r, &d, &s, &r,&s));
	/* Return (r, s) */
	/* Export result. */
	BN_RET_ON_ERR(bn_export_be_bin(&r, 0, sign_r, bytes, NULL));
	BN_RET_ON_ERR(bn_export_be_bin(&s, 0, sign_s, bytes, NULL));
	if (NULL != sign_size) {
		(*sign_size) = bytes;
	}
	return (0);
}
static inline int
ecdsa_sign_le(ec_curve_p curve, uint8_t *hash, size_t hash_size,
    uint8_t *priv_key, size_t priv_key_size,
    uint8_t *rnd, size_t rnd_size,
    uint8_t *sign_r, uint8_t *sign_s, size_t *sign_size) {
	size_t bits, bytes;
	bn_t r, s, d;

	if (NULL == curve || NULL == hash || 0 == hash_size ||
	    NULL == priv_key || 0 == priv_key_size ||
	    NULL == rnd || 0 == rnd_size)
		return (EINVAL);
	/* Calc bytes count for numbers. */
	bytes = EC_CURVE_CALC_BYTES(curve);
	if (rnd_size < priv_key_size || priv_key_size > bytes)
		return (EINVAL); /* Random number too short / Private key too long. */
	/* Double size + 1 digit. */
	bits = EC_CURVE_CALC_BITS_DBL(curve);
	/* Init */
	BN_RET_ON_ERR(bn_init(&r, bits));
	BN_RET_ON_ERR(bn_init(&s, bits));
	BN_RET_ON_ERR(bn_init(&d, bits));
	/* HASH import. */
	BN_RET_ON_ERR(bn_import_le_bin(&r, hash, min(hash_size, bytes)));
	/* Random number. */
	BN_RET_ON_ERR(bn_import_le_bin(&s, rnd, bytes));
	/* Key import. */
	BN_RET_ON_ERR(bn_import_le_bin(&d, priv_key, priv_key_size));
	/* Get sign. */
	BN_RET_ON_ERR(ecdsa_sign(curve, &r, &d, &s, &r,&s));
	/* Return (r, s) */
	/* Export result. */
	BN_RET_ON_ERR(bn_export_le_bin(&r, 0, sign_r, bytes, NULL));
	BN_RET_ON_ERR(bn_export_le_bin(&s, 0, sign_s, bytes, NULL));
	if (NULL != sign_size) {
		(*sign_size) = bytes;
	}
	return (0);
}

/* Verifying */
/* 
 * Input:
 *  curve - EC domain parameters
 *  hash - hash of message (e)
 *  sign_r - signature r
 *  sign_s - signature s
 *  pub_key - pub key (Q)
 * Output:
 * - none
 * Return: 0 on no error, -2 on bad sign, -1 if some algorim error, >0 on other error.
 */
static inline int
ecdsa_verify(ec_curve_p curve, bn_p hash, bn_p sign_r, bn_p sign_s,
    ec_point_p pub_key) {
	size_t bits;
	bn_t u1, u2;
	ec_point_t R;

	if (NULL == curve || NULL == hash ||
	    NULL == sign_r || NULL == sign_s ||
	    NULL == pub_key)
		return (EINVAL);
	if (bn_cmp(sign_r, &curve->n) >= 0 ||
	    bn_cmp(sign_s, &curve->n) >= 0) /* sign_r and sign_s check. */
		return (EINVAL);
	/* Double size + 1 digit. */
	bits = EC_CURVE_CALC_BITS_DBL(curve);
	/* Init */
	BN_RET_ON_ERR(bn_init(&u1, bits));
	BN_RET_ON_ERR(bn_init(&u2, bits));
	BN_RET_ON_ERR(ec_point_init(&R, curve->m));
	/* Hash too long? - reduce. */
	BN_RET_ON_ERR(bn_assign(&u1, hash));
	BN_RET_ON_ERR(bn_mod_reduce(&u1, &curve->n, &curve->n_mod_rd_data));

	/* ECDSA: u1 = (hash * s^−1) mod n, u2 = (r * s^−1) mod n */
	/* GOST: u1 = (hash^−1 * s) mod n, u2 = -(hash^−1 * r) mod n */
	/* calc... */
	switch (curve->algo) {
	case EC_CURVE_ALGO_ECDSA:
		/* u2 = (s)^−1 mod n */
		BN_RET_ON_ERR(bn_assign(&u2, sign_s));
		BN_RET_ON_ERR(bn_mod_inv(&u2, &curve->n,
		    &curve->n_mod_rd_data));
		/* u1 = (hash * s^−1) mod n */
		BN_RET_ON_ERR(bn_mod_mult(&u1, &u2, &curve->n,
		    &curve->n_mod_rd_data));
		/* u2 = (r * s^−1) mod n */
		BN_RET_ON_ERR(bn_mod_mult(&u2, sign_r, &curve->n,
		    &curve->n_mod_rd_data));
		break;
	case EC_CURVE_ALGO_GOST20XX:
		if (0 != bn_is_zero(&u1)) { /* GOST step 2: if e == 0 then e = 1. */
			BN_RET_ON_ERR(bn_assign_digit(&u1, 1));
		}
		BN_RET_ON_ERR(bn_mod_inv(&u1, &curve->n,
		    &curve->n_mod_rd_data));
		/* u2 = -(hash^−1 * r) */
		BN_RET_ON_ERR(bn_assign(&u2, &curve->n));
		BN_RET_ON_ERR(bn_mod_sub(&u2, &u1, &curve->n,
		    &curve->n_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_mult(&u2, sign_r, &curve->n,
		    &curve->n_mod_rd_data));
		/* u1 = (hash^−1 * s) */
		BN_RET_ON_ERR(bn_mod_mult(&u1, sign_s, &curve->n,
		    &curve->n_mod_rd_data));
		break;
	default:
		return (EINVAL);
	}
	/* R = (Rx, Ry) = u1*G + u2*Q */
	ec_point_twin_mult_bp(&u1, pub_key, &u2, curve, &R); /* Slow operation. */
	if (0 != R.infinity)
		return (-1);
	/* v = Rx mod n */
	BN_RET_ON_ERR(bn_assign(&u1, &R.x));
	BN_RET_ON_ERR(bn_mod(&u1, &curve->n, &curve->n_mod_rd_data));
	if (0 != bn_cmp(&u1, sign_r))
		return (-2);
	return (0);
}
/* 
 * Input:
 *  curve - EC domain parameters
 *  hash - point to hash of message
 *  hash_size - hash size
 *  sign_r - signature r data
 *  sign_s - signature s data
 *  sign_size - signature size
 *  pub_key_x - compressed or packed pub key data
 *  pub_key_y - if != NULL and compress = 0 then it reveice Y of pub key data
 *  pub_key_size - pub key size
 * Output:
 * - none
 * Return: 0 on no error, -2 on bad sign, -1 if some algorim error, >0 on other error.
 */
static inline int
ecdsa_verify_be(ec_curve_p curve,
    uint8_t *hash, size_t hash_size,
    uint8_t *sign_r, uint8_t *sign_s, size_t sign_size,
    uint8_t *pub_key_x, uint8_t *pub_key_y, size_t pub_key_size) {
	size_t bits, bytes;
	bn_t e, r, s;
	ec_point_t Q;

	if (NULL == curve || NULL == hash || 0 == hash_size || 
	    NULL == sign_r || NULL == sign_s || 0 == sign_size ||
	    NULL == pub_key_x || 0 == pub_key_size)
		return (EINVAL);
	/* Calc bytes count for numbers. */
	bytes = EC_CURVE_CALC_BYTES(curve);
	if (sign_size > bytes)
		return (EINVAL);
	/* Double size + 1 digit. */
	bits = EC_CURVE_CALC_BITS_DBL(curve);
	/* Init */
	BN_RET_ON_ERR(bn_init(&e, bits));
	BN_RET_ON_ERR(bn_init(&r, bits));
	BN_RET_ON_ERR(bn_init(&s, bits));
	BN_RET_ON_ERR(ec_point_init(&Q, curve->m));
	/* Import Q.*/
	BN_RET_ON_ERR(ecdsa_pub_key_import_be(curve, pub_key_x, pub_key_y,
	    pub_key_size, &Q));
	/* Import Hash. */
	BN_RET_ON_ERR(bn_import_be_bin(&e, hash, min(hash_size, bytes)));
	/* Import r.*/
	BN_RET_ON_ERR(bn_import_be_bin(&r, sign_r, sign_size));
	/* Import s.*/
	BN_RET_ON_ERR(bn_import_be_bin(&s, sign_s, sign_size));
	/* Verify. */
	BN_RET_ON_ERR(ecdsa_verify(curve, &e, &r, &s, &Q));
	return (0);
}
static inline int
ecdsa_verify_le(ec_curve_p curve,
    uint8_t *hash, size_t hash_size,
    uint8_t *sign_r, uint8_t *sign_s, size_t sign_size,
    uint8_t *pub_key_x, uint8_t *pub_key_y, size_t pub_key_size) {
	size_t bits, bytes;
	bn_t e, r, s;
	ec_point_t Q;

	if (NULL == curve || NULL == hash || 0 == hash_size || 
	    NULL == sign_r || NULL == sign_s || 0 == sign_size ||
	    NULL == pub_key_x || 0 == pub_key_size)
		return (EINVAL);
	/* Calc bytes count for numbers. */
	bytes = EC_CURVE_CALC_BYTES(curve);
	if (sign_size > bytes)
		return (EINVAL);
	/* Double size + 1 digit. */
	bits = EC_CURVE_CALC_BITS_DBL(curve);
	/* Init */
	BN_RET_ON_ERR(bn_init(&e, bits));
	BN_RET_ON_ERR(bn_init(&r, bits));
	BN_RET_ON_ERR(bn_init(&s, bits));
	BN_RET_ON_ERR(ec_point_init(&Q, curve->m));
	/* Import Q.*/
	BN_RET_ON_ERR(ecdsa_pub_key_import_le(curve, pub_key_x, pub_key_y,
	    pub_key_size, &Q));
	/* Import Hash. */
	BN_RET_ON_ERR(bn_import_le_bin(&e, hash, min(hash_size, bytes)));
	/* Import r.*/
	BN_RET_ON_ERR(bn_import_le_bin(&r, sign_r, sign_size));
	/* Import s.*/
	BN_RET_ON_ERR(bn_import_le_bin(&s, sign_s, sign_size));
	/* Verify. */
	BN_RET_ON_ERR(ecdsa_verify(curve, &e, &r, &s, &Q));
	return (0);
}

/* Verifying (alternative), using private key */
/* 
 * Input:
 *  curve - EC domain parameters
 *  hash - hash of message (e)
 *  sign_r - signature r
 *  sign_s - signature s
 *  priv_key - private key (d)
 * Output:
 * - none
 * Return: 0 on no error, -2 on bad sign, -1 if some algorim error, >0 on other error.
 */
static inline int
ecdsa_verify_priv_key(ec_curve_p curve, bn_p hash, bn_p sign_r, bn_p sign_s,
    bn_p priv_key) {
	size_t bits;
	bn_t u1, u2;
	ec_point_t R;

	if (NULL == curve || NULL == hash ||
	    NULL == sign_r || NULL == sign_s ||
	    NULL == priv_key)
		return (EINVAL);
	if (bn_cmp(sign_r, &curve->n) >= 0 ||
	    bn_cmp(sign_s, &curve->n) >= 0) /* sign_r and sign_s check. */
		return (EINVAL);
	if (bn_cmp(priv_key, &curve->n) >= 0) /* Key check. */
		return (EINVAL);
	/* Double size + 1 digit. */
	bits = EC_CURVE_CALC_BITS_DBL(curve);
	/* Init */
	BN_RET_ON_ERR(bn_init(&u1, bits));
	BN_RET_ON_ERR(bn_init(&u2, bits));
	BN_RET_ON_ERR(ec_point_init(&R, curve->m));
	/* Hash too long? - reduce. */
	BN_RET_ON_ERR(bn_assign(&u1, hash));
	BN_RET_ON_ERR(bn_mod_reduce(&u1, &curve->n,
	    &curve->n_mod_rd_data));

	/* ECDSA: u1 = (hash * s^−1) mod n, u2 = (r * s^−1) mod n */
	/* GOST: u1 = (hash^−1 * s) mod n, u2 = -(hash^−1 * r) mod n */
	/* calc... */
	switch (curve->algo) {
	case EC_CURVE_ALGO_ECDSA:
		/* u2 = (s)^−1 mod n */
		BN_RET_ON_ERR(bn_assign(&u2, sign_s));
		BN_RET_ON_ERR(bn_mod_inv(&u2, &curve->n,
		    &curve->n_mod_rd_data));
		/* u1 = (hash * s^−1) mod n */
		BN_RET_ON_ERR(bn_mod_mult(&u1, &u2, &curve->n,
		    &curve->n_mod_rd_data));
		/* u2 = (r * s^−1) mod n */
		BN_RET_ON_ERR(bn_mod_mult(&u2, sign_r, &curve->n,
		    &curve->n_mod_rd_data));
		break;
	case EC_CURVE_ALGO_GOST20XX:
		if (0 != bn_is_zero(&u1)) { /* GOST step 2: if e == 0 then e = 1. */
			BN_RET_ON_ERR(bn_assign_digit(&u1, 1));
		}
		BN_RET_ON_ERR(bn_mod_inv(&u1, &curve->n,
		    &curve->n_mod_rd_data));
		/* u2 = -(hash^−1 * r) */
		BN_RET_ON_ERR(bn_assign(&u2, &curve->n));
		BN_RET_ON_ERR(bn_mod_sub(&u2, &u1, &curve->n,
		    &curve->n_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_mult(&u2, sign_r, &curve->n,
		    &curve->n_mod_rd_data));
		/* u1 = (hash^−1 * s) */
		BN_RET_ON_ERR(bn_mod_mult(&u1, sign_s, &curve->n,
		    &curve->n_mod_rd_data));
		break;
	default:
		return (EINVAL);
	}
	/* R = (Rx, Ry) = (u1 + u2 * d) * G */
	BN_RET_ON_ERR(bn_mod_mult(&u2, priv_key, &curve->n,
	    &curve->n_mod_rd_data));
	BN_RET_ON_ERR(bn_mod_add(&u2, &u1, &curve->n,
	    &curve->n_mod_rd_data));
	ec_point_mult_bp(&u2, curve, &R);
	if (0 != R.infinity)
		return (-2);
	/* v = Rx mod n */
	BN_RET_ON_ERR(bn_assign(&u1, &R.x));
	BN_RET_ON_ERR(bn_mod(&u1, &curve->n, &curve->n_mod_rd_data));
	if (0 != bn_cmp(&u1, sign_r))
		return (-2);
	return (0);
}
/* 
 * Input:
 *  curve - EC domain parameters
 *  hash - point to hash of message
 *  hash_size - hash size
 *  sign_r - signature r data
 *  sign_s - signature s data
 *  sign_size - signature size
 *  priv_key - private key data
 *  priv_key_size - private key size
 * Output:
 * - none
 * Return: 0 on no error, -1 if some algorim error, >0 on other error.
 */
static inline int
ecdsa_verify_priv_key_be(ec_curve_p curve,
    uint8_t *hash, size_t hash_size, 
    uint8_t *sign_r, uint8_t *sign_s, size_t sign_size,
    uint8_t *priv_key, size_t priv_key_size) {
	size_t bits, bytes;
	bn_t e, r, s, d;

	if (NULL == curve || NULL == hash || 0 == hash_size || 
	    NULL == sign_r || NULL == sign_s || 0 == sign_size ||
	    NULL == priv_key || 0 == priv_key_size)
		return (EINVAL);
	/* Calc bytes count for numbers. */
	bytes = EC_CURVE_CALC_BYTES(curve);
	if (sign_size > bytes)
		return (EINVAL);
	/* Double size + 1 digit. */
	bits = EC_CURVE_CALC_BITS_DBL(curve);
	/* Init */
	BN_RET_ON_ERR(bn_init(&e, bits));
	BN_RET_ON_ERR(bn_init(&r, bits));
	BN_RET_ON_ERR(bn_init(&s, bits));
	BN_RET_ON_ERR(bn_init(&d, bits));
	/* Import Hash. */
	BN_RET_ON_ERR(bn_import_be_bin(&e, hash, min(hash_size, bytes)));
	/* Import r.*/
	BN_RET_ON_ERR(bn_import_be_bin(&r, sign_r, sign_size));
	/* Import s.*/
	BN_RET_ON_ERR(bn_import_be_bin(&s, sign_s, sign_size));
	/* Key import. */
	BN_RET_ON_ERR(bn_import_be_bin(&d, priv_key, priv_key_size));
	/* Verify. */
	BN_RET_ON_ERR(ecdsa_verify_priv_key(curve, &e, &r, &s, &d));
	return (0);
}
static inline int
ecdsa_verify_priv_key_le(ec_curve_p curve,
    uint8_t *hash, size_t hash_size, 
    uint8_t *sign_r, uint8_t *sign_s, size_t sign_size,
    uint8_t *priv_key, size_t priv_key_size) {
	size_t bits, bytes;
	bn_t e, r, s, d;

	if (NULL == curve || NULL == hash || 0 == hash_size || 
	    NULL == sign_r || NULL == sign_s || 0 == sign_size ||
	    NULL == priv_key || 0 == priv_key_size)
		return (EINVAL);
	/* Calc bytes count for numbers. */
	bytes = EC_CURVE_CALC_BYTES(curve);
	if (sign_size > bytes)
		return (EINVAL);
	/* Double size + 1 digit. */
	bits = EC_CURVE_CALC_BITS_DBL(curve);
	/* Init */
	BN_RET_ON_ERR(bn_init(&e, bits));
	BN_RET_ON_ERR(bn_init(&r, bits));
	BN_RET_ON_ERR(bn_init(&s, bits));
	BN_RET_ON_ERR(bn_init(&d, bits));
	/* Import Hash. */
	BN_RET_ON_ERR(bn_import_le_bin(&e, hash, min(hash_size, bytes)));
	/* Import r.*/
	BN_RET_ON_ERR(bn_import_le_bin(&r, sign_r, sign_size));
	/* Import s.*/
	BN_RET_ON_ERR(bn_import_le_bin(&s, sign_s, sign_size));
	/* Key import. */
	BN_RET_ON_ERR(bn_import_le_bin(&d, priv_key, priv_key_size));
	/* Verify. */
	BN_RET_ON_ERR(ecdsa_verify_priv_key(curve, &e, &r, &s, &d));
	return (0);
}

/* Elliptic Curve Diffie-Hellman Primitive */
/* Input: private key from BOB and public key from ALICE! */
/* Output: shared shared secret for Bob and Alice. */
/* 
 * Input:
 *  curve - EC domain parameters
 *  use_cofactor - use cofactor h in calculations
 *  pub_key - pub key (Q) (Alice)
 *  priv_key - private key (d) (Bob)
 * Output:
 *  shared_key - shared secret key (can point to priv_key)
 * Return: 0 on no error, -1 if some algorim error, >0 on other error.
 */
static inline int
ecdsa_dh(ec_curve_p curve, int use_cofactor, ec_point_p pub_key,
    bn_p priv_key, bn_p shared_key) {
	ec_point_t Q;

	if (NULL == curve || NULL == pub_key || NULL == priv_key ||
	    NULL == shared_key)
		return (EINVAL);
	if (bn_cmp(priv_key, &curve->n) >= 0) /* Key check. */
		return (EINVAL);
	/* Init */
	BN_RET_ON_ERR(ec_point_init(&Q, curve->m));
	BN_RET_ON_ERR(ec_point_assign(&Q, pub_key));
	BN_RET_ON_ERR(bn_assign(shared_key, priv_key)); /* Use as temp. */
	/* P = (Px, Py) = h * d * Q */
	if (0 != use_cofactor) {
		BN_RET_ON_ERR(bn_mod_mult_digit(shared_key, curve->h,
		    &curve->n, &curve->n_mod_rd_data));
	}
	BN_RET_ON_ERR(ec_point_unknown_pt_mult(&Q, shared_key, curve));
	if (0 != Q.infinity)
		return (-1);
	BN_RET_ON_ERR(bn_assign(shared_key, &Q.x));
	return (0);
}
/* 
 * Input:
 *  curve - EC domain parameters
 *  use_cofactor - use cofactor h in calculations
 *  pub_key_x - compressed or packed pub key data
 *  pub_key_y - if != NULL and compress = 0 then it reveice Y of pub key data
 *  pub_key_size - pub key size
 *  priv_key - private key data
 *  priv_key_size - private key size
 * Output:
 *  shared_key - shared secret key data
 *  shared_size - shared secret key size
 * Return: 0 on no error, -1 if some algorim error, >0 on other error.
 */
static inline int
ecdsa_dh_be(ec_curve_p curve, int use_cofactor,
    uint8_t *pub_key_x, uint8_t *pub_key_y, size_t pub_key_size,
    uint8_t *priv_key, size_t priv_key_size, 
    uint8_t *shared_key, size_t *shared_size) {
	size_t bits, bytes;
	bn_t d;
	ec_point_t Q;

	if (NULL == curve ||
	    NULL == pub_key_x || 0 == pub_key_size ||
	    NULL == priv_key || 0 == priv_key_size ||
	    NULL == shared_key)
		return (EINVAL);
	/* Calc bytes count for numbers. */
	bytes = EC_CURVE_CALC_BYTES(curve);
	if (priv_key_size > bytes)
		return (EINVAL); /* Private key too long. */
	/* Double size + 1 digit. */
	bits = EC_CURVE_CALC_BITS_DBL(curve);
	/* Init */
	BN_RET_ON_ERR(bn_init(&d, bits));
	BN_RET_ON_ERR(ec_point_init(&Q, curve->m));
	/* Import Q.*/
	BN_RET_ON_ERR(ecdsa_pub_key_import_be(curve, pub_key_x,
	    pub_key_y, pub_key_size, &Q));
	/* Key import. */
	BN_RET_ON_ERR(bn_import_be_bin(&d, priv_key, priv_key_size));
	/* Get Shared Key. */
	BN_RET_ON_ERR(ecdsa_dh(curve, use_cofactor, &Q, &d, &d));
	/* Export result. */
	BN_RET_ON_ERR(bn_export_be_bin(&d, 0, shared_key, bytes, NULL));
	if (NULL != shared_size) {
		(*shared_size) = bytes;
	}
	return (0);
}
static inline int
ecdsa_dh_le(ec_curve_p curve, int use_cofactor,
    uint8_t *pub_key_x, uint8_t *pub_key_y, size_t pub_key_size,
    uint8_t *priv_key, size_t priv_key_size, 
    uint8_t *shared_key, size_t *shared_size) {
	size_t bits, bytes;
	bn_t d;
	ec_point_t Q;

	if (NULL == curve ||
	    NULL == pub_key_x || 0 == pub_key_size ||
	    NULL == priv_key || 0 == priv_key_size ||
	    NULL == shared_key)
		return (EINVAL);
	/* Calc bytes count for numbers. */
	bytes = EC_CURVE_CALC_BYTES(curve);
	if (priv_key_size > bytes)
		return (EINVAL); /* Private key too long. */
	/* Double size + 1 digit. */
	bits = EC_CURVE_CALC_BITS_DBL(curve);
	/* Init */
	BN_RET_ON_ERR(bn_init(&d, bits));
	BN_RET_ON_ERR(ec_point_init(&Q, curve->m));
	/* Import Q.*/
	BN_RET_ON_ERR(ecdsa_pub_key_import_le(curve, pub_key_x,
	    pub_key_y, pub_key_size, &Q));
	/* Key import. */
	BN_RET_ON_ERR(bn_import_le_bin(&d, priv_key, priv_key_size));
	/* Get Shared Key. */
	BN_RET_ON_ERR(ecdsa_dh(curve, use_cofactor, &Q, &d, &d));
	/* Export result. */
	BN_RET_ON_ERR(bn_export_le_bin(&d, 0, shared_key, bytes, NULL));
	if (NULL != shared_size) {
		(*shared_size) = bytes;
	}
	return (0);
}

/* Public Key Recovery from ECDSA private key d and EC domain parameters */
/* 
 * Input:
 *  curve - EC domain parameters
 *  priv_key - private key data
 *  priv_key_size - private key size
 *  pub_key_compress - 0 - do not compress, != 0 compress pub key
 * Output:
 *  pub_key_x - compressed or packed pub key data
 *  pub_key_y - if != NULL and compress = 0 then it reveice Y of pub key data
 *  pub_key_size - pub key size
 * Return: 0 on no error, -1 if some algorim error, >0 on other error.
 */
static inline int
ecdsa_recover_pub_key_from_priv_key_be(ec_curve_p curve,
    uint8_t *priv_key, size_t priv_key_size,
    int pub_key_compress,
    uint8_t *pub_key_x, uint8_t *pub_key_y, size_t *pub_key_size) {
	size_t bits, bytes;
	bn_t d;
	ec_point_t Q;

	if (NULL == curve || NULL == priv_key || 0 == priv_key_size || 
	    NULL == pub_key_x)
		return (EINVAL);
	/* Calc bytes count for numbers. */
	bytes = EC_CURVE_CALC_BYTES(curve);
	if (priv_key_size > bytes)
		return (EINVAL); /* Private key too long. */
	/* Double size + 1 digit. */
	bits = EC_CURVE_CALC_BITS_DBL(curve);
	/* Init */
	BN_RET_ON_ERR(bn_init(&d, bits));
	BN_RET_ON_ERR(ec_point_init(&Q, bits));
	/* Key import. */
	BN_RET_ON_ERR(bn_import_be_bin(&d, priv_key, priv_key_size));
	if (bn_cmp(&d, &curve->n) >= 0) /* Key check. */
		return (EINVAL);
	/* Q = dG */
	ec_point_mult_bp(&d, curve, &Q);
	BN_RET_ON_ERR(ec_point_check_as_pub_key(&Q, curve));
	/* Export result. */
	BN_RET_ON_ERR(ecdsa_pub_key_export_be(curve, pub_key_compress,
	    &Q, pub_key_x, pub_key_y, pub_key_size));
	return (0);
}
static inline int
ecdsa_recover_pub_key_from_priv_key_le(ec_curve_p curve,
    uint8_t *priv_key, size_t priv_key_size,
    int pub_key_compress,
    uint8_t *pub_key_x, uint8_t *pub_key_y, size_t *pub_key_size) {
	size_t bits, bytes;
	bn_t d;
	ec_point_t Q;

	if (NULL == curve || NULL == priv_key || 0 == priv_key_size || 
	    NULL == pub_key_x)
		return (EINVAL);
	/* Calc bytes count for numbers. */
	bytes = EC_CURVE_CALC_BYTES(curve);
	if (priv_key_size > bytes)
		return (EINVAL); /* Private key too long. */
	/* Double size + 1 digit. */
	bits = EC_CURVE_CALC_BITS_DBL(curve);
	/* Init */
	BN_RET_ON_ERR(bn_init(&d, bits));
	BN_RET_ON_ERR(ec_point_init(&Q, bits));
	/* Key import. */
	BN_RET_ON_ERR(bn_import_le_bin(&d, priv_key, priv_key_size));
	if (bn_cmp(&d, &curve->n) >= 0) /* Key check. */
		return (EINVAL);
	/* Q = dG */
	ec_point_mult_bp(&d, curve, &Q);
	BN_RET_ON_ERR(ec_point_check_as_pub_key(&Q, curve));
	/* Export result. */
	BN_RET_ON_ERR(ecdsa_pub_key_export_le(curve, pub_key_compress,
	    &Q, pub_key_x, pub_key_y, pub_key_size));
	return (0);
}


#if 0
/* Public Key Recovery from ECDSA signature (r,s) and EC domain parameters */
/* 
 * Input:
 *  curve - EC domain parameters
 *  hash - point to hash of message
 *  hash_size - hash size
 *  sign_r - signature r data
 *  sign_s - signature s data
 *  sign_size - signature size
 *  pub_key_compress - 0 - do not compress, != 0 compress pub key
 * Output:
 *  pub_key_x - compressed or packed pub key data
 *  pub_key_y - if != NULL and compress = 0 then it reveice Y of pub key data
 *  pub_key_size - pub key size
 * Return: 0 on no error, -1 if some algorim error, >0 on other error.
 */
static inline int
ecdsa_recover_pub_key_from_sign_be(ec_curve_p curve,
    uint8_t *hash, size_t hash_size,
    uint8_t *sign_r, uint8_t *sign_s, size_t sign_size,
    int pub_key_compress,
    uint8_t *pub_key_x, uint8_t *pub_key_y, size_t *pub_key_size) {
	size_t bits, bytes, j, k;
	bn_t r, s, e, x;
	ec_point_t R, Q;

	if (NULL == curve || NULL == hash || 0 == hash_size || 
	    NULL == sign_r || NULL == sign_s || 0 == sign_size ||
	    NULL == pub_key_x)
		return (EINVAL);
	/* Calc bytes count for numbers. */
	bytes = EC_CURVE_CALC_BYTES(curve);
	if (sign_size > bytes)
		return (EINVAL);
	/* Double size + 1 digit. */
	bits = EC_CURVE_CALC_BITS_DBL(curve);

	/* Import r.*/
	BN_RET_ON_ERR(bn_init(&r, bits));
	BN_RET_ON_ERR(bn_import_be_bin(&r, sign_r, sign_size));
	if (bn_cmp(&r, &curve->n) >= 0) /* sign_r check. */
		return (EINVAL);
	/* Import s.*/
	BN_RET_ON_ERR(bn_init(&s, bits));
	BN_RET_ON_ERR(bn_import_be_bin(&s, sign_s, sign_size));
	if (bn_cmp(&s, &curve->n) >= 0) /* sign_s check. */
		return (EINVAL);
	/* HASH import. */
	BN_RET_ON_ERR(bn_init(&e, bits));
	BN_RET_ON_ERR(bn_import_be_bin(&e, hash, min(hash_size, bytes)));
	BN_RET_ON_ERR(bn_mod_reduce(&e, &curve->n, &curve->n_mod_rd_data));

	BN_RET_ON_ERR(bn_init(&x, bits));
	BN_RET_ON_ERR(ec_point_init(&R, curve->m));
	BN_RET_ON_ERR(ec_point_init(&Q, curve->m));
	for (j = 0; j <= curve->h; j ++) {
		/* x = r + jn */
		if (0 != j) {
			BN_RET_ON_ERR(bn_assign(&x, &curve->n));
			BN_RET_ON_ERR(bn_mod_mult_digit(&x, curve->h,
			    &curve->p, &curve->p_mod_rd_data));
			BN_RET_ON_ERR(bn_mod_add(&x, &r, &curve->n,
			    &curve->n_mod_rd_data));
			BN_RET_ON_ERR(bn_assign(&R.x, &x));
		} else {
			BN_RET_ON_ERR(bn_assign(&R.x, &r));
		}
		/* Restore y + check: Is nR != O ? */
		if (0 != ec_point_restore_y_by_x(0, &R, curve))
			continue;
		/* Is nR != O ? */
		if (0 != ec_point_check_scalar_mult(&R, curve))
			continue;
		for (k = 1; k <= 2; k ++) {
			/* Q = r(^−1) * (s*R − e*G) */
		
			/* R = −R */
		}
	}
	return (-1);
}
#endif




#ifdef EC_SELF_TEST


typedef struct elliptic_curve_test1_vectors_s {
	const char *curve_name;
	size_t	curve_name_size;
	size_t	hex_str_len;
	const char *Sx;
	const char *Sy;
	const char *Tx;
	const char *Ty;
	/* R = S + T */
	const char *Rx_add;
	const char *Ry_add;
	/* R = S − T */
	const char *Rx_sub;
	const char *Ry_sub;
	/* R = 2S */
	const char *Rx_dbl;
	const char *Ry_dbl;
	/* R = dS */
	const char *d;
	const char *Rx_mult;
	const char *Ry_mult;
	/* R = dS + eT */
	const char *e;
	const char *Rx_twin_mult;
	const char *Ry_twin_mult;
} ec_point_tst1v_t, *ec_point_tst1v_p;

static ec_point_tst1v_t ec_curve_tst1v[] = {
	/* From: Mathematical routines for the NIST prime elliptic curves. */
	{
		/*.curve_name =*/	"secp521r1",
		/*.curve_name_size =*/	9,
		/*.hex_str_len =*/	136,
		/*.Sx =*/		"000001d5c693f66c08ed03ad0f031f937443458f601fd098d3d0227b4bf62873af50740b0bb84aa157fc847bcf8dc16a8b2b8bfd8e2d0a7d39af04b089930ef6dad5c1b4",
		/*.Sy =*/		"00000144b7770963c63a39248865ff36b074151eac33549b224af5c8664c54012b818ed037b2b7c1a63ac89ebaa11e07db89fcee5b556e49764ee3fa66ea7ae61ac01823",
		/*.Tx =*/		"000000f411f2ac2eb971a267b80297ba67c322dba4bb21cec8b70073bf88fc1ca5fde3ba09e5df6d39acb2c0762c03d7bc224a3e197feaf760d6324006fe3be9a548c7d5",
		/*.Ty =*/		"000001fdf842769c707c93c630df6d02eff399a06f1b36fb9684f0b373ed064889629abb92b1ae328fdb45534268384943f0e9222afe03259b32274d35d1b9584c65e305",
		/*.Rx_add =*/		"000001264ae115ba9cbc2ee56e6f0059e24b52c8046321602c59a339cfb757c89a59c358a9a8e1f86d384b3f3b255ea3f73670c6dc9f45d46b6a196dc37bbe0f6b2dd9e9",
		/*.Ry_add =*/		"00000062a9c72b8f9f88a271690bfa017a6466c31b9cadc2fc544744aeb817072349cfddc5ad0e81b03f1897bd9c8c6efbdf68237dc3bb00445979fb373b20c9a967ac55",
		/*.Rx_sub =*/		"000001292cb58b1795ba477063fef7cd22e42c20f57ae94ceaad86e0d21ff22918b0dd3b076d63be253de24bc20c6da290fa54d83771a225deecf9149f79a8e614c3c4cd",
		/*.Ry_sub =*/		"000001695e3821e72c7cacaadcf62909cd83463a21c6d03393c527c643b36239c46af117ab7c7ad19a4c8cf0ae95ed51729885461aa2ce2700a6365bca3733d2920b2267",
		/*.Rx_dbl =*/		"0000012879442f2450c119e7119a5f738be1f1eba9e9d7c6cf41b325d9ce6d643106e9d61124a91a96bcf201305a9dee55fa79136dc700831e54c3ca4ff2646bd3c36bc6",
		/*.Ry_dbl =*/		"0000019864a8b8855c2479cbefe375ae553e2393271ed36fadfc4494fc0583f6bd03598896f39854abeae5f9a6515a021e2c0eef139e71de610143f53382f4104dccb543",
		/*.d =*/		"000001eb7f81785c9629f136a7e8f8c674957109735554111a2a866fa5a166699419bfa9936c78b62653964df0d6da940a695c7294d41b2d6600de6dfcf0edcfc89fdcb1",
		/*.Rx_mult =*/		"00000091b15d09d0ca0353f8f96b93cdb13497b0a4bb582ae9ebefa35eee61bf7b7d041b8ec34c6c00c0c0671c4ae063318fb75be87af4fe859608c95f0ab4774f8c95bb",
		/*.Ry_mult =*/		"00000130f8f8b5e1abb4dd94f6baaf654a2d5810411e77b7423965e0c7fd79ec1ae563c207bd255ee9828eb7a03fed565240d2cc80ddd2cecbb2eb50f0951f75ad87977f",
		/*.e =*/		"00000137e6b73d38f153c3a7575615812608f2bab3229c92e21c0d1c83cfad9261dbb17bb77a63682000031b9122c2f0cdab2af72314be95254de4291a8f85f7c70412e3",
		/*.Rx_twin_mult =*/	"0000009d3802642b3bea152beb9e05fba247790f7fc168072d363340133402f2585588dc1385d40ebcb8552f8db02b23d687cae46185b27528adb1bf9729716e4eba653d",
		/*.Ry_twin_mult =*/	"0000000fe44344e79da6f49d87c1063744e5957d9ac0a505bafa8281c9ce9ff25ad53f8da084a2deb0923e46501de5797850c61b229023dd9cf7fc7f04cd35ebb026d89d",
	}, {
		/*.curve_name =*/	"secp384r1",
		/*.curve_name_size =*/	9,
		/*.hex_str_len =*/	96,
		/*.Sx =*/		"fba203b81bbd23f2b3be971cc23997e1ae4d89e69cb6f92385dda82768ada415ebab4167459da98e62b1332d1e73cb0e",
		/*.Sy =*/		"5ffedbaefdeba603e7923e06cdb5d0c65b22301429293376d5c6944e3fa6259f162b4788de6987fd59aed5e4b5285e45",
		/*.Tx =*/		"aacc05202e7fda6fc73d82f0a66220527da8117ee8f8330ead7d20ee6f255f582d8bd38c5a7f2b40bcdb68ba13d81051",
		/*.Ty =*/		"84009a263fefba7c2c57cffa5db3634d286131afc0fca8d25afa22a7b5dce0d9470da89233cee178592f49b6fecb5092",
		/*.Rx_add =*/		"12dc5ce7acdfc5844d939f40b4df012e68f865b89c3213ba97090a247a2fc009075cf471cd2e85c489979b65ee0b5eed",
		/*.Ry_add =*/		"167312e58fe0c0afa248f2854e3cddcb557f983b3189b67f21eee01341e7e9fe67f6ee81b36988efa406945c8804a4b0",
		/*.Rx_sub =*/		"6afdaf8da8b11c984cf177e551cee542cda4ac2f25cd522d0cd710f88059c6565aef78f6b5ed6cc05a6666def2a2fb59",
		/*.Ry_sub =*/		"7bed0e158ae8cc70e847a60347ca1548c348decc6309f48b59bd5afc9a9b804e7f7876178cb5a7eb4f6940a9c73e8e5e",
		/*.Rx_dbl =*/		"2a2111b1e0aa8b2fc5a1975516bc4d58017ff96b25e1bdff3c229d5fac3bacc319dcbec29f9478f42dee597b4641504c",
		/*.Ry_dbl =*/		"fa2e3d9dc84db8954ce8085ef28d7184fddfd1344b4d4797343af9b5f9d837520b450f726443e4114bd4e5bdb2f65ddd",
		/*.d =*/		"a4ebcae5a665983493ab3e626085a24c104311a761b5a8fdac052ed1f111a5c44f76f45659d2d111a61b5fdd97583480",
		/*.Rx_mult =*/		"e4f77e7ffeb7f0958910e3a680d677a477191df166160ff7ef6bb5261f791aa7b45e3e653d151b95dad3d93ca0290ef2",
		/*.Ry_mult =*/		"ac7dee41d8c5f4a7d5836960a773cfc1376289d3373f8cf7417b0c6207ac32e913856612fc9ff2e357eb2ee05cf9667f",
		/*.e =*/		"afcf88119a3a76c87acbd6008e1349b29f4ba9aa0e12ce89bcfcae2180b38d81ab8cf15095301a182afbc6893e75385d",
		/*.Rx_twin_mult =*/	"917ea28bcd641741ae5d18c2f1bd917ba68d34f0f0577387dc81260462aea60e2417b8bdc5d954fc729d211db23a02dc",
		/*.Ry_twin_mult =*/	"1a29f7ce6d074654d77b40888c73e92546c8f16a5ff6bcbd307f758d4aee684beff26f6742f597e2585c86da908f7186",
	}, {
		/*.curve_name =*/	"secp256r1",
		/*.curve_name_size =*/	9,
		/*.hex_str_len =*/	64,
		/*.Sx =*/		"de2444bebc8d36e682edd27e0f271508617519b3221a8fa0b77cab3989da97c9",
		/*.Sy =*/		"c093ae7ff36e5380fc01a5aad1e66659702de80f53cec576b6350b243042a256",
		/*.Tx =*/		"55a8b00f8da1d44e62f6b3b25316212e39540dc861c89575bb8cf92e35e0986b",
		/*.Ty =*/		"5421c3209c2d6c704835d82ac4c3dd90f61a8a52598b9e7ab656e9d8c8b24316",
		/*.Rx_add =*/		"72b13dd4354b6b81745195e98cc5ba6970349191ac476bd4553cf35a545a067e",
		/*.Ry_add =*/		"8d585cbb2e1327d75241a8a122d7620dc33b13315aa5c9d46d013011744ac264",
		/*.Rx_sub =*/		"c09ce680b251bb1d2aad1dbf6129deab837419f8f1c73ea13e7dc64ad6be6021",
		/*.Ry_sub =*/		"1a815bf700bd88336b2f9bad4edab1723414a022fdf6c3f4ce30675fb1975ef3",
		/*.Rx_dbl =*/		"7669e6901606ee3ba1a8eef1e0024c33df6c22f3b17481b82a860ffcdb6127b0",
		/*.Ry_dbl =*/		"fa878162187a54f6c39f6ee0072f33de389ef3eecd03023de10ca2c1db61d0c7",
		/*.d =*/		"c51e4753afdec1e6b6c6a5b992f43f8dd0c7a8933072708b6522468b2ffb06fd",
		/*.Rx_mult =*/		"51d08d5f2d4278882946d88d83c97d11e62becc3cfc18bedacc89ba34eeca03f",
		/*.Ry_mult =*/		"75ee68eb8bf626aa5b673ab51f6e744e06f8fcf8a6c0cf3035beca956a7b41d5",
		/*.e =*/		"d37f628ece72a462f0145cbefe3f0b355ee8332d37acdd83a358016aea029db7",
		/*.Rx_twin_mult =*/	"d867b4679221009234939221b8046245efcf58413daacbeff857b8588341f6b8",
		/*.Ry_twin_mult =*/	"f2504055c03cede12d22720dad69c745106b6607ec7e50dd35d54bd80f615275",
	}, {
		/*.curve_name =*/	"secp224r1",
		/*.curve_name_size =*/	9,
		/*.hex_str_len =*/	56,
		/*.Sx =*/		"6eca814ba59a930843dc814edd6c97da95518df3c6fdf16e9a10bb5b",
		/*.Sy =*/		"ef4b497f0963bc8b6aec0ca0f259b89cd80994147e05dc6b64d7bf22",
		/*.Tx =*/		"b72b25aea5cb03fb88d7e842002969648e6ef23c5d39ac903826bd6d",
		/*.Ty =*/		"c42a8a4d34984f0b71b5b4091af7dceb33ea729c1a2dc8b434f10c34",
		/*.Rx_add =*/		"236f26d9e84c2f7d776b107bd478ee0a6d2bcfcaa2162afae8d2fd15",
		/*.Ry_add =*/		"e53cc0a7904ce6c3746f6a97471297a0b7d5cdf8d536ae25bb0fda70",
		/*.Rx_sub =*/		"db4112bcc8f34d4f0b36047bca1054f3615413852a7931335210b332",
		/*.Ry_sub =*/		"90c6e8304da4813878c1540b2396f411facf787a520a0ffb55a8d961",
		/*.Rx_dbl =*/		"a9c96f2117dee0f27ca56850ebb46efad8ee26852f165e29cb5cdfc7",
		/*.Ry_dbl =*/		"adf18c84cf77ced4d76d4930417d9579207840bf49bfbf5837dfdd7d",
		/*.d =*/		"a78ccc30eaca0fcc8e36b2dd6fbb03df06d37f52711e6363aaf1d73b",
		/*.Rx_mult =*/		"96a7625e92a8d72bff1113abdb95777e736a14c6fdaacc392702bca4",
		/*.Ry_mult =*/		"0f8e5702942a3c5e13cd2fd5801915258b43dfadc70d15dbada3ed10",
		/*.e =*/		"54d549ffc08c96592519d73e71e8e0703fc8177fa88aa77a6ed35736",
		/*.Rx_twin_mult =*/	"dbfe2958c7b2cda1302a67ea3ffd94c918c5b350ab838d52e288c83e",
		/*.Ry_twin_mult =*/	"2f521b83ac3b0549ff4895abcc7f0c5a861aacb87acbc5b8147bb18b",
	}, {
		/*.curve_name =*/	"secp192r1",
		/*.curve_name_size =*/	9,
		/*.hex_str_len =*/	48,
		/*.Sx =*/		"d458e7d127ae671b0c330266d246769353a012073e97acf8",
		/*.Sy =*/		"325930500d851f336bddc050cf7fb11b5673a1645086df3b",
		/*.Tx =*/		"f22c4395213e9ebe67ddecdd87fdbd01be16fb059b9753a4",
		/*.Ty =*/		"264424096af2b3597796db48f8dfb41fa9cecc97691a9c79",
		/*.Rx_add =*/		"48e1e4096b9b8e5ca9d0f1f077b8abf58e843894de4d0290",
		/*.Ry_add =*/		"408fa77c797cd7dbfb16aa48a3648d3d63c94117d7b6aa4b",
		/*.Rx_sub =*/		"fc9683cc5abfb4fe0cc8cc3bc9f61eabc4688f11e9f64a2e",
		/*.Ry_sub =*/		"093e31d00fb78269732b1bd2a73c23cdd31745d0523d816b",
		/*.Rx_dbl =*/		"30c5bc6b8c7da25354b373dc14dd8a0eba42d25a3f6e6962",
		/*.Ry_dbl =*/		"0dde14bc4249a721c407aedbf011e2ddbbcb2968c9d889cf",
		/*.d =*/		"a78a236d60baec0c5dd41b33a542463a8255391af64c74ee",
		/*.Rx_mult =*/		"1faee4205a4f669d2d0a8f25e3bcec9a62a6952965bf6d31",
		/*.Ry_mult =*/		"5ff2cdfa508a2581892367087c696f179e7a4d7e8260fb06",
		/*.e =*/		"c4be3d53ec3089e71e4de8ceab7cce889bc393cd85b972bc",
		/*.Rx_twin_mult =*/	"019f64eed8fa9b72b7dfea82c17c9bfa60ecb9e1778b5bde",
		/*.Ry_twin_mult =*/	"16590c5fcd8655fa4ced33fb800e2a7e3c61f35d83503644",
	}, {
		/*.curve_name =*/	NULL,
		/*.curve_name_size =*/	0,
		/*.hex_str_len =*/	0,
		/*.Sx =*/		NULL,
		/*.Sy =*/		NULL,
		/*.Tx =*/		NULL,
		/*.Ty =*/		NULL,
		/*.Rx_add =*/		NULL,
		/*.Ry_add =*/		NULL,
		/*.Rx_sub =*/		NULL,
		/*.Ry_sub =*/		NULL,
		/*.Rx_dbl =*/		NULL,
		/*.Ry_dbl =*/		NULL,
		/*.d =*/		NULL,
		/*.Rx_mult =*/		NULL,
		/*.Ry_mult =*/		NULL,
		/*.e =*/		NULL,
		/*.Rx_twin_mult =*/	NULL,
		/*.Ry_twin_mult =*/	NULL,
	}
};


typedef struct elliptic_curve_test2_vectors_s {
	const char *curve_name;
	size_t	curve_name_size;
	size_t	hex_str_len;
	const char *hash; /* Message hash */
	size_t	hash_str_len;
	const char *d; /* Private key. */
	const char *Qx; /* Public key. */
	const char *Qy;
	const char *k; /* Random */
	/* Sign */
	const char *r;
	const char *s;
} ec_point_tst2v_t, *ec_point_tst2v_p;

static ec_point_tst2v_t ec_curve_tst2v[] = {
	/* From: gostR3410-2001 */
	{
		/*.curve_name =*/	"id-gostR3410-2001-Test_ParamSet",
		/*.curve_name_size =*/	30,
		/*.hex_str_len =*/	64,
		/*.hash =*/		"2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5",
		/*.hash_str_len=*/	64,
		/*.d =*/		"7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28",
		/*.Qx =*/		"7f2b49e270db6d90d8595bec458b50c58585ba1d4e9b788f6689dbd8e56fd80b",
		/*.Qy =*/		"26f1b489d6701dd185c8413a977b3cbbaf64d1c593d26627dffb101a87ff77da",
		/*.k =*/		"77105c9b20bcd3122823c8cf6fcc7b956de33814e95b7fe64fed924594dceab3",
		/*.r =*/		"41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc0493",
		/*.s =*/		"01456c64ba4642a1653c235a98a60249bcd6d3f746b631df928014f6c5bf9c40",
	},
	/* From: X9.62-1998: J.3 Examples of ECDSA over the Field  F. */
	{
		/*.curve_name =*/	"secp192r1",
		/*.curve_name_size =*/	9,
		/*.hex_str_len =*/	48,
		/*.hash =*/		"a9993e364706816aba3e25717850c26c9cd0d89d",
		/*.hash_str_len=*/	40,
		/*.d =*/		"1a8d598fc15bf0fd89030b5cb1111aeb92ae8baf5ea475fb",
		/*.Qx =*/		"62b12d60690cdcf330babab6e69763b471f994dd702d16a5",
		/*.Qy =*/		"63bf5ec08069705ffff65e5ca5c0d69716dfcb3474373902",
		/*.k =*/		"fa6de29746bbeb7f8bb1e761f85f7dfb2983169d82fa2f4e",
		/*.r =*/		"885052380ff147b734c330c43d39b2c4a89f29b0f749fead",
		/*.s =*/		"e9ecc78106def82bf1070cf1d4d804c3cb390046951df686",
	}, {
		/*.curve_name =*/	NULL,
		/*.curve_name_size =*/	0,
		/*.hex_str_len =*/	0,
		/*.hash =*/		NULL,
		/*.hash_str_len=*/	0,
		/*.d =*/		NULL,
		/*.Qx =*/		NULL,
		/*.Qy =*/		NULL,
		/*.k =*/		NULL,
		/*.r =*/		NULL,
		/*.s =*/		NULL,
	}
};


static inline int
ec_self_test(void) {
	size_t i, bits, rsize, priv_key_size, pub_key_size;
	bn_t d, e, tm;
	ec_point_t S, T, R, TM;
	ec_curve_t curve;
	uint8_t r[512], s[512];

	/* Calculations check. */
	for (i = 0; NULL != ec_curve_tst1v[i].curve_name; i ++) {
		/* Assign values. */
		BN_RET_ON_ERR(ecdsa_curve_from_str(
		    ecdsa_curve_str_get_by_name(ec_curve_tst1v[i].curve_name, ec_curve_tst1v[i].curve_name_size),
		    &curve));
		/* Assign values. */
		/* Double size + 1 digit. */
		bits = EC_CURVE_CALC_BITS_DBL(&curve);
		BN_RET_ON_ERR(bn_init(&d, bits));
		BN_RET_ON_ERR(bn_init(&e, bits));
		BN_RET_ON_ERR(ec_point_init(&S, bits));
		BN_RET_ON_ERR(ec_point_init(&T, bits));
		BN_RET_ON_ERR(ec_point_init(&R, bits));
		BN_RET_ON_ERR(ec_point_init(&TM, bits));

		/* Assign values. */
		BN_RET_ON_ERR(bn_import_be_hex(&d, (const uint8_t*)ec_curve_tst1v[i].d,
		    ec_curve_tst1v[i].hex_str_len));
		BN_RET_ON_ERR(bn_import_be_hex(&e, (const uint8_t*)ec_curve_tst1v[i].e,
		    ec_curve_tst1v[i].hex_str_len));
		BN_RET_ON_ERR(bn_import_be_hex(&S.x, (const uint8_t*)ec_curve_tst1v[i].Sx,
		    ec_curve_tst1v[i].hex_str_len));
		BN_RET_ON_ERR(bn_import_be_hex(&S.y, (const uint8_t*)ec_curve_tst1v[i].Sy,
		    ec_curve_tst1v[i].hex_str_len));
		BN_RET_ON_ERR(bn_import_be_hex(&T.x, (const uint8_t*)ec_curve_tst1v[i].Tx,
		    ec_curve_tst1v[i].hex_str_len));
		BN_RET_ON_ERR(bn_import_be_hex(&T.y, (const uint8_t*)ec_curve_tst1v[i].Ty,
		    ec_curve_tst1v[i].hex_str_len));

		/* R = S + T */
		BN_RET_ON_ERR(ec_point_assign(&TM, &S));
		BN_RET_ON_ERR(ec_point_add(&TM, &T, &curve));
		BN_RET_ON_ERR(bn_import_be_hex(&R.x, (const uint8_t*)ec_curve_tst1v[i].Rx_add,
		    ec_curve_tst1v[i].hex_str_len));
		BN_RET_ON_ERR(bn_import_be_hex(&R.y, (const uint8_t*)ec_curve_tst1v[i].Ry_add,
		    ec_curve_tst1v[i].hex_str_len));
		if (0 == ec_point_is_eq(&TM, &R))
			return (-1);
		/* R = S − T */
		BN_RET_ON_ERR(ec_point_assign(&TM, &S));
		BN_RET_ON_ERR(ec_point_sub(&TM, &T, &curve));
		BN_RET_ON_ERR(bn_import_be_hex(&R.x, (const uint8_t*)ec_curve_tst1v[i].Rx_sub,
		    ec_curve_tst1v[i].hex_str_len));
		BN_RET_ON_ERR(bn_import_be_hex(&R.y, (const uint8_t*)ec_curve_tst1v[i].Ry_sub,
		    ec_curve_tst1v[i].hex_str_len));
		if (0 == ec_point_is_eq(&TM, &R))
			return (-1);
		/* R = 2S */
		BN_RET_ON_ERR(ec_point_assign(&TM, &S));
		BN_RET_ON_ERR(ec_point_add(&TM, &TM, &curve));
		BN_RET_ON_ERR(bn_import_be_hex(&R.x, (const uint8_t*)ec_curve_tst1v[i].Rx_dbl,
		    ec_curve_tst1v[i].hex_str_len));
		BN_RET_ON_ERR(bn_import_be_hex(&R.y, (const uint8_t*)ec_curve_tst1v[i].Ry_dbl,
		    ec_curve_tst1v[i].hex_str_len));
		if (0 == ec_point_is_eq(&TM, &R))
			return (-1);
		/* R = dS */
		BN_RET_ON_ERR(ec_point_assign(&TM, &S));
		BN_RET_ON_ERR(ec_point_unknown_pt_mult(&TM, &d, &curve));
		BN_RET_ON_ERR(bn_import_be_hex(&R.x, (const uint8_t*)ec_curve_tst1v[i].Rx_mult,
		    ec_curve_tst1v[i].hex_str_len));
		BN_RET_ON_ERR(bn_import_be_hex(&R.y, (const uint8_t*)ec_curve_tst1v[i].Ry_mult,
		    ec_curve_tst1v[i].hex_str_len));
		if (0 == ec_point_is_eq(&TM, &R))
			return (-1);
		/* R = dS + eT */
		BN_RET_ON_ERR(ec_point_twin_mult(&S, &d, &T, &e, &curve, &TM));
		BN_RET_ON_ERR(bn_import_be_hex(&R.x, (const uint8_t*)ec_curve_tst1v[i].Rx_twin_mult,
		    ec_curve_tst1v[i].hex_str_len));
		BN_RET_ON_ERR(bn_import_be_hex(&R.y, (const uint8_t*)ec_curve_tst1v[i].Ry_twin_mult,
		    ec_curve_tst1v[i].hex_str_len));
		if (0 == ec_point_is_eq(&TM, &R))
			return (-1);
	}

	/* Calculations check 2. */
	for (i = 0; NULL != ec_curve_tst2v[i].curve_name; i ++) {
		/* Assign values. */
		BN_RET_ON_ERR(ecdsa_curve_from_str(
		    ecdsa_curve_str_get_by_name(ec_curve_tst2v[i].curve_name, ec_curve_tst2v[i].curve_name_size),
		    &curve));
		/* Assign values. */
		/* Double size + 1 digit. */
		bits = EC_CURVE_CALC_BITS_DBL(&curve);
		BN_RET_ON_ERR(bn_init(&d, bits));
		BN_RET_ON_ERR(bn_init(&e, bits));
		BN_RET_ON_ERR(bn_init(&tm, bits));
		BN_RET_ON_ERR(ec_point_init(&S, bits));
		BN_RET_ON_ERR(ec_point_init(&T, bits));
		BN_RET_ON_ERR(ec_point_init(&TM, bits));

		/* Assign values. */
		BN_RET_ON_ERR(bn_import_le_hex(&d, (const uint8_t*)ec_curve_tst2v[i].d,
		    ec_curve_tst2v[i].hex_str_len)); /* Private key. */
		BN_RET_ON_ERR(bn_import_le_hex(&e, (const uint8_t*)ec_curve_tst2v[i].hash,
		    ec_curve_tst2v[i].hash_str_len)); /* Message hash */
		BN_RET_ON_ERR(bn_import_le_hex(&tm, (const uint8_t*)ec_curve_tst2v[i].k,
		    ec_curve_tst2v[i].hex_str_len)); /* Random */
		BN_RET_ON_ERR(bn_import_le_hex(&S.x, (const uint8_t*)ec_curve_tst2v[i].Qx,
		    ec_curve_tst2v[i].hex_str_len)); /* Public key. */
		BN_RET_ON_ERR(bn_import_le_hex(&S.y, (const uint8_t*)ec_curve_tst2v[i].Qy,
		    ec_curve_tst2v[i].hex_str_len)); /* Public key. */
		BN_RET_ON_ERR(bn_import_le_hex(&T.x, (const uint8_t*)ec_curve_tst2v[i].r,
		    ec_curve_tst2v[i].hex_str_len)); /* Sign */
		BN_RET_ON_ERR(bn_import_le_hex(&T.y, (const uint8_t*)ec_curve_tst2v[i].s,
		    ec_curve_tst2v[i].hex_str_len)); /* Sign */

		/* Sign. */
		BN_RET_ON_ERR(ecdsa_sign_be(&curve, (uint8_t*)e.num, (ec_curve_tst2v[i].hash_str_len / 2),
		    (uint8_t*)d.num, (ec_curve_tst2v[i].hex_str_len / 2),
		    (uint8_t*)tm.num, (ec_curve_tst2v[i].hex_str_len / 2), (uint8_t*)r, (uint8_t*)s, &rsize));
		    
		BN_RET_ON_ERR(bn_import_le_bin(&TM.x, r, rsize));
		BN_RET_ON_ERR(bn_import_le_bin(&TM.y, s, rsize));
		if (0 == ec_point_is_eq(&T, &TM))
			return (-1);
		/* Verify using pub key. */
		BN_RET_ON_ERR(ecdsa_verify_be(&curve, (uint8_t*)e.num, (ec_curve_tst2v[i].hash_str_len / 2),
		    (uint8_t*)r, (uint8_t*)s, rsize,
		    (uint8_t*)&S.x.num, (uint8_t*)&S.y.num, (ec_curve_tst2v[i].hex_str_len / 2)));
	}


	/* Check: curve params, key gen, sign and verify. */
	/*  SHA-1("abc") = "a9993e364706816aba3e25717850c26c9cd0d89d" */
	uint8_t hash_abc[20] = {0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d};
	//uint8_t hash_abc[24] = {0, 0, 0, 0, 0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d};

	/* "random" for keys */
	BN_RET_ON_ERR(bn_init(&tm, 560));
	BN_RET_ON_ERR(bn_import_le_hex(&tm,
	    (const uint8_t*)"fc15bf0fd89030b5cb11fa6de29746bbeb7f8bb1e761f85f7dfb2983169d82fa2f4e1a8d598fc15bf0fd89030b5cb1111aeb92ae8baf5ea475fb", 140));

	for (i = 0; NULL != ec_curve_str[i].name; i ++) {
		BN_RET_ON_ERR(ecdsa_curve_from_str(&ec_curve_str[i], &curve));
		BN_RET_ON_ERR(ec_curve_validate(&curve, NULL));

		bits = EC_CURVE_CALC_BITS_DBL(&curve);
		BN_RET_ON_ERR(bn_init(&d, bits));
		BN_RET_ON_ERR(bn_init(&e, bits));
		BN_RET_ON_ERR(ec_point_init(&TM, bits));
		/* 'rand' for sign */
		BN_RET_ON_ERR(bn_assign(&e, &curve.p));
		BN_RET_ON_ERR(bn_xor(&e, &curve.b));
		BN_RET_ON_ERR(bn_xor(&e, &curve.n));
		
		/* Generating keys. */
		BN_RET_ON_ERR(ecdsa_key_gen_be(&curve, (uint8_t*)tm.num, 70, 1/* compress */,
		    (uint8_t*)d.num, &priv_key_size,
		    (uint8_t*)&TM.x.num, (uint8_t*)&TM.y.num, &pub_key_size));
		/* Sign. */
		rsize = priv_key_size;
		BN_RET_ON_ERR(ecdsa_sign_be(&curve, (uint8_t*)hash_abc, 20,
		    (uint8_t*)d.num, priv_key_size,
		    (uint8_t*)e.num, rsize, (uint8_t*)r, (uint8_t*)s, &rsize));
		/* Verify using pub key. */
		BN_RET_ON_ERR(ecdsa_verify_be(&curve, (uint8_t*)hash_abc, 20,
		    (uint8_t*)r, (uint8_t*)s, rsize,
		    (uint8_t*)&TM.x.num, (uint8_t*)&TM.y.num, pub_key_size));
		/* Verify using priv key. */
		BN_RET_ON_ERR(ecdsa_verify_priv_key_be(&curve,
		    (uint8_t*)hash_abc, 20, (uint8_t*)r, (uint8_t*)s, rsize,
		    (uint8_t*)d.num, priv_key_size));
	}

	return (0);
}
#endif /* self test */


#endif /* __ECDSA_H__ */
