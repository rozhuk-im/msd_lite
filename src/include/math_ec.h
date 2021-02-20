/*-
 * Copyright (c) 2013 - 2014 Rozhuk Ivan <rozhuk.im@gmail.com>
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

#ifndef __MATH_EC_H__
#define __MATH_EC_H__

#ifdef _WINDOWS
#	define EINVAL		ERROR_INVALID_PARAMETER
#else
#	include <sys/types.h>
#	include <inttypes.h>
#endif

#include "math_bn.h"



#define EC_CURVE_CALC_BYTES(curve) (((curve)->m + 7) / 8)
/* Double size + 1 digit. */
#define EC_CURVE_CALC_BITS_DBL(curve)	(BN_DIGIT_BITS + (2 * (curve)->m))


#ifndef EC_USE_PROJECTIVE /* Affine point calculations.  */

#	define ec_point_add(a, b, curve)					\
		ec_point_affine_add((a), (b), (curve))
#	define ec_point_sub(a, b, curve)					\
		ec_point_affine_sub((a), (b), (curve))

#	define ec_point_bin_mult(point, d, curve)				\
		ec_point_affine_bin_mult((point), (d), (curve))

#	define ec_pt_fpx_mult_data_t	ec_point_fpx_mult_data_t
#	define ec_point_fpx_mult_precompute(wbits, point, curve, mult_data)	\
		ec_point_affine_fpx_mult_precompute((wbits), (point), (curve), (mult_data))
#	define ec_point_fpx_mult(point, mult_data, d, curve)			\
		ec_point_affine_fpx_mult((point), (mult_data), (d), (curve))

#	define ec_pt_unkpt_mult_data_t	ec_point_unkpt_mult_data_t
#	define ec_point_unkpt_mult_precompute(wbits, point, curve, mult_data)	\
		ec_point_affine_unkpt_mult_precompute((wbits), (point), (curve), (mult_data))
#	define ec_point_unkpt_mult(point, mult_data, d, curve)			\
		ec_point_affine_unkpt_mult((point), (mult_data), (d), (curve))

#	define ec_point_twin_mult(a, ad, b, bd, curve, res)			\
		ec_point_affine_twin_mult((a), (ad), (b), (bd), (curve), (res))
#	define ec_point_fpx_unkpt_twin_mult_bp(Gd, b, bd, curve, res)		\
		ec_point_affine_fpx_unkpt_twin_mult_bp((Gd), (b), (bd), (curve), (res))

#else /* Projective point calculations.  */

#	define ec_point_add(a, b, curve)					\
		ec_point_proj_add_affine((a), (b), (curve))
#	define ec_point_sub(a, b, curve)					\
		ec_point_proj_sub_affine((a), (b), (curve))

#	define ec_point_bin_mult(point, d, curve)				\
		ec_point_proj_bin_mult_affine((point), (d), (curve))

#	define ec_pt_fpx_mult_data_t	ec_point_proj_fpx_mult_data_t
#	define ec_point_fpx_mult_precompute(wbits, point, curve, mult_data)	\
		ec_point_proj_fpx_mult_precompute_affine((wbits), (point), (curve), (mult_data))
#	define ec_point_fpx_mult(point, mult_data, d, curve)			\
		ec_point_proj_fpx_mult_affine((point), (mult_data), (d), (curve))

#	define ec_pt_unkpt_mult_data_t	ec_point_proj_unkpt_mult_data_t
#	define ec_point_unkpt_mult_precompute(wbits, point, curve, mult_data)	\
		ec_point_proj_unkpt_mult_precompute_affine((wbits), (point), (curve), (mult_data))
#	define ec_point_unkpt_mult(point, mult_data, d, curve)			\
		ec_point_proj_unkpt_mult_affine((point), (mult_data), (d), (curve))

#	define ec_point_twin_mult(a, ad, b, bd, curve, res)			\
		ec_point_proj_twin_mult((a), (ad), (b), (bd), (curve), (res))
#	define ec_point_fpx_unkpt_twin_mult_bp(Gd, b, bd, curve, res)		\
		ec_point_proj_fpx_unkpt_twin_mult_bp_affine((Gd), (b), (bd), (curve), (res))

#endif /* EC_USE_AFFINE */

#ifdef EC_PROJ_ADD_MIX
#	define ec_pt_proj_am_t			ec_point_t
#	define ec_pt_proj_am_is_at_infinity	ec_point_is_at_infinity
#else
#	define ec_pt_proj_am_t			ec_point_proj_t
#	define ec_pt_proj_am_is_at_infinity	ec_point_proj_is_at_infinity
#endif /* EC_PROJ_ADD_MIX */


#ifdef EC_DISABLE_PUB_KEY_CHK
#	define ec_point_check_as_pub_key__int(point, curve)	0 /* OK, no error. */
#else
#	define ec_point_check_as_pub_key__int(point, curve)			\
		ec_point_check_as_pub_key((point), (curve))
#endif


typedef struct elliptic_curve_point_s {
	bn_t	x;
	bn_t	y;
	int	infinity;
} ec_point_t, *ec_point_p;

typedef struct elliptic_curve_point_projective_s {
	bn_t	x;
	bn_t	y;
	bn_t	z;
} ec_point_proj_t, *ec_point_proj_p;



/* Prime field Fixed Point multiplication algo. */
/* Avaible types for EC_PF_FXP_MULT_ALGO:
 * EC_PF_FXP_MULT_ALGO_BIN - binary multiplication
 *
 * EC_PF_FXP_MULT_ALGO_BIN_PRECALC_DBL - binary with precalculated doubles:
 * fast but requires mutch mem
 * additional option: EC_PF_FXP_MULT_PRECALC_DBL_SIZE - must be max curve bits
 *
 * EC_PF_FXP_MULT_ALGO_SLIDING_WIN - sliding window multiplication
 * additional option: EC_PF_FXP_MULT_WIN_BITS - must be power of 2
 *
 * EC_PF_FXP_MULT_ALGO_COMB_1T - [1]:Algorithm 3.44 comb method for point
 * multiplication with 1 table
 * additional option: EC_PF_FXP_MULT_WIN_BITS
 *
 * EC_PF_FXP_MULT_ALGO_COMB_2T - [1]:Algorithm 3.45 comb method for point
 * multiplication with 2 tables
 * additional option: EC_PF_FXP_MULT_WIN_BITS
 */

#define EC_PF_FXP_MULT_ALGO_BIN			0
#define EC_PF_FXP_MULT_ALGO_BIN_PRECALC_DBL	1
#define EC_PF_FXP_MULT_ALGO_SLIDING_WIN		2
#define EC_PF_FXP_MULT_ALGO_COMB_1T		3
#define EC_PF_FXP_MULT_ALGO_COMB_2T		4
#define EC_PF_FXP_MULT_ALGO_MAX			EC_PF_FXP_MULT_ALGO_COMB_2T

/* Default EC_PF_FXP_MULT_ALGO */
#if !defined(EC_PF_FXP_MULT_ALGO) ||						\
    (EC_PF_FXP_MULT_ALGO != EC_PF_FXP_MULT_ALGO_BIN &&				\
    EC_PF_FXP_MULT_ALGO != EC_PF_FXP_MULT_ALGO_BIN_PRECALC_DBL &&		\
    EC_PF_FXP_MULT_ALGO != EC_PF_FXP_MULT_ALGO_SLIDING_WIN &&			\
    EC_PF_FXP_MULT_ALGO != EC_PF_FXP_MULT_ALGO_COMB_1T &&			\
    EC_PF_FXP_MULT_ALGO != EC_PF_FXP_MULT_ALGO_COMB_2T)
#	undef EC_PF_FXP_MULT_ALGO
#	define EC_PF_FXP_MULT_ALGO	EC_PF_FXP_MULT_ALGO_COMB_2T
#endif


/* Precalculated doubled points. */
/* Default count precalculated doubled points. */
#ifndef EC_PF_FXP_MULT_PRECALC_DBL_SIZE
#	define EC_PF_FXP_MULT_PRECALC_DBL_SIZE	528 /* Curve max bits */
#endif

typedef struct elliptic_curve_pf_fpx_pre_dbl_mult_data_s {
	ec_point_t	pt_arr[EC_PF_FXP_MULT_PRECALC_DBL_SIZE];
} ec_point_fpx_pre_dbl_mult_data_t, *ec_point_fpx_pre_dbl_mult_data_p;

typedef struct elliptic_curve_proj_pf_fpx_pre_dbl_mult_data_s {
	ec_pt_proj_am_t	pt_arr[EC_PF_FXP_MULT_PRECALC_DBL_SIZE];
} ec_point_proj_fpx_pre_dbl_mult_data_t, *ec_point_proj_fpx_pre_dbl_mult_data_p;


/* Sliding window. */
/* Default size of sliding window, must be power of 2 or any for COMB. */
#ifndef EC_PF_FXP_MULT_WIN_BITS
#	define EC_PF_FXP_MULT_WIN_BITS	8
#endif
/* Number of points for precomputed points. */
#define EC_PF_FXP_MULT_NUM_POINTS ((((size_t)1) << EC_PF_FXP_MULT_WIN_BITS) - 1)


typedef struct elliptic_curve_pf_fpx_sl_win_mult_data_s {
	size_t		wnd_bits; /* Window bits count. */
	ec_point_t	pt_arr[EC_PF_FXP_MULT_NUM_POINTS];
} ec_point_fpx_sl_win_mult_data_t, *ec_point_fpx_sl_win_mult_data_p;

typedef struct elliptic_curve_proj_pf_fpx_sl_win_mult_data_s {
	size_t		wnd_bits; /* Window bits count. */
	ec_pt_proj_am_t	pt_arr[EC_PF_FXP_MULT_NUM_POINTS];
} ec_point_proj_fpx_sl_win_mult_data_t, *ec_point_proj_fpx_sl_win_mult_data_p;


/* COMB 1t. */
typedef struct elliptic_curve_pf_fpx_comb1t_mult_data_s {
	size_t		wnd_bits; /* Window bits count. */
	size_t		wnd_count; /* Num of blocks EC_PF_FXP_MULT_WIN_BITS size. */
	ec_point_t	pt_add_arr[EC_PF_FXP_MULT_NUM_POINTS];
} ec_point_fpx_comb1t_mult_data_t, *ec_point_fpx_comb1t_mult_data_p;

typedef struct elliptic_curve_proj_pf_fpx_comb1t_mult_data_s {
	size_t		wnd_bits; /* Window bits count. */
	size_t		wnd_count;
	ec_pt_proj_am_t	pt_add_arr[EC_PF_FXP_MULT_NUM_POINTS];
} ec_point_proj_fpx_comb1t_mult_data_t, *ec_point_proj_fpx_comb1t_mult_data_p;


/* COMB 2t. (extended 1t, keep sync struct head with fpx_comb1t_mult_data) */
typedef struct elliptic_curve_pf_fpx_comb2t_mult_data_s {
	size_t		wnd_bits; /* Window bits count. */
	size_t		wnd_count; /* Num of blocks EC_PF_FXP_MULT_WIN_BITS size. */
	ec_point_t	pt_add_arr[EC_PF_FXP_MULT_NUM_POINTS];
	size_t		e_count;
	ec_point_t	pt_dbl_arr[EC_PF_FXP_MULT_NUM_POINTS];
} ec_point_fpx_comb2t_mult_data_t, *ec_point_fpx_comb2t_mult_data_p;

typedef struct elliptic_curve_proj_pf_fpx_comb2t_mult_data_s {
	size_t		wnd_bits; /* Window bits count. */
	size_t		wnd_count;
	ec_pt_proj_am_t	pt_add_arr[EC_PF_FXP_MULT_NUM_POINTS];
	size_t		e_count;
	ec_pt_proj_am_t	pt_dbl_arr[EC_PF_FXP_MULT_NUM_POINTS];
} ec_point_proj_fpx_comb2t_mult_data_t, *ec_point_proj_fpx_comb2t_mult_data_p;


#if EC_PF_FXP_MULT_ALGO == EC_PF_FXP_MULT_ALGO_BIN
/* None */
#elif EC_PF_FXP_MULT_ALGO == EC_PF_FXP_MULT_ALGO_BIN_PRECALC_DBL
#	define ec_point_fpx_mult_data_t		ec_point_fpx_pre_dbl_mult_data_t
#	define ec_point_proj_fpx_mult_data_t	ec_point_proj_fpx_pre_dbl_mult_data_t
#	define ec_point_affine_fpx_mult_precompute				\
		ec_point_affine_fpx_pre_dbl_mult_precompute
#	define ec_point_affine_fpx_mult						\
		ec_point_affine_fpx_pre_dbl_mult
#	define ec_point_proj_fpx_mult_precompute_affine				\
		ec_point_proj_fpx_pre_dbl_mult_precompute_affine
#	define ec_point_proj_fpx_mult						\
		ec_point_proj_fpx_pre_dbl_mult
#elif EC_PF_FXP_MULT_ALGO == EC_PF_FXP_MULT_ALGO_SLIDING_WIN
#	define ec_point_fpx_mult_data_t		ec_point_fpx_sl_win_mult_data_t
#	define ec_point_proj_fpx_mult_data_t	ec_point_proj_fpx_sl_win_mult_data_t
#	define ec_point_affine_fpx_mult_precompute				\
		ec_point_affine_fpx_sl_win_mult_precompute
#	define ec_point_affine_fpx_mult						\
		ec_point_affine_fpx_sl_win_mult
#	define ec_point_proj_fpx_mult_precompute_affine				\
		ec_point_proj_fpx_sl_win_mult_precompute_affine
#	define ec_point_proj_fpx_mult						\
		ec_point_proj_fpx_sl_win_mult
#elif EC_PF_FXP_MULT_ALGO == EC_PF_FXP_MULT_ALGO_COMB_1T
#	define ec_point_fpx_mult_data_t		ec_point_fpx_comb1t_mult_data_t
#	define ec_point_proj_fpx_mult_data_t	ec_point_proj_fpx_comb1t_mult_data_t
#	define ec_point_affine_fpx_mult_precompute				\
		ec_point_affine_fpx_comb1t_mult_precompute
#	define ec_point_affine_fpx_mult						\
		ec_point_affine_fpx_comb1t_mult
#	define ec_point_proj_fpx_mult_precompute_affine				\
		ec_point_proj_fpx_comb1t_mult_precompute_affine
#	define ec_point_proj_fpx_mult						\
		ec_point_proj_fpx_comb1t_mult
#elif EC_PF_FXP_MULT_ALGO == EC_PF_FXP_MULT_ALGO_COMB_2T
#	define ec_point_fpx_mult_data_t		ec_point_fpx_comb2t_mult_data_t
#	define ec_point_proj_fpx_mult_data_t	ec_point_proj_fpx_comb2t_mult_data_t
#	define ec_point_affine_fpx_mult_precompute				\
		ec_point_affine_fpx_comb2t_mult_precompute
#	define ec_point_affine_fpx_mult						\
		ec_point_affine_fpx_comb2t_mult
#	define ec_point_proj_fpx_mult_precompute_affine				\
		ec_point_proj_fpx_comb2t_mult_precompute_affine
#	define ec_point_proj_fpx_mult						\
		ec_point_proj_fpx_comb2t_mult
#endif /* EC_PF_FXP_MULT_ALGO */



/* Mult unknown point and digit. */
#define EC_PF_UNKPT_MULT_ALGO_BIN		EC_PF_FXP_MULT_ALGO_BIN
#define EC_PF_UNKPT_MULT_ALGO_BIN_PRECALC_DBL	EC_PF_FXP_MULT_ALGO_BIN_PRECALC_DBL
#define EC_PF_UNKPT_MULT_ALGO_SLIDING_WIN	EC_PF_FXP_MULT_ALGO_SLIDING_WIN
#define EC_PF_UNKPT_MULT_ALGO_COMB_1T		EC_PF_FXP_MULT_ALGO_COMB_1T
#define EC_PF_UNKPT_MULT_ALGO_COMB_2T		EC_PF_FXP_MULT_ALGO_COMB_2T
#define EC_PF_UNKPT_MULT_ALGO_SAME_AS_FXP	(EC_PF_FXP_MULT_ALGO_MAX + 1)
#define EC_PF_UNKPT_MULT_ALGO_MAX		EC_PF_UNKPT_MULT_ALGO_SAME_AS_FXP

/* Default EC_PF_UNKPT_MULT_ALGO */
#if !defined(EC_PF_UNKPT_MULT_ALGO) ||						\
    (EC_PF_UNKPT_MULT_ALGO != EC_PF_UNKPT_MULT_ALGO_BIN &&				\
    EC_PF_UNKPT_MULT_ALGO != EC_PF_UNKPT_MULT_ALGO_BIN_PRECALC_DBL &&		\
    EC_PF_UNKPT_MULT_ALGO != EC_PF_UNKPT_MULT_ALGO_SLIDING_WIN &&		\
    EC_PF_UNKPT_MULT_ALGO != EC_PF_UNKPT_MULT_ALGO_COMB_1T &&			\
    EC_PF_UNKPT_MULT_ALGO != EC_PF_UNKPT_MULT_ALGO_COMB_2T &&			\
    EC_PF_UNKPT_MULT_ALGO != EC_PF_UNKPT_MULT_ALGO_SAME_AS_FXP)
#	undef EC_PF_UNKPT_MULT_ALGO
#	define EC_PF_UNKPT_MULT_ALGO	EC_PF_UNKPT_MULT_ALGO_COMB_1T
#endif

/* Default size of sliding window, must be power of 2 or any for COMB. */
#ifndef EC_PF_UNKPT_MULT_WIN_BITS
#	define EC_PF_UNKPT_MULT_WIN_BITS	2
#endif

/* Owerwrite by fixed piont settings. */
#if EC_PF_UNKPT_MULT_ALGO == EC_PF_UNKPT_MULT_ALGO_SAME_AS_FXP
#	undef EC_PF_UNKPT_MULT_ALGO
#	define EC_PF_UNKPT_MULT_ALGO		EC_PF_FXP_MULT_ALGO
#	undef EC_PF_UNKPT_MULT_WIN_BITS
#	define EC_PF_UNKPT_MULT_WIN_BITS	EC_PF_FXP_MULT_WIN_BITS
#endif

#if EC_PF_UNKPT_MULT_ALGO == EC_PF_UNKPT_MULT_ALGO_BIN
/* None */
#elif EC_PF_UNKPT_MULT_ALGO == EC_PF_UNKPT_MULT_ALGO_BIN_PRECALC_DBL
#	define ec_point_unkpt_mult_data_t	ec_point_fpx_pre_dbl_mult_data_t
#	define ec_point_proj_unkpt_mult_data_t	ec_point_proj_fpx_pre_dbl_mult_data_t
#	define ec_point_affine_unkpt_mult_precompute				\
		ec_point_affine_fpx_pre_dbl_mult_precompute
#	define ec_point_affine_unkpt_mult					\
		ec_point_affine_fpx_pre_dbl_mult
#	define ec_point_proj_unkpt_mult_precompute_affine			\
		ec_point_proj_fpx_pre_dbl_mult_precompute_affine
#	define ec_point_proj_unkpt_mult						\
		ec_point_proj_fpx_pre_dbl_mult
#elif EC_PF_UNKPT_MULT_ALGO == EC_PF_UNKPT_MULT_ALGO_SLIDING_WIN
#	define ec_point_unkpt_mult_data_t	ec_point_fpx_sl_win_mult_data_t
#	define ec_point_proj_unkpt_mult_data_t	ec_point_proj_fpx_sl_win_mult_data_t
#	define ec_point_affine_unkpt_mult_precompute				\
		ec_point_affine_fpx_sl_win_mult_precompute
#	define ec_point_affine_unkpt_mult					\
		ec_point_affine_fpx_sl_win_mult
#	define ec_point_proj_unkpt_mult_precompute_affine			\
		ec_point_proj_fpx_sl_win_mult_precompute_affine
#	define ec_point_proj_unkpt_mult						\
		ec_point_proj_fpx_sl_win_mult
#elif EC_PF_UNKPT_MULT_ALGO == EC_PF_UNKPT_MULT_ALGO_COMB_1T
#	define ec_point_unkpt_mult_data_t	ec_point_fpx_comb1t_mult_data_t
#	define ec_point_proj_unkpt_mult_data_t	ec_point_proj_fpx_comb1t_mult_data_t
#	define ec_point_affine_unkpt_mult_precompute				\
		ec_point_affine_fpx_comb1t_mult_precompute
#	define ec_point_affine_unkpt_mult					\
		ec_point_affine_fpx_comb1t_mult
#	define ec_point_proj_unkpt_mult_precompute_affine			\
		ec_point_proj_fpx_comb1t_mult_precompute_affine
#	define ec_point_proj_unkpt_mult						\
		ec_point_proj_fpx_comb1t_mult
#elif EC_PF_UNKPT_MULT_ALGO == EC_PF_UNKPT_MULT_ALGO_COMB_2T
#	define ec_point_unkpt_mult_data_t	ec_point_fpx_comb2t_mult_data_t
#	define ec_point_proj_unkpt_mult_data_t	ec_point_proj_fpx_comb2t_mult_data_t
#	define ec_point_affine_unkpt_mult_precompute				\
		ec_point_affine_fpx_comb2t_mult_precompute
#	define ec_point_affine_unkpt_mult					\
		ec_point_affine_fpx_comb2t_mult
#	define ec_point_proj_unkpt_mult_precompute_affine			\
		ec_point_proj_fpx_comb2t_mult_precompute_affine
#	define ec_point_proj_unkpt_mult						\
		ec_point_proj_fpx_comb2t_mult
#endif /* EC_PF_UNKPT_MULT_ALGO */




/* Prime field multiple (twin) Point multiplication algo. */
/* Avaible types for EC_PF_TWIN_MULT_ALGO:
 * EC_PF_TWIN_MULT_ALGO_BIN - binary multiplication
 *
 * EC_PF_TWIN_MULT_ALGO_FXP_UNKPT - use EC_PF_FXP_MULT_ALGO for mult G and 
 * EC_PF_UNKPT_MULT_ALGO for other point.
 *
 * EC_PF_TWIN_MULT_ALGO_JOINT - use Joint sparse form
 */

#define EC_PF_TWIN_MULT_ALGO_BIN		0
#define EC_PF_TWIN_MULT_ALGO_FXP_UNKPT		1
#define EC_PF_TWIN_MULT_ALGO_JOINT		2
#define EC_PF_TWIN_MULT_ALGO_INTER		3

/* Default EC_PF_TWIN_MULT_ALGO */
#if !defined(EC_PF_TWIN_MULT_ALGO) ||						\
    (EC_PF_TWIN_MULT_ALGO != EC_PF_TWIN_MULT_ALGO_BIN &&			\
    EC_PF_TWIN_MULT_ALGO != EC_PF_TWIN_MULT_ALGO_FXP_UNKPT &&			\
    EC_PF_TWIN_MULT_ALGO != EC_PF_TWIN_MULT_ALGO_JOINT &&			\
    EC_PF_TWIN_MULT_ALGO != EC_PF_TWIN_MULT_ALGO_INTER)
#	undef EC_PF_TWIN_MULT_ALGO
#	define EC_PF_TWIN_MULT_ALGO	EC_PF_TWIN_MULT_ALGO_JOINT
#endif
/* Reset to EC_PF_TWIN_MULT_ALGO_BIN if
 * EC_PF_FXP_MULT_ALGO == EC_PF_FXP_MULT_ALGO_BIN and
 * EC_PF_UNKPT_MULT_ALGO == EC_PF_UNKPT_MULT_ALGO_BIN
 */
#if (EC_PF_TWIN_MULT_ALGO == EC_PF_TWIN_MULT_ALGO_FXP_UNKPT) &&			\
    EC_PF_FXP_MULT_ALGO == EC_PF_FXP_MULT_ALGO_BIN &&				\
    EC_PF_UNKPT_MULT_ALGO == EC_PF_UNKPT_MULT_ALGO_BIN
#	undef EC_PF_TWIN_MULT_ALGO
#	define EC_PF_TWIN_MULT_ALGO	EC_PF_TWIN_MULT_ALGO_BIN
#endif



#if EC_PF_TWIN_MULT_ALGO == EC_PF_TWIN_MULT_ALGO_BIN
#	define ec_point_affine_twin_mult					\
		ec_point_affine_bin_twin_mult
#	define ec_point_proj_twin_mult						\
		ec_point_proj_bin_twin_mult_affine
#elif EC_PF_TWIN_MULT_ALGO == EC_PF_TWIN_MULT_ALGO_FXP_UNKPT
#	define ec_point_affine_twin_mult					\
		ec_point_affine_bin_twin_mult
#	define ec_point_proj_twin_mult						\
		ec_point_proj_bin_twin_mult_affine
#elif EC_PF_TWIN_MULT_ALGO == EC_PF_TWIN_MULT_ALGO_JOINT
#	define ec_point_affine_twin_mult					\
		ec_point_affine_joint_twin_mult
#	define ec_point_proj_twin_mult						\
		ec_point_proj_joint_twin_mult_affine
#elif EC_PF_TWIN_MULT_ALGO == EC_PF_TWIN_MULT_ALGO_INTER
#	define ec_point_affine_twin_mult					\
		ec_point_affine_inter_twin_mult
#	define ec_point_proj_twin_mult						\
		ec_point_proj_inter_twin_mult_affine
#endif /* EC_PF_TWIN_MULT_ALGO */






typedef struct elliptic_curve_curve_s {
	//uint16_t m;	/* Binary field F2m */
	//uint16_t Fx[15];/* Binary field F2m */
	size_t	t;	/* security level: minimum length of symmetric keys */
	size_t	m;	/* Binary field F2m / bits count. */
	bn_t	p;	/* Prime field Fp */
	bn_t	a;
	bn_t	b;
	ec_point_t G;	/* The base point on the elliptic curve. */
	bn_t	n;
	uint32_t h;
	uint32_t algo;	/* EC_CURVE_ALGO_*: ECDSA, GOST */
	uint32_t flags;	/* EC_CURVE_FLAG_* */
#if EC_PF_FXP_MULT_ALGO != EC_PF_FXP_MULT_ALGO_BIN
	ec_pt_fpx_mult_data_t G_fpx_mult_data;
#endif
	bn_mod_rd_data_t p_mod_rd_data;
	bn_mod_rd_data_t n_mod_rd_data;
} ec_curve_t, *ec_curve_p;
#define EC_CURVE_ALGO_ECDSA	0
#define EC_CURVE_ALGO_GOST20XX	1

#define EC_CURVE_FLAG_A_M3	1 /* a = 3, use tricks. */




static inline int
ec_point_init(ec_point_p point, size_t bits) {

	if (NULL == point)
		return (EINVAL);
	BN_RET_ON_ERR(bn_init(&point->x, bits));
	BN_RET_ON_ERR(bn_init(&point->y, bits));
	point->infinity = 0;
	return (0);
}
static inline int
ec_point_proj_init(ec_point_proj_p point, size_t bits) {

	if (NULL == point)
		return (EINVAL);
	BN_RET_ON_ERR(bn_init(&point->x, bits));
	BN_RET_ON_ERR(bn_init(&point->y, bits));
	BN_RET_ON_ERR(bn_init(&point->z, bits));
	BN_RET_ON_ERR(bn_assign_digit(&point->z, 1));
	return (0);
}

/* dst = src */
static inline int
ec_point_assign(ec_point_p dst, ec_point_p src) {

	if (NULL == dst || NULL == src)
		return (EINVAL);
	if (dst == src)
		return (0);
	BN_RET_ON_ERR(bn_assign(&dst->x, &src->x));
	BN_RET_ON_ERR(bn_assign(&dst->y, &src->y));
	dst->infinity = src->infinity;
	return (0);
}
static inline int
ec_point_proj_assign(ec_point_proj_p dst, ec_point_proj_p src) {

	if (NULL == dst || NULL == src)
		return (EINVAL);
	if (dst == src)
		return (0);
	BN_RET_ON_ERR(bn_assign(&dst->x, &src->x));
	BN_RET_ON_ERR(bn_assign(&dst->y, &src->y));
	BN_RET_ON_ERR(bn_assign(&dst->z, &src->z));
	return (0);
}

#define ec_point_is_at_infinity(point)		(0 != (point)->infinity)
#define ec_point_proj_is_at_infinity(point)	(0 != bn_is_zero(&(point)->z))


/* is a == b? */
/* Returns: 1 if euqual. */
static inline int
ec_point_is_eq(ec_point_p a, ec_point_p b) {

	if (a == b)
		return (1);
	if (NULL == a || NULL == b)
		return (0);
	if (0 != ec_point_is_at_infinity(a) && 0 != ec_point_is_at_infinity(b))
		return (1);
	if (0 == ec_point_is_at_infinity(a) && 0 == ec_point_is_at_infinity(b) &&
	    0 != bn_is_equal(&a->x, &b->x) &&
	    0 != bn_is_equal(&a->y, &b->y))
		return (1);
	return (0);
}

/* is a = -b? */
/* Returns: -1 on error, 0 if not inverse, 1 if inverse. */
/* Assume: 0 == ec_point_check_affine() for both points. */
static inline int
ec_point_is_inverse(ec_point_p a, ec_point_p b, ec_curve_p curve) {
	bn_t tm;

	if (NULL == a || NULL == b || NULL == curve)
		return (-1);
	if (a == b)
		return (0);
	/* ax == bx ? */
	if (0 == bn_is_equal(&a->x, &b->x))
		return (0);
	/* p - ay == by ? */
	if (0 != bn_assign_init(&tm, &curve->p))
		return (-1);
	if (0 != bn_sub(&tm, &a->y, NULL))
		return (-1);
	if (0 != bn_is_equal(&tm, &b->y))
		return (1);
	return (0);
}


/* affine -> projective representation / ec_projectify() */
static inline int
ec_point_proj_import_affine(ec_point_proj_p a, ec_point_p b, ec_curve_p curve) {

	if (NULL == a || NULL == b || (void*)a == (void*)b || NULL == curve)
		return (EINVAL);
	if (0 != ec_point_is_at_infinity(b)) { /* Set to (0, 0, 0) */
		bn_assign_zero(&a->x);
		bn_assign_zero(&a->y);
		bn_assign_zero(&a->z);
	} else { /* Set to (x, y, 1) */
		BN_RET_ON_ERR(bn_assign(&a->x, &b->x));
		BN_RET_ON_ERR(bn_assign(&a->y, &b->y));
		BN_RET_ON_ERR(bn_assign_digit(&a->z, 1));
	}
	return (0);
}

/* projective -> affine representation / ec_affinify() */
static inline int
ec_point_proj_norm(ec_point_proj_p point, ec_curve_p curve) {
	size_t bits;
	bn_t z_inv, z_inv2, tm;

	if (NULL == point || NULL == curve)
		return (EINVAL);
	if (0 != ec_point_proj_is_at_infinity(point))
		return (0);
	if (0 != bn_is_one(&point->z))
		return (0);
	/* Init */
	bits = EC_CURVE_CALC_BITS_DBL(curve);
	BN_RET_ON_ERR(bn_init(&z_inv, bits));
	BN_RET_ON_ERR(bn_init(&z_inv2, bits));
	BN_RET_ON_ERR(bn_init(&tm, bits));
	/* Pre calc */
	BN_RET_ON_ERR(bn_assign(&z_inv, &point->z));
	BN_RET_ON_ERR(bn_mod_inv(&z_inv, &curve->p, &curve->p_mod_rd_data));
	BN_RET_ON_ERR(bn_assign(&z_inv2, &z_inv));
	BN_RET_ON_ERR(bn_mod_square(&z_inv2, &curve->p, &curve->p_mod_rd_data));
	/* Xres = X / Z^2 */
	BN_RET_ON_ERR(bn_assign(&tm, &point->x));
	BN_RET_ON_ERR(bn_mod_mult(&tm, &z_inv2, &curve->p, &curve->p_mod_rd_data));
	BN_RET_ON_ERR(bn_assign(&point->x, &tm));
	/* Yres = Y / Z^3 */
	BN_RET_ON_ERR(bn_assign(&tm, &point->y));
	BN_RET_ON_ERR(bn_mod_mult(&tm, &z_inv2, &curve->p, &curve->p_mod_rd_data));
	BN_RET_ON_ERR(bn_mod_mult(&tm, &z_inv, &curve->p, &curve->p_mod_rd_data));
	BN_RET_ON_ERR(bn_assign(&point->y, &tm));
	/* Yres = 1 */
	BN_RET_ON_ERR(bn_assign_digit(&point->z, 1));
	return (0);
}
static inline int
ec_point_proj_export_affine(ec_point_proj_p a, ec_point_p b, ec_curve_p curve) {

	if (NULL == a || NULL == b || (void*)a == (void*)b || NULL == curve)
		return (EINVAL);
	if (0 != ec_point_proj_is_at_infinity(a)) {
		b->infinity = 1;
		return (0);
	}
	BN_RET_ON_ERR(ec_point_proj_norm(a, curve));
	BN_RET_ON_ERR(bn_assign(&b->x, &a->x));
	BN_RET_ON_ERR(bn_assign(&b->y, &a->y));
	b->infinity = 0;
	return (0);
}

/* a = a + b */
static inline int
ec_point_proj_add(ec_point_proj_p a, ec_point_proj_p b, ec_curve_p curve) {
	size_t bits;
	bn_t res, y2, tm, tmA, tmB, tmC, tmD, tmE, tmF;

	if (NULL == a || NULL == b || NULL == curve)
		return (EINVAL);
	if (0 != ec_point_proj_is_at_infinity(b))
		return (0); /* a = a */
	if (0 != ec_point_proj_is_at_infinity(a)) {
		BN_RET_ON_ERR(ec_point_proj_assign(a, b));
		return (0); /* a = b */
	}
	/* Double size + 1 digit. */
	bits = EC_CURVE_CALC_BITS_DBL(curve);
	if (a != b) { /* Addition. */
		/* 12M + 4S + 6add + 1*2 */
		/* Init */
		BN_RET_ON_ERR(bn_init(&res, bits));
		BN_RET_ON_ERR(bn_init(&tmA, bits));
		BN_RET_ON_ERR(bn_init(&tmB, bits));
		BN_RET_ON_ERR(bn_init(&tmC, bits));
		BN_RET_ON_ERR(bn_init(&tmD, bits));
		BN_RET_ON_ERR(bn_init(&tmE, bits));
		BN_RET_ON_ERR(bn_init(&tmF, bits));
		BN_RET_ON_ERR(bn_init(&tm, bits));
		/* Prepare. */
		/* A = X1 * Z2^2 */
		BN_RET_ON_ERR(bn_assign(&tmA, &b->z));
		BN_RET_ON_ERR(bn_mod_square(&tmA, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_assign(&tmB, &tmA)); /* Save Z2^2 */
		BN_RET_ON_ERR(bn_mod_mult(&tmA, &a->x, &curve->p, &curve->p_mod_rd_data));
		/* B = Y1 * Z2^3 */
		BN_RET_ON_ERR(bn_mod_mult(&tmB, &b->z, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_mult(&tmB, &a->y, &curve->p, &curve->p_mod_rd_data));
		/* C = X2 * Z1^2 */
		BN_RET_ON_ERR(bn_assign(&tmC, &a->z));
		BN_RET_ON_ERR(bn_mod_square(&tmC, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_assign(&tmD, &tmC)); /* Save Z1^2 */
		BN_RET_ON_ERR(bn_mod_mult(&tmC, &b->x, &curve->p, &curve->p_mod_rd_data));
		/* D = Y2 * Z1^3 */
		BN_RET_ON_ERR(bn_mod_mult(&tmD, &a->z, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_mult(&tmD, &b->y, &curve->p, &curve->p_mod_rd_data));
		if (0 == bn_cmp(&tmA, &tmC)) {
			if (0 == bn_cmp(&tmB, &tmD))
				goto point_double;
			bn_assign_zero(&a->z);
			return (0); /* Point at infinity. */
		}
		/* E = (X2 * Z1^2 − X1 * Z2^2) = (C - A) */
		BN_RET_ON_ERR(bn_assign(&tmE, &tmC));
		BN_RET_ON_ERR(bn_mod_sub(&tmE, &tmA, &curve->p, &curve->p_mod_rd_data));
		/* F = (Y2 * Z1^3 − Y1 * Z2^3) = (D - B) */
		BN_RET_ON_ERR(bn_assign(&tmF, &tmD));
		BN_RET_ON_ERR(bn_mod_sub(&tmF, &tmB, &curve->p, &curve->p_mod_rd_data));
		/* C = A * E^2 */
		BN_RET_ON_ERR(bn_assign(&tmC, &tmE));
		BN_RET_ON_ERR(bn_mod_square(&tmC, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_assign(&tmD, &tmC)); /* Save E^2 */
		BN_RET_ON_ERR(bn_mod_mult(&tmC, &tmA, &curve->p, &curve->p_mod_rd_data));
		/* D = E^3 */
		BN_RET_ON_ERR(bn_mod_mult(&tmD, &tmE, &curve->p, &curve->p_mod_rd_data));

		/* Xres = F^2 - D - 2 * C */
		/* ... F^2 */
		BN_RET_ON_ERR(bn_assign(&res, &tmF));
		BN_RET_ON_ERR(bn_mod_square(&res, &curve->p, &curve->p_mod_rd_data));
		/* ... - D */
		BN_RET_ON_ERR(bn_mod_sub(&res, &tmD, &curve->p, &curve->p_mod_rd_data));
		/* - 2 * C */
		BN_RET_ON_ERR(bn_assign(&tm, &tmC));
		BN_RET_ON_ERR(bn_mod_mult_digit(&tm, 2, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_sub(&res, &tm, &curve->p, &curve->p_mod_rd_data));
		/* Xres = ... */
		BN_RET_ON_ERR(bn_assign(&a->x, &res));

		/* Yres = F * (C - Xres) - B * D */
		/* ... (C - Xres) * F */
		BN_RET_ON_ERR(bn_assign(&res, &tmC));
		BN_RET_ON_ERR(bn_mod_sub(&res, &a->x, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_mult(&res, &tmF, &curve->p, &curve->p_mod_rd_data));
		/* ... - B * D */
		BN_RET_ON_ERR(bn_assign(&tm, &tmD));
		BN_RET_ON_ERR(bn_mod_mult(&tm, &tmB, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_sub(&res, &tm, &curve->p, &curve->p_mod_rd_data));
		/* Yres = ... */
		BN_RET_ON_ERR(bn_assign(&a->y, &res));

		/* Zres = Z1 * Z2 * E */
		BN_RET_ON_ERR(bn_assign(&res, &tmE));
		BN_RET_ON_ERR(bn_mod_mult(&res, &a->z, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_mult(&res, &b->z, &curve->p, &curve->p_mod_rd_data));
		/* Zres = ... */
		BN_RET_ON_ERR(bn_assign(&a->z, &res));
	} else { /* a == b: Doubling. */
point_double:
		if (0 != bn_is_zero(&a->y)) {
			bn_assign_zero(&a->z);
			return (0); /* Point at infinity. */
		}
		/* [1]: Algorithm 3.21 */
		/* [2]: "dbl-2004-hmv" 2004 Hankerson–Menezes–Vanstone, page 91. */
		/* 4M + 4S + 1*half + 6add + 1*3 + 1*2 */
		/* Init */
		BN_RET_ON_ERR(bn_init(&tmA, bits));
		BN_RET_ON_ERR(bn_init(&tmB, bits));
		BN_RET_ON_ERR(bn_init(&tmC, bits));
		BN_RET_ON_ERR(bn_init(&y2, bits));
		/* Prepare. */
		/* tmB = 3 * X1^2 + a * Z1^4 */
		if (0 != (EC_CURVE_FLAG_A_M3 & curve->flags)) {
			/* tmB = 3 * (X1 − Z1^2) * (X1 + Z1^2) */
			BN_RET_ON_ERR(bn_assign(&tmA, &a->z));
			BN_RET_ON_ERR(bn_mod_square(&tmA, &curve->p, &curve->p_mod_rd_data));
			BN_RET_ON_ERR(bn_assign(&tmB, &a->x));
			BN_RET_ON_ERR(bn_mod_sub(&tmB, &tmA, &curve->p, &curve->p_mod_rd_data));
			BN_RET_ON_ERR(bn_mod_add(&tmA, &a->x, &curve->p, &curve->p_mod_rd_data));
			BN_RET_ON_ERR(bn_mod_mult(&tmB, &tmA, &curve->p, &curve->p_mod_rd_data));
			BN_RET_ON_ERR(bn_mod_mult_digit(&tmB, 3, &curve->p, &curve->p_mod_rd_data));
		} else {
			/* tmB = 3 * X^2 */
			BN_RET_ON_ERR(bn_assign(&tmB, &a->x));
			BN_RET_ON_ERR(bn_mod_square(&tmB, &curve->p, &curve->p_mod_rd_data));
			BN_RET_ON_ERR(bn_mod_mult_digit(&tmB, 3, &curve->p, &curve->p_mod_rd_data));
			if (0 == bn_is_zero(&curve->a)) { /* + (a * Z1^4) */
				BN_RET_ON_ERR(bn_assign(&tmA, &a->z));
				BN_RET_ON_ERR(bn_mod_exp_digit(&tmA, 4, &curve->p, &curve->p_mod_rd_data));
				BN_RET_ON_ERR(bn_mod_mult(&tmA, &curve->a, &curve->p, &curve->p_mod_rd_data));
				BN_RET_ON_ERR(bn_mod_add(&tmB, &tmA, &curve->p, &curve->p_mod_rd_data));
			}
		}
		/* Zres */
		BN_RET_ON_ERR(bn_assign(&y2, &a->y));
		BN_RET_ON_ERR(bn_mod_mult_digit(&y2, 2, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_assign(&tmA, &a->z));
		BN_RET_ON_ERR(bn_mod_mult(&tmA, &y2, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_assign(&a->z, &tmA));
		/* Xres */
		BN_RET_ON_ERR(bn_mod_square(&y2, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_assign(&tmC, &a->x));
		BN_RET_ON_ERR(bn_mod_mult(&tmC, &y2, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_square(&y2, &curve->p, &curve->p_mod_rd_data));
		if (0 != bn_is_odd(&y2))
			BN_RET_ON_ERR(bn_add(&y2, &curve->p, NULL));
		bn_r_shift(&y2, 1);
		BN_RET_ON_ERR(bn_assign(&tmA, &tmB));
		BN_RET_ON_ERR(bn_mod_square(&tmA, &curve->p, &curve->p_mod_rd_data));
		// XXX: - (2 * tmC)
		BN_RET_ON_ERR(bn_mod_sub(&tmA, &tmC, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_sub(&tmA, &tmC, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_assign(&a->x, &tmA));
		/* Yres */
		BN_RET_ON_ERR(bn_mod_sub(&tmC, &a->x, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_mult(&tmC, &tmB, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_sub(&tmC, &y2, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_assign(&a->y, &tmC));
	}
	return (0);
}

/* a = a - b */
static inline int
ec_point_proj_sub(ec_point_proj_p a, ec_point_proj_p b, ec_curve_p curve) {
	ec_point_proj_t tm;

	if (NULL == a || NULL == b || NULL == curve)
		return (EINVAL);
	BN_RET_ON_ERR(ec_point_proj_init(&tm, EC_CURVE_CALC_BITS_DBL(curve)));
	BN_RET_ON_ERR(bn_assign(&tm.x, &b->x));
	/* by = p - by */
	BN_RET_ON_ERR(bn_assign(&tm.y, &curve->p));
	BN_RET_ON_ERR(bn_mod_sub(&tm.y, &b->y, &curve->p, &curve->p_mod_rd_data));
	BN_RET_ON_ERR(bn_assign(&tm.z, &b->z));
	BN_RET_ON_ERR(ec_point_proj_add(a, &tm, curve));
	return (0);
}

/* n repeated point doublings. [1]: Algorithm 3.23 */
static inline int
ec_point_proj_dbl_n(ec_point_proj_p point, size_t n, ec_curve_p curve) {
	size_t i;
#ifdef EC_PROJ_REPEAT_DOUBLE
	size_t bits;
	bn_t Y, y2, tm, tmA, tmB, tmC;

	if (NULL == point || NULL == curve)
		return (EINVAL);
	if (0 != bn_is_zero(&point->y)) {
		bn_assign_zero(&point->z);
		return (0); /* Point at infinity. */
	}
	if (0 == n || 0 != ec_point_proj_is_at_infinity(point)) /* Point at infinity. */
		return (0);
	/* Double size + 1 digit. */
	bits = (EC_CURVE_CALC_BITS_DBL(curve) + (2 * BN_DIGIT_BITS));
	/* Init */
	BN_RET_ON_ERR(bn_init(&Y, bits));
	BN_RET_ON_ERR(bn_init(&y2, bits));
	BN_RET_ON_ERR(bn_init(&tmA, bits));
	BN_RET_ON_ERR(bn_init(&tmB, bits));
	BN_RET_ON_ERR(bn_init(&tmC, bits));
	BN_RET_ON_ERR(bn_init(&tm, bits));
	/* P0->y = 2 * P0->y */
	BN_RET_ON_ERR(bn_assign(&Y, &point->y));
	BN_RET_ON_ERR(bn_mod_mult_digit(&Y, 2, &curve->p, &curve->p_mod_rd_data));
	/* tmC = Z^4 */
	BN_RET_ON_ERR(bn_assign(&tmC, &point->z));
	BN_RET_ON_ERR(bn_mod_exp_digit(&tmC, 4, &curve->p, &curve->p_mod_rd_data));

	for (i = 0; i < n; i ++) {
		if (0 != (EC_CURVE_FLAG_A_M3 & curve->flags)) {
			/* tmA = 3(X^2 - tmC) */
			BN_RET_ON_ERR(bn_assign(&tmA, &point->x));
			BN_RET_ON_ERR(bn_mod_square(&tmA, &curve->p, &curve->p_mod_rd_data));
			BN_RET_ON_ERR(bn_mod_sub(&tmA, &tmC, &curve->p, &curve->p_mod_rd_data));
			BN_RET_ON_ERR(bn_mod_mult_digit(&tmA, 3, &curve->p, &curve->p_mod_rd_data));
		} else {
			/* tmA = 3 * X^2 */
			BN_RET_ON_ERR(bn_assign(&tmA, &point->x));
			BN_RET_ON_ERR(bn_mod_square(&tmA, &curve->p, &curve->p_mod_rd_data));
			BN_RET_ON_ERR(bn_mod_mult_digit(&tmA, 3, &curve->p, &curve->p_mod_rd_data));
			if (0 == bn_is_zero(&curve->a)) { /* + a * tmC */
				BN_RET_ON_ERR(bn_assign(&tm, &curve->a));
				BN_RET_ON_ERR(bn_mod_mult(&tm, &tmC, &curve->p, &curve->p_mod_rd_data));
				BN_RET_ON_ERR(bn_mod_add(&tmA, &tm, &curve->p, &curve->p_mod_rd_data));
			}
		}
		/* tmB = X * Y^2 */
		BN_RET_ON_ERR(bn_assign(&y2, &Y));
		BN_RET_ON_ERR(bn_mod_square(&y2, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_assign(&tmB, &point->x));
		BN_RET_ON_ERR(bn_mod_mult(&tmB, &y2, &curve->p, &curve->p_mod_rd_data));
		/* X = tmA^2 - 2 * tmB */
		BN_RET_ON_ERR(bn_assign(&tm, &tmA));
		BN_RET_ON_ERR(bn_mod_square(&tm, &curve->p, &curve->p_mod_rd_data));
		//XXX !!!
		BN_RET_ON_ERR(bn_mod_sub(&tm, &tmB, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_sub(&tm, &tmB, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_assign(&point->x, &tm));
		/* Z = Z * Y */
		BN_RET_ON_ERR(bn_assign(&tm, &Y));
		BN_RET_ON_ERR(bn_mod_mult(&tm, &point->z, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_assign(&point->z, &tm));
		/* y2 = y2^2 */
		BN_RET_ON_ERR(bn_mod_square(&y2, &curve->p, &curve->p_mod_rd_data));
		if (i < (n - 1)) /* tmC = tmC * Y^4 */
			BN_RET_ON_ERR(bn_mod_mult(&tmC, &y2, &curve->p, &curve->p_mod_rd_data));
		/* Y = 2 * tmA * (tmB - X) - Y^4 */
		BN_RET_ON_ERR(bn_mod_sub(&tmB, &point->x, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_mult_digit(&tmA, 2, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_mult(&tmA, &tmB, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_sub(&tmA, &y2, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_assign(&Y, &tmA));
	}

	if (0 != bn_is_odd(&Y))
		BN_RET_ON_ERR(bn_add(&Y, &curve->p, NULL));
		//BN_RET_ON_ERR(bn_mod_add(&tmA, &tm, &curve->p, &curve->p_mod_rd_data));
	bn_r_shift(&Y, 1);
	BN_RET_ON_ERR(bn_assign(&point->y, &Y));
#else
	for (i = 0; i < n; i ++) {
		BN_RET_ON_ERR(ec_point_proj_add(point, point, curve));
	}
#endif /* EC_PROJ_REPEAT_DOUBLE */
	return (0);
}

/* Require: curve->a == -3. */
static inline int
ec_point_proj_add_mix(ec_point_proj_p a, ec_point_p b, ec_curve_p curve) {
#ifdef EC_PROJ_ADD_MIX
	size_t bits;
	bn_t tm, tm1, tm2, tm3, tm4;

	if (NULL == a || NULL == b || NULL == curve)
		return (EINVAL);
	if (0 != ec_point_is_at_infinity(b))
		return (0); /* a = a */
	if (0 != ec_point_proj_is_at_infinity(a)) {
		BN_RET_ON_ERR(ec_point_proj_import_affine(a, b, curve));
		return (0); /* a = b */
	}
	/* Double size + 1 digit. */
	bits = EC_CURVE_CALC_BITS_DBL(curve);
	/* Init */
	BN_RET_ON_ERR(bn_init(&tm, bits));
	BN_RET_ON_ERR(bn_init(&tm1, bits));
	BN_RET_ON_ERR(bn_init(&tm2, bits));
	BN_RET_ON_ERR(bn_init(&tm3, bits));
	BN_RET_ON_ERR(bn_init(&tm4, bits));

#if 0 /* [2]: "mmadd-2007-bl", Z1=1 and Z2=1, 4M + 2S + 6add + 1*4 + 4*2 */
	if (0 != bn_is_one(&a->z)) {
		/* H = X2 - X1 */
		BN_RET_ON_ERR(bn_assign(&tm2, &b->x));
		BN_RET_ON_ERR(bn_mod_sub(&tm2, &a->x, &curve->p, &curve->p_mod_rd_data));
		/* Zres */
		/* Z3 = 2 * H */
		BN_RET_ON_ERR(bn_assign(&tm1, &tm2));
		BN_RET_ON_ERR(bn_mod_mult_digit(&tm1, 2, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_assign(&a->z, &tm1));
		/* HH = H^2 */
		BN_RET_ON_ERR(bn_assign(&tm1, &tm2));
		BN_RET_ON_ERR(bn_mod_square(&tm1, &curve->p, &curve->p_mod_rd_data));
		/* I = 4 * HH */
		BN_RET_ON_ERR(bn_mod_mult_digit(&tm1, 4, &curve->p, &curve->p_mod_rd_data));
		/* J = H * I */
		BN_RET_ON_ERR(bn_mod_mult(&tm2, &tm1, &curve->p, &curve->p_mod_rd_data));
		/* V = X1 * I */
		BN_RET_ON_ERR(bn_mod_mult(&tm1, &a->x, &curve->p, &curve->p_mod_rd_data));
		/* r = 2 * (Y2 - Y1) */
		BN_RET_ON_ERR(bn_assign(&tm3, &b->y));
		BN_RET_ON_ERR(bn_mod_sub(&tm3, &a->y, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_mult_digit(&tm3, 2, &curve->p, &curve->p_mod_rd_data));
		/* Xres */
		/* X3 = r^2 - J - 2 * V */
		BN_RET_ON_ERR(bn_assign(&tm, &tm3));
		BN_RET_ON_ERR(bn_mod_square(&tm, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_sub(&tm, &tm2, &curve->p, &curve->p_mod_rd_data));
		// XXX
		BN_RET_ON_ERR(bn_mod_sub(&tm, &tm1, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_sub(&tm, &tm1, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_assign(&a->x, &tm));
		/* Yres */
		/* Y3 = r * (V - X3) - 2 * Y1 * J */
		BN_RET_ON_ERR(bn_mod_sub(&tm1, &a->x, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_mult(&tm1, &tm3, &curve->p, &curve->p_mod_rd_data));
		/* - 2 * Y1 * J */
		BN_RET_ON_ERR(bn_mod_mult(&tm2, &a->y, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_mult_digit(&tm2, 2, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_sub(&tm1, &tm2, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_assign(&a->y, &tm1));
		return (0);
	}
#endif
	/* [1]: Algorithm 3.22 */
	/* [2]: "madd-2004-hmv" (2004 Hankerson–Menezes–Vanstone, page 91.) */
	/* 8M + 3S + 6add + 1*2 */
	/* T1 = Z1^2 */
	BN_RET_ON_ERR(bn_assign(&tm1, &a->z));
	BN_RET_ON_ERR(bn_mod_square(&tm1, &curve->p, &curve->p_mod_rd_data));
	/* T2 = T1 * Z1 */
	BN_RET_ON_ERR(bn_assign(&tm2, &tm1));
	BN_RET_ON_ERR(bn_mod_mult(&tm2, &a->z, &curve->p, &curve->p_mod_rd_data));
	/* T1 = T1 * b->x */
	BN_RET_ON_ERR(bn_mod_mult(&tm1, &b->x, &curve->p, &curve->p_mod_rd_data));
	/* T2 = T2 * b->y */
	BN_RET_ON_ERR(bn_mod_mult(&tm2, &b->y, &curve->p, &curve->p_mod_rd_data));
	/* T1 = T1 - a->x */
	BN_RET_ON_ERR(bn_mod_sub(&tm1, &a->x, &curve->p, &curve->p_mod_rd_data));
	/* T2 = T2 - a->y */
	BN_RET_ON_ERR(bn_mod_sub(&tm2, &a->y, &curve->p, &curve->p_mod_rd_data));

	if (0 != bn_is_zero(&tm1)) {
		if (0 != bn_is_zero(&tm2)) {
			BN_RET_ON_ERR(ec_point_proj_add(a, a, curve));
			return (0);
		} else {
			bn_assign_zero(&a->z);
			return (0); /* Point at infinity. */
		}
	}
	/* T3 = T1^2 */
	BN_RET_ON_ERR(bn_assign(&tm3, &tm1));
	BN_RET_ON_ERR(bn_mod_square(&tm3, &curve->p, &curve->p_mod_rd_data));
	/* T4 = T3 * T1 */
	BN_RET_ON_ERR(bn_assign(&tm4, &tm3));
	BN_RET_ON_ERR(bn_mod_mult(&tm4, &tm1, &curve->p, &curve->p_mod_rd_data));
	/* T3 = T3 * a->x */
	BN_RET_ON_ERR(bn_mod_mult(&tm3, &a->x, &curve->p, &curve->p_mod_rd_data));
	/* Z3 = Z1 * T1 */
	BN_RET_ON_ERR(bn_mod_mult(&tm1, &a->z, &curve->p, &curve->p_mod_rd_data));
	BN_RET_ON_ERR(bn_assign(&a->z, &tm1));
	/* T1 = 2 * T3 */
	BN_RET_ON_ERR(bn_assign(&tm1, &tm3));
	BN_RET_ON_ERR(bn_mod_mult_digit(&tm1, 2, &curve->p, &curve->p_mod_rd_data));
	/* a->x = T2^2 */
	BN_RET_ON_ERR(bn_assign(&tm, &tm2));
	BN_RET_ON_ERR(bn_mod_square(&tm, &curve->p, &curve->p_mod_rd_data));
	/* a->x = a->x - T1 */
	BN_RET_ON_ERR(bn_mod_sub(&tm, &tm1, &curve->p, &curve->p_mod_rd_data));
	/* a->x = a->x - T4 */
	BN_RET_ON_ERR(bn_mod_sub(&tm, &tm4, &curve->p, &curve->p_mod_rd_data));
	BN_RET_ON_ERR(bn_assign(&a->x, &tm));
	/* T3 = T3 - a->x */
	BN_RET_ON_ERR(bn_mod_sub(&tm3, &a->x, &curve->p, &curve->p_mod_rd_data));
	/* T3 = T3 * T2 */
	BN_RET_ON_ERR(bn_mod_mult(&tm3, &tm2, &curve->p, &curve->p_mod_rd_data));
	/* T4 = T4 * a->y */
	BN_RET_ON_ERR(bn_mod_mult(&tm4, &a->y, &curve->p, &curve->p_mod_rd_data));
	/* a->y = T3 - T4 */
	BN_RET_ON_ERR(bn_mod_sub(&tm3, &tm4, &curve->p, &curve->p_mod_rd_data));
	BN_RET_ON_ERR(bn_assign(&a->y, &tm3));
#else /* no EC_PROJ_ADD_MIX */
	ec_point_proj_t tm;

	if (NULL == a || NULL == b || NULL == curve)
		return (EINVAL);
	BN_RET_ON_ERR(ec_point_proj_init(&tm, curve->m));
	BN_RET_ON_ERR(ec_point_proj_import_affine(&tm, b, curve));
	BN_RET_ON_ERR(ec_point_proj_add(a, &tm, curve));
#endif /* EC_PROJ_ADD_MIX */
	return (0);
}
/* a = a - b */
static inline int
ec_point_proj_sub_mix(ec_point_proj_p a, ec_point_p b, ec_curve_p curve) {
	ec_point_t tm;

	if (NULL == a || NULL == b || NULL == curve)
		return (EINVAL);
	BN_RET_ON_ERR(ec_point_init(&tm, EC_CURVE_CALC_BITS_DBL(curve)));
	BN_RET_ON_ERR(bn_assign(&tm.x, &b->x));
	/* by = p - by */
	BN_RET_ON_ERR(bn_assign(&tm.y, &curve->p));
	BN_RET_ON_ERR(bn_mod_sub(&tm.y, &b->y, &curve->p, &curve->p_mod_rd_data));
	tm.infinity = b->infinity;
	BN_RET_ON_ERR(ec_point_proj_add_mix(a, &tm, curve));
	return (0);
}

/* Proxy funcs: convert affine to projective, do calcs, convert result to affine. */
static inline int
ec_point_proj_add_affine(ec_point_p a, ec_point_p b, ec_curve_p curve) {
	ec_point_proj_t tm;

	if (NULL == a || NULL == b || NULL == curve)
		return (EINVAL);
	BN_RET_ON_ERR(ec_point_proj_init(&tm, curve->m));
	BN_RET_ON_ERR(ec_point_proj_import_affine(&tm, a, curve));
	BN_RET_ON_ERR(ec_point_proj_add_mix(&tm, b, curve));
	BN_RET_ON_ERR(ec_point_proj_export_affine(&tm, a, curve));
	return (0);
}
static inline int
ec_point_proj_sub_affine(ec_point_p a, ec_point_p b, ec_curve_p curve) {
	ec_point_proj_t tm;

	if (NULL == a || NULL == b || NULL == curve)
		return (EINVAL);
	BN_RET_ON_ERR(ec_point_proj_init(&tm, curve->m));
	BN_RET_ON_ERR(ec_point_proj_import_affine(&tm, a, curve));
	BN_RET_ON_ERR(ec_point_proj_sub_mix(&tm, b, curve));
	BN_RET_ON_ERR(ec_point_proj_export_affine(&tm, a, curve));
	return (0);
}



/* Point mult. */
/* a = a * d. [1]: Algorithm 3.26 Right-to-left binary method for point multiplication */
static inline int
ec_point_proj_bin_mult(ec_point_proj_p point, bn_p d, ec_curve_p curve) {
	size_t i, bits;
	ec_point_proj_t tm;

	if (NULL == point || NULL == d || NULL == curve)
		return (EINVAL);
	if (0 != bn_is_zero(d)) { /* R←(1,1,0) */
		bn_assign_zero(&point->z);
		return (0);
	}
	if (0 != bn_is_one(d))
		return (0);
	if (0 != ec_point_proj_is_at_infinity(point)) /* R←(1,1,0) */
		return (0);
	BN_RET_ON_ERR(ec_point_proj_init(&tm, curve->m));
	BN_RET_ON_ERR(ec_point_proj_assign(&tm, point));
	bn_assign_zero(&point->z); /* "Zeroize" point. */
	bits = bn_calc_bits(d);
	for (i = 0; i < bits; i ++) {
		if (0 != bn_is_bit_set(d, i))
			BN_RET_ON_ERR(ec_point_proj_add(point, &tm, curve)); /* res += point */
		BN_RET_ON_ERR(ec_point_proj_add(&tm, &tm, curve)); /* point *= 2 */
	}
	return (0);
}


static inline int
ec_point_proj_fpx_pre_dbl_mult_precompute_affine(size_t wnd_bits __unused,
    ec_point_p point, ec_curve_p curve,
    ec_point_proj_fpx_pre_dbl_mult_data_p mult_data) {
	size_t i;

	if (NULL == point || NULL == curve || NULL == mult_data)
		return (EINVAL);
#ifdef EC_PROJ_ADD_MIX
	ec_point_proj_t tm;

	BN_RET_ON_ERR(ec_point_init(&mult_data->pt_arr[0], curve->m));
	BN_RET_ON_ERR(ec_point_assign(&mult_data->pt_arr[0], point));
	if (0 != ec_point_is_at_infinity(point)) /* R←(1,1,0) */
		return (0);
	BN_RET_ON_ERR(ec_point_proj_init(&tm, curve->m));
	BN_RET_ON_ERR(ec_point_proj_import_affine(&tm, point, curve));
	for (i = 1; i < curve->m; i ++) {
		BN_RET_ON_ERR(ec_point_proj_add(&tm, &tm, curve)); /* point *= 2 */
		/* Do some additional calcs for z = 1. */
		BN_RET_ON_ERR(ec_point_init(&mult_data->pt_arr[i], curve->m));
		BN_RET_ON_ERR(ec_point_proj_export_affine(&tm,
		    &mult_data->pt_arr[i], curve));
	}
#else
	BN_RET_ON_ERR(ec_point_proj_init(&mult_data->pt_arr[0], curve->m));
	BN_RET_ON_ERR(ec_point_proj_import_affine(&mult_data->pt_arr[0], point, curve));
	if (0 != ec_point_is_at_infinity(point)) /* R←(1,1,0) */
		return (0);
	for (i = 1; i < curve->m; i ++) {
		BN_RET_ON_ERR(ec_point_proj_init(&mult_data->pt_arr[i], curve->m));
		BN_RET_ON_ERR(ec_point_proj_assign(&mult_data->pt_arr[i],
		    &mult_data->pt_arr[(i - 1)]));
		BN_RET_ON_ERR(ec_point_proj_add(&mult_data->pt_arr[i],
		    &mult_data->pt_arr[i], curve)); /* point *= 2 */
		/* Do some additional calcs for z = 1. */
		BN_RET_ON_ERR(ec_point_proj_norm(&mult_data->pt_arr[i], curve));
	}
#endif /* EC_PROJ_ADD_MIX */
	return (0);
}

static inline int
ec_point_proj_fpx_pre_dbl_mult(ec_point_proj_p point,
    ec_point_proj_fpx_pre_dbl_mult_data_p mult_data, bn_p d, ec_curve_p curve) {
	size_t i, bits;

	if (NULL == point || NULL == d || NULL == mult_data || NULL == curve)
		return (EINVAL);
	if (0 != bn_is_one(d)) { /* Return orig point. */
#ifdef EC_PROJ_ADD_MIX
		BN_RET_ON_ERR(ec_point_proj_import_affine(point,
		    &mult_data->pt_arr[0], curve));
#else
		BN_RET_ON_ERR(ec_point_proj_assign(point, &mult_data->pt_arr[0]));
#endif /* EC_PROJ_ADD_MIX */
		return (0);
	}
	bn_assign_zero(&point->z); /* "Zeroize" point. */ /* R←(1,1,0) */
	if (0 != bn_is_zero(d) ||
	    0 != ec_pt_proj_am_is_at_infinity(&mult_data->pt_arr[0]))
		return (0);
	bits = bn_calc_bits(d);
	for (i = 0; i < bits; i ++) {
		if (0 != bn_is_bit_set(d, i))
#ifdef EC_PROJ_ADD_MIX
			BN_RET_ON_ERR(ec_point_proj_add_mix(point,
			    &mult_data->pt_arr[i], curve));
#else
			BN_RET_ON_ERR(ec_point_proj_add(point,
			    &mult_data->pt_arr[i], curve));
#endif
	}
	return (0);
}


/* Precompute the array of fixed base point for sliding window method. */
static inline int
ec_point_proj_fpx_sl_win_mult_precompute_affine(size_t wnd_bits, ec_point_p point,
    ec_curve_p curve, ec_point_proj_fpx_sl_win_mult_data_p mult_data) {
	size_t i, pt_cnt;

	if (0 == wnd_bits || NULL == point || NULL == curve || NULL == mult_data)
		return (EINVAL);
	if (0 != (wnd_bits & (wnd_bits - 1)))
		return (EINVAL); /* Must be power of 2. */
	if (0 != ec_point_is_at_infinity(point)) { /* R←(1,1,0) */
		mult_data->wnd_bits = 0; /* Will return point at infinity. */
		return (0);
	}
	pt_cnt = ((((size_t)1) << wnd_bits) - 1);
	mult_data->wnd_bits = wnd_bits;
#ifdef EC_PROJ_ADD_MIX
	ec_point_proj_t tm;

	BN_RET_ON_ERR(ec_point_init(&mult_data->pt_arr[0], curve->m));
	BN_RET_ON_ERR(ec_point_assign(&mult_data->pt_arr[0], point));
	BN_RET_ON_ERR(ec_point_proj_init(&tm, curve->m));
	BN_RET_ON_ERR(ec_point_proj_import_affine(&tm, point, curve));
	for (i = 1; i < pt_cnt; i ++) {
		BN_RET_ON_ERR(ec_point_proj_add_mix(&tm,
		    &mult_data->pt_arr[0], curve));
		/* Do some additional calcs for z = 1. */
		BN_RET_ON_ERR(ec_point_init(&mult_data->pt_arr[i], curve->m));
		BN_RET_ON_ERR(ec_point_proj_export_affine(&tm,
		    &mult_data->pt_arr[i], curve));
	}
#else
	BN_RET_ON_ERR(ec_point_proj_init(&mult_data->pt_arr[0], curve->m));
	BN_RET_ON_ERR(ec_point_proj_import_affine(&mult_data->pt_arr[0], point, curve));
	/* Set all array points to 'point' */
	for (i = 1; i < pt_cnt; i ++) {
		BN_RET_ON_ERR(ec_point_proj_init(&mult_data->pt_arr[i], curve->m));
		BN_RET_ON_ERR(ec_point_proj_assign(&mult_data->pt_arr[i],
		    &mult_data->pt_arr[0]));
	}
	for (i = 1; i < pt_cnt; i ++) {
		BN_RET_ON_ERR(ec_point_proj_add(&mult_data->pt_arr[i],
		    &mult_data->pt_arr[(i - 1)], curve));
		/* Do some additional calcs for z = 1. */
		BN_RET_ON_ERR(ec_point_proj_norm(&mult_data->pt_arr[i], curve));
	}
#endif /* EC_PROJ_ADD_MIX */
	return (0);
}

static inline int
ec_point_proj_fpx_sl_win_mult(ec_point_proj_p point,
    ec_point_proj_fpx_sl_win_mult_data_p mult_data, bn_p d, ec_curve_p curve) {
	ssize_t i, j;
	bn_digit_t windex, mask;

	if (NULL == point || NULL == d || NULL == mult_data || NULL == curve)
		return (EINVAL);
	if (0 != bn_is_one(d) && 0 != mult_data->wnd_bits) { /* Return orig point. */
#ifdef EC_PROJ_ADD_MIX
		BN_RET_ON_ERR(ec_point_proj_import_affine(point,
		    &mult_data->pt_arr[0], curve));
#else
		BN_RET_ON_ERR(ec_point_proj_assign(point, &mult_data->pt_arr[0]));
#endif /* EC_PROJ_ADD_MIX */
		return (0);
	}
	bn_assign_zero(&point->z); /* "Zeroize" point. */ /* R←(1,1,0) */
	if (0 != bn_is_zero(d) || 0 == mult_data->wnd_bits) /* ec_point_proj_is_at_infinity */
		return (0);
	mask = ((((bn_digit_t)1) << mult_data->wnd_bits) - 1);
	for (i = (d->digits - 1); i >= 0; i --) {
		for (j = ((BN_DIGIT_BITS / mult_data->wnd_bits) - 1); j >= 0; j --) {
			BN_RET_ON_ERR(ec_point_proj_dbl_n(point, mult_data->wnd_bits, curve));
			windex = (mask & (d->num[i] >> (j * mult_data->wnd_bits)));
			if (0 == windex)
				continue;
#ifdef EC_PROJ_ADD_MIX
			BN_RET_ON_ERR(ec_point_proj_add_mix(point,
			    &mult_data->pt_arr[(windex - 1)], curve));
#else
			BN_RET_ON_ERR(ec_point_proj_add(point,
			    &mult_data->pt_arr[(windex - 1)], curve));
#endif
		}
	}
	return (0);
}


/* COMB 1t. */
/* Precompute the array of fixed base point for COMB1t method. */
static inline int
ec_point_proj_fpx_comb1t_mult_precompute_affine(size_t wnd_bits, ec_point_p point,
    ec_curve_p curve, ec_point_proj_fpx_comb1t_mult_data_p mult_data) {
	size_t i, j, iidx;

	if (0 == wnd_bits || NULL == point || NULL == curve || NULL == mult_data)
		return (EINVAL);
	if (0 != ec_point_is_at_infinity(point)) { /* R←(1,1,0) */
		mult_data->wnd_bits = 0; /* Will return point at infinity. */
		return (0);
	}
	mult_data->wnd_bits = wnd_bits;
	/* Calculate windows count. (d = t/w) */
	mult_data->wnd_count = ((curve->m / wnd_bits) +
	    ((0 != (curve->m % wnd_bits)) ? 1 : 0));
	/* Calc add data. */
#ifdef EC_PROJ_ADD_MIX
	ec_point_proj_t tm;

	BN_RET_ON_ERR(ec_point_init(&mult_data->pt_add_arr[0], curve->m));
	BN_RET_ON_ERR(ec_point_assign(&mult_data->pt_add_arr[0], point));
	BN_RET_ON_ERR(ec_point_proj_init(&tm, curve->m));
	for (i = 1; i < wnd_bits; i ++) {
		iidx = (1 << i);
		BN_RET_ON_ERR(ec_point_proj_import_affine(&tm,
		    &mult_data->pt_add_arr[((1 << (i - 1)) - 1)], curve));
		BN_RET_ON_ERR(ec_point_proj_dbl_n(&tm, mult_data->wnd_count, curve));
		BN_RET_ON_ERR(ec_point_init(&mult_data->pt_add_arr[(iidx - 1)],
		    curve->m));
		BN_RET_ON_ERR(ec_point_proj_export_affine(&tm,
		    &mult_data->pt_add_arr[(iidx - 1)], curve));
		for (j = 1; j < iidx; j ++) {
			BN_RET_ON_ERR(ec_point_proj_import_affine(&tm,
			    &mult_data->pt_add_arr[(j - 1)], curve));
			BN_RET_ON_ERR(ec_point_proj_add_mix(&tm,
			    &mult_data->pt_add_arr[(iidx - 1)], curve));
			BN_RET_ON_ERR(ec_point_init(
			    &mult_data->pt_add_arr[(iidx + j - 1)], curve->m));
			BN_RET_ON_ERR(ec_point_proj_export_affine(&tm,
			    &mult_data->pt_add_arr[(iidx + j - 1)], curve));
		}
	}
#else
	BN_RET_ON_ERR(ec_point_proj_init(&mult_data->pt_add_arr[0], curve->m));
	BN_RET_ON_ERR(ec_point_proj_import_affine(&mult_data->pt_add_arr[0],
	    point, curve));
	for (i = 1; i < wnd_bits; i ++) {
		iidx = (1 << i);
		BN_RET_ON_ERR(ec_point_proj_init(&mult_data->pt_add_arr[(iidx - 1)],
		    curve->m));
		BN_RET_ON_ERR(ec_point_proj_assign(
		    &mult_data->pt_add_arr[(iidx - 1)],
		    &mult_data->pt_add_arr[((1 << (i - 1)) - 1)]));
		BN_RET_ON_ERR(ec_point_proj_dbl_n(&mult_data->pt_add_arr[(iidx - 1)],
		    mult_data->wnd_count, curve));
		BN_RET_ON_ERR(ec_point_proj_norm(&mult_data->pt_add_arr[(iidx - 1)],
		    curve));
		for (j = 1; j < iidx; j ++) {
			BN_RET_ON_ERR(ec_point_proj_init(
			    &mult_data->pt_add_arr[(iidx + j - 1)], curve->m));
			BN_RET_ON_ERR(ec_point_proj_assign(
			    &mult_data->pt_add_arr[(iidx + j - 1)],
			    &mult_data->pt_add_arr[(j - 1)]));
			BN_RET_ON_ERR(ec_point_proj_add(
			    &mult_data->pt_add_arr[(iidx + j - 1)],
			    &mult_data->pt_add_arr[(iidx - 1)], curve));
			BN_RET_ON_ERR(ec_point_proj_norm(
			    &mult_data->pt_add_arr[(iidx + j - 1)], curve));
		}
	}
#endif /* EC_PROJ_ADD_MIX */
	return (0);
}

static inline int
ec_point_proj_fpx_comb1t_mult(ec_point_proj_p point,
    ec_point_proj_fpx_comb1t_mult_data_p mult_data, bn_p d, ec_curve_p curve) {
	ssize_t i, bit_off;
	bn_digit_t windex;

	if (NULL == point || NULL == d || NULL == mult_data || NULL == curve)
		return (EINVAL);
	if (0 != bn_is_one(d) && 0 != mult_data->wnd_bits) { /* Return orig point. */
#ifdef EC_PROJ_ADD_MIX
		BN_RET_ON_ERR(ec_point_proj_import_affine(point,
		    &mult_data->pt_add_arr[0], curve));
#else
		BN_RET_ON_ERR(ec_point_proj_assign(point, &mult_data->pt_add_arr[0]));
#endif /* EC_PROJ_ADD_MIX */
		return (0);
	}
	bn_assign_zero(&point->z); /* "Zeroize" point. */ /* R←(1,1,0) */
	if (0 != bn_is_zero(d) || 0 == mult_data->wnd_bits) /* ec_point_proj_is_at_infinity */
		return (0);
	/* XXX: dont know how to mult. */
	if ((d->digits * BN_DIGIT_BITS) > curve->m) {
#ifdef EC_PROJ_ADD_MIX
		BN_RET_ON_ERR(ec_point_proj_import_affine(point,
		    &mult_data->pt_add_arr[0], curve));
#else
		BN_RET_ON_ERR(ec_point_proj_assign(point, &mult_data->pt_add_arr[0]));
#endif /* EC_PROJ_ADD_MIX */
		BN_RET_ON_ERR(ec_point_proj_bin_mult(point, d, curve));
		return (0);
	}
	bit_off = ((mult_data->wnd_bits * mult_data->wnd_count) - 1);
	for (i = (mult_data->wnd_count - 1); i >= 0; i --, bit_off --) {
		BN_RET_ON_ERR(ec_point_proj_add(point, point, curve));
		/* 1. Add table. */
		windex = bn_combo_column_get(d, bit_off,
		    mult_data->wnd_bits, mult_data->wnd_count);
		if (0 != windex) {
#ifdef EC_PROJ_ADD_MIX
			BN_RET_ON_ERR(ec_point_proj_add_mix(point,
			    &mult_data->pt_add_arr[(windex - 1)], curve));
#else
			BN_RET_ON_ERR(ec_point_proj_add(point,
			    &mult_data->pt_add_arr[(windex - 1)], curve));
#endif
		}
	}
	return (0);
}

/* COMB 2t. */
/* Precompute the array of fixed base point for COMB2t method. */
static inline int
ec_point_proj_fpx_comb2t_mult_precompute_affine(size_t wnd_bits, ec_point_p point,
    ec_curve_p curve, ec_point_proj_fpx_comb2t_mult_data_p mult_data) {
	size_t i, pt_cnt;

	if (0 == wnd_bits || NULL == point || NULL == curve || NULL == mult_data)
		return (EINVAL);
	BN_RET_ON_ERR(ec_point_proj_fpx_comb1t_mult_precompute_affine(wnd_bits,
	    point, curve, (ec_point_proj_fpx_comb1t_mult_data_p)mult_data));
	if (0 == mult_data->wnd_bits) /* ec_point_proj_is_at_infinity */
		return (0);
	pt_cnt = ((((size_t)1) << wnd_bits) - 1);
	/* Calculate windows count. (e = d/2) */
	mult_data->e_count = ((mult_data->wnd_count / 2) +
	    ((0 != (mult_data->wnd_count % 2)) ? 1 : 0));
	/* Calc dbl data. */
#ifdef EC_PROJ_ADD_MIX
	ec_point_proj_t tm;

	BN_RET_ON_ERR(ec_point_proj_init(&tm, curve->m));
	for (i = 0; i < pt_cnt; i ++) {
		BN_RET_ON_ERR(ec_point_proj_import_affine(&tm,
		    &mult_data->pt_add_arr[i], curve));
		BN_RET_ON_ERR(ec_point_proj_dbl_n(&tm, mult_data->e_count, curve));
		BN_RET_ON_ERR(ec_point_init(&mult_data->pt_dbl_arr[i], curve->m));
		BN_RET_ON_ERR(ec_point_proj_export_affine(&tm,
		    &mult_data->pt_dbl_arr[i], curve));
	}
#else
	for (i = 0; i < pt_cnt; i ++) {
		BN_RET_ON_ERR(ec_point_proj_init(&mult_data->pt_dbl_arr[i], curve->m));
		BN_RET_ON_ERR(ec_point_proj_assign(&mult_data->pt_dbl_arr[i],
		    &mult_data->pt_add_arr[i]));
		BN_RET_ON_ERR(ec_point_proj_dbl_n(&mult_data->pt_dbl_arr[i],
		    mult_data->e_count, curve));
		BN_RET_ON_ERR(ec_point_proj_norm(&mult_data->pt_dbl_arr[i], curve));
	}
#endif /* EC_PROJ_ADD_MIX */
	return (0);
}

static inline int
ec_point_proj_fpx_comb2t_mult(ec_point_proj_p point,
    ec_point_proj_fpx_comb2t_mult_data_p mult_data, bn_p d, ec_curve_p curve) {
	ssize_t i, bit_off;
	bn_digit_t windex;

	if (NULL == point || NULL == d || NULL == mult_data || NULL == curve)
		return (EINVAL);
	if (0 != bn_is_one(d) && 0 != mult_data->wnd_bits) { /* Return orig point. */
#ifdef EC_PROJ_ADD_MIX
		BN_RET_ON_ERR(ec_point_proj_import_affine(point,
		    &mult_data->pt_add_arr[0], curve));
#else
		BN_RET_ON_ERR(ec_point_proj_assign(point, &mult_data->pt_add_arr[0]));
#endif /* EC_PROJ_ADD_MIX */
		return (0);
	}
	bn_assign_zero(&point->z); /* "Zeroize" point. */ /* R←(1,1,0) */
	if (0 != bn_is_zero(d) || 0 == mult_data->wnd_bits) /* ec_point_proj_is_at_infinity */
		return (0);
	/* XXX: dont know how to mult. */
	if ((d->digits * BN_DIGIT_BITS) > curve->m) {
#ifdef EC_PROJ_ADD_MIX
		BN_RET_ON_ERR(ec_point_proj_import_affine(point,
		    &mult_data->pt_add_arr[0], curve));
#else
		BN_RET_ON_ERR(ec_point_proj_assign(point, &mult_data->pt_add_arr[0]));
#endif /* EC_PROJ_ADD_MIX */
		BN_RET_ON_ERR(ec_point_proj_bin_mult(point, d, curve));
		return (0);
	}
	bit_off = (((mult_data->wnd_bits - 1) * mult_data->wnd_count) +
	    (mult_data->e_count - 1));
	for (i = (mult_data->e_count - 1); i >= 0; i --, bit_off --) {
		BN_RET_ON_ERR(ec_point_proj_add(point, point, curve));
		/* 1. Add table. */
		windex = bn_combo_column_get(d, bit_off,
		    mult_data->wnd_bits, mult_data->wnd_count);
		if (0 != windex) {
#ifdef EC_PROJ_ADD_MIX
			BN_RET_ON_ERR(ec_point_proj_add_mix(point,
			    &mult_data->pt_add_arr[(windex - 1)], curve));
#else
			BN_RET_ON_ERR(ec_point_proj_add(point,
			    &mult_data->pt_add_arr[(windex - 1)], curve));
#endif
		}
		/* 2. Dbl table. */
		if ((i + mult_data->e_count) >= mult_data->wnd_count)
			continue;
		windex = bn_combo_column_get(d, (bit_off + mult_data->e_count),
		    mult_data->wnd_bits, mult_data->wnd_count);
		if (0 == windex)
			continue;
#ifdef EC_PROJ_ADD_MIX
		BN_RET_ON_ERR(ec_point_proj_add_mix(point,
		    &mult_data->pt_dbl_arr[(windex - 1)], curve));
#else
		BN_RET_ON_ERR(ec_point_proj_add(point,
		    &mult_data->pt_dbl_arr[(windex - 1)], curve));
#endif
	}
	return (0);
}



/* Proxy funcs: convert affine to projective, do calcs, convert result to affine. */
static inline int
ec_point_proj_bin_mult_affine(ec_point_p point, bn_p d, ec_curve_p curve) {
	ec_point_proj_t tm;

	if (NULL == point || NULL == d || NULL == curve)
		return (EINVAL);
	BN_RET_ON_ERR(ec_point_proj_init(&tm, curve->m));
	BN_RET_ON_ERR(ec_point_proj_import_affine(&tm, point, curve));
	BN_RET_ON_ERR(ec_point_proj_bin_mult(&tm, d, curve));
	BN_RET_ON_ERR(ec_point_proj_export_affine(&tm, point, curve));
	return (0);
}

#if EC_PF_FXP_MULT_ALGO != EC_PF_FXP_MULT_ALGO_BIN
static inline int
ec_point_proj_fpx_mult_affine(ec_point_p point,
    ec_point_proj_fpx_mult_data_t *mult_data, bn_p d, ec_curve_p curve) {
	ec_point_proj_t tm;

	if (NULL == point || NULL == d || NULL == curve)
		return (EINVAL);
	BN_RET_ON_ERR(ec_point_proj_init(&tm, curve->m));
	BN_RET_ON_ERR(ec_point_proj_fpx_mult(&tm, mult_data, d, curve));
	BN_RET_ON_ERR(ec_point_proj_export_affine(&tm, point, curve));
	return (0);
}
#endif

#if EC_PF_UNKPT_MULT_ALGO != EC_PF_UNKPT_MULT_ALGO_BIN
static inline int
ec_point_proj_unkpt_mult_affine(ec_point_p point,
    ec_point_proj_unkpt_mult_data_t *mult_data, bn_p d, ec_curve_p curve) {
	ec_point_proj_t tm;

	if (NULL == point || NULL == d || NULL == curve)
		return (EINVAL);
	BN_RET_ON_ERR(ec_point_proj_init(&tm, curve->m));
	BN_RET_ON_ERR(ec_point_proj_unkpt_mult(&tm, mult_data, d, curve));
	BN_RET_ON_ERR(ec_point_proj_export_affine(&tm, point, curve));
	return (0);
}
#endif


/* res = a*ad + b*bd */
static inline int
ec_point_proj_bin_twin_mult_affine(ec_point_p a, bn_p ad, ec_point_p b, bn_p bd,
    ec_curve_p curve, ec_point_p res) {
	ec_point_proj_t tmA, tmB;

	if (NULL == a || NULL == ad || NULL == b || NULL == bd || NULL == curve ||
	    NULL == res)
		return (EINVAL);
	BN_RET_ON_ERR(ec_point_proj_init(&tmA, curve->m));
	BN_RET_ON_ERR(ec_point_proj_init(&tmB, curve->m));
	BN_RET_ON_ERR(ec_point_proj_import_affine(&tmA, a, curve));
	BN_RET_ON_ERR(ec_point_proj_bin_mult(&tmA, ad, curve));
	BN_RET_ON_ERR(ec_point_proj_import_affine(&tmB, b, curve));
	BN_RET_ON_ERR(ec_point_proj_bin_mult(&tmB, bd, curve));
	BN_RET_ON_ERR(ec_point_proj_add(&tmA, &tmB, curve));
	BN_RET_ON_ERR(ec_point_proj_export_affine(&tmA, res, curve));
	return (0);
}

#ifdef EC_USE_PROJECTIVE
static inline int
ec_point_proj_fpx_unkpt_twin_mult_bp_affine(bn_p Gd, ec_point_p b, bn_p bd,
    ec_curve_p curve, ec_point_p res) {
	ec_point_proj_t tmA, tmB;

	if (NULL == Gd || NULL == b || NULL == bd || NULL == curve || NULL == res)
		return (EINVAL);
	BN_RET_ON_ERR(ec_point_proj_init(&tmA, curve->m));
	BN_RET_ON_ERR(ec_point_proj_init(&tmB, curve->m));

#if EC_PF_FXP_MULT_ALGO != EC_PF_FXP_MULT_ALGO_BIN
	BN_RET_ON_ERR(ec_point_proj_fpx_mult(&tmA, &curve->G_fpx_mult_data, Gd, curve));
#else
	BN_RET_ON_ERR(ec_point_proj_import_affine(&tmA, &curve->G, curve));
	BN_RET_ON_ERR(ec_point_proj_bin_mult(&tmA, Gd, curve));	
#endif

#if EC_PF_UNKPT_MULT_ALGO != EC_PF_UNKPT_MULT_ALGO_BIN
	ec_point_proj_unkpt_mult_data_t mult_data;

	BN_RET_ON_ERR(ec_point_proj_unkpt_mult_precompute_affine(
	    EC_PF_UNKPT_MULT_WIN_BITS, b, curve, &mult_data));
	BN_RET_ON_ERR(ec_point_proj_unkpt_mult(&tmB, &mult_data, bd, curve));
#else /* Unknown point bin mult. */
	BN_RET_ON_ERR(ec_point_proj_import_affine(&tmB, b, curve));
	BN_RET_ON_ERR(ec_point_proj_bin_mult(&tmB, bd, curve));
#endif

	BN_RET_ON_ERR(ec_point_proj_add(&tmA, &tmB, curve));
	BN_RET_ON_ERR(ec_point_proj_export_affine(&tmA, res, curve));

	return (0);
}
#endif

static inline int
ec_point_proj_joint_twin_mult_affine(ec_point_p a, bn_p ad, ec_point_p b, bn_p bd,
    ec_curve_p curve, ec_point_p res) {
	size_t jsf_cnt, offset;
	ssize_t i, idx;
	ec_point_proj_t tm;
	ec_pt_proj_am_t tbl[4];
	int8_t jsf[BN_BIT_LEN];

	if (NULL == a || NULL == ad || NULL == b || NULL == bd || NULL == curve ||
	    NULL == res)
		return (EINVAL);
	BN_RET_ON_ERR(ec_point_proj_init(&tm, curve->m));

#ifdef EC_PROJ_ADD_MIX
	/* Init table. */
	for (i = 0; i < 4; i ++)
		BN_RET_ON_ERR(ec_point_init(&tbl[i], curve->m));
	/* b */
	BN_RET_ON_ERR(ec_point_assign(&tbl[0], b));
	/* a */
	BN_RET_ON_ERR(ec_point_assign(&tbl[1], a));
	/* Calc: a + b */
	BN_RET_ON_ERR(ec_point_proj_import_affine(&tm, a, curve));
	BN_RET_ON_ERR(ec_point_proj_add_mix(&tm, &tbl[0], curve));
	BN_RET_ON_ERR(ec_point_proj_export_affine(&tm, &tbl[2], curve));
	/* Calc: a - b */
	BN_RET_ON_ERR(ec_point_proj_import_affine(&tm, a, curve));
	BN_RET_ON_ERR(ec_point_proj_sub_mix(&tm, &tbl[0], curve));
	BN_RET_ON_ERR(ec_point_proj_export_affine(&tm, &tbl[3], curve));
#else
	/* Init table. */
	for (i = 0; i < 4; i ++)
		BN_RET_ON_ERR(ec_point_proj_init(&tbl[i], curve->m));
	/* b */
	BN_RET_ON_ERR(ec_point_proj_import_affine(&tbl[0], b, curve));
	/* a */
	BN_RET_ON_ERR(ec_point_proj_import_affine(&tbl[1], a, curve));
	/* Calc: a + b */
	BN_RET_ON_ERR(ec_point_proj_assign(&tbl[2], &tbl[1]));
	BN_RET_ON_ERR(ec_point_proj_add(&tbl[2], &tbl[0], curve));
	BN_RET_ON_ERR(ec_point_proj_norm(&tbl[2], curve));
	/* Calc: a - b */
	BN_RET_ON_ERR(ec_point_proj_assign(&tbl[3], &tbl[1]));
	BN_RET_ON_ERR(ec_point_proj_sub(&tbl[3], &tbl[0], curve));
	BN_RET_ON_ERR(ec_point_proj_norm(&tbl[3], curve));
#endif /* EC_PROJ_ADD_MIX */

	/* Calc Joint sparse form. */
	BN_RET_ON_ERR(bn_calc_jsf(ad, bd, sizeof(jsf), jsf, &jsf_cnt, &offset));

	bn_assign_zero(&tm.z); /* "Zeroize" point. */
	for (i = (jsf_cnt - 1); i >= 0; i --) {
		BN_RET_ON_ERR(ec_point_proj_add(&tm, &tm, curve));
		idx = ((jsf[i] * 2) + jsf[(i + offset)]);
		if (0 != jsf[i] && jsf[i] == -jsf[(i + offset)]) {
			if (idx < 0) {
				idx = - 4;
			} else {
				idx = 4;
			}
		}
		if (0 == idx)
			continue;
#ifdef EC_PROJ_ADD_MIX
		if (idx < 0) {
			BN_RET_ON_ERR(ec_point_proj_sub_mix(&tm, &tbl[((-idx) - 1)],
			    curve));
		} else {
			BN_RET_ON_ERR(ec_point_proj_add_mix(&tm, &tbl[(idx - 1)],
			    curve));
		}
#else
		if (idx < 0) {
			BN_RET_ON_ERR(ec_point_proj_sub(&tm, &tbl[((-idx) - 1)],
			    curve));
		} else {
			BN_RET_ON_ERR(ec_point_proj_add(&tm, &tbl[(idx - 1)],
			    curve));
		}
#endif /* EC_PROJ_ADD_MIX */
	}
	BN_RET_ON_ERR(ec_point_proj_export_affine(&tm, res, curve));
	return (0);
}





#define EP_WIDTH 4
#define EP_DEPTH 4

#if 0
void ep_tab(ep_t *t, const ep_t p, int w) {
	if (w > 2) {
		ep_dbl(t[0], p);
		ep_add(t[1], t[0], p);
		for (int i = 2; i < (1 << (w - 2)); i++) {
			ep_add(t[i], t[i - 1], t[0]);
		}
	}
	ep_copy(t[0], p);
}
#endif

/* See [1]: Algorithm 3.38 Sliding window method for point multiplication */
static inline int
ec_point_proj_inter_twin_mult_precalc_affine(ec_point_p point, size_t wnd_bits,
    ec_curve_p curve, ec_pt_proj_am_t *tbl) {
	size_t i;
	
	if (NULL == point || 2 > wnd_bits || NULL == tbl)
		return (EINVAL);
	/* Calc: 1P, 3P, 5P, 7P.... */
#ifdef EC_PROJ_ADD_MIX
	ec_point_proj_t tm;

	BN_RET_ON_ERR(ec_point_proj_init(&tm, curve->m));

	/* Init table. */
	for (i = 0; i < (1 << (wnd_bits - 2)); i ++)
		BN_RET_ON_ERR(ec_point_init(&tbl[i], curve->m));
	if (wnd_bits > 2) {
		/* 0 */
		BN_RET_ON_ERR(ec_point_proj_import_affine(&tm, point, curve));
		BN_RET_ON_ERR(ec_point_proj_add(&tm, &tm, curve));
		BN_RET_ON_ERR(ec_point_proj_export_affine(&tm, &tbl[0], curve));
		/* 1 */
		BN_RET_ON_ERR(ec_point_proj_add_mix(&tm, point, curve));
		BN_RET_ON_ERR(ec_point_proj_export_affine(&tm, &tbl[1], curve));
		/* 2... */
		for (i = 2; i < (1 << (wnd_bits - 2)); i ++) {
			BN_RET_ON_ERR(ec_point_proj_add_mix(&tm, &tbl[0], curve));
			BN_RET_ON_ERR(ec_point_proj_export_affine(&tm, &tbl[i], curve));
		}
	}
	/* 0 */
	BN_RET_ON_ERR(ec_point_assign(&tbl[0], point));
#else
	/* Init table. */
	for (i = 0; i < (1 << (wnd_bits - 2)); i ++)
		BN_RET_ON_ERR(ec_point_proj_init(&tbl[i], curve->m));
	if (wnd_bits > 2) {
		/* 0 */
		BN_RET_ON_ERR(ec_point_proj_import_affine(&tbl[0], point, curve));
		BN_RET_ON_ERR(ec_point_proj_add(&tbl[0], &tbl[0], curve));
		BN_RET_ON_ERR(ec_point_proj_norm(&tbl[0], curve));
		/* 1 */
		BN_RET_ON_ERR(ec_point_proj_import_affine(&tbl[1], point, curve));
		BN_RET_ON_ERR(ec_point_proj_add(&tbl[1], &tbl[0], curve));
		BN_RET_ON_ERR(ec_point_proj_norm(&tbl[1], curve));
		/* 2... */
		for (i = 2; i < (1 << (wnd_bits - 2)); i ++) {
			BN_RET_ON_ERR(ec_point_proj_assign(&tbl[i], &tbl[(i - 1)]));
			BN_RET_ON_ERR(ec_point_proj_add(&tbl[i], &tbl[0], curve));
			BN_RET_ON_ERR(ec_point_proj_norm(&tbl[i], curve));
		}
	}
	/* 0 */
	BN_RET_ON_ERR(ec_point_proj_import_affine(&tbl[0], point, curve));
#endif /* EC_PROJ_ADD_MIX */
	return (0);
}

static inline int
ec_point_proj_inter_twin_mult_affine(ec_point_p a, bn_p ad, ec_point_p b, bn_p bd,
    ec_curve_p curve, ec_point_p res) {
	ssize_t i;
	size_t naf_cnt, naf0_cnt, naf1_cnt;
	ec_point_proj_t tm;
	ec_pt_proj_am_t tbl0[(1 << (EP_DEPTH - 2))], tbl1[(1 << (EP_WIDTH - 2))];
	int8_t naf0[(BN_BIT_LEN / 2)], naf1[(BN_BIT_LEN / 2)];

	if (NULL == a || NULL == ad || NULL == b || NULL == bd || NULL == curve ||
	    NULL == res)
		return (EINVAL);

	/* Compute the precomputation table. */
	BN_RET_ON_ERR(ec_point_proj_inter_twin_mult_precalc_affine(a, EP_DEPTH,
	    curve, (struct ec_point_t*)tbl0));
	BN_RET_ON_ERR(ec_point_proj_inter_twin_mult_precalc_affine(b, EP_WIDTH,
	    curve, (struct ec_point_t*)tbl1));

	/* Compute the w-TNAF representation of k. */
	BN_RET_ON_ERR(bn_calc_naf(ad, EP_DEPTH, sizeof(naf0), naf0, &naf0_cnt));
	BN_RET_ON_ERR(bn_calc_naf(bd, EP_WIDTH, sizeof(naf1), naf1, &naf1_cnt));
	naf_cnt = max(naf0_cnt, naf1_cnt);

	BN_RET_ON_ERR(ec_point_proj_init(&tm, curve->m));
	bn_assign_zero(&tm.z); /* "Zeroize" point. */
	for (i = (naf_cnt - 1); i >= 0; i --) {
		BN_RET_ON_ERR(ec_point_proj_add(&tm, &tm, curve));
#ifdef EC_PROJ_ADD_MIX
		if (0 != naf0[i]) {
			if (naf0[i] > 0) {
				BN_RET_ON_ERR(ec_point_proj_add_mix(&tm,
				    &tbl0[(naf0[i] / 2)], curve));
			} else {
				BN_RET_ON_ERR(ec_point_proj_sub_mix(&tm,
				    &tbl0[((-naf0[i]) / 2)], curve));
			}
		}
		if (0 == naf1[i])
			continue;
		if (naf1[i] > 0) {
			BN_RET_ON_ERR(ec_point_proj_add_mix(&tm,
			    &tbl1[(naf1[i] / 2)], curve));
		} else {
			BN_RET_ON_ERR(ec_point_proj_sub_mix(&tm,
			    &tbl1[((-naf1[i]) / 2)], curve));
		}
#else
		if (0 != naf0[i]) {
			if (naf0[i] > 0) {
				BN_RET_ON_ERR(ec_point_proj_add(&tm,
				    &tbl0[(naf0[i] / 2)], curve));
			} else {
				BN_RET_ON_ERR(ec_point_proj_sub(&tm,
				    &tbl0[((-naf0[i]) / 2)], curve));
			}
		}
		if (0 == naf1[i])
			continue;
		if (naf1[i] > 0) {
			BN_RET_ON_ERR(ec_point_proj_add(&tm,
			    &tbl1[(naf1[i] / 2)], curve));
		} else {
			BN_RET_ON_ERR(ec_point_proj_sub(&tm,
			    &tbl1[((-naf1[i]) / 2)], curve));
		}
#endif /* EC_PROJ_ADD_MIX */
	}
	/* Convert r to affine coordinates. */
	BN_RET_ON_ERR(ec_point_proj_export_affine(&tm, res, curve));
	return (0);
}





/* Calculations in affine. */

/* a = a + b */
static inline int
ec_point_affine_add(ec_point_p a, ec_point_p b, ec_curve_p curve) {
	size_t bits;
	bn_t lambda, tm;

	if (NULL == a || NULL == b || NULL == curve)
		return (EINVAL);
	if (0 != ec_point_is_at_infinity(b))
		return (0); /* a = a */
	if (0 != ec_point_is_at_infinity(a)) {
		BN_RET_ON_ERR(ec_point_assign(a, b));
		return (0); /* a = b */
	}
	/* Double size + 1 digit. */
	bits = EC_CURVE_CALC_BITS_DBL(curve);
	if (a != b/*0 == ec_point_is_eq(a, b)*/) { /* Addition. */
		/* lambda = (ay - by) / (ax - bx) (mod p) */
		/* Calculate */
		BN_RET_ON_ERR(bn_init(&tm, bits));
		BN_RET_ON_ERR(bn_assign(&tm, &b->x));
		BN_RET_ON_ERR(bn_mod_sub(&tm, &a->x, &curve->p, &curve->p_mod_rd_data));
		if (0 != bn_is_zero(&tm)) {
			if (0 != bn_is_equal(&a->y, &b->y))
				goto point_double;
			/* ec_point_is_inverse() == 1 or something wrong. */
			a->infinity = 1;
			return (0); /* Point at infinity. */
		}
		BN_RET_ON_ERR(bn_init(&lambda, bits));
		BN_RET_ON_ERR(bn_assign(&lambda, &b->y));
		BN_RET_ON_ERR(bn_mod_sub(&lambda, &a->y, &curve->p, &curve->p_mod_rd_data));
	} else { /* a == b: Doubling. */
point_double:
		/* lambda = (3*(x^2) + a) / (2*y) (mod p) */
		if (0 != bn_is_zero(&a->y)) {
			a->infinity = 1;
			return (0); /* Point at infinity. */
		}
		/* Init */
		BN_RET_ON_ERR(bn_init(&lambda, bits));
		BN_RET_ON_ERR(bn_init(&tm, bits));
		/* Calculate */
		BN_RET_ON_ERR(bn_assign(&lambda, &a->x));
		BN_RET_ON_ERR(bn_mod_square(&lambda, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_mult_digit(&lambda, 3, &curve->p, &curve->p_mod_rd_data));
		if (0 != (EC_CURVE_FLAG_A_M3 & curve->flags)) {
			BN_RET_ON_ERR(bn_assign_digit(&tm, 3));
			BN_RET_ON_ERR(bn_mod_sub(&lambda, &tm, &curve->p, &curve->p_mod_rd_data));
		} else {
			BN_RET_ON_ERR(bn_mod_add(&lambda, &curve->a, &curve->p, &curve->p_mod_rd_data));
		}
		BN_RET_ON_ERR(bn_assign(&tm, &a->y));
		BN_RET_ON_ERR(bn_mod_mult_digit(&tm, 2, &curve->p, &curve->p_mod_rd_data));
		//BN_RET_ON_ERR(bn_mod_add(&tm, &a->y, &curve->p, &curve->p_mod_rd_data)); /* eq left shift + mod. */
	}
	/* lambda = lambda / tm = lambda * (tm^-1) */
	BN_RET_ON_ERR(bn_mod_inv(&tm, &curve->p, &curve->p_mod_rd_data));
	BN_RET_ON_ERR(bn_mod_mult(&lambda, &tm, &curve->p, &curve->p_mod_rd_data));
	/* res_x = lambda^2 - ax - bx (mod p) */
	BN_RET_ON_ERR(bn_assign(&tm, &lambda));
	BN_RET_ON_ERR(bn_mod_square(&tm, &curve->p, &curve->p_mod_rd_data));
	BN_RET_ON_ERR(bn_mod_sub(&tm, &a->x, &curve->p, &curve->p_mod_rd_data));
	BN_RET_ON_ERR(bn_mod_sub(&tm, &b->x, &curve->p, &curve->p_mod_rd_data));
	/* Now: res_x = tm */
	/* res_y = lambda * (ax - res_x) - ay (mod p) */
	BN_RET_ON_ERR(bn_mod_sub(&a->x, &tm, &curve->p, &curve->p_mod_rd_data));
	BN_RET_ON_ERR(bn_mod_mult(&lambda, &a->x, &curve->p, &curve->p_mod_rd_data));
	BN_RET_ON_ERR(bn_mod_sub(&lambda, &a->y, &curve->p, &curve->p_mod_rd_data));
	/* Now: res_y = lambda */
	/* Assign results. */
	BN_RET_ON_ERR(bn_assign(&a->x, &tm));
	BN_RET_ON_ERR(bn_assign(&a->y, &lambda));
	a->infinity = 0;
	return (0);
}
/* a = a - b */
static inline int
ec_point_affine_sub(ec_point_p a, ec_point_p b, ec_curve_p curve) {
	ec_point_t tm;

	if (NULL == a || NULL == b || NULL == curve)
		return (EINVAL);
	BN_RET_ON_ERR(ec_point_init(&tm, EC_CURVE_CALC_BITS_DBL(curve)));
	BN_RET_ON_ERR(bn_assign(&tm.x, &b->x));
	/* p - by == by ? */
	BN_RET_ON_ERR(bn_assign(&tm.y, &curve->p));
	BN_RET_ON_ERR(bn_mod_sub(&tm.y, &b->y, &curve->p, &curve->p_mod_rd_data));
	tm.infinity = b->infinity;
	BN_RET_ON_ERR(ec_point_affine_add(a, &tm, curve));
	return (0);
}


static inline int
ec_point_affine_dbl_n(ec_point_p point, size_t n, ec_curve_p curve) {
	size_t i;

	for (i = 0; i < n; i ++)
		BN_RET_ON_ERR(ec_point_affine_add(point, point, curve));
	return (0);
}


/* a = a * d */
static inline int
ec_point_affine_bin_mult(ec_point_p point, bn_p d, ec_curve_p curve) {
	size_t i, bits;
	ec_point_t tm;

	if (NULL == point || NULL == d || NULL == curve)
		return (EINVAL);
	if (0 != ec_point_is_at_infinity(point)) /* R←(1,1,0) */
		return (0);
	if (0 != bn_is_zero(d)) {
		point->infinity = 1; /* R←(1,1,0) */
		return (0);
	}
	if (0 != bn_is_one(d))
		return (0);
	BN_RET_ON_ERR(ec_point_init(&tm, curve->m));
	BN_RET_ON_ERR(ec_point_assign(&tm, point));
	point->infinity = 1; /* "Zeroize" point. */
	bits = bn_calc_bits(d);
	for (i = 0; i < bits; i ++) {
		if (0 != bn_is_bit_set(d, i))
			BN_RET_ON_ERR(ec_point_affine_add(point, &tm, curve)); /* res += point */
		BN_RET_ON_ERR(ec_point_affine_add(&tm, &tm, curve)); /* point *= 2 */
	}
	return (0);
}


static inline int
ec_point_affine_fpx_pre_dbl_mult_precompute(size_t wnd_bits __unused,
    ec_point_p point, ec_curve_p curve, ec_point_fpx_pre_dbl_mult_data_p mult_data) {
	size_t i;

	if (NULL == point || NULL == curve || NULL == mult_data)
		return (EINVAL);
	BN_RET_ON_ERR(ec_point_init(&mult_data->pt_arr[0], curve->m));
	BN_RET_ON_ERR(ec_point_assign(&mult_data->pt_arr[0], point));
	if (0 != ec_point_is_at_infinity(point)) /* R←(1,1,0) */
		return (0);
	for (i = 1; i < curve->m; i ++) {
		BN_RET_ON_ERR(ec_point_init(&mult_data->pt_arr[1], curve->m));
		BN_RET_ON_ERR(ec_point_assign(&mult_data->pt_arr[i],
		    &mult_data->pt_arr[(i - 1)]));
		BN_RET_ON_ERR(ec_point_affine_add(&mult_data->pt_arr[i],
		    &mult_data->pt_arr[i], curve)); /* point *= 2 */
	}
	return (0);
}

static inline int
ec_point_affine_fpx_pre_dbl_mult(ec_point_p point,
    ec_point_fpx_pre_dbl_mult_data_p mult_data, bn_p d, ec_curve_p curve) {
	size_t i, bits;

	if (NULL == point || NULL == mult_data || NULL == d || NULL == curve)
		return (EINVAL);
	if (0 != bn_is_one(d)) { /* Return orig point. */
		BN_RET_ON_ERR(ec_point_assign(point, &mult_data->pt_arr[0]));
		return (0);
	}
	point->infinity = 1; /* "Zeroize" point. */ /* R←(1,1,0) */
	if (0 != bn_is_zero(d) ||
	    0 != ec_point_is_at_infinity(&mult_data->pt_arr[0]))
		return (0);
	bits = bn_calc_bits(d);
	for (i = 0; i < bits; i ++) {
		if (0 != bn_is_bit_set(d, i))
			BN_RET_ON_ERR(ec_point_affine_add(point,
			    &mult_data->pt_arr[i], curve));
	}
	return (0);
}


/* Precompute the array of fixed base point for sliding window method. */
static inline int 
ec_point_affine_fpx_sl_win_mult_precompute(size_t wnd_bits, ec_point_p point,
    ec_curve_p curve, ec_point_fpx_sl_win_mult_data_p mult_data) {
	size_t i, pt_cnt;

	if (0 == wnd_bits || NULL == point || NULL == curve || NULL == mult_data)
		return (EINVAL);
	if (0 != (wnd_bits & (wnd_bits - 1)))
		return (EINVAL); /* Must be power of 2. */
	if (0 != ec_point_is_at_infinity(point)) { /* R←(1,1,0) */
		mult_data->wnd_bits = 0; /* Will return point at infinity. */
		return (0);
	}
	pt_cnt = ((((size_t)1) << wnd_bits) - 1);
	mult_data->wnd_bits = wnd_bits;
	/* Set all array points to 'point' */
	for (i = 0; i < pt_cnt; i ++) {
		BN_RET_ON_ERR(ec_point_init(&mult_data->pt_arr[i], curve->m));
		BN_RET_ON_ERR(ec_point_assign(&mult_data->pt_arr[i], point));
	}
	for (i = 1; i < pt_cnt; i ++)
		BN_RET_ON_ERR(ec_point_affine_add(&mult_data->pt_arr[i],
		    &mult_data->pt_arr[(i - 1)], curve));
	return (0);
}

static inline int
ec_point_affine_fpx_sl_win_mult(ec_point_p point,
    ec_point_fpx_sl_win_mult_data_p mult_data, bn_p d, ec_curve_p curve) {
	ssize_t i, j;
	size_t k;
	bn_digit_t windex, mask;

	if (NULL == point || NULL == mult_data || NULL == d || NULL == curve)
		return (EINVAL);
	if (0 != bn_is_one(d) && 0 != mult_data->wnd_bits) { /* Return orig point. */
		BN_RET_ON_ERR(ec_point_assign(point, &mult_data->pt_arr[0]));
		return (0);
	}
	point->infinity = 1; /* "Zeroize" point. */ /* R←(1,1,0) */
	if (0 != bn_is_zero(d) || 0 == mult_data->wnd_bits) /* ec_point_is_at_infinity */
		return (0);
	mask = ((((bn_digit_t)1) << mult_data->wnd_bits) - 1);
	for (i = (d->digits - 1); i >= 0; i --) {
		for (j = ((BN_DIGIT_BITS / mult_data->wnd_bits) - 1); j >= 0; j --) {
			for (k = 0; k < mult_data->wnd_bits; k ++)
				BN_RET_ON_ERR(ec_point_affine_add(point, point, curve));
			windex = (mask & (d->num[i] >> (j * mult_data->wnd_bits)));
			if (0 == windex)
				continue;
			BN_RET_ON_ERR(ec_point_affine_add(point,
			    &mult_data->pt_arr[(windex - 1)], curve));
		}
	}
	return (0);
}


/* COMB 1t. */
/* Precompute the array of fixed base point for COMB1t method. */
static inline int
ec_point_affine_fpx_comb1t_mult_precompute(size_t wnd_bits, ec_point_p point,
    ec_curve_p curve, ec_point_fpx_comb1t_mult_data_p mult_data) {
	size_t i, j, iidx;

	if (0 == wnd_bits || NULL == point || NULL == curve || NULL == mult_data)
		return (EINVAL);
	if (0 != ec_point_is_at_infinity(point)) { /* R←(1,1,0) */
		mult_data->wnd_bits = 0; /* Will return point at infinity. */
		return (0);
	}
	mult_data->wnd_bits = wnd_bits;
	/* Calculate windows count. (d = t/w) */
	mult_data->wnd_count = ((curve->m / wnd_bits) +
	    ((0 != (curve->m % wnd_bits)) ? 1 : 0));
	/* Calc add data. */
	BN_RET_ON_ERR(ec_point_init(&mult_data->pt_add_arr[0], curve->m));
	BN_RET_ON_ERR(ec_point_assign(&mult_data->pt_add_arr[0], point));
	for (i = 1; i < wnd_bits; i ++) {
		iidx = (1 << i);
		BN_RET_ON_ERR(ec_point_init(&mult_data->pt_add_arr[(iidx - 1)],
		    curve->m));
		BN_RET_ON_ERR(ec_point_assign(&mult_data->pt_add_arr[(iidx - 1)],
		    &mult_data->pt_add_arr[((1 << (i - 1)) - 1)]));
		BN_RET_ON_ERR(ec_point_affine_dbl_n(&mult_data->pt_add_arr[(iidx - 1)],
		    mult_data->wnd_count, curve));
		for (j = 1; j < iidx; j ++) {
			BN_RET_ON_ERR(ec_point_init(
			    &mult_data->pt_add_arr[(iidx + j - 1)], curve->m));
			BN_RET_ON_ERR(ec_point_assign(
			    &mult_data->pt_add_arr[(iidx + j - 1)],
			    &mult_data->pt_add_arr[(j - 1)]));
			BN_RET_ON_ERR(ec_point_affine_add(
			    &mult_data->pt_add_arr[(iidx + j - 1)],
			    &mult_data->pt_add_arr[(iidx - 1)], curve));
		}
	}
	return (0);
}

static inline int
ec_point_affine_fpx_comb1t_mult(ec_point_p point,
    ec_point_fpx_comb1t_mult_data_p mult_data, bn_p d, ec_curve_p curve) {
	ssize_t i, bit_off;
	bn_digit_t windex;

	if (NULL == point || NULL == mult_data || NULL == d || NULL == curve)
		return (EINVAL);
	if (0 != bn_is_one(d) && 0 != mult_data->wnd_bits) { /* Return orig point. */
		BN_RET_ON_ERR(ec_point_assign(point, &mult_data->pt_add_arr[0]));
		return (0);
	}
	point->infinity = 1; /* "Zeroize" point. */ /* R←(1,1,0) */
	if (0 != bn_is_zero(d) || 0 == mult_data->wnd_bits) /* ec_point_is_at_infinity */
		return (0);
	/* XXX: dont know how to mult. */
	if ((d->digits * BN_DIGIT_BITS) > curve->m) {
		BN_RET_ON_ERR(ec_point_assign(point, &mult_data->pt_add_arr[0]));
		BN_RET_ON_ERR(ec_point_affine_bin_mult(point, d, curve));
		return (0);
	}
	bit_off = ((mult_data->wnd_bits * mult_data->wnd_count) - 1);
	for (i = (mult_data->wnd_count - 1); i >= 0; i --, bit_off --) {
		BN_RET_ON_ERR(ec_point_affine_add(point, point, curve));
		/* 1. Add table. */
		windex = bn_combo_column_get(d, bit_off,
		    mult_data->wnd_bits, mult_data->wnd_count);
		if (0 != windex) {
			BN_RET_ON_ERR(ec_point_affine_add(point,
			    &mult_data->pt_add_arr[(windex - 1)], curve));
		}
	}
	return (0);
}


/* COMB 2t. */
/* Precompute the array of fixed base point for COMB2t method. */
static inline int
ec_point_affine_fpx_comb2t_mult_precompute(size_t wnd_bits, ec_point_p point,
    ec_curve_p curve, ec_point_fpx_comb2t_mult_data_p mult_data) {
	size_t i, pt_cnt;

	if (0 == wnd_bits || NULL == point || NULL == curve || NULL == mult_data)
		return (EINVAL);
	BN_RET_ON_ERR(ec_point_affine_fpx_comb1t_mult_precompute(wnd_bits,
	    point, curve, (ec_point_fpx_comb1t_mult_data_p)mult_data));
	if (0 == mult_data->wnd_bits) /* ec_point_is_at_infinity */
		return (0);
	pt_cnt = ((((size_t)1) << wnd_bits) - 1);
	/* Calculate windows count. (e = d/2) */
	mult_data->e_count = ((mult_data->wnd_count / 2) +
	    ((0 != (mult_data->wnd_count % 2)) ? 1 : 0));
	/* Calc dbl data. */
	for (i = 0; i < pt_cnt; i ++) {
		BN_RET_ON_ERR(ec_point_init(&mult_data->pt_dbl_arr[i], curve->m));
		BN_RET_ON_ERR(ec_point_assign(&mult_data->pt_dbl_arr[i],
		    &mult_data->pt_add_arr[i]));
		BN_RET_ON_ERR(ec_point_affine_dbl_n(&mult_data->pt_dbl_arr[i],
		    mult_data->e_count, curve));
	}
	return (0);
}

static inline int
ec_point_affine_fpx_comb2t_mult(ec_point_p point,
    ec_point_fpx_comb2t_mult_data_p mult_data, bn_p d, ec_curve_p curve) {
	ssize_t i, bit_off;
	bn_digit_t windex;

	if (NULL == point || NULL == mult_data || NULL == d || NULL == curve)
		return (EINVAL);
	if (0 != bn_is_one(d) && 0 != mult_data->wnd_bits) { /* Return orig point. */
		BN_RET_ON_ERR(ec_point_assign(point, &mult_data->pt_add_arr[0]));
		return (0);
	}
	point->infinity = 1; /* "Zeroize" point. */ /* R←(1,1,0) */
	if (0 != bn_is_zero(d) || 0 == mult_data->wnd_bits) /* ec_point_proj_is_at_infinity */
		return (0);
	/* XXX: dont know how to mult. */
	if ((d->digits * BN_DIGIT_BITS) > curve->m) {
		BN_RET_ON_ERR(ec_point_assign(point, &mult_data->pt_add_arr[0]));
		BN_RET_ON_ERR(ec_point_affine_bin_mult(point, d, curve));
		return (0);
	}
	bit_off = (((mult_data->wnd_bits - 1) * mult_data->wnd_count) +
	    (mult_data->e_count - 1));
	for (i = (mult_data->e_count - 1); i >= 0; i --, bit_off --) {
		BN_RET_ON_ERR(ec_point_affine_add(point, point, curve));
		/* 1. Add table. */
		windex = bn_combo_column_get(d, bit_off,
		    mult_data->wnd_bits, mult_data->wnd_count);
		if (0 != windex) {
			BN_RET_ON_ERR(ec_point_affine_add(point,
			    &mult_data->pt_add_arr[(windex - 1)], curve));
		}
		/* 2. Dbl table. */
		if ((i + mult_data->e_count) >= mult_data->wnd_count)
			continue;
		windex = bn_combo_column_get(d, (bit_off + mult_data->e_count),
		    mult_data->wnd_bits, mult_data->wnd_count);
		if (0 == windex)
			continue;
		BN_RET_ON_ERR(ec_point_affine_add(point,
		    &mult_data->pt_dbl_arr[(windex - 1)], curve));
	}
	return (0);
}



/* res = a*ad + b*bd */
static inline int
ec_point_affine_bin_twin_mult(ec_point_p a, bn_p ad, ec_point_p b, bn_p bd,
    ec_curve_p curve, ec_point_p res) {
	ec_point_t tmA, tmB;

	if (NULL == a || NULL == ad || NULL == b || NULL == bd || NULL == curve ||
	    NULL == res)
		return (EINVAL);
	BN_RET_ON_ERR(ec_point_init(&tmA, curve->m));
	BN_RET_ON_ERR(ec_point_init(&tmB, curve->m));
	BN_RET_ON_ERR(ec_point_assign(&tmA, a));
	BN_RET_ON_ERR(ec_point_affine_bin_mult(&tmA, ad, curve));
	BN_RET_ON_ERR(ec_point_assign(&tmB, b));
	BN_RET_ON_ERR(ec_point_affine_bin_mult(&tmB, bd, curve));
	BN_RET_ON_ERR(ec_point_affine_add(&tmA, &tmB, curve));
	BN_RET_ON_ERR(ec_point_assign(res, &tmA));
	return (0);
}

#ifndef EC_USE_PROJECTIVE
static inline int
ec_point_affine_fpx_unkpt_twin_mult_bp(bn_p Gd, ec_point_p b, bn_p bd,
    ec_curve_p curve, ec_point_p res) {
	ec_point_t tmA, tmB;

	if (NULL == Gd || NULL == b || NULL == bd || NULL == curve || NULL == res)
		return (EINVAL);
	BN_RET_ON_ERR(ec_point_init(&tmA, curve->m));
	BN_RET_ON_ERR(ec_point_init(&tmB, curve->m));

#if EC_PF_FXP_MULT_ALGO != EC_PF_FXP_MULT_ALGO_BIN
	BN_RET_ON_ERR(ec_point_affine_fpx_mult(&tmA, &curve->G_fpx_mult_data, Gd, curve));
#else
	BN_RET_ON_ERR(ec_point_assign(&tmA, &(curve)->G));
	BN_RET_ON_ERR(ec_point_affine_bin_mult(&tmA, Gd, curve));
#endif

#if EC_PF_UNKPT_MULT_ALGO != EC_PF_UNKPT_MULT_ALGO_BIN
	ec_point_unkpt_mult_data_t mult_data;

	BN_RET_ON_ERR(ec_point_affine_unkpt_mult_precompute(
	    EC_PF_UNKPT_MULT_WIN_BITS, b, curve, &mult_data));
	BN_RET_ON_ERR(ec_point_affine_unkpt_mult(&tmB, &mult_data, bd, curve));
#else /* Unknown point bin mult. */
	BN_RET_ON_ERR(ec_point_assign(&tmB, b));
	BN_RET_ON_ERR(ec_point_affine_bin_mult(&tmB, bd, curve));
#endif

	BN_RET_ON_ERR(ec_point_affine_add(&tmA, &tmB, curve));
	BN_RET_ON_ERR(ec_point_assign(res, &tmA));

	return (0);
}
#endif

static inline int
ec_point_affine_joint_twin_mult(ec_point_p a, bn_p ad, ec_point_p b, bn_p bd,
    ec_curve_p curve, ec_point_p res) {
	size_t len, offset;
	ssize_t i, idx;
	ec_point_t tbl[4];
	int8_t jsf[BN_BIT_LEN];

	if (NULL == a || NULL == ad || NULL == b || NULL == bd || NULL == curve ||
	    NULL == res)
		return (EINVAL);

	/* Init table. */
	for (i = 0; i < 4; i ++)
		BN_RET_ON_ERR(ec_point_init(&tbl[i], curve->m));
	/* b */
	BN_RET_ON_ERR(ec_point_assign(&tbl[0], b));
	/* a */
	BN_RET_ON_ERR(ec_point_assign(&tbl[1], a));
	/* Calc: a + b */
	BN_RET_ON_ERR(ec_point_assign(&tbl[2], a));
	BN_RET_ON_ERR(ec_point_affine_add(&tbl[2], b, curve));
	/* Calc: a - b */
	BN_RET_ON_ERR(ec_point_assign(&tbl[3], a));
	BN_RET_ON_ERR(ec_point_affine_sub(&tbl[3], b, curve));

	/* Calc Joint sparse form. */
	BN_RET_ON_ERR(bn_calc_jsf(ad, bd, sizeof(jsf), jsf, &len, &offset));

	res->infinity = 1; /* "Zeroize" point. */
	for (i = (len - 1); i >= 0; i --) {
		BN_RET_ON_ERR(ec_point_affine_add(res, res, curve));
		idx = ((jsf[i] * 2) + jsf[(i + offset)]);
		if (0 != jsf[i] && jsf[i] == -jsf[(i + offset)]) {
			if (idx < 0) {
				idx = - 4;
			} else {
				idx = 4;
			}
		}
		if (0 == idx)
			continue;
		if (idx < 0) {
			BN_RET_ON_ERR(ec_point_affine_sub(res, &tbl[((-idx) - 1)],
			    curve));
		} else {
			BN_RET_ON_ERR(ec_point_affine_add(res, &tbl[(idx - 1)],
			    curve));
		}
	}
	return (0);
}



/* Mult unknown point and digit. */
static inline int
ec_point_unknown_pt_mult(ec_point_p point, bn_p d, ec_curve_p curve) {

#if EC_PF_UNKPT_MULT_ALGO == EC_PF_UNKPT_MULT_ALGO_BIN
	BN_RET_ON_ERR(ec_point_bin_mult(point, d, curve));
#else
	ec_pt_unkpt_mult_data_t mult_data;

	BN_RET_ON_ERR(ec_point_unkpt_mult_precompute(EC_PF_UNKPT_MULT_WIN_BITS,
	    point, curve, &mult_data));
	BN_RET_ON_ERR(ec_point_unkpt_mult(point, &mult_data, d, curve));
#endif /* EC_PF_FXP_MULT_ALGO */
	return (0);
}

/* Mult fixed base point and digit. */
static inline int
ec_point_mult_bp(bn_p d, ec_curve_p curve, ec_point_p res) {

#if EC_PF_FXP_MULT_ALGO == EC_PF_FXP_MULT_ALGO_BIN
	BN_RET_ON_ERR(ec_point_assign(res, &curve->G));
	BN_RET_ON_ERR(ec_point_bin_mult(res, d, curve));
#else
	BN_RET_ON_ERR(ec_point_fpx_mult(res, &curve->G_fpx_mult_data, d, curve));
#endif /* EC_PF_FXP_MULT_ALGO */
	return (0);
}

/* Mult fixed base point and digit. */
static inline int
ec_point_twin_mult_bp(bn_p Gd, ec_point_p b, bn_p bd, ec_curve_p curve,
    ec_point_p res) {
#if EC_PF_TWIN_MULT_ALGO == EC_PF_TWIN_MULT_ALGO_FXP_UNKPT
	BN_RET_ON_ERR(ec_point_fpx_unkpt_twin_mult_bp(Gd, b, bd, curve, res));
#else
	BN_RET_ON_ERR(ec_point_twin_mult(&curve->G, Gd, b, bd, curve, res));
#endif /* EC_PF_TWIN_MULT_ALGO */
	return (0);
}





/* Check whether the affine point 'point' is on the curve 'curve'. */
/* Return zero if point on curve. */
/* XXX: IEEE P1363 more srong cheks? */
static inline int
ec_point_check_affine(ec_point_p point, ec_curve_p curve) {
	size_t bits;
	bn_t x, y;

	if (NULL == point || NULL == curve)
		return (EINVAL);
	/* Check that x and y are integers in the interval [0, p − 1]. */
	if (bn_cmp(&curve->p, &point->x) <= 0)
		return (-1);
	if (bn_cmp(&curve->p, &point->y) <= 0)
		return (-1);
	/* Check that y^2 ≡ (x^3 + a*x + b) (mod p). */
	/* Double size. */
	bits = EC_CURVE_CALC_BITS_DBL(curve);
	/* Init */
	BN_RET_ON_ERR(bn_init(&x, bits));
	BN_RET_ON_ERR(bn_init(&y, bits));
	/* Calc. */
	BN_RET_ON_ERR(bn_assign(&x, &point->x));
	BN_RET_ON_ERR(bn_mod_exp_digit(&x, 3, &curve->p, &curve->p_mod_rd_data)); /* x^3 */
	BN_RET_ON_ERR(bn_mod_add(&x, &curve->b, &curve->p, &curve->p_mod_rd_data)); /* (x^3) + b */
	if (0 != (EC_CURVE_FLAG_A_M3 & curve->flags)) {
		BN_RET_ON_ERR(bn_assign(&y, &point->x));
		BN_RET_ON_ERR(bn_mod_mult_digit(&y, 3, &curve->p, &curve->p_mod_rd_data)); /* 3*x */
		BN_RET_ON_ERR(bn_mod_sub(&x, &y, &curve->p, &curve->p_mod_rd_data)); /* ((x^3) + b) - 3*x */
	} else {
		BN_RET_ON_ERR(bn_assign(&y, &curve->a));
		BN_RET_ON_ERR(bn_mod_mult(&y, &point->x, &curve->p, &curve->p_mod_rd_data)); /* a*x */
		BN_RET_ON_ERR(bn_mod_add(&x, &y, &curve->p, &curve->p_mod_rd_data)); /* ((x^3) + b) + a*x */
	}
	BN_RET_ON_ERR(bn_assign(&y, &point->y));
	BN_RET_ON_ERR(bn_mod_square(&y, &curve->p, &curve->p_mod_rd_data)); /* y^2 */
	if (0 != bn_cmp(&y, &x))
		return (-1);
	return (0);
}


/* Checks that Q is a scalar multiple of G:
 * nG = O (Point at infinity on an elliptic curve).
 */
static inline int
ec_point_check_scalar_mult(ec_point_p point, ec_curve_p curve) {
	ec_point_t Q;

	if (NULL == point || NULL == curve)
		return (EINVAL);
	BN_RET_ON_ERR(ec_point_init(&Q, curve->m));
	BN_RET_ON_ERR(ec_point_assign(&Q, point));
	BN_RET_ON_ERR(ec_point_unknown_pt_mult(&Q, &curve->n, curve));
	if (0 == Q.infinity)
		return (-1);
	return (0);
}

static inline int
ec_point_check_as_pub_key(ec_point_p point, ec_curve_p curve) {

	/* Check that Gy^2 ≡ (Gx^3 + a*Gx + b) (mod p). */
	BN_RET_ON_ERR(ec_point_check_affine(point, curve));
	
	/* SEC 1 Ver. 2.0: 3.2 Elliptic Curve Key Pairs, p 25:
	 * ...it may not be necessary to compute the point nQ.
	 * For example, if h = 1, then nQ = O is implied by the checks
	 * in Steps 2 and 3, because this property holds for all points Q ∈ E
	 */
	/* Check that nG = O (Point at infinity on an elliptic curve). */
	BN_RET_ON_ERR(ec_point_check_scalar_mult(point, curve));
	return (0);
}

/* Calc and return: y ≡ sqrt((x^3 + a*x + b)) (mod p). */
/* y_is_odd - from key decompress: 0 or 1; 2 - auto, but slower. */
static inline int
ec_point_restore_y_by_x(int y_is_odd, ec_point_p point, ec_curve_p curve) {
	int error;
	size_t bits;
	bn_t tm1, tm2;

	if (NULL == curve || NULL == point)
		return (EINVAL);
	/* Double size + 1 digit. */
	bits = EC_CURVE_CALC_BITS_DBL(curve);
	/* Init */
	BN_RET_ON_ERR(bn_init(&tm1, bits));
	BN_RET_ON_ERR(bn_init(&tm2, bits));
	/* tm1 = (x^3 + a*x + b) (mod p). */
	BN_RET_ON_ERR(bn_assign(&tm1, &point->x)); /* Assign x. */
	BN_RET_ON_ERR(bn_mod_exp_digit(&tm1, 3, &curve->p, &curve->p_mod_rd_data)); /* x^3 */
	BN_RET_ON_ERR(bn_mod_add(&tm1, &curve->b, &curve->p, &curve->p_mod_rd_data)); /* (x^3) + b */
	if (0 != (EC_CURVE_FLAG_A_M3 & curve->flags)) {
		BN_RET_ON_ERR(bn_assign(&tm2, &point->x)); /* Assign x. */
		BN_RET_ON_ERR(bn_mod_mult_digit(&tm2, 3, &curve->p, &curve->p_mod_rd_data)); /* 3*x */
		BN_RET_ON_ERR(bn_mod_sub(&tm1, &tm2, &curve->p, &curve->p_mod_rd_data)); /* ((x^3) + b) - 3*x */
	} else {
		BN_RET_ON_ERR(bn_assign(&tm2, &curve->a)); /* Assign a. */
		BN_RET_ON_ERR(bn_mod_mult(&tm2, &point->x, &curve->p, &curve->p_mod_rd_data)); /* a*x */
		BN_RET_ON_ERR(bn_mod_add(&tm1, &tm2, &curve->p, &curve->p_mod_rd_data)); /* ((x^3) + b) + a*x */
	}
	BN_RET_ON_ERR(bn_mod_sqrt(&tm1, &curve->p, &curve->p_mod_rd_data)); /* tm1 = sqrt((x^3 + a*x + b)) (mod p) */

	/* b ≡ pub_key_x[0] (mod 2) */
	if (2 == y_is_odd ||
	    (0 != bn_is_odd(&tm1) && 1 == y_is_odd) ||
	    (0 == bn_is_odd(&tm1) && 0 == y_is_odd)) {
		BN_RET_ON_ERR(bn_assign(&point->y, &tm1)); /* Assign y. */
#ifdef EC_DISABLE_PUB_KEY_CHK
		if (2 != y_is_odd)
			return (0);
#endif
		error = ec_point_check_as_pub_key(point, curve); /* Check y. */
		if (0 != error) { /* y not valid. */
			if (2 == y_is_odd) /* Try invert. */
				goto invert_y;
			BN_RET_ON_ERR(error);
		}
	} else { /* y = p − b */
invert_y:
		BN_RET_ON_ERR(bn_assign(&tm2, &curve->p)); /* Assign p. */
		BN_RET_ON_ERR(bn_mod_sub(&tm2, &tm1, &curve->p, &curve->p_mod_rd_data)); /* p - b */
		BN_RET_ON_ERR(bn_assign(&point->y, &tm2)); /* Assign y. */
		BN_RET_ON_ERR(ec_point_check_as_pub_key__int(point, curve)); /* Check y. */
	}
	return (0);
}


/* SEC 1 Ver. 2.0 + X9.62-1998 cheks. */
static inline int
ec_curve_validate(ec_curve_p curve, int *warnings) {
	int wrngs = 0;
	size_t j, bits;
	bn_t a, b, tm;

	if (NULL == curve)
		return (EINVAL);
	/* Double size + 1 digit. */
	bits = EC_CURVE_CALC_BITS_DBL(curve);;
	/* Init */
	BN_RET_ON_ERR(bn_init(&a, bits));
	BN_RET_ON_ERR(bn_init(&b, bits));
	BN_RET_ON_ERR(bn_init(&tm, bits));
	/* Check for flags.*/
	if (0 != (EC_CURVE_FLAG_A_M3 & curve->flags)) {
		BN_RET_ON_ERR(bn_assign(&a, &curve->p));
		bn_sub_digit(&a, 3, NULL);
		if (0 != bn_cmp(&a, &curve->a))
			return (-1);
	}
	/* 1. Check that p is an odd prime. */

	/* 2. Check that a, b, Gx, and Gy are integers in the interval [0, p − 1]. */
	if (bn_cmp(&curve->p, &curve->a) <= 0)
		return (-1);
	if (bn_cmp(&curve->p, &curve->b) <= 0)
		return (-1);
	if (bn_cmp(&curve->p, &curve->G.x) <= 0)
		return (-1);
	if (bn_cmp(&curve->p, &curve->G.y) <= 0)
		return (-1);

	/* 3. Check that (4*a^3 + 27*b^2) !≡ 0 (mod p). */
	/* Calculate. */
	BN_RET_ON_ERR(bn_assign(&b, &curve->b));
	BN_RET_ON_ERR(bn_mod_square(&b, &curve->p, &curve->p_mod_rd_data));
	BN_RET_ON_ERR(bn_mod_mult_digit(&b, 27, &curve->p, &curve->p_mod_rd_data));
	if (0 != (EC_CURVE_FLAG_A_M3 & curve->flags)) {
		BN_RET_ON_ERR(bn_assign_digit(&a, 108)); /* 4*(-3)^3 */
		BN_RET_ON_ERR(bn_mod_sub(&b, &a, &curve->p, &curve->p_mod_rd_data));
	} else {
		BN_RET_ON_ERR(bn_assign(&a, &curve->a));
		BN_RET_ON_ERR(bn_mod_exp_digit(&a, 3, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_mult_digit(&a, 4, &curve->p, &curve->p_mod_rd_data));
		BN_RET_ON_ERR(bn_mod_add(&b, &a, &curve->p, &curve->p_mod_rd_data));
	}
	if (0 != bn_is_zero(&b))
		return (-1);

	/* 4. Check that Gy^2 ≡ (Gx^3 + a*Gx + b) (mod p). */
	BN_RET_ON_ERR(ec_point_check_affine(&curve->G, curve));

	/* 5. Check that n is prime. 
	 * X9.62-1998: And that n > 2^160 and n > 4√p.
	 */
	// XXX n is prime?
	/* X9.62-1998: n > 4√p */
	BN_RET_ON_ERR(bn_assign(&tm, &curve->p));
	BN_RET_ON_ERR(bn_sqrt(&tm)); /* √p */
	BN_RET_ON_ERR(bn_mult_digit(&tm, 4)); /* 4 * √p */
	if (bn_cmp(&curve->n, &tm) <= 0)
		return (-1);
	/* X9.62-1998: n > 2^160 */
	/* According to American Bankers Association X9.62-1998
	 * all curves were n bits count is less than 160 is insecure.
	 */
	if (curve->m > 160) {
		BN_RET_ON_ERR(bn_assign_2exp(&tm, 160));
		if (bn_cmp(&curve->n, &tm) <= 0)
			return (-1);
	} else {
		wrngs ++;
	}

	/* 6. Check that h ≤ 2^(t/8), and that h = [(√p + 1)^2 / n]. */
	/* h ≤ 2^(t/8) */
	BN_RET_ON_ERR(bn_assign_digit(&a, curve->h));
	BN_RET_ON_ERR(bn_assign_2exp(&b, (curve->t / 8)));
	if (bn_cmp(&a, &b) > 0)
		return (-1);
	/* h = [(√p + 1)^2 / n] */
	BN_RET_ON_ERR(bn_assign(&tm, &curve->p));
	BN_RET_ON_ERR(bn_sqrt(&tm)); /* √p */
	bn_add_digit(&tm, 1, NULL); /* √p + 1 */
	BN_RET_ON_ERR(bn_square(&tm)); /* (√p + 1)^2 */
	BN_RET_ON_ERR(bn_div(&tm, &curve->n, NULL)); /* (√p + 1)^2 / n */
	BN_RET_ON_ERR(bn_assign_digit(&a, curve->h));
	if (0 != bn_cmp(&a, &tm)) {
		/* Some NIST curves fail this check. */
		//return (-1);
		wrngs ++;
	}

	/* 7. Check that nG = O (Point at infinity on an elliptic curve). */
	BN_RET_ON_ERR(ec_point_check_scalar_mult(&curve->G, curve));

	/* 8. Check that p^B !≡ 1(mod n) for all 1 ≤ B < 100, and that n != p. */
	if (0 == bn_cmp(&curve->n, &curve->p)) /* Anomalous Condition check. */
		return (-1);
	for (j = 1; j < 100; j ++) { /* MOV Condition check. */
		BN_RET_ON_ERR(bn_assign(&tm, &curve->p));
		BN_RET_ON_ERR(bn_mod_exp_digit(&tm, j, &curve->n, &curve->n_mod_rd_data));
		if (0 != bn_is_one(&tm))
			return (-1);
	}

	/*
	 * X9.62-1998
	 * If the elliptic curve was randomly generated in accordance with
	 * Annex A.3.3, verify that SEED is a bit string of length at least
	 * 160 bits, and that a and b were suitably derived from SEED.
	 */
	if (NULL != warnings)
		(*warnings) = wrngs;
	return (0);
}



#endif /* __MATH_EC_H__ */
