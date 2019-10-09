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


/* little-endian */
/* Some tricks from: http://graphics.stanford.edu/~seander/bithacks.html
 * and: http://www.hackersdelight.org/
 */

#ifndef __MATH_BIG_NUM_H__
#define __MATH_BIG_NUM_H__

#ifdef _WINDOWS
#	define EINVAL		ERROR_INVALID_PARAMETER
#	define EOVERFLOW	ERROR_INSUFFICIENT_BUFFER
#	define int8_t		signed char
#	define uint8_t		unsigned char
#	define uint16_t		WORD
#	define uint32_t		DWORD
#	define uint64_t		DWORDLONG
#	define size_t		SIZE_T
#	define ssize_t		SSIZE_T
#	define __unused
#else
#	include <sys/types.h>
#	include <inttypes.h>
#	include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strnlen, strerror... */
#	include <stdio.h> /* snprintf, fprintf */
#endif


#ifndef BN_BIT_LEN
#	define BN_BIT_LEN	2048
#endif

#ifndef BN_DIGIT_BIT_CNT
#	define BN_DIGIT_BIT_CNT 64
#	define BN_CC_MULL_DIV
#endif

/* MOD reduce algo. */
#define BN_MOD_REDUCE_ALGO_BASIC	0
#define BN_MOD_REDUCE_ALGO_BARRETT	1

#ifndef BN_MOD_REDUCE_ALGO
#	define BN_MOD_REDUCE_ALGO	BN_MOD_REDUCE_ALGO_BASIC
#endif



#if BN_DIGIT_BIT_CNT == 128
	typedef __uint128_t	bn_digit_t;
#	undef BN_CC_MULL_DIV
	//typedef __uint256_t	bn_ddigit_t;
#elif BN_DIGIT_BIT_CNT == 64
	typedef uint64_t	bn_digit_t;
#	ifdef BN_CC_MULL_DIV
		typedef __uint128_t	bn_ddigit_t;
#	endif
#elif BN_DIGIT_BIT_CNT == 32
	typedef uint32_t	bn_digit_t;
#	ifdef BN_CC_MULL_DIV
		typedef uint64_t	bn_ddigit_t;
#	endif
#elif BN_DIGIT_BIT_CNT == 16
	typedef uint16_t	bn_digit_t;
#	ifdef BN_CC_MULL_DIV
		typedef uint32_t	bn_ddigit_t;
#	endif
#elif BN_DIGIT_BIT_CNT == 8
	typedef uint8_t		bn_digit_t;
#	ifdef BN_CC_MULL_DIV
		typedef uint16_t	bn_ddigit_t;
#	endif
#endif

#define BN_LEN		(BN_BIT_LEN / 8)

/* Length of digit in bytes */
#define BN_DIGIT_SIZE	sizeof(bn_digit_t)

/* Length of digit in bits */
#define BN_DIGIT_BITS	(BN_DIGIT_SIZE * 8)

/* High digir bit */
#define BN_DIGIT_HI_BIT	(((bn_digit_t)1) << (BN_DIGIT_BITS - 1))

/* Maximum value of digit */
#define BN_MAX_DIGIT	((bn_digit_t)~0)

/* Maximum length in digits */
#define BN_MAX_DIGITS	(BN_BIT_LEN / BN_DIGIT_BITS)

/* Swap a and b */
#define bn_digit_swap(__a, __b)						\
{									\
	register bn_digit_t __t = (__a);				\
	(__a) = (__b);							\
	(__b) = __t;							\
}

#define bn_swap_ptr(__a, __b)						\
{									\
	register bn_p __t = (__a);					\
	(__a) = (__b);							\
	(__b) = __t;							\
}


#if defined(DEBUG) || defined(_DEBUG)

#ifdef _WINDOWS
#define BN_RET_ON_ERR(__err)						\
{									\
	int ret_error = (__err);					\
	if (0 != ret_error) {						\
		CHAR err_msg_buf[128];					\
		wsprintfA(err_msg_buf, "%s:%i %s: error = %i\r\n",	\
		    __FILE__, __LINE__, __FUNCTION__, ret_error);	\
		OutputDebugStringA(err_msg_buf);			\
		return (ret_error);					\
	}								\
}
#else
#define BN_RET_ON_ERR(__err)						\
{									\
	int ret_error = (__err);					\
	if (0 != ret_error) {						\
		fprintf(stderr, "%s:%i %s: error = %i\r\n",		\
		    __FILE__, __LINE__, __FUNCTION__, ret_error);	\
		return (ret_error);					\
	}								\
}
#endif /* _WINDOWS */

#else /* NODEBUG */

#define BN_RET_ON_ERR(__err)						\
{									\
	int ret_error = (__err);					\
	if (0 != ret_error)						\
		return (ret_error);					\
}

#endif /* _DEBUG */


#ifdef BN_USE_SSE
#	include <xmmintrin.h> /* SSE */
#	include <emmintrin.h> /* SSE2 */
#	include <pmmintrin.h> /* SSE3 */
#	include <tmmintrin.h> /* SSSE3 */
#	include <smmintrin.h> /* SSE4.1 */
#	include <nmmintrin.h> /* SSE4.2 */
#	define BN_PREFETCH(__prt)	_mm_prefetch((const char*)(__prt), _MM_HINT_T2) //_MM_HINT_NTA
#elif defined(__clang__) || defined(__GNUC__) /* NO: BN_USE_SSE */
#	define BN_PREFETCH(__prt)	__builtin_prefetch((__prt), 0, 0)
#else /* NO: BN_USE_SSE || __clang__ || __GNUC__ */
#	define BN_PREFETCH(__prt)
#endif /* BN_USE_SSE || __clang__ || __GNUC__ */

#define BN_PREFETCH_BN_DATA(__bn)		BN_PREFETCH(((const char*)(__bn)->num))
#define BN_PREFETCH_DIGITS(__digits, __count)	BN_PREFETCH(((const char*)(__digits)))
//#define BN_PREFETCH_DIGITS(digits, count)



#if defined(_MSC_VER) || defined(__INTEL_COMPILER)
#	define BN_ALIGN(__n) __declspec(align(__n)) /* DECLSPEC_ALIGN() */
#else /* GCC/clang */
#	define BN_ALIGN(__n) __attribute__((aligned(__n)))
#endif


#ifndef BN_NO_POINTERS_CHK
#	define BN_POINTER_CHK_EINVAL(__prt) if (NULL == (__prt)) return (EINVAL);
#else
#	define BN_POINTER_CHK_EINVAL(__prt)
#endif



typedef struct big_num_s {
	size_t		count; /* Digits count */
	size_t		digits; /* Non zero digits count */
BN_ALIGN(16) bn_digit_t	num[BN_MAX_DIGITS];
} bn_t, *bn_p;


typedef struct big_num_mod_reduce_data_s {
#if BN_MOD_REDUCE_ALGO == BN_MOD_REDUCE_ALGO_BASIC
	void	*none;
#elif BN_MOD_REDUCE_ALGO == BN_MOD_REDUCE_ALGO_BARRETT
	bn_t		Barrett; /* For Barrett Reduction. */
#endif
} bn_mod_rd_data_t, *bn_mod_rd_data_p;

#define BN_EXPORT_F_AUTO_SIZE	(1 << 0)



/*=========================== DIGIT OPERATIONS ===============================*/
/*--------------------------- OTHER OPERATIONS -------------------------------*/


static inline int
bn_digit_is_even(bn_digit_t digit) {

	return (0 == (digit & 1));
}
/* = bn_is_bit_set(bn, 0), = mod 2 (1 mod 2 = 1, 2 mod 2 = 0 ...) */
static inline int
bn_digit_is_odd(bn_digit_t digit) {

	return (0 != (digit & 1));
}

/* Returns: Population Count (Ones Count) = log2 = popcount. */
static inline size_t
bn_digit_bits(bn_digit_t digit) {
	register size_t n;
	register bn_digit_t reg = digit;

	if (0 == reg)
		return (reg);
	if (BN_MAX_DIGIT == reg)
		return (BN_DIGIT_BITS);
#if BN_DIGIT_BIT_CNT == 64
	reg -= ((reg >> 1) & 0x5555555555555555);
	reg = (((reg >> 2) & 0x3333333333333333) + (reg & 0x3333333333333333));
	reg = (((reg >> 4) + reg) & 0x0f0f0f0f0f0f0f0f);
	reg += (reg >> 8);
	reg += (reg >> 16);
	reg += (reg >> 32);
	n = (reg & 0x000000000000007f);
#elif BN_DIGIT_BIT_CNT == 32
	reg -= ((reg >> 1) & 0x55555555);
	reg = (((reg >> 2) & 0x33333333) + (reg & 0x33333333));
	reg = (((reg >> 4) + reg) & 0x0f0f0f0f);
	reg += (reg >> 8);
	reg += (reg >> 16);
	n = (reg & 0x0000003f);
	/* Note: an alternative to the last three executable lines above is:
	 * n = ((reg * 0x01010101) >> 24);
	 * if your machine has a fast multiplier (suggested by Jari Kirma). */
#elif BN_DIGIT_BIT_CNT == 16
	reg -= ((reg >> 1) & 0x5555);
	reg = (((reg >> 2) & 0x3333) + (reg & 0x3333));
	reg = (((reg >> 4) + reg) & 0x0f0f);
	reg += (reg >> 8);
	n = (reg & 0x001f);
#elif BN_DIGIT_BIT_CNT == 8
	reg -= ((reg >> 1) & 0x55);
	reg = (((reg >> 2) & 0x33) + (reg & 0x33));
	reg = (((reg >> 4) + reg) & 0x0f);
	n = (reg & 0x0f);
#else /* Original un optimized code. */
	for (n = 0; 0 != reg; reg >>= 1) {
		if (0 != (reg & 1)) {
			n ++;
		}
	}
#endif
	return (n);
}

/* Find first set (ffs) / find first one (ffo)
 * count trailing zeros (ctz) / number of trailing zeros (ntz) / Bit Scan Forward (bsf).
 * ctz(x) = ffs(x) − 1 (except for the zero input).
 * counts the number of zero bits preceding the most significant one bit.
 * 00000000000000001000000000001000 ( = 32776 )
 * ctz = 3, ffs = 4, clz = 16
 * see: http://en.wikipedia.org/wiki/Count_trailing_zeros
 */
static inline size_t
bn_digit_ctz(bn_digit_t digit) {
	register size_t n;
	register bn_digit_t reg = digit;

	if (0 == reg)
		return (BN_DIGIT_BITS);
	n = (BN_DIGIT_BITS - 1);
	reg &= (((bn_digit_t)0) - reg); /* BN_MAX_DIGIT + 1 = 0 */
#if BN_DIGIT_BIT_CNT == 64
	if (reg & 0x00000000ffffffff)
		n -= 32;
	if (reg & 0x0000ffff0000ffff)
		n -= 16;
	if (reg & 0x00ff00ff00ff00ff)
		n -= 8;
	if (reg & 0x0f0f0f0f0f0f0f0f)
		n -= 4;
	if (reg & 0x3333333333333333)
		n -= 2;
	if (reg & 0x5555555555555555)
		n --;
#elif BN_DIGIT_BIT_CNT == 32
	if (reg & 0x0000ffff)
		n -= 16;
	if (reg & 0x00ff00ff)
		n -= 8;
	if (reg & 0x0f0f0f0f)
		n -= 4;
	if (reg & 0x33333333)
		n -= 2;
	if (reg & 0x55555555)
		n --;
#elif BN_DIGIT_BIT_CNT == 16
	if (reg & 0x00ff)
		n -= 8;
	if (reg & 0x0f0f)
		n -= 4;
	if (reg & 0x3333)
		n -= 2;
	if (reg & 0x5555)
		n --;
#elif BN_DIGIT_BIT_CNT == 8
	if (reg & 0x0f)
		n -= 4;
	if (reg & 0x33)
		n -= 2;
	if (reg & 0x55)
		n --;
#else /* Original un optimized code. */
	for (n = 0; 0 == (reg & 1); n ++, reg >>= 1)
		;
#endif
	return (n);
}
static inline size_t
bn_digit_ffs(bn_digit_t digit) {

	if (0 == digit)
		return (0);
	return ((bn_digit_ctz(digit) + 1));
}
/* Count leading zeros (clz) / number of leading zeros (nlz),
 * which counts the number of zero bits preceding the most significant one bit.
 */
static inline size_t
bn_digit_clz(bn_digit_t digit) {
	register size_t n;
	register bn_digit_t reg = digit;

	if (0 == reg)
		return (BN_DIGIT_BITS);
	n = (BN_DIGIT_BITS - 1);
#if BN_DIGIT_BIT_CNT == 64
	if (reg & 0xffffffff00000000) {
		reg &= 0xffffffff00000000;
		n -= 32;
	}
	if (reg & 0xffff0000ffff0000) {
		reg &= 0xffff0000ffff0000;
		n -= 16;
	}
	if (reg & 0xff00ff00ff00ff00) {
		reg &= 0xff00ff00ff00ff00;
		n -= 8;
	}
	if (reg & 0xf0f0f0f0f0f0f0f0) {
		reg &= 0xf0f0f0f0f0f0f0f0;
		n -= 4;
	}
	if (reg & 0xcccccccccccccccc) {
		reg &= 0xcccccccccccccccc;
		n -= 2;
	}
	if (reg & 0xaaaaaaaaaaaaaaaa) {
		n --;
	}
#elif BN_DIGIT_BIT_CNT == 32
	if (reg & 0xffff0000) {
		reg &= 0xffff0000;
		n -= 16;
	}
	if (reg & 0xff00ff00) {
		reg &= 0xff00ff00;
		n -= 8;
	}
	if (reg & 0xf0f0f0f0) {
		reg &= 0xf0f0f0f0;
		n -= 4;
	}
	if (reg & 0xcccccccc) {
		reg &= 0xcccccccc;
		n -= 2;
	}
	if (reg & 0xaaaaaaaa) {
		n --;
	}
#elif BN_DIGIT_BIT_CNT == 16
	if (reg & 0xff00) {
		reg &= 0xff00;
		n -= 8;
	}
	if (reg & 0xf0f0) {
		reg &= 0xf0f0;
		n -= 4;
	}
	if (reg & 0xcccc) {
		reg &= 0xcccc;
		n -= 2;
	}
	if (reg & 0xaaaa) {
		n --;
	}
#elif BN_DIGIT_BIT_CNT == 8
	if (reg & 0xf0) {
		reg &= 0xf0;
		n -= 4;
	}
	if (reg & 0xcc) {
		reg &= 0xcc;
		n -= 2;
	}
	if (reg & 0xaa) {
		n --;
	}
#else /* Original un optimized code. */
	for (n = 0; 0 == (reg & BN_DIGIT_HI_BIT); n ++, reg <<= 1)
		;
#endif
	return (n);
}

/* Determining if an digit is a power of 2 */
#define bn_digit_is_pow2(digit)		((0 != digit && 0 == (digit & (digit - 1))))


/*-------------------------- ARITHMETIC OPERATIONS ---------------------------*/
/* 
 * Return result = a * b, where a and b are bn_digit_t~s.
 * The result is a hi and lo bn_digit_t~s
 * shift and add: http://en.wikipedia.org/wiki/Binary_multiplier
 */
static inline void
bn_digit_mult__int(bn_digit_t a, bn_digit_t b,
    bn_digit_t *result_lo, bn_digit_t *result_hi) {

#if defined(BN_CC_MULL_DIV)
	register bn_ddigit_t tm = (((bn_ddigit_t)a) * ((bn_ddigit_t)b));
	(*result_lo) = (tm & BN_MAX_DIGIT);
	(*result_hi) = (tm >> BN_DIGIT_BITS);
#else
	register bn_digit_t reg_res_hi = 0, reg_res_lo = 0;
	register bn_digit_t reg_multiplier, reg_multiplicand, reg_multiplicand_hi = 0;

	/* Speed optimizations. */
	if (0 == a || 0 == b) {
		(*result_lo) = 0;
		(*result_hi) = 0;
		return;
	}
	if (a > b) { /* Optimize cycles count. */
		reg_multiplicand = a;
		reg_multiplier = b;
	} else {
		reg_multiplicand = b;
		reg_multiplier = a;
	}
	if (1 == reg_multiplier) {
		reg_res_lo = reg_multiplicand;
		goto ok_exit;
	}
	if (0 != bn_digit_is_pow2(reg_multiplicand)) {
		reg_multiplicand_hi = bn_digit_ctz(reg_multiplicand);
		reg_res_lo = (reg_multiplier << reg_multiplicand_hi);
		reg_res_hi = (reg_multiplier >> (BN_DIGIT_BITS - reg_multiplicand_hi));
		goto ok_exit;
	}
	if (0 != bn_digit_is_pow2(reg_multiplier)) {
		reg_multiplicand_hi = bn_digit_ctz(reg_multiplier);
		reg_res_lo = (reg_multiplicand << reg_multiplicand_hi);
		reg_res_hi = (reg_multiplicand >> (BN_DIGIT_BITS - reg_multiplicand_hi));
		goto ok_exit;
	}
	/* Calculation. */
#if 1
	/* It is Knuth's Algorithm M from [Knu2] section 4.3.1.
	 * Derived from muldwu.c in the Hacker's Delight collection.
	 * http://www.hackersdelight.org/hdcodetxt/mont64.c.txt
	 * Montgomery Multiplication:
	 * http://www.hackersdelight.org/MontgomeryMultiplication.pdf */
	bn_digit_t u0, u1, v0, v1, k, t;
	bn_digit_t w0, w1, w2;

	u1 = (reg_multiplicand >> (BN_DIGIT_BIT_CNT / 2));
	u0 = (reg_multiplicand & (BN_MAX_DIGIT >> (BN_DIGIT_BIT_CNT / 2)));
	v1 = (reg_multiplier >> (BN_DIGIT_BIT_CNT / 2));
	v0 = (reg_multiplier & (BN_MAX_DIGIT >> (BN_DIGIT_BIT_CNT / 2)));

	t = (u0 * v0);
	w0 = (t & (BN_MAX_DIGIT >> (BN_DIGIT_BIT_CNT / 2)));
	k = (t >> (BN_DIGIT_BIT_CNT / 2));

	t = ((u1 * v0) + k);
	w1 = (t & (BN_MAX_DIGIT >> (BN_DIGIT_BIT_CNT / 2)));
	w2 = (t >> (BN_DIGIT_BIT_CNT / 2));

	t = ((u0 * v1) + w1);
	k = (t >> (BN_DIGIT_BIT_CNT / 2));

	reg_res_lo = ((t << (BN_DIGIT_BIT_CNT / 2)) + w0);
	reg_res_hi = ((u1 * v1) + w2 + k);
#else
	/* Simple and slow multiplication. */
	while (0 != reg_multiplier) {
		if (1 & reg_multiplier) {
			reg_res_lo += reg_multiplicand;
			if (reg_res_lo < reg_multiplicand) {
				reg_res_hi ++;
			}
			reg_res_hi += reg_multiplicand_hi;
		}
		reg_multiplicand_hi <<= 1;
		if (BN_DIGIT_HI_BIT & reg_multiplicand) {
			reg_multiplicand_hi |= 1;
		}
		reg_multiplicand <<= 1;
		reg_multiplier >>= 1;
	}
#endif
ok_exit:
	(*result_lo) = reg_res_lo;
	(*result_hi) = reg_res_hi;
	return;
#endif /* BN_CC_MULL_DIV */
}
static inline void
bn_digit_mult(bn_digit_t a, bn_digit_t b,
    bn_digit_t *result_lo, bn_digit_t *result_hi) {
	bn_digit_t res_lo, res_hi;
	
	if (0 == a || 0 == b) {
		res_lo = 0;
		res_hi = 0;
	} else {
		bn_digit_mult__int(a, b, &res_lo, &res_hi);
	}
	if (NULL != result_lo)
		(*result_lo) = res_lo;
	if (NULL != result_hi)
		(*result_hi) = res_hi;
}

/*
 * result = dividend / divisor
 * remainder = dividend % divisor
 * where: dividend = result * divisor + remainder
 * http://en.wikipedia.org/wiki/Division_algorithm
 * Integer division (unsigned) with remainder
 */
static inline int
bn_digit_div__int(bn_digit_t dividend_lo, bn_digit_t dividend_hi, bn_digit_t divisor,
    bn_digit_t *result_lo, bn_digit_t *result_hi,
    bn_digit_t *remainder_lo, bn_digit_t *remainder_hi) {

#if defined(BN_CC_MULL_DIV)
	register bn_ddigit_t res, rem, tm;

	if (0 == divisor) { /* dividend / 0 !!! */
		(*result_lo) = 0;
		(*result_hi) = 0;
		(*remainder_lo) = 0;
		(*remainder_hi) = 0;
		return (EINVAL);
	}
	/* Calculation. */
	tm = ((((bn_ddigit_t)dividend_hi) << BN_DIGIT_BITS) |
	    ((bn_ddigit_t)dividend_lo));
	res = (tm / divisor);
	rem = (tm % divisor);
	(*result_lo) = (res & BN_MAX_DIGIT);
	(*result_hi) = (res >> BN_DIGIT_BITS);
	(*remainder_lo) = (rem & BN_MAX_DIGIT);
	(*remainder_hi) = (rem >> BN_DIGIT_BITS);
	return (0);
#else /* BN_CC_MULL_DIV */
	register size_t num_bits;
	register bn_digit_t reg_dividend_lo = dividend_lo, reg_dividend_hi = dividend_hi;
	register bn_digit_t reg_divisor = divisor;
	register bn_digit_t reg_quotient_hi = 0, reg_quotient_lo = 0;
	register bn_digit_t reg_divisor_lo = 0;

	if (0 == reg_divisor) { /* dividend / 0 !!! */
		(*result_lo) = reg_quotient_lo;
		(*result_hi) = reg_quotient_hi;
		(*remainder_lo) = 0; /* remainder */
		(*remainder_hi) = reg_dividend_hi;
		return (EINVAL);
	}
#if 1
	/* Speed optimizations. */
	if (1 == reg_divisor) { /* dividend / 1, return dividend. */
		(*result_lo) = reg_dividend_lo;
		(*result_hi) = reg_dividend_hi;
		(*remainder_lo) = 0; /* remainder */
		(*remainder_hi) = 0; /* remainder */
		return (0);
	}
	if (0 == reg_dividend_hi) {
		//if (reg_divisor > reg_dividend_lo) /* Return dividend_lo as remainder. */
		//	goto ok_exit; /* Special case: 0 / divisor, return 0. */
		if (reg_divisor == reg_dividend_lo) { /* dividend eq divisor, return 1. */
			reg_quotient_lo = 1;
			reg_dividend_lo = 0; /* remainder */
			reg_dividend_hi = 0; /* remainder */
		}
		if (reg_divisor < reg_dividend_lo) {
			reg_quotient_lo = (reg_dividend_lo / divisor);
			reg_dividend_lo = (reg_dividend_lo % divisor); /* remainder */
		}
		(*result_lo) = reg_quotient_lo;
		(*result_hi) = reg_quotient_hi;
		(*remainder_lo) = reg_dividend_lo;
		(*remainder_hi) = reg_dividend_hi;
		return (0);
	}
	if (0 != bn_digit_is_pow2(divisor)) {
		num_bits = bn_digit_ctz(divisor);
		(*result_lo) = ((reg_dividend_lo >> num_bits) |
		    (reg_dividend_hi << (BN_DIGIT_BITS - num_bits)));
		(*result_hi) = (reg_dividend_hi >> num_bits);
		(*remainder_lo) = (reg_dividend_lo & ((((bn_digit_t)1) << num_bits) - 1));
		(*remainder_hi) = (reg_dividend_hi & ((((bn_digit_t)1) << (BN_DIGIT_BITS - num_bits)) - 1));
		return (0);
	}
#endif
	/* Calculation. */
	/* num_bits = bn_digit_clz(reg_divisor);
	 * reg_divisor <<= num_bits;
	 * num_bits += (BN_DIGIT_BITS + 1);
	 * here local optimized equivalent version.
	 */
	num_bits = (BN_DIGIT_BITS + 1);
	while (0 == (BN_DIGIT_HI_BIT & reg_divisor)) {
		reg_divisor <<= 1;
		num_bits ++;
	}
	for (; num_bits != 0; num_bits --) {
		reg_quotient_hi <<= 1;
		if (BN_DIGIT_HI_BIT & reg_quotient_lo) {
			reg_quotient_hi |= 1;
		}
		reg_quotient_lo <<= 1;

		if ((reg_divisor < reg_dividend_hi) ||
		    ((reg_divisor == reg_dividend_hi) &&
		     (reg_divisor_lo <= reg_dividend_lo))) {
			reg_dividend_hi -= reg_divisor;
			if (reg_dividend_lo < reg_divisor_lo) {
				reg_dividend_hi --;
			}
			reg_dividend_lo -= reg_divisor_lo;
			reg_quotient_lo |= 1;
		}

		reg_divisor_lo >>= 1;
		if (1 & reg_divisor) {
			reg_divisor_lo |= BN_DIGIT_HI_BIT;
		}
		reg_divisor >>= 1;
	}
	(*result_lo) = reg_quotient_lo;
	(*result_hi) = reg_quotient_hi;
	(*remainder_lo) = reg_dividend_lo;
	(*remainder_hi) = reg_dividend_hi;
	return (0);
#endif /* BN_CC_MULL_DIV */
}
/* Optimized for internal use. */
static inline int
bn_digit_div__int_short(bn_digit_t dividend_lo, bn_digit_t dividend_hi, bn_digit_t divisor,
    bn_digit_t *result_lo) {

#if defined(BN_CC_MULL_DIV)
	register bn_ddigit_t tm;

	if (0 == divisor) { /* dividend / 0 !!! */
		(*result_lo) = 0;
		return (EINVAL);
	}
	/* Calculation. */
	tm = ((((bn_ddigit_t)dividend_hi) << BN_DIGIT_BITS) |
	    ((bn_ddigit_t)dividend_lo));
	(*result_lo) = ((tm / divisor) & BN_MAX_DIGIT);
	return (0);
#else /* BN_CC_MULL_DIV */
	register size_t num_bits;
	register bn_digit_t reg_dividend_lo = dividend_lo, reg_dividend_hi = dividend_hi;
	register bn_digit_t reg_divisor = divisor;
	register bn_digit_t reg_quotient_lo = 0;
	register bn_digit_t reg_divisor_lo = 0;

	if (0 == reg_divisor) { /* dividend / 0 !!! */
		(*result_lo) = 0; /* remainder */
		return (EINVAL);
	}
#if 1
	/* Speed optimizations. */
	if (1 == reg_divisor) { /* dividend / 1, return dividend. */
		(*result_lo) = reg_dividend_lo;
		return (0);
	}
	if (0 == reg_dividend_hi) {
		if (reg_divisor > reg_dividend_lo) { /* Return dividend_lo as remainder. */
			(*result_lo) = 0; /* Special case: 0 / divisor, return 0. */
			return (0);
		}
		if (reg_divisor == reg_dividend_lo) { /* dividend eq divisor, return 1. */
			(*result_lo) = 1;
			return (0);
		}
		(*result_lo) = (reg_dividend_lo / divisor);
		return (0);
	}
	if (0 != bn_digit_is_pow2(divisor)) {
		num_bits = bn_digit_ctz(divisor);
		(*result_lo) = ((reg_dividend_lo >> num_bits) |
		    (reg_dividend_hi << (BN_DIGIT_BITS - num_bits)));
		return (0);
	}
#endif
	/* Calculation. */
	/* num_bits = bn_digit_clz(reg_divisor);
	 * reg_divisor <<= num_bits;
	 * num_bits += (BN_DIGIT_BITS + 1);
	 * here local optimized equivalent version.
	 */
	num_bits = (BN_DIGIT_BITS + 1);
	while (0 == (BN_DIGIT_HI_BIT & reg_divisor)) {
		reg_divisor <<= 1;
		num_bits ++;
	}
	for (; num_bits != 0; num_bits --) {
		reg_quotient_lo <<= 1;

		if ((reg_divisor < reg_dividend_hi) ||
		    ((reg_divisor == reg_dividend_hi) &&
		     (reg_divisor_lo <= reg_dividend_lo))) {
			reg_dividend_hi -= reg_divisor;
			if (reg_dividend_lo < reg_divisor_lo) {
				reg_dividend_hi --;
			}
			reg_dividend_lo -= reg_divisor_lo;
			reg_quotient_lo |= 1;
		}

		reg_divisor_lo >>= 1;
		if (1 & reg_divisor) {
			reg_divisor_lo |= BN_DIGIT_HI_BIT;
		}
		reg_divisor >>= 1;
	}
	(*result_lo) = reg_quotient_lo;
	return (0);
#endif /* BN_CC_MULL_DIV */
}

static inline int
bn_digit_div(bn_digit_t dividend_lo, bn_digit_t dividend_hi, bn_digit_t divisor,
    bn_digit_t *result_lo, bn_digit_t *result_hi,
    bn_digit_t *remainder_lo, bn_digit_t *remainder_hi) {
	int error;
	bn_digit_t res_lo, res_hi, rem_lo, rem_hi;

	error = bn_digit_div__int(dividend_lo, dividend_hi, divisor,
	    &res_lo, &res_hi, &rem_lo, &rem_hi);

	if (NULL != result_lo)
		(*result_lo) = res_lo;
	if (NULL != result_hi)
		(*result_hi) = res_hi;
	if (NULL != remainder_lo)
		(*remainder_lo) = rem_lo;
	if (NULL != remainder_hi)
		(*remainder_hi) = rem_hi;
	return (error);
}

/* Return: gcd(a, b).
 * greatest common divisor (gcd), also known as the greatest common factor (gcf),
 * or highest common factor (hcf), of two or more integers (at least one of which
 * is not zero), is the largest positive integer that divides the numbers without
 * a remainder.
 * http://en.wikipedia.org/wiki/Greatest_common_divisor
 * gcd(a, 0) = |a|, for a ≠ 0; gcd(a, b) = gcd(b, a); gcd(0, 0) = 0
 */
/* Euclid's algorithm */
static inline bn_digit_t
bn_digit_gcd(bn_digit_t a, bn_digit_t b) {
/*
 *	t = a mod b
 *	a = b
 *	b = t
 * or
 *	a = a mod b
 *	a swap b
 */
	/* Speed optimizations. */
	/* GCD(0, b) == b; GCD(a, 0) == a, GCD(0, 0) == 0 */
	if (0 == a)
		return (b);
	if (0 == b || a == b)
		return (a);
	if (a < b) {
		bn_digit_swap(a, b);
	}
	while (0 != b) {
		//BN_RET_ON_ERR(bn_digit_div__int(a, 0, b, NULL, NULL, &a, NULL)); /* a = a mod b */
		a = (a % b);
		bn_digit_swap(a, b);
	}
	return (a);
}
/* Binary GCD / Stein's algorithm */
/* See: http://en.wikipedia.org/wiki/Binary_GCD_algorithm */
static inline bn_digit_t
bn_digit_gcd_bin(bn_digit_t a, bn_digit_t b) {
	register bn_digit_t reg_a = a, reg_b = b;
	size_t shift, shift_a, shift_b;

	/* Speed optimizations. */
	if (0 == reg_a)
		return (reg_b);
	if (0 == reg_b || reg_a == reg_b)
		return (reg_a);
	/* Let shift = the greatest power of 2 dividing both a and b. */
	shift_a = bn_digit_ctz(reg_a);
	shift_b = bn_digit_ctz(reg_b);
	shift = ((shift_a >= shift_b) ? shift_b : shift_a); /* min(shift_a, shift_b) */
	/* Remove all factors of 2 in a and b. */
	reg_a >>= shift_a;
	reg_b >>= shift_b;
	/* From here on, a is always odd. */
	while (0 != reg_b) {
		/* Remove all factors of 2 in b -- they are not common. */
		while (0 == (reg_b & 1)) {
			reg_b >>= 1;
		}
		/* Now a and b are both odd. Swap if necessary so a <= b,
		 * then set b -= a (which is even). */
		if (reg_a > reg_b) {
			bn_digit_swap(reg_a, reg_b);
		}
		reg_b -= reg_a; /* Here b >= a. */
	}
	reg_a <<= shift; /* Restore common factors of 2. */
	return (reg_a);
}
/* Extended Euclid's algorithm */
/* http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm */
/* a*x + b*y = gcd(a, b) */
static inline bn_digit_t
bn_digit_egcd(bn_digit_t a, bn_digit_t b, bn_digit_t *ax, bn_digit_t *by) {
	bn_digit_t q, t, x = 0, x_prev = 1, y = 1, y_prev = 0;

	/* Speed optimizations. */
	if (NULL == ax && NULL == by)
		return (bn_digit_gcd(a, b));
	if (0 == a) {
		a = b;
		bn_digit_swap(x_prev, y_prev);
		goto ok_exit; /* return (b, x = 0, y = 1); */
	}
	if (0 == b)
		goto ok_exit; /* return (a, x = 1, y = 0); */
	if (a == b) {
		y_prev = 1;
		goto ok_exit;  /* return (a, x = 1, y = 1); */
	}
	if (a < b) {
		bn_digit_swap(a, b);
		bn_digit_swap(x, y);
		bn_digit_swap(x_prev, y_prev);
	}
	while (0 != b) {
		/* q = a div b; (a, b) = (b, a mod b); */
		//BN_RET_ON_ERR(bn_digit_div__int(a, 0, b, &q, NULL, &a, NULL));
		q = (a / b);
		a = (a % b);
		bn_digit_swap(a, b);
		if (NULL != ax) { /* (x, lastx) = (lastx - quotient*x, x); */
			t = (q * x);
			x_prev -= t;
			bn_digit_swap(x, x_prev);
		}
		if (NULL != by) { /* (y, lasty) = (lasty - quotient*y, y); */
			t = (q * y);
			y_prev -= t;
			bn_digit_swap(y, y_prev);
		}
	}
ok_exit:
	if (NULL != ax)
		(*ax) = x_prev;
	if (NULL != by)
		(*by) = y_prev;
	return (a);
}



/*=========================== DIGITS OPERATIONS ==============================*/
/*--------------------------- OTHER OPERATIONS -------------------------------*/

/* Returns: the significant length of a in digits. */
static inline size_t
bn_digits_calc_digits(bn_digit_t *a, size_t count) {
	register ssize_t i;

	if (NULL == a || 0 == count)
		return (0);
	for (i = (ssize_t)(count - 1); i >= 0; i --) {
		if (0 != a[i])
			break;
	}
	return ((size_t)(i + 1));
}

/* Returns: sign of a - b. */
/* XXX: timing attack? */
/* XXX: memcmp() optimization? */
static inline int
bn_digits_cmp(bn_digit_t *a, bn_digit_t *b, size_t count) {
	register ssize_t i;

	if (a == b || 0 == count)
		return (0); /* Euqual. */
	if (NULL == a || NULL == b) {
		if (NULL != a)
			return (1);
		return (-1);
	}
	for (i = (ssize_t)(count - 1); i >= 0; i --) {
		if (a[i] == b[i])
			continue;
		if (a[i] > b[i])
			return (1);
		return (-1);
	}
	return (0); /* Euqual. */
}


/*------------------------- Conversion functions -----------------------------*/
/* Import big-endian bin num. */
static inline int
bn_digits_import_be_bin(bn_digit_t *a, size_t count,
    const uint8_t *buf, size_t buf_size, size_t *count_ret) {
	register const uint8_t *r_pos;
	register uint8_t *w_pos;

	BN_POINTER_CHK_EINVAL(a);
	BN_POINTER_CHK_EINVAL(buf);
	if (0 == count || 0 == buf_size)
		return (EINVAL);
	if ((count * BN_DIGIT_SIZE) < buf_size)
		return (EOVERFLOW);
	r_pos = (buf + (buf_size - 1));
	w_pos = (uint8_t*)a;
	BN_PREFETCH_DIGITS(buf, count);
	for (; r_pos >= buf; r_pos --, w_pos ++) {
		(*w_pos) = (*r_pos);
	}
	if (NULL == count_ret) {
		memset(w_pos, 0, ((count * BN_DIGIT_SIZE) - buf_size));
	} else {
		count = (buf_size / BN_DIGIT_SIZE);
		if (0 != (buf_size % BN_DIGIT_SIZE)) {
			memset(w_pos, 0, (BN_DIGIT_SIZE - (buf_size % BN_DIGIT_SIZE)));
			count ++;
		}
		(*count_ret) = count;
	}
	return (0);
}
/* Export to big-endian bin num. */
static inline int
bn_digits_export_be_bin(bn_digit_t *a, size_t count, uint32_t flags,
    uint8_t *buf, size_t buf_size, size_t *buf_size_ret) {
	register uint8_t *r_pos, *r_pos_min, *w_pos, *w_pos_max;
	size_t tm;

	BN_POINTER_CHK_EINVAL(a);
	BN_POINTER_CHK_EINVAL(buf);
	if (0 == buf_size)
		return (EINVAL);
	w_pos = buf;
	w_pos_max = (w_pos + buf_size);
	if (0 == count) { /* is a = 0? */
		if (0 != (flags & BN_EXPORT_F_AUTO_SIZE)) {
			buf_size = 1;
		}
		memset(w_pos, 0, buf_size);
		if (NULL != buf_size_ret)
			(*buf_size_ret) = buf_size;
		return (0);
	}
	/* Looking for non zero byte in a. */
	r_pos_min = (uint8_t*)a;
	BN_PREFETCH_DIGITS(a, count);
	r_pos = (r_pos_min + (count * BN_DIGIT_SIZE) - 1);
	for (; r_pos >= r_pos_min && 0 == (*r_pos); r_pos --)
		;
	tm = (size_t)(1 + r_pos - r_pos_min);
	if (0 != (flags & BN_EXPORT_F_AUTO_SIZE)) {
		if (NULL != buf_size_ret)
			(*buf_size_ret) = tm;
		if (tm > buf_size) /* Not enouth space in buf. */
			return (EOVERFLOW);
	} else {
		if (NULL != buf_size_ret)
			(*buf_size_ret) = buf_size;
		if (tm > buf_size) /* Not enouth space in buf. */
			return (EOVERFLOW);
		memset(w_pos, 0, (buf_size - tm));
		w_pos += (buf_size - tm);
	}
	for (; r_pos >= r_pos_min && w_pos_max > w_pos; r_pos --, w_pos ++) {
		(*w_pos) = (*r_pos);
	}
	return (0);
}

/* Import from little-endian bin num. */
static inline int
bn_digits_import_le_bin(bn_digit_t *a, size_t count,
    const uint8_t *buf, size_t buf_size, size_t *count_ret) {

	BN_POINTER_CHK_EINVAL(a);
	BN_POINTER_CHK_EINVAL(buf);
	if (0 == count || 0 == buf_size)
		return (EINVAL);
	if ((count * BN_DIGIT_SIZE) < buf_size)
		return (EOVERFLOW);
	memcpy(a, buf, buf_size);
	if (NULL == count_ret) {
		memset((((uint8_t*)a) + buf_size), 0,
		    ((count * BN_DIGIT_SIZE) - buf_size));
	} else {
		count = (buf_size / BN_DIGIT_SIZE);
		if (0 != (buf_size % BN_DIGIT_SIZE)) {
			memset((((uint8_t*)a) + buf_size), 0,
			    (BN_DIGIT_SIZE - (buf_size % BN_DIGIT_SIZE)));
			count ++;
		}
		(*count_ret) = count;
	}
	return (0);
}
/* Export to little-endian bin num. */
static inline int
bn_digits_export_le_bin(bn_digit_t *a, size_t count, uint32_t flags,
    uint8_t *buf, size_t buf_size, size_t *buf_size_ret) {
	size_t bn_size, ddiff;

	BN_POINTER_CHK_EINVAL(a);
	BN_POINTER_CHK_EINVAL(buf);
	if (0 == buf_size)
		return (EINVAL);
	bn_size = (count * BN_DIGIT_SIZE);
	if (NULL != buf_size_ret) {
		(*buf_size_ret) = ((0 != (flags & BN_EXPORT_F_AUTO_SIZE)) ?
		    bn_size : buf_size);
	}
	if (bn_size > buf_size) { /* Additional check: zero bytes in last digit */
		ddiff = (bn_size - buf_size);
		if (ddiff > BN_DIGIT_SIZE)
			return (EOVERFLOW);
		if (ddiff == BN_DIGIT_SIZE && 0 != a[(count - 1)])
			return (EOVERFLOW);
		/* Calculate maximum value of last bn_digit_t to export. */
		if (a[(count - 1)] >= (((bn_digit_t)1) << (1 + (ddiff * 8))))
			return (EOVERFLOW);
		bn_size = buf_size; /* Fix len and continue. */
		if (NULL != buf_size_ret) /* Update return value. */
			(*buf_size_ret) = bn_size;
	}
	memcpy(buf, a, bn_size);
	if (bn_size < buf_size &&
	    0 == (flags & BN_EXPORT_F_AUTO_SIZE)) { /* Zeroize end. */
		memset((buf + bn_size), 0, (buf_size - bn_size));
	}
	return (0);
}

/* Import from little-endian hex string (L->H). */
static inline int
bn_digits_import_le_hex(bn_digit_t *a, size_t count,
    const uint8_t *buf, size_t buf_size) {
	register const uint8_t *r_pos, *r_pos_max;
	register uint8_t *w_pos, *w_pos_max, cur_char, byte = 0;
	register size_t cnt;

	BN_POINTER_CHK_EINVAL(a);
	BN_POINTER_CHK_EINVAL(buf);
	if (0 == count || 0 == buf_size)
		return (EINVAL);
	if ((count * BN_DIGIT_SIZE) < (buf_size / 2))
		return (EOVERFLOW);
	r_pos = buf;
	r_pos_max = (r_pos + buf_size);
	w_pos = (uint8_t*)a;
	w_pos_max = (w_pos + (count * BN_DIGIT_SIZE));

	BN_PREFETCH_DIGITS(buf, count);
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
		byte = (((uint8_t)(byte << 4)) | cur_char);
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
/* Export to little-endian hex string (L->H). */
static inline int
bn_digits_export_le_hex(bn_digit_t *a, size_t count, uint32_t flags,
    uint8_t *buf, size_t buf_size, size_t *buf_size_ret) {
	static const uint8_t *hex_tbl = (const uint8_t*)"0123456789abcdef";
	register uint8_t *r_pos, *r_pos_max, *w_pos, *w_pos_max, byte;
	size_t tm;

	BN_POINTER_CHK_EINVAL(a);
	BN_POINTER_CHK_EINVAL(buf);
	if (2 > buf_size)
		return (EINVAL);
	w_pos = buf;
	w_pos_max = (w_pos + buf_size);
	if (0 == count) { /* is a = 0? */
		if (0 != (flags & BN_EXPORT_F_AUTO_SIZE)) {
			buf_size = 2;
		} else {
			buf_size &= ~((size_t)1);
		}
		memset(w_pos, '0', buf_size);
		w_pos += buf_size;
		goto ok_exit;
	}
	r_pos = (uint8_t*)a;
	r_pos_max = (r_pos + (count * BN_DIGIT_SIZE));
	tm = (2 * (count * BN_DIGIT_SIZE));
	if (tm > buf_size) { /* Not enouth space in buf. */
		if (NULL != buf_size_ret)
			(*buf_size_ret) = tm;
		return (EOVERFLOW);
	}
	BN_PREFETCH_DIGITS(a, count);
	for (; r_pos < r_pos_max; r_pos ++) {
		byte = (*r_pos);
		(*w_pos ++) = hex_tbl[((byte >> 4) & 0x0f)];
		(*w_pos ++) = hex_tbl[(byte & 0x0f)];
	}
	if (0 == (flags & BN_EXPORT_F_AUTO_SIZE)) { /* Zeroize end. */
		buf_size -= tm;
		buf_size &= ~((size_t)1);
		memset(w_pos, '0', buf_size);
		w_pos += buf_size;
	}
ok_exit:
	if (w_pos_max > w_pos) { /* Zero end of string. */
		(*w_pos) = 0;
	}
	if (NULL != buf_size_ret)
		(*buf_size_ret) = (size_t)(w_pos - buf);
	return (0);
}

/* Import from big-endian hex string (H->L). */
static inline int
bn_digits_import_be_hex(bn_digit_t *a, size_t count,
    const uint8_t *buf, size_t buf_size) {
	register const uint8_t *r_pos;
	register uint8_t *w_pos, *w_pos_max, cur_char, byte = 0;
	register size_t cnt;

	BN_POINTER_CHK_EINVAL(a);
	BN_POINTER_CHK_EINVAL(buf);
	if (0 == count || 0 == buf_size)
		return (EINVAL);
	if ((count * BN_DIGIT_SIZE) < (buf_size / 2))
		return (EOVERFLOW);
	r_pos = (buf + (buf_size - 1));
	w_pos = (uint8_t*)a;
	w_pos_max = (w_pos + (count * BN_DIGIT_SIZE));

	BN_PREFETCH_DIGITS(buf, count);
	for (cnt = 0; r_pos >= buf; r_pos --) {
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
		byte = ((byte >> 4) | ((uint8_t)(cur_char << 4)));
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
/* Export to big-endian hex string (H->L). */
static inline int
bn_digits_export_be_hex(bn_digit_t *a, size_t count, uint32_t flags,
    uint8_t *buf, size_t buf_size, size_t *buf_size_ret) {
	static const uint8_t *hex_tbl = (const uint8_t*)"0123456789abcdef";
	register uint8_t *r_pos, *r_pos_min, *w_pos, *w_pos_max, byte;
	size_t tm;

	BN_POINTER_CHK_EINVAL(a);
	BN_POINTER_CHK_EINVAL(buf);
	if (2 > buf_size)
		return (EINVAL);
	w_pos = buf;
	w_pos_max = (w_pos + buf_size);
	if (0 == count) { /* is a = 0? */
		if (0 != (flags & BN_EXPORT_F_AUTO_SIZE)) {
			buf_size = 2;
		} else {
			buf_size &= ~((size_t)1);
		}
		memset(w_pos, '0', buf_size);
		w_pos += buf_size;
		goto ok_exit;
	}
	/* Looking for non zero byte in a. */
	r_pos_min = (uint8_t*)a;
	r_pos = (r_pos_min + (count * BN_DIGIT_SIZE) - 1);
	BN_PREFETCH_DIGITS(a, count);
	for (; r_pos >= r_pos_min && 0 == (*r_pos); r_pos --)
		;
	tm = (size_t)(2 * (1 + r_pos - r_pos_min));
	if (tm > buf_size) { /* Not enouth space in buf. */
		if (NULL != buf_size_ret)
			(*buf_size_ret) = tm;
		return (EOVERFLOW);
	}
	if (0 == (flags & BN_EXPORT_F_AUTO_SIZE)) { /* Zeroize start. */
		buf_size -= tm;
		buf_size &= ~((size_t)1);
		memset(w_pos, '0', buf_size);
		w_pos += buf_size;
	}
	for (; r_pos >= r_pos_min; r_pos --) {
		byte = (*r_pos);
		(*w_pos ++) = hex_tbl[((byte >> 4) & 0x0f)];
		(*w_pos ++) = hex_tbl[(byte & 0x0f)];
	}
ok_exit:
	if (w_pos_max > w_pos) { /* Zero end of string. */
		(*w_pos) = 0;
	}
	if (NULL != buf_size_ret)
		(*buf_size_ret) = (size_t)(w_pos - buf);
	return (0);
}


/*------------------------------ ASSIGNMENTS ---------------------------------*/
/* Assigns: a = 0. */
static inline void
bn_digits_assign_zero(bn_digit_t *a, size_t count) {

	if (NULL == a || 0 == count)
		return;
	memset(a, 0, (count * BN_DIGIT_SIZE));
	return;
}


/*-------------------------- ARITHMETIC OPERATIONS ---------------------------*/
/* Computes: a *= 2^bits (i.e. shifts left c bits). */
static inline void
bn_digits_l_shift(bn_digit_t *a, size_t count, size_t bits) {
	register size_t i = 0, crr_bits_cnt;
	register bn_digit_t tm, crr = 0;

	if (NULL == a || 0 == count || 0 == bits)
		return;
#if 0
	if ((count * BN_DIGIT_BITS) <= bits) {
		bn_digits_assign_zero(a, count);
		return;
	}
#endif
	BN_PREFETCH_DIGITS(a, count);
	crr_bits_cnt = (7 & bits);
	if (0 == crr_bits_cnt || BN_DIGIT_BITS < bits) { /* memmove() optimization. */
		i = (bits / 8);
		memmove((((uint8_t*)a) + i), (uint8_t*)a, ((count * BN_DIGIT_SIZE) - i));
		memset((uint8_t*)a, 0, i);
		if (0 == crr_bits_cnt)
			return;
		bits -= (i * 8);
		i /= BN_DIGIT_SIZE; /* Skip zero digits at start. */
	}
	crr_bits_cnt = (BN_DIGIT_BITS - bits);
	for (; i < count; i ++) {
		tm = a[i];
		a[i] = ((tm << bits) | crr);
		crr = (tm >> crr_bits_cnt);
	}
}
/* Computes: a /= 2^bits (i.e. shifts right c bits). */
static inline void
bn_digits_r_shift(bn_digit_t *a, size_t count, size_t bits) {
	register size_t i, crr_bits_cnt;

	if (NULL == a || 0 == count || 0 == bits)
		return;
#if 0
	if ((count * BN_DIGIT_BITS) <= bits) {
		bn_digits_assign_zero(a, count);
		return;
	}
#endif
	BN_PREFETCH_DIGITS(a, count);
	crr_bits_cnt = (7 & bits);
	if (0 == crr_bits_cnt || BN_DIGIT_BITS < bits) { /* memmove() optimization. */
		i = (bits / 8);
		memmove(((uint8_t*)a), (((uint8_t*)a) + i), ((count * BN_DIGIT_SIZE) - i));
		memset((((uint8_t*)a) + ((count * BN_DIGIT_SIZE) - i)), 0, i);
		if (0 == crr_bits_cnt)
			return;
		bits -= (i * 8);
		count -= (i / BN_DIGIT_SIZE); /* Skip zero digits at end. */
	}

	crr_bits_cnt = (BN_DIGIT_BITS - bits);
	for (i = 0; i < (count - 1); i ++) {
		a[i] = ((a[i] >> bits) | (a[(i + 1)] << crr_bits_cnt));
	}
	a[i] = (a[i] >> bits);
}

/* Computes: a += b. Returns carry. */
static inline void
bn_digits_add_digit(bn_digit_t *a, size_t count, bn_digit_t b, bn_digit_t *carry) {
	register size_t i;
	register bn_digit_t crr = 0;

	if (NULL == a || 0 == count || 0 == b)
		goto ok_exit;

	BN_PREFETCH_DIGITS(a, a_count);
#if 0
	crr = b;
	for (i = 0; 0 != crr && i < count; i ++) {
		a[i] += crr;
		crr = ((a[i] < crr) ? 1 : 0);
	}
#else
	a[0] += b;
	if (a[0] >= b)
		goto ok_exit;
	for (i = 1; i < count; i ++) {
		a[i] ++;
		if (1 <= a[i])
			goto ok_exit;
	}
	crr ++;
#endif
ok_exit:
	if (NULL != carry)
		(*carry) = crr;
	return;
}
/* a_count - all avaible digits, b_count - set to non zero digits count. */
static inline int
bn_digits_add(bn_digit_t *a, size_t a_count, bn_digit_t *b, size_t b_count,
    bn_digit_t *carry) {
	int error = 0;
	register size_t i;
	register bn_digit_t tm, crr = 0;

	if (NULL == a || NULL == b) {
		error = EINVAL;
		goto ok_exit;
	}
	if (0 == b_count)
		goto ok_exit;
	if (a_count < b_count) {
		error = EOVERFLOW;
		goto ok_exit;
	}
	BN_PREFETCH_DIGITS(a, a_count);
	BN_PREFETCH_DIGITS(b, b_count);
	for (i = 0; i < b_count; i ++) {
		tm = b[i]; /* If a == b */
		a[i] += crr;
		crr = ((a[i] < crr) ? 1 : 0);
		if (0 == tm)
			continue;
		a[i] += tm;
		if (a[i] < tm) {
			crr = 1;
		}
	}
	if (0 != crr && a_count > b_count) {
		bn_digits_add_digit(&a[b_count], (a_count - b_count), crr, carry);
		return (0);
	}
ok_exit:
	if (NULL != carry)
		(*carry) = crr;
	return (error);
}

/* Computes: a -= b. Returns borrow. */
static inline void
bn_digits_sub_digit(bn_digit_t *a, size_t count, bn_digit_t b, bn_digit_t *borrow) {
	register size_t i;
	register bn_digit_t brrw = 0;

	if (NULL == a || 0 == count || 0 == b)
		goto ok_exit;
	BN_PREFETCH_DIGITS(a, a_count);
	a[0] -= b;
	if (a[0] > (BN_MAX_DIGIT - b)) {
		brrw = 1;
	}
	for (i = 1; 0 != brrw && i < count; i ++) {
		a[i] -= brrw;
		brrw = ((a[i] > (BN_MAX_DIGIT - brrw)) ? 1 : 0);
	}
ok_exit:
	if (NULL != borrow)
		(*borrow) = brrw;
	return;
}
/* a_count, b_count - set to non zero digits count. */
static inline void
bn_digits_sub__int(bn_digit_t *a, size_t a_count, bn_digit_t *b, size_t b_count,
    bn_digit_t *borrow) {
	register size_t i;
	register bn_digit_t tm, brrw = 0;

	if (0 == b_count)
		return;
	if (a == b) {
		bn_digits_assign_zero(a, b_count);
		return;
	}
	//BN_PREFETCH_DIGITS(a, a_count);
	//BN_PREFETCH_DIGITS(b, b_count);
	for (i = 0; i < b_count; i ++) {
		tm = b[i]; /* If a == b */
		a[i] -= brrw;
		brrw = ((a[i] > (BN_MAX_DIGIT - brrw)) ? 1 : 0);
		if (0 == tm)
			continue;
		a[i] -= tm;
		if (a[i] > (BN_MAX_DIGIT - tm)) {
			brrw = 1;
		}
	}
	if (0 != brrw && a_count > b_count) {
		bn_digits_sub_digit(&a[b_count], (a_count - b_count), brrw, borrow);
		return;
	}
	if (NULL != borrow)
		(*borrow) = brrw;
}
static inline int
bn_digits_sub(bn_digit_t *a, size_t a_count, bn_digit_t *b, size_t b_count,
    bn_digit_t *borrow) {
	bn_digit_t brrw = 0;

	if (NULL == a || NULL == b)
		return (EINVAL);
	if (0 == b_count)
		goto ok_exit;
	if (a_count < b_count)
		return (EOVERFLOW);
	bn_digits_sub__int(a, a_count, b, b_count, &brrw);
ok_exit:
	if (NULL != borrow)
		(*borrow) = brrw;
	return (0);
}

/* Computes: a *= d, where d is a digit. Returns carry. */
static inline void
bn_digits_mult_digit__int(bn_digit_t *a, size_t a_count, bn_digit_t d) {
	register size_t i;
	register bn_digit_t crr = 0;
	bn_digit_t /*t_lo,*/ t_hi;

	if (0 == a_count)
		return;
#if 1	/* Speed optimizations. */
	if (0 != bn_digit_is_pow2(d)) {
		bn_digits_l_shift(a, a_count, bn_digit_ctz(d));
		return;
	}
#endif
	/* Calculation. */
	for (i = 0; i < a_count; i ++) {
#if 1
		t_hi = 0;
		if (0 != a[i]) {
			bn_digit_mult__int(d, a[i], &a[i], &t_hi);
		}
		a[i] += crr;
		crr = ((a[i] < crr) ? 1 : 0);
		crr += t_hi;
#else
		t_lo = a[i];
		a[i] += crr;
		crr = ((a[i] < crr) ? 1 : 0);
		if (0 == t_lo)
			continue;
		bn_digit_mult__int(d, t_lo, &t_lo, &t_hi);
		crr += t_hi;
		a[i] += t_lo;
		if (a[i] < t_lo) {
			crr ++;
		}
#endif
	}
}
/* Computes: a += b*d, where d is a digit. Returns carry. */
static inline void
bn_digits_add_digit_mult__int(bn_digit_t *a, size_t a_count, bn_digit_t *b,
    size_t b_count, bn_digit_t d) {
	register size_t i;
	register bn_digit_t crr = 0;
	bn_digit_t t_hi, t_lo;

	if (1 == d) {
		bn_digits_add(a, a_count, b, b_count, NULL);
		return;
	}

	for (i = 0; i < b_count; i ++) {
#if 1
		if (0 != b[i]) {
			bn_digit_mult__int(d, b[i], &t_lo, &t_hi); /* If a == b */
		} else {
			t_lo = 0;
			t_hi = 0;
		}
		a[i] += crr;
		crr = ((a[i] < crr) ? 1 : 0);
		crr += t_hi;
		a[i] += t_lo;
		if (a[i] < t_lo) {
			crr ++;
		}
#else
		t_lo = b[i]; /* If a == b */
		a[i] += crr;
		crr = ((a[i] < crr) ? 1 : 0);
		if (0 == t_lo)
			continue;
		bn_digit_mult__int(d, t_lo, &t_lo, &t_hi);
		crr += t_hi;
		a[i] += t_lo;
		if (a[i] < t_lo) {
			crr ++;
		}
#endif
	}
	if (0 != crr && a_count > b_count) {
		bn_digits_add_digit(&a[b_count], (a_count - b_count), crr, NULL);
	}
}

/* Computes: a -= b*d, where d is a digit. Returns borrow. */
static inline void
bn_digits_sub_digit_mult__int(bn_digit_t *a, size_t a_count, bn_digit_t *b,
    size_t b_count, bn_digit_t d, bn_digit_t *borrow) {
	register size_t i;
	register bn_digit_t brrw = 0;
	bn_digit_t t_hi, t_lo;

	if (1 == d) {
		bn_digits_sub__int(a, a_count, b, b_count, borrow);
		return;
	}
	//BN_PREFETCH_DIGITS(a, a_count);
	//BN_PREFETCH_DIGITS(b, b_count);
	for (i = 0; i < b_count; i ++) {
#if 0
		t_lo = 0;
		t_hi = 0;
		if (0 != b[i]) {
			bn_digit_mult__int(d, b[i], &t_lo, &t_hi); /* If a == b */
		}
		a[i] -= brrw;
		brrw = ((a[i] > (BN_MAX_DIGIT - brrw)) ? 1 : 0);
		brrw += t_hi;
		a[i] -= t_lo;
		if (a[i] > (BN_MAX_DIGIT - t_lo)) {
			brrw ++;
		}
#else
		t_lo = b[i]; /* If a == b */
		a[i] -= brrw;
		brrw = ((a[i] > (BN_MAX_DIGIT - brrw)) ? 1 : 0);
		if (0 == t_lo)
			continue;
		bn_digit_mult__int(d, t_lo, &t_lo, &t_hi);
		brrw += t_hi;
		a[i] -= t_lo;
		if (a[i] > (BN_MAX_DIGIT - t_lo)) {
			brrw ++;
		}
#endif
	}
	if (0 != brrw && a_count > b_count) {
		bn_digits_sub_digit(&a[b_count], (a_count - b_count), brrw, borrow);
		return;
	}
	if (NULL != borrow)
		(*borrow) = brrw;
}



/*=========================== BINUM OPERATIONS ===============================*/
/*--------------------------- OTHER OPERATIONS -------------------------------*/
/* bits = bits count */
static inline int
bn_init(bn_p bn, size_t bits) {

	BN_POINTER_CHK_EINVAL(bn);
	if (BN_BIT_LEN < bits || 0 == bits)
		return (EINVAL);
	bn->count = ((bits + (BN_DIGIT_BITS - 1)) / BN_DIGIT_BITS);
	if (BN_MAX_DIGITS < bn->count)
		return (EINVAL);
	bn->digits = 0;
	return (0);
}

/* Returns: the significant length of bn in digits. */
static inline size_t
bn_calc_digits(bn_p bn) {

	if (NULL == bn)
		return (0);
	bn->digits = bn_digits_calc_digits(bn->num, bn->count);
	return (bn->digits);
}
/* Return: count bits. */
static inline size_t
bn_calc_bits(bn_p bn) {

	if (NULL == bn)
		return (0);
	if (0 == bn->digits)
		return (0);
	return (((bn->digits * BN_DIGIT_BITS) - bn_digit_clz(bn->num[(bn->digits - 1)])));
}

/* Updates internal bn info: digits count. */
static inline void
bn_update(bn_p bn) {

	bn_calc_digits(bn);
}

/* Do delayed digits initialization. */
static inline void
bn_init_digits__int(bn_p bn, size_t digit_off) {
	register size_t i;

	//digit_off += 4;
	if (digit_off <= bn->digits)
		return;
	if (digit_off > bn->count) {
		digit_off = bn->count;
	}
	for (i = bn->digits; i < digit_off; i ++) {
		bn->num[i] = 0;
	}
}
/* Updates internal bn info: digits count. digit_off - updated digit offset. */
static inline void
bn_update_digits__int(bn_p bn, size_t digits) {

	if (digits >= bn->count) {
		bn->digits = bn_digits_calc_digits(bn->num, bn->count);
		return;
	}
	if (digits < bn->digits) {
		//bn->digits = digits;
		bn->digits = bn_digits_calc_digits(bn->num, bn->digits);
		return; /* Nothink to do. */
	}
	if (digits > bn->digits && 0 != bn->num[(digits - 1)]) {
		bn->digits = digits;
		return;
	}
	/* digits >= bn->digits */
	bn->digits = bn_digits_calc_digits(bn->num, digits);
}

/* Return: count trailing zeros (ctz). */
static inline size_t
bn_ctz(bn_p bn) {
	register size_t i, cnt;

	if (NULL == bn || 0 == bn->digits)
		return (0);
	BN_PREFETCH_BN_DATA(bn);
	for (i = 0, cnt = 0; i < bn->digits; i ++, cnt += BN_DIGIT_BITS) {
		if (0 == bn->num[i])
			continue;
		cnt += bn_digit_ctz(bn->num[i]);
		break;
	}
	return (cnt);
}
/* Return: count leading zeros (clz). */
static inline size_t
bn_clz(bn_p bn) {

	if (NULL == bn)
		return (0);
	return (((BN_DIGIT_BITS * (bn->count - bn->digits)) +
	    bn_digit_clz(bn->num[(bn->digits - 1)])));
}

/* Returns: nonzero if bn is zero. */
static inline int
bn_is_zero(bn_p bn) {

	return ((NULL == bn || 0 == bn->digits));
}
/* Returns: 1 if bn = 1 */
static inline int
bn_is_one(bn_p bn) {

	return ((NULL != bn && 1 == bn->digits && 1 == bn->num[0]));
}

static inline size_t
bn_is_pow2(bn_p bn) {
	register size_t i;

	if (NULL == bn || 0 == bn->digits)
		return (0);
	if (0 == bn_digit_is_pow2(bn->num[(bn->digits - 1)]))
		return (0);
	for (i = 0; i < (bn->digits - 1); i ++) {
		if (0 != bn->num[i])
			return (0);
	}
	return (1);
}

/* Returns: sign of a - b. */
static inline int
bn_cmp(bn_p a, bn_p b) {

	if (a == b)
		return (0); /* Euqual. */
	if (NULL == a || NULL == b) {
		if (NULL != a)
			return (1);
		return (-1);
	}
	/* No need to compare bn->count. */
	if (a->digits != b->digits) {
		if (a->digits > b->digits)
			return (1);
		return (-1);
	}
	return (bn_digits_cmp(a->num, b->num, a->digits));
}
/* Returns: 1 if a = b. */
static inline int
bn_is_equal(bn_p a, bn_p b) {

	return (0 == bn_cmp(a, b));
}

/* Test_ whether the 'bits' bit in bn is one */
static inline int
bn_is_bit_set(bn_p bn, size_t bit) {

	if (NULL == bn)
		return (0);
#if 1
	if (BN_DIGIT_BITS > bit)
		return (0 != (bn->num[0] & (((bn_digit_t)1) << bit)));
#endif
	if ((bn->digits * BN_DIGIT_BITS) <= bit)
		return (0);
	return (0 != (bn->num[(bit / BN_DIGIT_BITS)] & (((bn_digit_t)1) << (bit % BN_DIGIT_BITS))));
}
static inline int
bn_bit_set(bn_p bn, size_t bit, int val) {
	size_t idx;

	BN_POINTER_CHK_EINVAL(bn);
	idx = (bit / BN_DIGIT_BITS);
	if (bn->count <= idx)
		return (EOVERFLOW);
	bn_init_digits__int(bn, (idx + 1));
	if (0 == val) { /* Clear bit. */
		bn->num[idx] &= ~(((bn_digit_t)1) << (bit % BN_DIGIT_BITS));
	} else {
		bn->num[idx] |= (((bn_digit_t)1) << (bit % BN_DIGIT_BITS));
	}
	bn_update_digits__int(bn, (idx + 1));
	return (0);
}

static inline int
bn_is_even(bn_p bn) {

	return (NULL != bn && 0 != bn->digits && 0 == (bn->num[0] & 1));
}
/* = bn_is_bit_set(bn, 0), = mod 2 (1 mod 2 = 1, 2 mod 2 = 0 ...) */
static inline int
bn_is_odd(bn_p bn) {

	return (NULL != bn && 0 != bn->digits && 0 != (bn->num[0] & 1));
}

/*------------------------- Conversion functions -----------------------------*/
/* Import big-endian bun num. Reverse bytes copy (H->L). */
static inline int
bn_import_be_bin(bn_p bn, const uint8_t *buf, size_t buf_size) {
	size_t digits;

	BN_POINTER_CHK_EINVAL(bn);
	BN_PREFETCH_BN_DATA(bn);
	BN_RET_ON_ERR(bn_digits_import_be_bin(bn->num, bn->count, buf, buf_size,
	    &digits));
	bn_update_digits__int(bn, digits);
	return (0);
}
/* Export big-endian bin num. Reverse bytes copy (H->L). */
static inline int
bn_export_be_bin(bn_p bn, uint32_t flags, uint8_t *buf, size_t buf_size,
    size_t *buf_size_ret) {

	BN_POINTER_CHK_EINVAL(bn);
	BN_RET_ON_ERR(bn_digits_export_be_bin(bn->num, bn->digits, flags,
	    buf, buf_size, buf_size_ret));
	return (0);
}

/* Import little-endian bin num / Normal copy (L->H). */
static inline int
bn_import_le_bin(bn_p bn, const uint8_t *buf, size_t buf_size) {
	size_t digits;

	BN_POINTER_CHK_EINVAL(bn);
	BN_RET_ON_ERR(bn_digits_import_le_bin(bn->num, bn->count, buf, buf_size,
	    &digits));
	bn_update_digits__int(bn, digits);
	return (0);
}
/* Export to little-endian bin num / Normal copy (L->H). */
static inline int
bn_export_le_bin(bn_p bn, uint32_t flags, uint8_t *buf, size_t buf_size,
    size_t *buf_size_ret) {

	BN_POINTER_CHK_EINVAL(bn);
	BN_RET_ON_ERR(bn_digits_export_le_bin(bn->num, bn->digits, flags,
	    buf, buf_size, buf_size_ret));
	return (0);
}

/* Import from little-endian hex string (L->H). */
static inline int
bn_import_le_hex(bn_p bn, const uint8_t *buf, size_t buf_size) {

	BN_POINTER_CHK_EINVAL(bn);
	BN_PREFETCH_BN_DATA(bn);
	bn_init_digits__int(bn, bn->count);
	BN_RET_ON_ERR(bn_digits_import_le_hex(bn->num, bn->count, buf, buf_size));
	bn_update(bn);
	return (0);
}
/* Export to little-endian hex string (L->H). */
static inline int
bn_export_le_hex(bn_p bn, uint32_t flags, uint8_t *buf, size_t buf_size,
    size_t *buf_size_ret) {

	BN_POINTER_CHK_EINVAL(bn);
	BN_RET_ON_ERR(bn_digits_export_le_hex(bn->num, bn->digits, flags,
	    buf, buf_size, buf_size_ret));
	return (0);
}

/* Import from big-endian hex string (H->L). */
static inline int
bn_import_be_hex(bn_p bn, const uint8_t *buf, size_t buf_size) {

	BN_POINTER_CHK_EINVAL(bn);
	BN_PREFETCH_BN_DATA(bn);
	bn_init_digits__int(bn, bn->count);
	BN_RET_ON_ERR(bn_digits_import_be_hex(bn->num, bn->count, buf, buf_size));
	bn_update(bn);
	return (0);
}
/* Export to big-endian hex string (H->L). */
static inline int
bn_export_be_hex(bn_p bn, uint32_t flags, uint8_t *buf, size_t buf_size,
    size_t *buf_size_ret) {

	BN_POINTER_CHK_EINVAL(bn);
	BN_RET_ON_ERR(bn_digits_export_be_hex(bn->num, bn->digits, flags,
	    buf, buf_size, buf_size_ret));
	return (0);
}

/*------------------------------ ASSIGNMENTS ---------------------------------*/
/* Assigns: a = b. */
static inline int
bn_assign(bn_p dst, bn_p src) {

	BN_POINTER_CHK_EINVAL(dst);
	BN_POINTER_CHK_EINVAL(src);
	if (dst == src)
		return (0);
	if (src->digits > dst->count)
		return (EOVERFLOW);
	dst->digits = src->digits;
	memcpy(dst->num, src->num, (BN_DIGIT_SIZE * src->digits));
	return (0);
}

static inline int
bn_assign_init(bn_p dst, bn_p src) {

	BN_POINTER_CHK_EINVAL(dst);
	BN_POINTER_CHK_EINVAL(src);
	if (dst == src)
		return (0);
	dst->count = src->count;
	dst->digits = src->digits;
	memcpy(dst->num, src->num, (BN_DIGIT_SIZE * src->digits));
	return (0);
}

/* Assigns: a = 0. */
static inline void
bn_assign_zero(bn_p bn) {

	if (NULL == bn)
		return;
	bn->digits = 0;
}


/* Assigns: a = 2^exp. bn_bit_set() */
static inline int
bn_assign_2exp(bn_p bn, size_t exp) {

	bn_assign_zero(bn);
	BN_RET_ON_ERR(bn_bit_set(bn, exp, 1));
	return (0);
}

/* Assigns: a = b, where b is a digit. */
static inline int
bn_assign_digit(bn_p bn, bn_digit_t digit) {

	BN_POINTER_CHK_EINVAL(bn);
	if (0 == bn->count)
		return (EOVERFLOW);
	bn->digits = 1;
	bn->num[0] = digit;
	return (0);
}

/*-------------------------- ARITHMETIC OPERATIONS ---------------------------*/
/* Computes: bn *= 2^bits (i.e. shifts left c bits). */
static inline void
bn_l_shift(bn_p bn, size_t bits) {
	size_t digits;

	if (NULL == bn || 0 == bn->digits)
		return;
#if 0
	if ((bn->count * BN_DIGIT_BITS) <= bits) {
		bn_assign_zero(bn);
		return;
	}
#endif
	digits = min(bn->count, (bn->digits + 1 + (bits / BN_DIGIT_BITS)));
	bn_init_digits__int(bn, digits);
	bn_digits_l_shift(bn->num, digits, bits);
	bn_update_digits__int(bn, digits);
}
/* Computes: bn /= 2^bits (i.e. shifts right c bits). */
static inline void
bn_r_shift(bn_p bn, size_t bits) {

	if (NULL == bn || 0 == bn->digits)
		return;
#if 0
	if ((bn->digits * BN_DIGIT_BITS) <= bits) {
		bn_assign_zero(bn);
		return;
	}
#endif
	bn_digits_r_shift(bn->num, bn->digits, bits);
	bn_update_digits__int(bn, bn->digits);
}

/* Computes: bn &= n. */
static inline int
bn_and(bn_p bn, bn_p n) {
	register size_t i, digits;

	BN_POINTER_CHK_EINVAL(bn);
	BN_POINTER_CHK_EINVAL(n);
	BN_PREFETCH_BN_DATA(bn);
	BN_PREFETCH_BN_DATA(n);
	digits = min(bn->digits, n->digits);
	for (i = 0; i < digits; i ++) {
		bn->num[i] &= n->num[i];
	}
	if (bn->count > digits) {
		bn->num[digits] = 0;
	}
	bn_update_digits__int(bn, digits);
	return (0);
}

/* Computes: bn |= n. */
static inline int
bn_or(bn_p bn, bn_p n) {
	size_t i, digits;

	BN_POINTER_CHK_EINVAL(bn);
	BN_POINTER_CHK_EINVAL(n);
	if (bn->count < n->digits)
		return (EOVERFLOW);
	BN_PREFETCH_BN_DATA(bn);
	BN_PREFETCH_BN_DATA(n);
	digits = max(bn->digits, n->digits);
	bn_init_digits__int(bn, digits);
	for (i = 0; i < n->digits; i ++) {
		bn->num[i] |= n->num[i];
	}
	bn_update_digits__int(bn, digits);
	return (0);
}

/* Computes: bn ^= n. */
static inline int
bn_xor(bn_p bn, bn_p n) {
	size_t i, digits;

	BN_POINTER_CHK_EINVAL(bn);
	BN_POINTER_CHK_EINVAL(n);
	if (bn->count < n->digits)
		return (EOVERFLOW);
	BN_PREFETCH_BN_DATA(bn);
	BN_PREFETCH_BN_DATA(n);
	digits = max(bn->digits, n->digits);
	bn_init_digits__int(bn, digits);
	for (i = 0; i < n->digits; i ++) {
		bn->num[i] ^= n->num[i];
	}
	bn_update_digits__int(bn, digits);
	return (0);
}


/* Computes: bn += n. Returns carry. */
static inline void
bn_add_digit(bn_p bn, bn_digit_t n, bn_digit_t *carry) {
	size_t digits;

	if (NULL == bn || 0 == n)
		return;
	digits = (bn->digits + 1);
	bn_init_digits__int(bn, digits);
	bn_digits_add_digit(bn->num, bn->count, n, carry);
	bn_update_digits__int(bn, digits);
}
static inline int
bn_add(bn_p bn, bn_p n, bn_digit_t *carry) {
	size_t digits;

	BN_POINTER_CHK_EINVAL(bn);
	BN_POINTER_CHK_EINVAL(n);
	digits = (max(bn->digits, n->digits) + 1);
	bn_init_digits__int(bn, digits);
	BN_RET_ON_ERR(bn_digits_add(bn->num, bn->count,
	    n->num, n->digits, carry));
	bn_update_digits__int(bn, digits);
	return (0);
}

/* Computes: bn -= n. Returns borrow. */
static inline void
bn_sub_digit(bn_p bn, bn_digit_t n, bn_digit_t *borrow) {
	size_t digits;

	if (NULL == bn || 0 == n)
		return;
	digits = bn->digits;
	if (0 == digits || (1 == digits && bn->num[0] < n)) {
		digits = bn->count;
	}
	bn_init_digits__int(bn, digits);
	bn_digits_sub_digit(bn->num, bn->count, n, borrow);
	bn_update_digits__int(bn, digits);
}

static inline int
bn_sub(bn_p bn, bn_p n, bn_digit_t *borrow) {
	size_t digits;

	BN_POINTER_CHK_EINVAL(bn);
	BN_POINTER_CHK_EINVAL(n);
	if (bn == n) {
		bn_assign_zero(bn);
		if (NULL != borrow) {
			(*borrow) = 0;
		}
	}
	digits = bn->digits;
	if (digits < n->digits ||
	    (digits == n->digits && bn->num[(digits - 1)] <= n->num[(digits - 1)])) {
		digits = bn->count;
	}
	bn_init_digits__int(bn, digits);
	BN_RET_ON_ERR(bn_digits_sub(bn->num, bn->count,
	    n->num, n->digits, borrow));
	bn_update_digits__int(bn, digits);
	return (0);
}

/* Computes: bn *= n. */
static inline int
bn_mult(bn_p bn, bn_p n) {
	bn_t tmp;
	bn_p multiplicand, multiplier;
	size_t j, digits;

	/* Speed optimizations. */
	if (0 != bn_is_zero(bn) || 0 != bn_is_zero(n)) {
		bn_assign_zero(bn);
		return (0);
	}
	digits = (bn->digits + n->digits);
	if (digits > bn->count)
		return (EOVERFLOW);
#if 0 /* Also this check is bn or n == 1 */
	if (0 != bn_is_pow2(bn)) {
		j = bn_ctz(bn);
		BN_RET_ON_ERR(bn_assign(bn, n));
		bn_l_shift(bn, j);
		return (0);
	}
	if (0 != bn_is_pow2(n)) {
		bn_l_shift(bn, bn_ctz(n));
		return (0);
	}
#endif
	BN_RET_ON_ERR(bn_assign_init(&tmp, bn));
	if (bn == n) { /* bn = n */
		multiplicand = &tmp;
		multiplier = &tmp;
	} else {
		if (bn_cmp(&tmp, n) > 0) { /* bn => n */
			multiplicand = &tmp;
			multiplier = n;
		} else {
			multiplicand = n;
			multiplier = &tmp;
		}
	}
	/* Calculation. */
	bn_assign_zero(bn);
	BN_PREFETCH_BN_DATA(bn);
	BN_PREFETCH_BN_DATA(n);
	bn_init_digits__int(bn, digits);
	for (j = 0; j < multiplier->digits; j ++) {
		if (0 == multiplier->num[j])
			continue;
		bn_digits_add_digit_mult__int(&bn->num[j],
		    (digits - j), multiplicand->num, multiplicand->digits,
		    multiplier->num[j]);
	}
	bn_update_digits__int(bn, digits);
	return (0);
}
/* Computes bn = bn * n. */
static inline int
bn_mult_digit(bn_p bn, bn_digit_t n) {
	bn_t tmp;
	size_t digits;

	/* Speed optimizations. */
	if (0 != bn_is_zero(bn))
		return (0);

	switch (n) {
	case 0:
		bn_assign_zero(bn);
		break;
	case 1:
		break;
	case 2: // XXX shift check
		BN_RET_ON_ERR(bn_add(bn, bn, NULL));
		break;
	case 3:
		BN_RET_ON_ERR(bn_assign_init(&tmp, bn));
		BN_RET_ON_ERR(bn_add(&tmp, &tmp, NULL));
		BN_RET_ON_ERR(bn_add(bn, &tmp, NULL));
		break;
	default:
		digits = bn->digits;
		if (digits >= bn->count)
			return (EOVERFLOW);
		digits ++;
		BN_PREFETCH_BN_DATA(bn);
		bn_init_digits__int(bn, digits);
		bn_digits_mult_digit__int(bn->num, digits, n);
		bn_update_digits__int(bn, digits);
		break;
	}
	return (0);
}
/* Computes: bn = bn^2 */
static inline int
bn_square(bn_p bn) {

	BN_RET_ON_ERR(bn_mult(bn, bn));
	return (0);
}
/* Computes: bn = bn^exp */
/* Binary powering, aka exponentiation by squaring. */
static inline int
bn_exp_digit(bn_p bn, bn_digit_t exp) {
	bn_t base;

	BN_POINTER_CHK_EINVAL(bn);
	/* Speed optimizations. */
	switch (exp) {
	case 0: /* bn^0 = 1 */
		BN_RET_ON_ERR(bn_assign_digit(bn, 1));
		return (0);
	case 1: /* bn^1 = bn */
		return (0);
	case 2: /* bn^2 = bn_square() = bn*bn */
		BN_RET_ON_ERR(bn_mult(bn, bn));
		return (0);
	}
	if ((bn->digits * exp) > bn->count)
		return (EOVERFLOW);
	if (1 == bn->digits) {
		switch (bn->num[0]) {
		case 0: /* 0^exp = 0, exp != 0 */
		case 1: /* 1^exp = 1, exp != 0 */
			return (0);
		case 2:
			BN_RET_ON_ERR(bn_assign_2exp(bn, exp));
			return (0);
		}
	}
	/* Calculation. */
	BN_RET_ON_ERR(bn_assign_init(&base, bn));
	BN_RET_ON_ERR(bn_assign_digit(bn, 1));
	for (; 0 != exp; exp >>= 1) {
		if (0 != (exp & 1)) {
			BN_RET_ON_ERR(bn_mult(bn, &base));
		}
		BN_RET_ON_ERR(bn_mult(&base, &base));
	}
	return (0);
}

/*  Computes: bn = bn div d, remainder = bn mod d. */
/*  Computes: bn /= d, remainder = bn % d. */
static inline int
bn_div(bn_p bn, bn_p d, bn_p remainder) {
	int error = 0;
	size_t shift;
	ssize_t j;
	bn_digit_t ai, t;
	bn_t tnn, tdd;
	bn_p nn = &tnn, dd = &tdd;

	/* Internal: n = bn; bn = n / d. */
	BN_POINTER_CHK_EINVAL(bn);
	BN_POINTER_CHK_EINVAL(d);
	if (0 != bn_is_zero(d)) /* dividend / 0 !!! */
		return (EINVAL);
	if (bn == d) /* n = d */
		goto n_eq_d;
#if 0
	/* Speed optimizations. */
	if (0 != bn_is_zero(bn)) { /* 0 / divisor, return 0. */
		if (bn != remainder) {
			bn_assign_zero(remainder);
		}
		return (0);
	}
	if (0 != bn_is_one(d)) { /* dividend / 1, return dividend. */
		bn_assign_zero(remainder);
		return (0);
	}
	if (0 != bn_is_pow2(d)) {
		shift = bn_ctz(d);
		if (NULL != remainder) { /* = (bn & ((1 < shift) - 1)) */
			BN_RET_ON_ERR(bn_assign_init(nn, bn));
			BN_RET_ON_ERR(bn_assign_2exp(nn, shift));
			bn_sub_digit(nn, 1, NULL);
			BN_RET_ON_ERR(bn_assign(remainder, bn));
			BN_RET_ON_ERR(bn_and(remainder, nn));
		}
		if (bn != remainder) {
			bn_r_shift(bn, shift);
		}
		return (0);
	}
#endif
	switch (bn_cmp(bn, d)) {
	case 0: /* n = d */
n_eq_d:
		if (bn != remainder) {
			bn_assign_digit(bn, 1);
		}
		bn_assign_zero(remainder);
		return (0);
	case -1: /* n < d */
		if (bn != remainder) {
			if (NULL != remainder) {
				error = bn_assign(remainder, bn);
			}
			bn_assign_zero(bn);
		}
		return (error);
	}
	/* Normalize operands. */
	shift = bn_digit_clz(d->num[(d->digits - 1)]);
	if (bn->count == bn->digits && shift > bn_digit_clz(bn->num[(bn->digits - 1)]))
		return (EOVERFLOW); /* Not enouth space in nn to hold normalized. */
	BN_RET_ON_ERR(bn_assign_init(dd, d));
	bn_init_digits__int(dd, dd->count);
	bn_l_shift(dd, shift);
	t = dd->num[(dd->digits - 1)];
	BN_RET_ON_ERR(bn_assign_init(nn, bn));
	bn_init_digits__int(nn, nn->count);
	bn_l_shift(nn, shift); /* XXX: Data lost here & update digits count. */

	/* Calculation. */
	bn_assign_zero(bn);
	//bn_init_digits__int(bn, (1 + nn->digits - dd->digits));
	for (j = (ssize_t)(nn->digits - dd->digits); j >= 0; j --) {
		/* Underestimate quotient digit and subtract. */
		if (nn->count == ((size_t)j + dd->digits)) {
			if (t == BN_MAX_DIGIT) {
				ai = 0;
			} else {
				/*BN_RET_ON_ERR(bn_digit_div__int_short(
				    nn->num[(j + dd->digits - 1)], 0, (t + 1), &ai));*/
				ai = (nn->num[((size_t)j + dd->digits - 1)] / (t + 1));
			}
		} else {
			if (t == BN_MAX_DIGIT) {
				ai = nn->num[((size_t)j + dd->digits)];
			} else {
				BN_RET_ON_ERR(bn_digit_div__int_short(
				    nn->num[((size_t)j + dd->digits - 1)],
				    nn->num[((size_t)j + dd->digits)], (t + 1), &ai));
			}
		}
		if (0 != ai) {
			bn_digits_sub_digit_mult__int(&nn->num[j], (size_t)(nn->digits - (size_t)j),
			    dd->num, dd->digits, ai, NULL);
		}
		/* Correct estimate. */
		while ((nn->count > ((size_t)j + dd->digits) && 
		    0 != nn->num[((size_t)j + dd->digits)]) ||
		    bn_digits_cmp(&nn->num[j], dd->num, dd->digits) >= 0) {
			ai ++;
			bn_digits_sub__int(&nn->num[j], (size_t)(nn->digits - (size_t)j),
			    dd->num, dd->digits, NULL);
		}
		bn->num[j] = ai;
	}
	bn_update_digits__int(bn, (1 + nn->digits - dd->digits));
	if (NULL != remainder) { /* Restore result. */
		bn_update_digits__int(nn, nn->digits);
		bn_r_shift(nn, shift);
		BN_RET_ON_ERR(bn_assign(remainder, nn));
	}
	return (0);
}


/* Computes: bn = gcd(a, b). */
/* Euclid's algorithm */
static inline int
bn_gcd(bn_p bn, bn_p a, bn_p b) {
	bn_t tmp;
	bn_p ta = bn, tb = &tmp;

	BN_POINTER_CHK_EINVAL(bn);
	BN_POINTER_CHK_EINVAL(a);
	BN_POINTER_CHK_EINVAL(b);
	/* Speed optimizations. */
	if (0 != bn_is_zero(a)) {
		BN_RET_ON_ERR(bn_assign(bn, b));
		return (0);
	}
	if (0 != bn_is_zero(b)) {
		BN_RET_ON_ERR(bn_assign(bn, a));
		return (0);
	}
	switch (bn_cmp(a, b)) {
	case -1: /* a < b */
		BN_RET_ON_ERR(bn_assign_init(tb, a));
		BN_RET_ON_ERR(bn_assign_init(ta, b));
		break;
	case 0: /* a = b */
		BN_RET_ON_ERR(bn_assign(bn, a));
		return (0);
	case 1: /* a > b */
		BN_RET_ON_ERR(bn_assign_init(ta, a));
		BN_RET_ON_ERR(bn_assign_init(tb, b));
		break;
	}

	while (0 == bn_is_zero(tb)) {
		BN_RET_ON_ERR(bn_div(ta, tb, ta)); /* = bn_mod(ta, tb); // ta = ta mod tb */
		bn_swap_ptr(ta, tb); /* swap(ta, tb) */
	}
	BN_RET_ON_ERR(bn_assign(bn, ta));
	return (0);
}
/* Binary GCD / Stein's algorithm */
static inline int
bn_gcd_bin(bn_p bn, bn_p a, bn_p b) {
	size_t shift, shift_a, shift_b;
	bn_t tmp;
	bn_p ta = bn, tb = &tmp;

	BN_POINTER_CHK_EINVAL(bn);
	BN_POINTER_CHK_EINVAL(a);
	BN_POINTER_CHK_EINVAL(b);
	/* Speed optimizations. */
	if (0 != bn_is_zero(a)) {
		BN_RET_ON_ERR(bn_assign(bn, b));
		return (0);
	}
	if (0 != bn_is_zero(b)) {
		BN_RET_ON_ERR(bn_assign(bn, a));
		return (0);
	}
	if (0 == bn_cmp(a, b)) { /* a = b */
		BN_RET_ON_ERR(bn_assign(bn, a));
		return (0);
	}

	BN_RET_ON_ERR(bn_assign_init(ta, a));
	BN_RET_ON_ERR(bn_assign_init(tb, b));
	/* Let shift = the greatest power of 2 dividing both a and b. */
	shift_a = bn_ctz(ta);
	shift_b = bn_ctz(tb);
	shift = ((shift_a >= shift_b) ? shift_b : shift_a); /* min(shift_a, shift_b) */
	bn_r_shift(ta, shift_a); /* Remove all factors of 2 in a. */

	/* From here on, a is always odd. */
	while (0 == bn_is_zero(tb)) {
		/* Remove all factors of 2 in b -- they are not common. */
		bn_r_shift(tb, shift_b);
		/* Now a and b are both odd. Swap if necessary so a <= b,
		 * then set b -= a (which is even). */
		if (bn_cmp(ta, tb) > 0) {
			bn_swap_ptr(ta, tb);
		}
		BN_RET_ON_ERR(bn_sub(tb, ta, NULL)); /* Here b >= a. */
		shift_b = bn_ctz(tb);
	}
	BN_RET_ON_ERR(bn_assign(bn, ta));
	bn_l_shift(bn, shift); /* Restore common factors of 2. */
	return (0);
}
/* Extended Euclid's algorithm */
static inline int
bn_egcd(bn_p bn, bn_p a, bn_p b, bn_p ax, bn_p by) {
	bn_digit_t borrow;
	bn_t tmp, q, t, tx_prev, ty_prev;
	bn_p ta = bn, tb = &tmp, x = ax, x_prev = &tx_prev, y = by, y_prev = &ty_prev;

	BN_POINTER_CHK_EINVAL(bn);
	BN_POINTER_CHK_EINVAL(a);
	BN_POINTER_CHK_EINVAL(b);
	/* Speed optimizations. */
	if (NULL == x && NULL == y) {
		BN_RET_ON_ERR(bn_gcd(bn, a, b));
		return (0);
	}
	/* Init big digits, set values for case: a > b. */
	if (NULL != x) {
		bn_assign_zero(x);
		BN_RET_ON_ERR(bn_init(x_prev, (BN_DIGIT_BITS * x->count)));
		BN_RET_ON_ERR(bn_assign_digit(x_prev, 1));
	}
	if (NULL != y) {
		BN_RET_ON_ERR(bn_assign_digit(y, 1));
		BN_RET_ON_ERR(bn_init(y_prev, (BN_DIGIT_BITS * y->count)));
	}
	/* Speed optimizations. */
	if (0 != bn_is_zero(a)) {
		ta = b;
		x_prev = x;
		y_prev = y;
		goto ok_exit; /* return (b, x = 0, y = 1); */
	}
	if (0 != bn_is_zero(b)) {
		ta = a;
		goto ok_exit; /* return (a, x = 1, y = 0); */
	}
	switch (bn_cmp(a, b)) {
	case -1: /* a < b */
		BN_RET_ON_ERR(bn_assign_init(ta, b));
		BN_RET_ON_ERR(bn_assign_init(tb, a));
		bn_digit_swap(x->num[0], y->num[0]); /* bn_swap_ptr(x, y); - will damage result! */
		bn_swap_ptr(x_prev, y_prev);
		break;
	case 0: /* a = b */
		ta = a;
		y_prev = y;
		goto ok_exit; /* return (a, x = 1, y = 1); */
	case 1: /* a > b */
		BN_RET_ON_ERR(bn_assign_init(ta, a));
		BN_RET_ON_ERR(bn_assign_init(tb, b));
		break;
	}

	/* Init temp big digits. */
	BN_RET_ON_ERR(bn_init(&q, ((ta->count + 1) * BN_DIGIT_BITS)));
	BN_RET_ON_ERR(bn_init(&t, (2 * q.count * BN_DIGIT_BITS)));
	while (0 == bn_is_zero(tb)) {
		/* q = a div b; (a, b) = (b, a mod b); */
		BN_RET_ON_ERR(bn_assign(&q, ta));
		BN_RET_ON_ERR(bn_div(&q, tb, ta));
		bn_swap_ptr(ta, tb);
		if (NULL != x) { /* (x, lastx) = (lastx - quotient*x, x); */
			BN_RET_ON_ERR(bn_assign(&t, &q));
			BN_RET_ON_ERR(bn_mult(&t, x)); /* t = q*x */
			BN_RET_ON_ERR(bn_add(x_prev, &t, &borrow)); /* x_prev -= t; */
			//BN_RET_ON_ERR(bn_sub(x_prev, &t, &borrow)); /* x_prev -= t; */
			//if (0 != borrow)
			//	bn_inverse(x_prev);
			bn_swap_ptr(x, x_prev);
		}
		if (NULL != y) { /* (y, lasty) = (lasty - quotient*y, y); */
			BN_RET_ON_ERR(bn_assign(&t, &q));
			BN_RET_ON_ERR(bn_mult(&t, y)); /* t = q*y */
			BN_RET_ON_ERR(bn_add(y_prev, &t, &borrow)); /* y_prev -= t; */
			//BN_RET_ON_ERR(bn_sub(y_prev, &t, &borrow)); /* y_prev -= t; */
			//if (0 != borrow)
			//	bn_inverse(y_prev);
			bn_swap_ptr(y, y_prev);
		}
	}
ok_exit:
	BN_RET_ON_ERR(bn_assign(bn, ta));
	BN_RET_ON_ERR(bn_assign(ax, x_prev));
	BN_RET_ON_ERR(bn_assign(by, y_prev));
	return (0);
}


#define bn_sqrt(bn)	bn_sqrt1(bn) // 
//#define bn_sqrt(bn)	bn_sqrt2(bn) // 
//#define bn_sqrt(bn)	bn_sqrt3(bn) // 
//#define bn_sqrt(bn)	bn_sqrt4(bn) // 
//#define bn_sqrt(bn)	bn_sqrt5(bn) // 

/* Computes: Square root: bn = √bn. */
/* http://en.wikipedia.org/wiki/Methods_of_computing_square_roots */
static inline int
bn_sqrt1(bn_p bn) {
	size_t bits;
	bn_t res, bit, tmp;

	BN_POINTER_CHK_EINVAL(bn);
	bits = (bn->count * BN_DIGIT_BITS);
	BN_RET_ON_ERR(bn_init(&res, bits));
	BN_RET_ON_ERR(bn_init(&bit, bits));
	BN_RET_ON_ERR(bn_init(&tmp, bits));
	BN_RET_ON_ERR(bn_assign_2exp(&bit, (bits - bn_clz(bn))));
	while (bn_cmp(&bit, bn) > 0) {
		bn_r_shift(&bit, 2);
	}

	while (0 == bn_is_zero(&bit)) {
		BN_RET_ON_ERR(bn_assign(&tmp, &res));
		BN_RET_ON_ERR(bn_add(&tmp, &bit, NULL));
		bn_r_shift(&res, 1);
		if (bn_cmp(bn, &tmp) >= 0) {
			BN_RET_ON_ERR(bn_sub(bn, &tmp, NULL));
			BN_RET_ON_ERR(bn_add(&res, &bit, NULL));
		}
		bn_r_shift(&bit, 2);
	}
	BN_RET_ON_ERR(bn_assign(bn, &res));
	return (0);
}
/*
 *	Square root by abacus algorithm, Martin Guy @ UKC, June 1985.
 *	From a book on programming abaci by Mr C. Woo.
 *	Argument is a positive integer, as is result.
 *
 *	I have formally proved that on exit:
 *		   2		   2		   2
 *		res  <= x < (res+1)	and	res  + op == x
 *
 *	This is also nine times faster than the library routine (-lm).
 */
static inline int
bn_sqrt2(bn_p bn) {
	size_t bits;
	bn_t res, bit, tmp;

	BN_POINTER_CHK_EINVAL(bn);
	bits = (bn->count * BN_DIGIT_BITS);
	BN_RET_ON_ERR(bn_init(&res, bits));
	BN_RET_ON_ERR(bn_init(&bit, bits));
	BN_RET_ON_ERR(bn_init(&tmp, bits));
	BN_RET_ON_ERR(bn_assign_2exp(&bit, (bits - bn_clz(bn))));
	while (bn_cmp(&bit, bn) > 0) {
		bn_r_shift(&bit, 2);
	}

	while (0 == bn_is_zero(&bit)) {
		BN_RET_ON_ERR(bn_assign(&tmp, &res));
		BN_RET_ON_ERR(bn_add(&tmp, &bit, NULL));
		if (bn_cmp(bn, &tmp) >= 0) {
			BN_RET_ON_ERR(bn_sub(bn, &tmp, NULL));
			BN_RET_ON_ERR(bn_assign(&tmp, &bit));
			bn_l_shift(&tmp, 1);
			BN_RET_ON_ERR(bn_add(&res, &tmp, NULL));
		}
		bn_r_shift(&res, 1);
		bn_r_shift(&bit, 2);
	}
	BN_RET_ON_ERR(bn_assign(bn, &res));
	return (0);
}

static inline int
bn_sqrt3(bn_p bn) {
	size_t bits;
	ssize_t bit;
	bn_t res, tmp;

	BN_POINTER_CHK_EINVAL(bn);
	bits = (bn->count * BN_DIGIT_BITS);
	bit = (ssize_t)(bits - bn_clz(bn));
	bit &= ~((size_t)1);
	BN_RET_ON_ERR(bn_init(&res, bits));
	BN_RET_ON_ERR(bn_init(&tmp, bits));

	while (bit >= 0) {
		BN_RET_ON_ERR(bn_assign(&tmp, &res));
		BN_RET_ON_ERR(bn_bit_set(&tmp, (size_t)bit, 1));
		bn_r_shift(&res, 1);
		if (bn_cmp(bn, &tmp) >= 0) {
			BN_RET_ON_ERR(bn_sub(bn, &tmp, NULL));
			BN_RET_ON_ERR(bn_bit_set(&res, (size_t)bit, 1));
		}
		bit -= 2;
	}
	BN_RET_ON_ERR(bn_assign(bn, &res));
	return (0);
}
/* Binary Square Root algorithm, explained fully in Embedded.com article. */
static inline int
bn_sqrt4(bn_p bn) {/* broken? */
	size_t i, bits;
	bn_t root, rem;

	BN_POINTER_CHK_EINVAL(bn);
	bits = (bn->count * BN_DIGIT_BITS);
	BN_RET_ON_ERR(bn_init(&root, bits));
	BN_RET_ON_ERR(bn_init(&rem, bits));
	bits = ((bits - bn_clz(bn)) / 2);

	for (i = 0; i < bits; i ++) {
		bn_l_shift(&rem, 2);
		if (0 != bn_is_bit_set(bn, (i * 2))) {
			BN_RET_ON_ERR(bn_bit_set(&rem, 0, 1));
		}
		if (0 != bn_is_bit_set(bn, ((i * 2) + 1))) {
			BN_RET_ON_ERR(bn_bit_set(&rem, 1, 1));
		}
		bn_l_shift(&root, 1);
		if (bn_cmp(&root, &rem) < 0) {
			BN_RET_ON_ERR(bn_bit_set(&root, 0, 1)); /* ++ */
			BN_RET_ON_ERR(bn_sub(&rem, &root, NULL));
			bn_add_digit(&root, 1, NULL);
		}
	}
	bn_r_shift(&root, 1);
	BN_RET_ON_ERR(bn_assign(bn, &root));
	return (0);
}

static inline int
bn_sqrt5(bn_p bn) {
	size_t bits;
	bn_t res, tmp;

	BN_POINTER_CHK_EINVAL(bn);
	bits = 1 + ((bn->count * BN_DIGIT_BITS) - bn_clz(bn)) / 2;
	BN_RET_ON_ERR(bn_init(&tmp, (bn->count * BN_DIGIT_BITS)));
	BN_RET_ON_ERR(bn_init(&res, (bn->count * BN_DIGIT_BITS)));
	BN_RET_ON_ERR(bn_assign_2exp(&res, bits));

	for (;; bits --) {
		BN_RET_ON_ERR(bn_bit_set(&res, bits, 1)); /* Set bit.*/
		BN_RET_ON_ERR(bn_assign(&tmp, &res));
		BN_RET_ON_ERR(bn_square(&tmp));
		if (bn_cmp(&tmp, bn) > 0) {
			BN_RET_ON_ERR(bn_bit_set(&res, bits, 0)); /* Unset bit.*/
		}
		if (0 == bits)
			break;
	}
	BN_RET_ON_ERR(bn_assign(bn, &res));
	return (0);
}


/* Shared code for COMB mult. */
/* Get bits from bit_offset in all windows and return result as bn_digit_t. */
static inline bn_digit_t
bn_combo_column_get(bn_p bn, size_t bit_off, size_t wnd_bits, size_t wnd_count) {
	register size_t i, off, bits_cnt;
	register bn_digit_t res = 0;

	if (NULL == bn)
		return (res);
	bits_cnt = (bn->digits * BN_DIGIT_BITS);
	for (i = wnd_bits, off = bit_off; i > 0; i --, off -= wnd_count) {
		res <<= 1;
		//if (0 != bn_is_bit_set(bn, off))
		if (bits_cnt > off &&
		    0 != (bn->num[(off / BN_DIGIT_BITS)] & (((bn_digit_t)1) << (off % BN_DIGIT_BITS)))) {
			res |= 1;
		}
	}
	return (res);
}

/* [1]: Algorithm 3.50 Joint sparse form */
static inline int
bn_calc_jsf(bn_p a, bn_p b, size_t jsf_arr_size,
    int8_t *jsf_arr, size_t *jsf_arr_items_cnt_ret, size_t *offset_ret) {
	bn_t tmA, tmB;
	register size_t i = 0, offset;
	register bn_digit_t l0, l1;
	register int8_t itm, d0 = 0, d1 = 0;

	if (NULL == a || NULL == b || NULL == jsf_arr)
		return (EINVAL);
	offset = (max(bn_calc_bits(a), bn_calc_bits(b)) + 1);
	if (jsf_arr_size < (2 * offset))
		return (EOVERFLOW);
	BN_RET_ON_ERR(bn_assign_init(&tmA, a));
	BN_RET_ON_ERR(bn_assign_init(&tmB, b));

	while ((0 == bn_is_zero(&tmA) || 0 != d0) ||
	    (0 == bn_is_zero(&tmB) || 0 != d1)) {
		l0 = (((int8_t)tmA.num[0] + d0) & 0x7); /* mod 8. */
		l1 = (((int8_t)tmB.num[0] + d1) & 0x7);

		if (0 != bn_digit_is_even(l0)) {
			itm = 0;
		} else {
			itm = (2 - (l0 & 0x3));
			if ((3 == l0 || 5 == l0) && (2 == (l1 & 0x3))) {
				itm = - itm;
			}
		}
		jsf_arr[i] = itm;
		if ((2 * d0) == (1 + itm)) {
			d0 = (int8_t)(1 - d0);
		}

		if (0 != bn_digit_is_even(l1)) {
			itm = 0;
		} else {
			itm = (2 - (l1 & 0x3));
			if ((3 == l1 || 5 == l1) && (2 == (l0 & 0x3))) {
				itm = - itm;
			}
		}
		jsf_arr[(i + offset)] = itm;
		if ((2 * d1) == (1 + itm)) {
			d1 = (int8_t)(1 - d1);
		}

		i ++;
		bn_r_shift(&tmA, 1); // >> 1
		bn_r_shift(&tmB, 1); // >> 1
	}
	if (NULL != jsf_arr_items_cnt_ret)
		(*jsf_arr_items_cnt_ret) = i;
	if (NULL != offset_ret)
		(*offset_ret) = offset;
	return (0);
}

/* [1]: Algorithm 3.30 Computing the NAF of a positive integer */
/* [1]: Algorithm 3.35 Computing the width-w NAF of a positive integer */
static inline int
bn_calc_naf(bn_p bn, size_t wnd_bits, size_t naf_arr_size, int8_t *naf_arr,
    size_t *naf_arr_items_cnt_ret) {
	bn_t tm;
	register size_t i = 0;
	register bn_digit_t mask;
	register int8_t itm;
	register uint8_t sign_bit;

	if (NULL == bn || 2 > wnd_bits || NULL == naf_arr)
		return (EINVAL);
	if (naf_arr_size < (bn_calc_bits(bn) + 1))
		return (EOVERFLOW);
	mask = ((((bn_digit_t)1) << wnd_bits) - 1);
	sign_bit = (uint8_t)(((uint8_t)1) << (wnd_bits - 1));
	BN_RET_ON_ERR(bn_assign_init(&tm, bn));

	while (0 == bn_is_zero(&tm)) {
		if (0 != (tm.num[0] & 1)) { /* Is odd? */
			/* Get wnd_bits bits, convert to +-(wnd_bits/2). */
#if 1
			itm = (int8_t)(tm.num[0] & mask);
			if (0 != (sign_bit & itm)) {
				itm -= (sign_bit * 2);
			}
#else /* Original from 3.30 and 3.35 */
			if (2 == wnd_bits) {
				itm = (2 - (tm.num[0] & mask));
				/* 0:  2
				 * 1:  1
				 * 2:  0
				 * 3: -1
				 */
			} else {
				itm = (tm.num[0] & mask);
				if (sign_bit < itm) {
					itm -= (sign_bit * 2);
				}
				/* 0:  0
				 * 1:  1
				 * 2:  0
				 * 3: -1
				 */
			}
#endif
			if (itm < 0) {
				bn_add_digit(&tm, (bn_digit_t)-itm, NULL);
			} else {
				bn_sub_digit(&tm, (bn_digit_t)itm, NULL);
			}
			naf_arr[i] = itm;
		} else {
			naf_arr[i] = 0;
		}
		bn_r_shift(&tm, 1); // >> 1
		i ++;
	}
	memset(&naf_arr[i], 0, (naf_arr_size - i));

	if (NULL != naf_arr_items_cnt_ret)
		(*naf_arr_items_cnt_ret) = i;
	return (0);
}




/*------------------------- NUMBER THEORY ------------------------------------*/

/* From Handbook of Applied Cryptography Algorithm 14.42 */
/* Init Barrett Reduction. */
static inline int
bn_mod_rd_data_init(bn_p m, bn_mod_rd_data_p mod_rd_data) {

	BN_POINTER_CHK_EINVAL(m);
	BN_POINTER_CHK_EINVAL(mod_rd_data);
#if BN_MOD_REDUCE_ALGO == BN_MOD_REDUCE_ALGO_BASIC
	/* Nothink to do. */
	/* Supress warnings. */
	m = NULL;
	mod_rd_data = NULL;
#elif BN_MOD_REDUCE_ALGO == BN_MOD_REDUCE_ALGO_BARRETT

	BN_RET_ON_ERR(bn_init(&mod_rd_data->Barrett,
	    (BN_DIGIT_BITS * 2 * (m->digits + 1))));
	//mod_rd_data->Barrett.num[(2 * m->digits)] = 1;
	BN_RET_ON_ERR(bn_bit_set(&mod_rd_data->Barrett,
	    (BN_DIGIT_BITS * 2 * m->digits), 1));
	BN_RET_ON_ERR(bn_div(&mod_rd_data->Barrett, m, NULL));
#endif /* BN_MOD_REDUCE_ALGO */

	return (0);
}


/* Computes: bn = bn mod m. */
static inline int
bn_mod(bn_p bn, bn_p m, bn_mod_rd_data_p mod_rd_data) {

#if BN_MOD_REDUCE_ALGO == BN_MOD_REDUCE_ALGO_BASIC

	mod_rd_data = NULL; /* Supress warning. */
	BN_RET_ON_ERR(bn_div(bn, m, bn)); /* bn_div() do calculations only if bn > m. */

#elif BN_MOD_REDUCE_ALGO == BN_MOD_REDUCE_ALGO_BARRETT
	bn_t q, r;

	if (NULL == mod_rd_data || 0 == mod_rd_data->Barrett.digits) {
		BN_RET_ON_ERR(bn_div(bn, m, bn)); /* bn_div() do calculations only if bn > m. */
		return (0);
	}
	if (bn_cmp(bn, m) < 0) /* bn < m */
		return (0);

	BN_RET_ON_ERR(bn_init(&q, (BN_DIGIT_BITS * 2 * (m->digits + 6))));
	BN_RET_ON_ERR(bn_init(&r, (BN_DIGIT_BITS * 2 * (m->digits + 4))));

#if 0
	BN_RET_ON_ERR(bn_assign(&q, bn));
	bn_r_shift(&q, (BN_DIGIT_BITS * (m->digits - 1)));
	BN_RET_ON_ERR(bn_assign(&r, bn));
	r.digits = (m->digits + 1);
#else
	q.digits = (bn->digits - (m->digits - 1));
	memcpy(q.num, &bn->num[(m->digits - 1)], (q.digits * BN_DIGIT_SIZE));
	//memset(&q.num[q.digits], 0, ((q.count - q.digits) * BN_DIGIT_SIZE));
	r.digits = (m->digits + 1);
	memcpy(r.num, bn->num, (r.digits * BN_DIGIT_SIZE));
	//memset(&r.num[r.digits], 0, ((bn->digits - r.digits+1) * BN_DIGIT_SIZE));
#endif
	/* q = q * mu */
	BN_RET_ON_ERR(bn_mult(&q, &mod_rd_data->Barrett));
	/* q = q * m */
	bn_r_shift(&q, (BN_DIGIT_BITS * (m->digits + 1)));
	BN_RET_ON_ERR(bn_mult(&q, m));
	q.digits = (m->digits + 1);
	//memset(&q.num[q.digits], 0, ((q.count - q.digits) * BN_DIGIT_SIZE));
	r.digits = q.digits;
	//memset(&r.num[r.digits], 0, ((r.count - r.digits) * BN_DIGIT_SIZE));
	if (bn_cmp(&r, &q) < 0) {
		r.num[r.digits] = 1;
		r.digits ++;
		//BN_RET_ON_ERR(bn_bit_set(&r, (BN_DIGIT_BITS * (m->digits + 1)), 1));
	}
	BN_RET_ON_ERR(bn_sub(&r, &q, NULL));
	r.digits = m->digits;
	while (bn_cmp(&r, m) >= 0) {
		BN_RET_ON_ERR(bn_sub(&r, m, NULL));
	}
	BN_RET_ON_ERR(bn_assign(bn, &r));
#endif /* BN_MOD_REDUCE_ALGO */

	return (0);
#if 0
    NN_DIGIT q2[2*MAX_NN_DIGITS+6], q1[MAX_NN_DIGITS+4], r2[2*MAX_NN_DIGITS+8], r1[MAX_NN_DIGITS+4], tm[MAX_NN_DIGITS+4];
    //int i; //for debug
    //trace(DBG_USR1, "enter into barrett mod\n\r");
    memset(q2, 0, (2*MAX_NN_DIGITS+6)*NN_DIGIT_LEN);
    memcpy(q1, b + m->digits - 1, (bn->digits - m->digits + 1)*NN_DIGIT_LEN);
    memset(q1 + bn->digits-m->digits + 1, 0, MAX_NN_DIGITS+4-bn->digits+m->digits-1);
    memcpy(r1, b, (m->digits+1)*NN_DIGIT_LEN);
    memset(r1 + m->digits + 1, 0, (MAX_NN_DIGITS + 4 - m->digits - 1)*NN_DIGIT_LEN);
    memcpy(tm, m->num, m->digits*NN_DIGIT_LEN);
    memset(tm + m->digits, 0, MAX_NN_DIGITS + 4 - m->digits);

    //NN_Mult (a, b, c, digits)       Computes a = b * c.
    //q_2=q_1*mu
    NN_Mult(q2, q1, mod_rd_data->Barrett.num, mod_rd_data->Barrett.digits);
    //q_3*tm
    NN_Mult(r2, q2+m->digits+1, tm, mod_rd_data->Barrett->digits);
    memset(r2+m->digits+1, 0, (2*MAX_NN_DIGITS+8-m->digits-1)*NN_DIGIT_LEN);
    if (NN_Cmp(r1, r2, m->digits+1) < 0)
      r1[m->digits+1] = 1;
    NN_Sub(r1, r1, r2, m->digits+2);

    while(NN_Cmp(r1, tm, m->digits) >= 0)
      NN_Sub(r1, r1, tm, m->digits);

    memcpy(a, r1, m->digits*NN_DIGIT_LEN);
#endif
}

/* Computes: bn = (bn + n) mod m. */
static inline int
bn_mod_add(bn_p bn, bn_p n, bn_p m, bn_mod_rd_data_p mod_rd_data __unused) {

	BN_POINTER_CHK_EINVAL(bn);
	BN_POINTER_CHK_EINVAL(n);
	BN_POINTER_CHK_EINVAL(m);
	BN_RET_ON_ERR(bn_add(bn, n, NULL));
	if (bn_cmp(bn, m) >= 0) { /* bn >= m */
		BN_RET_ON_ERR(bn_sub(bn, m, NULL));
	}
	//BN_RET_ON_ERR(bn_mod(bn, m, mod_rd_data));
	return (0);
}

/* Computes: bn = (bn - n) mod m. */
static inline int
bn_mod_sub(bn_p bn, bn_p n, bn_p m, bn_mod_rd_data_p mod_rd_data) {

	BN_POINTER_CHK_EINVAL(bn);
	BN_POINTER_CHK_EINVAL(n);
	BN_POINTER_CHK_EINVAL(m);
	if (bn_cmp(bn, n) < 0) { /* bn < n */
		BN_RET_ON_ERR(bn_add(bn, m, NULL));
	}
	BN_RET_ON_ERR(bn_sub(bn, n, NULL));
	BN_RET_ON_ERR(bn_mod(bn, m, mod_rd_data));
	return (0);
}

/* Computes bn = (bn * n) mod m. */
static inline int
bn_mod_mult(bn_p bn, bn_p n, bn_p m, bn_mod_rd_data_p mod_rd_data) {

	BN_RET_ON_ERR(bn_mult(bn, n));
	BN_RET_ON_ERR(bn_mod(bn, m, mod_rd_data));
	return (0);
}
/* Computes bn = (bn * n) mod m. */
static inline int
bn_mod_mult_digit(bn_p bn, bn_digit_t n, bn_p m, bn_mod_rd_data_p mod_rd_data) {

	BN_RET_ON_ERR(bn_mult_digit(bn, n));
	BN_RET_ON_ERR(bn_mod(bn, m, mod_rd_data));
	return (0);
}
/* Computes: bn = bn^2 mod m. */
static inline int
bn_mod_square(bn_p bn, bn_p m, bn_mod_rd_data_p mod_rd_data) {

	BN_RET_ON_ERR(bn_mod_mult(bn, bn, m, mod_rd_data));
	return (0);
}

/* Computes: bn = bn^exp mod m. */
/* Binary powering, aka exponentiation by squaring. */
static inline int
bn_mod_exp_digit(bn_p bn, size_t exp, bn_p m, bn_mod_rd_data_p mod_rd_data) {
	bn_t base;

	BN_POINTER_CHK_EINVAL(bn);
	BN_POINTER_CHK_EINVAL(m);
	if (bn->count < m->count || (bn->digits * 2) > bn->count)
		return (EOVERFLOW);
	/* Speed optimizations. */
	switch (exp) {
	case 0: /* bn^0 = 1 */
		BN_RET_ON_ERR(bn_assign_digit(bn, 1));
		return (0);
	case 1: /* bn^1 = bn */
		return (0);
	case 2: /* bn^2 = bn_square() = bn*bn */
		BN_RET_ON_ERR(bn_mod_mult(bn, bn, m, mod_rd_data));
		return (0);
	case 3: /* bn^3 = bn_square() = bn*bn */
		BN_RET_ON_ERR(bn_assign_init(&base, bn));
		BN_RET_ON_ERR(bn_mod_mult(&base, bn, m, mod_rd_data));
		BN_RET_ON_ERR(bn_mod_mult(bn, &base, m, mod_rd_data));
		return (0);
	}
	if (1 == bn->digits) {
		switch (bn->num[0]) {
		case 0: /* 0^exp = 0, exp != 0 */
		case 1: /* 1^exp = 1, exp != 0 */
			return (0);
#if 0
		case 2:
			BN_RET_ON_ERR(bn_assign_2exp(bn, exp));
			BN_RET_ON_ERR(bn_mod(bn, m, mod_rd_data));
			return (0);
#endif
		}
	}
	/* Calculation. */
	BN_RET_ON_ERR(bn_assign_init(&base, bn));
	BN_RET_ON_ERR(bn_assign_digit(bn, 1));
	for (; 0 != exp; exp >>= 1) {
		if (0 != (exp & 1)) {
			BN_RET_ON_ERR(bn_mod_mult(bn, &base, m, mod_rd_data));
		}
		BN_RET_ON_ERR(bn_mod_mult(&base, &base, m, mod_rd_data));
	}
	return (0);
}

static inline int
bn_mod_exp(bn_p bn, bn_p exp, bn_p m, bn_mod_rd_data_p mod_rd_data) {
	size_t bits, i;
	bn_t base;

	BN_POINTER_CHK_EINVAL(bn);
	BN_POINTER_CHK_EINVAL(exp);
	BN_POINTER_CHK_EINVAL(m);
	if (bn->count < m->count)
		return (EOVERFLOW);
	/* Speed optimizations. */
	if (1 == exp->digits) {
		switch (exp->num[0]) {
		case 0: /* bn^0 = 1 */
			BN_RET_ON_ERR(bn_assign_digit(bn, 1));
			return (0);
		case 1: /* bn^1 = bn */
			return (0);
		case 2: /* bn^2 = bn_square() = bn*bn */
			BN_RET_ON_ERR(bn_mod_mult(bn, bn, m, mod_rd_data));
			return (0);
		}
	}
	if ((bn->digits * 2) > bn->count)
		return (EOVERFLOW);
	if (1 == bn->digits) {
		switch (bn->num[0]) {
		case 0: /* 0^exp = 0, exp != 0 */
		case 1: /* 1^exp = 1, exp != 0 */
			return (0);
#if 0
		case 2:
			BN_RET_ON_ERR(bn_assign_2exp(bn, exp));
			BN_RET_ON_ERR(bn_mod(bn, m, mod_rd_data));
			return (0);
#endif
		}
	}
	/* Calculation. */
	BN_RET_ON_ERR(bn_assign_init(&base, bn));
	BN_RET_ON_ERR(bn_assign_digit(bn, 1));
	BN_PREFETCH_BN_DATA(exp);
	bits = bn_calc_bits(exp);
	for (i = 0; i < bits; i ++) {
		if (0 != bn_is_bit_set(exp, i)) {
			BN_RET_ON_ERR(bn_mod_mult(bn, &base, m, mod_rd_data));
		}
		BN_RET_ON_ERR(bn_mod_mult(&base, &base, m, mod_rd_data));
	}
	return (0);
}


#define bn_mod_inv(bn, m, md)	bn_mod_inv_bin(bn, m, md) //  10389 (103896666)
//#define bn_mod_inv(bn, m, md)	bn_mod_inv1(bn, m, md) // 14898 (148980955)
//#define bn_mod_inv(bn, m, md)	bn_mod_inv2(bn, m, md) // 17097 (170977096)
//#define bn_mod_inv(bn, m, md)	bn_mod_inv3(bn, m, md) // fail
//#define bn_mod_inv(bn, m, md)	bn_mod_inv_mont(bn, m, md) // 

/* Compute a = 1/b mod c, assuming inverse exists. */
/* y = (x * p) mod m; x = (y * q) mod m; (p * q) = 1 mod m */
static inline int
bn_mod_inv1(bn_p bn, bn_p m, bn_mod_rd_data_p mod_rd_data __unused) {
	int u1Sign;
	size_t bits;
	bn_t q, t1, t3, u1, u3, v1, v3, w;

	if (0 != bn_is_zero(bn) || 0 != bn_is_zero(m) || bn_cmp(bn, m) >= 0)
		return (EINVAL);
	/* Apply extended Euclidean algorithm, modified to avoid negative numbers. */
	bits = ((4 + max(bn->digits, m->digits)) * BN_DIGIT_BITS);
	BN_RET_ON_ERR(bn_init(&q, bits));
	BN_RET_ON_ERR(bn_init(&t1, bits));
	BN_RET_ON_ERR(bn_init(&t3, bits));
	BN_RET_ON_ERR(bn_init(&u1, bits));
	BN_RET_ON_ERR(bn_init(&u3, bits));
	BN_RET_ON_ERR(bn_init(&v1, bits));
	BN_RET_ON_ERR(bn_init(&v3, bits));
	BN_RET_ON_ERR(bn_init(&w, bits));

	BN_RET_ON_ERR(bn_assign_digit(&u1, 1));
	bn_assign_zero(&v1);
	BN_RET_ON_ERR(bn_assign(&u3, bn));
	BN_RET_ON_ERR(bn_assign(&v3, m));
	u1Sign = 1;

	while (0 == bn_is_zero(&v3)) {
		//NN_Div(q, t3, u3, v3);
		BN_RET_ON_ERR(bn_assign(&q, &u3));
		BN_RET_ON_ERR(bn_div(&q, &v3, &t3));
		//NN_Mult(w, q, v1);
		BN_RET_ON_ERR(bn_assign(&w, &q));
		BN_RET_ON_ERR(bn_mult(&w, &v1));
		//NN_Add(t1, u1, w);
		BN_RET_ON_ERR(bn_assign(&t1, &u1));
		BN_RET_ON_ERR(bn_add(&t1, &w, NULL));

		BN_RET_ON_ERR(bn_assign(&u1, &v1));
		BN_RET_ON_ERR(bn_assign(&v1, &t1));
		BN_RET_ON_ERR(bn_assign(&u3, &v3));
		BN_RET_ON_ERR(bn_assign(&v3, &t3));
		u1Sign = -u1Sign;
	}

	/* Negate result if sign is negative. */
	if (u1Sign < 0) {
		BN_RET_ON_ERR(bn_assign(bn, m));
		BN_RET_ON_ERR(bn_sub(bn, &u1, NULL));
	} else {
		BN_RET_ON_ERR(bn_assign(bn, &u1));
	}
	return (0);
}
/* найти элемент, мультипликативно обратный к bn в поле вычетов по модулю m */
static inline int
bn_mod_inv2(bn_p bn, bn_p m, bn_mod_rd_data_p mod_rd_data) {
	/* r, q, d, d1 = 1, d2 = 0, u = m, v = bn; */
	size_t bits;
	bn_t r, q, d, d1, d2, u;
	bn_p pu = &u, pv = bn, pr = &r, pd = &d, pd1 = &d1, pd2 = &d2, pt;

	if (0 != bn_is_zero(bn) || 0 != bn_is_zero(m) || bn_cmp(bn, m) >= 0)
		return (EINVAL);
	bits = ((4 + max(bn->digits, m->digits)) * BN_DIGIT_BITS);
	BN_RET_ON_ERR(bn_init(&r, bits));
	BN_RET_ON_ERR(bn_init(&q, bits));
	BN_RET_ON_ERR(bn_init(&d, bits));
	BN_RET_ON_ERR(bn_init(&d1, bits));
	BN_RET_ON_ERR(bn_init(&d2, bits));
	BN_RET_ON_ERR(bn_init(&u, bits));

	BN_RET_ON_ERR(bn_assign(&u, m));
	bn_assign_zero(&d2);
	BN_RET_ON_ERR(bn_assign_digit(&d1, 1));

	while (0 == bn_is_zero(pv)) { /* while (v != 0) */
		/* r = u % v; q = (u - r) / v; */
		BN_RET_ON_ERR(bn_assign(&q, pu));
		BN_RET_ON_ERR(bn_div(&q, pv, pr));
		/* d = d2 - q*d1 (mod m) */
		BN_RET_ON_ERR(bn_mod_mult(&q, pd1, m, mod_rd_data));
		BN_RET_ON_ERR(bn_assign(pd, pd2));
		BN_RET_ON_ERR(bn_mod_sub(pd, &q, m, mod_rd_data));
		/* u = v; v = r; d2 = d1; d1 = d; */
		pt = pu; pu = pv; pv = pr; pr = pt;
		pt = pd2; pd2 = pd1; pd1 = pd; pd = pt;
	}

	/* если u = 1, то d2 - число, обратное bn в кольце вычетов по модулю m
	иначе - обратного элемента не сущетсвует */
	if (pd2 != bn) {
		BN_RET_ON_ERR(bn_assign(bn, pd2));
	}
	return (0);
}

static inline int
bn_mod_inv3(bn_p bn, bn_p m, bn_mod_rd_data_p mod_rd_data) {
	size_t bits;
	bn_t gcd, x, y;

	if (0 != bn_is_zero(bn) || 0 != bn_is_zero(m) || bn_cmp(bn, m) >= 0)
		return (EINVAL);
	bits = ((4 + max(bn->digits, m->digits)) * BN_DIGIT_BITS);
	BN_RET_ON_ERR(bn_init(&gcd, bits));
	BN_RET_ON_ERR(bn_init(&x, bits));
	BN_RET_ON_ERR(bn_init(&y, bits));

	BN_RET_ON_ERR(bn_egcd(&gcd, bn, m, &x, &y));
	if (0 == bn_is_one(&gcd))
		return (EINVAL);
	BN_RET_ON_ERR(bn_assign(bn, &x));
	BN_RET_ON_ERR(bn_mod(bn, m, mod_rd_data));
	return (0);
}

/* mp_mod_inv (r,c,m): Set bn = bn^−1(mod m). */
static inline int
bn_mod_inv_bin(bn_p bn, bn_p m, bn_mod_rd_data_p mod_rd_data) {
	size_t bits;
	bn_t u, v, x1, x2;

	if (0 != bn_is_zero(bn) || 0 != bn_is_zero(m) || bn_cmp(bn, m) >= 0)
		return (EINVAL);
	bits = ((4 + max(bn->digits, m->digits)) * BN_DIGIT_BITS);
	BN_RET_ON_ERR(bn_init(&u, bits));
	BN_RET_ON_ERR(bn_init(&v, bits));
	BN_RET_ON_ERR(bn_init(&x1, bits));
	BN_RET_ON_ERR(bn_init(&x2, bits));

	BN_RET_ON_ERR(bn_assign(&u, bn));
	BN_RET_ON_ERR(bn_assign(&v, m));
	BN_RET_ON_ERR(bn_assign_digit(&x1, 1));
	//bn_assign_zero(&x2);

	while (0 == bn_is_one(&u) && 0 == bn_is_one(&v)) {
		while (0 != bn_is_even(&u)) { /* Zero bit check. */
			bn_r_shift(&u, 1);
			if (0 == bn_is_even(&x1)) {
				BN_RET_ON_ERR(bn_add(&x1, m, NULL));
			}
			bn_r_shift(&x1, 1);
		}
		while (0 != bn_is_even(&v)) {
			bn_r_shift(&v, 1);
			if (0 == bn_is_even(&x2)) {
				BN_RET_ON_ERR(bn_add(&x2, m, NULL));
			}
			bn_r_shift(&x2, 1);
		}
		if (bn_cmp(&u, &v) >= 0) {
			BN_RET_ON_ERR(bn_mod_sub(&u, &v, m, mod_rd_data));
			BN_RET_ON_ERR(bn_mod_sub(&x1, &x2, m, mod_rd_data));
		} else {
			BN_RET_ON_ERR(bn_mod_sub(&v, &u, m, mod_rd_data));
			BN_RET_ON_ERR(bn_mod_sub(&x2, &x1, m, mod_rd_data));
		}
	}

	if (0 != bn_is_one(&u)) {
		BN_RET_ON_ERR(bn_assign(bn, &x1));
	} else {
		BN_RET_ON_ERR(bn_assign(bn, &x2));
	}
	return (0);
}

/* Computes: bn = bn div d mod m
 * algorithm in "From Euclid's GCD to Montgomery Multiplication to the Great Divide"
 */
static inline int
bn_mod_div_mont(bn_p bn, bn_p d, bn_p m, bn_mod_rd_data_p mod_rd_data __unused) {
	size_t bits;
	int cmp_res;
	bn_t /*u,*/ v, a, b;

	if (0 != bn_is_zero(bn) || 0 != bn_is_zero(m) || bn_cmp(bn, m) >= 0)
		return (EINVAL);
	bits = ((4 + max(bn->digits, m->digits)) * BN_DIGIT_BITS);
	//BN_RET_ON_ERR(bn_init(&u, bits));
	BN_RET_ON_ERR(bn_init(&v, bits));
	BN_RET_ON_ERR(bn_init(&a, bits));
	BN_RET_ON_ERR(bn_init(&b, bits));

	//BN_RET_ON_ERR(bn_assign(&u, bn));
	//bn_assign_zero(&v);
	BN_RET_ON_ERR(bn_assign(&a, d));
	BN_RET_ON_ERR(bn_assign(&b, m));

	while ((cmp_res = bn_cmp(&a, &b)) != 0) {
		if (0 != bn_is_even(&a)) {
			bn_r_shift(&a, 1);
			if (0 == bn_is_even(bn)) {
				BN_RET_ON_ERR(bn_add(bn, m, NULL));
			}
			bn_r_shift(bn, 1);
		} else if (0 != bn_is_even(&b)) {
			bn_r_shift(&b, 1);
			if (0 == bn_is_even(&v)) {
				BN_RET_ON_ERR(bn_add(&v, m, NULL));
			}
			bn_r_shift(&v, 1);
		} else if (cmp_res > 0) {
			BN_RET_ON_ERR(bn_sub(&a, &b, NULL));
			bn_r_shift(&a, 1);
			if (bn_cmp(bn, &v) < 0) {
				BN_RET_ON_ERR(bn_add(bn, m, NULL));
			}
			BN_RET_ON_ERR(bn_sub(bn, &v, NULL));
			if (0 == bn_is_even(bn)) {
				BN_RET_ON_ERR(bn_add(bn, m, NULL));
			}
			bn_r_shift(bn, 1);
		} else {
			BN_RET_ON_ERR(bn_sub(&b, &a, NULL));
			bn_r_shift(&b, 1);
			if (bn_cmp(&v, bn) < 0) {
				BN_RET_ON_ERR(bn_add(&v, m, NULL));
			}
			BN_RET_ON_ERR(bn_sub(&v, bn, NULL));
			if (0 == bn_is_even(&v)) {
				BN_RET_ON_ERR(bn_add(&v, m, NULL));
			}
			bn_r_shift(&v, 1);
		}
	}

	return (0);
}

/* mp_mod_inv (r,c,m): Set bn = bn^−1(mod m). Partial Montgomery inversion. */
static inline int
bn_mod_inv_mont(bn_p bn, bn_p m, bn_mod_rd_data_p mod_rd_data) {
	bn_t tm;
	
	BN_RET_ON_ERR(bn_init(&tm, ((1 + max(bn->digits, m->digits)) * BN_DIGIT_BITS)));
	BN_RET_ON_ERR(bn_assign_digit(&tm, 1));
	BN_RET_ON_ERR(bn_mod_div_mont(&tm, bn, m, mod_rd_data));
	BN_RET_ON_ERR(bn_assign(bn, &tm));
	return (0);
}

/* Computes: bn = bn div d mod m. */
/* Computes: bn = bn / d mod m. */
/* bn = bn / d = bn * (d^-1) mod m */
static inline int
bn_mod_div(bn_p bn, bn_p d, bn_p m, bn_mod_rd_data_p mod_rd_data) {
	bn_t tmp;

	BN_RET_ON_ERR(bn_assign_init(&tmp, d));
	BN_RET_ON_ERR(bn_mod_inv(&tmp, m, mod_rd_data));
	BN_RET_ON_ERR(bn_mod_mult(bn, &tmp, m, mod_rd_data));
	return (0);
}


/* Computes bn = (bn mod (m − 1)) + 1. */
static inline int
bn_mod_reduce(bn_p bn, bn_p m, bn_mod_rd_data_p mod_rd_data) {
	bn_t tmp;

	BN_POINTER_CHK_EINVAL(bn);
	BN_POINTER_CHK_EINVAL(m);
	if (bn_cmp(bn, m) < 0)
		return (0);
	BN_RET_ON_ERR(bn_assign_init(&tmp, m));
	bn_sub_digit(&tmp, 1, NULL);
	BN_RET_ON_ERR(bn_mod(bn, &tmp, mod_rd_data));
	bn_add_digit(bn, 1, NULL);
	return (0);
}

/*  */
static inline int
bn_mod_small(bn_p bn, bn_p m, bn_mod_rd_data_p mod_rd_data __unused) {

	BN_POINTER_CHK_EINVAL(bn);
	BN_POINTER_CHK_EINVAL(m);

	while (bn_cmp(bn, m) > 0) {
		BN_RET_ON_ERR(bn_sub(bn, m, NULL));
	}

	return (0);
}


/* Calculate Legendre symbol, returns: -1, 0, 1. */
static inline int
bn_mod_legendre(bn_p bn, bn_p m, bn_mod_rd_data_p mod_rd_data) {
	bn_t tm, tm2, a;

	BN_POINTER_CHK_EINVAL(bn);
	BN_POINTER_CHK_EINVAL(m);
	if (0 == bn_is_odd(m))
		return (EINVAL);
	/* Speed optimizations. */
	BN_RET_ON_ERR(bn_assign_init(&a, bn));
	BN_RET_ON_ERR(bn_mod(&a, m, mod_rd_data));
	if (0 != bn_is_zero(&a))
		return (0);
	if (0 != bn_is_one(&a))
		return (1);
	/* Legendre = bn ^ ((m - 1) / 2) mod m */
	BN_RET_ON_ERR(bn_assign_init(&tm, m));
	bn_sub_digit(&tm, 1, NULL); /* tm = m - 1 */
	BN_RET_ON_ERR(bn_assign_init(&tm2, &tm));
	bn_r_shift(&tm2, 1); /* (m - 1) / 2 */
	BN_RET_ON_ERR(bn_mod_exp(&a, &tm2, m, mod_rd_data)); /* a = bn^tm2 mod m */
	if (0 == bn_cmp(&tm, &a)) /* Is a = -1? */
		return (-1);
	if (0 != bn_is_zero(&a)) /* Is a = 0? */
		return (0);
	return (1); /* a = 1 */
}

/* Computes: Square root: bn = (√bn) mod m. */
/* m - odd prime. */
/* X9.62-1998 p.66: D.1.4 Finding Square Roots Modulo bn Prime */
static inline int
bn_mod_sqrt(bn_p bn, bn_p m, bn_mod_rd_data_p mod_rd_data) {
	bn_t tm, tm2, orig;
	size_t bits;

	BN_POINTER_CHK_EINVAL(bn);
	BN_POINTER_CHK_EINVAL(m);
	if (0 == bn_is_odd(m))
		return (EINVAL);
	/* Speed optimizations. */
	BN_RET_ON_ERR(bn_mod(bn, m, mod_rd_data));
	if (0 != bn_is_zero(bn) || 0 != bn_is_one(bn))
		return (0);
	if (-1 == bn_mod_legendre(bn, m, mod_rd_data))
		return (-1);
	BN_RET_ON_ERR(bn_assign_init(&orig, bn)); /* Save bn for checking. */
	if (3 == (m->num[0] & 3)) { /* Is m mod 4 == 3? */
		/* bn = bn^((m + 1) / 4) mod m */
		BN_RET_ON_ERR(bn_assign_init(&tm, m));
		bn_add_digit(&tm, 1, NULL); /* m + 1 */
		bn_r_shift(&tm, 2); /* (m + 1) / 4 */
		BN_RET_ON_ERR(bn_mod_exp(bn, &tm, m, mod_rd_data));
	} else if (5 == (m->num[0] & 7)) { /* Is m mod 8 == 5? */
		/* tm = (2 * bn)^((m - 5) / 8) mod m */
		BN_RET_ON_ERR(bn_assign_init(&tm2, m));
		//bn_sub_digit(&tm2, 5, NULL); /* m - 5: skiped, next shifting do same. */
		bn_r_shift(&tm2, 3); /* (m - 5) / 8 */
		BN_RET_ON_ERR(bn_assign_init(&tm, bn));
		BN_RET_ON_ERR(bn_mod_mult_digit(&tm, 2, m, mod_rd_data));
		BN_RET_ON_ERR(bn_mod_exp(&tm, &tm2, m, mod_rd_data));
		/* tm2 = ((2 * bn * tm^2) - 1) mod m */
		BN_RET_ON_ERR(bn_assign_init(&tm2, bn));
		BN_RET_ON_ERR(bn_mod_mult_digit(&tm2, 2, m, mod_rd_data));
		BN_RET_ON_ERR(bn_mod_mult(&tm2, &tm, m, mod_rd_data));
		BN_RET_ON_ERR(bn_mod_mult(&tm2, &tm, m, mod_rd_data));
		bn_sub_digit(&tm2, 1, NULL);
		/* bn = bn * tm * tm2 mod m */
		BN_RET_ON_ERR(bn_mod_mult(bn, &tm, m, mod_rd_data));
		BN_RET_ON_ERR(bn_mod_mult(bn, &tm2, m, mod_rd_data));
	} else if (1 == (m->num[0] & 3)) { /* Is m mod 4 == 1? - Tonelli–Shanks algorithm. */
		bn_t b, t, bn_inv;

		bits = (BN_DIGIT_BITS + (max(bn->digits, m->digits) * 2 * BN_DIGIT_BITS));
		BN_RET_ON_ERR(bn_init(&tm, bits));
		BN_RET_ON_ERR(bn_init(&b, bits));
		BN_RET_ON_ERR(bn_init(&t, bits));
		/* Select b random quadratic nonresidue. */
		/* Initialize random algorithm. */
		BN_RET_ON_ERR(bn_assign(&b, bn));
		BN_RET_ON_ERR(bn_assign(&tm, m));
		bits = bn_calc_bits(&b);
		do {
			bn_r_shift(&tm, 1);
			BN_RET_ON_ERR(bn_xor(&b, &tm));
		} while (-1 != bn_mod_legendre(&b, m, mod_rd_data) && 0 != --bits);
		if (0 == bits)
			return (-1);
		/* Find bits and t, such as (m - 1) = 2^bits*t, where t is odd */
		BN_RET_ON_ERR(bn_assign_init(&tm2, m));
		bn_sub_digit(&tm2, 1, NULL); /* tm2 = (m - 1) */
		bits = bn_ctz(&tm2);
		/* Scans the binary representation of tm2 for 1 from behind, this gives us the
		 * number of times tm2 can be devided with 2 before it gives an odd. This bit
		 * manipulation ought to be faster than repeated division by 2.
		 * Example:
		 * prime = 113		binary = 1110001 
		 * prime - 1 = 112	binary = 1110000
		 * 112 / 2^4 = 7, 7 is odd. */
		BN_RET_ON_ERR(bn_assign_2exp(&tm, bits)); /* tm = 2 ^ bits */
		BN_RET_ON_ERR(bn_assign(&t, &tm2));
		BN_RET_ON_ERR(bn_div(&t, &tm, NULL)); /* t = tm2 / tm */
		/* Set b = b^t mod m */
		BN_RET_ON_ERR(bn_mod_exp(&b, &t, m, mod_rd_data));
		/* Computation of bn^-1 mod m */
		BN_RET_ON_ERR(bn_assign_init(&bn_inv, bn));
		BN_RET_ON_ERR(bn_mod_inv(&bn_inv, m, mod_rd_data));
		/* Set bn = bn^((t + 1) / 2) mod m */
		bn_add_digit(&t, 1, NULL); /* t = t + 1 */
		bn_r_shift(&t, 1); /* t = t / 2 */
		BN_RET_ON_ERR(bn_mod_exp(bn, &t, m, mod_rd_data)); /* bn = bn^t mod m */
		/* Calc loop. */
		for (; 1 < bits; bits --) {
			/* Set t = ((bn ^ 2) * bn_inv) ^ (2 ^ (bits - i - 1)) mod m */
			BN_RET_ON_ERR(bn_assign_2exp(&tm, (bits - 2))); /* tm = 2^(bits - i - 1) mod m, (bits - i - 1) < bits count of m, so no mod. */
			BN_RET_ON_ERR(bn_assign(&t, bn));
			BN_RET_ON_ERR(bn_mod_square(&t, m, mod_rd_data)); /* t = (bn ^ 2) mod m */
			BN_RET_ON_ERR(bn_mod_mult(&t, &bn_inv, m, mod_rd_data)); /* t = (bn ^ 2) * bn_inv mod m */
			BN_RET_ON_ERR(bn_mod_exp(&t, &tm, m, mod_rd_data)); /* t = ((bn ^ 2) * bn_inv) ^ tm */
			/* If t-(-1) mod m == 0, since t < m then 
			 * we can use (m - 1) == t instead */
			if (0 == bn_cmp(&t, &tm2)) { /* Set bn = bn * b mod m */
				BN_RET_ON_ERR(bn_mod_mult(bn, &b, m, mod_rd_data));
			}
			BN_RET_ON_ERR(bn_mod_square(&b, m, mod_rd_data)); /* b = b^2 mod m */
		}
	} else {
		return (-1);
	}
	/* Checking. */
	BN_RET_ON_ERR(bn_assign_init(&tm, bn));
	BN_RET_ON_ERR(bn_mod_square(&tm, m, mod_rd_data));
	if (0 != bn_cmp(&tm, &orig))
		return (-1);
	return (0);
}




#ifdef BN_SELF_TEST

static inline int
bn_self_test(void) {
	size_t j;
	bn_digit_t da, db;
	bn_t a, b, q, r, bn;
	/*  Welschenbach M., 4.3 Division with Remainder, Test_ values. */
	const uint8_t *div_a = (const uint8_t*)"e37d3abc904baba7a2ac4b6d8f782b2bf84919d2917347690d9e93dcdd2b91cee9983c564cf1312206c91e74d80ba479064c8f42bd70aaaa689f80d435afc997ce853b465703c8edca";
	const uint8_t *div_b = (const uint8_t*)"080b0987b72c1667c30c9156a6674c2e73e61a1fd527d4e78b3f1505603c566658459b83ccfd587ba9b5fcbdc0ad09152e0ac265";
	const uint8_t *div_q = (const uint8_t*)"1c48a1c798541ae0b9eb2c6327b1fffff4fe5c0e2723";
	const uint8_t *div_r = (const uint8_t*)"ca2312fbb3f4c23add7655e94c3410b15c6064bd48a4e5fcc33ddf553e7cb829bf66fbfd61b4667f5ed6b387ec47c5272cf6fb";
	//uint8_t buf[4096];

	BN_RET_ON_ERR(bn_init(&bn, BN_BIT_LEN));
	BN_RET_ON_ERR(bn_assign_digit(&bn, 1));
	for (j = 0; j < BN_BIT_LEN; j ++) {
		bn_l_shift(&bn, j);
		if (0 == bn_is_bit_set(&bn, j))
			return (1002);
		bn_r_shift(&bn, j);
		if (0 == bn_is_one(&bn))
			return (1002);
	}
	bn_assign_zero(&bn);
	for (j = 0; j < BN_BIT_LEN; j ++) {
		BN_RET_ON_ERR(bn_bit_set(&bn, j, 1));
		if (0 == bn_is_bit_set(&bn, j))
			return (1002);
		BN_RET_ON_ERR(bn_bit_set(&bn, j, 0));
		if (0 != bn_is_bit_set(&bn, j))
			return (1002);
	}

	BN_RET_ON_ERR(bn_init(&a, BN_BIT_LEN));
	BN_RET_ON_ERR(bn_init(&b, BN_BIT_LEN));
	BN_RET_ON_ERR(bn_init(&q, BN_BIT_LEN));
	BN_RET_ON_ERR(bn_init(&r, BN_BIT_LEN));

	BN_RET_ON_ERR(bn_import_be_hex(&a, div_a, strlen((const char*)div_a)));
	BN_RET_ON_ERR(bn_import_be_hex(&b, div_b, strlen((const char*)div_b)));
	BN_RET_ON_ERR(bn_import_be_hex(&q, div_q, strlen((const char*)div_q)));
	BN_RET_ON_ERR(bn_import_be_hex(&r, div_r, strlen((const char*)div_r)));

	/* bn = (b * q) + r */
	BN_RET_ON_ERR(bn_assign(&bn, &b));
	BN_RET_ON_ERR(bn_mult(&bn, &q));
	BN_RET_ON_ERR(bn_add(&bn, &r, NULL));
	if (0 != bn_cmp(&a, &bn))
		return (1003);

	/* q = (a / b); r = (a % b). */
	BN_RET_ON_ERR(bn_assign(&q, &a));
	BN_RET_ON_ERR(bn_div(&q, &b, &r));
	//BN_RET_ON_ERR(bn_export_be_hex(&q, 0, buf, sizeof(buf), &j));
	BN_RET_ON_ERR(bn_import_be_hex(&bn, div_q, strlen((const char*)div_q)));
	if (0 != bn_cmp(&q, &bn))
		return (1004);
	//BN_RET_ON_ERR(bn_export_be_hex(&r, 0, buf, sizeof(buf), &j));
	BN_RET_ON_ERR(bn_import_be_hex(&bn, div_r, strlen((const char*)div_r)));
	if (0 != bn_cmp(&r, &bn))
		return (1005);//*/
	
	BN_RET_ON_ERR(bn_assign(&q, &a));
	BN_RET_ON_ERR(bn_mult_digit(&q, 3));
	BN_RET_ON_ERR(bn_assign_digit(&r, 3));
	BN_RET_ON_ERR(bn_mult(&r, &a));
	if (0 != bn_cmp(&r, &q))
		return (1005);//*/
	

	/* GCD */
	if (bn_digit_gcd(54, 24) != bn_digit_gcd_bin(54, 24))
		return (1006);
	if (bn_digit_gcd(24, 54) != bn_digit_gcd(54, 24))
		return (1007);
	if (bn_digit_gcd_bin(24, 54) != bn_digit_gcd_bin(54, 24))
		return (1008);
	if (bn_digit_gcd(120, 23) != bn_digit_egcd(120, 23, &da, &db) ||
	    0 != ((bn_digit_t)(da + 9)) || db != 47)
		return (1009);
	BN_RET_ON_ERR(bn_assign_digit(&a, 54));
	BN_RET_ON_ERR(bn_assign_digit(&b, 24));
	BN_RET_ON_ERR(bn_assign_digit(&r, 6));

	BN_RET_ON_ERR(bn_gcd(&bn, &a, &b));
	if (0 != bn_cmp(&r, &bn))
		return (1010);
	BN_RET_ON_ERR(bn_gcd_bin(&bn, &a, &b));
	if (0 != bn_cmp(&r, &bn))
		return (1011);

#if 0 /* broken */
	BN_RET_ON_ERR(bn_assign_digit(&a, 120));
	BN_RET_ON_ERR(bn_assign_digit(&b, 23));
	BN_RET_ON_ERR(bn_egcd(&bn, &a, &b, &r, &q));//NULL, NULL);
#endif
	
	/* mod_inv */
	const uint8_t *mod_inv_m256 = (const uint8_t*)"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
	const uint8_t *mod_inv_k256 = (const uint8_t*)"580ec00d856434334cef3f71ecaed4965b12ae37fa47055b1965c7b134ee45d0";
	const uint8_t *mod_inv_r256 = (const uint8_t*)"6a664fa115356d33f16331b54c4e7ce967965386c7dcbf2904604d0c132b4a74";
	BN_RET_ON_ERR(bn_import_be_hex(&q, mod_inv_m256, strlen((const char*)mod_inv_m256)));
	BN_RET_ON_ERR(bn_import_be_hex(&a, mod_inv_k256, strlen((const char*)mod_inv_k256)));
	BN_RET_ON_ERR(bn_import_be_hex(&r, mod_inv_r256, strlen((const char*)mod_inv_r256)));
	
	BN_RET_ON_ERR(bn_assign(&bn, &a));
	BN_RET_ON_ERR(bn_mod_inv1(&bn, &q, NULL));
	if (0 != bn_cmp(&bn, &r))
		return (1020);
	BN_RET_ON_ERR(bn_assign(&bn, &a));
	BN_RET_ON_ERR(bn_mod_inv2(&bn, &q, NULL));
	if (0 != bn_cmp(&bn, &r))
		return (1021);
#if 0 /* broken */
	BN_RET_ON_ERR(bn_assign(&bn, &a));
	BN_RET_ON_ERR(bn_mod_inv3(&bn, &q, NULL));
	if (0 != bn_cmp(&bn, &r))
		return (1022);
#endif
	BN_RET_ON_ERR(bn_assign(&bn, &a));
	BN_RET_ON_ERR(bn_mod_inv_bin(&bn, &q, NULL));
	if (0 != bn_cmp(&bn, &r))
		return (1023);

	
	const uint8_t *mod_inv_m384 = (const uint8_t*)"ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
	const uint8_t *mod_inv_k384 = (const uint8_t*)"dc6b44036989a196e39d1cdac000812f4bdd8b2db41bb33af51372585ebd1db63f0ce8275aa1fd45e2d2a735f8749359";
	const uint8_t *mod_inv_r384 = (const uint8_t*)"7436f03088e65c37ba8e7b33887fbc87757514d611f7d1fbdf6d2104a297ad318cdbf7404e4ba37e599666df37b8d8be";
	BN_RET_ON_ERR(bn_import_be_hex(&q, mod_inv_m384, strlen((const char*)mod_inv_m384)));
	BN_RET_ON_ERR(bn_import_be_hex(&a, mod_inv_k384, strlen((const char*)mod_inv_k384)));
	BN_RET_ON_ERR(bn_import_be_hex(&r, mod_inv_r384, strlen((const char*)mod_inv_r384)));

	BN_RET_ON_ERR(bn_assign(&bn, &a));
	BN_RET_ON_ERR(bn_mod_inv1(&bn, &q, NULL));
	if (0 != bn_cmp(&bn, &r))
		return (1025);
	BN_RET_ON_ERR(bn_assign(&bn, &a));
	BN_RET_ON_ERR(bn_mod_inv2(&bn, &q, NULL));
	if (0 != bn_cmp(&bn, &r))
		return (1026);
#if 0 /* broken */
	BN_RET_ON_ERR(bn_assign(&bn, &a));
	BN_RET_ON_ERR(bn_mod_inv3(&bn, &q, NULL));
	if (0 != bn_cmp(&bn, &r))
		return (1027);
#endif
	BN_RET_ON_ERR(bn_assign(&bn, &a));
	BN_RET_ON_ERR(bn_mod_inv_bin(&bn, &q, NULL));
	if (0 != bn_cmp(&bn, &r))
		return (1028);


	return (0);
}
#endif /* self test */


#endif /* __BIG_NUM_H__ */















#if 0 /* Unused code */


/* Return shift for b untill a>=b */
static inline size_t
bn_digit_shift_cmp(bn_digit_t a, bn_digit_t b) {
	register bn_digit_t reg_a = a, reg_b = b;
	register size_t i;

	for (i = 0; reg_a < reg_b; i ++, reg_b >>= 1)
		;
	return (i);
}


/* Broken. */
static inline int // XXX different counts
bn_div(bn_p bn, bn_p d, bn_p remainder) {
	int error = 0;
	register ssize_t shift;
	register size_t i, j, num_bits, n_digits, d_digits, tshift;
	size_t decs = 0, dd_shift = 0, nn_shift = 0;
	bn_t tn, td;
	bn_p nn = &tn, dd = &td;

	/* Internal: n = bn; bn = n / d. */
	BN_POINTER_CHK_EINVAL(bn);
	BN_POINTER_CHK_EINVAL(d);
	if (0 != bn_is_zero(d)) /* dividend / 0 !!! */
		return (EINVAL);
	if (bn == d) /* n = d */
		goto n_eq_d;
#if 0
	/* Speed optimizations. */
	if (0 != bn_is_zero(bn)) { /* 0 / divisor, return 0. */
		if (bn != remainder) {
			bn_assign_zero(remainder);
		}
		return (0);
	}
	if (0 != bn_is_one(d)) { /* dividend / 1, return dividend. */
		bn_assign_zero(remainder);
		return (0);
	}
	if (0 != bn_is_pow2(d)) {
		shift = bn_ctz(d);
		if (NULL != remainder) { /* = (bn & ((1 < shift) - 1)) */
			BN_RET_ON_ERR(bn_assign_init(nn, bn));
			BN_RET_ON_ERR(bn_assign_2exp(nn, shift));
			bn_sub_digit(nn, 1, NULL);
			BN_RET_ON_ERR(bn_assign(remainder, bn));
			BN_RET_ON_ERR(bn_and(remainder, nn));
		}
		if (bn != remainder) {
			bn_r_shift(bn, shift);
		}
		return (0);
	}
#endif
	switch (bn_cmp(bn, d)) {
	case 0: /* n = d */
n_eq_d:
		if (bn != remainder) {
			bn_assign_digit(bn, 1);
		}
		bn_assign_zero(remainder);
		return (0);
	case -1: /* n < d */
		if (bn != remainder) {
			if (NULL != remainder) {
				error = bn_assign(remainder, bn);
			}
			bn_assign_zero(bn);
		}
		return (error);
	}

	/* Calculation. */
	n_digits = bn->digits;
	d_digits = d->digits;
	/* shift = leading zero bits of divisor count + (n_digits - d_digits) digits bits count. */
	tshift = bn_digit_clz(bn->num[(n_digits - 1)]);
	shift = (bn_digit_clz(d->num[(d_digits - 1)]) +
	    ((n_digits - d_digits) * BN_DIGIT_BITS) - tshift);
	BN_RET_ON_ERR(bn_assign_init(dd, d));
	bn_init_digits__int(dd, dd->count);
	bn_digits_l_shift(dd->num, n_digits, shift); /* << Normalize. */
	BN_RET_ON_ERR(bn_assign_init(nn, bn));
	bn_init_digits__int(nn, nn->count);

	if (bn != remainder) { /* Quotient and remainder calculation. */
		bn_assign_zero(bn);
		bn_init_digits__int(bn, (1 + nn->digits - dd->digits));
#if 1 /* Un optimized base algo. */
		for (; shift >= 0; shift --) {
			bn_digits_l_shift(bn->num, n_digits, 1);
			if (bn_digits_cmp(nn->num, dd->num, n_digits) >= 0) {
				bn_digits_sub__int(nn->num, n_digits,
				    dd->num, n_digits, NULL);
				bn->num[0] |= 1;
			}
			bn_r_shift(dd, 1);
		}
		bn_update_digits__int(bn, (1 + nn->digits - dd->digits));
		bn_update_digits__int(nn, nn->digits);
#endif
#if 0 /* Broken, fix it. */
		/*
		 * Optimizations:
		 * 1. Shift bn (quotient) only before write bit ONE.
		 * 2. Shift R only hi dd (devizor) digit and compare with hi nn (devident) digit,
		 *  after nn >= dd shift whole dd.
		 * 3. Do all shifts and substracts only for (d_digits + 1) window on nn and dd,
		 *  were n_digits > d_digits.
		 */
		if (n_digits > d_digits) {
			d_digits ++; /* When moving dd we have + one digit (part of digit). */
			i = (n_digits - d_digits);
		} else {
			//d_digits = n_digits;
			i = 0;
		}
		shift += tshift; /* Move j to tshift for point as bit offset */
		//for (num_bits = 0, j = tshift; j <= shift; j ++) {
		for (num_bits = 0, j = tshift; /*j <= shift*/; /*j ++*/) {
			if (bn_digits_cmp(&nn->num[i], &dd->num[i], d_digits) >= 0) {
				bn_digits_sub__int(&nn->num[i], d_digits,
				    &dd->num[i], d_digits, NULL);
				if (0 != (1 & bn->num[0])) {/* Skip first shift. */
					bn_digits_l_shift(bn->num, n_digits,
					    (j - num_bits)); /* << Shift here many bytes. */
					nn_shift += (j - num_bits);
				}
				bn->num[0] |= 1;
				num_bits = j;
				decs ++;
			}
		#if 0 /* This part is broken, no optimization 2. */
			tshift = bn_digit_shift_cmp(nn->num[i + d_digits - 1],
				dd->num[i + d_digits - 1]);
			if ((j + tshift) > shift)
				break;//tshift = 0;
			dd_shift += tshift;
			bn_digits_r_shift(dd->num, n_digits, tshift);
			//bn_digits_r_shift(&dd->num[i], d_digits, tshift);
			j += tshift;
			if (0 == (j & (BN_DIGIT_BITS - 1)) && 0 != j) {
			//if (((j + tshift) & (~(BN_DIGIT_BITS - 1))) > (j & (~(BN_DIGIT_BITS - 1)))) {
				if (0 != i) {
					i --; /* Slide dd window. */
				} else {
					d_digits --; /* Decrease dd window. */
				}
			}
			if (0 == tshift) {
				j ++;
				continue;
			}

			//if (j <= shift)
			//	continue;
			//break;
		#endif
		#if 1
			dd_shift ++;
			bn_digits_r_shift(&dd->num[i], d_digits, 1);
			if (0 == (j & (BN_DIGIT_BITS - 1)) && 0 != j) {
				if (0 != i) {
					i --; /* Slide dd window. */
				} else {
					d_digits --; /* Decrease dd window. */
				}
			}
		#endif
		}
		if (j > (shift + 1) || j == num_bits) {
			j = (shift + 1);
		}
		bn_digits_l_shift(bn->num, n_digits, ((j - num_bits) - 1)); /* << Final shift. */
#endif
	} else { /* Only remainder calculation. */
		for (; shift >= 0; shift --) {
			if (bn_digits_cmp(nn->num, dd->num, n_digits) >= 0) {
				bn_digits_sub__int(nn->num, n_digits,
				    dd->num, n_digits, NULL);
			}
			bn_digits_r_shift(dd->num, n_digits, 1);
		}
		bn_update_digits__int(nn, n_digits);
	}
	BN_RET_ON_ERR(bn_assign(remainder, nn));
	return (0);
}


#endif /* __MATH_BIG_NUM_H__ */
