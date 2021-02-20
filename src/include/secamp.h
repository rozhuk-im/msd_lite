/*-
 * Copyright (c) 2016 Rozhuk Ivan <rim@vedapro.ru>
 * All rights reserved.
 *
 *
 * Author: Rozhuk Ivan <rozhuk.im@gmail.com>
 *
 *
 */

#ifndef __SECAMP_H__
#define __SECAMP_H__

#ifndef _WINDOWS
#	include <sys/param.h>
#	ifndef BSD
#		define _GNU_SOURCE /* See feature_test_macros(7) */
#		define __USE_GNU 1
#	endif
#	include <sys/types.h>
#	include <math.h>
#	ifdef _KERNEL
#		include <sys/systm.h>
#	else
#		include <string.h> /* memcpy, memmove, memset... */
#		include <inttypes.h>
#	endif
#	define secamp_print(__fmt, args...)	fprintf(stdout, (__fmt), ##args)
#else
#	include <stdlib.h>
#	include <math.h>
#	define uint8_t		unsigned char
#	define uint32_t		DWORD
#	define uint64_t		DWORDLONG
#	define size_t		SIZE_T
#	define secamp_print()
#endif


#include "toeplitz.h"
#define SECAMP_FAST	1

#if 0
% K - двоичная строка 
% r - длина синдрома
% t - длина хеш-кода
% qber - доля ошибок в битах после процедуры оценки ошибок
% delta - критический предел доли ошибок
delta = 0.05;
% q_k - количество бит, по которым была оценена вероятность ошибки
q_k = 512;
% eps_ver - надежность верификации
eps_ver = 5*1e-11;
% eps_aut - надежность аутентификации
eps_aut = 1e-20;
% eps_pa - надежность усиления секретности
eps_pa = 1e-12;
% eps_qkd - надежность ключа
eps_qkd = eps_ver+eps_aut+eps_pa;
% l - требуемая длина ключа
 
n=length(K);
%Определение возможности создания ключа заданной длины и показателя
%ненадежности
 
v = sqrt((2*(n+q_k)*(q_k+1)*log(1/eps_pa))/(n*q_k*q_k));
lhs = 2^(-0.2*(n*(1-h(delta+v))-r-t-l));
if (lhs > eps_pa)
% ключ создать невозможно
    ErrCode = 1;
end
ErrCode = 0;
end
#endif


static inline double
secamp_bin_entrp(double val) {

	return ((-val * log2(val) - (1 - val) * log2((1 - val))));
}

/*
 * raw_data_size: length(K) = n
 * sindrom_size: r
 * hash_size: t
 * err_max: delta
 * required_key_len: l
 */
static inline int
secamp_is_invalid(size_t raw_data_size, size_t sindrom_size, size_t hash_size,
    double qber, double err_max, double q_k,
    double eps_ver, double eps_aut, double eps_pa,
    size_t required_key_len) {
	double v, lhs;

	if (qber > err_max)
		return (1); /* XXX: RFC! */
	if (0 == raw_data_size ||
	    0 == eps_pa ||
	    0 == q_k)
		return (1); /* Division by zero. */

	v = sqrt(((2 * (raw_data_size + q_k) * (q_k + 1) * log((1 / eps_pa))) / (raw_data_size * q_k * q_k)));
	lhs = pow(2, (-0.2 * (raw_data_size * (1 - secamp_bin_entrp(err_max + v)) - sindrom_size - hash_size - required_key_len)));
	if (lhs > eps_pa)
		return (1);
	return (0); /* Params OK. */
}

static inline int
secamp_toepliz(const uint8_t *matr, size_t matr_size,
    size_t rows_count, size_t cols_count,
    const uint8_t *vec, size_t vec_size,
    uint8_t *res, size_t res_size) {
#ifdef SECAMP_FAST
	int error;
	uint8_t *tmbuf;
	size_t tmbuf_size;

	tmbuf_size = (TOEPLITZ_BITS2BYTES(matr_size) + 512);
	tmbuf = malloc(tmbuf_size);
	if (NULL == tmbuf)
		goto fall_back;
	error = toeplitz_mult_fast(matr, matr_size, rows_count, cols_count,
	    vec, vec_size, tmbuf, tmbuf_size, res, res_size);
	free(tmbuf);
	if (0 == error)
		return (error);
fall_back:
#endif
	return (toeplitz_mult(matr, matr_size, rows_count, cols_count,
	    vec, vec_size, res, res_size));
}




#ifdef SECAMP_SELF_TEST


typedef struct secamp_test1_vectors_s {
	size_t	raw_data_size;
	size_t	sindrom_size;
	size_t	hash_size;
	double	qber;
	double	err_max;
	double	q_k;
	double	eps_ver;
	double	eps_aut;
	double	eps_pa;
	size_t	required_key_len;
	int	result;
} secamp_tst1v_t, *secamp_tst1v_p;

static secamp_tst1v_t secamp_tst1v[] = {
	{ /* 0. From VedaPro int */
		/*.raw_data_size = (n)*/1944,
		/*.sindrom_size = (r)*/	972,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/972,
		/*.result =*/		1,
	}, { /* 1. From VedaPro int */
		/*.raw_data_size = (n)*/1944,
		/*.sindrom_size = (r)*/	648,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/972,
		/*.result =*/		1,
	}, { /* 2. From VedaPro int */
		/*.raw_data_size = (n)*/1944,
		/*.sindrom_size = (r)*/	486,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/972,
		/*.result =*/		1,
	}, { /* 3. From VedaPro int */
		/*.raw_data_size = (n)*/1944,
		/*.sindrom_size = (r)*/	324,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/972,
		/*.result =*/		1,
	}, { /* 4. From VedaPro int */
		/*.raw_data_size = (n)*/19440,
		/*.sindrom_size = (r)*/	972,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/972,
		/*.result =*/		1,
	}, { /* 5. From VedaPro int */
		/*.raw_data_size = (n)*/19440,
		/*.sindrom_size = (r)*/	648,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/972,
		/*.result =*/		1,
	}, { /* 6. From VedaPro int */
		/*.raw_data_size = (n)*/19440,
		/*.sindrom_size = (r)*/	486,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/972,
		/*.result =*/		1,
	}, { /* 7. From VedaPro int */
		/*.raw_data_size = (n)*/19440,
		/*.sindrom_size = (r)*/	324,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/972,
		/*.result =*/		1,
	}, { /* 8. From VedaPro int */
		/*.raw_data_size = (n)*/194400,
		/*.sindrom_size = (r)*/	972,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/972,
		/*.result =*/		0,
	}, { /* 9. From VedaPro int */
		/*.raw_data_size = (n)*/194400,
		/*.sindrom_size = (r)*/	648,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/972,
		/*.result =*/		0,
	}, { /* 10. From VedaPro int */
		/*.raw_data_size = (n)*/194400,
		/*.sindrom_size = (r)*/	486,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/972,
		/*.result =*/		0,
	}, { /* 11. From VedaPro int */
		/*.raw_data_size = (n)*/194400,
		/*.sindrom_size = (r)*/	324,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/972,
		/*.result =*/		0,
	}, { /* 12. From VedaPro int */
		/*.raw_data_size = (n)*/1944000,
		/*.sindrom_size = (r)*/	972,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/972,
		/*.result =*/		0,
	}, { /* 13. From VedaPro int */
		/*.raw_data_size = (n)*/1944000,
		/*.sindrom_size = (r)*/	648,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/972,
		/*.result =*/		0,
	}, { /* 14. From VedaPro int */
		/*.raw_data_size = (n)*/1944000,
		/*.sindrom_size = (r)*/	486,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/972,
		/*.result =*/		0,
	}, { /* 15. From VedaPro int */
		/*.raw_data_size = (n)*/1944000,
		/*.sindrom_size = (r)*/	324,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/972,
		/*.result =*/		0,

	}, { /* 16. From VedaPro int */
		/*.raw_data_size = (n)*/1944,
		/*.sindrom_size = (r)*/	972,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/18000,
		/*.result =*/		1,
	}, { /* 17. From VedaPro int */
		/*.raw_data_size = (n)*/1944,
		/*.sindrom_size = (r)*/	648,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/18000,
		/*.result =*/		1,
	}, { /* 18. From VedaPro int */
		/*.raw_data_size = (n)*/1944,
		/*.sindrom_size = (r)*/	486,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/18000,
		/*.result =*/		1,
	}, { /* 19. From VedaPro int */
		/*.raw_data_size = (n)*/1944,
		/*.sindrom_size = (r)*/	324,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/18000,
		/*.result =*/		1,

	}, { /* 20. From VedaPro int */
		/*.raw_data_size = (n)*/19440,
		/*.sindrom_size = (r)*/	972,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/18000,
		/*.result =*/		1,
	}, { /* 21. From VedaPro int */
		/*.raw_data_size = (n)*/19440,
		/*.sindrom_size = (r)*/	648,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/18000,
		/*.result =*/		1,
	}, { /* 22. From VedaPro int */
		/*.raw_data_size = (n)*/19440,
		/*.sindrom_size = (r)*/	486,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/18000,
		/*.result =*/		1,
	}, { /* 23. From VedaPro int */
		/*.raw_data_size = (n)*/19440,
		/*.sindrom_size = (r)*/	324,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/18000,
		/*.result =*/		1,

	}, { /* 24. From VedaPro int */
		/*.raw_data_size = (n)*/194400,
		/*.sindrom_size = (r)*/	972,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/18000,
		/*.result =*/		1,
	}, { /* 25. From VedaPro int */
		/*.raw_data_size = (n)*/194400,
		/*.sindrom_size = (r)*/	648,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/18000,
		/*.result =*/		1,
	}, { /* 26. From VedaPro int */
		/*.raw_data_size = (n)*/194400,
		/*.sindrom_size = (r)*/	486,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/18000,
		/*.result =*/		1,
	}, { /* 27. From VedaPro int */
		/*.raw_data_size = (n)*/194400,
		/*.sindrom_size = (r)*/	324,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/18000,
		/*.result =*/		1,

	}, { /* 28. From VedaPro int */
		/*.raw_data_size = (n)*/1944000,
		/*.sindrom_size = (r)*/	972,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/18000,
		/*.result =*/		0,
	}, { /* 29. From VedaPro int */
		/*.raw_data_size = (n)*/1944000,
		/*.sindrom_size = (r)*/	648,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/18000,
		/*.result =*/		0,
	}, { /* 30. From VedaPro int */
		/*.raw_data_size = (n)*/1944000,
		/*.sindrom_size = (r)*/	486,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/18000,
		/*.result =*/		0,
	}, { /* 31. From VedaPro int */
		/*.raw_data_size = (n)*/1944000,
		/*.sindrom_size = (r)*/	324,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/18000,
		/*.result =*/		0,

	}, { /* 32. From VedaPro int */
		/*.raw_data_size = (n)*/1944,
		/*.sindrom_size = (r)*/	972,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/153453,
		/*.result =*/		1,
	}, { /* 33. From VedaPro int */
		/*.raw_data_size = (n)*/1944,
		/*.sindrom_size = (r)*/	648,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/153453,
		/*.result =*/		1,
	}, { /* 34. From VedaPro int */
		/*.raw_data_size = (n)*/1944,
		/*.sindrom_size = (r)*/	486,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/153453,
		/*.result =*/		1,
	}, { /* 35. From VedaPro int */
		/*.raw_data_size = (n)*/1944,
		/*.sindrom_size = (r)*/	324,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/153453,
		/*.result =*/		1,

	}, { /* 36. From VedaPro int */
		/*.raw_data_size = (n)*/19440,
		/*.sindrom_size = (r)*/	972,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/153453,
		/*.result =*/		1,
	}, { /* 37. From VedaPro int */
		/*.raw_data_size = (n)*/19440,
		/*.sindrom_size = (r)*/	648,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/153453,
		/*.result =*/		1,
	}, { /* 38. From VedaPro int */
		/*.raw_data_size = (n)*/19440,
		/*.sindrom_size = (r)*/	486,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/153453,
		/*.result =*/		1,
	}, { /* 39. From VedaPro int */
		/*.raw_data_size = (n)*/19440,
		/*.sindrom_size = (r)*/	324,
		/*.hash_size = (t)*/	50,
		/*.qber =*/		0.04,
		/*.err_max =*/		0.05,
		/*.q_k =*/		512,
		/*.eps_ver =*/		(5 * 1e-11),
		/*.eps_aut =*/		1e-20,
		/*.eps_pa =*/		1e-12,
		/*.required_key_len =(l)*/153453,
		/*.result =*/		1,

	}, { /* NULL */
		/*.raw_data_size = (n)*/0,
		/*.sindrom_size = (r)*/	0,
		/*.hash_size = (t)*/	0,
		/*.qber =*/		0,
		/*.err_max =*/		0,
		/*.q_k =*/		0,
		/*.eps_ver =*/		0,
		/*.eps_aut =*/		0,
		/*.eps_pa =*/		0,
		/*.required_key_len =(l)*/0,
		/*.result =*/		0,
	}
};

/* 0 - OK, non zero - error */
static inline int
secamp_self_test() {
	int error = 0, result;
	size_t i;

	for (i = 0; 0 != secamp_tst1v[i].raw_data_size; i ++) {

		result = secamp_is_invalid(secamp_tst1v[i].raw_data_size,
		    secamp_tst1v[i].sindrom_size, secamp_tst1v[i].hash_size,
		    secamp_tst1v[i].qber, secamp_tst1v[i].err_max,
		    secamp_tst1v[i].q_k, secamp_tst1v[i].eps_ver,
		    secamp_tst1v[i].eps_aut, secamp_tst1v[i].eps_pa,
		    secamp_tst1v[i].required_key_len);

		if (secamp_tst1v[i].result != result) {
			secamp_print("%zu secamp_is_invalid:      ERROR: \ncontrol:    %i\ncalculated: %i\n",
			    i, secamp_tst1v[i].result, result);
			error ++;
		} else {
			secamp_print("%zu secamp_is_invalid:      OK! - %i\n", i, result);
		}
	}

	return (error);
}
#endif

#endif /* __SECAMP_H__ */
