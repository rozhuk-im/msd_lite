/*-
 * Copyright (c) 2005 - 2013 Rozhuk Ivan <rozhuk.im@gmail.com>
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
 
 
 
 #if !defined(AFX_STRTONUM__H__INCLUDED_)
#define AFX_STRTONUM__H__INCLUDED_



#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000


#ifdef _WINDOWS
	#define uint8_t		unsigned char
	#define uint16_t	WORD
	#define int32_t		LONG
	#define uint32_t	DWORD
	#define int64_t		LONGLONG
	#define uint64_t	DWORDLONG
	#define	size_t		SIZE_T
	#define	ssize_t		SSIZE_T
#else
#include <inttypes.h>
#endif


#define STR2NUM_SINGN(str, str_len, cur_singn, cur_char)			\
	for (; 0 != str_len; str_len --, str ++) {				\
		cur_char = (*str);						\
		if ('-' == cur_char)						\
			cur_singn = -1;						\
		else if ('+' == cur_char)					\
			cur_singn = 1;						\
		else								\
			break;							\
	}

#define STR2NUM(str, str_len, ret_num, cur_char)				\
	for (; 0 != str_len; str_len --, str ++) {				\
		cur_char = ((*str) - '0');					\
		if (9 < cur_char)						\
			continue;						\
		ret_num *= 10;							\
		ret_num += cur_char;						\
	}



static inline size_t
StrToUNum(const char *str, size_t str_len) {
	size_t ret_num = 0;
	register uint8_t cur_char;

	if (NULL == str || 0 == str_len)
		return (0);
	STR2NUM(str, str_len, ret_num, cur_char);
	return (ret_num);
}

static inline size_t
UStr8ToUNum(const uint8_t *str, size_t str_len) {
	size_t ret_num = 0;
	register uint8_t cur_char;

	if (NULL == str || 0 == str_len)
		return (0);
	STR2NUM(str, str_len, ret_num, cur_char);
	return (ret_num);
}

static inline uint32_t
StrToUNum32(const char *str, size_t str_len) {
	uint32_t ret_num = 0;
	register uint8_t cur_char;

	if (NULL == str || 0 == str_len)
		return (0);
	STR2NUM(str, str_len, ret_num, cur_char);
	return (ret_num);
}

static inline uint32_t
UStr8ToUNum32(const uint8_t *str, size_t str_len) {
	uint32_t ret_num = 0;
	register uint8_t cur_char;

	if (NULL == str || 0 == str_len)
		return (0);
	STR2NUM(str, str_len, ret_num, cur_char);
	return (ret_num);
}

static inline uint64_t
StrToUNum64(const char *str, size_t str_len) {
	uint64_t ret_num = 0;
	register uint8_t cur_char;

	if (NULL == str || 0 == str_len)
		return (0);
	STR2NUM(str, str_len, ret_num, cur_char);
	return (ret_num);
}

static inline uint64_t
UStr8ToUNum64(const uint8_t *str, size_t str_len) {
	uint64_t ret_num = 0;
	register uint8_t cur_char;

	if (NULL == str || 0 == str_len)
		return (0);
	STR2NUM(str, str_len, ret_num, cur_char);
	return (ret_num);
}


/* Signed. */

static inline ssize_t
StrToNum(const char *str, size_t str_len) {
	ssize_t ret_num = 0, cur_singn = 1;
	register uint8_t cur_char;

	if (NULL == str || 0 == str_len)
		return (0);
	STR2NUM_SINGN(str, str_len, cur_singn, cur_char);
	STR2NUM(str, str_len, ret_num, cur_char);
	ret_num *= cur_singn;
	return (ret_num);
}

static inline ssize_t
UStr8ToNum(const uint8_t *str, size_t str_len) {
	ssize_t ret_num = 0, cur_singn = 1;
	register uint8_t cur_char;

	if (NULL == str || 0 == str_len)
		return (0);
	STR2NUM_SINGN(str, str_len, cur_singn, cur_char);
	STR2NUM(str, str_len, ret_num, cur_char);
	ret_num *= cur_singn;
	return (ret_num);
}

static inline int32_t
StrToNum32(const char *str, size_t str_len) {
	int32_t ret_num = 0, cur_singn = 1;
	register uint8_t cur_char;

	if (NULL == str || 0 == str_len)
		return (0);
	STR2NUM_SINGN(str, str_len, cur_singn, cur_char);
	STR2NUM(str, str_len, ret_num, cur_char);
	ret_num *= cur_singn;
	return (ret_num);
}

static inline int32_t
UStr8ToNum32(const uint8_t *str, size_t str_len) {
	int32_t ret_num = 0, cur_singn = 1;
	register uint8_t cur_char;

	if (NULL == str || 0 == str_len)
		return (0);
	STR2NUM_SINGN(str, str_len, cur_singn, cur_char);
	STR2NUM(str, str_len, ret_num, cur_char);
	ret_num *= cur_singn;
	return (ret_num);
}

static inline int64_t
StrToNum64(const char *str, size_t str_len) {
	int64_t ret_num = 0, cur_singn = 1;
	register uint8_t cur_char;

	if (NULL == str || 0 == str_len)
		return (0);
	STR2NUM_SINGN(str, str_len, cur_singn, cur_char);
	STR2NUM(str, str_len, ret_num, cur_char);
	ret_num *= cur_singn;
	return (ret_num);
}

static inline int64_t
UStr8ToNum64(const uint8_t *str, size_t str_len) {
	int64_t ret_num = 0, cur_singn = 1;
	register uint8_t cur_char;

	if (NULL == str || 0 == str_len)
		return (0);
	STR2NUM_SINGN(str, str_len, cur_singn, cur_char);
	STR2NUM(str, str_len, ret_num, cur_char);
	ret_num *= cur_singn;
	return (ret_num);
}


#endif // !defined(AFX_STRTONUM__H__INCLUDED_)
