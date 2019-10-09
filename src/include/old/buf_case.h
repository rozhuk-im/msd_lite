/*-
 * Copyright (c) 2004 - 2014 Rozhuk Ivan <rozhuk.im@gmail.com>
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
 
 
 
 #if !defined(AFX_BUFCASE__H__INCLUDED_)
#define AFX_BUFCASE__H__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef WINDOWS
#include <inttypes.h>
#else
#define uint8_t		unsigned char
#endif
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */



static inline size_t
buf_to_lower(void *dst, const void *src, size_t buf_size) {
	register uint8_t tm;
	register uint8_t *byte_src, *byte_src_max, *byte_dst;

	if (NULL == dst || NULL == src || 0 == buf_size)
		return (0);
	byte_src = ((uint8_t*)((size_t)src));
	byte_src_max = (byte_src + buf_size);
	byte_dst = (uint8_t*)dst;
	for (; byte_src < byte_src_max; byte_src ++, byte_dst ++) {
		tm = (*byte_src);
		if ('A' <= tm && 'Z' >= tm)
			tm |= 32;
		(*byte_dst) = tm;
	}
	return (buf_size);
}


static inline size_t
buf_to_upper(void *dst, const void *src, size_t buf_size) {
	register uint8_t tm;
	register uint8_t *byte_src, *byte_src_max, *byte_dst;

	if (NULL == dst || NULL == src || 0 == buf_size)
		return (0);
	byte_src = ((uint8_t*)((size_t)src));
	byte_src_max = (byte_src + buf_size);
	byte_dst = (uint8_t*)dst;
	for (; byte_src < byte_src_max; byte_src ++, byte_dst ++) {
		tm = (*byte_src);
		if ('a' <= tm && 'z' >= tm)
			tm &= ~32;
		(*byte_dst) = tm;
	}
	return (buf_size);
}


/* compare, ignory case, like strncasecmp() */
static inline int
buf_cmpi(const void *buf1, size_t buf1_size, const void *buf2, size_t buf2_size) {
	register uint8_t tm1, tm2;
	register uint8_t *buf1_byte, *buf1_byte_max, *buf2_byte;

	if (buf1_size != buf2_size)
		return ((buf1_size - buf2_size));
	if (0 == buf1_size || buf1 == buf2)
		return (0);
	if (NULL == buf1 || NULL == buf2)
		return ( ((NULL == buf1) ? 0 : 127) - ((NULL == buf2) ? 0 : 127) );

	buf1_byte = ((uint8_t*)((size_t)buf1));
	buf1_byte_max = (buf1_byte + buf1_size);
	buf2_byte = ((uint8_t*)((size_t)buf2));
	for (; buf1_byte < buf1_byte_max; buf1_byte ++, buf2_byte ++) {
		tm1 = (*buf1_byte);
		if ('A' <= tm1 && 'Z' >= tm1)
			tm1 |= 32;
		tm2 = (*buf2_byte);
		if ('A' <= tm2 && 'Z' >= tm2)
			tm2 |= 32;
		if (tm1 == tm2)
			continue;
		return ((tm1 - tm2));
	}
	return (0);
}

static inline int
buf_cmp(const void *buf1, size_t buf1_size, const void *buf2, size_t buf2_size) {

	if (buf1_size != buf2_size)
		return ((buf1_size - buf2_size));
	if (0 == buf1_size || buf1 == buf2)
		return (0);
	if (NULL == buf1 || NULL == buf2)
		return ( ((NULL == buf1) ? 0 : 127) - ((NULL == buf2) ? 0 : 127) );

	return (memcmp(buf1, buf2, buf1_size));
}


#endif // !defined(AFX_BUFCASE__H__INCLUDED_)
