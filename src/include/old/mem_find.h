/*-
 * Copyright (c) 2004 - 2012 Rozhuk Ivan <rozhuk.im@gmail.com>
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
 
 
#if !defined(AFX_MEMORYFIND__H__INCLUDED_)
#define AFX_MEMORYFIND__H__INCLUDED_


#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef _WINDOWS
#include <sys/param.h>
#ifndef BSD
#define _GNU_SOURCE /* See feature_test_macros(7) */
#define __USE_GNU 1
#endif
#include <sys/types.h>
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <inttypes.h>
#endif



static inline void *
mem_find_byte(size_t from, const void *buf, size_t buf_size, unsigned char what_find) {

	if (NULL == buf || 0 == buf_size || from >= buf_size)
		return (NULL);

	return ((void*)memchr((const void*)(((const char*)buf) + from), what_find,
	    (buf_size - from)));
}


static inline void *
mem_find_byte_rev(size_t from, const void *buf, size_t buf_size,
    unsigned char what_find) {

	if (NULL == buf || 0 == buf_size || from >= buf_size)
		return (NULL);

#ifndef _WINDOWS
	return (memrchr(buf, what_find, (buf_size - from)));
#else
	register unsigned char *cur_pos;

	cur_pos = (unsigned char*)(((size_t)buf) + (buf_size - from));
	while (cur_pos > buf) {
		if ((*cur_pos) == what_find)
			return (cur_pos);
		cur_pos --;
	}

	return (NULL);
#endif
}


static inline void *
mem_find(size_t from, const void *buf, size_t buf_size, const void *what_find,
    size_t what_find_size) {

	if (NULL == buf || 0 == buf_size || NULL == what_find ||
	    0 == what_find_size || (from + what_find_size) > buf_size)
		return (NULL);

	if (1 == what_find_size) // MemoryFindByte
		return ((void*)memchr((const void*)(((const char*)buf) + from),
		    (*((const char*)what_find)), (buf_size - from)));

#ifndef _WINDOWS
	return (memmem((void*)(((size_t)buf) + from), (buf_size - from), what_find,
	    what_find_size));
#else
	register void *cur_pos;

	cur_pos = (void*)(((size_t)buf) + from);
	if ((from + what_find_size) == buf_size) { // only MemoryCompare
		if (0 == memcmp(cur_pos, what_find, what_find_size))
			return (cur_pos);
		else
			return (NULL);
	}

	buf_size -= (what_find_size - 1);
	while (NULL != cur_pos) {
		cur_pos = memchr(cur_pos, (*((const char*)what_find)),
		    (buf_size - from));
		if (NULL != cur_pos) {
			if (0 == memcmp(cur_pos, what_find, what_find_size)) {
				return (cur_pos);
			} else {
				cur_pos = (void*)(((size_t)cur_pos) + 1);
			}
		}
	}
	return (NULL);
#endif
}

static inline int
mem_replace_arr(const void *src, size_t src_size, size_t repl_count, void *tmp_arr,
    const void **src_repl, const size_t *src_repl_counts,
    const void **dst_repl, const size_t *dst_repl_counts,
    void *dst, size_t dst_size, size_t *dst_size_ret) {
	size_t ret_count = 0;
	uint8_t *dst_buf = dst, *src_buf = (uint8_t*)src, *fouded_local[32];
	register uint8_t *dst_cur, *src_cur, *src_cur_prev, *dst_max;
	uint8_t **founded = fouded_local;
	register size_t i, first_idx = 0, founded_cnt = 0;

	if (31 < repl_count) {
		if (NULL == tmp_arr)
			return (-1);
		founded = tmp_arr;
	}
	src_cur_prev = src_buf;
	dst_cur = dst_buf;
	dst_max = (dst_buf + dst_size);
	for (i = 0; i < repl_count; i ++) { // scan for replace in first time
		founded[i] = mem_find((src_cur_prev - src_buf), src_buf, src_size, src_repl[i], src_repl_counts[i]);
		if (NULL != founded[i])
			founded_cnt ++;
	}

	while (0 != founded_cnt) {
		// looking for first to replace
		for (i = 0; i < repl_count; i ++) {
			if (NULL != founded[i] &&
			    (founded[i] < founded[first_idx] ||
			    NULL == founded[first_idx]))
				first_idx = i;
		}
		if (NULL == founded[first_idx])
			break; /* Should newer happen. */
		// in founded
		i = (founded[first_idx] - src_cur_prev);
		if (dst_max <= (dst_cur + (i + src_repl_counts[first_idx])))
			return (-1);
		memmove(dst_cur, src_cur_prev, i);
		dst_cur += i;
		memcpy(dst_cur, dst_repl[first_idx], dst_repl_counts[first_idx]);
		dst_cur += dst_repl_counts[first_idx];
		src_cur_prev = (founded[first_idx] + src_repl_counts[first_idx]);
		ret_count ++;

		for (i = 0; i < repl_count; i ++) { // loking for in next time
			if (NULL == founded[i] || founded[i] >= src_cur_prev)
				continue;
			founded[i] = mem_find((src_cur_prev - src_buf), src_buf, src_size, src_repl[i], src_repl_counts[i]);
			if (NULL == founded[i])
				founded_cnt --;
		}
	} /* while */
	src_cur = (src_buf + src_size);
	memmove(dst_cur, src_cur_prev, (src_cur - src_cur_prev));
	dst_cur += (src_cur - src_cur_prev);

	if (dst_size_ret)
		(*dst_size_ret) = (dst_cur - dst_buf);

	return (ret_count);
}



#endif // !defined(AFX_MEMORYFIND__H__INCLUDED_)
