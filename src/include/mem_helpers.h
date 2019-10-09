/*-
 * Copyright (c) 2004 - 2016 Rozhuk Ivan <rozhuk.im@gmail.com>
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
 
 
#ifndef __MEMORY_HELPERS_H__
#define __MEMORY_HELPERS_H__


#ifndef _WINDOWS
#	include <sys/param.h>
#	ifdef __linux__ /* Linux specific code. */
#		define _GNU_SOURCE /* See feature_test_macros(7) */
#		define __USE_GNU 1
#	endif /* Linux specific code. */
#	include <sys/types.h>
#	include <sys/mman.h> /* mmap, munmap */
#	ifdef _KERNEL
#		include <sys/systm.h>
#	else
#		include <inttypes.h>
#		include <stdlib.h>
#		include <string.h> /* memcpy, memmove, memset... */
#		include <strings.h> /* strncasecmp() */
#	endif
	/* Secure version of memset(). */
	static void *(*volatile memset_volatile)(void*, int, size_t) = memset;
#else
#	define EINVAL		ERROR_INVALID_PARAMETER
#	define ENOMEM		ERROR_OUTOFMEMORY
#	define uint8_t		unsigned char
#	define size_t		SIZE_T
#	include <string.h> /* memcpy, memmove, memset... */
#	include <stdint.h>
#endif
#include <stdlib.h>

#ifndef SIZE_T_MAX
#	define SIZE_T_MAX	((size_t)~0)
#endif



#ifdef _WINDOWS /* Windows does not have these functions. */

/* Secure version of memset(). */
static inline void *
memset_volatile(const void *buf, const int val, const size_t buf_size) {
	register uint8_t *ptm = (uint8_t*)buf;
	register const uint8_t *buf_max = (((uint8_t*)buf) + buf_size);

	while (ptm < buf_max) {
		(*ptm) = val;
		ptm ++;
	}
	return (buf_max);
}

static inline void *
memrchr(const void *buf, const int what_find, const size_t buf_size) {
	register uint8_t *ptm = (((uint8_t*)buf) + buf_size - 1);

	while (ptm >= buf) {
		if ((*ptm) == (uint8_t)what_find)
			return (ptm);
		ptm --;
	}
	return (NULL);
}

static inline void *
memmem(const void *buf, const size_t buf_size, const void *what_find,
    const size_t what_find_size) {
	register uint8_t *ptm;

	if (0 == what_find_size || what_find_size > buf_size)
		return (NULL);
	if (1 == what_find_size) /* use fast memchr() */
		return ((void*)memchr(buf, (*((uint8_t*)what_find)), buf_size));
	if (what_find_size == buf_size) { /* only memcmp() */
		if (0 == memcmp(buf, what_find, what_find_size))
			return ((void*)buf);
		return (NULL);
	}

	ptm = ((uint8_t*)buf);
	buf_size -= (what_find_size - 1);
	for (;;) {
		ptm = (uint8_t*)memchr(ptm, (*((uint8_t*)what_find)),
		    (buf_size - (ptm - ((uint8_t*)buf))));
		if (NULL == ptm)
			return (NULL);
		if (0 == memcmp(ptm, what_find, what_find_size))
			return (ptm);
		ptm ++;
	}
	return (NULL);
}

#endif


////////////////////////////////////////////////////////////////////////
//////////////////////// Find byte in memory. //////////////////////////
////////////////////////////////////////////////////////////////////////
static inline void *
mem_chr(const void *buf, const size_t size, const uint8_t what_find) {

	if (NULL == buf || 0 == size)
		return (NULL);
	return ((void*)memchr(buf, what_find, size));
}

static inline void *
mem_chr_off(const size_t offset, const void *buf, const size_t size,
    const uint8_t what_find) {

	if (NULL == buf || offset >= size)
		return (NULL);
	return (memchr((((const uint8_t*)buf) + offset), what_find,
	    (size - offset)));
}

static inline void *
mem_chr_ptr(const void *ptr, const void *buf, const size_t size,
    const uint8_t what_find) {
	size_t offset;

	if (NULL == buf || buf > ptr)
		return (NULL);
	offset = (size_t)(((const uint8_t*)ptr) - ((const uint8_t*)buf));
	if (offset >= size)
		return (NULL);
	return ((void*)memchr(ptr, what_find, (size - offset)));
}


////////////////////////////////////////////////////////////////////////
//////////////// Reverse find byte in memory. //////////////////////////
////////////////////////////////////////////////////////////////////////
static inline void *
mem_rchr(const void *buf, const size_t size, const uint8_t what_find) {

	if (NULL == buf || 0 == size)
		return (NULL);
	return (memrchr(buf, what_find, size));
}

static inline void *
mem_rchr_off(size_t offset, const void *buf, const size_t size,
    const uint8_t what_find) {

	if (NULL == buf || offset >= size)
		return (NULL);
	return (memrchr(buf, what_find, (size - offset)));
}

static inline void *
mem_rchr_ptr(const void *ptr, const void *buf, const size_t size,
    const uint8_t what_find) {
	size_t offset;

	if (NULL == buf || buf > ptr)
		return (NULL);
	offset = (size_t)(((const uint8_t*)ptr) - ((const uint8_t*)buf));
	if (offset >= size)
		return (NULL);
	return (memrchr(buf, what_find, offset));
}


////////////////////////////////////////////////////////////////////////
///////////////// Find bytes array in memory. //////////////////////////
////////////////////////////////////////////////////////////////////////
#define mem_find_cstr(__buf, __size, __cstr)				\
    mem_find((__buf), (__size), __cstr, (sizeof(__cstr) - 1))

#define mem_find_off_cstr(__off, __buf, __size, __cstr)			\
    mem_find_off((__off), (__buf), (__size), __cstr, (sizeof(__cstr) - 1))

#define mem_find_ptr_cstr(__ptr, __buf, __size, __cstr)			\
    mem_find_ptr((__ptr), (__buf), (__size), __cstr, (sizeof(__cstr) - 1))


static inline void *
mem_find(const void *buf, const size_t buf_size, const void *what_find,
    const size_t what_find_size) {

	if (NULL == buf || NULL == what_find || 0 == what_find_size)
		return (NULL);
	return (memmem(buf, buf_size, what_find, what_find_size));
}

static inline void *
mem_find_off(const size_t offset, const void *buf, const size_t buf_size,
    const void *what_find, const size_t what_find_size) {

	if (NULL == buf || offset >= buf_size ||
	    NULL == what_find || 0 == what_find_size)
		return (NULL);
	return (memmem((((const uint8_t*)buf) + offset), (buf_size - offset),
	    what_find, what_find_size));
}

static inline void *
mem_find_ptr(const void *ptr, const void *buf, const size_t buf_size,
    const void *what_find, const size_t what_find_size) {
	size_t offset;

	if (NULL == buf || buf > ptr ||
	    NULL == what_find || 0 == what_find_size)
		return (NULL);
	offset = (size_t)(((const uint8_t*)ptr) - ((const uint8_t*)buf));
	if (offset >= buf_size)
		return (NULL);
	return (memmem(ptr, (buf_size - offset), what_find, what_find_size));
}


////////////////////////////////////////////////////////////////////////
/////// Replace items from src_repl array to items from dst_repl. //////
////////////////////////////////////////////////////////////////////////
static inline int
mem_replace_arr(const void *src, const size_t src_size, const size_t repl_count, void *tmp_arr,
    const void **src_repl, const size_t *src_repl_counts,
    const void **dst_repl, const size_t *dst_repl_counts,
    void *dst, const size_t dst_size, size_t *dst_size_ret, size_t *replaced) {
	size_t ret_count = 0;
	uint8_t *dst_buf, *fouded_local[32];
	const uint8_t *src_buf;
	register uint8_t *dst_cur, *dst_max;
	register const uint8_t *src_cur, *src_cur_prev;
	uint8_t **founded = fouded_local;
	register size_t i, first_idx = 0, founded_cnt = 0;

	if (NULL == src || NULL == dst ||
	    ((NULL == src_repl || NULL == dst_repl) && 0 != repl_count))
		return (EINVAL);
	if (31 < repl_count) {
		if (NULL == tmp_arr)
			return (EINVAL);
		founded = (uint8_t**)tmp_arr;
	}
	dst_buf = (uint8_t*)dst;
	src_buf = (const uint8_t*)src;
	src_cur_prev = src_buf;
	dst_cur = dst_buf;
	dst_max = (dst_buf + dst_size);
	for (i = 0; i < repl_count; i ++) { // scan for replace in first time
		founded[i] = (uint8_t*)mem_find(src_buf, src_size, src_repl[i],
		    src_repl_counts[i]);
		if (NULL != founded[i]) {
			founded_cnt ++;
		}
	}

	while (0 != founded_cnt) {
		// looking for first to replace
		for (i = 0; i < repl_count; i ++) {
			if (NULL != founded[i] &&
			    (founded[i] < founded[first_idx] ||
			    NULL == founded[first_idx])) {
				first_idx = i;
			}
		}
		if (NULL == founded[first_idx])
			break; /* Should newer happen. */
		// in founded
		i = (size_t)(founded[first_idx] - src_cur_prev);
		if (dst_max <= (dst_cur + (i + src_repl_counts[first_idx])))
			return (ENOBUFS);
		memmove(dst_cur, src_cur_prev, i);
		dst_cur += i;
		memcpy(dst_cur, dst_repl[first_idx], dst_repl_counts[first_idx]);
		dst_cur += dst_repl_counts[first_idx];
		src_cur_prev = (founded[first_idx] + src_repl_counts[first_idx]);
		ret_count ++;

		for (i = 0; i < repl_count; i ++) { // loking for in next time
			if (NULL == founded[i] || founded[i] >= src_cur_prev)
				continue;
			founded[i] = (uint8_t*)mem_find_ptr(src_cur_prev, src_buf,
			    src_size, src_repl[i], src_repl_counts[i]);
			if (NULL == founded[i]) {
				founded_cnt --;
			}
		}
	} /* while */
	src_cur = (src_buf + src_size);
	memmove(dst_cur, src_cur_prev, (size_t)(src_cur - src_cur_prev));
	dst_cur += (src_cur - src_cur_prev);

	if (NULL != dst_size_ret) {
		(*dst_size_ret) = (size_t)(dst_cur - dst_buf);
	}
	if (NULL != replaced) {
		(*replaced) = ret_count;
	}
	return (0);
}


////////////////////////////////////////////////////////////////////////
////////////////////////// Case lower/upper. ///////////////////////////
////////////////////////////////////////////////////////////////////////
static inline size_t
mem_to_lower(void *dst, const void *src, const size_t size) {
	register uint8_t tm;
	register uint8_t *ptm;
	register const uint8_t *dst_max;

	if (NULL == dst || NULL == src || 0 == size)
		return (0);
	memmove(dst, src, size);
	ptm = ((uint8_t*)dst);
	dst_max = (ptm + size);
	for (; ptm < dst_max; ptm ++) {
		tm = (*ptm);
		if ('A' <= tm &&
		    'Z' >= tm) {
			(*ptm) = (tm | 32);
		}
	}
	return (size);
}

static inline size_t
mem_to_upper(void *dst, const void *src, const size_t size) {
	register uint8_t tm;
	register uint8_t *ptm;
	register const uint8_t *dst_max;

	if (NULL == dst || NULL == src || 0 == size)
		return (0);
	memmove(dst, src, size);
	ptm = ((uint8_t*)dst);
	dst_max = (ptm + size);
	for (; ptm < dst_max; ptm ++) {
		tm = (*ptm);
		if ('a' <= tm &&
		    'z' >= tm) {
			(*ptm) = (tm & ~32);
		}
	}
	return (size);
}


////////////////////////////////////////////////////////////////////////
////////////////////////// memcmp() wrappers. //////////////////////////
////////////////////////////////////////////////////////////////////////
#define mem_cmp_cstr(__cstr, __buf)					\
    mem_cmp(__cstr, (__buf), (sizeof(__cstr) - 1))

#define mem_cmpn_cstr(__cstr, __buf, __size)				\
    mem_cmpn(__cstr, (sizeof(__cstr) - 1), (__buf), (__size))


static inline int
mem_cmp(const void *buf1, const void *buf2, const size_t size) {

	if (0 == size || buf1 == buf2)
		return (0);
	if (NULL == buf1)
		return (-127);
	if (NULL == buf2)
		return (127);
	return (memcmp(buf1, buf2, size));
}

static inline int
mem_cmpn(const void *buf1, const size_t buf1_size,
    const void *buf2, const size_t buf2_size) {

	if (buf1_size != buf2_size)
		return (((buf1_size > buf2_size) ? 127 : -127));
	return (mem_cmp(buf1, buf2, buf1_size));
}

/* Secure version of memcmp(). */
static inline int
mem_scmp(const void *buf1, const void *buf2, const size_t size) {
	register int res = 0;
	register size_t i;
	register const uint8_t *a = (const uint8_t*)buf1;
	register const uint8_t *b = (const uint8_t*)buf2;

	if (0 == size || buf1 == buf2)
		return (0);
	if (NULL == buf1)
		return (-127);
	if (NULL == buf2)
		return (127);
	for (i = 0; i < size; i ++) {
		res |= (a[i] ^ b[i]);
	}

	return (res);
}


////////////////////////////////////////////////////////////////////////
////////////// Compare, ignory case, like strncasecmp() ////////////////
////////////////////////////////////////////////////////////////////////
#define mem_cmpi_cstr(__cstr, __buf)					\
    mem_cmpi(__cstr, (__buf), (sizeof(__cstr) - 1))

#define mem_cmpin_cstr(__cstr, __buf, __size)				\
    mem_cmpin(__cstr, (sizeof(__cstr) - 1), (__buf), (__size))


static inline int
mem_cmpi(const void *buf1, const void *buf2, const size_t size) {

	if (0 == size || buf1 == buf2)
		return (0);
	if (NULL == buf1)
		return (-127);
	if (NULL == buf2)
		return (127);
#if !defined(_KERNEL) && !defined(_WINDOWS)
	return (strncasecmp((const char*)buf1, (const char*)buf2, size));
#else
	register uint8_t tm1, tm2;
	register uint8_t *buf1_byte, *buf2_byte;
	register const uint8_t *buf1_max;

	buf1_byte = ((uint8_t*)buf1);
	buf1_max = (buf1_byte + size);
	buf2_byte = ((uint8_t*)buf2);
	for (; buf1_byte < buf1_max; buf1_byte ++, buf2_byte ++) {
		tm1 = (*buf1_byte);
		if ('A' <= tm1 &&
		    'Z' >= tm1) {
			tm1 |= 32;
		}
		tm2 = (*buf2_byte);
		if ('A' <= tm2 &&
		    'Z' >= tm2) {
			tm2 |= 32;
		}
		if (tm1 == tm2)
			continue;
		return ((tm1 - tm2));
	}
	return (0);
#endif
}

static inline int
mem_cmpin(const void *buf1, const size_t buf1_size,
    const void *buf2, const size_t buf2_size) {

	if (buf1_size != buf2_size)
		return (((buf1_size > buf2_size) ? 127 : -127));
	return (mem_cmpi(buf1, buf2, buf1_size));
}


////////////////////////////////////////////////////////////////////////
/////////////////// Memory management wrappers. ////////////////////////
////////////////////////////////////////////////////////////////////////
/* Secure version of memset(). */
static inline void *
mem_set(void *buf, const size_t size, const uint8_t c) {

	if (NULL == buf || 0 == size)
		return (buf);
	return (memset_volatile(buf, c, size));
}

#define mem_bzero(__buf, __size)	mem_set((__buf), (__size), 0)


/* Debug memory fill. */
#ifdef DEBUG
#define mem_filld(__buf, __size)	mem_set((__buf), (__size), 0xab)
#else
#define mem_filld(__buf, __size)
#endif


/* Allocate and zero memory. */
#define zalloc(__size)			calloc(1, (__size))
#define zallocarray(__nmemb, __size)	calloc((__nmemb), (__size))


#define mallocarray(__nmemb, __size)	reallocarray(NULL, (__nmemb), (__size))

#if !defined(__FreeBSD_version) || __FreeBSD_version < 1100000
static inline void *
reallocarray(void *buf, const size_t nmemb, const size_t size) {
	size_t nmemb_size;

	nmemb_size = (nmemb * size);
	if (0 == nmemb_size) {
		if (0 != nmemb &&
		    0 != size) { /* Overflow. */
			errno = ENOMEM;
			return (NULL);
		}
		nmemb_size ++;
	} else if (((nmemb | size) & (SIZE_T_MAX << (sizeof(size_t) * 4))) &&
	    (nmemb_size / size) != nmemb) { /* size_t overflow. */
		errno = ENOMEM;
		return (NULL);
	}
	return (realloc(buf, nmemb_size));
}
#endif

static inline int
realloc_items(void **items, const size_t item_size,
    size_t *allocated, const size_t alloc_blk_cnt, const size_t count) {
	size_t allocated_prev, allocated_new;
	uint8_t *items_new;

	if (NULL == items || NULL == allocated || 0 == alloc_blk_cnt)
		return (EINVAL);
	allocated_prev = (*allocated);
	if (NULL != (*items) &&
	    allocated_prev > count &&
	    allocated_prev <= (count + alloc_blk_cnt))
		return (0);
	allocated_new = (((count / alloc_blk_cnt) + 1) * alloc_blk_cnt);
	items_new = (uint8_t*)reallocarray((*items), item_size, allocated_new);
	if (NULL == items_new) /* Realloc fail! */
		return (ENOMEM);
	if (allocated_new > allocated_prev) { /* Init new mem. */
		mem_bzero((items_new + (allocated_prev * item_size)),
		    ((allocated_new - allocated_prev) * item_size));
	}
	(*items) = items_new;
	(*allocated) = allocated_new;

	return (0);
}


////////////////////////////////////////////////////////////////////////
/////////////////////// mmap() based allocator /////////////////////////
////////////////////////////////////////////////////////////////////////
#ifndef _WINDOWS

#define mapalloc(__size)	mapalloc_fd((uintptr_t)-1, (__size))

static inline void *
mapalloc_fd(uintptr_t fd, const size_t size) {
	void *buf;
	int flags = 0;

	if (0 == size)
		return (NULL);
	/* Set flags. */
	if (((uintptr_t)-1) == fd) { /* From virt mem. */
		fd = ((uintptr_t)-1);
		flags |= MAP_ANONYMOUS;
#ifdef __linux__ /* Linux specific code. */
		flags |= MAP_PRIVATE;
#endif /* Linux specific code. */
	} else { /* From file. */
		flags |= MAP_SHARED;
	}
#ifdef BSD /* BSD specific code. */
	flags |= MAP_NOCORE;
#endif /* BSD specific code. */

	buf = mmap(NULL, size, (PROT_READ | PROT_WRITE),
	    (flags
#ifdef MAP_ALIGNED_SUPER /* BSD specific code. */
	     | MAP_ALIGNED_SUPER
#endif /* BSD specific code. */
#ifdef MAP_HUGETLB /* Linux specific code. */
	     | MAP_HUGETLB
#endif /* Linux specific code. */
	    ), (int)fd, 0);
	if (MAP_FAILED == buf) { /* Retry without super/huge pages */
		buf = mmap(NULL, size, (PROT_READ | PROT_WRITE), flags,
		    (int)fd, 0);
		if (MAP_FAILED == buf)
			return (NULL);
	}
	if (0 != mlock(buf, size)) { /* We reach system limit or have no real memory! */
		/* bsd tune: vm.max_wired !!! */
		/* No fail, just less perfomance. */
		//munmap(mem, size);
		//return (NULL);
	}
	mem_bzero(buf, size);
	return (buf);
}

static inline void
mapfree(void *buf, const size_t size) {

	if (NULL == buf ||
	    0 == size)
		return;
	munmap(buf, size);
}

#endif /* _WINDOWS */

#endif /* __MEMORY_HELPERS_H__ */
