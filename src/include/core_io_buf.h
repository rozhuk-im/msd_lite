/*-
 * Copyright (c) 2011 - 2016 Rozhuk Ivan <rozhuk.im@gmail.com>
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


#ifndef __CORE_IO_BUF_H__
#define __CORE_IO_BUF_H__

#include <sys/types.h>
#include <inttypes.h>
#include <stdlib.h> /* malloc, exit */


typedef struct io_buf_s {
	uint8_t	*data;		/* Pointer to data. */
	size_t	size;		/* Buffer size. */
	size_t	used;		/* Data size. */
	size_t	offset;		/* Read from buffer offset to write/send. */
	size_t	transfer_size;	/* Write/send, read/recv size. */
	uint32_t flags;
} io_buf_t, *io_buf_p;

#define IO_BUF_F_ALLOC_BUF__INT	(((uint32_t)1) << 0) /* Allocate mem for io_buf_t. Internal use only! */
#define IO_BUF_F_DATA_ALLOC	(((uint32_t)1) << 1) /* Allocate / realloc / free mem for data. */
#define IO_BUF_F_DATA_SHARED	(((uint32_t)1) << 2) /* Single mem for io_buf_t + data. */
#define IO_BUF_FLAGS_BAD_MASK	(IO_BUF_F_DATA_ALLOC | IO_BUF_F_DATA_SHARED)
#ifndef IO_BUF_FLAGS_STD	/* Default. */
#	define IO_BUF_FLAGS_STD	(IO_BUF_F_DATA_SHARED)
#endif


#define IO_BUF_OFFSET_SIZE(__iobuf)	((__iobuf)->size - (__iobuf)->offset)
#define IO_BUF_OFFSET_GET(__iobuf)	((__iobuf)->data + (__iobuf)->offset)
#define IO_BUF_FREE_SIZE(__iobuf)	((__iobuf)->size - (__iobuf)->used)
#define IO_BUF_FREE_GET(__iobuf)	((__iobuf)->data + (__iobuf)->used)


/*
 * Macros for increment/decrement value
 * increment in range up to "max"
 * decrement in range down to zero.
 * Prevent owerflow.
 */
#define IO_BUF_VALUE_IN_RANGE_INC(__val, __max, __size)	{		\
	if ((__max) > (__val) && ((__max) - (__val)) > (__size)) {	\
		(__val) += (__size);					\
	} else {							\
		(__val) = (__max);					\
	}								\
}

#define IO_BUF_VALUE_IN_RANGE_DEC(__val, __size) {			\
	if ((__val) > (__size)) {					\
		(__val) -= (__size);					\
	} else {							\
		(__val) = 0;						\
	}								\
}


/*
 * Macros for increment/decrement io_buf feilds
 * increment in range up to "buf->size"
 * decrement in range down to zero
 */
#define IO_BUF_USED_INC(__iobuf, __size)				\
    IO_BUF_VALUE_IN_RANGE_INC((__iobuf)->used, (__iobuf)->size, (size_t)(__size))
#define IO_BUF_USED_DEC(__iobuf, __size)				\
    IO_BUF_VALUE_IN_RANGE_DEC((__iobuf)->used, (size_t)(__size))

#define IO_BUF_OFFSET_INC(__iobuf, __size)				\
    IO_BUF_VALUE_IN_RANGE_INC((__iobuf)->offset, (__iobuf)->size, (size_t)(__size))
#define IO_BUF_OFFSET_DEC(__iobuf, __size)				\
    IO_BUF_VALUE_IN_RANGE_DEC((__iobuf)->offset, (size_t)(__size))

#define IO_BUF_TR_SIZE_GET(__iobuf)	((__iobuf)->transfer_size)
#define IO_BUF_TR_SIZE_SET(__iobuf, __size)				\
    (__iobuf)->transfer_size = (__size)
#define IO_BUF_TR_SIZE_INC(__iobuf, __size)				\
    IO_BUF_VALUE_IN_RANGE_INC((__iobuf)->transfer_size, (__iobuf)->size, (size_t)(__size))
#define IO_BUF_TR_SIZE_DEC(__iobuf, __size)				\
    IO_BUF_VALUE_IN_RANGE_DEC((__iobuf)->transfer_size, (size_t)(__size))



#define IO_BUF_BUSY_SIZE_SET(__iobuf, __size) {				\
	(__iobuf)->used = (__size);					\
	(__iobuf)->offset = (__size);					\
}

#define IO_BUF_MARK_TRANSFER_ALL_USED(__iobuf) {			\
	(__iobuf)->offset = 0;						\
	(__iobuf)->transfer_size = (__iobuf)->used;			\
}

#define IO_BUF_MARK_TRANSFER_ALL_FREE(__iobuf) {			\
	(__iobuf)->offset = (__iobuf)->used;				\
	(__iobuf)->transfer_size = IO_BUF_FREE_SIZE((__iobuf));		\
}

#define IO_BUF_MARK_AS_EMPTY(__iobuf) {					\
	(__iobuf)->used = 0;						\
	(__iobuf)->offset = 0;						\
	(__iobuf)->transfer_size = 0;					\
}


#ifdef DEBUG
#include "macro_helpers.h"

static inline void
io_buf_sign_set__int(io_buf_p io_buf) {

	/* Set magic number. */
	io_buf->data[(io_buf->size + 0)] = 0x00; /* String end marker. */
	io_buf->data[(io_buf->size + 1)] = 0x12;
	io_buf->data[(io_buf->size + 2)] = 0xfe;
	io_buf->data[(io_buf->size + 3)] = 0x56;
}
static inline void
io_buf_sign_check__int(io_buf_p io_buf) {

	if (0x00 != io_buf->data[(io_buf->size + 0)] ||
	    0x12 != io_buf->data[(io_buf->size + 1)] ||
	    0xfe != io_buf->data[(io_buf->size + 2)] ||
	    0x56 != io_buf->data[(io_buf->size + 3)]) {
		debug_break();
	}
}
#else
static inline void
io_buf_sign_set__int(io_buf_p io_buf) {

	/* Set magic number. */
	io_buf->data[(io_buf->size + 0)] = 0x00; /* String end marker. */
}
#	define io_buf_sign_check__int(__io_buf)
#endif


/* Warning!
 * see usage in io_buf_alloc
 * size - data size, sizeof(io_buf_t) is NOT included!!!
 */
static inline io_buf_p
io_buf_init(io_buf_p io_buf, uint32_t flags, uint8_t *data, size_t size) {

	if (NULL == io_buf)
		return (io_buf);

	if (0 != (flags & IO_BUF_F_DATA_SHARED)) {
		io_buf->data = (uint8_t*)(io_buf + 1);
	} else {
		io_buf->data = data;
	}
	io_buf->size = size;
	IO_BUF_MARK_AS_EMPTY(io_buf);
	io_buf->flags = (flags & ~IO_BUF_F_ALLOC_BUF__INT);

	return (io_buf);
}

static inline io_buf_p
io_buf_alloc(uint32_t flags, size_t size) {
	io_buf_p io_buf;
	uint8_t *data = NULL;
	
	if (IO_BUF_FLAGS_BAD_MASK == (flags & IO_BUF_FLAGS_BAD_MASK))
		return (NULL);

	if (0 != (flags & IO_BUF_F_DATA_SHARED)) {
		io_buf = malloc((sizeof(io_buf_t) + size + sizeof(uint32_t)));
		if (NULL == io_buf)
			return (NULL);
	} else {
		io_buf = malloc(sizeof(io_buf_t));
		if (NULL == io_buf)
			return (NULL);
		if (0 != (flags & IO_BUF_F_DATA_ALLOC) &&
		    0 != size) {
			data = malloc((size + sizeof(uint32_t)));
			if (NULL == data) {
				free(io_buf);
				return (NULL);
			}
		} else {
			size = 0;
		}
	}

	io_buf_init(io_buf, flags, data, size);
	io_buf_sign_set__int(io_buf);
	io_buf->flags |= IO_BUF_F_ALLOC_BUF__INT;

	return (io_buf);
}

static inline int
io_buf_realloc(io_buf_p *pio_buf, uint32_t flags, size_t size) {
	io_buf_p io_buf;
	uint8_t *data;

	if (NULL == pio_buf)
		return (EINVAL);
	if (NULL == (*pio_buf)) { /* alloc. */
		if (IO_BUF_FLAGS_BAD_MASK == (flags & IO_BUF_FLAGS_BAD_MASK))
			return (EINVAL);
		(*pio_buf) = io_buf_alloc(flags, size);
		if (NULL == (*pio_buf))
			return (errno);
		return (0);
	}
	/* realloc. */
	if ((0 != (IO_BUF_F_DATA_SHARED & (*pio_buf)->flags) && /* io_buf and data in unmanaged mem. */
	    0 == (IO_BUF_F_ALLOC_BUF__INT & (*pio_buf)->flags)) &&
	    0 == (IO_BUF_F_DATA_ALLOC & (*pio_buf)->flags)) /* unmanaged ext buf. */
		return (EINVAL);
		
	io_buf_sign_check__int((*pio_buf));

	if (0 != (IO_BUF_F_DATA_SHARED & (*pio_buf)->flags)) {
		io_buf = realloc((*pio_buf), (sizeof(io_buf_t) + size + sizeof(uint32_t)));
		if (NULL == io_buf)
			return (ENOMEM);
		(*pio_buf) = io_buf;
		io_buf->data = (uint8_t*)(io_buf + 1);
	} else { /* IO_BUF_F_DATA_ALLOC */
		io_buf = (*pio_buf);
		data = realloc(io_buf->data, (size + sizeof(uint32_t)));
		if (NULL == data)
			return (ENOMEM);
		io_buf->data = data;
	}
	io_buf->size = size;
	io_buf_sign_set__int(io_buf);
	if (io_buf->used > size) {
		io_buf->used = size;
	}
	if (io_buf->offset > size) {
		io_buf->offset = size;
	}
	if (io_buf->transfer_size > io_buf->used) {
		io_buf->transfer_size = io_buf->used;
	}
	return (0);
}

static inline void
io_buf_free(io_buf_p io_buf) {

	if (NULL == io_buf)
		return;
	io_buf_sign_check__int(io_buf);
	if (0 != (IO_BUF_F_DATA_ALLOC & io_buf->flags)) {
		free(io_buf->data);
		io_buf->data = NULL;
		io_buf->size = 0;
		IO_BUF_MARK_AS_EMPTY(io_buf);
	}
	if (0 != (IO_BUF_F_ALLOC_BUF__INT & io_buf->flags)) {
		free(io_buf);
	}
}

#define IO_BUF_PRINTF(__iobuf, __fmt, __args...)			\
	    IO_BUF_USED_INC((__iobuf),					\
		snprintf((char*)IO_BUF_FREE_GET((__iobuf)),		\
		    IO_BUF_FREE_SIZE((__iobuf)), (__fmt), ##__args))

static inline int
io_buf_copy_buf(io_buf_p dst, io_buf_p src) {

	if (dst == src)
		return (0); /* Not copyed, but OK. */
	if (NULL == dst || NULL == src)
		return (EINVAL);
	if (dst->size < src->used)
		return (ENOBUFS);
	memcpy(dst->data, src->data, src->used);
	//dst->size = src->size;
	dst->used = src->used;
	dst->offset = src->offset;
	dst->transfer_size = src->transfer_size;
	return (0);
}

static inline int
io_buf_copyin(io_buf_p io_buf, const void *data, size_t data_size) {

	if (0 == data_size)
		return (0); /* Not copyed, but OK. */
	if (NULL == io_buf || NULL == data)
		return (EINVAL);
	if (IO_BUF_FREE_SIZE(io_buf) < data_size)
		return (ENOBUFS);
	memcpy(IO_BUF_FREE_GET(io_buf), data, data_size);
	IO_BUF_USED_INC(io_buf, data_size);
	return (0);
}
static inline int
io_buf_copyin_buf(io_buf_p dst, io_buf_p src) {

	if (dst == src)
		return (0); /* Not copyed, but OK. */
	if (NULL == src)
		return (EINVAL);
	return (io_buf_copyin(dst, src->data, src->used));
}
/* Copy constant/hardcoded string to buf. */
#define IO_BUF_COPYIN_CSTR(__iobuf, __str)				\
	    io_buf_copyin((__iobuf), __str, (sizeof(__str) - 1))
#define IO_BUF_COPYIN_CRLF(__iobuf)					\
	    io_buf_copyin((__iobuf), "\r\n", 2)
#define IO_BUF_COPYIN_CRLFCRLF(__iobuf)					\
	    io_buf_copyin((__iobuf), "\r\n\r\n", 4)


#endif /* __CORE_IO_BUF_H__ */
