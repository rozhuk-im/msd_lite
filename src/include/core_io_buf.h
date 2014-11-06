/*-
 * Copyright (c) 2011 - 2014 Rozhuk Ivan <rozhuk.im@gmail.com>
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
} io_buf_t, *io_buf_p;


#define IO_BUF_OFFSET_SIZE(iobuf)	((iobuf)->size - (iobuf)->offset)
#define IO_BUF_OFFSET_GET(iobuf)	((iobuf)->data + (iobuf)->offset)
#define IO_BUF_FREE_SIZE(iobuf)		((iobuf)->size - (iobuf)->used)
#define IO_BUF_FREE_GET(iobuf)		((iobuf)->data + (iobuf)->used)


/*
 * Macros for increment/decrement value
 * increment in range up to "max"
 * decrement in range down to zero
 */
#define IO_BUF_VALUE_IN_RANGE_INC(value, max, inc_size)				\
do {										\
	if (max > value && (max - value) > (inc_size)) /* Prevent owerflow. */	\
		value += (inc_size);						\
	else									\
		value = max;							\
} while (0)

#define IO_BUF_VALUE_IN_RANGE_DEC(value, dec_size)				\
do {										\
	if (value > (dec_size))							\
		value -= (dec_size);						\
	else									\
		value = 0;							\
} while (0)


/*
 * Macros for increment/decrement io_buf feilds
 * increment in range up to "buf->size"
 * decrement in range down to zero
 */
#define IO_BUF_USED_INC(iobuf, inc_size)					\
    IO_BUF_VALUE_IN_RANGE_INC((iobuf)->used, (iobuf)->size, (size_t)(inc_size))
#define IO_BUF_USED_DEC(iobuf, dec_size)					\
    IO_BUF_VALUE_IN_RANGE_DEC((iobuf)->used, (size_t)(dec_size))

#define IO_BUF_OFFSET_INC(iobuf, inc_size)					\
    IO_BUF_VALUE_IN_RANGE_INC((iobuf)->offset, (iobuf)->size, (size_t)(inc_size))
#define IO_BUF_OFFSET_DEC(iobuf, dec_size)					\
    IO_BUF_VALUE_IN_RANGE_DEC((iobuf)->offset, (size_t)(dec_size))

#define IO_BUF_TR_SIZE_GET(iobuf)	((iobuf)->transfer_size)
#define IO_BUF_TR_SIZE_SET(iobuf, size)	(iobuf)->transfer_size = (size)
#define IO_BUF_TR_SIZE_INC(iobuf, inc_size)					\
    IO_BUF_VALUE_IN_RANGE_INC((iobuf)->transfer_size, (iobuf)->size, (size_t)(inc_size))
#define IO_BUF_TR_SIZE_DEC(iobuf, dec_size)					\
    IO_BUF_VALUE_IN_RANGE_DEC((iobuf)->transfer_size, (size_t)(dec_size))



#define IO_BUF_BUSY_SIZE_SET(iobuf, size)					\
do {										\
	(iobuf)->used = (size);							\
	(iobuf)->offset = (size);						\
} while (0)

#define IO_BUF_MARK_TRANSFER_ALL_USED(iobuf)					\
do {										\
	(iobuf)->offset = 0;							\
	(iobuf)->transfer_size = (iobuf)->used;					\
} while (0)

#define IO_BUF_MARK_TRANSFER_ALL_FREE(iobuf)					\
do {										\
	(iobuf)->offset = (iobuf)->used;					\
	(iobuf)->transfer_size = IO_BUF_FREE_SIZE((iobuf));			\
} while (0)

#define IO_BUF_MARK_AS_EMPTY(iobuf)						\
do {										\
	(iobuf)->used = 0;							\
	(iobuf)->offset = 0;							\
	(iobuf)->transfer_size = 0;						\
} while (0)



// warning!
// see usage in io_buf_alloc
// size - data size, sizeof(io_buf_t) is NOT included!!!
static inline io_buf_p
io_buf_init_mem(io_buf_p io_buf, size_t size) {

	if (NULL == io_buf)
		return (io_buf);

	io_buf->data = (uint8_t*)(io_buf + 1);
	io_buf->size = size;
	IO_BUF_MARK_AS_EMPTY(io_buf);

	return (io_buf);
}

static inline io_buf_p
io_buf_alloc(size_t size) {
	io_buf_p io_buf;

	io_buf = malloc((sizeof(io_buf_t) + size + sizeof(void*)));
	return (io_buf_init_mem(io_buf, size));
}

static inline int
io_buf_realloc(io_buf_p *pio_buf, size_t size) {
	io_buf_p io_buf;

	if (NULL == pio_buf)
		return (EINVAL);
	io_buf = realloc((*pio_buf), (sizeof(io_buf_t) + size + sizeof(void*)));
	if (NULL == io_buf)
		return (ENOMEM);
	io_buf->data = (uint8_t*)(io_buf + 1);
	io_buf->size = size;
	if (NULL == (*pio_buf)) {
		IO_BUF_MARK_AS_EMPTY(io_buf);
	} else {
		if (io_buf->used > size)
			io_buf->used = size;
		if (io_buf->offset > size)
			io_buf->offset = size;
		if (io_buf->transfer_size > io_buf->used)
			io_buf->transfer_size = io_buf->used;
	}
	(*pio_buf) = io_buf;
	return (0);
}

static inline void
io_buf_free(io_buf_p io_buf) {

	if (NULL == io_buf)
		return;
	free(io_buf);
}

static inline int
io_buf_copyin_buf(io_buf_p dst, io_buf_p src) {

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

#define IO_BUF_PRINTF(io_buf, fmt, args...)					\
	    IO_BUF_USED_INC((io_buf),						\
		snprintf((char*)IO_BUF_FREE_GET((io_buf)),			\
		    IO_BUF_FREE_SIZE((io_buf)), (fmt), ##args))

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
/* Copy constant/hardcoded string to buf. */
#define IO_BUF_COPYIN_CSTR(io_buf, str)						\
	    io_buf_copyin((io_buf), str, (sizeof(str) - 1))

#define IO_BUF_COPYIN_CRLF(io_buf)						\
	    io_buf_copyin((io_buf), "\r\n", 2)
#define IO_BUF_COPYIN_CRLFCRLF(io_buf)						\
	    io_buf_copyin((io_buf), "\r\n\r\n", 4)


#endif /* __CORE_IO_BUF_H__ */
