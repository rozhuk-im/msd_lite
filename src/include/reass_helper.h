/*-
 * Copyright (c) 2016 Rozhuk Ivan <rim@vedapro.ru>
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
 *
 */

#ifndef __REASSEMBLE_HELPER_H__
#define __REASSEMBLE_HELPER_H__


#ifndef _WINDOWS
#	include <sys/param.h>
#	ifndef BSD
#		define _GNU_SOURCE /* See feature_test_macros(7) */
#		define __USE_GNU 1
#	endif
#	include <sys/types.h>
#	ifdef _KERNEL
#		include <sys/systm.h>
#	else
#		include <string.h> /* memcpy, memmove, memset... */
#		include <inttypes.h>
#	endif
#else
#	include <stdlib.h>
#	define uint8_t		unsigned char
#	define uint64_t		DWORDLONG
#	define size_t		SIZE_T
#	define EINVAL		ERROR_INVALID_PARAMETER
#	define EBADMSG		ERROR_INVALID_DATA
#	define ENOBUFS		ERROR_INSUFFICIENT_BUFFER
#endif


#ifndef UINT64_T_MAX
#	define UINT64_T_MAX	((uint64_t)~0)
#endif
#ifndef SIZE_T_MAX
#	define SIZE_T_MAX	((size_t)~0)
#endif

#define REASS_HLP_GET_BIT(__buf, __bit)	(((((uint8_t*)(__buf))[((__bit) >> 3)] >> ((__bit) & 0x07))) & 0x01)
#define REASS_HLP_SET_BIT(__buf, __bit)	((uint8_t*)(__buf))[((__bit) >> 3)] |= (((uint8_t)1) << ((__bit) & 0x07))


/* Fragmet reasseble buf + data. */
typedef struct reasseble_helper_s {
	uint8_t		*buf;
	size_t		buf_size; /* Buffer size. */
	uint8_t		*bitmap;
	size_t		bitmap_size; /* Buffer size. */
	size_t		blk_size; /* Block size, from first block. */
	size_t		blk_cnt; /* Received blocks count. */
	size_t		recv_cnt; /* Received bytes count. */
	size_t		sequence_size; /* Sequence size calculated by last fragment. */
	size_t		dup_cnt; /* Duplicate packets count. */
	size_t		reorders_cnt; /* Packets reorder count. */
	uint64_t	first_seq_no; /* Sequence number, from first block. */
	uint64_t	last_seq_no; /* Sequence number, from last block. */
	uint64_t	cur_seq_no; /* Sequence number, from last received block. */
} reass_hlp_t, *reass_hlp_p;



/* Fragmet reasseble buf functions. */
static inline void
reass_hlp_reset(reass_hlp_p reass_hlp) {

	if (NULL == reass_hlp) {
		return;
	}
	reass_hlp->recv_cnt = 0;
	reass_hlp->blk_cnt = 0;
	reass_hlp->blk_size = 0;
	reass_hlp->sequence_size = 0;
	reass_hlp->dup_cnt = 0;
	reass_hlp->reorders_cnt = 0;
	reass_hlp->first_seq_no = 0;
	reass_hlp->last_seq_no = 0;
	if (NULL != reass_hlp->bitmap) { /* Init bitmap. */
		memset(reass_hlp->bitmap, 0, reass_hlp->bitmap_size);
	}
}

static inline int
reass_hlp_init(reass_hlp_p reass_hlp, void *buf, size_t buf_size,
    uint8_t *bitmap, size_t bitmap_size) {

	if (NULL == reass_hlp || NULL == buf || 0 == buf_size) {
		return (EINVAL);
	}
	reass_hlp->buf = buf;
	reass_hlp->buf_size = buf_size;
	reass_hlp->bitmap = bitmap;
	reass_hlp->bitmap_size = bitmap_size;
	reass_hlp_reset(reass_hlp);

	return (0);
}

static inline void
reass_hlp_free(reass_hlp_p reass_hlp) {

	if (NULL == reass_hlp) {
		return;
	}
	free(reass_hlp);
}

static inline reass_hlp_p
reass_hlp_alloc(size_t buf_size, size_t min_frag_size) {
	reass_hlp_p reass_hlp;
	size_t bitmap_size;

	if (0 == min_frag_size) {
		min_frag_size ++;
	}
	buf_size += 128; /* Guard space. */
	bitmap_size = ((buf_size / min_frag_size) + 128);
	reass_hlp = malloc((sizeof(reass_hlp_t) + buf_size + bitmap_size));
	if (NULL == reass_hlp)
		return (NULL);
	reass_hlp->buf = (uint8_t*)(reass_hlp + 1);
	reass_hlp->buf_size = buf_size;
	reass_hlp->bitmap = (reass_hlp->buf + buf_size);
	reass_hlp->bitmap_size = bitmap_size;
	reass_hlp_reset(reass_hlp);

	return (reass_hlp);
}



static inline size_t
reass_hlp_seq_calc_diff(uint64_t first_seq_no, uint64_t last_seq_no) {

	if (last_seq_no >= first_seq_no) {
		last_seq_no -= first_seq_no;
	} else { /* Seq num overflow. */
		last_seq_no += (UINT64_T_MAX - first_seq_no);
	}
	if (SIZE_T_MAX < last_seq_no)
		return (SIZE_T_MAX); /* sizeof(uint64_t) > sizeof(size_t) */
	return (last_seq_no);
}

static inline int
reass_hlp_handle_frag(reass_hlp_p reass_hlp, uint64_t seq_no, int is_first,
    int is_last, void *data, size_t data_size) {
	size_t blk_idx, offset;

	if (NULL == reass_hlp || (NULL == data && 0 != data_size)) {
		return (EINVAL);
	}
	if (is_first) { /* Reset on first packet or do it by hand before and never set this flag. */
		if (0 == data_size) {
			return (EINVAL); /* Bad block size. */
		}
		reass_hlp_reset(reass_hlp);
		reass_hlp->blk_size = data_size;
		reass_hlp->first_seq_no = seq_no;
		if (NULL != reass_hlp->bitmap) {
			if ((reass_hlp->buf_size / reass_hlp->blk_size) > (reass_hlp->bitmap_size * 8)) {
				return (ENOBUFS); /* Not enought bitmap space. */
			}
		}
	} else {
		if (0 == is_last && reass_hlp->blk_size != data_size) {
			return (EINVAL); /* Fragment size is wierd and it is not last frag. */
		}
		if ((reass_hlp->cur_seq_no + 1) != seq_no) { /* Sequence not OK. */
			reass_hlp->reorders_cnt ++;
		}
	}
	/* Prepare: calc block index and offset. */
	blk_idx = reass_hlp_seq_calc_diff(reass_hlp->first_seq_no, seq_no);
	offset = (blk_idx * reass_hlp->blk_size);
	/* Check for mult overflow. */
	if (((blk_idx | reass_hlp->blk_size) & (SIZE_T_MAX << (sizeof(size_t) * 4))) &&
	    (offset / reass_hlp->blk_size) != blk_idx) {
		return (EINVAL); /* size_t overflow. */
	}
	/* Check: in buf range. */
	if ((offset + data_size) > reass_hlp->buf_size) {
		return (EINVAL); /* Not enought buf space, assume that it is frag with bad seqno. */
	}
	/* Check by bitmap: is block already received? */
	if (NULL != reass_hlp->bitmap) { /* Using bitmap. */
		if (reass_hlp->bitmap_size <= blk_idx)
			return (ERANGE);
		if (0 != REASS_HLP_GET_BIT(reass_hlp->bitmap, blk_idx)) {
			reass_hlp->dup_cnt ++;
			return (EAGAIN); /* Fragment already received / dup detected. */
		}
		/* Update bitmap. */
		REASS_HLP_SET_BIT(reass_hlp->bitmap, blk_idx);
	}
	/* Add new data. */
	if (is_last && 0 == reass_hlp->sequence_size) {
		reass_hlp->sequence_size = (offset + data_size); /* Cant be zero, so use as marker that last frag received. */
		reass_hlp->last_seq_no = seq_no;
		if (reass_hlp->sequence_size > reass_hlp->buf_size) {
			return (ENOBUFS); /* Not enought buf space, realloc() required. */
		}
	}
	memcpy((reass_hlp->buf + offset), data, data_size);
	reass_hlp->recv_cnt += data_size;
	reass_hlp->blk_cnt ++;
	reass_hlp->cur_seq_no = seq_no;

	if (0 == reass_hlp->sequence_size || /* We dont know sequence size, no last frag received. */
	    (reass_hlp_seq_calc_diff(reass_hlp->first_seq_no, reass_hlp->last_seq_no) + 1) > reass_hlp->blk_cnt) {
		return (EAGAIN); /* Require more data. */
	}
	if (reass_hlp->sequence_size != reass_hlp->recv_cnt) { /* Is all OK? */
		return (EBADMSG); /* Lost some fragments/data? */
	}
	return (0); /* All fragments received!. */
}


#endif /* __REASSEMBLE_HELPER_H__ */
