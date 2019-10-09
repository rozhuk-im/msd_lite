/*-
 * Copyright (c) 2012 - 2016 Rozhuk Ivan <rozhuk.im@gmail.com>
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

/*
 * Ring buffer
 * single writer, multiple readers
 * 
 */


#include <sys/param.h>

#ifdef __linux__ /* Linux specific code. */
#	define _GNU_SOURCE /* See feature_test_macros(7) */
#	define __USE_GNU 1
#endif /* Linux specific code. */

#include <sys/types.h>

#include <inttypes.h>
#include <stdlib.h> /* malloc, exit */
#include <unistd.h> /* close, write, sysconf */
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <errno.h>

#include "macro_helpers.h"
#include "mem_helpers.h"
#include "core_net_helpers.h"
#ifdef DEBUG
#include "core_log.h"
#endif
#include "core_r_buf.h"


size_t		iovec_aggregate_ex(iovec_p iov, size_t iov_cnt, size_t data_size,
		    size_t off, iovec_p ret, size_t ret_cnt,
		    size_t *reminder_data_size_ret);
int		r_buf_rpos_check(r_buf_p r_buf, r_buf_rpos_p rpos, size_t *drop_size);



static inline size_t
r_buf_iovec_calc_size(iovec_p iov, size_t iov_cnt) {
	register size_t i, ret = 0;

	for (i = 0; i < iov_cnt; i ++) {
		ret += iov[i].iov_len;
	}
	return (ret);
}

static inline int
r_buf_rpos_index_inc(r_buf_p r_buf, r_buf_rpos_p rpos) {

	if (rpos->round_num == r_buf->round_num) {
		if (rpos->iov_index > r_buf->iov_index)
			return (0);
		rpos->iov_index ++;
		return (1);
	}
	/* Assume: rpos->round_num == (r_buf->round_num - 1) */
	rpos->iov_index ++;
	if (rpos->iov_index > r_buf->iov_index_max) {
		rpos->iov_index = 0;
		rpos->round_num = r_buf->round_num;
	}
	return (1);
}


size_t
iovec_aggregate_ex(iovec_p iov, size_t iov_cnt, size_t data_size, size_t off,
    iovec_p ret, size_t ret_cnt, size_t *reminder_data_size_ret) {
	register size_t i, j = 0;

	/* Do not send packet fragment as last packet in buf. */
	if (0 == iov_cnt || 0 == ret_cnt || 0 == data_size ||
	    (iov[0].iov_len - off) >= data_size ||
	    (1 == iov_cnt && 0 == (iov[0].iov_len - off))) {
		if (NULL != reminder_data_size_ret) {
			(*reminder_data_size_ret) = 0;
		}
		return (0);
	}
	ret_cnt --;
	ret[0].iov_base = (iov[0].iov_base + off);
	ret[0].iov_len = (iov[0].iov_len - off);
	data_size -= ret[0].iov_len;
	for (i = 1; i < iov_cnt && j < ret_cnt && data_size >= iov[i].iov_len; i ++) {
		data_size -= iov[i].iov_len;
		if ((iov[(i - 1)].iov_base + iov[(i - 1)].iov_len) ==
		    iov[i].iov_base) { /* Split together. */
			ret[j].iov_len += iov[i].iov_len;
		} else { /* Next region. */
			j ++;
			ret[j] = iov[i];
		}
	}
	if (NULL != reminder_data_size_ret) {
		(*reminder_data_size_ret) = data_size;
	}
	return ((j + 1));
}


int
r_buf_rpos_cmp(r_buf_rpos_p rpos1, r_buf_rpos_p rpos2) {

	if (rpos1 == rpos2)
		return (0);
	if (NULL == rpos1)
		return (-127);
	if (NULL == rpos2)
		return (127);

	if (rpos1->round_num == rpos2->round_num) {
		if (rpos1->iov_index == rpos2->iov_index) {
			if (rpos1->iov_off == rpos2->iov_off)
				return (0);
			if (rpos1->iov_off > rpos2->iov_off)
				return (1);
			return (-1); /* rpos1->iov_off < rpos2->iov_off */
		}
		if (rpos1->iov_index > rpos2->iov_index)
			return (1);
		return (-1); /* rpos1->iov_index < rpos2->iov_index */
	}
	if (rpos1->round_num > rpos2->round_num)
		return (1);
	return (-1); /* rpos1->round_num < rpos2->round_num */
}

size_t
r_buf_rpos_calc_size(r_buf_p r_buf, r_buf_rpos_p rpos1, r_buf_rpos_p rpos2) {
	size_t ret;
	r_buf_rpos_p rpos_lo = NULL, rpos_hi = NULL;

	if (NULL == r_buf || NULL == rpos1 || NULL == rpos2)
		return (0);
	if (0 == r_buf_rpos_check_fast(r_buf, rpos1) ||
	    0 == r_buf_rpos_check_fast(r_buf, rpos2))
		return (0);

	switch (r_buf_rpos_cmp(rpos1, rpos2)) {
	case 0:
		return (0);
	case -1:
		rpos_lo = rpos1;
		rpos_hi = rpos2;
		break;
	case 1:
		rpos_lo = rpos2;
		rpos_hi = rpos1;
		break;
	}

	if (rpos_lo->round_num == rpos_hi->round_num) {
		if (rpos_lo->iov_index == rpos_hi->iov_index) /* Optimized size calculation. */
			return (0);
		if (RBUF_F_FRAG & r_buf->flags) {
			ret = r_buf_iovec_calc_size(&r_buf->iov[rpos_lo->iov_index],
			    (1 + rpos_hi->iov_index - rpos_lo->iov_index));
		} else { /* Optimized size calculation. */
			ret = (size_t)((r_buf->iov[rpos_hi->iov_index].iov_base +
			    r_buf->iov[rpos_hi->iov_index].iov_len) -
			    r_buf->iov[rpos_lo->iov_index].iov_base);
		}
	} else {
		if (RBUF_F_FRAG & r_buf->flags) {
			ret = r_buf_iovec_calc_size(&r_buf->iov[rpos_lo->iov_index],
			    (1 + r_buf->iov_index_max - rpos_lo->iov_index));
			ret += r_buf_iovec_calc_size(r_buf->iov, (1 + rpos_hi->iov_index));
		} else { /* Optimized size calculation. */
			ret = (size_t)((r_buf->iov[r_buf->iov_index_max].iov_base +
			    r_buf->iov[r_buf->iov_index_max].iov_len) -
			    r_buf->iov[rpos_lo->iov_index].iov_base);
			ret += (size_t)((r_buf->iov[rpos_hi->iov_index].iov_base +
			    r_buf->iov[rpos_hi->iov_index].iov_len) -
			    r_buf->buf);
		}
	}

	return (ret);
}


int
r_buf_rpos_init(r_buf_p r_buf, r_buf_rpos_p rpos, size_t data_size) {

	if (NULL == r_buf || NULL == rpos)
		return (EINVAL);
	rpos->iov_off = 0;
	rpos->iov_index = (r_buf->iov_index + 1);
	rpos->round_num = r_buf->round_num;
	
	while (rpos->iov_index > 0 &&
	    data_size >= r_buf->iov[rpos->iov_index].iov_len) {
		data_size -= r_buf->iov[rpos->iov_index].iov_len;
		rpos->iov_index --;
	}
	if (data_size <= r_buf->iov[rpos->iov_index].iov_len ||
	    0 == (RBUF_F_FULL & r_buf->flags))
		return (0);
	rpos->iov_index = r_buf->iov_index_max;
	rpos->round_num --;
	while (rpos->iov_index > r_buf->iov_index &&
	    data_size >= r_buf->iov[rpos->iov_index].iov_len) {
		data_size -= r_buf->iov[rpos->iov_index].iov_len;
		rpos->iov_index --;
	}

	return (0);
}

int
r_buf_rpos_init_near(r_buf_p r_buf, r_buf_rpos_p rpos, size_t data_size,
    r_buf_rpos_p rposs, size_t rposs_cnt) {
	int error, cmp;
	size_t i, dsize_lo, dsize_hi;
	
	if (1 == rposs_cnt) {
		memcpy(rpos, &rposs[0], sizeof(r_buf_rpos_t));
		return (0);
	}
	error = r_buf_rpos_init(r_buf, rpos, data_size);
	if (0 != error ||
	    0 == rposs_cnt) /* No error in this case. */
		return (error);

	for (i = 1; i < rposs_cnt; i ++) {
		cmp = r_buf_rpos_cmp(rpos, &rposs[i]);
		if (0 == cmp)
			return (0); /* No need to find near index. */
		if (0 > cmp)
			break;
	}
	/* Select nearest index. */
	dsize_lo = (data_size - r_buf_data_avail_size(r_buf, &rposs[(i - 1)], NULL));
	dsize_hi = (r_buf_data_avail_size(r_buf, &rposs[i], NULL) - data_size);
	if (dsize_lo < dsize_hi) {
		memcpy(rpos, &rposs[(i - 1)], sizeof(r_buf_rpos_t));
	} else {
		memcpy(rpos, &rposs[i], sizeof(r_buf_rpos_t));
	}

	return (0);
}

int
r_buf_rpos_check_fast(r_buf_p r_buf, r_buf_rpos_p rpos) {

	/* Reader at current round, ckecks. */
	if (rpos->round_num == r_buf->round_num) {
		if (rpos->iov_index <= (r_buf->iov_index + 1)) /* See: r_buf_rpos_index_inc() */
			return (1); /* OK: in range. */
		/* rpos > wpos */
		return (0); /* No data to read, no dropped. */
	}
	/* Reader at pevious round, ckecks. */
	if (((size_t)(rpos->round_num + 1)) == r_buf->round_num) {
		/* (rpos->round_num + 1) == 0 in some cases! */
		if (rpos->iov_index > r_buf->iov_index_max) {
			/* Reader out of buf range in previous round - normal. */
			return (1); /* OK: fixed. */
		}
		if (rpos->iov_index > r_buf->iov_index)
			return (1); /* OK: in range. */
		/* Out of range: slow reader. */
		return (0);
	}
	/* Some data lost for this receiver. */
	return (0);
}
int
r_buf_rpos_check(r_buf_p r_buf, r_buf_rpos_p rpos, size_t *drop_size_ret) {
	size_t drop_size;

	/* Paranoid check. */
	if (r_buf->iov[rpos->iov_index].iov_len <= rpos->iov_off) {
		rpos->iov_off = 0;
	}
	/* Reader at current round, ckecks. */
	if (rpos->round_num == r_buf->round_num) {
		if (rpos->iov_index <= (r_buf->iov_index + 1)) /* See: r_buf_rpos_index_inc() */
			return (1); /* OK: in range. */
		/* rpos > wpos */
		rpos->iov_off = 0;
		rpos->iov_index = (r_buf->iov_index + 1);
		if (NULL != drop_size_ret) {
			(*drop_size_ret) = 0;
		}
		return (0); /* No data to read, no dropped. */
	}
	/* Reader at pevious round, ckecks. */
	if (((size_t)(rpos->round_num + 1)) == r_buf->round_num) {
		/* (rpos->round_num + 1) == 0 in some cases! */
		if (rpos->iov_index > r_buf->iov_index_max) {
			/* Reader out of buf range in previous round - normal. */
			rpos->iov_off = 0;
			rpos->iov_index = 0;
			rpos->round_num ++;
			return (1); /* OK: fixed. */
		}
		if (rpos->iov_index > r_buf->iov_index)
			return (1); /* OK: in range. */
		/* Out of range: slow reader. */
		drop_size = (r_buf->size + r_buf_iovec_calc_size(&r_buf->iov[rpos->iov_index],
		    (1 + r_buf->iov_index - rpos->iov_index)));
		if (NULL != drop_size_ret) {
			(*drop_size_ret) = drop_size;
		}
		return (0);
	}
	/* Some data lost for this receiver. */
	//if (rpos->iov_index <= r_buf->iov_index ||
	//    (r_buf->round_num - rpos->round_num) > 1) {
		//LOGD_EV_FMT("AHTUNG 3 - user lost data / to slow receiver!!!");
	//}
	//LOGD_EV_FMT("rbuf: rn = %i, index = %i; rpos: rn = %i, index = %i",
	//    r_buf->round_num, r_buf->iov_index, rpos->round_num, rpos->iov_index);

	/* Calc dropped size. */
	if (((size_t)(rpos->round_num + 1)) >= r_buf->round_num) { /* rpos > wpos */
		drop_size = 0;
	} else { /* rpos << wpos: wery slow reader. */
		drop_size = (r_buf->size * (r_buf->round_num - rpos->round_num));
	}
	rpos->iov_off = 0;
	rpos->iov_index = (r_buf->iov_index + 1);
	rpos->round_num = r_buf->round_num;
	if (NULL != drop_size_ret) {
		(*drop_size_ret) = drop_size;
	}
	return (0);
}


r_buf_p
r_buf_alloc(uintptr_t fd, size_t size, size_t min_block_size) {
	r_buf_p r_buf;
	size_t page_size;

	if (0 == size || 0 == min_block_size) /* Prevent division by zero. */
		return (NULL);
	r_buf = zalloc(sizeof(r_buf_t));
	if (NULL == r_buf)
		return (NULL);
	page_size = (size_t)sysconf(_SC_PAGE_SIZE);
	//r_buf->size = ALIGNEX((size + min_block_size), page_size); /* XXX: Minimum buf. */
	//while (r_buf->size > size)
	//	r_buf->size -= page_size;
	r_buf->size = size;
	//LOGD_EV_FMT("mapalloc_fd: size = %zu, r_buf->size = %zu", size, r_buf->size);
	r_buf->buf = mapalloc_fd(fd, r_buf->size);
	if (NULL == r_buf->buf) {
		//LOGD_ERR(errno, "mapalloc 1");
		goto err_out;
	}
	r_buf->iov_count = ((r_buf->size / min_block_size) + 32);
	r_buf->iov_size = ALIGNEX((sizeof(iovec_t) * r_buf->iov_count), page_size);
	r_buf->iov = mapalloc(r_buf->iov_size);
	if (NULL == r_buf->iov) {
		//LOGD_ERR(errno, "mapalloc 2");
		goto err_out;
	}
	//r_buf->iov_index = ~0; /* r_buf_wbuf_get() increment this, set to: -1. */
	r_buf->buf_max = (r_buf->buf + r_buf->size);
	r_buf->min_block_size = min_block_size;
	return (r_buf);

err_out:
	/* Error. */
	r_buf_free(r_buf);
	return (NULL);
}

void
r_buf_free(r_buf_p r_buf) {

	if (NULL == r_buf)
		return;
	if (NULL != r_buf->buf) {
		mapfree(r_buf->buf, r_buf->size);
	}
	if (NULL != r_buf->iov) {
		mapfree(r_buf->iov, r_buf->iov_size);
	}
	mem_filld(r_buf, sizeof(r_buf_t));
	free(r_buf);
}

#if 0
int
r_buf_wbuf_pos_inc(r_buf_p r_buf) {
	size_t buf_size; /* Avaible size. */

	if (NULL == r_buf)
		return (EINVAL);
	buf_size = (r_buf->size - r_buf->wpos);
	if (0 != r_buf->iov[r_buf->iov_index].iov_len) {
		r_buf->iov_index ++;
		r_buf->iov[r_buf->iov_index].iov_len = 0;
	}
	if (buf_size < min_buf_size || /* Not enough space at buf end. */
	    buf_size < r_buf->min_block_size /*||
	    r_buf->iov_count == r_buf->iov_index*/) { /* Paranoid check. */
		buf_size = r_buf->size;
		r_buf->wpos = 0;
		r_buf->iov_index_max = (r_buf->iov_index - 1);
		r_buf->iov_index = 0;
		r_buf->round_num ++;
		r_buf->flags |= RBUF_F_FULL;
		r_buf->iov[r_buf->iov_index].iov_len = 0;
	}
	r_buf->iov[r_buf->iov_index].iov_base = (r_buf->buf + r_buf->wpos);
	(*buf) = r_buf->iov[r_buf->iov_index].iov_base;
	return (buf_size);
}
#endif

/* Return pointer to buf and size avaible to write. */
size_t
r_buf_wbuf_get(r_buf_p r_buf, size_t min_buf_size, uint8_t **buf) {
	size_t buf_size; /* Avaible size. */

	if (NULL == r_buf)
		return (0);
	if (r_buf->size < min_buf_size) /* Paranoid check. */
		return (0); /* Not enough space. */
	buf_size = (r_buf->size - r_buf->wpos);
	if (0 != r_buf->iov[r_buf->iov_index].iov_len) {
		r_buf->iov_index ++;
		r_buf->iov[r_buf->iov_index].iov_len = 0;
	}
	if (buf_size < min_buf_size || /* Not enough space at buf end. */
	    buf_size < r_buf->min_block_size /*||
	    r_buf->iov_count == r_buf->iov_index*/) { /* Paranoid check. */
		buf_size = r_buf->size;
		r_buf->wpos = 0;
		r_buf->iov_index_max = (r_buf->iov_index - 1);
		r_buf->iov_index = 0;
		r_buf->round_num ++;
		r_buf->flags |= RBUF_F_FULL;
		r_buf->iov[r_buf->iov_index].iov_len = 0;
	}
	r_buf->iov[r_buf->iov_index].iov_base = (r_buf->buf + r_buf->wpos);
	(*buf) = r_buf->iov[r_buf->iov_index].iov_base;
	return (buf_size);
}

/* Set written data size and data offset for buf. */
int
r_buf_wbuf_set(r_buf_p r_buf, size_t offset, size_t buf_size) {
	size_t data_size; /* Data in buffer. */

	if (NULL == r_buf)
		return (EINVAL);
	/* Paranoid checks. */
	if (offset >= buf_size)
		return (EINVAL);
	data_size = (buf_size - offset);
	if (data_size < r_buf->min_block_size || /* Data to small. */
	    data_size > (r_buf->size - r_buf->wpos)) /* Not enough space. */
		return (EINVAL);
	r_buf->iov[r_buf->iov_index].iov_len = data_size;
	if (0 != offset) {
		r_buf->flags |= RBUF_F_FRAG;
		r_buf->iov[r_buf->iov_index].iov_base += offset;
	}
	r_buf->wpos += buf_size;
	r_buf->iov_index_max = max(r_buf->iov_index_max, r_buf->iov_index);
	return (0);
}

int
r_buf_wbuf_set2(r_buf_p r_buf, uint8_t *buf, size_t buf_size, r_buf_rpos_p rpos) {
	uint8_t *buf_end;

	if (NULL == r_buf || NULL == buf)
		return (EINVAL);
	/* Paranoid check. */
	if (buf_size < r_buf->min_block_size || /* Data to small. */
	    buf < r_buf->iov[r_buf->iov_index].iov_base) /* Invalid buf pointer. */
		return (EINVAL); /* Paranoid check. */
	buf_end = (buf + buf_size);
	if (buf_end > r_buf->buf_max) /* Invalid buf pointer. */
		return (EINVAL);
	if (buf != r_buf->iov[r_buf->iov_index].iov_base) {
		r_buf->flags |= RBUF_F_FRAG;
	}
	r_buf->iov[r_buf->iov_index].iov_base = buf;
	r_buf->iov[r_buf->iov_index].iov_len = buf_size;
	r_buf->wpos = (size_t)(buf_end - r_buf->buf);
	r_buf->iov_index_max = max(r_buf->iov_index_max, r_buf->iov_index);

	if (NULL != rpos) {
		rpos->iov_index = r_buf->iov_index;
		rpos->iov_off = 0;
		rpos->round_num = r_buf->round_num;
	}
	// XXX!!!
	r_buf->iov_index ++;
	r_buf->iov[r_buf->iov_index].iov_base = buf_end;
	r_buf->iov[r_buf->iov_index].iov_len = 0;
	return (0);
}

#if 0
int
r_buf_wbuf_set_ex(r_buf_p r_buf, iovec_p iov, size_t iov_cnt) {
	uint8_t *buf_end;

	/* Paranoid check. */
	if (buf_size < r_buf->min_block_size || /* Data to small. */
	    buf < r_buf->iov[r_buf->iov_index].iov_base) /* Invalid buf pointer. */
		return (EINVAL); /* Paranoid check. */
	buf_end = (buf + buf_size);
	if (buf_end > r_buf->buf_max) /* Invalid buf pointer. */
		return (EINVAL);
	if (buf != r_buf->iov[r_buf->iov_index].iov_base) {
		r_buf->flags |= RBUF_F_FRAG;
		LOGD_EV("AHTUNG 4 RBUF_F_FRAG!!!");
	}
	r_buf->iov[r_buf->iov_index].iov_base = buf;
	r_buf->iov[r_buf->iov_index].iov_len = buf_size;
	r_buf->wpos = (buf_end - r_buf->buf);
	r_buf->iov_index_max = max(r_buf->iov_index_max, r_buf->iov_index);

	// XXX!!!
	r_buf->iov_index ++;
	r_buf->iov[r_buf->iov_index].iov_base = buf_end;
	r_buf->iov[r_buf->iov_index].iov_len = 0;
	return (0);
}
#endif

size_t
r_buf_data_avail_size(r_buf_p r_buf, r_buf_rpos_p rpos, size_t *drop_size_ret) {
	size_t ret;

	if (NULL == r_buf || NULL == rpos)
		return (0);
	if (0 == r_buf_rpos_check(r_buf, rpos, drop_size_ret))
		return (0);
	if (rpos->round_num == r_buf->round_num) {
		if (rpos->iov_index == (r_buf->iov_index + 1)) { /* Optimized size calculation. */
			ret = 0;
			goto return_ok;
		}
		if (RBUF_F_FRAG & r_buf->flags) {
			ret = r_buf_iovec_calc_size(&r_buf->iov[rpos->iov_index],
			    (1 + r_buf->iov_index - rpos->iov_index));
		} else { /* Optimized size calculation. */
			ret = (size_t)(r_buf->wpos -
			    (size_t)(r_buf->iov[rpos->iov_index].iov_base - r_buf->buf));
		}
	} else {
		if (RBUF_F_FRAG & r_buf->flags) {
			ret = r_buf_iovec_calc_size(&r_buf->iov[rpos->iov_index],
			    (1 + r_buf->iov_index_max - rpos->iov_index));
			ret += r_buf_iovec_calc_size(r_buf->iov, (1 + r_buf->iov_index));
		} else { /* Optimized size calculation. */
			ret = (size_t)((r_buf->iov[r_buf->iov_index_max].iov_base +
			    r_buf->iov[r_buf->iov_index_max].iov_len) -
			    r_buf->iov[rpos->iov_index].iov_base);
			ret += r_buf->wpos;
		}
	}
	ret -= rpos->iov_off;
return_ok:
	if (NULL != drop_size_ret) {
		(*drop_size_ret) = 0;
	}
	return (ret);
}

size_t
r_buf_data_get(r_buf_p r_buf, r_buf_rpos_p rpos, size_t data_size,
    iovec_p iov, size_t iov_cnt, size_t *drop_size_ret, size_t *data_size_ret) {
	size_t ret = 0, tm;

	if (NULL == r_buf || NULL == rpos || 0 == data_size ||
	    NULL == iov || 0 == iov_cnt ||
	    0 == r_buf_rpos_check(r_buf, rpos, drop_size_ret)) {
		if (NULL != data_size_ret)
			(*data_size_ret) = 0;
		return (ret);
	}
	if (rpos->round_num == r_buf->round_num) {
		/* Optimized size calculation. */
		if (rpos->iov_index == (r_buf->iov_index + 1)) {
			tm = data_size;
			goto return_ok;
		}
		ret = iovec_aggregate_ex(&r_buf->iov[rpos->iov_index],
		    (1 + r_buf->iov_index - rpos->iov_index), data_size,
		    rpos->iov_off, iov, iov_cnt, &tm);
	} else {
		ret = iovec_aggregate_ex(&r_buf->iov[rpos->iov_index],
		    (1 + r_buf->iov_index_max - rpos->iov_index), data_size,
		    rpos->iov_off, iov, iov_cnt, &tm);
		ret += iovec_aggregate_ex(r_buf->iov, (1 + r_buf->iov_index),
		    tm, 0, &iov[ret], (iov_cnt - ret), &tm);
	}
return_ok:
	if (NULL != drop_size_ret) {
		(*drop_size_ret) = 0;
	}
	if (NULL != data_size_ret) {
		(*data_size_ret) = (data_size - tm);
	}
	return (ret);
}

int
r_buf_data_get_conv2off(r_buf_p r_buf, iovec_p iov, size_t iov_cnt) {
	size_t i;

	if (NULL == r_buf)
		return (EINVAL);
	if (NULL == iov || 0 == iov_cnt)
		return (0);

	for (i = 0; i < iov_cnt; i ++) {
		iov[i].iov_base -= (size_t)r_buf->buf;
	}

	return (0);
}

void
r_buf_rpos_inc(r_buf_p r_buf, r_buf_rpos_p rpos, size_t data_size) {

	if (NULL == r_buf || NULL == rpos || 0 == data_size)
		return;
	/* Process iov offset. */
	if (0 != rpos->iov_off) {
		if (data_size >= (r_buf->iov[rpos->iov_index].iov_len - rpos->iov_off)) {
			data_size -= (r_buf->iov[rpos->iov_index].iov_len - rpos->iov_off);
			rpos->iov_off = 0;
			if (0 == r_buf_rpos_index_inc(r_buf, rpos))
				return;
		} else { /* Inc iov offset. */
			rpos->iov_off += data_size;
			return;
		}
	}
	/* Normal iov process. */
	for (; 0 != data_size;) {
		if (r_buf->iov[rpos->iov_index].iov_len > data_size) {
			rpos->iov_off = data_size;
			return;
		}
		data_size -= r_buf->iov[rpos->iov_index].iov_len;
		if (0 == r_buf_rpos_index_inc(r_buf, rpos))
			return; /* XXX this situation is BUG and must newer happen. */
	}
}
