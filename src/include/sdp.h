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
 * SDP: Session Description Protocol
 * RFC 4566
 *
 */

#ifndef __SDP_PROTO_H__
#define __SDP_PROTO_H__


#include <sys/types.h>
#include <inttypes.h>
#include "mem_helpers.h"

#ifndef CRLF
#define CRLF	"\r\n"
#endif



/* Return value for specified type. */
static inline int
sdp_msg_type_get(uint8_t *sdp_msg, size_t sdp_msg_size, const uint8_t type,
    size_t *line, uint8_t **val_ret, size_t *val_ret_size) {
	uint8_t *val, *val_end;
	size_t i, start_line;

	if (NULL == sdp_msg || 0 == sdp_msg_size)
		return (EINVAL);

	/* Skeep first lines. */
	val = (sdp_msg - 2);
	start_line = (NULL != line) ? (*line) : 0;
	for (i = 0; i < start_line && NULL != val; i ++) {
		val = mem_find_ptr_cstr((val + 2), sdp_msg, sdp_msg_size, CRLF);
	}

	for (; NULL != val; i ++) {
		val += 2;
		if (type == (*val) && '=' == (*(val + 1))) {
			/* Found! */
			val += 2;
			if (NULL != line)
				(*line) = i;
			if (NULL != val_ret)
				(*val_ret) = val;
			if (NULL != val_ret_size) {
				val_end = mem_find_ptr_cstr(val, sdp_msg,
				    sdp_msg_size, CRLF);
				if (NULL == val_end)
					val_end = (sdp_msg + sdp_msg_size);
				(*val_ret_size) = (val_end - val);
			}
			return (0);
		}
		/* Move to next value name. */
		val = mem_find_ptr_cstr(val, sdp_msg, sdp_msg_size, CRLF);
	}
	return (EINVAL);
}

static inline size_t
sdp_msg_type_get_count(uint8_t *sdp_msg, size_t sdp_msg_size, const uint8_t type) {
	size_t line = 0;
	size_t ret = 0;

	while (0 == sdp_msg_type_get(sdp_msg, sdp_msg_size, type, &line, NULL, NULL)) {
		line ++;
		ret ++;
	}
	return (ret);
}

/* Split buf to array of arguments, separated by SP return number of arguments. */
static inline size_t
sdp_msg_feilds_get(uint8_t *buf, size_t buf_size, size_t max_feilds,
    uint8_t **feilds, size_t *feilds_sizes) {
	uint8_t *cur_pos, *max_pos, *ptm;
	size_t ret, data_size;

	if (NULL == buf || 0 == buf_size || 0 == max_feilds || NULL == feilds)
		return (0);

	ret = 0;
	cur_pos = buf;
	max_pos = (buf + buf_size);
	while (max_feilds > ret && max_pos > cur_pos) {
		/* Calculate data size. */
		ptm = mem_chr_ptr(cur_pos, buf, buf_size, ' ');
		if (NULL != ptm)
			data_size = (ptm - cur_pos);
		else
			data_size = (max_pos - cur_pos);
		feilds[ret] = cur_pos;
		feilds_sizes[ret] = data_size;
		ret ++;

		/* Move to next arg. */
		data_size ++;
		cur_pos += data_size;
	}
	return (ret);
}

/* Check message format. */
static inline int
sdp_msg_sec_chk(uint8_t *sdp_msg, size_t sdp_msg_size) {
	uint8_t *ptm, *msg_max;

	/*
	 * Security checks:
	 * 1. Min size: 16
	 * 2. Start with: 'v=0'CRLF
	 * 3. Control codes: < 32, !=CRLF !=tab, > 126
	 * 4. Format: [CRLF]type=
	 * 5. "v=" count == 1 !
	 * 6. "o=" count == 1 !
	 * 7. "s=" count == 1 !
	 * 8. "t=" count > 0 !
	 * 9. "c=" count > 0 !
	 * 10. "m=" count > 0 !
	 * no order checks now.
	 */

	/* 1. */
	if (16 > sdp_msg_size)
		return (1);
	/* 2. (4. - first line) */
	if (0 != memcmp(sdp_msg, "v=0\r\n", 5))
		return (2);
	/* 3, 4. */
	msg_max = (sdp_msg + sdp_msg_size);
	for (ptm = sdp_msg; ptm < msg_max; ptm ++) {
		if ((*ptm) > 31 || (*ptm) == '\t') /* XXX: tab? */
			continue;
		if ((*ptm) > 126)
			return (3); /* Control codes. */
		if ((*ptm) != '\r' || ((ptm + 1) < msg_max && (*(ptm + 1)) != '\n'))
			return (3); /* Control codes. */
		ptm ++; /* Skeep: CRLF. (point to LF) */
		if ((ptm + 2) >= msg_max)
			continue;
		if ('a' > (*(ptm + 1)) || 'z' < (*(ptm + 1)))
			return (3); /* Control codes / whitespace. */
		if ('=' != (*(ptm + 2)))
			return (4); /* Invalid format. */
		ptm += 2; /* Skeep: '<type>='. (point to '=') */
	}
	/* 5. */
	if (1 != sdp_msg_type_get_count(sdp_msg, sdp_msg_size, 'v'))
		return (5);
	/* 6. */
	if (1 != sdp_msg_type_get_count(sdp_msg, sdp_msg_size, 'o'))
		return (6);
	/* 7. */
	if (1 != sdp_msg_type_get_count(sdp_msg, sdp_msg_size, 's'))
		return (7);
	/* 8. */
	if (0 == sdp_msg_type_get_count(sdp_msg, sdp_msg_size, 't'))
		return (8);
	/* 9. */
	if (0 == sdp_msg_type_get_count(sdp_msg, sdp_msg_size, 'c'))
		return (9);
	/* 10. */
	if (0 == sdp_msg_type_get_count(sdp_msg, sdp_msg_size, 'm'))
		return (9);

	return (0);
}


#endif /* __SDP_PROTO_H__ */
