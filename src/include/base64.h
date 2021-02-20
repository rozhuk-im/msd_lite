/*-
 * Copyright (c) 2003 - 2014 Rozhuk Ivan <rozhuk.im@gmail.com>
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
 */


#ifndef AFX_BASE64__H__INCLUDED_
#define AFX_BASE64__H__INCLUDED_


#ifndef _WINDOWS
#include <sys/types.h>
#include <inttypes.h>
#else
#define EINVAL		ERROR_INVALID_HANDLE
#define ENOBUFS		ERROR_BUFFER_OVERFLOW
#define uint8_t		unsigned char
#define size_t		SIZE_T
#endif

/*
 *      BASE64 coding:
 *      214             46              138
 *      11010100        00101110        10001010
 *            !             !             !
 *      ---------->>> convert 3 8bit to 4 6bit
 *      110101  000010  111010  001010
 *      53      2       58      10
 *      this numbers is offset in array coding below...
 */

static const uint8_t *base64_tbl_coding = (uint8_t*)
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const uint8_t base64_tbl_decoding[256] = {
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
	64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
	64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};


static inline int
base64_encode(uint8_t *src, size_t src_size, uint8_t *dst, size_t dst_size, size_t *enc_size) {
	size_t tm, src_m3_size;
	register uint8_t *wpos, *rpos, *src_m3_max;
	
	if (NULL == src || 0 == src_size)
		return (EINVAL);
	/* dst buf size calculation. */
	tm = (src_size / 3);
	src_m3_size = (tm * 3);
	if (src_m3_size != src_size) /* is multiple of 3? */
		tm ++;
	tm *= 4;
	if (NULL != enc_size)
		(*enc_size) = tm;
	if (dst_size < tm) /* Is dst buf too small? */
		return (ENOBUFS);
	if (NULL == dst)
		return (EINVAL);
	wpos = dst;
	rpos = src;
	/* Main loop: encode 3 -> 4 */
	for (src_m3_max = (src + src_m3_size); rpos < src_m3_max; rpos += 3) {
		(*wpos ++) = base64_tbl_coding[rpos[0] >> 2]; /* c1 */
		(*wpos ++) = base64_tbl_coding[((rpos[0] << 4) & 0x30) | ((rpos[1] >> 4) & 0x0f)]; /* c2 */
		(*wpos ++) = base64_tbl_coding[((rpos[1] << 2) & 0x3c) | ((rpos[2] >> 6) & 0x03)]; /* c3 */
		(*wpos ++) = base64_tbl_coding[rpos[2] & 0x3f]; /* c4 */
	}
	/* Tail special encoding. */
	if (src_size != src_m3_size) { /* If src_size was not a multiple of 3: 1-2 bytes tail special coding. */
		(*wpos ++) = base64_tbl_coding[rpos[0] >> 2]; /* c1 */
		if (1 == (src_size - src_m3_size)) { /* 1 byte tail. */
			(*wpos ++) = base64_tbl_coding[((rpos[0] << 4) & 0x30)]; /* c2 */
			(*wpos ++) = '='; /* c3: tail padding. */
		} else { /* 2 bytes tail. */
			(*wpos ++) = base64_tbl_coding[((rpos[0] << 4) & 0x30) | ((rpos[1] >> 4) & 0x0f)]; /* c2 */
			(*wpos ++) = base64_tbl_coding[((rpos[1] << 2) & 0x3c)]; /* c3 */
		}
		(*wpos ++) = '='; /* c4: tail padding. */
	}
	(*wpos) = 0;
#if 0
	if (tm != (wpos - dst)) { /* Must be euqual! */
		(*enc_size) = (wpos - dst);
	}
#endif
	return (0);
}


static inline int
base64_decode(uint8_t *src, size_t src_size, uint8_t *dst, size_t dst_size, size_t *dcd_size) {
	size_t tm, src_m4_size;
	register uint8_t *wpos, *rpos, *src_m4_max;

	if (NULL == src || 2 > src_size)
		return (EINVAL);
	/* Remove tail padding. */
	for (; 0 < src_size; src_size --) {
		if (src[(src_size - 1)] != '=')
			break;
	}
	if (2 > src_size) /* Check again: at least 2 byte needed for decoder. */
		return (EINVAL);
	/* dst buf size calculation. */
	tm = (src_size / 4);
	src_m4_size = (tm * 4);
	if (src_m4_size != src_size) /* is multiple of 4? */
		tm ++;
	tm *= 3;
	if (dst_size < tm) { /* Is dst buf too small? */
		if (NULL != dcd_size)
			(*dcd_size) = tm;
		return (ENOBUFS);
	}
	if (NULL == dst)
		return (EINVAL);
	wpos = dst;
	rpos = src;
	/* Main loop: decode 4 -> 3 */
	for (src_m4_max = (src + src_m4_size); rpos < src_m4_max; rpos += 4) {
		(*wpos ++) = (base64_tbl_decoding[rpos[0]] << 2 | base64_tbl_decoding[rpos[1]] >> 4);
		(*wpos ++) = (base64_tbl_decoding[rpos[1]] << 4 | base64_tbl_decoding[rpos[2]] >> 2);
		(*wpos ++) = (base64_tbl_decoding[rpos[2]] << 6 | base64_tbl_decoding[rpos[3]]);
	}
	/* Tail special decoding. */
	switch ((src_size - src_m4_size)) {
	case 2:
		(*wpos ++) = (base64_tbl_decoding[rpos[0]] << 2 | base64_tbl_decoding[rpos[1]] >> 4);
		break;
	case 3:
		(*wpos ++) = (base64_tbl_decoding[rpos[0]] << 2 | base64_tbl_decoding[rpos[1]] >> 4);
		(*wpos ++) = (base64_tbl_decoding[rpos[1]] << 4 | base64_tbl_decoding[rpos[2]] >> 2);
		break;
	}
	(*wpos) = 0;
	if (NULL != dcd_size) /* Real decoded size can be smaller than calculated. */
		(*dcd_size) = (wpos - dst);
	return (0);
}

/* Copy only Base64 encoded symbols. */
static inline int
base64_en_copy(uint8_t *src, uint8_t *dst, size_t buf_size, size_t *new_size) {
	register uint8_t *wpos, *rpos, *src_max, tmb;

	if (NULL == src || NULL == dst || 0 == buf_size)
		return (EINVAL);
	wpos = dst;
	rpos = src;
	for (src_max = (src + buf_size); rpos < src_max; rpos ++) {
		tmb = (*rpos);
		if (64 != base64_tbl_decoding[tmb])
			(*wpos ++) = tmb;
	}
	if (NULL != new_size)
		(*new_size) = (wpos - dst);
	return (0);
}


static inline int
base64_decode_fmt(uint8_t *src, size_t src_size, uint8_t *dst, size_t dst_size, size_t *dcd_size) {
	int error;

	if (src_size > dst_size)
		return (ENOBUFS);
	error = base64_en_copy(src, dst, src_size, &src_size);
	if (0 != error)
		return (error);
	return (base64_decode(dst, src_size, dst, dst_size, dcd_size));
}



#endif // !defined(AFX_BASE64__H__INCLUDED_)
