/*-
 * Copyright (c) 2013 - 2016 Rozhuk Ivan <rozhuk.im@gmail.com>
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


#include <sys/param.h>
#ifdef __linux__ /* Linux specific code. */
#	define _GNU_SOURCE /* See feature_test_macros(7) */
#	define __USE_GNU 1
#endif /* Linux specific code. */
#include <sys/types.h>
//#include <sys/time.h>
//#include <sys/param.h>
#include <inttypes.h>
#include <stdlib.h> /* malloc, exit */
#include <unistd.h> /* close, write, sysconf */
#include <fcntl.h> // open
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <stdarg.h> // va_start, va_arg
#include <errno.h>

//#include "core_helpers.h"
#include "xml.h"
#include "StrToNum.h"

#include "macro_helpers.h"
#include "core_xconfig.h"



typedef struct xcfg_file_s { /* Config file. */
	uint8_t	*data;	// config file content
	off_t	size;	// file size
} xcfg_file_t;


int
xcfg_file_open(const char *file, xcfg_file_p *pxcfd) {
	xcfg_file_p xcfg;
	int fd, error;
	ssize_t readed;

	if (NULL == file || NULL == pxcfd)
		return (EINVAL);
	xcfg = zalloc(sizeof(xcfg_file_t));
	if (NULL == xcfg)
		return (ENOMEM);
	/* Open file. */
	fd = open(file, O_RDONLY);
	if (-1 == fd) {
		error = errno;
		xcfg_file_close(xcfg);
		return (error);
	}
	/* Get file size. */
	xcfg->size = lseek(fd, 0, SEEK_END);
	if (-1 == xcfg->size) {
		error = errno;
		close(fd);
		xcfg_file_close(xcfg);
		return (error);
	}
	lseek(fd, 0, SEEK_SET);
	/* Allocate buf for file content. */
	xcfg->data = malloc((xcfg->size + 4));
	if (NULL == xcfg->data) {
		close(fd);
		xcfg_file_close(xcfg);
		return (ENOMEM);
	}
	/* Read file content. */
	readed = read(fd, xcfg->data, xcfg->size);
	close(fd);
	if (-1 == readed) {
		error = errno;
		xcfg_file_close(xcfg);
		return (error);
	}
	(*pxcfd) = xcfg;
	return (0);
}

void
xcfg_file_close(xcfg_file_p xcfg) {

	if (NULL == xcfg)
		return;
	if (NULL != xcfg->data)
		free(xcfg->data);
	free(xcfg);
}


size_t
xcfg_file_calc_val_count(xcfg_file_p xcfg, const uint8_t *tag1, ...) {
	size_t ret = 0;
	uint8_t *next_pos = NULL;
	const uint8_t *tag_arr[XML_MAX_LEVELS];
	size_t tag_arr_count, tag_arr_cnt[XML_MAX_LEVELS];
	va_list va;

	if (NULL == xcfg || NULL == tag1)
		return (ret);
	/* Load args to local array. */
	tag_arr[0] = tag1;
	tag_arr_cnt[0] = strlen((char*)tag1);
	va_start(va, tag1);
	for (tag_arr_count = 1; XML_MAX_LEVELS > tag_arr_count; tag_arr_count ++) {
		tag_arr[tag_arr_count] = va_arg(va, const uint8_t*);
		if (NULL == tag_arr[tag_arr_count])
			break;
		tag_arr_cnt[tag_arr_count] = strlen((char*)tag_arr[tag_arr_count]);
	}
	va_end(va);
	while (0 == xml_get_val_arr(xcfg->data, xcfg->size, &next_pos,
	    tag_arr_count, &tag_arr[0], &tag_arr_cnt[0], NULL, 0, NULL, 0))
		ret ++;
	return (ret);
}

int
xcfg_file_get_val_data(xcfg_file_p xcfg, uint8_t **next_pos,
    uint8_t **ret_value, size_t *ret_value_size, const uint8_t *tag1, ...) {
	const uint8_t *tag_arr[XML_MAX_LEVELS];
	size_t tag_arr_count, tag_arr_cnt[XML_MAX_LEVELS];
	va_list va;

	if (NULL == xcfg || NULL == tag1)
		return (EINVAL);
	/* Load args to local array. */
	tag_arr[0] = tag1;
	tag_arr_cnt[0] = strlen((char*)tag1);
	va_start(va, tag1);
	for (tag_arr_count = 1; XML_MAX_LEVELS > tag_arr_count; tag_arr_count ++) {
		tag_arr[tag_arr_count] = va_arg(va, const uint8_t*);
		if (NULL == tag_arr[tag_arr_count])
			break;
		tag_arr_cnt[tag_arr_count] = strlen((char*)tag_arr[tag_arr_count]);
	}
	va_end(va);
	return (xml_get_val_arr(xcfg->data, xcfg->size, next_pos,
	    tag_arr_count, &tag_arr[0], &tag_arr_cnt[0], NULL, 0,
	    ret_value, ret_value_size));
}

int
xcfg_file_get_val_ssize_t(xcfg_file_p xcfg, uint8_t **next_pos,
    ssize_t *val_ret, const uint8_t *tag1, ...) {
	int error;
	const uint8_t *tag_arr[XML_MAX_LEVELS];
	uint8_t *val = NULL;
	size_t val_size = 0, tag_arr_count, tag_arr_cnt[XML_MAX_LEVELS];
	va_list va;

	if (NULL == xcfg || NULL == val_ret || NULL == tag1)
		return (EINVAL);
	/* Load args to local array. */
	tag_arr[0] = tag1;
	tag_arr_cnt[0] = strlen((char*)tag1);
	va_start(va, tag1);
	for (tag_arr_count = 1; XML_MAX_LEVELS > tag_arr_count; tag_arr_count ++) {
		tag_arr[tag_arr_count] = va_arg(va, const uint8_t*);
		if (NULL == tag_arr[tag_arr_count])
			break;
		tag_arr_cnt[tag_arr_count] = strlen((char*)tag_arr[tag_arr_count]);
	}
	va_end(va);
	error = xml_get_val_arr(xcfg->data, xcfg->size, next_pos,
	    tag_arr_count, &tag_arr[0], &tag_arr_cnt[0], NULL, 0,
	    &val, &val_size);
	if (0 != error)
		return (error);
	(*val_ret) = UStr8ToNum(val, val_size);
	return (0);
}

int
xcfg_file_get_val_int(xcfg_file_p xcfg, uint8_t **next_pos,
    int32_t *val_ret, const uint8_t *tag1, ...) {
	int error;
	const uint8_t *tag_arr[XML_MAX_LEVELS];
	uint8_t *val = NULL;
	size_t val_size = 0, tag_arr_count, tag_arr_cnt[XML_MAX_LEVELS];
	va_list va;

	if (NULL == xcfg || NULL == val_ret || NULL == tag1)
		return (EINVAL);
	/* Load args to local array. */
	tag_arr[0] = tag1;
	tag_arr_cnt[0] = strlen((char*)tag1);
	va_start(va, tag1);
	for (tag_arr_count = 1; XML_MAX_LEVELS > tag_arr_count; tag_arr_count ++) {
		tag_arr[tag_arr_count] = va_arg(va, const uint8_t*);
		if (NULL == tag_arr[tag_arr_count])
			break;
		tag_arr_cnt[tag_arr_count] = strlen((char*)tag_arr[tag_arr_count]);
	}
	va_end(va);
	error = xml_get_val_arr(xcfg->data, xcfg->size, next_pos,
	    tag_arr_count, &tag_arr[0], &tag_arr_cnt[0], NULL, 0,
	    &val, &val_size);
	if (0 != error)
		return (error);
	(*val_ret) = UStr8ToNum32(val, val_size);
	return (0);
}
