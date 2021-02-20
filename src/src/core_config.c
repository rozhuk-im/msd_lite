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


#include <sys/param.h>
#ifdef __linux__ /* Linux specific code. */
#	define _GNU_SOURCE /* See feature_test_macros(7) */
#	define __USE_GNU 1
#endif /* Linux specific code. */
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <stdlib.h> /* malloc, exit */
#include <unistd.h> // close
#include <fcntl.h> // open
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <errno.h>

#include "macro_helpers.h"
#include "mem_helpers.h"
#include "core_helpers.h"
#include "StrToNum.h"

#include "core_config.h"



// pre allocate cfg_line_t structs
#define CFG_FILE_LINES_PREALLOC		1024

#define CFG_FILE_MAX_VAL_NAME		255
#define CFG_FILE_MAX_VAL_INT_LEN	64



typedef struct cfg_line_s {
	off_t		offset;	// from start of file
	size_t		size;	// from offset to first LF/CRLF
} cfg_line_t, *cfg_line_p;


typedef struct cfg_file_s { /* Config file. */
	char		*data;		// config file content
	off_t		size;		// file size
	size_t		lines_count;	// lines count
	cfg_line_p	lines;		// lines offset and sizes
} cfg_file_t;





int
cfg_file_open(const char *file, cfg_file_p *pcfd) {
	cfg_file_p cfd;
	char *ptm, *ptm_end, *pos_max;
	int error;
	size_t items_allocated, items_count;

	if (NULL == file || NULL == pcfd)
		return (EINVAL);

	cfd = zalloc(sizeof(cfg_file_t));
	if (NULL == cfd)
		return (ENOMEM);
	/* Open file. */
	error = read_file(file, 0, 0, &cfd->data, &cfd->size);
	if (0 != error) {
		cfg_file_close(cfd);
		return (error);
	}

	items_count = 0;
	items_allocated = 0;
	ptm = cfd->data;
	pos_max = (cfd->data + cfd->size);
	while (ptm < pos_max) {
		/* LF */
		ptm_end = mem_chr_ptr(ptm, cfd->data, cfd->size, '\n');
		if (NULL == ptm_end)
			break;

		error = realloc_items((void**)&cfd->lines,
		    sizeof(cfg_line_t), &items_allocated,
		    CFG_FILE_LINES_PREALLOC, items_count);
		if (0 != error) {
			cfg_file_close(cfd);
			return (error);
		}
		cfd->lines[items_count].offset = (ptm - cfd->data);
		cfd->lines[items_count].size = (ptm_end - ptm);
		if ('\r' == (*(ptm_end - 1))) /* End of line is CRLF. */
			cfd->lines[items_count].size --;
		items_count ++;
		ptm = (ptm_end + 1);
	}
	/* Last line. */
	cfd->lines[items_count].offset = (ptm - cfd->data);
	cfd->lines[items_count].size = (pos_max - ptm);
	items_count ++;
	cfd->lines_count = items_count;
	(*pcfd) = cfd;
	
	return (0);
}

void
cfg_file_close(cfg_file_p cfd) {

	if (NULL == cfd)
		return;

	if (NULL != cfd->data)
		free(cfd->data);
	if (NULL != cfd->lines)
		free(cfd->lines);
	free(cfd);
}

size_t
cfg_file_lines_count(cfg_file_p cfd) {

	if (NULL == cfd)
		return (0);

	return (cfd->lines_count);
}

int
cfg_file_get_line(cfg_file_p cfd, size_t line, char **data_ret,
    size_t *data_size_ret) {

	if (NULL == cfd || line >= cfd->lines_count || NULL == data_ret ||
	    NULL == data_size_ret)
		return (EINVAL);

	(*data_ret) = (cfd->data + cfd->lines[line].offset);
	(*data_size_ret) = cfd->lines[line].size;

	return (0);
}

size_t
cfg_file_calc_val_count(cfg_file_t *cfd, const char *val_name, size_t val_name_size,
    const char comment_char, const char *separator, size_t separator_size,
    size_t line) {
	size_t i, data_size, sptab_count, ret;
	char *data;

	if (NULL == cfd || NULL == val_name || 0 == val_name_size ||
	    NULL == separator || 0 == separator_size || line >= cfd->lines_count)
		return (0);

	ret = 0;
	for (i = line; i < cfd->lines_count; i ++) {
		data = (cfd->data + cfd->lines[i].offset);
		data_size = cfd->lines[i].size;

		/* Skeep spaces and tabs before value name. */
		sptab_count = calc_sptab_count(data, data_size);
		data += sptab_count;
		data_size -= sptab_count;
		/* Line commented. */
		if (comment_char == (*data))
			continue;
		/* Is string to small? */
		if ((val_name_size + separator_size) > data_size)
			continue;
		/* Value name euqual? */
		if (0 != mem_cmpi(val_name, data, val_name_size))
			continue;
		/* Skeep spaces and tabs after value name. */
		data += val_name_size;
		data_size -= val_name_size;
		sptab_count = calc_sptab_count(data, data_size);
		data += sptab_count;
		data_size -= sptab_count;
		/* Is string to small? */
		if (separator_size > data_size)
			continue;
		/* Is separator ok? */
		if (0 != memcmp(data, separator, separator_size))
			continue;
		ret ++;
	}
	/* Not found. */
	return (ret);
}

int
cfg_file_get_val_data(cfg_file_p cfd, const char *val_name, size_t val_name_size,
    const char comment_char, const char *separator, size_t separator_size,
    size_t *line, char **data_ret, size_t *data_size_ret) {
	size_t i, start_line, data_size, sptab_count;
	char *data, *ptm;

	if (NULL == cfd || NULL == val_name || 0 == val_name_size ||
	    NULL == separator || 0 == separator_size ||
	    (NULL != line && (*line) >= cfd->lines_count) || NULL == data_ret ||
	    NULL == data_size_ret)
		return (EINVAL);

	start_line = (NULL != line) ? (*line) : 0;
	for (i = start_line; i < cfd->lines_count; i ++) {
		data = (cfd->data + cfd->lines[i].offset);
		data_size = cfd->lines[i].size;
		/* Skeep spaces and tabs before value name. */
		sptab_count = calc_sptab_count(data, data_size);
		data += sptab_count;
		data_size -= sptab_count;
		/* Line commented. */
		if (comment_char == (*data))
			continue;
		/* String to small? */
		if ((val_name_size + separator_size) > data_size)
			continue;
		/* Value name euqual? */
		if (0 != mem_cmpi(val_name, data, val_name_size))
			continue;
		/* Skeep spaces and tabs after value name. */
		data += val_name_size;
		data_size -= val_name_size;
		sptab_count = calc_sptab_count(data, data_size);
		data += sptab_count;
		data_size -= sptab_count;
		/* String to small? */
		if (separator_size > data_size)
			continue;
		/* Is separator ok? */
		if (0 != memcmp(data, separator, separator_size))
			continue;
		/* Skeep spaces and tabs after separator. */
		data += separator_size;
		data_size -= separator_size;
		sptab_count = calc_sptab_count(data, data_size);
		data += sptab_count;
		data_size -= sptab_count;
		/* Comment at end of line. */
		ptm = mem_chr(data, data_size, comment_char);
		if (NULL != ptm)
			data_size = (ptm - data);
		/* Cut out tabs/spaces from end of line. */
		sptab_count = calc_sptab_count_r(data, data_size);
		data_size -= sptab_count;

		(*data_ret) = data;
		(*data_size_ret) = data_size;
		if (NULL != line)
			(*line) = i;
		return (0);
	}
	/* Not found. */
	return (-1);
}

int
cfg_file_get_raw_data(cfg_file_p cfd, const char comment_char, size_t *line,
    char **data_ret, size_t *data_size_ret) {
	size_t i, start_line, data_size, sptab_count;
	char *data, *ptm;

	if (NULL == cfd || (NULL != line && (*line) >= cfd->lines_count) ||
	    NULL == data_ret || NULL == data_size_ret)
		return (EINVAL);

	start_line = (NULL != line) ? (*line) : 0;
	for (i = start_line; i < cfd->lines_count; i ++) {
		data = (cfd->data + cfd->lines[i].offset);
		data_size = cfd->lines[i].size;
		/* Skeep spaces and tabs before data. */
		sptab_count = calc_sptab_count(data, data_size);
		data += sptab_count;
		data_size -= sptab_count;
		/* Line commented. */
		if (comment_char == (*data))
			continue;
		/* Comment at end of line. */
		ptm = mem_chr(data, data_size, comment_char);
		if (NULL != ptm)
			data_size = (ptm - data);
		/* Cut out tabs/spaces from end of line. */
		sptab_count = calc_sptab_count_r(data, data_size);
		data_size -= sptab_count;

		(*data_ret) = data;
		(*data_size_ret) = data_size;
		if (NULL != line)
			(*line) = i;
		return (0);
	}
	/* Not found. */
	return (-1);
}

int
cfg_file_get_val_int(cfg_file_p cfd, const char *val_name, size_t val_name_size,
    const char comment_char, const char *separator, size_t separator_size,
    size_t *line, int32_t *val_ret) {
	int ret;
	char *int_val;
	size_t int_val_size;

	if (NULL == val_ret)
		return (EINVAL);
	ret = cfg_file_get_val_data(cfd, val_name, val_name_size, comment_char,
	    separator, separator_size, line, &int_val, &int_val_size);
	if (0 != ret)
		return (ret);
	(*val_ret) = StrToNum32(int_val, int_val_size);
	return (0);
}

int
cfg_file_get_val_ssize_t(cfg_file_p cfd, const char *val_name, size_t val_name_size,
    const char comment_char, const char *separator, size_t separator_size,
    size_t *line, ssize_t *val_ret) {
	int ret;
	char *int_val;
	size_t int_val_size;

	if (NULL == val_ret)
		return (EINVAL);
	ret = cfg_file_get_val_data(cfd, val_name, val_name_size, comment_char,
	    separator, separator_size, line, &int_val, &int_val_size);
	if (0 != ret)
		return (ret);
	(*val_ret) = StrToNum(int_val, int_val_size);
	return (0);
}
