/*-
 * Copyright (c) 2007 - 2016 Rozhuk Ivan <rozhuk.im@gmail.com>
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
#include <inttypes.h>
//#include <stdlib.h>
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <stdarg.h> /* va_start, va_arg */
#include <errno.h>

#include "xml.h"
#include "mem_helpers.h"
#include "StrToNum.h"



#ifndef is_space
#	define is_space(__c)	(' ' == (__c) || ('\t' <= (__c) && '\r' >= (__c)))
#endif



static const char *xml_tags[]		= { "&apos;", "&quot;", "&amp;", "&lt;", "&gt;" };
static const size_t xml_tags_counts[]	= { 6, 6, 5, 4, 4 };
static const char *xml_symbols[]	= { "\'", "\"", "&", "<", ">" };
static const size_t xml_symbols_counts[] = { 1, 1, 1, 1, 1 };



/* Decode XML coded string. The function translate special xml code into standard characters. */
int
xml_decode(const uint8_t *encoded, size_t encoded_size,
    uint8_t *xml, size_t xml_buf_size, size_t *xml_size) {

	return (mem_replace_arr(encoded, encoded_size, 5, NULL,
	    (void*)xml_tags, xml_tags_counts,
	    (void*)xml_symbols, xml_symbols_counts,
	    xml, xml_buf_size, xml_size, NULL));
}

/* Encode XML coded string. The function translate special saved xml characters into special characters. */
int
xml_encode(const uint8_t *xml, size_t xml_size, uint8_t *encoded,
    size_t encoded_buf_size, size_t *encoded_size) {

	return (mem_replace_arr(xml, xml_size, 5, NULL,
	    (void*)xml_symbols, xml_symbols_counts,
	    (void*)xml_tags, xml_tags_counts,
	    encoded, encoded_buf_size, encoded_size, NULL));
}


int
xml_get_val_arr(const uint8_t *xml_data, size_t xml_data_size,
    const uint8_t **next_pos,
    size_t tag_arr_count, const uint8_t **tag_arr, size_t *tag_arr_cnt,
    const uint8_t **ret_attr, size_t *ret_attr_size,
    const uint8_t **ret_value, size_t *ret_value_size) {
	int ee;
	const uint8_t *xml_data_end, *TagStart, *TagEnd, *TagNameEnd, *attr = NULL, *value = NULL;
	size_t cur_tag = 0, data_avail, attr_size = 0;
	ssize_t level = 0;

	if (NULL != next_pos && xml_data <= (*next_pos) &&
	    (xml_data + xml_data_size) > (*next_pos)) {
		TagEnd = (*next_pos);
		cur_tag = ((TagEnd == xml_data) ? 0 : (tag_arr_count - 1));
	} else { /* Not set or Out of range. */
		TagEnd = xml_data;
	}
	xml_data_end = (xml_data + xml_data_size);
	for (;;) {
		TagStart = mem_chr_ptr(TagEnd, xml_data, xml_data_size, '<');
		if (NULL == TagStart)
			return (ESPIPE);
		TagStart ++;
		data_avail = (size_t)(xml_data_end - TagStart);
		switch ((*TagStart)) {
		case '?': /* <?...?> processing instructions */
			TagEnd = mem_find_ptr_cstr(TagStart, xml_data, xml_data_size, "?>");
			if (NULL == TagEnd)
				return (ESPIPE);
			TagEnd += 2;
			continue;
		case '!':
			TagStart ++;
			data_avail --;
			if (2 < data_avail && 0 == memcmp(TagStart, "--", 2)) { /* <!-- xml comment --> */
				TagStart += 2;
				TagEnd = mem_find_ptr_cstr(TagStart, xml_data, xml_data_size, "-->");
				if (NULL == TagEnd)
					return (ESPIPE);
				TagEnd += 3;
				continue;
			} else if (7 < data_avail && 0 == memcmp(TagStart, "[CDATA[", 7)) { /* <![CDATA] cdata ]]> */
				TagStart += 7;
				TagEnd = mem_find_ptr_cstr(TagStart, xml_data, xml_data_size, "]]>");
				if (NULL == TagEnd)
					return (ESPIPE);
				TagEnd += 3;
				continue;
			} else if (7 < data_avail && 0 == memcmp(TagStart, "DOCTYPE", 7)) { /* dtd */
				TagStart += 7;
				TagEnd = mem_chr_ptr(TagStart, xml_data, xml_data_size, '>');
				if (NULL == TagEnd)
					return (ESPIPE);
				TagEnd ++;
				continue;
			}
			return (ESPIPE);
		case '>':  /* "<>" - may cause infinite loop */
			TagEnd = (TagStart + 1);
			continue;
		case '/': /* close tag "</...>" */
			TagEnd = mem_chr_ptr(TagStart, xml_data, xml_data_size, '>');
			if (NULL == TagEnd)
				return (ESPIPE);
			TagEnd --;
			if (TagEnd == TagStart) /* "</>" do notfing */
				continue;
			level --;
			if (0 <= level) /* Close some sub tag. */
				continue;
			if (0 != mem_cmpn(tag_arr[(cur_tag - 1)], tag_arr_cnt[(cur_tag -1)],
			    (TagStart + 1), (size_t)(TagEnd - TagStart))) /* Is name close qual name open? */
				continue;
			cur_tag --; /* tag close, up one tag level */
			level = 0;
			//LOG_EV_FMT("close tag_arr (%zu) = %s", tag_arr_cnt[cur_tag], tag_arr[cur_tag]);
			if (NULL == value) /* cur_tag < tag_arr_count */
				continue;
			if (NULL != next_pos) {
				(*next_pos) = (TagEnd + 2);
			}
			if (NULL != ret_attr) {
				(*ret_attr) = attr;
			}
			if (NULL != ret_attr_size) {
				(*ret_attr_size) = attr_size;
			}
			if (NULL != ret_value || NULL != ret_value_size) {
				data_avail = (size_t)((TagStart - 1) - value);
				/* Extract CDATA */
				TagStart = mem_chr(value, data_avail, '<');
				if (NULL != TagStart &&
				    8 < (size_t)(data_avail - (size_t)(TagStart - value)) &&
				    0 == memcmp((TagStart + 1), "![CDATA[", 8)) {
					TagStart += 9;
					TagEnd = mem_find_ptr_cstr(TagStart, value, data_avail, "]]>");
					if (NULL != TagEnd) {
						value = TagStart;
						data_avail = (size_t)(TagEnd - value);
					}
				}
				if (NULL != ret_value) {
					(*ret_value) = value;
				}
				if (NULL != ret_value_size) {
					(*ret_value_size) = data_avail;
				}
			}
			return (0);
		case '_': /* new tag */
		case ':':
		default:
			TagEnd = mem_chr_ptr(TagStart, xml_data, xml_data_size, '>');
			if (NULL == TagEnd)
				return (ESPIPE);
			TagEnd --;
			ee = ('/' == (*TagEnd)); /* <foo /> - no data in element. */
			if (0 != ee) {
				TagEnd --;
			} else {
				level ++;
			}
			/* Look for name end. */
			for (TagNameEnd = TagStart;
			    0 == is_space((*TagNameEnd)) && TagNameEnd < TagEnd;
			    TagNameEnd ++)
				;
			if (is_space((*TagNameEnd))) { /* <foo attr="attr val"...> */
				TagNameEnd --;
			}
			if (1 != level &&
			    0 == ee) /* Open some sub tag. */
				continue;
			if (0 != mem_cmpn(tag_arr[cur_tag], tag_arr_cnt[cur_tag],
			    TagStart, (size_t)((TagNameEnd + 1) - TagStart)))
				continue; /* Name not match. */
			/* Found target tag. */
			//LOG_EV_FMT("open tag_arr (%zu) = %s", tag_arr_cnt[cur_tag], tag_arr[cur_tag]);
			cur_tag ++;
			level = 0;
			if (cur_tag < tag_arr_count)
				continue;
			//LOG_EV_FMT("open tag_arr (%zu) = %s", tag_arr_cnt[cur_tag-1], tag_arr[cur_tag-1]);
			/* Our final target. */
			value = (TagEnd + 2);
			for (attr = (TagNameEnd + 1);
			    0 != is_space((*attr)) && attr < TagEnd; attr ++)
				;
			attr_size = (size_t)((TagEnd + 1) - attr);
			if (0 == ee)
				continue;
			/* <foo /> - no data in element. */
			if (NULL != next_pos) {
				(*next_pos) = (TagEnd + 2);
			}
			if (NULL != ret_attr) {
				(*ret_attr) = NULL;
			}
			if (NULL != ret_attr_size) {
				(*ret_attr_size) = 0;
			}
			if (NULL != ret_value) {
				(*ret_value) = NULL;
			}
			if (NULL != ret_value_size) {
				(*ret_value_size) = 0;
			}
			return (0);
		} /* end switch */
	} /* end for */
	return (ESPIPE);
}


int
xml_get_val_args(const uint8_t *xml_data, size_t xml_data_size,
    const uint8_t **next_pos,
    const uint8_t **ret_attr, size_t *ret_attr_size,
    const uint8_t **ret_value, size_t *ret_value_size,
    const uint8_t *tag1, ...) {
	const uint8_t *tag_arr[XML_MAX_LEVELS];
	size_t tag_arr_count, tag_arr_cnt[XML_MAX_LEVELS];
	va_list va;

	/* Load args to local array. */
	tag_arr[0] = tag1;
	tag_arr_cnt[0] = strlen((const char*)tag1);
	//LOG_EV_FMT("tag_arr (%zu) = %s", tag_arr_cnt[0], tag_arr[0]);
	va_start(va, tag1);
	for (tag_arr_count = 1; XML_MAX_LEVELS > tag_arr_count; tag_arr_count ++) {
		tag_arr[tag_arr_count] = va_arg(va, const uint8_t*);
		if (NULL == tag_arr[tag_arr_count]) {
			tag_arr_cnt[tag_arr_count] = 0;
			break;
		}
		tag_arr_cnt[tag_arr_count] = strlen((const char*)tag_arr[tag_arr_count]);
		//LOG_EV_FMT("tag_arr (%zu) = %s", tag_arr_cnt[tag_arr_count], tag_arr[tag_arr_count]);
	}
	va_end(va);
	return (xml_get_val_arr(xml_data, xml_data_size, next_pos,
	    tag_arr_count, &tag_arr[0], &tag_arr_cnt[0],
	    ret_attr, ret_attr_size,
	    ret_value, ret_value_size));
}

int
xml_get_val_size_t_args(const uint8_t *xml_data, size_t xml_data_size,
    const uint8_t **next_pos, size_t *val_ret, const uint8_t *tag1, ...) {
	int error;
	const uint8_t *tag_arr[XML_MAX_LEVELS];
	const uint8_t *val = NULL;
	size_t val_size = 0, tag_arr_count, tag_arr_cnt[XML_MAX_LEVELS];
	va_list va;

	if (NULL == xml_data || 0 == xml_data_size || NULL == val_ret || NULL == tag1)
		return (EINVAL);
	/* Load args to local array. */
	tag_arr[0] = tag1;
	tag_arr_cnt[0] = strlen((const char*)tag1);
	va_start(va, tag1);
	for (tag_arr_count = 1; XML_MAX_LEVELS > tag_arr_count; tag_arr_count ++) {
		tag_arr[tag_arr_count] = va_arg(va, const uint8_t*);
		if (NULL == tag_arr[tag_arr_count]) {
			tag_arr_cnt[tag_arr_count] = 0;
			break;
		}
		tag_arr_cnt[tag_arr_count] = strlen((const char*)tag_arr[tag_arr_count]);
	}
	va_end(va);
	error = xml_get_val_arr(xml_data, xml_data_size, next_pos,
	    tag_arr_count, &tag_arr[0], &tag_arr_cnt[0], NULL, 0,
	    &val, &val_size);
	if (0 != error)
		return (error);
	(*val_ret) = UStr8ToUNum(val, val_size);
	return (0);
}

int
xml_get_val_ssize_t_args(const uint8_t *xml_data, size_t xml_data_size,
    const uint8_t **next_pos, ssize_t *val_ret, const uint8_t *tag1, ...) {
	int error;
	const uint8_t *tag_arr[XML_MAX_LEVELS];
	const uint8_t *val = NULL;
	size_t val_size = 0, tag_arr_count, tag_arr_cnt[XML_MAX_LEVELS];
	va_list va;

	if (NULL == xml_data || 0 == xml_data_size || NULL == val_ret || NULL == tag1)
		return (EINVAL);
	/* Load args to local array. */
	tag_arr[0] = tag1;
	tag_arr_cnt[0] = strlen((const char*)tag1);
	va_start(va, tag1);
	for (tag_arr_count = 1; XML_MAX_LEVELS > tag_arr_count; tag_arr_count ++) {
		tag_arr[tag_arr_count] = va_arg(va, const uint8_t*);
		if (NULL == tag_arr[tag_arr_count]) {
			tag_arr_cnt[tag_arr_count] = 0;
			break;
		}
		tag_arr_cnt[tag_arr_count] = strlen((const char*)tag_arr[tag_arr_count]);
	}
	va_end(va);
	error = xml_get_val_arr(xml_data, xml_data_size, next_pos,
	    tag_arr_count, &tag_arr[0], &tag_arr_cnt[0], NULL, 0,
	    &val, &val_size);
	if (0 != error)
		return (error);
	(*val_ret) = UStr8ToNum(val, val_size);
	return (0);
}

int
xml_get_val_uint32_args(const uint8_t *xml_data, size_t xml_data_size,
    const uint8_t **next_pos, uint32_t *val_ret, const uint8_t *tag1, ...) {
	int error;
	const uint8_t *tag_arr[XML_MAX_LEVELS];
	const uint8_t *val = NULL;
	size_t val_size = 0, tag_arr_count, tag_arr_cnt[XML_MAX_LEVELS];
	va_list va;

	if (NULL == xml_data || 0 == xml_data_size || NULL == val_ret || NULL == tag1)
		return (EINVAL);
	/* Load args to local array. */
	tag_arr[0] = tag1;
	tag_arr_cnt[0] = strlen((const char*)tag1);
	va_start(va, tag1);
	for (tag_arr_count = 1; XML_MAX_LEVELS > tag_arr_count; tag_arr_count ++) {
		tag_arr[tag_arr_count] = va_arg(va, const uint8_t*);
		if (NULL == tag_arr[tag_arr_count]) {
			tag_arr_cnt[tag_arr_count] = 0;
			break;
		}
		tag_arr_cnt[tag_arr_count] = strlen((const char*)tag_arr[tag_arr_count]);
	}
	va_end(va);
	error = xml_get_val_arr(xml_data, xml_data_size, next_pos,
	    tag_arr_count, &tag_arr[0], &tag_arr_cnt[0], NULL, 0,
	    &val, &val_size);
	if (0 != error)
		return (error);
	(*val_ret) = UStr8ToUNum32(val, val_size);
	return (0);
}

int
xml_get_val_int32_args(const uint8_t *xml_data, size_t xml_data_size,
    const uint8_t **next_pos, int32_t *val_ret, const uint8_t *tag1, ...) {
	int error;
	const uint8_t *tag_arr[XML_MAX_LEVELS];
	const uint8_t *val = NULL;
	size_t val_size = 0, tag_arr_count, tag_arr_cnt[XML_MAX_LEVELS];
	va_list va;

	if (NULL == xml_data || 0 == xml_data_size || NULL == val_ret || NULL == tag1)
		return (EINVAL);
	/* Load args to local array. */
	tag_arr[0] = tag1;
	tag_arr_cnt[0] = strlen((const char*)tag1);
	va_start(va, tag1);
	for (tag_arr_count = 1; XML_MAX_LEVELS > tag_arr_count; tag_arr_count ++) {
		tag_arr[tag_arr_count] = va_arg(va, const uint8_t*);
		if (NULL == tag_arr[tag_arr_count]) {
			tag_arr_cnt[tag_arr_count] = 0;
			break;
		}
		tag_arr_cnt[tag_arr_count] = strlen((const char*)tag_arr[tag_arr_count]);
	}
	va_end(va);
	error = xml_get_val_arr(xml_data, xml_data_size, next_pos,
	    tag_arr_count, &tag_arr[0], &tag_arr_cnt[0], NULL, 0,
	    &val, &val_size);
	if (0 != error)
		return (error);
	(*val_ret) = UStr8ToNum32(val, val_size);
	return (0);
}

int
xml_get_val_uint64_args(const uint8_t *xml_data, size_t xml_data_size,
    const uint8_t **next_pos, uint64_t *val_ret, const uint8_t *tag1, ...) {
	int error;
	const uint8_t *tag_arr[XML_MAX_LEVELS];
	const uint8_t *val = NULL;
	size_t val_size = 0, tag_arr_count, tag_arr_cnt[XML_MAX_LEVELS];
	va_list va;

	if (NULL == xml_data || 0 == xml_data_size || NULL == val_ret || NULL == tag1)
		return (EINVAL);
	/* Load args to local array. */
	tag_arr[0] = tag1;
	tag_arr_cnt[0] = strlen((const char*)tag1);
	va_start(va, tag1);
	for (tag_arr_count = 1; XML_MAX_LEVELS > tag_arr_count; tag_arr_count ++) {
		tag_arr[tag_arr_count] = va_arg(va, const uint8_t*);
		if (NULL == tag_arr[tag_arr_count]) {
			tag_arr_cnt[tag_arr_count] = 0;
			break;
		}
		tag_arr_cnt[tag_arr_count] = strlen((const char*)tag_arr[tag_arr_count]);
	}
	va_end(va);
	error = xml_get_val_arr(xml_data, xml_data_size, next_pos,
	    tag_arr_count, &tag_arr[0], &tag_arr_cnt[0], NULL, 0,
	    &val, &val_size);
	if (0 != error)
		return (error);
	(*val_ret) = UStr8ToUNum64(val, val_size);
	return (0);
}

int
xml_get_val_int64_args(const uint8_t *xml_data, size_t xml_data_size,
    const uint8_t **next_pos, int64_t *val_ret, const uint8_t *tag1, ...) {
	int error;
	const uint8_t *tag_arr[XML_MAX_LEVELS];
	const uint8_t *val = NULL;
	size_t val_size = 0, tag_arr_count, tag_arr_cnt[XML_MAX_LEVELS];
	va_list va;

	if (NULL == xml_data || 0 == xml_data_size || NULL == val_ret || NULL == tag1)
		return (EINVAL);
	/* Load args to local array. */
	tag_arr[0] = tag1;
	tag_arr_cnt[0] = strlen((const char*)tag1);
	va_start(va, tag1);
	for (tag_arr_count = 1; XML_MAX_LEVELS > tag_arr_count; tag_arr_count ++) {
		tag_arr[tag_arr_count] = va_arg(va, const uint8_t*);
		if (NULL == tag_arr[tag_arr_count]) {
			tag_arr_cnt[tag_arr_count] = 0;
			break;
		}
		tag_arr_cnt[tag_arr_count] = strlen((const char*)tag_arr[tag_arr_count]);
	}
	va_end(va);
	error = xml_get_val_arr(xml_data, xml_data_size, next_pos,
	    tag_arr_count, &tag_arr[0], &tag_arr_cnt[0], NULL, 0,
	    &val, &val_size);
	if (0 != error)
		return (error);
	(*val_ret) = UStr8ToNum64(val, val_size);
	return (0);
}

size_t
xml_calc_tag_count_args(const uint8_t *xml_data, size_t xml_data_size,
    const uint8_t *tag1, ...) {
	size_t ret = 0;
	const uint8_t *next_pos = NULL;
	const uint8_t *tag_arr[XML_MAX_LEVELS];
	size_t tag_arr_count, tag_arr_cnt[XML_MAX_LEVELS];
	va_list va;

	if (NULL == xml_data || 0 == xml_data_size || NULL == tag1)
		return (ret);
	/* Load args to local array. */
	tag_arr[0] = tag1;
	tag_arr_cnt[0] = strlen((const char*)tag1);
	va_start(va, tag1);
	for (tag_arr_count = 1; XML_MAX_LEVELS > tag_arr_count; tag_arr_count ++) {
		tag_arr[tag_arr_count] = va_arg(va, const uint8_t*);
		if (NULL == tag_arr[tag_arr_count]) {
			tag_arr_cnt[tag_arr_count] = 0;
			break;
		}
		tag_arr_cnt[tag_arr_count] = strlen((const char*)tag_arr[tag_arr_count]);
	}
	va_end(va);
	while (0 == xml_get_val_arr(xml_data, xml_data_size, &next_pos,
	    tag_arr_count, &tag_arr[0], &tag_arr_cnt[0], NULL, 0, NULL, 0)) {
		ret ++;
	}
	return (ret);
}



int
xml_get_val_ns_arr(const uint8_t *xml_data, size_t xml_data_size,
    const uint8_t **next_pos,
    size_t tag_arr_count, const uint8_t **tag_arr, size_t *tag_arr_cnt,
    const uint8_t **ret_ns, size_t *ret_ns_size,
    const uint8_t **ret_attr, size_t *ret_attr_size,
    const uint8_t **ret_value, size_t *ret_value_size) {
	int ee;
	const uint8_t *xml_data_end, *TagStart, *TagEnd, *NameSpStart = NULL, *NameSpEnd;
	const uint8_t *TagNameStart, *TagNameEnd, *attr = NULL, *value = NULL;
	size_t cur_tag = 0, data_avail, attr_size = 0;
	ssize_t level = 0;

	if (NULL == xml_data || 0 == xml_data_size || 0 == tag_arr_count ||
	    NULL == tag_arr || NULL == tag_arr_cnt || NULL == ret_ns_size)
		return (EINVAL);

	mem_bzero(ret_ns_size, (sizeof(size_t) * tag_arr_count));
	if (NULL != next_pos && xml_data <= (*next_pos) &&
	    (xml_data + xml_data_size) > (*next_pos)) {
		TagEnd = (*next_pos);
		cur_tag = ((TagEnd == xml_data) ? 0 : (tag_arr_count - 1));
	} else { /* Not set or Out of range. */
		TagEnd = xml_data;
	}
	xml_data_end = (xml_data + xml_data_size);
	for (;;) {
		TagStart = mem_chr_ptr(TagEnd, xml_data, xml_data_size, '<');
		if (NULL == TagStart)
			return (ESPIPE);
		TagStart ++;
		data_avail = (size_t)(xml_data_end - TagStart);
		switch ((*TagStart)) {
		case '?': /* <?...?> processing instructions */
			TagEnd = mem_find_ptr_cstr(TagStart, xml_data, xml_data_size, "?>");
			if (NULL == TagEnd)
				return (ESPIPE);
			TagEnd += 2;
			continue;
		case '!':
			TagStart ++;
			data_avail --;
			if (2 < data_avail && 0 == memcmp(TagStart, "--", 2)) { /* <!-- xml comment --> */
				TagStart += 2;
				TagEnd = mem_find_ptr_cstr(TagStart, xml_data, xml_data_size, "-->");
				if (NULL == TagEnd)
					return (ESPIPE);
				TagEnd += 3;
				continue;
			} else if (7 < data_avail && 0 == memcmp(TagStart, "[CDATA[", 7)) { /* <![CDATA] cdata ]]> */
				TagStart += 7;
				TagEnd = mem_find_ptr_cstr(TagStart, xml_data, xml_data_size, "]]>");
				if (NULL == TagEnd)
					return (ESPIPE);
				TagEnd += 3;
				continue;
			} else if (7 < data_avail && 0 == memcmp(TagStart, "DOCTYPE", 7)) { /* dtd */
				TagStart += 7;
				TagEnd = mem_chr_ptr(TagStart, xml_data, xml_data_size, '>');
				if (NULL == TagEnd)
					return (ESPIPE);
				TagEnd ++;
				continue;
			}
			return (ESPIPE);
		case '>':  /* "<>" - may cause infinite loop */
			TagEnd = (TagStart + 1);
			continue;
		case '/': /* close tag "</...>" */
			TagEnd = mem_chr_ptr(TagStart, xml_data, xml_data_size, '>');
			if (NULL == TagEnd)
				return (ESPIPE);
			TagEnd --;
			if (TagEnd == TagStart) /* "</>" do notfing */
				continue;
			TagNameStart = (TagStart + 1); /* = ... + '/' */
			level --;
			//LOG_EV_FMT("tag cmp (%zu) = %s", ((TagEnd + 1) - TagNameStart), TagNameStart);
			if (0 <= level) /* Close some sub tag. */
				continue;
			if (0 != ret_ns_size[(cur_tag - 1)]) { /* Fix name space. */
				TagNameStart += (ret_ns_size[(cur_tag - 1)] + 1); /* = 'ns' + ':' */
			}
			if (0 != mem_cmpn(tag_arr[(cur_tag - 1)], tag_arr_cnt[(cur_tag -1)],
			    TagNameStart, (size_t)((TagEnd + 1) - TagNameStart))) /* Is name close qual name open? */
				continue;
			cur_tag --; /* tag close, up one tag level */
			level = 0;
			//LOG_EV_FMT("close tag_arr (%zu) = %s", tag_arr_cnt[cur_tag], tag_arr[cur_tag]);
			if (NULL == value) /* cur_tag < tag_arr_count */
				continue;
			/* Found, return OK. */
			if (NULL != next_pos) {
				(*next_pos) = (TagEnd + 2);
			}
			if (NULL != ret_attr) {
				(*ret_attr) = attr;
			}
			if (NULL != ret_attr_size) {
				(*ret_attr_size) = attr_size;
			}
			if (NULL != ret_value || NULL != ret_value_size) {
				data_avail = (size_t)((TagStart - 1) - value);
				/* Extract CDATA */
				TagStart = mem_chr(value, data_avail, '<');
				if (NULL != TagStart &&
				    8 < (size_t)(data_avail - (size_t)(TagStart - value)) &&
				    0 == memcmp((TagStart + 1), "![CDATA[", 8)) {
					TagStart += 9;
					TagEnd = mem_find_ptr_cstr(TagStart, value, data_avail, "]]>");
					if (NULL != TagEnd) {
						value = TagStart;
						data_avail = (size_t)(TagEnd - value);
					}
				}
				if (NULL != ret_value) {
					(*ret_value) = value;
				}
				if (NULL != ret_value_size) {
					(*ret_value_size) = data_avail;
				}
			}
			return (0);
		case '_': /* new tag */
		case ':':
		default:
			TagEnd = mem_chr_ptr(TagStart, xml_data, xml_data_size, '>');
			if (NULL == TagEnd)
				return (ESPIPE);
			TagEnd --;
			ee = ('/' == (*TagEnd)); /* <ns:foo /> - no data in element. */
			if (0 != ee) {
				TagEnd --;
			} else {
				level ++;
			}
			/* Look for name end. */
			TagNameStart = TagStart;
			for (TagNameEnd = TagNameStart;
			    0 == is_space((*TagNameEnd)) && TagNameEnd < TagEnd;
			    TagNameEnd ++)
				;
			if (is_space((*TagNameEnd))) { /* <ns:foo attr="attr val"...> */
				TagNameEnd --;
			}
			//LOG_EV_FMT("tag cmp (%zu) = %s", ((TagNameEnd + 1) - TagNameStart), TagNameStart);
			if (1 != level &&
			    0 == ee) /* Open some sub tag. */
				continue;
			NameSpEnd = mem_chr(TagNameStart,
			    (size_t)((TagNameEnd + 1) - TagNameStart), ':');
			if (NULL != NameSpEnd) {
				NameSpStart = TagNameStart;
				TagNameStart = (NameSpEnd + 1);
			}
			if (0 != mem_cmpn(tag_arr[cur_tag], tag_arr_cnt[cur_tag],
			    TagNameStart, (size_t)((TagNameEnd + 1) - TagNameStart)))
				continue; /* Name not match. */
			/* Found target tag. */
			if (NULL != ret_ns) {
				ret_ns[cur_tag] = NameSpStart;
			}
			//if (NULL != ret_ns_size)
			ret_ns_size[cur_tag] = ((NULL == NameSpEnd) ? 0 : (size_t)(NameSpEnd - NameSpStart));
			//LOG_EV_FMT("open tag_arr (%zu) = %s", tag_arr_cnt[cur_tag], tag_arr[cur_tag]);
			level = 0;
			cur_tag ++;
			if (cur_tag < tag_arr_count)
				continue;
			/* Our final target. */
			value = (TagEnd + 2);
			for (attr = (TagNameEnd + 1);
			    0 != is_space((*attr)) && attr < TagEnd; attr ++)
				;
			attr_size = (size_t)((TagEnd + 1) - attr);
			if (0 == ee)
				continue;
			/* <ns:foo /> - no data in element. */
			/* Found, return OK. */
			if (NULL != next_pos) {
				(*next_pos) = (TagEnd + 2);
			}
			if (NULL != ret_attr) {
				(*ret_attr) = NULL;
			}
			if (NULL != ret_attr_size) {
				(*ret_attr_size) = 0;
			}
			if (NULL != ret_value) {
				(*ret_value) = NULL;
			}
			if (NULL != ret_value_size) {
				(*ret_value_size) = 0;
			}
			return (0);
		} /* end switch */
	} /* end for */
	return (ESPIPE);
}


int
xml_get_val_ns_args(const uint8_t *xml_data, size_t xml_data_size,
    const uint8_t **next_pos,
    const uint8_t **ret_ns, size_t *ret_ns_size,
    const uint8_t **ret_attr, size_t *ret_attr_size,
    const uint8_t **ret_value, size_t *ret_value_size,
    const uint8_t *tag1, ...) {
	const uint8_t *tag_arr[XML_MAX_LEVELS];
	size_t tag_arr_count, tag_arr_cnt[XML_MAX_LEVELS], ns_size[XML_MAX_LEVELS];
	va_list va;

	/* Load args to local array. */
	tag_arr[0] = tag1;
	tag_arr_cnt[0] = strlen((const char*)tag1);
	va_start(va, tag1);
	for (tag_arr_count = 1; XML_MAX_LEVELS > tag_arr_count; tag_arr_count ++) {
		tag_arr[tag_arr_count] = va_arg(va, const uint8_t*);
		if (NULL == tag_arr[tag_arr_count])
			break;
		tag_arr_cnt[tag_arr_count] = strlen((const char*)tag_arr[tag_arr_count]);
		//LOG_EV_FMT("tag_arr (%zu) = %s", tag_arr_cnt[tag_arr_count], tag_arr[tag_arr_count]);
	}
	va_end(va);
	if (NULL == ret_ns_size) {
		ret_ns_size = &ns_size[0];
	}
	return (xml_get_val_ns_arr(xml_data, xml_data_size, next_pos,
	    tag_arr_count, &tag_arr[0], &tag_arr_cnt[0],
	    ret_ns, ret_ns_size,
	    ret_attr, ret_attr_size, 
	    ret_value, ret_value_size));
}
