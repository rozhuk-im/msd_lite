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


#ifndef __XML_H__
#define __XML_H__

#include <sys/types.h>
#include <inttypes.h>

#ifndef XML_MAX_LEVELS
#define XML_MAX_LEVELS	32
#endif



int	xml_decode(const uint8_t *encoded, size_t encoded_size,
	    uint8_t *xml, size_t xml_buf_size, size_t *xml_size);
int	xml_encode(const uint8_t *xml, size_t xml_size, uint8_t *encoded,
	    size_t encoded_buf_size, size_t *encoded_size);

int	xml_get_val_arr(const uint8_t *xml_data, size_t xml_data_size,
	    const uint8_t **next_pos,
	    size_t tag_arr_count, const uint8_t **tag_arr, size_t *tag_arr_cnt,
	    const uint8_t **ret_attr, size_t *ret_attr_size,
	    const uint8_t **ret_value, size_t *ret_value_size);
int	xml_get_val_args(const uint8_t *xml_data, size_t xml_data_size,
	    const uint8_t **next_pos,
	    const uint8_t **ret_attr, size_t *ret_attr_size,
	    const uint8_t **ret_value, size_t *ret_value_size,
	    const uint8_t *tag1, ...);
int	xml_get_val_size_t_args(const uint8_t *xml_data, size_t xml_data_size,
	    const uint8_t **next_pos, size_t *val_ret, const uint8_t *tag1, ...);
int	xml_get_val_ssize_t_args(const uint8_t *xml_data, size_t xml_data_size,
	    const uint8_t **next_pos, ssize_t *val_ret, const uint8_t *tag1, ...);
int	xml_get_val_uint32_args(const uint8_t *xml_data, size_t xml_data_size,
	    const uint8_t **next_pos, uint32_t *val_ret, const uint8_t *tag1, ...);
int	xml_get_val_int32_args(const uint8_t *xml_data, size_t xml_data_size,
	    const uint8_t **next_pos, int32_t *val_ret, const uint8_t *tag1, ...);
int	xml_get_val_uint64_args(const uint8_t *xml_data, size_t xml_data_size,
	    const uint8_t **next_pos, uint64_t *val_ret, const uint8_t *tag1, ...);
int	xml_get_val_int64_args(const uint8_t *xml_data, size_t xml_data_size,
	    const uint8_t **next_pos, int64_t *val_ret, const uint8_t *tag1, ...);
size_t	xml_calc_tag_count_args(const uint8_t *xml_data, size_t xml_data_size,
	    const uint8_t *tag1, ...);

int	xml_get_val_ns_arr(const uint8_t *xml_data, size_t xml_data_size,
	    const uint8_t **next_pos,
	    size_t tag_arr_count, const uint8_t **tag_arr, size_t *tag_arr_cnt,
	    const uint8_t **ret_ns, size_t *ret_ns_size,
	    const uint8_t **ret_attr, size_t *ret_attr_size,
	    const uint8_t **ret_value, size_t *ret_value_size);
int	xml_get_val_ns_args(const uint8_t *xml_data, size_t xml_data_size,
	    const uint8_t **next_pos,
	    const uint8_t **ret_ns, size_t *ret_ns_size,
	    const uint8_t **ret_attr, size_t *ret_attr_size,
	    const uint8_t **ret_value, size_t *ret_value_size,
	    const uint8_t *tag1, ...);


#endif /* __XML_H__ */
