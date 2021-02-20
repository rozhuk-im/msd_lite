/*-
 * Copyright (c) 2011 - 2012 Rozhuk Ivan <rozhuk.im@gmail.com>
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


#ifndef __BT_ENCODE_H__
#define __BT_ENCODE_H__



#define BT_EN_TYPE_STR	0
#define BT_EN_TYPE_NUM	1
#define BT_EN_TYPE_LIST	2
#define BT_EN_TYPE_DICT	3
#define BT_EN_TYPE_ALL	255


typedef struct bt_en_node_s *bt_en_node_p;

/*
 * XXX: the "val" field of be_dict and be_node can be confusing ...
 */

typedef struct be_en_dict_s {
	bt_en_node_p key;
	bt_en_node_p val;
} be_en_dict_t, *be_en_dict_p;



typedef struct bt_en_node_s {
	uint8_t	type; // see BT_EN_TYPE_*
	uint8_t *raw; // pointer to raw data
	size_t	raw_size; // size of raw data: s- str len; i - numbers count (from 'i' to 'e')
	union {
		uint8_t		*s;
		int64_t		i;
		bt_en_node_p	*l;
		be_en_dict_p	d;
	} val;
	size_t	val_count; // number of values, for i and s allways 1
} bt_en_node_t;




bt_en_node_p  bt_en_alloc(uint8_t type, uint8_t *raw, size_t raw_size);
void	bt_en_free(bt_en_node_p node);
int	bt_en_decode(uint8_t *buf, size_t buf_size, bt_en_node_p *ret_data,
	    size_t *ret_buf_off);
int	bt_dict_find(bt_en_node_p node, size_t *cur_off, const uint8_t *key_name,
	    size_t key_name_size, uint8_t key_type, bt_en_node_p *ret_data);









#endif /* __BT_ENCODE_H__ */
