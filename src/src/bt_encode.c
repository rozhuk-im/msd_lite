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
 * Based on: http://funzix.git.sourceforge.net/git/gitweb.cgi?p=funzix/funzix;a=blob;f=bencode/bencode.c
 * Written by: Mike Frysinger <vapier@gmail.com>
 *
 */

/*
 * http://wiki.theory.org/BitTorrentSpecification
 */


#include <sys/types.h>
#include <stdlib.h>
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <errno.h>


#include "mem_helpers.h"
#include "StrToNum.h"
#include "bt_encode.h"


#define BT_EN_PRE_ALLOC_ITEMS	64



/*
 * Allocate bt encoded node and set some values
 */
bt_en_node_p
bt_en_alloc(uint8_t type, uint8_t *raw, size_t raw_size) {
	bt_en_node_p ret;
	
	ret = zalloc(sizeof(bt_en_node_t));
	if (NULL == ret)
		return (NULL);
	ret->type = type;
	ret->raw_size = raw_size;
	ret->raw = raw;

	return (ret);
}

/*
 * Free bt encoded node and all other containing nodes
 */
void
bt_en_free(bt_en_node_p node) {
	size_t i;

	if (NULL == node)
		return;

	switch (node->type) {
	case BT_EN_TYPE_STR:
	case BT_EN_TYPE_NUM:
		break;
	case BT_EN_TYPE_LIST:
		for (i = 0; i < node->val_count; i ++)
			bt_en_free(node->val.l[i]);
		free(node->val.l);
		break;
	case BT_EN_TYPE_DICT:
		for (i = 0; i < node->val_count; i ++) {
			bt_en_free(node->val.d[i].key);
			bt_en_free(node->val.d[i].val);
		}
		free(node->val.d);
		break;
	}
	free(node);
}


/*
 * Decode buf data to allocated bt_en_node_t struct,
 * return pointer to bt_en_node_t and offset in buffer were node end
 *
 * NOTE:
 * byte strings and other pointers - pointed to buf, so you mast
 * keep buf with all content unchanged until returned bt_en_node_t used
 */
int
bt_en_decode(uint8_t *buf, size_t buf_size, bt_en_node_p *ret_data, size_t *ret_buf_off) {
	size_t raw_size, buf_off, items_allocated, items_count;
	uint8_t *ptm, *cur_pos, *buf_max;
	bt_en_node_p *l;
	be_en_dict_p d;
	int error;

	if (NULL == buf || 0 == buf_size || NULL == ret_data)
		return (EINVAL);

	buf_max = (buf + buf_size);
	(*ret_data) = NULL;

	switch ((*buf)) {
	case '0': /* byte strings */
	case '1': /* <string length encoded in base ten ASCII>:<string data> */
	case '2': /* example: ...5:01234... */
	case '3': /* example: ...5:abcde... */
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		/* Find end of num, num = byte string len. */
		ptm = mem_chr_off(1, buf, buf_size, ':');
		if (NULL == ptm)
			return (EBADMSG);
		/* Convert and check len. */
		raw_size = UStr8ToUNum(buf, (ptm - buf));
		ptm ++;
		if (buf_max <= (raw_size + ptm))
			return (EBADMSG); /* Out of buff range. */
		/* Allocate node for returning data. */
		(*ret_data) = bt_en_alloc(BT_EN_TYPE_STR, ptm, raw_size);
		if (NULL == (*ret_data))
			return (ENOMEM);
		/* Store data and return OK. */
		(*ret_data)->val.s = ptm;
		(*ret_data)->val_count = 1;
		if (NULL != ret_buf_off)
			(*ret_buf_off) = (raw_size + (ptm - buf));
		return (0);
		break;
	case 'i': /* integers, i<integer encoded in base ten ASCII>e , example: ...i852e... */
		cur_pos = (buf + 1); /* skeep 'i' */
		/* Loooking for end of integer. */
		ptm = mem_chr_off(1, buf, buf_size, 'e');
		if (NULL == ptm)
			return (EBADMSG);
		/* Allocate node for returning data. */
		(*ret_data) = bt_en_alloc(BT_EN_TYPE_NUM, cur_pos, (ptm - cur_pos));
		if (NULL == (*ret_data))
			return (ENOMEM);
		/* Store data and return OK. */
		(*ret_data)->val.i = UStr8ToNum64(cur_pos, (ptm - cur_pos));
		(*ret_data)->val_count = 1;
		if (NULL != ret_buf_off)
			(*ret_buf_off) = ((ptm - buf) + 1); /* 1: 'e' */
		return (0);
		break;
	case 'l': /* lists: l<bencoded values>e , Example: l4:spam4:eggse */
		cur_pos = (buf + 1); /* Skeep 'l' */
		l = NULL;
		items_count = 0;
		items_allocated = 0;
		/* Decode and store list items. */
		for (;;) {
			/* Check: is we need re pre alloc memmory for list items. */
			error = realloc_items((void**)&l,
			    sizeof(bt_en_node_p), &items_allocated,
			    BT_EN_PRE_ALLOC_ITEMS, items_count);
			if (0 != error)
				break;
			/* Decode and store list element. */
			error = bt_en_decode(cur_pos, (buf_max - cur_pos),
			    &l[items_count], &buf_off);
			if (0 != error)
				break;
			items_count ++;
			cur_pos += buf_off;
			/* Is we in buff range? */
			if (buf_max < cur_pos) {
				error = EBADMSG; /* Out of range. */
				break;
			}
			/* Is it end of list? */
			if ('e' == (*cur_pos))
				break; /* All done. */
		}
		/* Allocate node for returning data. */
		if (0 == error) {
			(*ret_data) = bt_en_alloc(BT_EN_TYPE_LIST, (buf + 1),
			    ((cur_pos - buf) - 2)); /* 2: 'l' + 'e' */
			if (NULL == (*ret_data))
				error = ENOMEM;
		}
		/* Fail, free nodes = list items. */
		if (0 != error) {
			for (buf_off = 0; buf_off < items_count; buf_off ++) {
				bt_en_free(l[buf_off]);
			}
			free(l);

			if (NULL != (*ret_data))
				free((*ret_data));
			(*ret_data) = NULL;
			return (error);
		}
		/* Store data and return OK. */
		l = reallocarray(l, (items_count + 1), sizeof(bt_en_node_p));
		(*ret_data)->val.l = l;
		(*ret_data)->val_count = items_count;
		if (NULL != ret_buf_off)
			(*ret_buf_off) = ((cur_pos - buf) + 1); /* 1: 'e' */
		return (0);
		break;
	case 'd': /* dictionaries, d<bencoded string><bencoded element>e */
		cur_pos = (buf + 1); // skeep 'd'
		d = NULL;
		items_count = 0;
		items_allocated = 0;
		/* Decode and store dictonary items. */
		for (;;) {
			/* Check: is we need re pre allocate memmory for list items. */
			error = realloc_items((void**)&d,
			    sizeof(be_en_dict_t), &items_allocated,
			    BT_EN_PRE_ALLOC_ITEMS, items_count);
			if (0 != error)
				break;
			/* Dict key. */
			error = bt_en_decode(cur_pos, (buf_max - cur_pos),
			    &d[items_count].key, &buf_off);
			if (0 != error)
				break;
			/* Key mast bee string. */
			if (d[items_count].key->type != BT_EN_TYPE_STR) {
				bt_en_free(d[items_count].key);
				break;
			}
			cur_pos += buf_off;
			/* Value. */
			error = bt_en_decode(cur_pos, (buf_max - cur_pos),
			    &d[items_count].val, &buf_off);
			if (0 != error) {
				bt_en_free(d[items_count].key);
				break;
			}
			items_count ++;
			cur_pos += buf_off;
			/* Is we in buff range? */
			if (buf_max < cur_pos) {
				error = EBADMSG; /* Out of range. */
				break;
			}
			/* Is it end of list? */
			if ('e' == (*cur_pos))
				break; /* All done. */
		}
		/* Allocate node for returning data. */
		if (0 == error) {
			(*ret_data) = bt_en_alloc(BT_EN_TYPE_DICT, (buf + 1),
			    ((cur_pos - buf) - 2)); /* 2: 'd' + 'e' */
			if (NULL == (*ret_data))
				error = ENOMEM;
		}
		/* Fail, free nodes = dict items. */
		if (0 != error) { /* Fail, free nodes. */
			for (buf_off = 0; buf_off < items_count; buf_off ++) {
				bt_en_free(d[buf_off].key);
				bt_en_free(d[buf_off].val);
			}
			free(d);

			if (NULL != (*ret_data))
				free((*ret_data));
			(*ret_data) = NULL;
			return (error);
		}
		/* Store data and return OK. */
		d = reallocarray(d, (items_count + 1), sizeof(be_en_dict_t));
		(*ret_data)->val.d = d;
		(*ret_data)->val_count = items_count;
		if (NULL != ret_buf_off)
			(*ret_buf_off) = ((cur_pos - buf) + 1); /* 1: 'e' */
		return (0);
		break;
	default: /* Unknown / invalid. */
		return (EBADMSG);
		break;
	}

	return (0);
}


/*
 * Find bt_en_node_t struct by name and type
 * in dictonaru bt_en_node_t, from offset (= index)
 * return pointer to bt_en_node_t and offset (= index)
 */
int
bt_dict_find(bt_en_node_p node, size_t *cur_off, const uint8_t *key_name,
    size_t key_name_size, uint8_t key_type, bt_en_node_p *ret_data) {
	size_t i;
	be_en_dict_p d;

	if (NULL == node || NULL == key_name || 0 == key_name_size ||
	    NULL == ret_data)
		return (EINVAL);
	if (BT_EN_TYPE_DICT != node->type || 0 == node->val_count)
		return (EINVAL);
	d = node->val.d;
	i = (NULL != cur_off) ? (*cur_off) : 0;
	for (; i < node->val_count; i ++) {
		if ((d[i].val->type == key_type || BT_EN_TYPE_ALL == key_type) &&
		    0 == mem_cmpn(key_name, key_name_size, d[i].key->val.s, d[i].key->raw_size)) {
			(*ret_data) = d[i].val;
			if (NULL != cur_off)
				(*cur_off) = i;
			return (0);
		}	
	}
	return (-1);
}

