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


#include <sys/types.h>
#include <stdlib.h>
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <errno.h>

#include "mem_helpers.h"
#include "macro_helpers.h"
#include "core_net_helpers.h"
#include "bt_encode.h"
#include "bt_tracker.h"




bt_tr_ann_ans_p
bt_tr_ann_ans_alloc(void) {

	return (zalloc(sizeof(bt_tr_ann_ans_t)));
}


void
bt_tr_ann_ans_free(bt_tr_ann_ans_p tr_ans) {

	if (NULL == tr_ans)
		return;
	if (NULL != tr_ans->peers)
		free(tr_ans->peers);
	free(tr_ans);
}


/* parce/decode bencoded answer from tracker, by http
 *
 * NOTE:
 * strings and other pointers - pointed to buf, so you mast
 * keep buf with all content unchanged until returned 
 * bt_tr_ann_ans_t is used
 */
int
bt_tr_ann_ans_decode(uint8_t *buf, size_t buf_size, bt_tr_ann_ans_p *ret_data) {
	bt_tr_ann_ans_p tr_ans;
	bt_en_node_p node, val;
	size_t i, tm, off;
	bt_tr_peer_p peers;
	bt_tr_peer_caddr4_p peer4;
	bt_tr_peer_caddr6_p peer6;
	int error;

	if (NULL == buf || 0 == buf_size || NULL == ret_data)
		return (EINVAL);

	// process buf data
	error = bt_en_decode(buf, buf_size, &node, NULL);
	if (0 != error) {// decode error
		(*ret_data) = NULL;
		return (error);
	}
	if (BT_EN_TYPE_DICT != node->type) {// invalid data type
		bt_en_free(node);
		(*ret_data) = NULL;
		return (EINVAL);
	}

	tr_ans = bt_tr_ann_ans_alloc();
	if (NULL == tr_ans) {
		bt_en_free(node);
		return (ENOMEM);
	}

	if (0 == bt_dict_find(node, NULL, (uint8_t*)"failure reason", 14,
	    BT_EN_TYPE_STR, &val)) {
		tr_ans->failure_reason = val->val.s;
		tr_ans->failure_reason_size = val->raw_size;
	}

	// bep 31
	if (0 == bt_dict_find(node, NULL, (uint8_t*)"retry in", 8,
	    BT_EN_TYPE_ALL, &val)) {
		if (BT_EN_TYPE_STR == val->type &&
		    0 == mem_cmpn_cstr("never", val->val.s, val->raw_size)) {
			tr_ans->retry_in = -1;
		} else if (BT_EN_TYPE_NUM == val->type && -1 < val->val.i) {
			tr_ans->retry_in = val->val.i;
		}
	}
	if (0 == bt_dict_find(node, NULL, (uint8_t*)"warning message", 15,
	    BT_EN_TYPE_STR, &val)) {
		tr_ans->warning_message = val->val.s;
		tr_ans->warning_message_size = val->raw_size;
	}
	if (0 == bt_dict_find(node, NULL, (uint8_t*)"interval", 8,
	    BT_EN_TYPE_NUM, &val)) {
		tr_ans->interval = val->val.i;
	}
	if (0 == bt_dict_find(node, NULL, (uint8_t*)"min interval", 12,
	    BT_EN_TYPE_NUM, &val)) {
		tr_ans->min_interval = val->val.i;
	}
	if (0 == bt_dict_find(node, NULL, (uint8_t*)"tracker id", 10,
	    BT_EN_TYPE_STR, &val)) {
		tr_ans->tracker_id = val->val.s;
		tr_ans->tracker_id_size = val->raw_size;
	}
	if (0 == bt_dict_find(node, NULL, (uint8_t*)"complete", 8,
	    BT_EN_TYPE_NUM, &val))
		tr_ans->complete = val->val.i;

	if (0 == bt_dict_find(node, NULL, (uint8_t*)"incomplete", 10,
	    BT_EN_TYPE_NUM, &val)) {
		tr_ans->incomplete = val->val.i;
	}
	if (0 == bt_dict_find(node, NULL, (uint8_t*)"external ip", 11,
	    BT_EN_TYPE_STR, &val)) {
		switch (val->raw_size) {
		case 4: // IPv4
			sain4_init(&tr_ans->ext_ip.sin4);
			//tr_ans->ext_ip.sin4.sin_port = 0;
			sain4_a_set(&tr_ans->ext_ip.sin4, val->val.s);
			break;
		case 16: // IPv6
			sain6_init(&tr_ans->ext_ip.sin6);
			//tr_ans->ext_ip.sin6.sin6_port = 0;
			sain6_a_set(&tr_ans->ext_ip.sin6, val->val.s);
			break;
		default: // unknown/error
			//mem_bzero(&tr_ans->ext_ip, sizeof(bt_tr_ss_addr_t));
			break;
		}
	}

	// process peers IPv4 binary or dictionary model
	if (0 == bt_dict_find(node, NULL, (uint8_t*)"peers", 5,
	    BT_EN_TYPE_ALL, &val)) {
		/* Binary model. */
		if (BT_EN_TYPE_STR == val->type &&
		    sizeof(bt_tr_peer_caddr4_t) <= val->raw_size &&
		    0 == (val->raw_size % sizeof(bt_tr_peer_caddr4_t))) {
			tm = (val->raw_size / sizeof(bt_tr_peer_caddr4_t));
			peers = reallocarray(tr_ans->peers,
			    (tr_ans->peers_count + tm), sizeof(bt_tr_peer_t));
			if (NULL == peers) {
				bt_en_free(node);
				bt_tr_ann_ans_free(tr_ans);
				(*ret_data) = NULL;
				return (ENOMEM);
			}
			/* Copy peers to bt_tr_ann_ans_t. */
			off = tr_ans->peers_count;
			peer4 = (bt_tr_peer_caddr4_p)val->val.s;
			for (i = 0; i < tm; i ++) {
				peers[(i + off)].flags = 0;
				sain4_init(&peers[(i + off)].addr.sin4);
				peers[(i + off)].addr.sin4.sin_port = peer4[i].port;
				sain4_a_set(&peers[(i + off)].addr.sin4,
				    &peer4[i].addr);
				peers[(i + off)].uflags = 0;
			}
			tr_ans->peers = peers;
			tr_ans->peers_count += tm;
		} else if (BT_EN_TYPE_DICT == val->type) { /* Dictionary model. */
		
		}
	}

	/* Bep 7: peers6 IPv6 binary or dictionary model. */
	if (0 == bt_dict_find(node, NULL, (uint8_t*)"peers6", 6,
	    BT_EN_TYPE_ALL, &val)) {
		/* Binary model. */
		if (BT_EN_TYPE_STR == val->type &&
		    sizeof(bt_tr_peer_caddr6_t) <= val->raw_size &&
		    0 == (val->raw_size % sizeof(bt_tr_peer_caddr6_t))) {
			tm = (val->raw_size / sizeof(bt_tr_peer_caddr6_t));
			peers = reallocarray(tr_ans->peers,
			    (tr_ans->peers_count + tm), sizeof(bt_tr_peer_t));
			if (NULL == peers) {
				bt_en_free(node);
				bt_tr_ann_ans_free(tr_ans);
				(*ret_data) = NULL;
				return (ENOMEM);
			}
			/* Copy peers to bt_tr_ann_ans_t. */
			off = tr_ans->peers_count;
			peer6 = (bt_tr_peer_caddr6_p)val->val.s;
			for (i = 0; i < tm; i ++) {
				peers[(i + off)].flags = 0;
				sain6_init(&peers[(i + off)].addr.sin6);
				peers[(i + off)].addr.sin6.sin6_port = peer6[i].port;
				sain6_a_set(&peers[(i + off)].addr.sin6,
				    &peer6[i].addr);
				peers[(i + off)].uflags = 0;
			}
			tr_ans->peers = peers;
			tr_ans->peers_count += tm;
		} else if (BT_EN_TYPE_DICT == val->type) { /* Dictionary model. */
		
		}
	}
	(*ret_data) = tr_ans;
	bt_en_free(node);

	return (0);
}


int
bt_tr_req_ev_get(uint8_t *buf, size_t buf_size) {
	int i;

	if (NULL == buf || 0 == buf_size)
		return (BT_TR_REQ_EV_NONE);
	for (i = BT_TR_REQ_EV_STARTED; i < BT_TR_REQ_EV_UNKNOWN; i ++) {
		if (0 == mem_cmpin(buf, buf_size, bt_tr_req_event[i],
		    bt_tr_req_event_size[i]))
			return (i);
	}
	return (BT_TR_REQ_EV_UNKNOWN);
}
