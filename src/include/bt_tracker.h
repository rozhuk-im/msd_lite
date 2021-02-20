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


#ifndef __BT_TRACKER_H__
#define __BT_TRACKER_H__


#include <sys/socket.h>
#include <netinet/in.h>




/* compact analog of struct sockaddr_storage */
union bt_tr_ss_addr {
	struct sockaddr		sa;
	struct sockaddr_in	sin4;
	struct sockaddr_in6	sin6;	// 28 bytes
	uint8_t			pad[32]; // struct sockaddr_storage
};
typedef union bt_tr_ss_addr bt_tr_ss_addr_t, *bt_tr_ss_addr_p;



typedef struct bt_tr_peer_s {
	uint32_t	flags;		// flags, internal
	uint8_t 	peer_id[20];	// peer's self-selected ID, as described above for the tracker request (string)
	bt_tr_ss_addr_t	addr;		// peer's IP address either IPv6 (hexed) or IPv4 (dotted quad) or DNS name (string)
	uint64_t	uflags;		/* User flags / pad. */
} bt_tr_peer_t, *bt_tr_peer_p; // 4 + 20 + 32 + 8 = 64 bytes

#define BT_TRACKER_PEER_F_ID_SET	1 // peer_id contain valid data



typedef struct bt_tr_peer_compact4_s { // 4 + 2 = 6 bytes
	struct in_addr	addr;		// peer's IPv4 address
	uint16_t	port;		// peer's port number (integer)
} __attribute__((__packed__)) bt_tr_peer_caddr4_t, *bt_tr_peer_caddr4_p;



typedef struct bt_tr_peer_compact6_s { // 16 + 2 = 18 bytes
	struct in6_addr	addr;		// peer's IPv6 address
	uint16_t	port;		// peer's port number (integer)
} __attribute__((__packed__)) bt_tr_peer_caddr6_t, *bt_tr_peer_caddr6_p;


/* Answer... */

typedef struct bt_tr_ann_ans_s { /* Tracker announce answer. */
	uint8_t		*failure_reason;	// If present, then no other keys may be present
	size_t		failure_reason_size;
	uint64_t	retry_in;		// bep 31: -1: never, 0: not set
	uint8_t		*warning_message;	// (new, optional) Similar to failure reason, but the response still gets processed normally
	size_t		warning_message_size;
	uint64_t	interval;		// Interval in seconds that the client should wait between sending regular requests to the tracker
	uint64_t	min_interval;		// (optional) Minimum announce interval. If present clients must not reannounce more frequently than this
	uint8_t		*tracker_id;		// A string that the client should send back on its next announcements
	size_t		tracker_id_size;
	uint64_t	complete;		// number of peers with the entire file, i.e. seeders (integer)
	uint64_t	incomplete;		// number of non-seeder peers, aka "leechers" (integer)
	bt_tr_ss_addr_t	ext_ip;		// bep24: tracker return external IP
	bt_tr_peer_p	peers;		// ipv4 peers
	size_t		peers_count;
} bt_tr_ann_ans_t, *bt_tr_ann_ans_p;




bt_tr_ann_ans_p bt_tr_ann_ans_alloc(void);
void	bt_tr_ann_ans_free(bt_tr_ann_ans_p data);
int	bt_tr_ann_ans_decode(uint8_t *buf, size_t buf_size, bt_tr_ann_ans_p *ret_data);




/* Request... */

#define BT_TR_REQ_PR_INFOHASH	0
#define BT_TR_REQ_PR_PEERID	1
#define BT_TR_REQ_PR_PORT	2
#define BT_TR_REQ_PR_UPLOADED	3
#define BT_TR_REQ_PR_DOWNLOADED	4
#define BT_TR_REQ_PR_LEFT	5
#define BT_TR_REQ_PR_CORRUPT	6
#define BT_TR_REQ_PR_KEY	7
#define BT_TR_REQ_PR_TRACKERID	8
#define BT_TR_REQ_PR_EVENT	9
#define BT_TR_REQ_PR_NUMWANT	10
#define BT_TR_REQ_PR_COMPACT	11
#define BT_TR_REQ_PR_NOPEERID	12
#define BT_TR_REQ_PR_IP		13
#define BT_TR_REQ_PR_IPV4	14
#define BT_TR_REQ_PR_IPV6	15

static const uint8_t *bt_tr_req_param[] = {
	(uint8_t*)"info_hash",
	(uint8_t*)"peer_id",
	(uint8_t*)"port",
	(uint8_t*)"uploaded",
	(uint8_t*)"downloaded",
	(uint8_t*)"left",
	/* Optional */
	(uint8_t*)"corrupt",
	(uint8_t*)"key",
	(uint8_t*)"trackerid",
	(uint8_t*)"event",
	(uint8_t*)"numwant",
	(uint8_t*)"compact",
	(uint8_t*)"no_peer_id",
	(uint8_t*)"ip",
	(uint8_t*)"ipv6",
	(uint8_t*)"ipv4",
	NULL
};
static const size_t bt_tr_req_param_size[] = {
	9,
	7,
	4,
	8,
	10,
	4, /* left */
	7,
	3,
	9,
	5, /* event */
	7,
	7,
	10, /* no_peer_id */
	2,
	4,
	4,
	0
};
static const uint8_t bt_tr_req_param_required[] = {
	BT_TR_REQ_PR_INFOHASH,
	BT_TR_REQ_PR_PEERID,
	BT_TR_REQ_PR_PORT,
	BT_TR_REQ_PR_UPLOADED,
	BT_TR_REQ_PR_DOWNLOADED,
	BT_TR_REQ_PR_LEFT
};
static const uint8_t bt_tr_req_param_optional[] = {
	BT_TR_REQ_PR_CORRUPT,
	BT_TR_REQ_PR_KEY,
	BT_TR_REQ_PR_TRACKERID,
	BT_TR_REQ_PR_EVENT,
	BT_TR_REQ_PR_NUMWANT,
	BT_TR_REQ_PR_COMPACT,
	BT_TR_REQ_PR_NOPEERID,
	BT_TR_REQ_PR_IP,
	BT_TR_REQ_PR_IPV4,
	BT_TR_REQ_PR_IPV6
};



#define BT_TR_REQ_EV_NONE	0
#define BT_TR_REQ_EV_STARTED	1
#define BT_TR_REQ_EV_STOPPED	2
#define BT_TR_REQ_EV_COMPLETED	3
#define BT_TR_REQ_EV_PAUSED	4
#define BT_TR_REQ_EV_UNKNOWN	5

static const uint8_t *bt_tr_req_event[] = {
	(uint8_t *)"none",		/* For logs only. size=0 */
	(uint8_t *)"started",
	(uint8_t *)"stopped",
	(uint8_t *)"completed",
	(uint8_t *)"paused",	/* http://bittorrent.org/beps/bep_0021.html */
	(uint8_t *)"unknown"	/* For logs only. size=0 */
};
static const size_t bt_tr_req_event_size[] = {
	0,
	7,
	7,
	9,
	6,
	0
};


int	bt_tr_req_ev_get(uint8_t *buf, size_t buf_size);


#endif /* __BT_TRACKER_H__ */
