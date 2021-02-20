/*-
 * Copyright (c) 2012 - 2013 Rozhuk Ivan <rozhuk.im@gmail.com>
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
 * RTP: A Transport Protocol for Real-Time Applications
 * RFC 3550
 *
 */

#ifndef __RTP_PROTO_H__
#define __RTP_PROTO_H__

#include <sys/types.h>
#include <inttypes.h>


/*
 * Current protocol version.
 */
#define RTP_VERSION    2

#define RTP_SEQ_MOD (1<<16)
#define RTP_MAX_SDES 255 /* maximum text length for SDES */

typedef enum {
	RTCP_SR		= 200,
	RTCP_RR		= 201,
	RTCP_SDES	= 202,
	RTCP_BYE	= 203,
	RTCP_APP	= 204
} rtcp_type_t;

typedef enum {
	RTCP_SDES_END	= 0,
	RTCP_SDES_CNAME = 1,
	RTCP_SDES_NAME	= 2,
	RTCP_SDES_EMAIL = 3,
	RTCP_SDES_PHONE = 4,
	RTCP_SDES_LOC	= 5,
	RTCP_SDES_TOOL	= 6,
	RTCP_SDES_NOTE	= 7,
	RTCP_SDES_PRIV	= 8
} rtcp_sdes_type_t;


/*
 * RTP data header
 */
typedef struct rtp_hdr_s {
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t version:2; /* Version: identifies the version of RTP. */
	uint8_t p:1;	/* Padding: if set last octet contains a count of how many padding octets should be ignored. */
	uint8_t x:1;	/* Extension header followed. */
	uint8_t cc:4;	/* Count contains the number of CSRC identifiers. */

	uint8_t m:1;	/* Marker: interpretation is defined by a profile. */
	uint8_t pt:7;	/* Identifies the format of the RTP payload. */
#else
	uint8_t cc:4;	/* Count contains the number of CSRC identifiers. */
	uint8_t x:1;	/* Extension header followed. */
	uint8_t p:1;	/* Padding: if set last octet contains a count of how many padding octets should be ignored. */
	uint8_t version:2; /* Version: identifies the version of RTP. */

	uint8_t pt:7;	/* Identifies the format of the RTP payload. */
	uint8_t m:1;	/* Marker: interpretation is defined by a profile. */
#endif
	uint16_t seq;	/* Sequence number. */
	uint32_t ts;	/* Timestamp. */
	uint32_t ssrc;	/* Identifies the synchronization source. */
	//uint32_t csrc list[];/* CSRC identifiers list: 0 to 15 items. */
} __attribute__((__packed__)) rtp_hdr_t, *rtp_hdr_p;

#define RTP_HDR_SN_MAX	0xffff


typedef struct rtp_hdr_ext_s {
	uint16_t custom_data;	/* Defined by profile. */
	uint16_t length;	/* Length: counts the number of 32-bit words in the extension. */
} __attribute__((__packed__)) rtp_hdr_ext_t, *rtp_hdr_ext_p;



/*
 * RTCP common header word
 */
typedef struct {
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t version:2;	/* protocol version */
	uint8_t p:1;		/* padding flag */
	uint8_t count:5;	/* varies by packet type */
#else
	uint8_t count:5;	/* varies by packet type */
	uint8_t p:1;		/* padding flag */
	uint8_t version:2;	/* protocol version */
#endif
	uint8_t pt:8;		/* RTCP packet type */
	uint16_t length;	/* pkt len in words, w/o this word */
} __attribute__((__packed__)) rtcp_common_t;

/*
 * Big-endian mask for version, padding bit and packet type pair
 */
#define RTCP_VALID_MASK (0xc000 | 0x2000 | 0xfe)
#define RTCP_VALID_VALUE ((RTP_VERSION << 14) | RTCP_SR)

/*
 * Reception report block
 */
typedef struct {
	uint32_t ssrc;		/* data source being reported */
	uint8_t fraction:8;	/* fraction lost since last SR/RR */
	int32_t lost:24;	/* cumul. no. pkts lost (signed!) */
	uint32_t last_seq;	/* extended last seq. no. received */
	uint32_t jitter;	/* interarrival jitter */
	uint32_t lsr;		/* last SR packet from this source */
	uint32_t dlsr;		/* delay since last SR packet */
} __attribute__((__packed__)) rtcp_rr_t;

/*
 * SDES item
 */
typedef struct {
	uint8_t type;		/* type of item (rtcp_sdes_type_t) */
	uint8_t length;	/* length of item (in octets) */
	char data[1];		/* text, not null-terminated */
} __attribute__((__packed__)) rtcp_sdes_item_t;

/*
 * One RTCP packet
 */
typedef struct {
	rtcp_common_t common;		/* common header */
	union {
		/* sender report (SR) */
		struct {
			uint32_t ssrc;		/* sender generating this report */
			uint32_t ntp_sec;	/* NTP timestamp */
			uint32_t ntp_frac;
			uint32_t rtp_ts;	/* RTP timestamp */
			uint32_t psent;	/* packets sent */
			uint32_t osent;	/* octets sent */
			rtcp_rr_t rr[1];	/* variable-length list */
		} sr;
		/* reception report (RR) */
		struct {
			uint32_t ssrc;		/* receiver generating this report */
			rtcp_rr_t rr[1];	/* variable-length list */
		} rr;
		/* source description (SDES) */
		struct rtcp_sdes {
			uint32_t src;		/* first SSRC/CSRC */
			rtcp_sdes_item_t item[1]; /* list of SDES items */
		} sdes;
		/* BYE */
		struct {
			uint32_t src[1];	/* list of sources */
			/* can't express trailing text for reason */
		} bye;
	} r;
} __attribute__((__packed__)) rtcp_t;

typedef struct rtcp_sdes rtcp_sdes_t;

/*
 * Per-source state information
 */
typedef struct {
	uint16_t max_seq;	/* highest seq. number seen */
	uint32_t cycles;	/* shifted count of seq. number cycles */
	uint32_t base_seq;	/* base seq number */
	uint32_t bad_seq;	/* last 'bad' seq number + 1 */
	uint32_t probation;	/* sequ. packets till source is valid */
	uint32_t received;	/* packets received */
	uint32_t expected_prior; /* packet expected at last interval */
	uint32_t received_prior; /* packet received at last interval */
	uint32_t transit;	/* relative trans time for prev pkt */
	uint32_t jitter;	/* estimated jitter */
       /* ... */
} __attribute__((__packed__)) rtp_src_info_t, *rtp_src_info_p;


static inline int
rtp_payload_get(const uint8_t *buf, const size_t buf_size,
    size_t *start_off, size_t *end_off) {
	rtp_hdr_p rtp_hdr = (rtp_hdr_p)buf;
	rtp_hdr_ext_p rtp_hdr_ext;
	size_t s_off, e_off = 0;

	if (sizeof(rtp_hdr_t) > buf_size)
		return (EINVAL);
	if (RTP_VERSION != rtp_hdr->version) /* RTP version check. */
		return (EINVAL);
	s_off = (sizeof(rtp_hdr_t) + (sizeof(uint32_t) * rtp_hdr->cc));

	if (rtp_hdr->x) { /* Extension. */
		rtp_hdr_ext = (rtp_hdr_ext_p)(buf + s_off);
		s_off += sizeof(rtp_hdr_ext_t);
		if (s_off > buf_size)
			return (EINVAL);
		s_off += (sizeof(uint32_t) * ntohs(rtp_hdr_ext->length)); // XXX: ntohs() ???
	}
	if (rtp_hdr->p) /* Pad after data. */
		e_off = buf[(buf_size - 1)];
	if ((s_off + e_off) > buf_size)
		return (EINVAL);

	(*start_off) = s_off;
	(*end_off) = e_off;

	return (0);
}



static inline void
rtp_src_info_seq_init(rtp_src_info_p info, uint16_t seq) {

	info->base_seq = seq;
	info->max_seq = seq;
	info->bad_seq = (RTP_SEQ_MOD + 1); /* so seq == bad_seq is false */
	info->cycles = 0;
	info->received = 0;
	info->received_prior = 0;
	info->expected_prior = 0;
	/* other initialization */
}

static inline int
rtp_src_info_seq_update(rtp_src_info_p info, uint16_t seq) {
	uint16_t udelta = (seq - info->max_seq);
	const int MAX_DROPOUT = 3000;
	const int MAX_MISORDER = 100;
	const int MIN_SEQUENTIAL = 2;

	/*
	 * Source is not valid until MIN_SEQUENTIAL packets with
	 * sequential sequence numbers have been received.
	 */
	if (info->probation) {
		/* packet is in sequence */
		if (seq == (info->max_seq + 1)) {
			info->probation --;
			info->max_seq = seq;
			if (info->probation == 0) {
				rtp_src_info_seq_init(info, seq);
				info->received ++;
				return (1);
			}
		} else {
			info->probation = (MIN_SEQUENTIAL - 1);
			info->max_seq = seq;
		}
		return (0);
	} else if (udelta < MAX_DROPOUT) {
		/* in order, with permissible gap */
		if (seq < info->max_seq) /* Sequence number wrapped - count another 64K cycle. */
			info->cycles += RTP_SEQ_MOD;
		info->max_seq = seq;
	} else if (udelta <= (RTP_SEQ_MOD - MAX_MISORDER)) {
		/* the sequence number made a very large jump */
		if (seq == info->bad_seq) {
			/*
			 * Two sequential packets -- assume that the other side
			 * restarted without telling us so just re-sync
			 * (i.e., pretend this was the first packet).
			 */
			rtp_src_info_seq_init(info, seq);
		} else {
			info->bad_seq = (seq + 1) & (RTP_SEQ_MOD - 1);
			return (0);
		}
	} else {
		/* duplicate or reordered packet */
	}
	info->received ++;

	return (1);
}




#endif /* __RTP_PROTO_H__ */
