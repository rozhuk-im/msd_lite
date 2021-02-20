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
 * SAP: Session Announcement Protocol
 * RFC 2974
 *
 */

#ifndef __SAP_PROTO_H__
#define __SAP_PROTO_H__

#include <sys/types.h>
#include <sys/socket.h> // AF_INET, AF_INET6
#include <inttypes.h>
#include "mem_find.h"



#define SAP_PORT 9875 /* SAP is always on that port */
#define SAP_V4_LINK_ADDRESS	"224.0.0.255"	/* Link-local SAP address */
#define SAP_V4_LOCAL_ADDRESS	"239.255.255.255" /* Local (smallest non-link-local scope) SAP address */
#define SAP_V4_ORG_ADDRESS	"239.195.255.255" /* Organization-local SAP address */
#define SAP_V4_GLOBAL_ADDRESS	"224.2.127.254"	/* Global-scope SAP address */

#define SAP_V6_ADDR_LINK_LOCAL	"FF02::2:7FFE"	// link local scope
#define SAP_V6_ADDR_SITE_LOCAL	"FF05::2:7FFE"	// site local scope
#define SAP_V6_ADDR_ORG_LOCAL	"FF08::2:7FFE"	// Organization-Local scope
#define SAP_V6_ADDR_GLOBAL	"FF0E::2:7FFE"	// Global  scope

#define SAP_MIN_PAYLOAD		16 /* "application/sdp" + '/0' */


typedef union sap_hdr_flags_u {
	uint8_t u8;
	struct sap_hdr_flags_s {
#if BYTE_ORDER == BIG_ENDIAN
		uint8_t v:3; /* Version Number = 1 */
		uint8_t a:1; /* Address type: 0 = 32bit, 1 = 128 bit */
		uint8_t r:1; /* Reserved. */
		uint8_t t:1; /* Message Type: 0 = sess announcement, 1 = sess delete */
		uint8_t e:1; /* Encryption Bit. */
		uint8_t c:1; /* Compressed bit. (zlib) */
#else
		uint8_t c:1; /* Compressed bit. (zlib) */
		uint8_t e:1; /* Encryption Bit. */
		uint8_t t:1; /* Message Type: 0 = sess announcement, 1 = sess delete */
		uint8_t r:1; /* Reserved. */
		uint8_t a:1; /* Address type: 0 = 32bit, 1 = 128 bit */
		uint8_t v:3; /* Version Number = 1 */
#endif
	} __attribute__((__packed__)) bits;
} __attribute__((__packed__)) sap_hdr_flags_t, *sap_hdr_flags_p;

typedef struct sap_hdr_s {
	sap_hdr_flags_t flags;
	uint8_t		auth_len;
	uint16_t	msg_id_hash;
} __attribute__((__packed__)) sap_hdr_t, *sap_hdr_p;



static inline int
sap_packet_is_valid(uint8_t *pkt, size_t pkt_size) {

	if (NULL == pkt || sizeof(sap_hdr_t) > pkt_size) /* No packet. */
		return (0);
	if (1 != ((sap_hdr_p)pkt)->flags.bits.v) /* Invalid proto version. */
		return (0);
	if (0 == ((sap_hdr_p)pkt)->msg_id_hash) /* Invalid id hash. */
		return (0);
	if (pkt_size < (sizeof(sap_hdr_t) +
	    ((0 == ((sap_hdr_p)pkt)->flags.bits.a) ? 4 : 16) +
	    ((sap_hdr_p)pkt)->auth_len) + SAP_MIN_PAYLOAD) /* Bad packet. */
		return (0);

	return (1);
}

static inline uint8_t *
sap_packet_get_orig_src(uint8_t *pkt) {

	if (NULL == pkt) /* No packet. */
		return (NULL);

	return (pkt + sizeof(sap_hdr_t));
}

static inline uint16_t
sap_packet_get_orig_src_type(uint8_t *pkt) {

	if (NULL == pkt) /* No packet. */
		return (0);

	return (((0 == ((sap_hdr_p)pkt)->flags.bits.a) ? AF_INET : AF_INET6));
}

static inline uint8_t *
sap_packet_get_auth_data(uint8_t *pkt) {

	if (NULL == pkt) /* No packet. */
		return (NULL);

	return (pkt + sizeof(sap_hdr_t) +
	    ((0 == ((sap_hdr_p)pkt)->flags.bits.a) ? 4 : 16));
}

static inline uint8_t *
sap_packet_get_payload(uint8_t *pkt, size_t pkt_size) {
	uint8_t *ret, *tm;

	if (NULL == pkt) /* No packet. */
		return (NULL);
	ret = (pkt + sizeof(sap_hdr_t) +
	    ((0 == ((sap_hdr_p)pkt)->flags.bits.a) ? 4 : 16) +
	    ((sap_hdr_p)pkt)->auth_len);
	//if (0 == memcmp("application/sdp", ret, 16))
	//	ret += 16; /* Text, including null char. */
	tm = mem_find_byte((ret - pkt), pkt, pkt_size, 0);
	if (NULL != tm) /* Optional payload end. */
		ret = (tm + 1);

	return (ret);
}



#endif /* __SAP_PROTO_H__ */
