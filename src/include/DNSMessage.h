/*-
 * Copyright (c) 2004 - 2014 Rozhuk Ivan <rozhuk.im@gmail.com>
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



#ifndef __DNSMESSAGE_H__
#define __DNSMESSAGE_H__


#ifdef _WINDOWS
#	define EINVAL		ERROR_INVALID_PARAMETER
#	define EOVERFLOW	ERROR_INSUFFICIENT_BUFFER
#	define ESPIPE		ERROR_NOT_FOUND
#	define EBADMSG		ERROR_INVALID_DATA // DNS_ERROR_BAD_PACKET
#	define EOPNOTSUPP	ERROR_NOT_SUPPORTED
#	define ELOOP		ERROR_DS_LOOP_DETECT
#	define uint8_t		unsigned char
#	define uint16_t		WORD
#	define uint32_t		DWORD
#	define size_t		SIZE_T
#else
#	include <sys/types.h>
#	include <inttypes.h>
#	include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strnlen, strerror... */
#	include <netinet/in.h> /* ntohs(), htons(), ntohl(), htonl() */
#endif

#include "mem_helpers.h"



//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
// RFC 1035 Domain Implementation and Specification
// RFC 4035
// http://www.iana.org/numbers.htm
// http://www.iana.org/assignments/dns-parameters
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////


/* Basic DNS definitions. */

#define DNS_MAX_NAME_CYCLES		DNS_MAX_LABEL_BUFFER_LENGTH

/* DNS Names limited to 255, 63 in any one label. */
#define DNS_PORT			53
#define DNS_MAX_NAME_LENGTH		(255)
#define DNS_MAX_LABEL_LENGTH		(63)

#define DNS_MAX_NAME_BUFFER_LENGTH	(256)
#define DNS_MAX_LABEL_BUFFER_LENGTH	(64)

// XXX - not cheked for BIG_ENDIAN!!! #if BYTE_ORDER == BIG_ENDIAN
#define SEQ_LABEL_CTRL_MASK		((uint8_t)0xC0)	//XX------
#define SEQ_LABEL_CTRL_LEN		((uint8_t)0x00)	//00------ // RFC 1035 4.1.4: // 6 bit - label len, see SEQ_LABEL_DATA_MASK
#define SEQ_LABEL_CTRL_EDNS		((uint8_t)0x40)	//01------ // RFC 2671 (Extension Mechanisms for DNS (EDNS0)) //value is encoded in the lower six bits of the first octet
#define SEQ_LABEL_CTRL_RECERVED		((uint8_t)0x80)	//10------ // not used now
#define SEQ_LABEL_CTRL_COMPRESSED	((uint8_t)0xC0)	//11------ // RFC 1035 4.1.4: 14 bits = offset from the start of the message
#define SEQ_LABEL_DATA_MASK		((uint8_t)0x3F)	//--XXXXXX
#define SEQ_LABEL_COMPRESSED_DATA_MASK	((uint16_t)0x3FFF)//--XXXXXXXXXXXXXX // RFC 1035 4.1.4: 14 bits = offset from the start of the message

#define EXTENDED_LABEL_TYPE_ELT		((uint8_t)0x1)	//--000001 // RFC 2673 (Binary Labels in the Domain Name System)
#define EXTENDED_LABEL_TYPE_RESERVED	((uint8_t)0x3F)	//--111111 // RFC 2671 (Extension Mechanisms for DNS (EDNS0))



/* 4.1.2. Question section format. */
typedef struct dns_question_s {
	uint8_t		*name;
	uint16_t	type;
	uint16_t	class;
} __attribute__((__packed__)) dns_question_t, *dns_question_p;

/* 
 * 3.2. RR definitions
 * 3.2.1. Format
 * 4.1.3. Resource record format
 */
typedef struct dns_rr_s {
	uint8_t		*name;	/* Name of the node to which this RR pertains. */
	uint16_t	type;	/* RR TYPE. */
	uint16_t	class;	/* RR CLASS61: error: expected specifier-qualifier-. */
	uint32_t	ttl;	/* Time interval that the resource record may be cached. */
	uint16_t	rdlength; /* Length in octets of the RDATA field. */
	uint8_t		rdata;	// 
} __attribute__((__packed__)) dns_rr_t, *dns_rr_p;

#define DNS_TTL_MAX	604800 /* One week. */




typedef union dns_ex_flags_u { /* RFC 2671 (Extension Mechanisms for DNS (EDNS0)). */
	uint16_t u16;
	struct dns_ex_flags_s {
#if BYTE_ORDER == BIG_ENDIAN
		uint8_t d0	:1; //QR RFC 3225 (Indicating Resolver Support of DNSSEC): "DNSSEC OK"
		uint8_t __zero0	:7; //--
#else
		uint8_t __zero0	:7; //--
		uint8_t d0	:1; //QR RFC 3225 (Indicating Resolver Support of DNSSEC): "DNSSEC OK"
#endif
		uint8_t z	:8; //--
	} __attribute__((__packed__)) bits;
} __attribute__((__packed__)) dns_ex_flags_t, *dns_ex_flags_p;


typedef struct dns_opt_rr_s { /* RFC 2671 (Extension Mechanisms for DNS (EDNS0)): 4 - OPT pseudo-RR. */
	uint8_t		name;	/* empty (root domain) = 0 */
	uint16_t	type;	/* = DNS_RR_TYPE_OPT. */
	uint16_t	udp_payload_size;/* Sender's UDP payload size. */
	//uint32_t	ttl;	/* Extended RCODE and flags. */
	uint8_t		version; /* */
	uint8_t		ex_rcode; /* Forms upper 8 bits of extended 12-bit RCODE. */
	dns_ex_flags_t	ex_flags; /* Extended DNS header flags. */
	// end ttl
	uint16_t	rdlength; /* Describes RDATA. */
	uint8_t		rdata;	/* {attribute, value} pairs. */
} __attribute__((__packed__)) dns_opt_rr_t, *dns_opt_rr_p;


typedef struct dns_opt_rr_var_s { // RFC 2671 (Extension Mechanisms for DNS (EDNS0)): The variable part of an OPT RR is encoded in its RDATA
	uint16_t	code;	/* (Assigned by IANA). */
	uint16_t	lenght;	/* Size (in octets) of OPTION-DATA. */
	uint8_t		data;	/* Varies per OPTION-CODE. */
} __attribute__((__packed__)) dns_opt_rr_var_t, *dns_opt_rr_var_p;

#define DNS_OPT_RR_VAR_OPTION_CODE	65535 /* RFC 2671: Reserved for future expansion. */



/* 3.2.2. TYPE values. */
#define DNS_RR_TYPE_A		((uint16_t)1)	/* Host address. */
#define DNS_RR_TYPE_A_SZ	"A"
#define DNS_RR_TYPE_NS		((uint16_t)2)	/* Authoritative name server. */
#define DNS_RR_TYPE_NS_SZ	"NS"
#define DNS_RR_TYPE_MD		((uint16_t)3)	/* Mail destination (Obsolete - use MX). */
#define DNS_RR_TYPE_MD_SZ	"MD"
#define DNS_RR_TYPE_MF		((uint16_t)4)	/* Mail forwarder (Obsolete - use MX). */
#define DNS_RR_TYPE_MF_SZ	"MF"
#define DNS_RR_TYPE_CNAME	((uint16_t)5)	/* Canonical name for an alias. */
#define DNS_RR_TYPE_CNAME_SZ	"CNAME"
#define DNS_RR_TYPE_SOA		((uint16_t)6)	/* Marks the start of a zone of authority. */
#define DNS_RR_TYPE_SOA_SZ	"SOA"
#define DNS_RR_TYPE_MB		((uint16_t)7)	/* Mailbox domain name (EXPERIMENTAL). */
#define DNS_RR_TYPE_MB_SZ	"MB"
#define DNS_RR_TYPE_MG		((uint16_t)8)	/* Mail group member (EXPERIMENTAL). */
#define DNS_RR_TYPE_MG_SZ	"MG"
#define DNS_RR_TYPE_MR		((uint16_t)9)	/* Mail rename domain name (EXPERIMENTAL). */
#define DNS_RR_TYPE_MR_SZ	"MR"
#define DNS_RR_TYPE_NULL	((uint16_t)10)	/* Null RR (EXPERIMENTAL). */
#define DNS_RR_TYPE_NULL_SZ	"NULL"
#define DNS_RR_TYPE_WKS		((uint16_t)11)	/* Well known service description. */
#define DNS_RR_TYPE_WKS_SZ	"WKS"
#define DNS_RR_TYPE_PTR		((uint16_t)12)	/* Domain name pointer. */
#define DNS_RR_TYPE_PTR_SZ	"PTR"
#define DNS_RR_TYPE_HINFO	((uint16_t)13)	/* Host information. */
#define DNS_RR_TYPE_HINFO_SZ	"HINFO"
#define DNS_RR_TYPE_MINFO	((uint16_t)14)	/* Mailbox or mail list information. */
#define DNS_RR_TYPE_MINFO_SZ	"MINFO"
#define DNS_RR_TYPE_MX		((uint16_t)15)	/* Mail exchange. */
#define DNS_RR_TYPE_MX_SZ	"MX"
#define DNS_RR_TYPE_TXT		((uint16_t)16)	/* Text strings. */
#define DNS_RR_TYPE_TXT_SZ	"TXT"
#define DNS_RR_TYPE_RP		((uint16_t)17)	/* RFC 1183. */
#define DNS_RR_TYPE_RP_SZ	"RP"
#define DNS_RR_TYPE_AFSDB	((uint16_t)18)	/* RFC 1183. */
#define DNS_RR_TYPE_AFSDB_SZ	"AFSDB"
#define DNS_RR_TYPE_X25		((uint16_t)19)	/* RFC 1183. */
#define DNS_RR_TYPE_X25_SZ	"X25"
#define DNS_RR_TYPE_ISDN	((uint16_t)20)	/* RFC 1183. */
#define DNS_RR_TYPE_ISDN_SZ	"ISDN"
#define DNS_RR_TYPE_RT		((uint16_t)21)	/* RFC 1183. */
#define DNS_RR_TYPE_RT_SZ	"RT"
#define DNS_RR_TYPE_NSAP	((uint16_t)22)	/* RFC 1706. */
#define DNS_RR_TYPE_NSAP_SZ	"NSAP"
#define DNS_RR_TYPE_NSAP_PTR	((uint16_t)23)	/* RFC 1706. */
#define DNS_RR_TYPE_NSAP_PTR_SZ	"NSAP-PTR"
#define DNS_RR_TYPE_SIG		((uint16_t)24)	/* RFC 2931 (DNS Request and Transaction Signatures ( SIG(0)s )). */
#define DNS_RR_TYPE_SIG_SZ	"SIG"
#define DNS_RR_TYPE_KEY		((uint16_t)25)	/* RFC 2535 (Domain Name System Security Extensions). */
#define DNS_RR_TYPE_KEY_SZ	"KEY"
#define DNS_RR_TYPE_PX		((uint16_t)26)	/* RFC 2163. */
#define DNS_RR_TYPE_PX_SZ	"PX"
#define DNS_RR_TYPE_GPOS	((uint16_t)27)	/* RFC 1712. */
#define DNS_RR_TYPE_GPOS_SZ	"GPOS"
#define DNS_RR_TYPE_AAAA	((uint16_t)28)	/* RFC 1886 (IPv6 DNS Extensions). */
#define DNS_RR_TYPE_AAAA_SZ	"AAAA"
#define DNS_RR_TYPE_LOC		((uint16_t)29)	/* [Vixie]. */
#define DNS_RR_TYPE_LOC_SZ	"LOC"
#define DNS_RR_TYPE_NXT		((uint16_t)30)	/* RFC 2535 (Domain Name System Security Extensions). */
#define DNS_RR_TYPE_NXT_SZ	"NXT"
#define DNS_RR_TYPE_EID		((uint16_t)31)	/* [Patton]. */
#define DNS_RR_TYPE_EID_SZ	"EID"
#define DNS_RR_TYPE_NIMLOC	((uint16_t)32)	/* [Patton]. */
#define DNS_RR_TYPE_NIMLOC_SZ	"NIMLOC"
#define DNS_RR_TYPE_SRV		((uint16_t)33)	/* RFC 2782. */
#define DNS_RR_TYPE_SRV_SZ	"SRV"
#define DNS_RR_TYPE_ATMA	((uint16_t)34)	/* [Dobrowski]. */
#define DNS_RR_TYPE_ATMA_SZ	"ATMA"
#define DNS_RR_TYPE_NAPTR	((uint16_t)35)	/* RFC 2168, RFC 2915. */
#define DNS_RR_TYPE_NAPTR_SZ	"NAPTR"
#define DNS_RR_TYPE_KX		((uint16_t)36)	/* RFC 2230. */
#define DNS_RR_TYPE_KX_SZ	"KX"
#define DNS_RR_TYPE_CERT	((uint16_t)37)	/* RFC 2538. */
#define DNS_RR_TYPE_CERT_SZ	"CERT"
#define DNS_RR_TYPE_A6		((uint16_t)38)	/* RFC 2874. */
#define DNS_RR_TYPE_A6_SZ	"A6"
#define DNS_RR_TYPE_DNAME	((uint16_t)39)	/* RFC 2672. */
#define DNS_RR_TYPE_DNAME_SZ	"DNAME"
#define DNS_RR_TYPE_SINK	((uint16_t)40)	/* [Eastlake]. */
#define DNS_RR_TYPE_SINK_SZ	"SINK"
#define DNS_RR_TYPE_OPT		((uint16_t)41)	/* RFC 2671 (Extension Mechanisms for DNS (EDNS0)). */
#define DNS_RR_TYPE_OPT_SZ	"OPT"
#define DNS_RR_TYPE_APL		((uint16_t)42)	/* RFC 3123 (A DNS RR Type for Lists of Address Prefixes). */
#define DNS_RR_TYPE_APL_SZ	"APL"
#define DNS_RR_TYPE_DS		((uint16_t)43)	/* RFC 3658. */
#define DNS_RR_TYPE_DS_SZ	"DS"
#define DNS_RR_TYPE_SSHFP	((uint16_t)44)	/* [RFC-ietf-secsh-dns-05.txt]. */
#define DNS_RR_TYPE_SSHFP_SZ	"SSHFP"
#define DNS_RR_TYPE_RRSIG	((uint16_t)46)	/* [RFC-ietf-dnsext-dnssec-2535typecode-change-04.txt]. */
#define DNS_RR_TYPE_RRSIG_SZ	"RRSIG"
#define DNS_RR_TYPE_NSEC	((uint16_t)47)	/* [RFC-ietf-dnsext-dnssec-2535typecode-change-04.txt]. */
#define DNS_RR_TYPE_NSEC_SZ	"NSEC"
#define DNS_RR_TYPE_DNSKEY	((uint16_t)48)	/* [RFC-ietf-dnsext-dnssec-2535typecode-change-04.txt]. */
#define DNS_RR_TYPE_DNSKEY_SZ	"DNSKEY"
#define DNS_RR_TYPE_DHCID	((uint16_t)49)	/* RFC4701. */
#define DNS_RR_TYPE_DHCID_SZ	"DHCID"
#define DNS_RR_TYPE_NSEC3	((uint16_t)50)	/* RFC5155. */
#define DNS_RR_TYPE_NSEC3_SZ	"NSEC3"
#define DNS_RR_TYPE_NSEC3PARAM	((uint16_t)51)	/* RFC5155. */
#define DNS_RR_TYPE_NSEC3PARAM_SZ "NSEC3PARAM"
#define DNS_RR_TYPE_HIP		((uint16_t)55)	/* RFC5205 (Host Identity Protocol). */
#define DNS_RR_TYPE_HIP_SZ	"HIP"
#define DNS_RR_TYPE_NINFO	((uint16_t)56)	/* [Reid]. */
#define DNS_RR_TYPE_NINFO_SZ	"NINFO"
#define DNS_RR_TYPE_RKEY	((uint16_t)57)	/* [Reid]. */
#define DNS_RR_TYPE_RKEY_SZ	"RKEY"
#define DNS_RR_TYPE_TALINK	((uint16_t)58)	/* [Wijngaards] (Trust Anchor LINK). */
#define DNS_RR_TYPE_TALINK_SZ	"TALINK"
#define DNS_RR_TYPE_UINFO	((uint16_t)100) /* [IANA-Reserved]. */
#define DNS_RR_TYPE_UINFO_SZ	"UINFO"
#define DNS_RR_TYPE_UID		((uint16_t)101) /* [IANA-Reserved]. */
#define DNS_RR_TYPE_UID_SZ	"UID"
#define DNS_RR_TYPE_GID		((uint16_t)102) /* [IANA-Reserved]. */
#define DNS_RR_TYPE_GID_SZ	"GID"
#define DNS_RR_TYPE_UNSPEC	((uint16_t)103) /* [IANA-Reserved]. */
#define DNS_RR_TYPE_UNSPEC_SZ	"UNSPEC"
#define DNS_RR_TYPE_TKEY	((uint16_t)249) /* RFC 2930. */
#define DNS_RR_TYPE_TKEY_SZ	"TKEY"
#define DNS_RR_TYPE_TSIG	((uint16_t)250) /* RFC 3123 (A DNS RR Type for Lists of Address Prefixes). */
#define DNS_RR_TYPE_TSIG_SZ	"TSIG"
#define DNS_RR_TYPE_IXFR	((uint16_t)251) /* RFC 1995. */
#define DNS_RR_TYPE_IXFR_SZ	"IXFR"
/*
 * 3.2.3. QTYPE values
 * aditional TYPE values specialy for question
 */
#define DNS_RR_QTYPE_AXFR	((uint16_t)252) /* Request for a transfer of an entire zone. */
#define DNS_RR_QTYPE_AXFR_SZ	"AXFR"
#define DNS_RR_QTYPE_MAILB	((uint16_t)253) /* Request for mailbox-related records (MB, MG or MR). */
#define DNS_RR_QTYPE_MAILB_SZ	"MAILB"
#define DNS_RR_QTYPE_MAILA	((uint16_t)254) /* Request for mail agent RRs (Obsolete - see MX). */
#define DNS_RR_QTYPE_MAILA_SZ	"MAILA"
#define DNS_RR_QTYPE_ALL	((uint16_t)255) /* Request for all records. */
#define DNS_RR_QTYPE_ALL_SZ	"*"


static const char *szDNS_RR_TYPEA[256] = {
/* 0 */	NULL,			DNS_RR_TYPE_A_SZ,	DNS_RR_TYPE_NS_SZ,	DNS_RR_TYPE_MD_SZ,
/* 4 */	DNS_RR_TYPE_MF_SZ,	DNS_RR_TYPE_CNAME_SZ,	DNS_RR_TYPE_SOA_SZ,	DNS_RR_TYPE_MB_SZ,
/* 8 */	DNS_RR_TYPE_MG_SZ,	DNS_RR_TYPE_MR_SZ,	DNS_RR_TYPE_NULL_SZ,	DNS_RR_TYPE_WKS_SZ,
/* 12*/	DNS_RR_TYPE_PTR_SZ,	DNS_RR_TYPE_HINFO_SZ,	DNS_RR_TYPE_MINFO_SZ,	DNS_RR_TYPE_MX_SZ,
/* 16*/	DNS_RR_TYPE_TXT_SZ,	DNS_RR_TYPE_RP_SZ,	DNS_RR_TYPE_AFSDB_SZ,	DNS_RR_TYPE_X25_SZ,
/* 20*/	DNS_RR_TYPE_ISDN_SZ,	DNS_RR_TYPE_RT_SZ,	DNS_RR_TYPE_NSAP_SZ,	DNS_RR_TYPE_NSAP_PTR_SZ,
/* 24*/	DNS_RR_TYPE_SIG_SZ,	DNS_RR_TYPE_KEY_SZ,	DNS_RR_TYPE_PX_SZ,	DNS_RR_TYPE_GPOS_SZ,
/* 28*/	DNS_RR_TYPE_AAAA_SZ,	DNS_RR_TYPE_LOC_SZ,	DNS_RR_TYPE_NXT_SZ,	DNS_RR_TYPE_EID_SZ,
/* 32*/	DNS_RR_TYPE_NIMLOC_SZ,	DNS_RR_TYPE_SRV_SZ,	DNS_RR_TYPE_ATMA_SZ,	DNS_RR_TYPE_NAPTR_SZ,
/* 36*/	DNS_RR_TYPE_KX_SZ,	DNS_RR_TYPE_CERT_SZ,	DNS_RR_TYPE_A6_SZ,	DNS_RR_TYPE_DNAME_SZ,
/* 40*/	DNS_RR_TYPE_SINK_SZ,	DNS_RR_TYPE_OPT_SZ,	DNS_RR_TYPE_APL_SZ,	DNS_RR_TYPE_DS_SZ,
/* 44*/	DNS_RR_TYPE_SSHFP_SZ,	NULL,			DNS_RR_TYPE_RRSIG_SZ,	DNS_RR_TYPE_NSEC_SZ,
/* 48*/	DNS_RR_TYPE_DNSKEY_SZ,	DNS_RR_TYPE_DHCID_SZ,	DNS_RR_TYPE_NSEC3_SZ,	DNS_RR_TYPE_NSEC3PARAM_SZ,
/* 52*/	NULL,			NULL,			NULL,			DNS_RR_TYPE_HIP_SZ,
/* 56*/	DNS_RR_TYPE_NINFO_SZ,	DNS_RR_TYPE_RKEY_SZ,	DNS_RR_TYPE_TALINK_SZ,	NULL,
/* 60*/	NULL,			NULL,			NULL,			NULL,
/* 64*/	NULL,			NULL,			NULL,			NULL,
/* 68*/	NULL,			NULL,			NULL,			NULL,
/* 72*/	NULL,			NULL,			NULL,			NULL,
/* 76*/	NULL,			NULL,			NULL,			NULL,
/* 80*/	NULL,			NULL,			NULL,			NULL,
/* 84*/	NULL,			NULL,			NULL,			NULL,
/* 88*/	NULL,			NULL,			NULL,			NULL,
/* 92*/	NULL,			NULL,			NULL,			NULL,
/* 96*/	NULL,			NULL,			NULL,			NULL,
/*100*/	DNS_RR_TYPE_UINFO_SZ,	DNS_RR_TYPE_UID_SZ,	DNS_RR_TYPE_GID_SZ,	DNS_RR_TYPE_UNSPEC_SZ,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL,			DNS_RR_TYPE_TKEY_SZ,	DNS_RR_TYPE_TSIG_SZ,	DNS_RR_TYPE_IXFR_SZ,
	DNS_RR_QTYPE_AXFR_SZ,	DNS_RR_QTYPE_MAILB_SZ,	DNS_RR_QTYPE_MAILA_SZ,	DNS_RR_QTYPE_ALL_SZ
};



/* 3.2.4. CLASS values. */
#define DNS_RR_CLASS_IN		((uint16_t)1)	/* Internet. */
#define DNS_RR_CLASS_IN_SZ	"IN"
#define DNS_RR_CLASS_CS		((uint16_t)2)	/* CSNET class (Obsolete - used only for examples in some obsolete RFCs). */
#define DNS_RR_CLASS_CS_SZ	"CS"
#define DNS_RR_CLASS_CH		((uint16_t)3)	/* CHAOS class. */
#define DNS_RR_CLASS_CH_SZ	"CH"
#define DNS_RR_CLASS_HS		((uint16_t)4)	/* Hesiod [Dyer 87]. */
#define DNS_RR_CLASS_HS_SZ	"HS"

/* 
 * 3.2.5. QCLASS values
 * aditional CLASS values specialy for question.
 */
#define DNS_RR_QCLASS_NONE	((uint16_t)254)	/* QCLASS None [RFC 2136].// RFC 2136 (Dynamic Updates in the Domain Name System (DNS UPDATE)). */
#define DNS_RR_QCLASS_NONE_SZ	""
#define DNS_RR_QCLASS_ANY	((uint16_t)255)	/* Any class. */
#define DNS_RR_QCLASS_ANY_SZ	"*"




/*
 * 4. MESSAGES
 * 4.1. Format
 * +---------------------+
 * | Header |
 * +---------------------+
 * | Question | the question for the name server
 * +---------------------+
 * | Answer | RRs answering the question
 * +---------------------+
 * | Authority | RRs pointing toward an authority
 * +---------------------+
 * | Additional | RRs holding additional information
 * +---------------------+
 */

/* 4.1.1. Header section format. */
typedef union dns_hdr_flags_u {
	uint16_t u16;
	struct dns_hdr_flags_s {
#if BYTE_ORDER == BIG_ENDIAN
		uint8_t qr	:1; //QR /* Query (0), or a response (1). */
		uint8_t opcode	:4; //Q- /* specifies kind of query. */
		uint8_t aa	:1; //-R /* Authoritative Answer. */
		uint8_t tc	:1; //-R /* TrunCation. */
		uint8_t rd	:1; //Q- /* Recursion Desired. */

		uint8_t ra	:1; //-R /* Recursion Available. */
		uint8_t z	:1; //--
		uint8_t ad	:1; //-R /* RFC 2535 [Page 29] (Domain Name System Security Extensions). */
		uint8_t cd	:1; //Q- /* RFC 2535 [Page 29] (Domain Name System Security Extensions)
		uint8_t rcode	:4; //-R /* Response code, low 4 byte, see EDNS0. */
#else
		uint8_t rd	:1; //Q- /* Recursion Desired. */
		uint8_t tc	:1; //-R /* TrunCation. */
		uint8_t aa	:1; //-R /* Authoritative Answer. */
		uint8_t opcode	:4; //Q- /* specifies kind of query. */
		uint8_t qr	:1; //QR /* Query (0), or a response (1). */

		uint8_t rcode	:4; //-R /* Response code, low 4 byte, see EDNS0. */
		uint8_t cd	:1; //Q- /* RFC 2535 [Page 29] (Domain Name System Security Extensions)
		uint8_t ad	:1; //-R /* RFC 2535 [Page 29] (Domain Name System Security Extensions). */
		uint8_t z	:1; //--
		uint8_t ra	:1; //-R /* Recursion Available. */
#endif
	} __attribute__((__packed__)) bits;
} __attribute__((__packed__)) dns_hdr_flags_t, *dns_hdr_flags_p;

#define DNS_HDR_FLAG_QR_QUERY		0
#define DNS_HDR_FLAG_QR_RESPONSE	1

#define DNS_HDR_FLAG_OPCODE_QUERY	0 /* RFC1035. */
#define DNS_HDR_FLAG_OPCODE_IQUERY	1 /* RFC3425. */
#define DNS_HDR_FLAG_OPCODE_STATUS	2 /* RFC1035. */
#define DNS_HDR_FLAG_OPCODE_NOTIFY	4 /* RFC1996. */
#define DNS_HDR_FLAG_OPCODE_UPDATE	5 /* RFC 2136 (Dynamic Updates in the Domain Name System (DNS UPDATE)). */

#define DNS_HDR_FLAG_RCODE_NOERROR	 0 /* 0. */
#define DNS_HDR_FLAG_RCODE_FORMERROR	 1 /* FORMAT_ERROR. */
#define DNS_HDR_FLAG_RCODE_SERVFAIL	 2 /* SERVER_FAILURE. */
#define DNS_HDR_FLAG_RCODE_NXDOMAIN	 3 /* NAME_ERROR. */
#define DNS_HDR_FLAG_RCODE_NOTIMPL	 4 /* NOT_IMPLEMENTED. */
#define DNS_HDR_FLAG_RCODE_REFUSED	 5
#define DNS_HDR_FLAG_RCODE_YXDOMAIN	 6 /* RFC 2136 (Dynamic Updates in the Domain Name System (DNS UPDATE)). */
#define DNS_HDR_FLAG_RCODE_YXRRSET	 7 /* RFC 2136 (Dynamic Updates in the Domain Name System (DNS UPDATE)). */
#define DNS_HDR_FLAG_RCODE_NXRRSET	 8 /* RFC 2136 (Dynamic Updates in the Domain Name System (DNS UPDATE)). */
#define DNS_HDR_FLAG_RCODE_NOTAUTH	 9 /* RFC 2136 (Dynamic Updates in the Domain Name System (DNS UPDATE)). */
#define DNS_HDR_FLAG_RCODE_NOTZONE	10 /* RFC 2136 (Dynamic Updates in the Domain Name System (DNS UPDATE)). */
#define DNS_HDR_FLAG_RCODE_BADVERS	16 /* RFC 2671 (Extension Mechanisms for DNS (EDNS0)). */
#define DNS_HDR_FLAG_RCODE_BADSIG	16 /* RFC 2845 (Secret Key Transaction Authentication for DNS (TSIG)). */
#define DNS_HDR_FLAG_RCODE_BADKEY	17 /* RFC 2845 (Secret Key Transaction Authentication for DNS (TSIG)). */
#define DNS_HDR_FLAG_RCODE_BADTIME	18 /* RFC 2845 (Secret Key Transaction Authentication for DNS (TSIG)). */
#define DNS_HDR_FLAG_RCODE_BADMODE	19 /* RFC 2930. */
#define DNS_HDR_FLAG_RCODE_BADNAME	20 /* RFC 2930. */
#define DNS_HDR_FLAG_RCODE_BADALG	21 /* RFC 2930. */
#define DNS_HDR_FLAG_RCODE_BADTRUNC	22 /* RFC 4635 (Bad Truncation). */



typedef struct dns_hdr_s {
	uint16_t		id;	/* Req identifier. */
	dns_hdr_flags_t		flags;
	union {
		uint16_t	qd_count; /* Number of entries in the question section. */
		uint16_t	zo_count;
	};
	union {
		uint16_t	an_count; /* Number of resource records in the answer section. */
		uint16_t	pr_count;
	};
	union {
		uint16_t	ns_count; /* Number of name server resource records. */
		uint16_t	up_count;
	};
	uint16_t		ar_count; /* Number of resource records in the additional records section. */
} __attribute__((__packed__)) dns_hdr_t, *dns_hdr_p;




#ifdef _WINDOWS
static inline DWORD
rcode2win32err(uint16_t rcode16) {
	return (((rcode16) ?
	    (rcode16 + DNS_ERROR_RESPONSE_CODES_BASE) :
	    0));
}

static inline uint16_t
Win32ErrorToRCode(DWORD error) {
	return (((0 != error) ?
	    (uint16_t)(error - DNS_ERROR_RESPONSE_CODES_BASE) :
	    0));
}
#endif


static inline uint16_t
RCodeSplit(uint8_t rcode, uint8_t ex_rcode) {
	uint16_t rcode16;

	rcode16 = ex_rcode;
	rcode16 = (rcode16 << 4);
	rcode16 |= (rcode & 0x0f);

	return (rcode16);
}

static inline uint8_t
RCodeUnSplit(uint16_t rcode16, uint8_t *ex_rcode) {

	if (NULL != ex_rcode) 
		(*ex_rcode) = (uint8_t)((rcode16 >> 4) & 0xff);

	return ((rcode16 & 0x0f));
}


/*
 * Reverce zones in domain name
 * src = "www.sample.org"
 * dst = "org.sample.www"
 * !!! src != dst !!!
 * test: ".1.12.123.1234.12345.123456.1234567..12345678." => ".12345678..1234567.123456.12345.1234.123.12.1."
 */
static inline void
DomainNameZonesReverce(uint8_t *dst, const uint8_t *src, size_t name_len) {
	const uint8_t *src_pos, *src_dot_pos;
	uint8_t *dst_pos;
	size_t cp_size;

	if (NULL == dst || NULL == src || 0 == name_len)
		return;

	src_pos = src;
	src_dot_pos = src;
	dst_pos = (dst + name_len + 1);
	for (;;) {
		src_dot_pos = (uint8_t*)mem_chr_ptr(src_dot_pos, src,
		    name_len, '.');
		if (NULL == src_dot_pos) {// точка не найдена, считаем что она в конце строки
			cp_size = ((name_len - (src_pos - src)) + 1);
			dst_pos -= cp_size;
			memcpy(dst_pos, src_pos, cp_size);
			(*((uint8_t*)(dst_pos + (cp_size - 1)))) = '.';
			dst[name_len] = 0;
			return;
		}
		// точка найдена, вычисляем длинну от предудущей точки и записываем её вместо
		// предыдущей, если предыдущее небыло, то пишем перед строкой
		cp_size = ((src_dot_pos - src_pos) + 1);
		dst_pos -= cp_size;
		memcpy(dst_pos, src_pos, cp_size);
		src_dot_pos ++; // move out from dot
		src_pos = src_dot_pos;
	}
}


static inline size_t
DomainNameZonesGetCount(const uint8_t *name, size_t name_len) {
	size_t ret;
	const uint8_t *dot_pos;

	if (NULL == name || 0 == name_len)
		return (0);
	dot_pos = name;
	ret = 1;
	for (;;) {
		dot_pos = (uint8_t*)mem_chr_ptr(dot_pos, name,
		    name_len, '.');
		if (NULL == dot_pos)
			return (ret);
		ret ++;
		dot_pos ++;
	}
	return (ret);
}


static inline size_t
DomainNameZonesLeft(const uint8_t *name, size_t name_len, size_t zones_count,
    uint8_t **name_ret) {
	const uint8_t *dot_pos;

	if (NULL != name_ret)
		(*name_ret) = (uint8_t*)((size_t)name);
	if (NULL == name || 0 == name_len || 0 == zones_count)
		return (0);

	dot_pos = name;
	for (; 0 != zones_count; zones_count --) {
		dot_pos = (uint8_t*)mem_chr_ptr(dot_pos, name,
		    name_len, '.');
		if (NULL == dot_pos) {// dot not found, let it be at the end of string
			dot_pos = (name + name_len + 1);
			break;
		}
		dot_pos ++;
	}
	return (((dot_pos - name) - 1));
}


static inline size_t
DomainNameZonesRight(const uint8_t *name, size_t name_len, size_t zones_count,
    uint8_t **name_ret) {
	const uint8_t *dot_pos, *name_end;

	if (NULL == name || 0 == name_len)
		return (0);
	if (0 == zones_count) {
		if (NULL != name_ret)
			(*name_ret) = (uint8_t*)(((size_t)name) + name_len);
		return (0);
	}

	name_end = (name + name_len);
	dot_pos = (name_end + 1);
	for (; 0 != zones_count; zones_count --) {
		dot_pos = (uint8_t*)mem_rchr_off(((name_end - dot_pos) + 1),
		    name, name_len, '.');
		if (NULL == dot_pos) {// dot not found for this zones count, return full name
			if (NULL != name_ret)
				(*name_ret) = (uint8_t*)((size_t)name);
			return (name_len);
		}
	}
	dot_pos ++;// move from dot
	if (NULL != name_ret)
		(*name_ret) = (uint8_t*)((size_t)dot_pos);

	return ((name_end - dot_pos));
}


// коприрует имя хоста в буффер и заменяет в нём = . = на длинну, не производит компресию
static inline int
DomainNameToSequenceOfLabels(const uint8_t *name, size_t name_len, uint8_t *buf,
    size_t buf_size, size_t *name_size_ret) {
	uint8_t *label_pos, *dot_pos;
	size_t name_size, len;

	if ((NULL == name && 0 != name_len) || NULL == buf) // invalid buf or name
		return (EINVAL);

	/* calculate buf size for name */
	name_size = (0 == name_len) ? 1 : (name_len + 2);
	if (NULL != name_size_ret) /* return valid buf size */
		(*name_size_ret) = name_size;

	if (name_size > buf_size) // small buf
		return (EOVERFLOW);
	if (0 == name_len) {
		(*((uint8_t*)buf)) = 0;// store null label = end marker
		return (0);
	}

	label_pos = buf; // first label contain len
	dot_pos = (label_pos + 1); // ponts to start of domain name
	memcpy(dot_pos, name, name_len); // copy domain name to new place (or move it 1 byte from start)
	(*(uint8_t*)(buf + name_len + 1)) = 0; // store null label = end marker

	// now replace dots by labels with len
	for (;;) {
		dot_pos = (uint8_t*)mem_chr_ptr(dot_pos, buf, name_size, '.');
		if (NULL == dot_pos) {// dot not found, let it be at the end of string
			len = (((buf + name_size) - label_pos) - 2);// '-2': dont count dot and last null label (end marker)
			if (0 == len || SEQ_LABEL_DATA_MASK < len) // label max size is 63 bytes
				return (EINVAL);
			(*(uint8_t*)label_pos) = (uint8_t)len;
			return (0);
		}
		len = ((dot_pos - label_pos) - 1);// '-1': dont count dot
		if (0 == len || SEQ_LABEL_DATA_MASK < len) // label max size is 63 bytes
			return (EINVAL);
		(*(uint8_t*)label_pos) = (uint8_t)len;
		label_pos = dot_pos;
		dot_pos ++;// move next
	}
	return (0);
}


// возвращает размер занимаемый SequenceOfLabels не обращая внимания на компресию
static inline int
SequenceOfLabelsGetSize(const uint8_t *buf, size_t buf_size, size_t *name_len_ret) {
	const uint8_t *cur_pos, *max_pos;
	uint16_t label;

	if (NULL == buf || 0 == buf_size || NULL == name_len_ret)
		return (EINVAL);

	cur_pos = buf;
	max_pos = (cur_pos + buf_size);
	for (;;) {// перебираем все куски текста
		label = (*cur_pos);
		cur_pos ++; // now it points to data
		switch((label & SEQ_LABEL_CTRL_MASK)){
		case SEQ_LABEL_CTRL_LEN:		//00------ // RFC 1035 4.1.4: // 6 bit - label len, see SEQ_LABEL_DATA_MASK
			label &= SEQ_LABEL_DATA_MASK;// now it contain len
			if ((cur_pos + label) > max_pos)
				return (EBADMSG); /* Out of buf range. */
			if (0 == label) { // null label = end of name, ALL DONE!!!
				(*name_len_ret) = (cur_pos - buf);
				return (0);
			}
			cur_pos += label;// move to next label
			break;
		case SEQ_LABEL_CTRL_EDNS: //01------ // RFC 2671 (Extension Mechanisms for DNS (EDNS0)) //value is encoded in the lower six bits of the first octet
		case SEQ_LABEL_CTRL_RECERVED: //10------ // not used now
			(*name_len_ret) = (cur_pos - buf);
			return (0);// XXX if its wrong, then error will be generated in other place
			break;
		case SEQ_LABEL_CTRL_COMPRESSED: //11------ // RFC 1035 4.1.4: 14 bits = offset from the start of the message
			(*name_len_ret) = ((cur_pos - buf) + 1);// 1 = 1 offset byte (low 8 bits of offset)
			return (0);
			break;
		}
	}

	return (0);
}


// копируем имя хоста, заменяем длинну на = . = , игнорируем компресию
static inline int
SequenceOfLabelsToDomainName(const uint8_t *buf, size_t buf_size, uint8_t *name,
    size_t name_buf_size, size_t *name_len_ret) {
	const uint8_t *cur_pos, *max_pos;
	uint16_t label;

	if (NULL == buf || 0 == buf_size || NULL == name || 0 == name_buf_size)
		return (EINVAL);
	if (name_buf_size < (buf_size - 1)) { // small out buffer
		if (NULL != name_len_ret)
			(*name_len_ret) = buf_size;
		return (EOVERFLOW);
	}

	cur_pos = buf;
	max_pos = (cur_pos + buf_size);
	for (;;) {// перебираем все куски текста
		label = (*cur_pos);
		if ((label & SEQ_LABEL_CTRL_MASK) != SEQ_LABEL_CTRL_LEN)
			return (EOPNOTSUPP);// unsupported label type (possible ends)
		label &= SEQ_LABEL_DATA_MASK;// now it contain len
		cur_pos ++; // now it points to data

		if ((cur_pos + label) > max_pos)
			return (EBADMSG); /* Out of buf range. */
		if (0 == label) { // null label = end of name, ALL DONE!!!
			if (0 != (cur_pos - buf)) // clear last dot
				name --;
			(*name) = 0; // set zero at the end
			if (NULL != name_len_ret)
				(*name_len_ret) = (cur_pos - buf);
			return (0);
		}

		memcpy(name, cur_pos, label);
		name += label;
		(*name) = '.';
		name ++;
		cur_pos += label;// move to next label
	}

	return (0);
}

//////////////////////////////////////////////////////////////////////////
///////////////////////////// DNS HEADER /////////////////////////////////
//////////////////////////////////////////////////////////////////////////
static inline uint16_t
dns_hdr_id_get(dns_hdr_p hdr) {
	return (hdr->id);
}

static inline void
dns_hdr_id_set(dns_hdr_p hdr, uint16_t id) {
	hdr->id = id;
}


static inline uint16_t
dns_hdr_flags_get(dns_hdr_p hdr) {
	return (hdr->flags.u16);
}

static inline void
dns_hdr_flags_set(dns_hdr_p hdr, uint16_t flags) {
	hdr->flags.u16 = flags;
}

static inline uint8_t
dns_hdr_rcode_get(dns_hdr_p hdr) {
	return (hdr->flags.bits.rcode);
}

#ifdef _WINDOWS
static inline DWORD
dns_hdr_win32err_get(dns_hdr_p hdr) {
	// EDNS0: RR_OPT has another 8 bit rcode value
	return (rcode2win32err(hdr->flags.bits.rcode));
}
#endif


static inline uint16_t
dns_hdr_qd_get(dns_hdr_p hdr) {
	return (ntohs(hdr->qd_count));
}
static inline void
dns_hdr_qd_set(dns_hdr_p hdr, uint16_t val) {
	hdr->qd_count = htons(val);
}

static inline void
dns_hdr_qd_inc(dns_hdr_p hdr, uint16_t val) {
	hdr->qd_count = htons((uint16_t)(ntohs(hdr->qd_count) + val));
}

static inline void
dns_hdr_qd_dec(dns_hdr_p hdr, uint16_t val) {
	hdr->qd_count = htons((uint16_t)(ntohs(hdr->qd_count) - val));
}


static inline uint16_t
dns_hdr_an_get(dns_hdr_p hdr) {
	return (ntohs(hdr->an_count));
}

static inline void
dns_hdr_an_set(dns_hdr_p hdr, uint16_t val) {
	hdr->an_count = htons(val);
}

static inline void
dns_hdr_an_inc(dns_hdr_p hdr, uint16_t val) {
	hdr->an_count = htons((uint16_t)(ntohs(hdr->an_count) + val));
}

static inline void
dns_hdr_an_dec(dns_hdr_p hdr, uint16_t val) {
	hdr->an_count = htons((uint16_t)(ntohs(hdr->an_count) - val));
}


static inline uint16_t
dns_hdr_ns_get(dns_hdr_p hdr) {
	return (ntohs(hdr->ns_count));
}

static inline void
dns_hdr_ns_set(dns_hdr_p hdr, uint16_t val) {
	hdr->ns_count = htons(val);
}

static inline void
dns_hdr_ns_inc(dns_hdr_p hdr, uint16_t val) {
	hdr->ns_count = htons((uint16_t)(ntohs(hdr->ns_count) + val));
}

static inline void
dns_hdr_ns_dec(dns_hdr_p hdr, uint16_t val) {
	hdr->ns_count = htons((uint16_t)(ntohs(hdr->ns_count) - val));
}


static inline uint16_t
dns_hdr_ar_get(dns_hdr_p hdr) {
	return (ntohs(hdr->ar_count));
}

static inline void
dns_hdr_ar_set(dns_hdr_p hdr, uint16_t val) {
	hdr->ar_count = htons(val);
}

static inline void
dns_hdr_ar_inc(dns_hdr_p hdr, uint16_t val) {
	hdr->ar_count = htons((uint16_t)(ntohs(hdr->ar_count) + val));
}

static inline void
dns_hdr_ar_dec(dns_hdr_p hdr, uint16_t val) {
	hdr->ar_count = htons((uint16_t)(ntohs(hdr->ar_count) - val));
}


static inline int
dns_hdr_create(uint16_t id, uint16_t flags, dns_hdr_p hdr, size_t msgbuf_size,
    size_t *msg_size_ret) {

	if (NULL != msg_size_ret)
		(*msg_size_ret) = sizeof(dns_hdr_t);
	if (msgbuf_size < sizeof(dns_hdr_t))
		return (EOVERFLOW);

	hdr->id = id;
	hdr->flags.u16 = flags;
	hdr->qd_count = 0;
	hdr->an_count = 0;
	hdr->ns_count = 0;
	hdr->ar_count = 0;

	return (0);
}


/*
 * Host byte order to network or network to host
 */
static inline void
dns_hdr_flip(dns_hdr_p hdr) {
	//hdr->id = htons(hdr->id);
	//hdr->flags.u16 = (hdr->flags.u16);
	hdr->qd_count = htons(hdr->qd_count);
	hdr->an_count = htons(hdr->an_count);
	hdr->ns_count = htons(hdr->ns_count);
	hdr->ar_count = htons(hdr->ar_count);
}

//////////////////////////////////////////////////////////////////////////
/////////////////////////// Name operations //////////////////////////////
//////////////////////////////////////////////////////////////////////////
/* Store name to DNS message, can compress it. */
static inline int
dns_msg_name2sequence_of_labels(dns_hdr_p hdr, size_t msgbuf_size, size_t offset,
    const uint8_t *name, size_t name_len, int compress, size_t *name_size_ret) {
	int error;
	uint8_t *buf;

	if (sizeof(dns_hdr_t) > offset || msgbuf_size < offset)
		return (EINVAL);

	if (0 != compress) // XXX not implemented et
		return (EOPNOTSUPP);

	buf = (((uint8_t*)hdr) + offset);
	error = DomainNameToSequenceOfLabels(name, name_len, buf,
	    (msgbuf_size - offset), name_size_ret);

	return (error);
}

/* Return uncompressed(!) name len. */
static inline int
dns_msg_sequence_of_labels_get_name_len(dns_hdr_p hdr, size_t msg_size,
    size_t offset, size_t *name_len_ret) {
	uint8_t *cur_pos, *new_pos, *max_pos;
	uint16_t label;
	size_t name_len, jumps;

	if (NULL == hdr || sizeof(dns_hdr_t) > offset ||
	    msg_size < offset || NULL == name_len_ret)
		return (EINVAL);
	if (sizeof(dns_hdr_t) > msg_size)
		return (EBADMSG);

	cur_pos = (((uint8_t*)hdr) + offset);
	max_pos = (cur_pos + msg_size); // XXX check this!
	name_len = 0;
	for (jumps = 0; jumps < DNS_MAX_NAME_CYCLES;) {// перебираем все куски текста
		label = (*((uint8_t*)cur_pos));
		if ((label & SEQ_LABEL_CTRL_MASK) == SEQ_LABEL_CTRL_COMPRESSED) {
			// SEQ_LABEL_CTRL_COMPRESSED означает что указанно смещение а не длинна
			offset = (ntohs((*((uint16_t *)cur_pos))) &
			    SEQ_LABEL_COMPRESSED_DATA_MASK);
			new_pos = (((uint8_t*)hdr) + offset);
			if (msg_size < offset || sizeof(dns_hdr_t) > offset ||
			    cur_pos == new_pos)
				return (EBADMSG);// bad pointer
			// pointer OK: in buf range, not pointed to self
			cur_pos = new_pos;
			jumps ++;
			continue;
		}
		if ((label & SEQ_LABEL_CTRL_MASK) != SEQ_LABEL_CTRL_LEN)
			return (EOPNOTSUPP);// unsupported label type (possible edns)
		label &= SEQ_LABEL_DATA_MASK;// now it contain len
		cur_pos ++; // now it points to data

		if ((cur_pos + label) > max_pos)
			return (EBADMSG); /* Out of buf range. */
		if (0 == label) { // null label = end of name, ALL DONE!!!
			if (0 != name_len) // clear last dot
				name_len --;
			(*name_len_ret) = name_len;
			return (0);
		}
		name_len += (label + 1);
		cur_pos += label;// move to next label
	}

	return (ELOOP);
}

/* Return uncompressed(!) name. */
static inline int
dns_msg_sequence_of_labels2name(dns_hdr_p hdr, size_t msg_size, size_t offset,
    uint8_t *name, size_t name_buf_size, size_t *name_len_ret) {
	uint8_t *cur_pos, *new_pos, *max_pos;
	uint16_t label;
	size_t name_len, jumps;

	if (NULL == hdr || NULL == name || 0 == name_buf_size ||
	    sizeof(dns_hdr_t) > offset || msg_size < offset)
		return (EINVAL);
	if (sizeof(dns_hdr_t) > msg_size)
		return (EBADMSG);

	cur_pos = (((uint8_t*)hdr) + offset);
	max_pos = (cur_pos + msg_size); // XXX check this!
	name_len = 0;
	for (jumps = 0; jumps < DNS_MAX_NAME_CYCLES;) {// перебираем все куски текста
		label = (*((uint8_t*)cur_pos));
		if ((label & SEQ_LABEL_CTRL_MASK) == SEQ_LABEL_CTRL_COMPRESSED) {
			// SEQ_LABEL_CTRL_COMPRESSED означает что указанно смещение а не длинна
			offset = (ntohs((*((uint16_t *)cur_pos))) &
			    SEQ_LABEL_COMPRESSED_DATA_MASK);
			new_pos = (((uint8_t*)hdr) + offset);
			if (msg_size < offset || sizeof(dns_hdr_t) > offset ||
			    cur_pos == new_pos)
				return (EBADMSG);// bad pointer
			// pointer OK: in buf range, not pointed to self
			cur_pos = new_pos;
			jumps ++;
			continue;
		}
		if ((label & SEQ_LABEL_CTRL_MASK) != SEQ_LABEL_CTRL_LEN)
			return (EOPNOTSUPP);// unsupported label type (possible edns)
		label &= SEQ_LABEL_DATA_MASK;// now it contain len
		cur_pos ++; // now it points to data

		if ((cur_pos + label) > max_pos)
			return (EBADMSG); /* Out of buf range. */
		if (0 == label) { // null label = end of name, ALL DONE!!!
			if (0 != name_len) {// clear last dot
				name_len --;
				name --;
			}
			(*name) = 0; // set zero at the end
			if (NULL != name_len_ret)
				(*name_len_ret) = name_len;
			return (0);
		}

		name_len += (label + 1);
		if (name_len >= name_buf_size) {
			if (NULL != name_len_ret) // return required len
				(*name_len_ret) = name_len;
			return (EOVERFLOW);
		}
		// место в буффере куда копируется имя ещё есть
		memcpy(name, cur_pos, label);
		name += label;
		(*name) = '.';
		name ++;
		cur_pos += label;// move to next label
	}

	return (ELOOP);
}

//////////////////////////////////////////////////////////////////////////
/////////////////////////////Question/////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
/* Question and increase question counter in DNS header. */
static inline int
dns_msg_question_add(dns_hdr_p hdr, size_t msg_size, size_t msgbuf_size,
    int compress, const uint8_t *name, size_t name_len, uint16_t query_type,
    uint16_t query_class, size_t *msg_size_ret) {
	int error;
	size_t labels_sequence_size, question_size;
	dns_question_p question;

	if (NULL == hdr)
		return (EINVAL);
	if (sizeof(dns_hdr_t) > msg_size)
		return (EBADMSG);
	question_size = (msg_size + (2 + name_len) +
	    (sizeof(dns_question_t) - sizeof(uint8_t*)));
	if (msgbuf_size < question_size) {
		if (NULL != msg_size_ret)
			(*msg_size_ret) = question_size;
		return (EOVERFLOW);
	}

	error = dns_msg_name2sequence_of_labels(hdr, msgbuf_size, msg_size,
	    name, name_len, compress, &labels_sequence_size);
	if (error != 0)
		return (error);

	question = (dns_question_p)((((size_t)hdr) + msg_size +
	    labels_sequence_size) - sizeof(uint8_t*));
	question_size = (msg_size + labels_sequence_size +
	    (sizeof(dns_question_t) - sizeof(uint8_t*)));

	//question->name;
	question->type = htons(query_type);
	question->class = htons(query_class);
	// увеличиваем счётчик вопросов в заголовке
	dns_hdr_qd_inc(hdr, 1);

	if (NULL != msg_size_ret)
		(*msg_size_ret) = question_size;

	return (error);
}

/* Extract and return Question data. */
static inline int
dns_msg_question_get_data(dns_hdr_p hdr, size_t msg_size, size_t offset,
    uint8_t *name, size_t *name_len, uint16_t *query_type, uint16_t *query_class,
    size_t *question_size_ret) {
	int error = 0;
	size_t name_size, question_size;
	dns_question_p question;

	if (NULL == hdr || 0 == offset || msg_size < offset)
		return (EINVAL);
	if (sizeof(dns_hdr_t) > msg_size)
		return (EBADMSG);

	/* Get name size to get access to another RR data. */
	if (0 != SequenceOfLabelsGetSize((((uint8_t*)hdr) + offset),
	    (msg_size - offset), &name_size))
		return (EBADMSG);
	question = (dns_question_p)((((size_t)hdr) + offset + name_size) -
	    sizeof(uint8_t*));
	question_size = (name_size + (sizeof(dns_question_t) - sizeof(uint8_t*)));
	if ((offset + question_size) > msg_size)
		return (EBADMSG); /* Out of buf range. */

	if (NULL != name && 0 != name_len)
		error = dns_msg_sequence_of_labels2name(hdr, msg_size, offset,
		    name, (*name_len), name_len);
	if (NULL != query_type)
		(*query_type) = ntohs(question->type);
	if (NULL != query_class)
		(*query_class) = ntohs(question->class);
	if (NULL != question_size_ret)
		(*question_size_ret) = question_size;

	return (error);
}


/* Return Question size. */
static inline int
dns_msg_question_get_size(dns_hdr_p hdr, size_t msg_size, size_t offset,
    size_t *question_size_ret) {
	return (dns_msg_question_get_data(hdr, msg_size, offset, NULL, NULL, NULL,
	    NULL, question_size_ret));
}

//////////////////////////////////////////////////////////////////////////
/////////////////////////////RR///////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
/* Add Resource Record data to DMS message. */
static inline int
dns_msg_rr_add(dns_hdr_p hdr, size_t msg_size, size_t msgbuf_size, int compress,
    const uint8_t *name, size_t name_len, uint16_t type, uint16_t class,
    uint32_t ttl, uint16_t data_size, void *data, size_t *rr_size) {
	int error;
	size_t labels_sequence_size, rr_size_tm;
	dns_rr_p rr;

	if (NULL == hdr)
		return (EINVAL);
	if (sizeof(dns_hdr_t) > msg_size)
		return (EBADMSG);
	rr_size_tm = (msg_size + (2 + name_len) + (sizeof(dns_rr_t) -
	    (sizeof(uint8_t*) + sizeof(uint8_t))) + data_size);
	if (NULL != rr_size)
		(*rr_size) = rr_size_tm;
	if (msgbuf_size < rr_size_tm) 
		return (EOVERFLOW);

	/* Store name in DNS message buff.  */
	error = dns_msg_name2sequence_of_labels(hdr, msgbuf_size,
	    msg_size, name, name_len, compress, &labels_sequence_size);
	if (error != 0)
		return (error);

	rr = (dns_rr_p)((((size_t)hdr) + msg_size + labels_sequence_size) -
	    sizeof(uint8_t*));
	rr_size_tm = (msg_size + labels_sequence_size + (sizeof(dns_rr_t) -
	    (sizeof(uint8_t*) + sizeof(uint8_t))) + data_size);

	//rr->name = ;
	rr->type = htons(type);
	rr->class = htons(class);
	rr->ttl = htonl(ttl);
	rr->rdlength = htons(data_size);
	memcpy(&rr->rdata, data, data_size);

	return (error);
}

/*
 * Add OPT pseudo Resource Record data:
 * RFC 2671 (Extension Mechanisms for DNS (EDNS0)).
 */
static inline int
dns_msg_optrr_add(dns_hdr_p hdr, size_t msg_size, size_t msgbuf_size,
    uint16_t udp_payload_size, uint8_t version, uint8_t ex_rcode, uint16_t ex_flags,
    uint16_t data_size, void *data, size_t *rr_size) {
	dns_opt_rr_p opt_rr;
	size_t rr_size_tm;

	if (NULL == hdr)
		return (EINVAL);
	if (sizeof(dns_hdr_t) > msg_size)
		return (EBADMSG);
	rr_size_tm = (msg_size + (sizeof(dns_opt_rr_t) - sizeof(uint8_t)) +
	    data_size);
	if (NULL != rr_size)
		(*rr_size) = rr_size_tm;
	if (msgbuf_size < rr_size_tm)
		return (EOVERFLOW);

	opt_rr = (dns_opt_rr_p)(((size_t)hdr) + msg_size);
	opt_rr->name = 0; /* Empty (root domain) = 0 */
	opt_rr->type = htons(DNS_RR_TYPE_OPT);
	opt_rr->udp_payload_size = htons(udp_payload_size);
	opt_rr->version = version;
	opt_rr->ex_rcode = ex_rcode;
	opt_rr->ex_flags.u16 = ex_flags;
	opt_rr->rdlength = htons(data_size);
	memcpy(&opt_rr->rdata, data, data_size);

	return (0);
}


/* Extract and return Resource Record data. */
static inline int
dns_msg_rr_get_data(dns_hdr_p hdr, size_t msg_size, size_t offset, uint8_t *name,
    size_t *name_len, uint16_t *type, uint16_t *class, uint32_t *ttl,
    uint16_t *data_size, void **data, size_t *rr_size) {
	int error = 0;
	size_t name_size, rr_size_tm;
	dns_rr_p dns_rr;

	if (NULL == hdr || 0 == msg_size || 0 == offset || msg_size < offset)
		return (EINVAL);
	if (sizeof(dns_hdr_t) > msg_size)
		return (EBADMSG);

	/* Get name size and skeep it to get other data. */
	if (0 != SequenceOfLabelsGetSize((((uint8_t*)hdr) + offset),
	    (msg_size - offset), &name_size))
		return (EBADMSG);

	dns_rr = (dns_rr_p)((((size_t)hdr) + offset + name_size) - sizeof(uint8_t*));
	rr_size_tm = (name_size + (sizeof(dns_rr_t) - (sizeof(uint8_t*) +
	    sizeof(uint8_t))) + ntohs(dns_rr->rdlength));
	if ((offset + rr_size_tm) > msg_size)
		return (EBADMSG); /* Out of buf range. */

	if (NULL != name && 0 != name_len)
		error = dns_msg_sequence_of_labels2name(hdr, msg_size, offset,
		    (uint8_t*)name, (*name_len), name_len);
	if (NULL != type)
		(*type) = ntohs(dns_rr->type);
	if (NULL != class)
		(*class) = ntohs(dns_rr->class);
	if (NULL != ttl)
		(*ttl) = ((ntohs(dns_rr->type) == DNS_RR_TYPE_OPT) ?
		    dns_rr->ttl :
		    ntohl(dns_rr->ttl));
	if (NULL != data_size)
		(*data_size) = ntohs(dns_rr->rdlength);
	if (NULL != data)
		(*data) = &dns_rr->rdata;
	if (NULL != rr_size)
		(*rr_size) = rr_size_tm;

	return (error);
}


/* Calculate and return Resouce Record size. */
static inline int
dns_msg_rr_get_size(dns_hdr_p hdr, size_t msg_size, size_t offset, size_t *rr_size) {
	return (dns_msg_rr_get_data(hdr, msg_size, offset, NULL, NULL, NULL, NULL,
	    NULL, NULL, NULL, rr_size));
}

/* Find and return Resource Records by name. */
static inline int
dns_msg_rr_find(dns_hdr_p hdr, size_t msg_size, size_t *offset_ret, size_t *rr_count,
    const uint8_t *name, size_t name_len, uint16_t *type, uint16_t *class,
    uint32_t *ttl, uint16_t *data_size, void **data, size_t *rr_size) {
	int error;
	uint8_t nametm[(DNS_MAX_NAME_LENGTH * 2)];
	size_t i, offset, rr_size_tm = 0, name_lentm;

	if (NULL == hdr || NULL == offset_ret || NULL == rr_count ||
	    sizeof(nametm) < name_len)
		return (EINVAL);
	if (sizeof(dns_hdr_t) > msg_size || msg_size < (*offset_ret))
		return (EBADMSG);
	// search loop: extract data from first record, compare names
	// exit if found, or continue search untill buffer is in range, and
	// elements counter is not zero
	offset = (*offset_ret);
	for (i = (*rr_count); i != 0; ) {
		i --;
		name_lentm = sizeof(nametm);
		error = dns_msg_rr_get_data(hdr, msg_size, offset, nametm,
		    &name_lentm, type, class, ttl, data_size, data, &rr_size_tm);
		if (error != 0) { /* Out of buf range. */
			i = 0;
			goto out_ret;
		}
		if (0 == mem_cmpin(name, name_len, nametm, name_lentm)) {
			/* Founded!!! */
			if (NULL != rr_size)
				(*rr_size) = rr_size_tm;
			goto out_ret;
		}
		offset += rr_size_tm;
	}
	error = ESPIPE;

out_ret:
	(*offset_ret) = offset;
	(*rr_count) = i;
	return (error);	
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////DNSMessage//////////////////////////////////
//////////////////////////////////////////////////////////////////////////
/*
 * Validate DNS message;
 * return:
 * - offset for: QD, AN, NS and AR;
 * - resource Records count;
 * - real size.
 */
static inline int
dns_msg_info_get(dns_hdr_p hdr, size_t msgbuf_size, size_t *qd_off, size_t *an_off,
    size_t *ns_off, size_t *ar_off, size_t *rr_count, size_t *msg_size_ret) {
	int error;
	size_t i, tm, count;
	size_t offset, qd_offset, an_offset, ns_offset, ar_offset, total_rr_count;

	if (NULL == hdr)
		return (EINVAL);
	if (sizeof(dns_hdr_t) > msgbuf_size)
		return (EBADMSG);

	tm = 0; // supress warnings about using uninitialized
	qd_offset = sizeof(dns_hdr_t);
	offset = qd_offset;
	an_offset = 0;
	ns_offset = 0;
	ar_offset = 0;
	total_rr_count = 0;

	/* Questions: check... */
	count = dns_hdr_qd_get(hdr);
	for (i = 0; i < count; i ++) {
		error = dns_msg_question_get_size(hdr, msgbuf_size, offset, &tm);
		if (error != 0)
			return (error);
		offset += tm;
	}
	an_offset = offset;

	/* ANswers: check... */
	count = dns_hdr_an_get(hdr);
	total_rr_count += count;
	for (i = 0; i < count; i ++) {
		error = dns_msg_rr_get_size(hdr, msgbuf_size, offset, &tm);
		if (error != 0)
			return (error);
		offset += tm;
	}
	ns_offset = offset;
	/* Name Servers: check... */
	count = dns_hdr_ns_get(hdr);
	total_rr_count += count;
	for (i = 0; i < count; i ++) {
		error = dns_msg_rr_get_size(hdr, msgbuf_size, offset, &tm);
		if (error != 0)
			return (error);
		offset += tm;
	}
	ar_offset = offset;
	/* Additional Records: check... */
	count = dns_hdr_ar_get(hdr);
	total_rr_count += count;
	for (i = 0; i < count; i ++) {
		error = dns_msg_rr_get_size(hdr, msgbuf_size, offset, &tm);
		if (error != 0)
			return (error);
		offset += tm;
	}
	/* Set return values. */
	if (NULL != qd_off)
		(*qd_off) = qd_offset;
	if (NULL != an_off)
		(*an_off) = an_offset;
	if (NULL != ns_off)
		(*ns_off) = ns_offset;
	if (NULL != ar_off)
		(*ar_off) = ar_offset;
	if (NULL != rr_count)
		(*rr_count) = total_rr_count;
	if (NULL != msg_size_ret)
		(*msg_size_ret) = offset;

	return (0);
}


static inline size_t
dns_msg_size_get(dns_hdr_p hdr, size_t msgbuf_size) {
	size_t ret = 0;

	dns_msg_info_get(hdr, msgbuf_size, NULL, NULL, NULL, NULL, NULL, &ret);
	return (ret);
}


static inline int
dns_msg_validate(dns_hdr_p hdr, size_t msgbuf_size) {
	return (dns_msg_info_get(hdr, msgbuf_size, NULL, NULL, NULL, NULL, NULL,
	    NULL));
}



#endif // __DNSMESSAGE_H__
