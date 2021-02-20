/*-
 * Copyright (c) 2013 - 2016 Rozhuk Ivan <rozhuk.im@gmail.com>
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

/* http://www.dvb.org/standards */


#ifndef __MPEG2_H__
#define __MPEG2_H__

#include <sys/types.h>
#include <inttypes.h>
#include "mem_helpers.h"

#ifndef min
#	define min(a,b)		(((a) < (b)) ? (a) : (b))
#endif

#ifndef max
#	define max(a, b)	(((a) > (b)) ? (a) : (b))
#endif


/* 188, 192, 204, 208 bytes packets. */
#define MPEG2_TS_PKT_SIZE_188	188 /* MPEG-2 TS packet size */
#define MPEG2_TS_PKT_SIZE_192	192 /* MPEG-2 TS packet size */
#define MPEG2_TS_PKT_SIZE_204	204 /* MPEG-2 TS packet size */
#define MPEG2_TS_PKT_SIZE_208	208 /* MPEG-2 TS packet size */
#define MPEG2_TS_PKT_SIZE_MIN	MPEG2_TS_PKT_SIZE_188
#define MPEG2_TS_PKT_SIZE_MAX	MPEG2_TS_PKT_SIZE_208
#define MPEG2_TS_PKT_SIZES_CNT	4


/* Partial Transport Stream Packet */
typedef struct mpeg2_ts_hdr_s {
	uint8_t		sb;	/* sync byte = 0x47 */
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t		te:1;	/* Transport Error Indicator. */
	uint8_t		pus:1;	/* Payload Unit Start Indicator: 1 means start of PES data or PSI. */
	uint8_t		tp:1;	/* Transport Priority. */

	uint16_t	pid:13;	/* Packet ID. */

	uint8_t		sc:2;	/* Scrambling control. */
	uint8_t		afe:1;	/* Adaptation field exist. */
	uint8_t		cp:1;	/* Contains payload. */
	uint8_t		cc:4;	/* Continuity counter. */
#else
	uint8_t		pid_hi:5; /* Packet ID. */
	uint8_t		tp:1;	/* Transport Priority. */
	uint8_t		pus:1;	/* Payload Unit Start Indicator. */
	uint8_t		te:1;	/* Transport Error Indicator. */

	uint8_t		pid_lo;	/* Packet ID. */

	uint8_t		cc:4;	/* Continuity counter. */
	uint8_t		cp:1;	/* Contains payload. */
	uint8_t		afe:1;	/* Adaptation field exist. */
	uint8_t		sc:2;	/* Scrambling control. */
#endif
	/* Adaptation field. */
	/* Payload Data. */
} __attribute__((__packed__)) mpeg2_ts_hdr_t, *mpeg2_ts_hdr_p;

#define MPEG2_TS_SB		0x47

#if BYTE_ORDER == BIG_ENDIAN
	#define MPEG2_TS_PID(hdr)	((hdr)->pid)
	#define MPEG2_TS_PID_SET(hdr, pid) (hdr)->pid = (pid)
#else
	#define MPEG2_TS_PID(hdr)					\
	    (((uint16_t)(hdr)->pid_lo) | ((uint16_t)((hdr)->pid_hi << 8)))
	#define MPEG2_TS_PID_SET(hdr, pid)				\
	    { (hdr)->pid_lo = ((pid) & 0xff); (hdr)->pid_hi = (((pid) >> 8) & 0x1f); }
#endif

#define MPEG2_TS_PID_PAT	0x0000	/* Program Association Table. */
#define MPEG2_TS_PID_CAT	0x0001	/* Conditional Access Table. */
#define MPEG2_TS_PID_TSDT	0x0002	/* Transport Stream Description Table. */
#define MPEG2_TS_PID_IPMPCIT	0x0003	/* IPMP Control Information Table. */
#define MPEG2_TS_PID_NIT_DEF	0x0010	/* Network Information Table. Default PID value. */
#define MPEG2_TS_PID_SDT	0x0011	/* Service Description Table. */
#define MPEG2_TS_PID_EIT	0x0012	/* Event Information Table. */
#define MPEG2_TS_PID_RST	0x0013	/* Running Status Table. */
#define MPEG2_TS_PID_TDT	0x0014	/* Time and Date Table. */
#define MPEG2_TS_PID_EPG	0x0018	/* EPG Table. */
#define MPEG2_TS_PID_TT		0x001d	/* Test_data Table. */
#define MPEG2_TS_PID_DIT	0x001e	/* . */
#define MPEG2_TS_PID_SIT	0x001f	/* . */
#define MPEG2_TS_PID_NULL	0x1fff	/* Null packets. */
#define MPEG2_TS_PID__COUNT__	0x2000	/* PIDs count. */
// BAT- Bouquet Association Table (groups services into logical groups)
// SDT- Service Description Table (describes the name and other details of services)

#define MPEG2_TS_SC_NS		0 /* Not scrambled. */
#define MPEG2_TS_SC_RESERVED	1 /* Reserved for future use */
#define MPEG2_TS_SC_SEK		2 /* Scrambled with even key */
#define MPEG2_TS_SC_SOK		3 /* Scrambled with odd key */

#define MPEG2_TS_CC_MAX		0x0f /* Continuity counter max value. */
#define MPEG2_TS_CC_MASK	0x0f /* Continuity counter maask. */
#define MPEG2_TS_CC_GET_NEXT(val) (((val) + 1) & MPEG2_TS_CC_MASK)
#define MPEG2_TS_CC_GET_PREV(val) (((val) - 1) & MPEG2_TS_CC_MASK)

#define MPEG2_TS_HDR_IS_VALID(hdr)	(MPEG2_TS_SB == (hdr)->sb)
#define MPEG2_TS_HDR_GET_NEXT(hdr, size)				\
	((mpeg2_ts_hdr_p)(((uint8_t*)(hdr)) + (size)))
#define MPEG2_TS_HDR_GET_PREV(hdr, size)				\
	((mpeg2_ts_hdr_p)(((uint8_t*)(hdr)) - (size)))


/* Adaptation Field */
typedef struct mpeg2_ts_adapt_field_s {
	uint8_t		len;	/* Number of bytes in the adaptation field immediately following this byte */
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t		di:1;	/* Discontinuity indicator. */
	uint8_t		rai:1;	/* Random Access indicator. */
	uint8_t		espi:1;	/* Elementary stream priority indicator. */
	uint8_t		pcr:1;	/* PCR flag. */
	uint8_t		opcr:1;	/* OPCR flag. */
	uint8_t		sp:1;	/* Splicing point flag. */
	uint8_t		tpd:1;	/* Transport private data flag. */
	uint8_t		afx:1;	/* Adaptation field extension flag. */
#else
	uint8_t		afx:1;	/* Adaptation field extension flag. */
	uint8_t		tpd:1;	/* Transport private data flag. */
	uint8_t		sp:1;	/* Splicing point flag. */
	uint8_t		opcr:1;	/* OPCR flag. */
	uint8_t		pcr:1;	/* PCR flag. */
	uint8_t		espi:1;	/* Elementary stream priority indicator. */
	uint8_t		rai:1;	/* Random Access indicator. */
	uint8_t		di:1;	/* Discontinuity indicator. */
#endif
	/* PCR */
	/* OPCR */
	/* Splice countdown */
	/* data... */
} __attribute__((__packed__)) mpeg2_ts_adapt_field_t, *mpeg2_ts_adapt_field_p;


/* Adaptation Field PCR */
typedef struct mpeg2_ts_adapt_field_pcr_s {
#if BYTE_ORDER == BIG_ENDIAN
	uint64_t	base:33; /* program_clock_reference_base. */
	uint8_t		r0:6;	/* Reserved. */
	uint16_t	ext:9;	/* program_clock_reference_extension. */
#else
	uint64_t	base:33; /* program_clock_reference_base. */
	uint8_t		r0:6;	/* Reserved. */
	uint16_t	ext:9;	/* program_clock_reference_extension. */
#endif
} __attribute__((__packed__)) mpeg2_ts_adapt_field_pcr_t, *mpeg2_ts_adapt_field_pcr_p;






/*
 * Program-specific information (PSI)
 * (tables)
 */

/* Tables IDs */
/* MPEG-2 tables. */
#define MPEG2_PSI_TID_PAT	0x00 /* PID 0x0000 */
#define MPEG2_PSI_TID_CAT	0x01 /* PID 0x0001 */
#define MPEG2_PSI_TID_PMT	0x02
#define MPEG2_PSI_TID_TSDT	0x03 /* PID 0x0002: Transport Stream Description Table. */
/* DVB tables. */
#define MPEG2_PSI_TID_NIT	0x40 /* PID 0x0010: Information about the current network. */
#define MPEG2_PSI_TID_NIT_OTH	0x41 /* PID 0x0010: Information about other networks. */
#define MPEG2_PSI_TID_SDT	0x42 /* PID 0x0011: SDT which describe the actual TS. */
#define MPEG2_PSI_TID_SDT_OTH	0x46 /* PID 0x0011: SDT Information about other networks. */
#define MPEG2_PSI_TID_EIT_A	0x4e /* PID 0x0012: actual TS, present/following event */
#define MPEG2_PSI_TID_EIT_O	0x4f /* PID 0x0012: other TS, present/following event */
#define MPEG2_PSI_TID_EIT_AS_MIN 0x50 /* PID 0x0012: actual TS, event schedule information */
#define MPEG2_PSI_TID_EIT_AS_MAX 0x5f /* PID 0x0012: actual TS, event schedule information */
#define MPEG2_PSI_TID_EIT_OS_MIN 0x60 /* PID 0x0012: other TS, event schedule information */
#define MPEG2_PSI_TID_EIT_OS_MAX 0x6f /* PID 0x0012: other TS, event schedule information */
#define MPEG2_PSI_TID_TDT	0x70 /* PID 0x0014 */
#define MPEG2_PSI_TID_TOT	0x73 /* PID 0x0014 */
#define MPEG2_PSI_TID_STUFF	0xff /* Stuffing, bytes may be discarded by a decoder. */


//uint8_t pf:8;			/* If PUS is set. Pointer field: offset to payload data. */


/* Program-specific information: Table header */
typedef struct mpeg2_psi_tbl_hdr_s { /* Table base header. */
	uint8_t		tid;	/* Table ID */
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t		ss:1;	/* Section syntax indicator: Always 1 for PAT */
	uint8_t		pr:1;	/* Private bit: PAT, PMT, CAT set this to 0. Other tables set this to 1 */
	uint8_t		r0:2;	/* Always set to binary '11' */
	uint16_t	sec_len:12; /* Section length: -5 bytes */
#else
	uint8_t		sec_len_hi:4; /* Section length */
	uint8_t		r0:2;	/* Always set to binary '11' */
	uint8_t		pr:1;	/* Private bit: PAT, PMT, CAT set this to 0. Other tables set this to 1 */
	uint8_t		ss:1;	/* Section syntax indicator: Always 1 for PAT */

	uint8_t		sec_len_lo; /* Section length */
#endif
	/* Syntax section/Table data... */
	// uint32_t crc32:32;	/* CRC32 */ */
} __attribute__((__packed__)) mpeg2_psi_tbl_hdr_t, *mpeg2_psi_tbl_hdr_p;
#if BYTE_ORDER == BIG_ENDIAN
	#define MPEG2_PSI_TBL_SEC_LEN(hdr)	(((hdr)->sec_len) & 0x3ff)
#else
	#define MPEG2_PSI_TBL_SEC_LEN(hdr)				\
	    ((((uint16_t)(hdr)->sec_len_lo) | ((uint16_t)((hdr)->sec_len_hi << 8))) & 0x3ff)
#endif

#define MPEG2_PSI_SEC_LEN_MAX		1024
#define MPEG2_PSI_SEC_LEN_PRIV_MAX	4096


/* Program-specific information: Section syntax */
typedef struct mpeg2_psi_tbl_sntx_s { /* Program association table */
	uint16_t	tid_ext; /* Table ID extension: User defined data / Informational only identifier. */
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t		r0:2;	/* Always set to binary '11' */
	uint8_t		ver:5;	/* Version number */
	uint8_t		cn:1;	/* Current/next indicator */
#else
	uint8_t		cn:1;	/* Current/next indicator */
	uint8_t		ver:5;	/* Version number */
	uint8_t		r0:2;	/* Always set to binary '11' */
#endif
	uint8_t		sn;	/* Section number */
	uint8_t		lsn;	/* Last section number */
	/* sections... */
	// uint32_t crc32:32;	/* CRC32 */ */
} __attribute__((__packed__)) mpeg2_psi_tbl_sntx_t, *mpeg2_psi_tbl_sntx_p;

#define MPEG2_TS_PSI_TBL_VER_MAX	0x1f /* PSI table max value. */
#define MPEG2_TS_PSI_TBL_VER_MASK	0x1f /* PSI table mask. */
#define MPEG2_TS_PSI_TBL_VER_GET_NEXT(val)				\
	(((val) + 1) & MPEG2_TS_PSI_TBL_VER_MASK)
#define MPEG2_TS_PSI_TBL_VER_GET_PREV(val)				\
	(((val) - 1) & MPEG2_TS_PSI_TBL_VER_MASK)
#define MPEG2_PSI_IS_PAT_HDR(hdr)					\
	(MPEG2_PSI_TID_PAT == (hdr)->tid && 1 == (hdr)->ss && 0 == (hdr)->pr)


/* Program association table syntax */
typedef struct mpeg2_psi_pat_sntx_s {
	uint16_t	tsid;	/* transport stream ID: User defined data. */
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t		r0:2;	/* Always set to binary '11' */
	uint8_t		ver:5;	/* Version number */
	uint8_t		cn:1;	/* Current/next indicator */
#else
	uint8_t		cn:1;	/* Current/next indicator */
	uint8_t		ver:5;	/* Version number */
	uint8_t		r0:2;	/* Always set to binary '11' */
#endif
	uint8_t		sn;	/* Section number */
	uint8_t		lsn;	/* Last section number */
	/* sections... */
	// uint32_t crc32:32;	/* CRC32 */ */
} __attribute__((__packed__)) mpeg2_psi_pat_sntx_t, *mpeg2_psi_pat_sntx_p;


/* Program association table section: 4 bytes */
typedef struct mpeg2_psi_pat_sec_s {
	uint16_t	pn;	/* Program num. */
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t		r0:3;	/* Reserved: Always set to binary '111' */
	uint16_t	pid:13;	/* Packet ID / PMT PID. */
#else
	uint8_t		pid_hi:5; /* Packet ID / PMT PID. */
	uint8_t		r0:3;	/* Reserved: Always set to binary '111' */

	uint8_t		pid_lo;	/* Packet ID / PMT PID. */
#endif
} __attribute__((__packed__)) mpeg2_psi_pat_sec_t, *mpeg2_psi_pat_sec_p;

#if BYTE_ORDER == BIG_ENDIAN
	#define MPEG2_PSI_PAT_SEC_PID(hdr)	((hdr)->pid)
#else
	#define MPEG2_PSI_PAT_SEC_PID(hdr)				\
	    (((uint16_t)(hdr)->pid_lo) | ((uint16_t)((hdr)->pid_hi << 8)))
#endif



/* Conditional Access Table. */
#define MPEG2_PSI_IS_CAT_HDR(hdr)					\
	(MPEG2_PSI_TID_CAT == (hdr)->tid)



/* Program map table */
typedef struct mpeg2_psi_pmt_sntx_s {
	uint16_t	pnum;	/* Program num. */
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t		r0:2;	/* Always set to binary '11' */
	uint8_t		ver:5;	/* Version number */
	uint8_t		cn:1;	/* Current/next indicator */
#else
	uint8_t		cn:1;	/* Current/next indicator */
	uint8_t		ver:5;	/* Version number */
	uint8_t		r0:2;	/* Always set to binary '11' */
#endif
	uint8_t		sn;	/* Section number */
	uint8_t		lsn;	/* Last section number */
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t		r1:3;		/*  */
	uint16_t	pcr_pid:13;	/* PCR PID of general timecode stream, or 0x1FFF */

	uint8_t		r2:4;		/*  */
	uint16_t	p_info_len:12;	/* Program info length: Sum size of following program descriptors. */
#else
	uint8_t		pcr_pid_hi:5;	/* PCR PID of general timecode stream, or 0x1FFF */
	uint8_t		r1:3;		/*  */

	uint8_t		pcr_pid_lo;	/* PCR PID of general timecode stream, or 0x1FFF */

	uint8_t		p_info_len_hi:4; /* Program info length: Sum size of following program descriptors. */
	uint8_t		r2:4;		/*  */

	uint8_t		p_info_len_lo;	/* Program info length: Sum size of following program descriptors. */
#endif
	// uint8_t p_descr[]; /* Program descriptor */
	/* sections... */
	// uint32_t crc32:32;	/* CRC32 */ */
} __attribute__((__packed__)) mpeg2_psi_pmt_sntx_t, *mpeg2_psi_pmt_sntx_p;

#if BYTE_ORDER == BIG_ENDIAN
	#define MPEG2_PSI_PMT_PCR_PID(hdr)	((hdr)->pcr_pid)
	#define MPEG2_PSI_PMT_P_INFO_LEN(hdr)	((hdr)->p_info_len)
#else
	#define MPEG2_PSI_PMT_PCR_PID(hdr)				\
	    (((uint16_t)(hdr)->pcr_pid_lo) | ((uint16_t)((hdr)->pcr_pid_hi << 8)))
	#define MPEG2_PSI_PMT_P_INFO_LEN(hdr)				\
	    (((uint16_t)(hdr)->p_info_len_lo) | ((uint16_t)((hdr)->p_info_len_hi << 8)))
#endif
#define MPEG2_PSI_IS_PMT_HDR(hdr)					\
	(MPEG2_PSI_TID_PMT == (hdr)->tid && 1 == (hdr)->ss)
#define MPEG2_PSI_IS_PMT_SNTX(sntx)					\
	(0 == (sntx)->sn && 0 == (sntx)->lsn)

/* Program association table section */
typedef struct mpeg2_psi_pmt_sec_s {
	uint8_t		s_type;		/* stream type */
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t		r0:3;		/* Reserved: Always set to binary '111' */

	uint16_t	epid:13; 	/* Elementary PID. */

	uint8_t		r1:4;		/*  */
	uint16_t	es_info_len:12; /* ES Info length */
#else
	uint8_t		epid_hi:5;	/* Elementary PID. */
	uint8_t		r0:3;		/* Reserved: Always set to binary '111' */

	uint8_t		epid_lo;	/* Elementary PID. */

	uint8_t		es_info_len_hi:4; /* ES Info length. */
	uint8_t		r1:4;		/*  */

	uint8_t		es_info_len_lo;	/* ES Info length. */
#endif
	//uint8_t es_descr[];	/* ES Descriptor. */
} __attribute__((__packed__)) mpeg2_psi_pmt_sec_t, *mpeg2_psi_pmt_sec_p;

#if BYTE_ORDER == BIG_ENDIAN
	#define MPEG2_PSI_PMT_SEC_EPID(hdr)	((hdr)->epid)
	#define MPEG2_PSI_PMT_SEC_ES_INFO_LEN(hdr) ((hdr)->es_info_len)
#else
	#define MPEG2_PSI_PMT_SEC_EPID(hdr)				\
	    (((uint16_t)(hdr)->epid_lo) | ((uint16_t)((hdr)->epid_hi << 8)))
	#define MPEG2_PSI_PMT_SEC_ES_INFO_LEN(hdr)			\
	    (((uint16_t)(hdr)->es_info_len_lo) | ((uint16_t)((hdr)->es_info_len_hi << 8)))
#endif



/* Transport Stream Description Table. */
#define MPEG2_PSI_IS_TSDT_HDR(hdr)					\
	(MPEG2_PSI_TID_TSDT == (hdr)->tid)



/* Service description table */
typedef struct mpeg2_psi_sdt_sntx_s {
	uint16_t	tsid;	/* transport_stream_id . */
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t		r0:2;	/* Always set to binary '11' */
	uint8_t		ver:5;	/* Version number */
	uint8_t		cn:1;	/* Current/next indicator */
#else
	uint8_t		cn:1;	/* Current/next indicator */
	uint8_t		ver:5;	/* Version number */
	uint8_t		r0:2;	/* Always set to binary '11' */
#endif
	uint8_t		sn;	/* Section number */
	uint8_t		lsn;	/* Last section number */
	uint16_t	onid;	/* original_network_id */
	uint8_t		r1;	/* Reserved. */
	/* sections... */
	// uint32_t crc32:32;	/* CRC32 */ */
	/* payload data */
} __attribute__((__packed__)) mpeg2_psi_sdt_sntx_t, *mpeg2_psi_sdt_sntx_p;

#define MPEG2_PSI_IS_SDT_HDR(hdr)					\
	((MPEG2_PSI_TID_SDT == (hdr)->tid || MPEG2_PSI_TID_SDT_OTH == (hdr)->tid) && 1 == (hdr)->pr)

/* Service description table section */
typedef struct mpeg2_psi_sdt_sec_s {
	uint16_t	sid;		/* service_id */
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t		r0:6;		/* Reserved */
	uint8_t		eit_shed:1;	/* EIT_schedule_flag */
	uint8_t		eit_pf:1;	/* EIT_present_following_flag */

	uint8_t		rstatus:3;	/* running_status */
	uint8_t		free_ca:1;	/* free_CA_mode */
	uint16_t	descrs_len:12;	/* descriptors_loop_length */
#else
	uint8_t		eit_pf:1;	/* EIT_present_following_flag */
	uint8_t		eit_shed:1;	/* EIT_schedule_flag */
	uint8_t		r0:6;		/* Reserved */

	uint8_t		descrs_len_hi:4; /* descriptors_loop_length. */
	uint8_t		free_ca:1;	/* free_CA_mode */
	uint8_t		rstatus:3;	/* running_status */

	uint8_t		descrs_len_lo;	/* descriptors_loop_length */
#endif
	//uint8_t es_descr[];	/* ES Descriptor. */
} __attribute__((__packed__)) mpeg2_psi_sdt_sec_t, *mpeg2_psi_sdt_sec_p;

#if BYTE_ORDER == BIG_ENDIAN
	#define MPEG2_PSI_SDT_SEC_DESCRS_LEN(hdr) ((hdr)->descrs_len)
#else
	#define MPEG2_PSI_SDT_SEC_DESCRS_LEN(hdr)			\
	    (((uint16_t)(hdr)->descrs_len_lo) | ((uint16_t)((hdr)->descrs_len_hi << 8)))
#endif



typedef struct mpeg2_psi_eit_sntx_s {
	uint16_t	sid;	/* service_id. */
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t		r0:2;	/* Always set to binary '11' */
	uint8_t		ver:5;	/* Version number */
	uint8_t		cn:1;	/* Current/next indicator */
#else
	uint8_t		cn:1;	/* Current/next indicator */
	uint8_t		ver:5;	/* Version number */
	uint8_t		r0:2;	/* Always set to binary '11' */
#endif
	uint8_t		sn;	/* Section number */
	uint8_t		lsn;	/* Last section number */
	uint16_t	tid;	/* transport_stream_id */
	uint16_t	onid;	/* original_network_id */
	uint8_t		slsn;	/* segment_last_section_number. */
	uint8_t		ltid;	/* last_table_id. */
	/* sections... */
	// uint32_t crc32:32;	/* CRC32 */ */
	/* payload data */
} __attribute__((__packed__)) mpeg2_psi_eit_sntx_t, *mpeg2_psi_eit_sntx_p;

#define MPEG2_PSI_IS_EIT_HDR(hdr)					\
	((MPEG2_PSI_TID_EIT_A <= (hdr)->tid && MPEG2_PSI_TID_EIT_OS_MAX >= (hdr)->tid) && 1 == (hdr)->pr)

typedef struct mpeg2_psi_eit_sec_s {
	uint16_t	eid;		/* event_id */
	uint64_t	stime:40;	/* start_time */
	uint32_t	duration:24;	/* duration */
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t		rstatus:3;	/* running_status */
	uint8_t		free_ca:1;	/* free_CA_mode */
	uint16_t	descrs_len:12;	/* descriptors_loop_length */
#else
	uint8_t		descrs_len_hi:4; /* descriptors_loop_length. */
	uint8_t		free_ca:1;	/* free_CA_mode */
	uint8_t		rstatus:3;	/* running_status */

	uint8_t		descrs_len_lo;	/* descriptors_loop_length */
#endif
	//uint8_t es_descr[];	/* ES Descriptor. */
} __attribute__((__packed__)) mpeg2_psi_eit_sec_t, *mpeg2_psi_eit_sec_p;

#if BYTE_ORDER == BIG_ENDIAN
	#define MPEG2_PSI_EIT_SEC_DESCRS_LEN(hdr) ((hdr)->descrs_len)
#else
	#define MPEG2_PSI_EIT_SEC_DESCRS_LEN(hdr)			\
	    (((uint16_t)(hdr)->descrs_len_lo) | ((uint16_t)((hdr)->descrs_len_hi << 8)))
#endif







/* Descriptor */
typedef struct mpeg2_ts_descriptor_hdr_s {
	uint8_t		tag;	/* descriptor_tag identifies each descriptor. */
	uint8_t		len;	/* num of bytes of the descriptor immediately following descriptor_length field. */
	/* descriptor data. */
} __attribute__((__packed__)) mpeg2_ts_descr_hdr_t, *mpeg2_ts_descr_hdr_p;

#define MPEG2_DESCR_TAG(ptr)	((mpeg2_ts_descr_hdr_p)(ptr))->tag
#define MPEG2_DESCR_DATA_LEN(ptr) ((mpeg2_ts_descr_hdr_p)(ptr))->len
#define MPEG2_DESCR_DATA(ptr)	(((uint8_t*)(ptr)) + sizeof(mpeg2_ts_descr_hdr_t))
#define MPEG2_DESCR_NEXT(ptr)						\
    (mpeg2_ts_descr_hdr_p)(((uint8_t*)MPEG2_DESCR_DATA(ptr)) + MPEG2_DESCR_DATA_LEN(ptr))







/*
 * Packetized elementary stream.
 */

/* http://dvd.sourceforge.net/dvdinfo/pes-hdr.html */
/* http://dvd.sourceforge.net/dvdinfo/mpeghdrs.html */
/* http://en.wikipedia.org/wiki/Packetized_elementary_stream */

/* Packetized Elementary Stream Header */
typedef struct mpeg2_pes_hdr_s {
	uint32_t	pscp:24; /* Packet start code prefix = 0x000001 */
	uint8_t		sid;	/* Stream ID. */
	uint16_t	len;	/* PES Packet length. */
	/* Optional PES header (length >= 9) */
	/* Stuffing bytes */
	/* Data... */
} __attribute__((__packed__)) mpeg2_pes_hdr_t, *mpeg2_pes_hdr_p;

#if BYTE_ORDER == BIG_ENDIAN
	#define MPEG2_PES_PSCP		0x000001
#else
	#define MPEG2_PES_PSCP		0x010000
#endif

#define MPEG2_PES_SID_PRIV_GOP		0xb8 /* Group of Pictures */
#define MPEG2_PES_SID_PRIV_STREAM1	0xbd /* AC-3, Enhanced AC-3 or DTS / Private stream 1 (non MPEG audio, subpictures) */
#define MPEG2_PES_SID_PAD_STREAM	0xbe /* Padding stream */
#define MPEG2_PES_SID_PRIV_STREAM2	0xbf /* Private stream 2 (navigation data) */
#define MPEG2_PES_SID_AUDIO_START	0xc0
#define MPEG2_PES_SID_AUDIO_END		0xdf
#define MPEG2_PES_SID_VIDEO_START	0xe0
#define MPEG2_PES_SID_VIDEO_END		0xef
#define MPEG2_PES_SID_IS_AUDIO(sid)	(MPEG2_PES_SID_AUDIO_START <= (sid) && MPEG2_PES_SID_AUDIO_END >= (sid))
#define MPEG2_PES_SID_IS_VIDEO(sid)	(MPEG2_PES_SID_VIDEO_START <= (sid) && MPEG2_PES_SID_VIDEO_END >= (sid))

#define MPEG2_TS_PES_IS_VALID(hdr)	(MPEG2_PES_PSCP == (hdr)->pscp)

/* Packetized Elementary Stream Option Header */
typedef struct mpeg2_pes_opt_hdr_s {
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t		m:2;		/* Marker bits = 0x2 */
	uint8_t		sc:2;		/* Scrambling control */
	uint8_t		prio:1;		/* Priority */
	uint8_t		da:1;		/* Data alignment indicator */
	uint8_t		cr:1;		/* Copyright */
	uint8_t		ooc:1;		/* Original or Copy */

	uint8_t		pts_dts:2;	/* PTS DTS indicator */
	uint8_t		escr:1;		/* ESCR flag */
	uint8_t		esr:1;		/* ES rate flag */
	uint8_t		dsmtm:1;	/* DSM trick mode flag */
	uint8_t		aci:1;		/* Additional copy info flag */
	uint8_t		crc:1;		/* CRC flag */
	uint8_t		ex:1;		/* extension flag */
#else
	uint8_t		ooc:1;		/* Original or Copy */
	uint8_t		cr:1;		/* Copyright */
	uint8_t		da:1;		/* Data alignment indicator */
	uint8_t		prio:1;		/* Priority */
	uint8_t		sc:2;		/* Scrambling control */
	uint8_t		m:2;		/* Marker bits = 0x2 */

	uint8_t		ex:1;		/* extension flag */
	uint8_t		crc:1;		/* CRC flag */
	uint8_t		aci:1;		/* Additional copy info flag */
	uint8_t		dsmtm:1;	/* DSM trick mode flag */
	uint8_t		esr:1;		/* ES rate flag */
	uint8_t		escr:1;		/* ESCR flag */
	uint8_t		pts_dts:2;	/* PTS DTS indicator */
#endif
	uint8_t pes_hdr_len;	/* PES header length */
	/* Optional fields */
	/* Stuffing Bytes */
} __attribute__((__packed__)) mpeg2_pes_opt_hdr_t, *mpeg2_pes_opt_hdr_p;



/*
 * Elementary stream.
 */
/* Elementary Stream Video Header */
typedef struct mpeg2_es_video_hdr_s {
	uint32_t	sc;		/* start code = 0x000001b3 */
#if BYTE_ORDER == BIG_ENDIAN
	uint16_t	hs:12;		/* Horizontal Size. */

	uint16_t	vs:12;		/* Vertical Size. */

	uint8_t		ar:4;		/* Aspect ratio. */
	uint8_t		frc:4;		/* Frame rate code. */

	uint32_t	bit_rate:18;	/* Bit rate */
	uint8_t		m:1;		/* Marker bit. */
	uint16_t	vbvs:10;	/* VBV buf size: Size of video buffer verifier = 16*1024*vbv buf size */
	uint8_t		cp:1;		/* constrained parameters flag. */
	uint8_t		liqm:1;		/* load intra quantizer matrix. */
#else
#endif
	/* intra quantizer matrix: 0 or 64*8 */
	// uint8_t lniqm:1;	/* load non intra quantizer matrix. */
	/* non intra quantizer matrix: 0 or 64*8 */
	/* Data... */
} __attribute__((__packed__)) mpeg2_es_video_hdr_t, *mpeg2_es_video_hdr_p;

#if BYTE_ORDER == BIG_ENDIAN
	#define MPEG2_ES_VIDEO_HDR_SC		0x000001b3
#else
	#define MPEG2_ES_VIDEO_HDR_SC		0xb3010000
#endif





static inline int
mpeg2_ts_pkt_is_valid(mpeg2_ts_hdr_p ts_hdr, const size_t mpeg2_ts_pkt_size) {
	uint8_t *buf_pos;
	uint32_t pid;
	mpeg2_ts_adapt_field_p af;

	if (NULL == ts_hdr ||
	    MPEG2_TS_PKT_SIZE_MIN > mpeg2_ts_pkt_size ||
	    MPEG2_TS_PKT_SIZE_MAX < mpeg2_ts_pkt_size)
		return (0);
	if (0 == MPEG2_TS_HDR_IS_VALID(ts_hdr))
		return (0);
	pid = MPEG2_TS_PID(ts_hdr);
	if (MPEG2_TS_PID_NULL == pid) /* Null packets. */
		return (1);
	buf_pos = ((uint8_t*)(ts_hdr + 1)); /* Move pointer */
	
	if (0 != ts_hdr->afe) { /* Adapt feild. */
		af = ((mpeg2_ts_adapt_field_p)buf_pos);
		if ((af->len > (mpeg2_ts_pkt_size - 6) && 0 != ts_hdr->cp) ||
		    (af->len > (mpeg2_ts_pkt_size - 5) && 0 == ts_hdr->cp)) {
			return (0);
		}
		buf_pos += (1 + af->len); /* Move pointer */
	}
	/* End of Transport stream packet headers. */

	/* PSI: Program specific information processing. */
	switch (pid) {
	case MPEG2_TS_PID_PAT: /* Program Association Table. */
		if (0 == MPEG2_PSI_IS_PAT_HDR(((mpeg2_psi_tbl_hdr_p)buf_pos)))
			return (0);
		return (1);
	case MPEG2_TS_PID_CAT: /* Conditional Access Table. */
		if (0 == MPEG2_PSI_IS_CAT_HDR(((mpeg2_psi_tbl_hdr_p)buf_pos)))
			return (0);
		return (1);
	case MPEG2_TS_PID_TSDT: /* Transport Stream Description Table. */
		if (0 == MPEG2_PSI_IS_TSDT_HDR(((mpeg2_psi_tbl_hdr_p)buf_pos)))
			return (0);
		return (1);
	case MPEG2_TS_PID_SDT: /* Service Description Table. */
		if (0 == MPEG2_PSI_IS_SDT_HDR(((mpeg2_psi_tbl_hdr_p)buf_pos)))
			return (0);
		return (1);
	case MPEG2_TS_PID_EIT: /* Event Information Table. */
		if (0 == MPEG2_PSI_IS_EIT_HDR(((mpeg2_psi_tbl_hdr_p)buf_pos)))
			return (0);
		return (1);
	}

	return (1);
}


#define MPEG2_TS_PKT_SIZE_DETECT_PKTS_MAX	64

static inline int
mpeg2_ts_pkt_size_detect(const uint8_t *buf, const size_t buf_size,
    size_t *mpeg2_ts_pkt_size) {
	const uint8_t *ptm, *buf_end, *pkts[MPEG2_TS_PKT_SIZE_DETECT_PKTS_MAX];
	size_t i, j, k, cnt, seq_len, pkt_sizes_max_seq_len[MPEG2_TS_PKT_SIZES_CNT];
	const size_t pkt_sizes[MPEG2_TS_PKT_SIZES_CNT] = {
		MPEG2_TS_PKT_SIZE_188, MPEG2_TS_PKT_SIZE_192,
		MPEG2_TS_PKT_SIZE_204, MPEG2_TS_PKT_SIZE_208
	};

	if (NULL == buf ||
	    MPEG2_TS_PKT_SIZE_MIN > buf_size ||
	    NULL == mpeg2_ts_pkt_size)
		return (EINVAL);
	/* Find possible packets. */
	ptm = buf;
	buf_end = (buf + buf_size);
	for (cnt = 0; cnt < MPEG2_TS_PKT_SIZE_DETECT_PKTS_MAX;) {
		ptm = mem_chr_ptr(ptm, buf, buf_size, MPEG2_TS_SB);
		if (NULL == ptm)
			break;
		if ((ptm + MPEG2_TS_PKT_SIZE_MAX) > buf_end ||
		    0 == mpeg2_ts_pkt_is_valid((mpeg2_ts_hdr_p)ptm, MPEG2_TS_PKT_SIZE_MAX)) {
			ptm ++;
			continue;
		}
		pkts[cnt] = ptm;
		cnt ++;
		ptm ++;
	}
	/* Analize. */
	if (0 == cnt)
		return (EINVAL);
	/* Find max seq len. */
	for (i = 0; i < MPEG2_TS_PKT_SIZES_CNT; i ++) {
		pkt_sizes_max_seq_len[i] = 0;
		for (j = 0; j < cnt; j ++) {
			if (pkt_sizes_max_seq_len[i] > (cnt - j))
				break; /* Max seq len allready found. */
			seq_len = 0;
			for (k = j; k < cnt; k ++) {
				if (0 < k &&
				    (pkts[(k - 1)] + pkt_sizes[i]) != pkts[k])
					break; /* Wrong packet size. */
				if ((pkts[k] + pkt_sizes[i]) > buf_end)
					break; /* Packet to big / out of buf. */
				if (0 == mpeg2_ts_pkt_is_valid((mpeg2_ts_hdr_p)pkts[k], pkt_sizes[i]))
					break;
				seq_len ++;
			}
			if (seq_len < pkt_sizes_max_seq_len[i])
				continue;
			pkt_sizes_max_seq_len[i] = seq_len;
		}
	}
	/* Find size of max valid packets count. */
	seq_len = 0; /* max size. */
	j = 0; /* index of max size. */
	for (i = 0; i < MPEG2_TS_PKT_SIZES_CNT; i ++) {
		if (seq_len > pkt_sizes_max_seq_len[i])
			continue;
		seq_len = pkt_sizes_max_seq_len[i];
		j = i;
	}
	(*mpeg2_ts_pkt_size) = pkt_sizes[j];

	return (0);
}

/* Return:
 * 1: pkt point to MPEG2-TS packet
 * 0: if MPEG2-TS packet not found
 */
static inline int
mpeg2_ts_pkt_get_next(const uint8_t *buf, const size_t buf_size,
    const size_t off, const size_t mpeg2_ts_pkt_size, uint8_t **pkt) {
	const uint8_t *ptm/*, *buf_end*/;
	const size_t _buf_size = (buf_size - (mpeg2_ts_pkt_size - 1));

	if (mpeg2_ts_pkt_size > (buf_size - off))
		return (0);
	ptm = (buf + off);
	if (0 != MPEG2_TS_HDR_IS_VALID((mpeg2_ts_hdr_p)ptm)) {
		(*pkt) = (uint8_t*)ptm;
		return (1);
	}
	/*buf_end = (buf + buf_size);*/
	for (;;) {
		ptm = mem_chr_ptr(ptm, buf, _buf_size, MPEG2_TS_SB);
		if (NULL == ptm)
			return (0);
		if (0 == MPEG2_TS_HDR_IS_VALID((mpeg2_ts_hdr_p)ptm)) {
			ptm ++;
			continue;
		}
#if 0
		if (mpeg2_ts_pkt_size < (ptm - buf) && /* Prev packet check. */
		    0 == MPEG2_TS_HDR_IS_VALID(MPEG2_TS_HDR_GET_PREV(ptm, mpeg2_ts_pkt_size))) {
			ptm ++;
			continue;
		}
		if (mpeg2_ts_pkt_size < (buf_end - ptm) && /* Next packet check. */
		    0 == MPEG2_TS_HDR_IS_VALID(MPEG2_TS_HDR_GET_NEXT(ptm, mpeg2_ts_pkt_size))) {
			ptm ++;
			continue;
		}
#endif
		(*pkt) = (uint8_t*)ptm;
		break;
	}
	return (1);
}



/* af_size, pointer_size: 0 = no field, 1 = empty field.
 * mpeg2_ts_pkt_size = MPEG2_TS_PKT_SIZE_188 = 188
 */
static inline int
mpeg2_ts_serialize_calc_size(const size_t af_size,
    const size_t pointer_size, const size_t data_size,
    const size_t mpeg2_ts_pkt_size, size_t *buf_size_ret, size_t *pkts_count_ret) {
	size_t pkts_count, pkt_data_size, tm;

	pkts_count = 0;
	/* First packet: header + adaptation + pointer field. */
	pkt_data_size = sizeof(mpeg2_ts_hdr_t); /* = 4 */
	if (0 != af_size) { /* Adaptation field. */
		pkt_data_size += af_size;
		if (mpeg2_ts_pkt_size < pkt_data_size) /* Is valid adapt field size? */
			return (EINVAL);
		if (mpeg2_ts_pkt_size == pkt_data_size) { /* First packet without payload. */
			/* afe = 1, cp = 0. */
			pkts_count ++;
			pkt_data_size = sizeof(mpeg2_ts_hdr_t);
		}/* else we have free space in packet. */
	}
	if (0 != pointer_size) { /* Pointer field. PSI packets with tables. */
		if (mpeg2_ts_pkt_size < (sizeof(mpeg2_ts_hdr_t) + pointer_size + sizeof(mpeg2_psi_tbl_hdr_t)) ||
		    sizeof(mpeg2_psi_tbl_hdr_t) > data_size) /* Is valid pointer field and data sizes? */
			return (EINVAL);
		pkt_data_size += pointer_size;
		if (mpeg2_ts_pkt_size < (pkt_data_size + sizeof(mpeg2_psi_tbl_hdr_t))) {
			/* In case Adaptation field: pkt_data_size(before += pointer_size) > sizeof(mpeg2_ts_hdr_t)
			 * no space for pointer + table head. */
			/* First packet without payload. */
			/* afe = 1, cp = 0. */
			pkts_count ++;
			pkt_data_size = (sizeof(mpeg2_ts_hdr_t) + pointer_size);
		}
	}
	pkts_count ++;

	/* Section chunks. */
	if ((mpeg2_ts_pkt_size - pkt_data_size) < data_size) {
		/* afe = 0, cp = 1. */
		tm = (data_size - (mpeg2_ts_pkt_size - pkt_data_size));
		pkts_count += (tm / (mpeg2_ts_pkt_size - sizeof(mpeg2_ts_hdr_t)));
		if (0 != (tm % (mpeg2_ts_pkt_size - sizeof(mpeg2_ts_hdr_t)))) {
			pkts_count ++;
		}
	}

	if (NULL != buf_size_ret) {
		(*buf_size_ret) = (mpeg2_ts_pkt_size * pkts_count);
	}
	if (NULL != pkts_count_ret) {
		(*pkts_count_ret) = pkts_count;
	}
	return (0);
}

static inline int
mpeg2_ts_serialize_data(const uint32_t pid, const uint8_t sc,
    const uint8_t cc,
    const uint8_t *af, const size_t af_size, const size_t pointer_size,
    const uint8_t *data, const size_t data_size, const size_t mpeg2_ts_pkt_size,
    uint8_t *buf, const size_t buf_size, size_t *buf_size_ret, size_t *pkts_count_ret,
    uint8_t *cc_ret) {
	size_t pkts_count, pkt_data_size, r_off, chunk_payload_size, tm;
	uint8_t _cc = cc, *w_pos;
	mpeg2_ts_hdr_p ts_hdr;

	if ((NULL == af && 0 != af_size) || (NULL == data && 0 != data_size) ||
	    NULL == buf || buf_size < mpeg2_ts_pkt_size)
		return (EINVAL);
	/* First packet: header + adaptation + pointer field. */
	pkts_count = 0;
	ts_hdr = (mpeg2_ts_hdr_p)buf;
	ts_hdr->sb = MPEG2_TS_SB; /* sync byte = 0x47 */
	ts_hdr->te = 0; /* Transport Error Indicator. */
	ts_hdr->pus = 1; /* Payload Unit Start Indicator. */
	ts_hdr->tp = 0; /* Transport Priority. */
	MPEG2_TS_PID_SET(ts_hdr, pid); /* Packet ID. */
	ts_hdr->sc = sc; /* Scrambling control. */
	ts_hdr->afe = 0; /* Adaptation field exist. */
	ts_hdr->cp = 1; /* Contains payload. */
	ts_hdr->cc = _cc; /* Continuity counter. */
	_cc = MPEG2_TS_CC_GET_NEXT(_cc);
	w_pos = ((uint8_t*)(ts_hdr + 1));
	pkt_data_size = sizeof(mpeg2_ts_hdr_t); /* = 4 */

	if (0 != af_size) { /* Adaptation field. */
		pkt_data_size += af_size;
		if (mpeg2_ts_pkt_size < pkt_data_size) /* Is valid adapt field size? */
			return (EINVAL);
		ts_hdr->afe = 1; /* Adaptation field exist. */
		memcpy(w_pos, af, af_size);
		if (mpeg2_ts_pkt_size == pkt_data_size) { /* First packet without payload. */
			/* afe = 1, cp = 0. */
			ts_hdr->cp = 0; /* Contains payload. */
			pkts_count ++;
			/* Init next packet. */
			ts_hdr = MPEG2_TS_HDR_GET_NEXT(ts_hdr, mpeg2_ts_pkt_size);
			ts_hdr->sb = MPEG2_TS_SB; /* sync byte = 0x47 */
			ts_hdr->te = 0; /* Transport Error Indicator. */
			ts_hdr->pus = 1; /* Payload Unit Start Indicator. */
			ts_hdr->tp = 0; /* Transport Priority. */
			MPEG2_TS_PID_SET(ts_hdr, pid); /* Packet ID. */
			ts_hdr->sc = sc; /* Scrambling control. */
			ts_hdr->afe = 0; /* Adaptation field exist. */
			ts_hdr->cp = 0; /* Contains payload. */
			ts_hdr->cc = _cc; /* Continuity counter. */
			_cc = MPEG2_TS_CC_GET_NEXT(_cc);
			w_pos = ((uint8_t*)(ts_hdr + 1));
			pkt_data_size = sizeof(mpeg2_ts_hdr_t);
		} else { /* we have free space in packet. */
			w_pos += af_size;
		}
	}
	if (0 != pointer_size) { /* Pointer field. PSI packets with tables. */
		if (mpeg2_ts_pkt_size < (sizeof(mpeg2_ts_hdr_t) + pointer_size + sizeof(mpeg2_psi_tbl_hdr_t)) ||
		    sizeof(mpeg2_psi_tbl_hdr_t) > data_size) /* Is valid pointer field and data sizes? */
			return (EINVAL);
		pkt_data_size += pointer_size;
		if (mpeg2_ts_pkt_size < (pkt_data_size + sizeof(mpeg2_psi_tbl_hdr_t))) {
			/* In case Adaptation field: pkt_data_size(before += pointer_size) > sizeof(mpeg2_ts_hdr_t)
			 * no space for pointer + table head. */
			/* First packet without payload. */
			/* afe = 1, cp = 0. */
			ts_hdr->cp = 0; /* Contains payload. */
			/* Staff padding. */
			memset(w_pos, 0xff, (mpeg2_ts_pkt_size - (pkt_data_size - pointer_size)));
			pkts_count ++;
			/* Init next packet. */
			ts_hdr = MPEG2_TS_HDR_GET_NEXT(ts_hdr, mpeg2_ts_pkt_size);
			ts_hdr->sb = MPEG2_TS_SB; /* sync byte = 0x47 */
			ts_hdr->te = 0; /* Transport Error Indicator. */
			ts_hdr->pus = 1; /* Payload Unit Start Indicator. */
			ts_hdr->tp = 0; /* Transport Priority. */
			MPEG2_TS_PID_SET(ts_hdr, pid); /* Packet ID. */
			ts_hdr->sc = sc; /* Scrambling control. */
			ts_hdr->afe = 0; /* Adaptation field exist. */
			ts_hdr->cp = 1; /* Contains payload. */
			ts_hdr->cc = _cc; /* Continuity counter. */
			_cc = MPEG2_TS_CC_GET_NEXT(_cc);
			w_pos = ((uint8_t*)(ts_hdr + 1));
			pkt_data_size = (sizeof(mpeg2_ts_hdr_t) + pointer_size);
		}
		(*w_pos) = (uint8_t)(pointer_size - 1); /* Store pointer size. */
		if (1 < pointer_size) { /* Supress warning. */
			memset((w_pos + 1), 0xff, (pointer_size - 1));
		}
		w_pos += pointer_size;
	}

	/* Free space in current packet VS data_size. */
	r_off = min((mpeg2_ts_pkt_size - pkt_data_size), data_size);
	memcpy(w_pos, data, r_off);
	pkt_data_size += r_off;
	if (mpeg2_ts_pkt_size > pkt_data_size) /* Staff padding. */
		memset((w_pos + r_off), 0xff, (mpeg2_ts_pkt_size - pkt_data_size));
	pkts_count ++;

	/* Section chunks. */
	if (r_off < data_size) { /* Not all data serialized. */
		chunk_payload_size = (mpeg2_ts_pkt_size - sizeof(mpeg2_ts_hdr_t));
		for (; data_size > r_off;) {
			ts_hdr = MPEG2_TS_HDR_GET_NEXT(ts_hdr, mpeg2_ts_pkt_size);
			ts_hdr->sb = MPEG2_TS_SB;
			ts_hdr->te = 0;
			ts_hdr->pus = 0;
			ts_hdr->tp = 0;
			MPEG2_TS_PID_SET(ts_hdr, pid);
			ts_hdr->sc = sc;
			ts_hdr->afe = 0;
			ts_hdr->cp = 1;
			ts_hdr->cc = _cc;
			_cc = MPEG2_TS_CC_GET_NEXT(_cc);
			tm = min(chunk_payload_size, (data_size - r_off));
			memcpy((ts_hdr + 1), &data[r_off], tm);
			if (chunk_payload_size > tm) {
				memset((((uint8_t*)(ts_hdr + 1)) + tm), 0xff,
				    (chunk_payload_size - tm));
			}
			r_off += tm;
			pkts_count ++;
		}
	}

	if (NULL != buf_size_ret) {
		(*buf_size_ret) = (mpeg2_ts_pkt_size * pkts_count);
	}
	if (NULL != pkts_count_ret) {
		(*pkts_count_ret) = pkts_count;
	}
	if (NULL != cc_ret) {
		(*cc_ret) = _cc;
	}
	return (0);
}




#endif /* __MPEG2_H__ */
