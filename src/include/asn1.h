/*-
 * Copyright (c) 2013 Rozhuk Ivan <rozhuk.im@gmail.com>
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


#ifndef __ASN_1_H__
#define __ASN_1_H__

#ifdef _WINDOWS
#define EINVAL		ERROR_INVALID_HANDLE
#define ESPIPE		2
#define EBADMSG		3
#define EDOM		4
#define EOVERFLOW	ERROR_BUFFER_OVERFLOW
#else
#include <sys/types.h>
#include <inttypes.h>
#endif



/* Identifier */
/* Bit: 7:8 - Class */
#define ASN_ID_F_CLASS_MASK	((uint8_t)0xc0)
#define ASN_ID_F_CLASS_UNIVERSAL ((uint8_t)0x00)
#define ASN_ID_F_CLASS_APP	((uint8_t)0x40)
#define ASN_ID_F_CLASS_CONTEXT	((uint8_t)0x80)
#define ASN_ID_F_CLASS_PRIVATE	((uint8_t)0xc0)

#define ASN_ID_CLASS_UNIVERSAL	(ASN_ID_F_CLASS_UNIVERSAL >> 6)
#define ASN_ID_CLASS_APP	(ASN_ID_F_CLASS_APP >> 6)
#define ASN_ID_CLASS_CONTEXT	(ASN_ID_F_CLASS_CONTEXT >> 6)
#define ASN_ID_CLASS_PRIVATE	(ASN_ID_F_CLASS_PRIVATE >> 6)

#define ASN_ID_CLASS_GET(byte)	((byte) >> 6)

/* Bit: 6 - P/C */
#define ASN_ID_F_PRIMITIVE	((uint8_t)0x00)
#define ASN_ID_F_CONSTRUCTED	((uint8_t)0x20)
#define ASN_IS_ID_CONSTRUCTED(byte) ((byte) & ASN_ID_F_CONSTRUCTED)

/* Bit: 1:5 - Class Tag */
/* Tags for ASN_CLASS_UNIVERSAL */
#define ASN_ID_CU_TAG_MASK	((uint8_t)0x1f)
#define ASN_ID_CU_TAG_EOC	((uint8_t)0x00) /* End-of-Content */
#define ASN_ID_CU_TAG_BOOLEAN	((uint8_t)0x01)
#define ASN_ID_CU_TAG_INTEGER	((uint8_t)0x02)
#define ASN_ID_CU_TAG_BIT_STR	((uint8_t)0x03)
#define ASN_ID_CU_TAG_OCTET_STR ((uint8_t)0x04)
#define ASN_ID_CU_TAG_NULL	((uint8_t)0x05)
#define ASN_ID_CU_TAG_OBJ_ID	((uint8_t)0x06)
#define ASN_ID_CU_TAG_OBJ_DESCR	((uint8_t)0x07)
#define ASN_ID_CU_TAG_EXTERNAL	((uint8_t)0x08)
#define ASN_ID_CU_TAG_REAL	((uint8_t)0x09)
#define ASN_ID_CU_TAG_ENUMERATED ((uint8_t)0x0a)
#define ASN_ID_CU_TAG_EMBEDDED_PDV ((uint8_t)0x0b)
#define ASN_ID_CU_TAG_UTF8_STR	((uint8_t)0x0c)
#define ASN_ID_CU_TAG_RELATIVE_OID ((uint8_t)0x0d)
/* e - reserved */
/* f - reserved */
#define ASN_ID_CU_TAG_SEQUENCE	((uint8_t)0x10)
#define ASN_ID_CU_TAG_SET	((uint8_t)0x11)
#define ASN_ID_CU_TAG_NUM_STR	((uint8_t)0x12)
#define ASN_ID_CU_TAG_PRINT_STR	((uint8_t)0x13) /* PrintableString */
#define ASN_ID_CU_TAG_T61_STR	((uint8_t)0x14)
#define ASN_ID_CU_TAG_VIDEOTEX_STR ((uint8_t)0x15)
#define ASN_ID_CU_TAG_IA5_STR	((uint8_t)0x16)
#define ASN_ID_CU_TAG_UTC_TIME	((uint8_t)0x17)
#define ASN_ID_CU_TAG_GEN_TIME	((uint8_t)0x18) /* GeneralizedTime */
#define ASN_ID_CU_TAG_GRAPH_STR ((uint8_t)0x19) /* GraphicString */
#define ASN_ID_CU_TAG_VIS_STR	((uint8_t)0x1a) /* VisibleString */
#define ASN_ID_CU_TAG_GEN_STR	((uint8_t)0x1b) /* GeneralString */
#define ASN_ID_CU_TAG_UNI_STR	((uint8_t)0x1c) /* UniversalString */
#define ASN_ID_CU_TAG_CHAR_STR	((uint8_t)0x1d) /* CHARACTER STRING */
#define ASN_ID_CU_TAG_BMP_STR	((uint8_t)0x1e)
#define ASN_ID_CU_TAG_LONG_FORM	((uint8_t)0x1f) /* long-form identifier */

#define ASN_ID_CLASS_TAG_GET(byte) ((byte) & ASN_ID_CU_TAG_MASK)

#define ASN_ID_F_PC		((uint8_t)0xff) /* Valid only in this array. */
/* ps flags for ASN_ID_CLASS_UNIVERSAL */
static const uint8_t asn_class_uni_ps[] = {
	ASN_ID_F_PRIMITIVE,	/* 0x00 */
	ASN_ID_F_PRIMITIVE,	/* 0x01 */
	ASN_ID_F_PRIMITIVE,	/* 0x02 */
	ASN_ID_F_PC,		/* 0x03 */
	ASN_ID_F_PC,		/* 0x04 */
	ASN_ID_F_PRIMITIVE,	/* 0x05 */
	ASN_ID_F_PRIMITIVE,	/* 0x06 */
	ASN_ID_F_PC,		/* 0x07 */
	ASN_ID_F_CONSTRUCTED,	/* 0x08 */
	ASN_ID_F_PRIMITIVE,	/* 0x09 */
	ASN_ID_F_PRIMITIVE,	/* 0x0a */
	ASN_ID_F_CONSTRUCTED,	/* 0x0b */
	ASN_ID_F_PC,		/* 0x0c */
	ASN_ID_F_PRIMITIVE,	/* 0x0d */
	ASN_ID_F_PC,		/* 0x0e -- */
	ASN_ID_F_PC,		/* 0x0f -- */
	ASN_ID_F_CONSTRUCTED,	/* 0x10 */
	ASN_ID_F_CONSTRUCTED,	/* 0x11 */
	ASN_ID_F_PC,		/* 0x12 */
	ASN_ID_F_PC,		/* 0x13 */
	ASN_ID_F_PC,		/* 0x14 */
	ASN_ID_F_PC,		/* 0x15 */
	ASN_ID_F_PC,		/* 0x16 */
	ASN_ID_F_PC,		/* 0x17 */
	ASN_ID_F_PC,		/* 0x18 */
	ASN_ID_F_PC,		/* 0x19 */
	ASN_ID_F_PC,		/* 0x1a */
	ASN_ID_F_PC,		/* 0x1b */
	ASN_ID_F_PC,		/* 0x1c */
	ASN_ID_F_PC,		/* 0x1d */
	ASN_ID_F_PC,		/* 0x1e */
	ASN_ID_F_PC		/* 0x1f -- */
};

/* Display names for ASN_ID_CLASS_UNIVERSAL */
static const char *asn_class_uni_dname[] = {
	/* 0x00 */ "EOC",
	/* 0x01 */ "BOOLEAN",
	/* 0x02 */ "INTEGER",
	/* 0x03 */ "BIT_STRING",
	/* 0x04 */ "OCTET STRING",
	/* 0x05 */ "NULL",
	/* 0x06 */ "OBJECT IDENTIFIER",
	/* 0x07 */ "Object Descriptor",
	/* 0x08 */ "EXTERNAL",
	/* 0x09 */ "REAL",
	/* 0x0a */ "ENUMERATED",
	/* 0x0b */ "EMBEDDED PDV",
	/* 0x0c */ "UTF8String",
	/* 0x0d */ "RELATIVE-OID",
	/* 0x0e */ "reserved 0x0e",
	/* 0x0f */ "reserved 0x0f",
	/* 0x10 */ "SEQUENCE",
	/* 0x11 */ "SET",
	/* 0x12 */ "NumericString",
	/* 0x13 */ "PrintableString", // ASCII subset
	/* 0x14 */ "T61String", // aka TeletexString
	/* 0x15 */ "VideotexString",
	/* 0x16 */ "IA5String", // ASCII
	/* 0x17 */ "UTCTime",
	/* 0x18 */ "GeneralizedTime",
	/* 0x19 */ "GraphicString",
	/* 0x1a */ "VisibleString", // ASCII subset
	/* 0x1b */ "GeneralString",
	/* 0x1c */ "UniversalString",
	/* 0x1d */ "CHARACTER STRING",
	/* 0x1e */ "BMPString",
	/* 0x1f */ "Long form of tag",
};


/* Length */
#define ASN_LEN_LONG		((uint8_t)0x80)
#define ASN_IS_LEN_LONG(byte)	((byte) & ASN_LEN_LONG)

#define ASN_BIT8		((uint8_t)0x80)



#define ASN_MIN_OID_LEN		2
#define ASN_MAX_OID_LEN		128 /* max subid's in an oid */
#define ASN_MAX_NAME_LEN	MAX_OID_LEN


static inline int
asn_parse(uint8_t *buf, size_t buf_size, size_t *offset, size_t *hdr_size,
    uint8_t *aclass, uint8_t *ps, size_t *atag, uint8_t **data, size_t *data_size) {
	uint8_t *cur_pos, *max_pos, cls, f_ps, *dt;
	size_t off = 0, h_size = 0, tag, tm, dt_size;

	if (NULL == buf || 0 == buf_size)
		return (EINVAL);
	if (NULL != offset) {
		off = (*offset);
		if (off > buf_size)
			return (EINVAL);
		if (off == buf_size)
			return (ESPIPE);
	}
	if (ASN_MIN_OID_LEN > (buf_size - off))
		return (EBADMSG);
	cur_pos = (buf + off);
	max_pos = (buf + buf_size);
	/* Identifier. */
	cls = ASN_ID_CLASS_GET((*cur_pos));
	f_ps = ASN_IS_ID_CONSTRUCTED((*cur_pos));
	tag = ASN_ID_CLASS_TAG_GET((*cur_pos));
	cur_pos ++;
	h_size ++;
	if (ASN_ID_CU_TAG_LONG_FORM == tag) {
		tag = 0;
		do { /* Shift and add in low order 7 bits. */
			tag <<= 7;
			tag |= ((*cur_pos) & ~ASN_BIT8); // XXX check this
			h_size ++;
			/* Is last byte has high bit clear? */
		} while (((*cur_pos ++) & ASN_BIT8) && max_pos > cur_pos);
		if (max_pos == cur_pos)
			return (EBADMSG);
	}
	/* Length. */
	dt_size = (*cur_pos);
	cur_pos ++;
	h_size ++;
	if (ASN_IS_LEN_LONG(dt_size)) {
		tm = (dt_size & ~ASN_LEN_LONG);
		if (tm == 0) { /* XXX: The indefinite form: find 00 00 as end. */
			return (EDOM);
		} else {
			h_size += tm;
			while ((tm --) && max_pos > cur_pos) { /* Skeep zero bytes. */
				dt_size = (*cur_pos ++);
				if (dt_size)
					break;
			}
			if (tm > sizeof(dt_size))
				return (EOVERFLOW);
			while ((tm --) && max_pos > cur_pos) {
				dt_size <<= 8;
				dt_size |= (*cur_pos ++);
			}
			if (max_pos == cur_pos ||
			    (buf_size - (off + h_size)) < dt_size)
				return (EBADMSG);
		}
	}
	dt = cur_pos;
	/* Flags check. */
	if (ASN_ID_CLASS_UNIVERSAL == cls &&
	    (ASN_ID_F_PC != asn_class_uni_ps[tag] && f_ps != asn_class_uni_ps[tag]))
		return (EBADMSG);
	/* Ok, return. */
	if (NULL != offset)
		(*offset) = (off + h_size + dt_size);
	if (NULL != hdr_size)
		(*hdr_size) = h_size;
	if (NULL != aclass)
		(*aclass) = cls;
	if (NULL != ps)
		(*ps) = f_ps;
	if (NULL != atag)
		(*atag) = tag;
	if (NULL != data)
		(*data) = dt;
	if (NULL != data_size)
		(*data_size) = dt_size;
	return (0);
}



#endif /* __ASN_1_H__ */
