/*-
 * Copyright (c) 2014 Rozhuk Ivan <rozhuk.im@gmail.com>
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
 * http://www.iana.org/assignments/radius-types/radius-types.xhtml
 * RFC 2869: RADIUS Extensions
 * RFC 2868: RADIUS Tunnel Authentication Attributes
 * RFC 3162: RADIUS and IPv6
 * RFC 3576: Dynamic Authorization Extensions to RADIUS
 * RFC 4072: Diameter EAP Application
 * RFC 4675: VLAN and Priority Attributes
 * RFC 5090: RADIUS Extension Digest Authentication
 * RFC 5997: Use of Status-Server Packets in the Remote Authentication Dial In User Service (RADIUS) Protocol
 */

#ifndef __RADIUS_PKT_H__
#define __RADIUS_PKT_H__

#ifdef _WINDOWS
#	define EINVAL		ERROR_INVALID_PARAMETER
#	define EOVERFLOW	ERROR_INSUFFICIENT_BUFFER
#	define ESPIPE		ERROR_NOT_FOUND
#	define EBADMSG		ERROR_INVALID_DATA
#	define EEXIST		ERROR_FILE_EXISTS
#	define ECANCELED	ERROR_CANCELLED
#	define ENOATTR		ERROR_NO_DATA
#	define uint8_t		unsigned char
#	define uint16_t		WORD
#	define uint32_t		DWORD
#	define uint64_t		DWORDLONG
#	define size_t		SIZE_T
#	define ssize_t		SSIZE_T
#else
#	include <sys/types.h>
#	include <inttypes.h>
#	include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strnlen, strerror... */
#	include <netinet/in.h> /* ntohs(), htons() */
#	ifndef ENOATTR
#		define ENOATTR	ENODATA
#	endif
#endif


#include "md5.h"



#define RADIUS_SERVER_PORT			1812
#define RADIUS_ACCT_PORT			1813
#define RADIUS_POD_UDP_PORT			1700
#define RADIUS_TLS_PORT				2083
#define RADIUS_COA_UDP_PORT			3799


/* Attribute types and values */
#define RADIUS_ATTR_TYPE_INTERNAL_USE			0 /* Internal use. */
#define RADIUS_ATTR_TYPE_USER_NAME			1
#define RADIUS_ATTR_TYPE_USER_PASSWORD			2
	#define RADIUS_A_T_USER_PASSWORD_MAX_LEN		128
#define RADIUS_ATTR_TYPE_CHAP_PASSWORD			3
#define RADIUS_ATTR_TYPE_NAS_IP_ADDRESS			4
#define RADIUS_ATTR_TYPE_NAS_PORT			5
#define RADIUS_ATTR_TYPE_SERVICE_TYPE			6
	#define RADIUS_A_T_SERVICE_TYPE_LOGIN			1
	#define RADIUS_A_T_SERVICE_TYPE_FRAMED			2
	#define RADIUS_A_T_SERVICE_TYPE_CALLBACK_LOGIN		3
	#define RADIUS_A_T_SERVICE_TYPE_CALLBACK_FRAMED		4
	#define RADIUS_A_T_SERVICE_TYPE_OUTBOUND		5
	#define RADIUS_A_T_SERVICE_TYPE_ADMINISTRATIVE		6
	#define RADIUS_A_T_SERVICE_TYPE_NAS_PROMPT		7
	#define RADIUS_A_T_SERVICE_TYPE_AUTHENTICATE_ONLY	8
	#define RADIUS_A_T_SERVICE_TYPE_CALLBACK_NAS_PROMPT	9
	#define RADIUS_A_T_SERVICE_TYPE_CALLBACK_NAS_CHECK	10
	#define RADIUS_A_T_SERVICE_TYPE_CALLBACK_NAS_ADMIN	11
	#define RADIUS_A_T_SERVICE_TYPE_VOICE			12
	#define RADIUS_A_T_SERVICE_TYPE_FAX			13
	#define RADIUS_A_T_SERVICE_TYPE_MODEM_RELAY		14
	#define RADIUS_A_T_SERVICE_TYPE_IAPP_REGISTER		15
	#define RADIUS_A_T_SERVICE_TYPE_IAPP_AP_CHECK		16
	#define RADIUS_A_T_SERVICE_TYPE_AUTHORIZE_ONLY		17
	#define RADIUS_A_T_SERVICE_TYPE_FRAMED_MANAGEMENT	18
#define RADIUS_ATTR_TYPE_FRAMED_PROTOCOL		7
	#define RADIUS_A_T_FRAMED_PROTOCOL_PPP			1
	#define RADIUS_A_T_FRAMED_PROTOCOL_SLIP			2
	#define RADIUS_A_T_FRAMED_PROTOCOL_ARAP			3
	#define RADIUS_A_T_FRAMED_PROTOCOL_GANDALF		4
	#define RADIUS_A_T_FRAMED_PROTOCOL_XYLOGICS		5
	#define RADIUS_A_T_FRAMED_PROTOCOL_X75_SYNCHRONOUS	6
	#define RADIUS_A_T_FRAMED_PROTOCOL_GPRS_PDP_CONTEXT	7
#define RADIUS_ATTR_TYPE_FRAMED_IP_ADDRESS		8
#define RADIUS_ATTR_TYPE_FRAMED_IP_NETMASK		9
#define RADIUS_ATTR_TYPE_FRAMED_ROUTING			10
#define RADIUS_ATTR_TYPE_FILTER_ID			11
#define RADIUS_ATTR_TYPE_FRAMED_MTU			12
#define RADIUS_ATTR_TYPE_FRAMED_COMPRESSION		13
	#define RADIUS_A_T_FRAMED_COMPRESSION_NONE		0
	#define RADIUS_A_T_FRAMED_COMPRESSION_VJ		1
	#define RADIUS_A_T_FRAMED_COMPRESSION_IPX_HDR		2
	#define RADIUS_A_T_FRAMED_COMPRESSION_STAC_LZS		3
#define RADIUS_ATTR_TYPE_LOGIN_IP_HOST			14
#define RADIUS_ATTR_TYPE_LOGIN_SERVICE			15
	#define RADIUS_ATTR_LOGIN_SERVICE_TELNET		0
	#define RADIUS_ATTR_LOGIN_SERVICE_RLOGIN		1
	#define RADIUS_ATTR_LOGIN_SERVICE_TCP_CLEAR		2
	#define RADIUS_ATTR_LOGIN_SERVICE_PORTMASTER		3
	#define RADIUS_ATTR_LOGIN_SERVICE_LAT			4
	#define RADIUS_ATTR_LOGIN_SERVICE_X25_PAD		5
	#define RADIUS_ATTR_LOGIN_SERVICE_X25_T3POS		6
	#define RADIUS_ATTR_LOGIN_SERVICE_TCP_CLEAR_QUIET	8
#define RADIUS_ATTR_TYPE_LOGIN_TCP_PORT			16
/* unassiged			17 */
#define RADIUS_ATTR_TYPE_REPLY_MESSAGE			18
#define RADIUS_ATTR_TYPE_CALLBACK_NUMBER		19
#define RADIUS_ATTR_TYPE_CALLBACK_ID			20
/* unassiged			21 */
#define RADIUS_ATTR_TYPE_FRAMED_ROUTE			22
#define RADIUS_ATTR_TYPE_FRAMED_IPX_NETWORK		23
#define RADIUS_ATTR_TYPE_STATE				24
#define RADIUS_ATTR_TYPE_CLASS				25
#define RADIUS_ATTR_TYPE_VENDOR_SPECIFIC		26
#define RADIUS_ATTR_TYPE_SESSION_TIMEOUT		27
#define RADIUS_ATTR_TYPE_IDLE_TIMEOUT			28
#define RADIUS_ATTR_TYPE_TERMINATION_ACTION		29
	#define RADIUS_ATTR_TERMINATION_ACTION_DEFAULT		0
	#define RADIUS_ATTR_TERMINATION_ACTION_RADIUS_REQUEST	1
#define RADIUS_ATTR_TYPE_CALLED_STATION_ID		30
#define RADIUS_ATTR_TYPE_CALLING_STATION_ID		31
#define RADIUS_ATTR_TYPE_NAS_IDENTIFIER			32
#define RADIUS_ATTR_TYPE_PROXY_STATE			33
#define RADIUS_ATTR_TYPE_LOGIN_LAT_SERVICE		34
#define RADIUS_ATTR_TYPE_LOGIN_LAT_NODE			35
#define RADIUS_ATTR_TYPE_LOGIN_LAT_GROUP		36
#define RADIUS_ATTR_TYPE_FRAMED_APPLETALK_LINK		37
#define RADIUS_ATTR_TYPE_FRAMED_APPLETALK_NETWORK	38
#define RADIUS_ATTR_TYPE_FRAMED_APPLETALK_ZONE		39
/* reserved for accounting		40-59 */
/* Accounting attribute types and values */
#define RADIUS_ATTR_TYPE_ACCT_STATUS_TYPE		40
	#define RADIUS_A_T_ACCT_STATUS_START			1
	#define RADIUS_A_T_ACCT_STATUS_STOP			2
	#define RADIUS_A_T_ACCT_STATUS_INTERIM_UPDATE		3
	#define RADIUS_A_T_ACCT_STATUS_ACCOUNTING_ON		7
	#define RADIUS_A_T_ACCT_STATUS_ACCOUNTING_OFF		8
	#define RADIUS_A_T_ACCT_STATUS_TUNNEL_START		9
	#define RADIUS_A_T_ACCT_STATUS_TUNNEL_STOP		10
	#define RADIUS_A_T_ACCT_STATUS_TUNNEL_REJECT		11
	#define RADIUS_A_T_ACCT_STATUS_TUNNEL_LINK_START	12
	#define RADIUS_A_T_ACCT_STATUS_TUNNEL_LINK_STOP		13
	#define RADIUS_A_T_ACCT_STATUS_TUNNEL_LINK_REJECT	14
	#define RADIUS_A_T_ACCT_STATUS_FAILED			15
#define RADIUS_ATTR_TYPE_ACCT_DELAY_TIME		41
#define RADIUS_ATTR_TYPE_ACCT_INPUT_OCTETS		42
#define RADIUS_ATTR_TYPE_ACCT_OUTPUT_OCTETS		43
#define RADIUS_ATTR_TYPE_ACCT_SESSION_ID		44
#define RADIUS_ATTR_TYPE_ACCT_AUTHENTIC			45
	#define RADIUS_A_T_ACCT_AUTHENTIC_RADIUS		1
	#define RADIUS_A_T_ACCT_AUTHENTIC_LOCAL			2
	#define RADIUS_A_T_ACCT_AUTHENTIC_REMOTE		3
	#define RADIUS_A_T_ACCT_AUTHENTIC_DIAMETER		4
#define RADIUS_ATTR_TYPE_ACCT_SESSION_TIME		46
#define RADIUS_ATTR_TYPE_ACCT_INPUT_PACKETS		47
#define RADIUS_ATTR_TYPE_ACCT_OUTPUT_PACKETS		48
#define RADIUS_ATTR_TYPE_ACCT_TERMINATE_CAUSE		49
	#define RADIUS_A_T_ACCT_TERMINATE_CAUSE_USER_REQUEST		1
	#define RADIUS_A_T_ACCT_TERMINATE_CAUSE_LOST_CARRIER		2
	#define RADIUS_A_T_ACCT_TERMINATE_CAUSE_LOST_SERVICE		3
	#define RADIUS_A_T_ACCT_TERMINATE_CAUSE_IDLE_TIMEOUT		4
	#define RADIUS_A_T_ACCT_TERMINATE_CAUSE_SESSION_TIMEOUT		5
	#define RADIUS_A_T_ACCT_TERMINATE_CAUSE_ADMIN_RESET		6
	#define RADIUS_A_T_ACCT_TERMINATE_CAUSE_ADMIN_REBOOT		7
	#define RADIUS_A_T_ACCT_TERMINATE_CAUSE_PORT_ERROR		8
	#define RADIUS_A_T_ACCT_TERMINATE_CAUSE_NAS_ERROR		9
	#define RADIUS_A_T_ACCT_TERMINATE_CAUSE_NAS_REQUEST		10
	#define RADIUS_A_T_ACCT_TERMINATE_CAUSE_NAS_REBOOT		11
	#define RADIUS_A_T_ACCT_TERMINATE_CAUSE_PORT_UNNEEDED		12
	#define RADIUS_A_T_ACCT_TERMINATE_CAUSE_PORT_PREEMPTED		13
	#define RADIUS_A_T_ACCT_TERMINATE_CAUSE_PORT_SUSPENDED		14
	#define RADIUS_A_T_ACCT_TERMINATE_CAUSE_SERVICE_UNAVAILABLE	15
	#define RADIUS_A_T_ACCT_TERMINATE_CAUSE_CALLBACK		16
	#define RADIUS_A_T_ACCT_TERMINATE_CAUSE_USER_ERROR		17
	#define RADIUS_A_T_ACCT_TERMINATE_CAUSE_HOST_REQUEST		18
	#define RADIUS_A_T_ACCT_TERMINATE_CAUSE_SUPPLICANT_RESTART	19
	#define RADIUS_A_T_ACCT_TERMINATE_CAUSE_REAUTH_FAILURE		20
	#define RADIUS_A_T_ACCT_TERMINATE_CAUSE_PORT_REINITIALIZED	21
	#define RADIUS_A_T_ACCT_TERMINATE_CAUSE_PORT_ADMIN_DISABLED	22
	#define RADIUS_A_T_ACCT_TERMINATE_CAUSE_LOST_POWER		23
#define	RADIUS_ATTR_TYPE_ACCT_MULTI_SESSION_ID		50
#define	RADIUS_ATTR_TYPE_ACCT_LINK_COUNT		51
#define RADIUS_ATTR_TYPE_ACCT_INPUT_GIGAWORDS		52
#define RADIUS_ATTR_TYPE_ACCT_OUTPUT_GIGAWORDS		53
#define RADIUS_ATTR_TYPE_ACCT_EVENT_TIMESTAMP		55
/* End of accounting */

#define RADIUS_ATTR_TYPE_CHAP_CHALLENGE			60
#define RADIUS_ATTR_TYPE_NAS_PORT_TYPE			61
	#define RADIUS_A_T_NAS_PORT_TYPE_ASYNC			0
	#define RADIUS_A_T_NAS_PORT_TYPE_SYNC			1
	#define RADIUS_A_T_NAS_PORT_TYPE_ISDN_SYNC		2
	#define RADIUS_A_T_NAS_PORT_TYPE_ISDN_ASYNC_V120	3
	#define RADIUS_A_T_NAS_PORT_TYPE_ISDN_ASYNC_V110	4
	#define RADIUS_A_T_NAS_PORT_TYPE_VIRTUAL		5
	#define RADIUS_A_T_NAS_PORT_TYPE_PIAFS			6
	#define RADIUS_A_T_NAS_PORT_TYPE_HDLC_CLEAR_CHANNEL	7
	#define RADIUS_A_T_NAS_PORT_TYPE_X_25			8
	#define RADIUS_A_T_NAS_PORT_TYPE_X_75			9
	#define RADIUS_A_T_NAS_PORT_TYPE_G_3_FAX		10
	#define RADIUS_A_T_NAS_PORT_TYPE_SDSL			11
	#define RADIUS_A_T_NAS_PORT_TYPE_ADSL_CAP		12
	#define RADIUS_A_T_NAS_PORT_TYPE_ADSL_DMT		13
	#define RADIUS_A_T_NAS_PORT_TYPE_IDSL			14
	#define RADIUS_A_T_NAS_PORT_TYPE_ETHERNET		15
	#define RADIUS_A_T_NAS_PORT_TYPE_XDSL			16
	#define RADIUS_A_T_NAS_PORT_TYPE_CABLE			17
	#define RADIUS_A_T_NAS_PORT_TYPE_WIRELESS_OTHER		18
	#define RADIUS_A_T_NAS_PORT_TYPE_WIRELESS_IEEE_802_11	19
#define RADIUS_ATTR_TYPE_PORT_LIMIT			62
#define RADIUS_ATTR_TYPE_LOGIN_LAT_PORT			63
#define RADIUS_ATTR_TYPE_CONNECT_INFO			77
#define RADIUS_ATTR_TYPE_EAP_MSG			79
#define RADIUS_ATTR_TYPE_MSG_AUTHENTIC			80
#define RADIUS_ATTR_TYPE_ACCT_INTERIM_INTERVAL		85
#define RADIUS_ATTR_TYPE_CUI				89
#define RADIUS_ATTR_TYPE_NAS_IPV6_ADDRESS		95
#define RADIUS_ATTR_TYPE_FRAMED_INTERFACE_ID		96
#define RADIUS_ATTR_TYPE_FRAMED_IPV6_PREFIX		97
#define RADIUS_ATTR_TYPE_LOGIN_IPV6_HOST		98
#define RADIUS_ATTR_TYPE_FRAMED_IPV6_ROUTE		99
#define RADIUS_ATTR_TYPE_FRAMED_IPV6_POOL		100
#define	RADIUS_ATTR_TYPE_ERROR_CAUSE			101
	#define RADIUS_A_T_ERROR_CAUSE_SESS_CNTX_REMOVED	201 /* Residual Session Context Removed */
	#define RADIUS_A_T_ERROR_CAUSE_INVALID_EAP_PACKET	202 /* Invalid EAP Packet (Ignored) */
	#define RADIUS_A_T_ERROR_CAUSE_UNSUPPORTED_ATTR		401 /* Unsupported Attribute */
	#define RADIUS_A_T_ERROR_CAUSE_MISSING_ATTR		402 /* Missing Attribute */
	#define RADIUS_A_T_ERROR_CAUSE_NAS_ID_MISMATCH		403 /* NAS Identification Mismatch */
	#define RADIUS_A_T_ERROR_CAUSE_INVALID_REQUEST		404 /* Invalid Request */
	#define RADIUS_A_T_ERROR_CAUSE_UNSUPPORTED_SERVICE	405 /* Unsupported Service */
	#define RADIUS_A_T_ERROR_CAUSE_UNSUPPORTED_EXTENSION	406 /* Unsupported Extension */
	#define RADIUS_A_T_ERROR_CAUSE_ADM_PROHIBITED		501 /* Administratively Prohibited */
	#define RADIUS_A_T_ERROR_CAUSE_REQ_NOT_ROUTABLE		502 /* Request Not Routable (Proxy) */
	#define RADIUS_A_T_ERROR_CAUSE_SESS_CTX_NOT_FOUND	503 /* Session Context Not Found */
	#define RADIUS_A_T_ERROR_CAUSE_SESS_CTX_NOT_REMOVABLE	504 /* Session Context Not Removable */
	#define RADIUS_A_T_ERROR_CAUSE_OTH_PROXY_PROCESSING_ERR	505 /* Other Proxy Processing Error */
	#define RADIUS_A_T_ERROR_CAUSE_RESOURCES_UNAVAILABLE	506 /* Resources Unavailable */
	#define RADIUS_A_T_ERROR_CAUSE_REQ_INITIATED		507 /* Request Initiated */



typedef struct radius_attributes_params {
	const char	*display_name;
	uint8_t		len_min; /* Data size, without type and length fiels, 0xff = allow zero len. */
	uint8_t		len_max;
	uint8_t		data_type;
} rad_attr_param_t, *rad_attr_param_p;
/* Data types */
#define RADIUS_ATTR_PARAM_T_NONE	  0
#define RADIUS_ATTR_PARAM_T_STR		  1 /* string, Length >= 3 (in some cases bytes) */
#define RADIUS_ATTR_PARAM_T_TEXT	  2 /* UTF8 string, Length >= 3 */
#define RADIUS_ATTR_PARAM_T_IPV4	  3 /* Length = 6 */
#define RADIUS_ATTR_PARAM_T_IPV6	  4 /* Length = 18 */
#define RADIUS_ATTR_PARAM_T_IPV6_PREFIX	  5 /* At least 4 and no larger than 20 */
#define RADIUS_ATTR_PARAM_T_INT8	  6 /* Length = 6 */
#define RADIUS_ATTR_PARAM_T_INT16	  7 /* Length = 6 */
#define RADIUS_ATTR_PARAM_T_INT32	  8 /* Length = 6 */
#define RADIUS_ATTR_PARAM_T_INT64	  9 /* Length = 10 */
#define RADIUS_ATTR_PARAM_T_TIME32	 10 /* Length = 6 */
#define RADIUS_ATTR_PARAM_T_VENDOR_SPEC	250 /* Vendor-Specific, Length >= 7 */
#define RADIUS_ATTR_PARAM_T_EXT		251 /* Extended-Type, Length >= 4 */
#define RADIUS_ATTR_PARAM_T_EXT_LONG	252 /* Long Extended Type, Length >= 5 */
#define RADIUS_ATTR_PARAM_T_ADV		254 /* Advanced, see RFC for every arrt. May be interpreted as string. */
#define RADIUS_ATTR_PARAM_T_ANY		255 /* for: Experimental Use, Implementation
					 * Specific, Extended-Attribute
					 * Length >= 3 */
/* Flags */
#define RADIUS_ATTR_PARAM_F_FIXEDLEN	(1 << 0)
#define RADIUS_ATTR_PARAM_F_MINLEN	(1 << 1)


#define RADIUS_ATTR_PARAM_NONE		{ (const char*)"none", 0, 0, RADIUS_ATTR_PARAM_T_NONE }
#define RADIUS_ATTR_PARAM_ANY		{ (const char*)"any", 0, 0, RADIUS_ATTR_PARAM_T_ANY }
static const rad_attr_param_t rad_attr_params[] = {
/*   0 */	RADIUS_ATTR_PARAM_NONE,
/*   1 */	{ (const char*)"User-Name", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/*   2 */	{ (const char*)"User-Password", MD5_HASH_SIZE, RADIUS_A_T_USER_PASSWORD_MAX_LEN, RADIUS_ATTR_PARAM_T_STR },
/*   3 */	{ (const char*)"CHAP-Password", 17, 17, RADIUS_ATTR_PARAM_T_STR },
/*   4 */	{ (const char*)"NAS-IP-Address", 0, 0, RADIUS_ATTR_PARAM_T_IPV4 },
/*   5 */	{ (const char*)"NAS-Port", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*   6 */	{ (const char*)"Service-Type", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*   7 */	{ (const char*)"Framed-Protocol", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*   8 */	{ (const char*)"Framed-IP-Address", 0, 0, RADIUS_ATTR_PARAM_T_IPV4 },
/*   9 */	{ (const char*)"Framed-IP-Netmask", 0, 0, RADIUS_ATTR_PARAM_T_IPV4 },
/*  10 */	{ (const char*)"Framed-Routing", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  11 */	{ (const char*)"Filter-Id", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/*  12 */	{ (const char*)"Framed-MTU", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  13 */	{ (const char*)"Framed-Compression", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  14 */	{ (const char*)"Login-IP-Host", 0, 0, RADIUS_ATTR_PARAM_T_IPV4 },
/*  15 */	{ (const char*)"Login-Service", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  16 */	{ (const char*)"Login-TCP-Port", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  17 */	RADIUS_ATTR_PARAM_NONE,
/*  18 */	{ (const char*)"Reply-Message", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/*  19 */	{ (const char*)"Callback-Number", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  20 */	{ (const char*)"Callback-Id", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  21 */	RADIUS_ATTR_PARAM_NONE,
/*  22 */	{ (const char*)"Framed-Route", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/*  23 */	{ (const char*)"Framed-IPX-Network", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  24 */	{ (const char*)"State", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  25 */	{ (const char*)"Class", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  26 */	{ (const char*)"Vendor-Specific", 5, 0, RADIUS_ATTR_PARAM_T_VENDOR_SPEC },
/*  27 */	{ (const char*)"Session-Timeout", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  28 */	{ (const char*)"Idle-Timeout", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  29 */	{ (const char*)"Termination-Action", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  30 */	{ (const char*)"Called-Station-Id", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  31 */	{ (const char*)"Calling-Station-Id", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  32 */	{ (const char*)"NAS-Identifier", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  33 */	{ (const char*)"Proxy-State", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  34 */	{ (const char*)"Login-LAT-Service", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  35 */	{ (const char*)"Login-LAT-Node", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  36 */	{ (const char*)"Login-LAT-Group", 32, 0, RADIUS_ATTR_PARAM_T_STR },
/*  37 */	{ (const char*)"Framed-AppleTalk-Link", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  38 */	{ (const char*)"Framed-AppleTalk-Network", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  39 */	{ (const char*)"Framed-AppleTalk-Zone", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/* Accounting. */
/*  40 */	{ (const char*)"Acct-Status-Type", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  41 */	{ (const char*)"Acct-Delay-Time", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  42 */	{ (const char*)"Acct-Input-Octets", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  43 */	{ (const char*)"Acct-Output-Octets", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  44 */	{ (const char*)"Acct-Session-Id", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/*  45 */	{ (const char*)"Acct-Authentic", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  46 */	{ (const char*)"Acct-Session-Time", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  47 */	{ (const char*)"Acct-Input-Packets", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  48 */	{ (const char*)"Acct-Output-Packets", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  49 */	{ (const char*)"Acct-Terminate-Cause", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  50 */	{ (const char*)"Acct-Multi-Session-Id", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  51 */	{ (const char*)"Acct-Link-Count", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  52 */	{ (const char*)"Acct-Input-Gigawords", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  53 */	{ (const char*)"Acct-Output-Gigawords", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  54 */	RADIUS_ATTR_PARAM_NONE,
/*  55 */	{ (const char*)"Event-Timestamp", 0, 0, RADIUS_ATTR_PARAM_T_TIME32 },
/*  56 */	{ (const char*)"Egress-VLANID", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  57 */	{ (const char*)"Ingress-Filters", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  58 */	{ (const char*)"Egress-VLAN-Name", 2, 0, RADIUS_ATTR_PARAM_T_STR },
/*  59 */	{ (const char*)"User-Priority-Table", 8, 8, RADIUS_ATTR_PARAM_T_STR },
/* Accounting END. */
/*  60 */	{ (const char*)"CHAP-Challenge", 5, 0, RADIUS_ATTR_PARAM_T_STR },
/*  61 */	{ (const char*)"NAS-Port-Type", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  62 */	{ (const char*)"Port-Limit", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  63 */	{ (const char*)"Login-LAT-Port", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  64 */	{ (const char*)"Tunnel-Type", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  65 */	{ (const char*)"Tunnel-Medium-Type", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  66 */	{ (const char*)"Tunnel-Client-Endpoint", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  67 */	{ (const char*)"Tunnel-Server-Endpoint", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  68 */	{ (const char*)"Acct-Tunnel-Connection", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  69 */	{ (const char*)"Tunnel-Password", 3, 0, RADIUS_ATTR_PARAM_T_STR },
/*  70 */	{ (const char*)"ARAP-Password", 16, 16, RADIUS_ATTR_PARAM_T_STR },
/*  71 */	{ (const char*)"ARAP-Features", 14, 14, RADIUS_ATTR_PARAM_T_STR },
/*  72 */	{ (const char*)"ARAP-Zone-Access", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  73 */	{ (const char*)"ARAP-Security", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  74 */	{ (const char*)"ARAP-Security-Data", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  75 */	{ (const char*)"Password-Retry", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  76 */	{ (const char*)"Prompt", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  77 */	{ (const char*)"Connect-Info", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/*  78 */	{ (const char*)"Configuration-Token", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  79 */	{ (const char*)"EAP-Message", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  80 */	{ (const char*)"Message-Authenticator", MD5_HASH_SIZE, MD5_HASH_SIZE, RADIUS_ATTR_PARAM_T_STR },
/*  81 */	{ (const char*)"Tunnel-Private-Group-ID", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  82 */	{ (const char*)"Tunnel-Assignment-ID", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  83 */	{ (const char*)"Tunnel-Preference", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  84 */	{ (const char*)"ARAP-Challenge-Response", 8, 8, RADIUS_ATTR_PARAM_T_STR },
/*  85 */	{ (const char*)"Acct-Interim-Interval", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  86 */	{ (const char*)"Acct-Tunnel-Packets-Lost", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/*  87 */	{ (const char*)"NAS-Port-Id", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/*  88 */	{ (const char*)"Framed-Pool", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  89 */	{ (const char*)"CUI", 0xff, 0, RADIUS_ATTR_PARAM_T_STR },  /* Exception: allow zero data len. */
/*  90 */	{ (const char*)"Tunnel-Client-Auth-ID", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  91 */	{ (const char*)"Tunnel-Server-Auth-ID", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  92 */	{ (const char*)"NAS-Filter-Rule", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/*  93 */	RADIUS_ATTR_PARAM_NONE,
/*  94 */	{ (const char*)"Originating-Line-Info", 2, 2, RADIUS_ATTR_PARAM_T_STR },
/*  95 */	{ (const char*)"NAS-IPv6-Address", 0, 0, RADIUS_ATTR_PARAM_T_IPV6 },
/*  96 */	{ (const char*)"Framed-Interface-Id", 0, 0, RADIUS_ATTR_PARAM_T_INT64 },
/*  97 */	{ (const char*)"Framed-IPv6-Prefix", 0, 0, RADIUS_ATTR_PARAM_T_IPV6_PREFIX },
/*  98 */	{ (const char*)"Login-IPv6-Host", 0, 0, RADIUS_ATTR_PARAM_T_IPV6 },
/*  99 */	{ (const char*)"Framed-IPv6-Route", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 100 */	{ (const char*)"Framed-IPv6-Pool", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/* 101 */	{ (const char*)"Error-Cause Attribute", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/* 102 */	{ (const char*)"EAP-Key-Name", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/* 103 */	{ (const char*)"Digest-Response", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 104 */	{ (const char*)"Digest-Realm", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 105 */	{ (const char*)"Digest-Nonce", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 106 */	{ (const char*)"Digest-Response-Auth", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 107 */	{ (const char*)"Digest-Nextnonce", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 108 */	{ (const char*)"Digest-Method", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 109 */	{ (const char*)"Digest-URI", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 110 */	{ (const char*)"Digest-Qop", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 111 */	{ (const char*)"Digest-Algorithm", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 112 */	{ (const char*)"Digest-Entity-Body-Hash", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 113 */	{ (const char*)"Digest-CNonce", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 114 */	{ (const char*)"Digest-Nonce-Count", 8, 8, RADIUS_ATTR_PARAM_T_TEXT },
/* 115 */	{ (const char*)"Digest-Username", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 116 */	{ (const char*)"Digest-Opaque", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 117 */	{ (const char*)"Digest-Auth-Param", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 118 */	{ (const char*)"Digest-AKA-Auts", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 119 */	{ (const char*)"Digest-Domain", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 120 */	{ (const char*)"Digest-Stale", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 121 */	{ (const char*)"Digest-HA1", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 122 */	{ (const char*)"SIP-AOR", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 123 */	{ (const char*)"Delegated-IPv6-Prefix", 0, 0, RADIUS_ATTR_PARAM_T_IPV6_PREFIX },
/* 124 */	{ (const char*)"MIP6-Feature-Vector", 0, 0, RADIUS_ATTR_PARAM_T_INT64 },
/* 125 */	{ (const char*)"MIP6-Home-Link-Prefix", 0, 0, RADIUS_ATTR_PARAM_T_IPV6_PREFIX },
/* 126 */	{ (const char*)"Operator-Name", 2, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 127 */	{ (const char*)"Location-Information", 20, 0, RADIUS_ATTR_PARAM_T_STR },
/* 128 */	{ (const char*)"Location-Data", 3, 0, RADIUS_ATTR_PARAM_T_STR },
/* 129 */	{ (const char*)"Basic-Location-Policy-Rules", 10, 0, RADIUS_ATTR_PARAM_T_STR },
/* 130 */	{ (const char*)"Extended-Location-Policy-Rules", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/* 131 */	{ (const char*)"Location-Capable", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/* 132 */	{ (const char*)"Requested-Location-Info", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/* 133 */	{ (const char*)"Framed-Management-Protocol", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/* 134 */	{ (const char*)"Management-Transport-Protection", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/* 135 */	{ (const char*)"Management-Policy-Id", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 136 */	{ (const char*)"Management-Privilege-Level", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/* 137 */	{ (const char*)"PKM-SS-Cert", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/* 138 */	{ (const char*)"PKM-CA-Cert", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/* 139 */	{ (const char*)"PKM-Config-Settings", 28, 28, RADIUS_ATTR_PARAM_T_ADV },
/* 140 */	{ (const char*)"PKM-Cryptosuite-List", 3, 0, RADIUS_ATTR_PARAM_T_ADV },
/* 141 */	{ (const char*)"PKM-SAID", 2, 2, RADIUS_ATTR_PARAM_T_ADV },
/* 142 */	{ (const char*)"PKM-SA-Descriptor", 6, 6, RADIUS_ATTR_PARAM_T_ADV },
/* 143 */	{ (const char*)"PKM-Auth-Key", 133, 133, RADIUS_ATTR_PARAM_T_ADV },
/* 144 */	{ (const char*)"DS-Lite-Tunnel-Name", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 145 */	{ (const char*)"Mobile-Node-Identifier", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/* 146 */	{ (const char*)"Service-Selection", 0, 0, RADIUS_ATTR_PARAM_T_TEXT },
/* 147 */	{ (const char*)"PMIP6-Home-LMA-IPv6-Address", 0, 0, RADIUS_ATTR_PARAM_T_IPV6 },
/* 148 */	{ (const char*)"PMIP6-Visited-LMA-IPv6-Address", 0, 0, RADIUS_ATTR_PARAM_T_IPV6 },
/* 149 */	{ (const char*)"PMIP6-Home-LMA-IPv4-Address", 0, 0, RADIUS_ATTR_PARAM_T_IPV4 },
/* 150 */	{ (const char*)"PMIP6-Visited-LMA-IPv4-Address", 0, 0, RADIUS_ATTR_PARAM_T_IPV4 },
/* 151 */	{ (const char*)"PMIP6-Home-HN-Prefix", 0, 0, RADIUS_ATTR_PARAM_T_IPV6_PREFIX },
/* 152 */	{ (const char*)"PMIP6-Visited-HN-Prefix", 0, 0, RADIUS_ATTR_PARAM_T_IPV6_PREFIX },
/* 153 */	{ (const char*)"PMIP6-Home-Interface-ID", 0, 0, RADIUS_ATTR_PARAM_T_INT64 },
/* 154 */	{ (const char*)"PMIP6-Visited-Interface-ID", 0, 0, RADIUS_ATTR_PARAM_T_INT64 },
/* 155 */	{ (const char*)"PMIP6-Home-IPv4-HoA", 6, 6, RADIUS_ATTR_PARAM_T_ADV },
/* 156 */	{ (const char*)"PMIP6-Visited-IPv4-HoA", 6, 6, RADIUS_ATTR_PARAM_T_ADV },
/* 157 */	{ (const char*)"PMIP6-Home-DHCP4-Server-Address", 0, 0, RADIUS_ATTR_PARAM_T_IPV4 },
/* 158 */	{ (const char*)"PMIP6-Visited-DHCP4-Server-Address", 0, 0, RADIUS_ATTR_PARAM_T_IPV4 },
/* 159 */	{ (const char*)"PMIP6-Home-DHCP6-Server-Address", 0, 0, RADIUS_ATTR_PARAM_T_IPV6 },
/* 160 */	{ (const char*)"PMIP6-Visited-DHCP6-Server-Address", 0, 0, RADIUS_ATTR_PARAM_T_IPV6 },
/* 161 */	{ (const char*)"PMIP6-Home-IPv4-Gateway", 0, 0, RADIUS_ATTR_PARAM_T_IPV4 },
/* 162 */	{ (const char*)"PMIP6-Visited-IPv4-Gateway", 0, 0, RADIUS_ATTR_PARAM_T_IPV4 },
/* 163 */	{ (const char*)"EAP-Lower-Layer", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/* 164 */	{ (const char*)"GSS-Acceptor-Service-Name", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/* 165 */	{ (const char*)"GSS-Acceptor-Host-Name", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/* 166 */	{ (const char*)"GSS-Acceptor-Service-Specifics", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/* 167 */	{ (const char*)"GSS-Acceptor-Realm-Name", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/* 168 */	{ (const char*)"Framed-IPv6-Address", 0, 0, RADIUS_ATTR_PARAM_T_IPV6 },
/* 169 */	{ (const char*)"DNS-Server-IPv6-Address", 0, 0, RADIUS_ATTR_PARAM_T_IPV6 },
/* 170 */	{ (const char*)"Route-IPv6-Information", 0, 0, RADIUS_ATTR_PARAM_T_IPV6_PREFIX },
/* 171 */	{ (const char*)"Delegated-IPv6-Prefix-Pool", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/* 172 */	{ (const char*)"Stateful-IPv6-Address-Pool", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/* 173 */	{ (const char*)"IPv6-6rd-Configuration", 32, 0, RADIUS_ATTR_PARAM_T_ADV },
/* 174 */	{ (const char*)"Allowed-Called-Station-Id", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/* 175 */	{ (const char*)"EAP-Peer-Id", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/* 176 */	{ (const char*)"EAP-Server-Id", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/* 177 */	{ (const char*)"Mobility-Domain-Id", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/* 178 */	{ (const char*)"Preauth-Timeout", 0, 0, RADIUS_ATTR_PARAM_T_INT32 },
/* 179 */	{ (const char*)"Network-Id-Name", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/* 180 */	{ (const char*)"EAPoL-Announcement", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/* 181 */	{ (const char*)"WLAN-HESSID", 17, 17, RADIUS_ATTR_PARAM_T_STR },
/* 182 */	{ (const char*)"WLAN-Venue-Info", 4, 4, RADIUS_ATTR_PARAM_T_ADV },
/* 183 */	{ (const char*)"WLAN-Venue-Language", 2, 3, RADIUS_ATTR_PARAM_T_STR },
/* 184 */	{ (const char*)"WLAN-Venue-Name", 0, 0, RADIUS_ATTR_PARAM_T_STR },
/* 185 */	{ (const char*)"WLAN-Reason-Code", 4, 4, RADIUS_ATTR_PARAM_T_ADV },
/* 186 */	{ (const char*)"WLAN-Pairwise-Cipher", 4, 4, RADIUS_ATTR_PARAM_T_ADV },
/* 187 */	{ (const char*)"WLAN-Group-Cipher", 4, 4, RADIUS_ATTR_PARAM_T_ADV },
/* 188 */	{ (const char*)"WLAN-AKM-Suite", 4, 4, RADIUS_ATTR_PARAM_T_ADV },
/* 189 */	{ (const char*)"WLAN-Group-Mgmt-Cipher", 4, 4, RADIUS_ATTR_PARAM_T_ADV },
/* 190 */	{ (const char*)"WLAN-RF-Band", 4, 4, RADIUS_ATTR_PARAM_T_ADV },
/* 191 */	RADIUS_ATTR_PARAM_NONE,
/* Experimental Use */
/* 192 - 194 */	RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY,
/* 195 - 197 */	RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY,
/* 198 - 200 */	RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY,
/* 201 - 203 */	RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY,
/* 204 - 206 */	RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY,
/* 207 - 209 */	RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY,
/* 210 - 212 */	RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY,
/* 213 - 215 */	RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY,
/* 216 - 218 */	RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY,
/* 219 - 221 */	RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY,
/* 222 - 223 */	RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY,
/* Implementation Specific */
/* 224 - 226 */	RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY,
/* 227 - 229 */	RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY,
/* 230 - 232 */	RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY,
/* 233 - 235 */	RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY,
/* 236 - 238 */	RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY,
/* 239 - 240 */	RADIUS_ATTR_PARAM_ANY, RADIUS_ATTR_PARAM_ANY,
/* 241 */	{ (const char*)"Extended-Attribute-1", 0, 0, RADIUS_ATTR_PARAM_T_EXT },
/* 242 */	{ (const char*)"Extended-Attribute-2", 0, 0, RADIUS_ATTR_PARAM_T_EXT },
/* 243 */	{ (const char*)"Extended-Attribute-3", 0, 0, RADIUS_ATTR_PARAM_T_EXT },
/* 244 */	{ (const char*)"Extended-Attribute-4", 0, 0, RADIUS_ATTR_PARAM_T_EXT },
/* 245 */	{ (const char*)"Long-Extended-Type-1", 0, 0, RADIUS_ATTR_PARAM_T_EXT_LONG },
/* 246 */	{ (const char*)"Long-Extended-Type-2", 0, 0, RADIUS_ATTR_PARAM_T_EXT_LONG },
/* Reserved */
/* 247 - 248 */	RADIUS_ATTR_PARAM_NONE, RADIUS_ATTR_PARAM_NONE,
/* 249 - 250 */	RADIUS_ATTR_PARAM_NONE, RADIUS_ATTR_PARAM_NONE,
/* 251 - 252 */	RADIUS_ATTR_PARAM_NONE, RADIUS_ATTR_PARAM_NONE,
/* 253 - 255 */	RADIUS_ATTR_PARAM_NONE, RADIUS_ATTR_PARAM_NONE,
/* 255 */	RADIUS_ATTR_PARAM_NONE
};

typedef struct radius_pkt_attr_s { /* Radius packet Attributes. */
	uint8_t		type;	/* identifies the type of RADIUS Attribute */
	uint8_t		len;	/* length of this Attribute including the Type, Length and Value fields. */
	// Attribute data ...
} __attribute__((__packed__)) rad_pkt_attr_t, *rad_pkt_attr_p;
#define RADIUS_PKT_ATTR_DATA(attr)	((uint8_t*)(attr + 1))
#define RADIUS_PKT_ATTR_NEXT(attr)	((rad_pkt_attr_p)(((uint8_t*)attr) + attr->len))
#define RADIUS_ATTR_DATA_SIZE_MAX	253

typedef struct radius_pkt_attr_ext_s { /* Radius packet Attributes Extended-Type: RFC 6929 */
	uint8_t		type;	/* identifies the type of RADIUS Attribute */
	uint8_t		len;	/* length of this Attribute including the Type, Length and Value fields. */
	uint8_t		ext_type; /* Extended-Type of RADIUS Attribute */
	// Attribute data ...
} __attribute__((__packed__)) rad_pkt_attr_ext_t, *rad_pkt_attr_ext_p;

typedef struct radius_pkt_attr_extl_s { /* Radius packet Attributes Long Extended Type: RFC 6929 */
	uint8_t		type;	/* identifies the type of RADIUS Attribute */
	uint8_t		len;	/* length of this Attribute including the Type, Length and Value fields. */
	uint8_t		ext_type; /* Extended-Type of RADIUS Attribute */
	uint8_t		flags;	/* RADIUS_ATTR_EXT_LONG_F_* */
	// Attribute data ...
} __attribute__((__packed__)) rad_pkt_attr_extl_t, *rad_pkt_attr_extl_p;

#define RADIUS_ATTR_EXT_LONG_F_MORE	1 /* attribute contains "more" than 251 
					 * octets of data, MAY be set (1) if the 
					 * Length field has a value of 255 */


/* Packet types */
#define RADIUS_PKT_TYPE_ACCESS_REQUEST		 1 /* RFC2865 - Access-Request */
#define RADIUS_PKT_TYPE_ACCESS_ACCEPT		 2 /* RFC2865 - Access-Accept */
#define RADIUS_PKT_TYPE_ACCESS_REJECT		 3 /* RFC2865 - Access-Reject */
#define RADIUS_PKT_TYPE_ACCOUNTING_REQUEST	 4 /* RFC2866 - Accounting-Request */
#define RADIUS_PKT_TYPE_ACCOUNTING_RESPONSE	 5 /* RFC2866 - Accounting-Response */
#define RADIUS_PKT_TYPE_ACCESS_CHALLENGE	11 /* RFC2865 - Access-Challenge */
#define RADIUS_PKT_TYPE_STATUS_SERVER		12 /* RFC2865 / RFC5997 - Status Server (request) */
#define RADIUS_PKT_TYPE_STATUS_CLIENT		13 /* RFC2865 / RFC5997 - Status Server (response) */
#define RADIUS_PKT_TYPE_DISCONNECT_REQUEST	40 /* RFC3575 / RFC5176 - Disconnect-Request */
#define RADIUS_PKT_TYPE_DISCONNECT_ACK		41 /* RFC3575 / RFC5176 - Disconnect-Ack (positive) */
#define RADIUS_PKT_TYPE_DISCONNECT_NAK		42 /* RFC3575 / RFC5176 - Disconnect-Nak (not willing to perform) */
#define RADIUS_PKT_TYPE_COA_REQUEST		43 /* RFC3575 / RFC5176 - CoA-Request */
#define RADIUS_PKT_TYPE_COA_ACK			44 /* RFC3575 / RFC5176 - CoA-Ack (positive) */
#define RADIUS_PKT_TYPE_COA_NAK			45 /* RFC3575 / RFC5176 - CoA-Nak (not willing to perform) */




typedef struct radius_pkt_hdr_s { /* Radius packet header. */
	uint8_t		code;	/* Identifies the type of RADIUS packet, RADIUS_PKT_TYPE_.* */
	uint8_t		id;	/* Pkt identifier. */
	uint16_t	len;	/* Length of the packet including the Code, Identifier, Length, Authenticator and Attribute fields. */
	uint8_t		authenticator[16]; /* Used in the password hiding algorithm. */
	// Attributes: rad_pkt_attr_t ...
} __attribute__((__packed__)) rad_pkt_hdr_t, *rad_pkt_hdr_p;

#define RADIUS_PKT_MAX_SIZE		4096 /* From RFC. */
#define RADIUS_PKT_HDR_SIZE		sizeof(rad_pkt_hdr_t) /* 20 */
#define RADIUS_PKT_HDR_LEN_GET(pkt)	ntohs(pkt->len)
#define RADIUS_PKT_HDR_LEN_SET(pkt, n)	pkt->len = htons(n)
#define RADIUS_PKT_HDR_LEN_INC(pkt, n)	pkt->len = htons(ntohs(pkt->len) + n)
#define RADIUS_PKT_HDR_LEN_DEC(pkt, n)	pkt->len = htons(ntohs(pkt->len) - n)
#define RADIUS_PKT_HDR_ID_MAX_COUNT	256 /* Max uint8_t. */
#define RADIUS_PKT_END(pkt)		(((uint8_t*)pkt) + RADIUS_PKT_HDR_LEN_GET(pkt))
#define RADIUS_PKT_ATTRS(pkt)		((rad_pkt_attr_p)(pkt + 1))
#define RADIUS_PKT_ATTRS_SIZE(pkt)	(RADIUS_PKT_HDR_LEN_GET(pkt) - RADIUS_PKT_HDR_SIZE)



/* Constatnt time memory comparation, prevent timing attacks
 * http://www.cs.rice.edu/~dwallach/pub/crosby-timing2009.pdf */
static inline int
radius_sec_memcmp(uint8_t const *a, uint8_t const *b, size_t size) {
	register int res = 0;
	register size_t i;

	for (i = 0; i < size; i ++)
		res |= a[i] ^ b[i];
	return (res);
}


//////////////////////////////////////////////////////////////////////////
////////////////////////Radius packet attribute///////////////////////////
//////////////////////////////////////////////////////////////////////////


static inline int
radius_pkt_attr_get_from_offset(rad_pkt_hdr_p pkt, size_t offset,
    rad_pkt_attr_p *attr_ret) {
	size_t pkt_size;
	 rad_pkt_attr_p attr;

	if (NULL == pkt || NULL == attr_ret)
		return (EINVAL);
	pkt_size = RADIUS_PKT_HDR_LEN_GET(pkt);
	if (offset < RADIUS_PKT_HDR_SIZE || offset > pkt_size)
		return (EINVAL);
	attr = ((rad_pkt_attr_p)(((uint8_t*)pkt) + offset));
	if (((uint8_t*)RADIUS_PKT_ATTR_NEXT(attr)) > (((uint8_t*)pkt) + pkt_size))
		return (EBADMSG);
	(*attr_ret) = attr;
	return (0);
}


static inline int
radius_pkt_attr_chk(rad_pkt_attr_p attr) {
	rad_attr_param_p attr_prm;

	if (NULL == attr)
		return (EINVAL);
	if (0 == attr->type || 2 > attr->len)
		return (EBADMSG);

	attr_prm = (rad_attr_param_p)&rad_attr_params[attr->type];
	switch (attr_prm->data_type) {
	case RADIUS_ATTR_PARAM_T_NONE: /* Unknown format, cant check. */
		break;
	case RADIUS_ATTR_PARAM_T_STR: /* string, Length >= 3 */
	case RADIUS_ATTR_PARAM_T_TEXT: /* UTF8 string, Length >= 3 */
	case RADIUS_ATTR_PARAM_T_ADV: /* Length >= 3 */
	case RADIUS_ATTR_PARAM_T_ANY: /* Length >= 3 */
		switch (attr_prm->len_min) {
		case 0: /* At least one byte len required. */
			if (3 > attr->len)
				return (EBADMSG);
			break;
		case 0xff: /* Allow zero len. */
			break;
		default: /* Specific minimum len. */
			if (attr->len < (attr_prm->len_min + 2))
				return (EBADMSG);
			break;
		}
		if (0 != attr_prm->len_max && attr->len > (attr_prm->len_max + 2))
			return (EBADMSG);
		break;
	case RADIUS_ATTR_PARAM_T_IPV4: /* Length = 6 */
	case RADIUS_ATTR_PARAM_T_INT32: /* Length = 6 */
	case RADIUS_ATTR_PARAM_T_TIME32: /* Length = 6 */
		if (6 != attr->len)
			return (EBADMSG);
		break;
	case RADIUS_ATTR_PARAM_T_INT64:
		if (10 != attr->len)
			return (EBADMSG);
		break;
	case RADIUS_ATTR_PARAM_T_IPV6: /* Length = 18 */
		if (18 != attr->len)
			return (EBADMSG);
		break;
	case RADIUS_ATTR_PARAM_T_IPV6_PREFIX: /* Length = At least 4 and no larger than 20 */
		if (4 > attr->len || 20 < attr->len)
			return (EBADMSG);
		break;
	case RADIUS_ATTR_PARAM_T_VENDOR_SPEC: /* Vendor-Specific, Length >= 7 */
		if (7 > attr->len)
			return (EBADMSG);
		break;
	case RADIUS_ATTR_PARAM_T_EXT: /* Extended-Type, Length >= 4 */
		if (4 > attr->len)
			return (EBADMSG);
		break;
	case RADIUS_ATTR_PARAM_T_EXT_LONG: /* Long Extended Type, Length >= 5 */
		if (5 > attr->len)
			return (EBADMSG);
		break;
	default:
		return (EBADMSG);
	}
	return (0);
}

/* Offset - from pkt start, min offset = RADIUS_PKT_HDR_SIZE. */
static inline int
radius_pkt_attr_find_raw(rad_pkt_hdr_p pkt, size_t offset, uint8_t attr_type,
    rad_pkt_attr_p *attr_ret, size_t *offset_ret) {
	size_t attr_cnt;
	rad_pkt_attr_p attr;

	if (NULL == pkt)
		return (EINVAL);

	attr = RADIUS_PKT_ATTRS(pkt);
	attr_cnt = RADIUS_PKT_ATTRS_SIZE(pkt);
	if (0 != offset) {
		if (0 != radius_pkt_attr_get_from_offset(pkt, offset, &attr))
			return (EINVAL);
	}
	/* Find loop. */
	while (0 != attr_cnt) {
		/* This cheks allready done in radius_pkt_chk(). */
		if (attr_cnt < 2) /* No attr header. */
			return (EBADMSG);
		if (attr_cnt < attr->len) /* Out of header. */
			return (EBADMSG);
		if (0 == attr->type || 2 > attr->len) /* Bad attr. */
			return (EBADMSG);
		if (attr_type == attr->type) {
			if (NULL != attr_ret)
				(*attr_ret) = attr;
			if (NULL != offset_ret)
				(*offset_ret) = (((uint8_t*)attr) - ((uint8_t*)pkt));
			return (0);
		}
		attr_cnt -= attr->len;
		attr = RADIUS_PKT_ATTR_NEXT(attr);
	}
	return (ENOATTR); /* No more attrs. */
}
static inline int
radius_pkt_attr_find(rad_pkt_hdr_p pkt, size_t offset, uint8_t attr_type,
    size_t *offset_ret) {

	return (radius_pkt_attr_find_raw(pkt, offset, attr_type, NULL, offset_ret));
}


static inline int
radius_pkt_attr_password_encode(uint8_t *authenticator,
    uint8_t *password, size_t password_len, uint8_t *key, size_t key_len,
    uint8_t *buf, size_t buf_size, size_t *buf_size_ret) {
	size_t i, j, password_len_aligned;
	md5_ctx_t ctx, ctx_with_key;
	uint8_t digest[MD5_HASH_SIZE];

	if (password_len > RADIUS_A_T_USER_PASSWORD_MAX_LEN)
		return (EINVAL);
	/* Calc result size. */
	if (0 != password_len) {
		password_len_aligned = (password_len + (MD5_HASH_SIZE - 1));
		password_len_aligned &= ~(MD5_HASH_SIZE - 1);
	} else {
		password_len_aligned = MD5_HASH_SIZE;
	}
	if (NULL != buf_size_ret)
		(*buf_size_ret) = password_len_aligned;
	if (password_len_aligned > buf_size)
		return (EOVERFLOW);
	if (NULL == authenticator || (NULL == password && 0 != password_len) ||
	    (NULL == key && 0 != key_len) ||
	    (NULL == buf && 0 != buf_size))
		return (EINVAL);
	/* Copy and pad with zero. */
	memcpy(buf, password, password_len);
	memset((buf + password_len), 0, (password_len_aligned - password_len));
	/* Init md5 context. */
	md5_init(&ctx);
	md5_update(&ctx, key, key_len); /* key */
	memcpy(&ctx_with_key, &ctx, sizeof(md5_ctx_t)); /* Save context with key. */
	/* First block. */
	md5_update(&ctx, authenticator, MD5_HASH_SIZE); /* authenticator */
	/* Finish first and process other blocks. */
	for (j = 0;; j += MD5_HASH_SIZE) {
		md5_final(&ctx, digest);
		for (i = 0; i < MD5_HASH_SIZE; i ++)
			buf[(j + i)] ^= digest[i];
		if ((j + MD5_HASH_SIZE) >= password_len_aligned)
			break;
		memcpy(&ctx, &ctx_with_key, sizeof(md5_ctx_t));
		md5_update(&ctx, (buf + j), MD5_HASH_SIZE);
	}
	return (0);
}

static inline int
radius_pkt_attr_password_decode(uint8_t *authenticator,
    uint8_t *enc_password, size_t enc_password_len, uint8_t *key, size_t key_len,
    uint8_t *buf, size_t buf_size, size_t *buf_size_ret) {
	size_t i, j;
	md5_ctx_t ctx, ctx_with_key;
	uint8_t digest[MD5_HASH_SIZE];

	if (NULL == authenticator || (NULL == enc_password && 0 != enc_password_len) ||
	    0 == enc_password_len ||
	    RADIUS_A_T_USER_PASSWORD_MAX_LEN < enc_password_len ||
	    0 != (enc_password_len % MD5_HASH_SIZE) ||
	    (NULL == key && 0 != key_len) ||
	    (NULL == buf && 0 != buf_size))
		return (EINVAL);
	if (enc_password_len > buf_size) {
		if (NULL != buf_size_ret)
			(*buf_size_ret) = enc_password_len;
		return (EOVERFLOW);
	}
	/* Copy and pad with zero. */
	memcpy(buf, enc_password, enc_password_len);
	if (buf_size > enc_password_len)
		buf[enc_password_len] = 0;
	/* Init md5 context. */
	md5_init(&ctx);
	md5_update(&ctx, key, key_len); /* key */
	memcpy(&ctx_with_key, &ctx, sizeof(md5_ctx_t)); /* Save context with key. */
	/* First block. */
	md5_update(&ctx, authenticator, MD5_HASH_SIZE); /* authenticator */
	/* Finish first and process other blocks. */
	for (j = 0; j < enc_password_len; j += MD5_HASH_SIZE) {
		md5_final(&ctx, digest);
		if ((j + MD5_HASH_SIZE) < enc_password_len) {
			memcpy(&ctx, &ctx_with_key, sizeof(md5_ctx_t));
			md5_update(&ctx, (buf + j), MD5_HASH_SIZE);
		}
		for (i = 0; i < MD5_HASH_SIZE; i ++)
			buf[(j + i)] ^= digest[i];
	}
	if (NULL != buf_size_ret)
		(*buf_size_ret) = strnlen((const char*)buf, enc_password_len);
	return (0);
}


/* Call after radius_pkt_chk() !!!
 * Returns: 0 - sign OK;
 * -1 - no sign;
 * EBADMSG - bad sign. */
static inline int
radius_pkt_attr_msg_authenticator_calc(rad_pkt_hdr_p pkt, rad_pkt_attr_p attr,
    uint8_t *key, size_t key_len, int pkt_authenticator_inside, rad_pkt_hdr_p pkt_req,
    uint8_t *msg_authenticator) {
	uint8_t *msg_authr_data;
	hmac_md5_ctx_t hctx;

	if (NULL == pkt || NULL == attr || (NULL == key && 0 != key_len))
		return (EINVAL);
	if ((2 + MD5_HASH_SIZE) != attr->len) /* radius_pkt_attr_chk() do same. */
		return (EBADMSG);

	msg_authr_data = RADIUS_PKT_ATTR_DATA(attr);
	memset(msg_authenticator, 0, MD5_HASH_SIZE); /* Need for authenticator and msg authenticator. */
	hmac_md5_init(key, key_len, &hctx);
	hmac_md5_update(&hctx, (uint8_t*)pkt, 4); /* code + id + len */

	/* Process authenticator. */
	if (0 != pkt_authenticator_inside)
		goto authenticator_inside;
	switch (pkt->code) {
	case RADIUS_PKT_TYPE_ACCESS_REQUEST:
	case RADIUS_PKT_TYPE_STATUS_SERVER:
	case RADIUS_PKT_TYPE_STATUS_CLIENT:
authenticator_inside:
		/* Use as is: pkt->authenticator = random data. */
		hmac_md5_update(&hctx, pkt->authenticator, MD5_HASH_SIZE);
		break;
	case RADIUS_PKT_TYPE_ACCOUNTING_RESPONSE:
		if (NULL != pkt_req &&
		    pkt_req->code == RADIUS_PKT_TYPE_STATUS_SERVER)
			goto handle_ack;
		/* Passtrouth. */
	case RADIUS_PKT_TYPE_ACCOUNTING_REQUEST:
	case RADIUS_PKT_TYPE_DISCONNECT_REQUEST:
	case RADIUS_PKT_TYPE_COA_REQUEST:
		/* Set the authenticator to zero and calculate the HMAC. */
		hmac_md5_update(&hctx, msg_authenticator, MD5_HASH_SIZE);
		break;
	case RADIUS_PKT_TYPE_ACCESS_ACCEPT:
	case RADIUS_PKT_TYPE_ACCESS_REJECT:
	case RADIUS_PKT_TYPE_ACCESS_CHALLENGE:
	case RADIUS_PKT_TYPE_DISCONNECT_ACK:
	case RADIUS_PKT_TYPE_DISCONNECT_NAK:
	case RADIUS_PKT_TYPE_COA_ACK:
	case RADIUS_PKT_TYPE_COA_NAK:
		if (NULL == pkt_req) {
			hmac_md5_final(&hctx, msg_authenticator); /* Clear HMAC context. */
			return (EINVAL);
		}
handle_ack:
		hmac_md5_update(&hctx, pkt_req->authenticator, MD5_HASH_SIZE);
		break;
	default:
		return (EBADMSG);
		break;
	}
	/* Process attr. */
	/* Attrs before message authenticator and attr header. */
	hmac_md5_update(&hctx, (uint8_t*)RADIUS_PKT_ATTRS(pkt),
	    (msg_authr_data - ((uint8_t*)RADIUS_PKT_ATTRS(pkt))));
	/* Message authenticator data = zeroes. */
	hmac_md5_update(&hctx, msg_authenticator, MD5_HASH_SIZE);
	/* Attrs after msg authenticator. */
	hmac_md5_update(&hctx, (msg_authr_data + MD5_HASH_SIZE),
	    (RADIUS_PKT_END(pkt) - (msg_authr_data + MD5_HASH_SIZE)));
	/* All done! */
	hmac_md5_final(&hctx, msg_authenticator);
	return (0);
}

static inline int
radius_pkt_attr_msg_authenticator_chk(rad_pkt_hdr_p pkt, size_t offset,
    uint8_t *key, size_t key_len, int pkt_authenticator_inside, rad_pkt_hdr_p pkt_req,
    size_t *offset_ret) {
	int error;
	uint8_t calc_msg_authr[MD5_HASH_SIZE];
	rad_pkt_attr_p attr = NULL;

	if (NULL == pkt)
		return (EINVAL);
	if (0 != offset) {
		if (0 != radius_pkt_attr_get_from_offset(pkt, offset, &attr))
			return (EINVAL);
		if (RADIUS_ATTR_TYPE_MSG_AUTHENTIC != attr->type)
			return (EINVAL);
		if (NULL != offset_ret)
			(*offset_ret) = offset;
	} else {
		if (0 != radius_pkt_attr_find_raw(pkt, 0,
		    RADIUS_ATTR_TYPE_MSG_AUTHENTIC, &attr, offset_ret))
			return (-1);
	}
	error = radius_pkt_attr_msg_authenticator_calc(pkt, attr, key, key_len,
	    pkt_authenticator_inside, pkt_req, (uint8_t*)calc_msg_authr);
	if (0 != error)
		return (error);
	if (0 != radius_sec_memcmp(RADIUS_PKT_ATTR_DATA(attr), calc_msg_authr,
	    MD5_HASH_SIZE))
		return (EBADMSG);
	return (0);
}

static inline int
radius_pkt_attr_msg_authenticator_update(rad_pkt_hdr_p pkt, size_t offset,
    uint8_t *key, size_t key_len, int pkt_authenticator_inside, rad_pkt_hdr_p pkt_req,
    size_t *offset_ret) {
	rad_pkt_attr_p attr = NULL;

	if (NULL == pkt)
		return (EINVAL);
	if (0 != offset) {
		if (0 != radius_pkt_attr_get_from_offset(pkt, offset, &attr))
			return (EINVAL);
		if (RADIUS_ATTR_TYPE_MSG_AUTHENTIC != attr->type)
			return (EINVAL);
		if (NULL != offset_ret)
			(*offset_ret) = offset;
	} else {
		if (0 != radius_pkt_attr_find_raw(pkt, 0,
		    RADIUS_ATTR_TYPE_MSG_AUTHENTIC, &attr, offset_ret))
			return (-1);
	}
	return (radius_pkt_attr_msg_authenticator_calc(pkt, attr, key, key_len,
	    pkt_authenticator_inside, pkt_req, RADIUS_PKT_ATTR_DATA(attr)));
}


static inline int
radius_pkt_attr_alloc_raw(rad_pkt_hdr_p pkt, size_t pkt_buf_size, size_t *pkt_size_ret,
    uint8_t type, uint8_t len, rad_pkt_attr_p *attr_ret, size_t *offset_ret) {
	size_t pkt_size;
	rad_pkt_attr_p attr;

	if (NULL == pkt || RADIUS_ATTR_DATA_SIZE_MAX < len)
		return (EINVAL);
	pkt_size = RADIUS_PKT_HDR_LEN_GET(pkt);
	attr = ((rad_pkt_attr_p)(((uint8_t*)pkt) + pkt_size));
	pkt_size += (2 + len); /* 2 = type + len */
	if (NULL != pkt_size_ret)
		(*pkt_size_ret) = pkt_size;
	if (pkt_size > pkt_buf_size)
		return (EOVERFLOW);
	attr->type = type;
	attr->len = (2 + len);
	RADIUS_PKT_HDR_LEN_SET(pkt, pkt_size);
	if (NULL != attr_ret)
		(*attr_ret) = attr;
	if (NULL != offset_ret)
		(*offset_ret) = (((uint8_t*)attr) - ((uint8_t*)pkt));
	return (0);
}
static inline int
radius_pkt_attr_add_raw(rad_pkt_hdr_p pkt, size_t pkt_buf_size, size_t *pkt_size_ret,
    uint8_t type, uint8_t len, uint8_t *data,
    rad_pkt_attr_p *attr_ret, size_t *offset_ret) {
	int error;
	rad_pkt_attr_p attr = NULL;

	if (NULL == data && 0 != len)
		return (EINVAL);
	error = radius_pkt_attr_alloc_raw(pkt, pkt_buf_size, pkt_size_ret,
	    type, len, &attr, offset_ret);
	if (0 != error)
		return (error);
	memcpy(RADIUS_PKT_ATTR_DATA(attr), data, len);
	if (NULL != attr_ret)
		(*attr_ret) = attr;
	return (0);
}
static inline int
radius_pkt_attr_add(rad_pkt_hdr_p pkt, size_t pkt_buf_size, size_t *pkt_size_ret,
    uint8_t type, uint8_t len, uint8_t *data, size_t *offset_ret) {
	int error;
	size_t tm;
	rad_pkt_attr_p attr = NULL;
	rad_attr_param_p attr_prm;

	if (NULL == pkt)
		return (EINVAL);
	/* Special handle. */
	switch (type) {
	case RADIUS_ATTR_TYPE_USER_PASSWORD:
		if (RADIUS_A_T_USER_PASSWORD_MAX_LEN < len)
			return (EINVAL);
		/* Is allready added? */
		error = radius_pkt_attr_find(pkt, 0, type, offset_ret);
		if (ENOATTR != error) {
			if (0 == error)
				return (EEXIST); /* Replace return code. */
			return (error);
		}
		/* Is allready added CHAP? */
		error = radius_pkt_attr_find(pkt, 0, RADIUS_ATTR_TYPE_CHAP_PASSWORD,
		    NULL);
		if (ENOATTR != error) {
			if (0 == error)
				return (EEXIST); /* Replace return code. */
			return (error);
		}
		/* Calc size. */
		error = radius_pkt_attr_password_encode(NULL, NULL, len, NULL, 0,
		    NULL, 0, &tm);
		if (0 != error)
			return (error);
		/* Add attribute with empty data. */
		error = radius_pkt_attr_alloc_raw(pkt, pkt_buf_size, pkt_size_ret,
		    type, tm, &attr, offset_ret);
		if (0 != error)
			return (error);
		/* Encode password to attribute data - late, on pkt sign. */
		memcpy(RADIUS_PKT_ATTR_DATA(attr), data, len);
		memset((RADIUS_PKT_ATTR_DATA(attr) + len), 0, (tm - len));
		return (0);
		break;
	case RADIUS_ATTR_TYPE_MSG_AUTHENTIC:
		//return (ECANCELED); /* Allow or not allow to add this attribute, - thats is the question! */
		/* Is allready added? */
		error = radius_pkt_attr_find(pkt, 0, type, offset_ret);
		if (ENOATTR != error) {
			if (0 == error)
				return (EEXIST); /* Replace return code. */
			return (error);
		}
		/* Only allocate space, write data on pkt sign. */
		error = radius_pkt_attr_alloc_raw(pkt, pkt_buf_size, pkt_size_ret,
		    type, MD5_HASH_SIZE, &attr, offset_ret);
		if (0 != error)
			return (error);
		memset(RADIUS_PKT_ATTR_DATA(attr), 0, MD5_HASH_SIZE);
		return (0);
		break;
	}

	/* Other types standart processing. */
	/* Type and len checks. */
	if (0 == type)
		return (EINVAL);
	attr_prm = (rad_attr_param_p)&rad_attr_params[type];
	switch (attr_prm->data_type) {
	case RADIUS_ATTR_PARAM_T_NONE: /* Unknown format, cant check. */
		break;
	case RADIUS_ATTR_PARAM_T_STR: /* string, Length >= 3 */
	case RADIUS_ATTR_PARAM_T_TEXT: /* UTF8 string, Length >= 3 */
	case RADIUS_ATTR_PARAM_T_ADV: /* Length >= 3 */
	case RADIUS_ATTR_PARAM_T_ANY: /* Length >= 3 */
		switch (attr_prm->len_min) {
		case 0: /* At least one byte len required. */
			if (1 > len)
				return (EINVAL);
			break;
		case 0xff: /* Allow zero len. */
			break;
		default: /* Specific minimum len. */
			if (len < attr_prm->len_min)
				return (EINVAL);
			break;
		}
		if (0 != attr_prm->len_max && len > attr_prm->len_max)
			return (EINVAL);
		break;
	case RADIUS_ATTR_PARAM_T_IPV4: /* Length = 6 */
	case RADIUS_ATTR_PARAM_T_INT32: /* Length = 6 */
	case RADIUS_ATTR_PARAM_T_TIME32: /* Length = 6 */
		if (4 != len)
			return (EINVAL);
		break;
	case RADIUS_ATTR_PARAM_T_INT64:
		if (8 != len)
			return (EINVAL);
		break;
	case RADIUS_ATTR_PARAM_T_IPV6: /* Length = 18 */
		if (16 != len)
			return (EINVAL);
		break;
	case RADIUS_ATTR_PARAM_T_IPV6_PREFIX: /* Length = At least 4 and no larger than 20 */
		if (2 > len || 18 < len)
			return (EINVAL);
		break;
	case RADIUS_ATTR_PARAM_T_VENDOR_SPEC: /* Vendor-Specific, Length >= 7 */
		if (5 > len)
			return (EINVAL);
		break;
	case RADIUS_ATTR_PARAM_T_EXT: /* Extended-Type, Length >= 4 */
		if (2 > len)
			return (EINVAL);
		break;
	case RADIUS_ATTR_PARAM_T_EXT_LONG: /* Long Extended Type, Length >= 5 */
		if (3 > len)
			return (EINVAL);
		break;
	default:
		return (EINVAL);
	}
	/* Add attribute to packet end. */
	error = radius_pkt_attr_add_raw(pkt, pkt_buf_size, pkt_size_ret,
	    type, len, data, NULL, offset_ret);
	return (error);
}
static inline int
radius_pkt_attr_add_uint32(rad_pkt_hdr_p pkt, size_t pkt_buf_size, size_t *pkt_size_ret,
    uint8_t type, uint32_t data, size_t *offset_ret) {

	return (radius_pkt_attr_add(pkt, pkt_buf_size, pkt_size_ret, type,
	    4, (uint8_t*)&data, offset_ret));
}
static inline int
radius_pkt_attr_add_port(rad_pkt_hdr_p pkt, size_t pkt_buf_size, size_t *pkt_size_ret,
    uint8_t type, struct sockaddr_storage *addr, size_t *offset_ret) {

	if (NULL == addr)
		return (EINVAL);
	switch (addr->ss_family) {
	case AF_INET:
		return (radius_pkt_attr_add(pkt, pkt_buf_size, pkt_size_ret,
		    type, 4, (uint8_t*)&((struct sockaddr_in*)addr)->sin_port,
		    offset_ret));
		break;
	case AF_INET6:
		return (radius_pkt_attr_add(pkt, pkt_buf_size, pkt_size_ret,
		    type, 4, (uint8_t*)&((struct sockaddr_in6*)addr)->sin6_port,
		    offset_ret));
		break;
	}
	return (EINVAL);
}
static inline int
radius_pkt_attr_add_addr(rad_pkt_hdr_p pkt, size_t pkt_buf_size, size_t *pkt_size_ret,
    uint8_t type_v4, uint8_t type_v6, struct sockaddr_storage *addr,
    size_t *offset_ret) {

	if (NULL == addr)
		return (EINVAL);
	switch (addr->ss_family) {
	case AF_INET:
		return (radius_pkt_attr_add(pkt, pkt_buf_size, pkt_size_ret,
		    type_v4, sizeof(struct sockaddr_in),
		    (uint8_t*)&((struct sockaddr_in*)addr)->sin_addr,
		    offset_ret));
		break;
	case AF_INET6:
		return (radius_pkt_attr_add(pkt, pkt_buf_size, pkt_size_ret,
		    type_v6, sizeof(struct sockaddr_in6),
		    (uint8_t*)&((struct sockaddr_in6*)addr)->sin6_addr,
		    offset_ret));
		break;
	}
	return (EINVAL);
}

static inline int
radius_pkt_attr_get_data_ptr_raw(rad_pkt_hdr_p pkt, size_t offset,
    uint8_t *type, uint8_t **data, size_t *len) {
	int error;
	rad_pkt_attr_p attr = NULL;

	error = radius_pkt_attr_get_from_offset(pkt, offset, &attr);
	if (0 != error)
		return (error);
	if (NULL != type)
		(*type) = attr->type;
	if (NULL != data)
		(*data) = RADIUS_PKT_ATTR_DATA(attr);
	if (NULL != len)
		(*len) = (attr->len - 2);
	return (0);
}
static inline int
radius_pkt_attr_get_data_ptr(rad_pkt_hdr_p pkt, size_t offset,
    uint8_t *type, uint8_t **data, size_t *len) {
	int error;
	uint8_t data_type = 0, *data_ptr = NULL;
	size_t data_len = 0;

	error = radius_pkt_attr_get_data_ptr_raw(pkt, offset,
	    &data_type, &data_ptr, &data_len);
	if (0 != error)
		return (error);
	/* Special handle. */
	switch (data_type) {
	case RADIUS_ATTR_TYPE_USER_PASSWORD:
		/* After decoding in radius_pkt_verify() password may be zero padded. */
		data_len = strnlen((const char*)data_ptr, data_len);
		break;
	case RADIUS_ATTR_TYPE_MSG_AUTHENTIC:
		//return (ECANCELED); /* Allow or not allow to get this attribute, - thats is the question! */
		break;
	}
	if (NULL != type)
		(*type) = data_type;
	if (NULL != data)
		(*data) = data_ptr;
	if (NULL != len)
		(*len) = data_len;
	return (0);
}

static inline int
radius_pkt_attr_get_data_to_buf(rad_pkt_hdr_p pkt, size_t offset, size_t count,
    uint8_t type, uint8_t *buf, size_t buf_size, size_t *buf_size_ret) {
	int error = ENOATTR;
	uint8_t *ptm;
	size_t tm, data_len = 0;

	if (0 == count)
		count = ~count; /* Get all attrs. */
	while (0 != count && 0 == radius_pkt_attr_find(pkt, offset, type, &offset)) {
		error = radius_pkt_attr_get_data_ptr(pkt, offset, NULL, &ptm, &tm);
		if (0 != error)
			break;
		if (buf_size < (data_len + tm))
			break; /* Not enought free space in buf. */
		memcpy((buf + data_len), ptm, tm);
		data_len += tm;
		offset += (tm + 2); /* Move next. */
		count --;
	}
	if (NULL != buf_size_ret)
		(*buf_size_ret) = data_len;
	return (error);
}


//////////////////////////////////////////////////////////////////////////
/////////////////////////////Radius packet////////////////////////////////
//////////////////////////////////////////////////////////////////////////


static inline int
radius_pkt_chk(rad_pkt_hdr_p pkt, size_t pkt_size) {
	int error;
	size_t attr_cnt, msg_authentic_cnt = 0, eap_msg_cnt = 0;
	rad_pkt_attr_p attr;

	if (NULL == pkt)
		return (EINVAL);
	if (RADIUS_PKT_HDR_LEN_GET(pkt) > pkt_size ||
	    RADIUS_PKT_HDR_SIZE > RADIUS_PKT_HDR_LEN_GET(pkt) ||
	    RADIUS_PKT_MAX_SIZE < RADIUS_PKT_HDR_LEN_GET(pkt))
		return (EBADMSG);

	switch (pkt->code) {
	case RADIUS_PKT_TYPE_ACCESS_REQUEST:
	case RADIUS_PKT_TYPE_ACCESS_ACCEPT:
	case RADIUS_PKT_TYPE_ACCESS_REJECT:
	case RADIUS_PKT_TYPE_ACCOUNTING_REQUEST:
	case RADIUS_PKT_TYPE_ACCOUNTING_RESPONSE:
	case RADIUS_PKT_TYPE_ACCESS_CHALLENGE:
	case RADIUS_PKT_TYPE_STATUS_SERVER:
	case RADIUS_PKT_TYPE_STATUS_CLIENT:
	case RADIUS_PKT_TYPE_DISCONNECT_REQUEST:
	case RADIUS_PKT_TYPE_DISCONNECT_ACK:
	case RADIUS_PKT_TYPE_DISCONNECT_NAK:
	case RADIUS_PKT_TYPE_COA_REQUEST:
	case RADIUS_PKT_TYPE_COA_ACK:
	case RADIUS_PKT_TYPE_COA_NAK:
		break;
	default:
		return (EBADMSG);
	}
	
	attr = RADIUS_PKT_ATTRS(pkt);
	attr_cnt = RADIUS_PKT_ATTRS_SIZE(pkt);
	while (0 != attr_cnt) {
		if (attr_cnt < 2) /* No attr header. */
			return (EBADMSG);
		if (attr_cnt < attr->len) /* Out of header. */
			return (EBADMSG);
		error = radius_pkt_attr_chk(attr);
		if (0 != error)
			return (error);
		switch (attr->type) {
		case RADIUS_ATTR_TYPE_EAP_MSG:
			eap_msg_cnt ++;
			break;
		case RADIUS_ATTR_TYPE_MSG_AUTHENTIC:
			msg_authentic_cnt ++;
			break;
		}
		attr_cnt -= attr->len;
		attr = RADIUS_PKT_ATTR_NEXT(attr);
	}
	if (1 < msg_authentic_cnt) /* Wierd format? */
		return (EBADMSG);
	/* Message-Authenticator is required in Status-Server packets and/or
	 * if EAP message attr present. */
	if (0 == msg_authentic_cnt &&
	    (RADIUS_PKT_TYPE_STATUS_SERVER == pkt->code || 0 != eap_msg_cnt))
		return (EBADMSG);
	return (0);
}


/* Call after radius_pkt_chk() !!!
 * Returns: 0 - sign OK;
 * EBADMSG - bad sign. */
static inline int
radius_pkt_authenticator_calc(rad_pkt_hdr_p pkt, uint8_t *key, size_t key_len,
    int pkt_authenticator_inside, rad_pkt_hdr_p pkt_req, uint8_t *authenticator) {
	md5_ctx_t ctx;

	if (NULL == pkt || (NULL == key && 0 != key_len))
		return (EINVAL);

	switch (pkt->code) {
	case RADIUS_PKT_TYPE_ACCESS_REQUEST:
	case RADIUS_PKT_TYPE_STATUS_SERVER:
	case RADIUS_PKT_TYPE_STATUS_CLIENT:
		/* The authenticator is random, cant calc. */
		memcpy(authenticator, pkt->authenticator, MD5_HASH_SIZE);
		return (0);
		break;
	}
	if (0 != pkt_authenticator_inside) {
		/* MD5(packet + secret); */
		md5_init(&ctx);
		md5_update(&ctx, (uint8_t*)pkt, RADIUS_PKT_HDR_LEN_GET(pkt)); /* pkt hdr + attrs */
		md5_update(&ctx, key, key_len);
		md5_final(&ctx, authenticator);
		return (0);
	}
	switch (pkt->code) {
	case RADIUS_PKT_TYPE_ACCOUNTING_REQUEST:
	case RADIUS_PKT_TYPE_DISCONNECT_REQUEST:
	case RADIUS_PKT_TYPE_COA_REQUEST:
		memset(authenticator, 0, MD5_HASH_SIZE);
		/* MD5(packet + secret); */
		md5_init(&ctx);
		md5_update(&ctx, (uint8_t*)pkt, 4); /* code + id + len */
		md5_update(&ctx, authenticator, MD5_HASH_SIZE); /* authenticator */
		md5_update(&ctx, (uint8_t*)RADIUS_PKT_ATTRS(pkt),
		    RADIUS_PKT_ATTRS_SIZE(pkt)); /* attrs */
		md5_update(&ctx, key, key_len);
		md5_final(&ctx, authenticator);
		break;
	case RADIUS_PKT_TYPE_ACCESS_ACCEPT:
	case RADIUS_PKT_TYPE_ACCESS_REJECT:
	case RADIUS_PKT_TYPE_ACCESS_CHALLENGE:
	case RADIUS_PKT_TYPE_ACCOUNTING_RESPONSE:
	case RADIUS_PKT_TYPE_DISCONNECT_ACK:
	case RADIUS_PKT_TYPE_DISCONNECT_NAK:
	case RADIUS_PKT_TYPE_COA_ACK:
	case RADIUS_PKT_TYPE_COA_NAK:
	/* Verify the reply digest */
		if (NULL == pkt_req)
			return (EINVAL);
		/* MD5(packet + secret); */
		md5_init(&ctx);
		md5_update(&ctx, (uint8_t*)pkt, 4); /* code + id + len */
		md5_update(&ctx, pkt_req->authenticator, MD5_HASH_SIZE); /* authenticator */
		md5_update(&ctx, (uint8_t*)RADIUS_PKT_ATTRS(pkt),
		    RADIUS_PKT_ATTRS_SIZE(pkt)); /* attrs */
		md5_update(&ctx, key, key_len);
		md5_final(&ctx, authenticator);
		break;
	default:
		return (EINVAL);
		break;
	}
	return (0);
}

static inline int
radius_pkt_authenticator_chk(rad_pkt_hdr_p pkt, uint8_t *key, size_t key_len,
    int pkt_authenticator_inside, rad_pkt_hdr_p pkt_req) {
	uint8_t calc_authr[MD5_HASH_SIZE];

	if (NULL == pkt)
		return (EINVAL);
	/* Skeep check for types with random data in authenticator. */
	switch (pkt->code) {
	case RADIUS_PKT_TYPE_ACCESS_REQUEST:
	case RADIUS_PKT_TYPE_STATUS_SERVER:
	case RADIUS_PKT_TYPE_STATUS_CLIENT:
		return (0);
		break;
	}
	if (0 != radius_pkt_authenticator_calc(pkt, key, key_len,
	    pkt_authenticator_inside, pkt_req, (uint8_t*)calc_authr))
		return (EINVAL);
	if (0 != radius_sec_memcmp(pkt->authenticator, calc_authr, MD5_HASH_SIZE))
		return (EBADMSG);
	return (0);
}

static inline int
radius_pkt_authenticator_update(rad_pkt_hdr_p pkt, uint8_t *key, size_t key_len,
    int pkt_authenticator_inside, rad_pkt_hdr_p pkt_req) {

	if (NULL == pkt)
		return (EINVAL);
	/* For types with random data in authenticator. */
	switch (pkt->code) {
	case RADIUS_PKT_TYPE_ACCESS_REQUEST:
	case RADIUS_PKT_TYPE_STATUS_SERVER:
	case RADIUS_PKT_TYPE_STATUS_CLIENT:
		/* MUST BEEN SET BEFORE! */
		return (0);
		break;
	}
	return (radius_pkt_authenticator_calc(pkt, key, key_len,
	    pkt_authenticator_inside, pkt_req, (uint8_t*)pkt->authenticator));
}


static inline int
radius_pkt_init(rad_pkt_hdr_p pkt, size_t pkt_buf_size, size_t *pkt_size_ret,
    uint8_t code, uint8_t id, uint8_t *authenticator) {

	if (NULL == pkt)
		return (EINVAL);
	if (NULL != pkt_size_ret)
		(*pkt_size_ret) = RADIUS_PKT_HDR_SIZE;
	if (RADIUS_PKT_HDR_SIZE > pkt_buf_size)
		return (EOVERFLOW);
	/* Init data. */
	switch (code) {
	case RADIUS_PKT_TYPE_ACCOUNTING_RESPONSE:
		if (NULL != authenticator)
			goto handle_ack;
		/* Passtrouth. */
	case RADIUS_PKT_TYPE_ACCOUNTING_REQUEST:
	case RADIUS_PKT_TYPE_DISCONNECT_REQUEST:
	case RADIUS_PKT_TYPE_COA_REQUEST:
		/* The authenticator is zero. */
		memset(pkt->authenticator, 0, MD5_HASH_SIZE);
		break;
	case RADIUS_PKT_TYPE_ACCESS_REQUEST:
	case RADIUS_PKT_TYPE_STATUS_SERVER:
	case RADIUS_PKT_TYPE_STATUS_CLIENT:
		/* The authenticator is random. */
		/* Passtrouth. */
	case RADIUS_PKT_TYPE_ACCESS_ACCEPT:
	case RADIUS_PKT_TYPE_ACCESS_REJECT:
	case RADIUS_PKT_TYPE_ACCESS_CHALLENGE:
	case RADIUS_PKT_TYPE_DISCONNECT_ACK:
	case RADIUS_PKT_TYPE_DISCONNECT_NAK:
	case RADIUS_PKT_TYPE_COA_ACK:
	case RADIUS_PKT_TYPE_COA_NAK:
		/* The authenticator = authenticator from request. */
		if (NULL == authenticator)
			return (EINVAL);
handle_ack:
		memcpy(pkt->authenticator, authenticator, MD5_HASH_SIZE);
		break;
	default:
		return (EINVAL);
		break;
	}
	pkt->code = code;
	pkt->id = id;
	RADIUS_PKT_HDR_LEN_SET(pkt, RADIUS_PKT_HDR_SIZE);

	return (0);
}
static inline int
radius_pkt_reply_init(rad_pkt_hdr_p pkt, size_t pkt_buf_size, size_t *pkt_size_ret,
    uint8_t code, rad_pkt_hdr_p pkt_req) {

	if (NULL == pkt_req)
		return (EINVAL);
	return (radius_pkt_init(pkt, pkt_buf_size, pkt_size_ret, code,
	    pkt_req->id, pkt_req->authenticator));
}

static inline int
radius_pkt_sign(rad_pkt_hdr_p pkt, size_t pkt_buf_size, size_t *pkt_size_ret,
    uint8_t *key, size_t key_len, int add_msg_authr) {
	int error;
	size_t offset;
	rad_pkt_attr_p attr = NULL;

	if (NULL == pkt || (NULL == key && 0 != key_len))
		return (EINVAL);
	/* Encode User-Password. */
	if (0 == radius_pkt_attr_find_raw(pkt, 0, RADIUS_ATTR_TYPE_USER_PASSWORD,
	    &attr, NULL)) {
		/* Encode password from/to attribute data. */
		error = radius_pkt_attr_password_encode(pkt->authenticator,
		    RADIUS_PKT_ATTR_DATA(attr), (attr->len - 2), key, key_len,
		    RADIUS_PKT_ATTR_DATA(attr), (attr->len - 2), NULL);
		if (0 != error)
			return (error);
	}
	/* Message-Authenticator. */
	offset = 0;
	if (0 != add_msg_authr) { /* Add (and existing check). */
		error = radius_pkt_attr_add(pkt, pkt_buf_size, pkt_size_ret,
		    RADIUS_ATTR_TYPE_MSG_AUTHENTIC, 0, NULL, &offset);
		if (0 != error)
			return (error);
	} else { /* Try to find Message-Authenticator. */
		error = radius_pkt_attr_find(pkt, 0, RADIUS_ATTR_TYPE_MSG_AUTHENTIC,
		    &offset);
		if (ENOATTR != error && 0 != error)
			return (error);
	}
	if (0 != offset) { /* Message-Authenticator found, update it. */
		error = radius_pkt_attr_msg_authenticator_update(pkt, offset,
		    key, key_len, 1, NULL, NULL);
		if (0 != error)
			return (error);
	}
	/* Update authenticator if needed. */
	error = radius_pkt_authenticator_update(pkt, key, key_len, 1, NULL);
	if (NULL != pkt_size_ret)
		(*pkt_size_ret) = RADIUS_PKT_HDR_LEN_GET(pkt);

	return (error);
}

static inline int
radius_pkt_verify(rad_pkt_hdr_p pkt, uint8_t *key, size_t key_len,
    rad_pkt_hdr_p pkt_req) {
	int error;
	size_t offset;
	rad_pkt_attr_p attr = NULL;

	if (NULL == pkt || (NULL == key && 0 != key_len))
		return (EINVAL);
	/* If Message-Authenticator exist, check it. */
	if (0 == radius_pkt_attr_find(pkt, 0, RADIUS_ATTR_TYPE_MSG_AUTHENTIC,
	    &offset)) {
		error = radius_pkt_attr_msg_authenticator_chk(pkt, offset,
		    key, key_len, 0, pkt_req, NULL);
		if (0 != error)
			return (error);
	}
	/* Check authenticator if needed. */
	error = radius_pkt_authenticator_chk(pkt, key, key_len, 0, pkt_req);
	if (0 != error)
		return (error);
	/* Decode User-Password. */
	if (0 == radius_pkt_attr_find_raw(pkt, 0, RADIUS_ATTR_TYPE_USER_PASSWORD,
	    &attr, NULL)) {
		/* Decode password from/to attribute data. */
		error = radius_pkt_attr_password_decode(pkt->authenticator,
		    RADIUS_PKT_ATTR_DATA(attr), (attr->len - 2), key, key_len,
		    RADIUS_PKT_ATTR_DATA(attr), (attr->len - 2), NULL);
		if (0 != error)
			return (error);
	}
	return (error);
}






#endif /* __RADIUS_PKT_H__ */
