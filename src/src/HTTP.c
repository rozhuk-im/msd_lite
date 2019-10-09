/*-
 * Copyright (c) 2010 - 2016 Rozhuk Ivan <rozhuk.im@gmail.com>
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

/* RFC 2616 */
// https://code.google.com/p/xbt/source/browse/trunk/xbt/misc/bt_misc.cpp

#include <sys/param.h>

#ifdef __linux__ /* Linux specific code. */
#	define _GNU_SOURCE /* See feature_test_macros(7) */
#	define __USE_GNU 1
#endif /* Linux specific code. */

#include <sys/types.h>
#include <inttypes.h>
//#include <stdlib.h>
//#include <stdio.h> /* snprintf, fprintf */
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <errno.h>

#include "macro_helpers.h"
#include "mem_helpers.h"
#include "StrToNum.h"
#include "StrHexToNum.h"
#include "HTTP.h"


/* http://www.iana.org/assignments/http-status-codes/http-status-codes.xml */
static const char *reason_phrase_none = "";

/* Informational - Request received, continuing process */
static const char *reason_phrase_1xx[] = {
	"Continue",					/* 100 */
	"Switching Protocols",				/* 101 */
	"Processing",					/* 102 */
};
static const size_t reason_phrase_size_1xx[] = {
	8,						/* 100 */
	19,						/* 101 */
	10,						/* 102 */
};

/* Success - The action was successfully received, understood, and accepted */
static const char *reason_phrase_2xx[] = {
	"OK",						/* 200 */
	"Created",					/* 201 */
	"Accepted",					/* 202 */
	"Non-Authoritative Information",		/* 203 */
	"No Content",					/* 204 */
	"Reset Content",				/* 205 */
	"Partial Content",				/* 206 */
	"Multi-Status",					/* 207 */
	"Already Reported",				/* 208 */
	NULL,						/* 209 */
	NULL, NULL, NULL, NULL, NULL,			/* 210 - 214 */
	NULL, NULL, NULL, NULL, NULL,			/* 215 - 219 */
	NULL, NULL, NULL, NULL, NULL,			/* 220 - 224 */
	NULL,						/* 225 */
	"IM Used",					/* 226 */
};
static const size_t reason_phrase_size_2xx[] = {
	2,						/* 200 */
	7,						/* 201 */
	8,						/* 202 */
	29,						/* 203 */
	10,						/* 204 */
	13,						/* 205 */
	15,						/* 206 */
	12,						/* 207 */
	16,						/* 208 */
	0,						/* 209 */
	0, 0, 0, 0, 0,					/* 210 - 214 */
	0, 0, 0, 0, 0,					/* 215 - 219 */
	0, 0, 0, 0, 0,					/* 220 - 224 */
	0,						/* 225 */
	7,						/* 226 */
};

/* Redirection - Further action must be taken in order to complete the request */
static const char *reason_phrase_3xx[] = {
	"Multiple Choices",				/* 300 */
	"Moved Permanently",				/* 301 */
	"Found",					/* 302 */
	"See Other",					/* 303 */
	"Not Modified",					/* 304 */
	"Use Proxy",					/* 305 */
	NULL,						/* 306 */
	"Temporary Redirect",				/* 307 */
	"Permanent Redirect",				/* 308 */
};
static const size_t reason_phrase_size_3xx[] = {
	16,						/* 300 */
	17,						/* 301 */
	5,						/* 302 */
	9,						/* 303 */
	12,						/* 304 */
	9,						/* 305 */
	0,						/* 306 */
	18,						/* 307 */
	18,						/* 308 */
};

/* Client Error - The request contains bad syntax or cannot be fulfilled */
static const char *reason_phrase_4xx[] = {
	"Bad request",					/* 400 */
	"Unauthorized",					/* 401 */
	"Payment Required",				/* 402 */
	"Forbidden",					/* 403 */
	"Not Found",					/* 404 */
	"Method not Allowed",				/* 405 */
	"Not Acceptable",				/* 406 */
	"Proxy Authentication Required",		/* 407 */
	"Request Timeout",				/* 408 */
	"Conflict",					/* 409 */
	"Gone",						/* 410 */
	"Length Required",				/* 411 */
	"Precondition Failed",				/* 412 */
	"Request Entity Too Large",			/* 413 */
	"Request-URI Too Long",				/* 414 */
	"Unsupported Media Type",			/* 415 */
	"Requested Range Not Satisfiable",		/* 416 */
	"Expectation Failed",				/* 417 */
	NULL, NULL, NULL, NULL,				/* 418 - 421 */
	"Unprocessable Entity",				/* 422 */
	"Locked",					/* 423 */
	"Failed Dependency",				/* 424 */
	"Unassigned",					/* 425 */
	"Upgrade Required",				/* 426 */
	NULL,						/* 427 */
	"Precondition Required",			/* 428 */
	"Too Many Requests",				/* 429 */
	NULL,						/* 430 */
	"Request Header Fields Too Large",		/* 431 */
};
static const size_t reason_phrase_size_4xx[] = {
	11,						/* 400 */
	12,						/* 401 */
	16,						/* 402 */
	9,						/* 403 */
	9,						/* 404 */
	18,						/* 405 */
	14,						/* 406 */
	29,						/* 407 */
	15,						/* 408 */
	8,						/* 409 */
	4,						/* 410 */
	15,						/* 411 */
	19,						/* 412 */
	24,						/* 413 */
	20,						/* 414 */
	22,						/* 415 */
	31,						/* 416 */
	18,						/* 417 */
	0, 0, 0, 0,					/* 418 - 421 */
	20,						/* 422 */
	6,						/* 423 */
	17,						/* 424 */
	10,						/* 425 */
	16,						/* 426 */
	0,						/* 427 */
	21,						/* 428 */
	17,						/* 429 */
	0,						/* 430 */
	31,						/* 431 */
};

/* Server Error - The server failed to fulfill an apparently valid request */
static const char *reason_phrase_5xx[] = {
	"Internal Server Error",			/* 500 */
	"Not Implemented",				/* 501 */
	"Bad Gateway",					/* 502 */
	"Service Unavailable",				/* 503 */
	"Gateway Timeout",				/* 504 */
	"HTTP Version Not Supported",			/* 505 */
	"Variant Also Negotiates",			/* 506 */
	"Insufficient Storage",				/* 507 */
	"Loop Detected",				/* 508 */
	NULL,						/* 509 */
	"Not Extended",					/* 510 */
	"Network Authentication Required",		/* 511 */
};
static const size_t reason_phrase_size_5xx[] = {
	21,						/* 500 */
	15,						/* 501 */
	11,						/* 502 */
	19,						/* 503 */
	15,						/* 504 */
	26,						/* 505 */
	23,						/* 506 */
	20,						/* 507 */
	13,						/* 508 */
	0,						/* 509 */
	12,						/* 510 */
	31,						/* 511 */
};



const char *
http_get_err_descr(uint32_t status_code, size_t *descr_size_ret) {
	const char *reason_phrase = NULL;

	if (100 > status_code) { /* 0 - 99 */
	} else if (200 > status_code) { /* 100 - 199 */
		status_code -= 100;
		if (sizeof(reason_phrase_1xx) > status_code) {
			reason_phrase = reason_phrase_1xx[status_code];
		}
		if (NULL != reason_phrase &&
		    NULL != descr_size_ret) {
			(*descr_size_ret) = reason_phrase_size_1xx[status_code];
		}
	} else if (300 > status_code) { /* 200 - 299 */
		status_code -= 200;
		if (sizeof(reason_phrase_2xx) > status_code) {
			reason_phrase = reason_phrase_2xx[status_code];
		}
		if (NULL != reason_phrase &&
		    NULL != descr_size_ret) {
			(*descr_size_ret) = reason_phrase_size_2xx[status_code];
		}
	} else if (400 > status_code) { /* 300 - 399 */
		status_code -= 300;
		if (sizeof(reason_phrase_3xx) > status_code) {
			reason_phrase = reason_phrase_3xx[status_code];
		}
		if (NULL != reason_phrase &&
		    NULL != descr_size_ret) {
			(*descr_size_ret) = reason_phrase_size_3xx[status_code];
		}
	} else if (500 > status_code) { /* 400 - 499 */
		status_code -= 400;
		if (sizeof(reason_phrase_4xx) > status_code) {
			reason_phrase = reason_phrase_4xx[status_code];
		}
		if (NULL != reason_phrase &&
		    NULL != descr_size_ret) {
			(*descr_size_ret) = reason_phrase_size_4xx[status_code];
		}
	} else if (600 > status_code) { /* 500 - 599 */
		status_code -= 500;
		if (sizeof(reason_phrase_5xx) > status_code) {
			reason_phrase = reason_phrase_5xx[status_code];
		}
		if (NULL != reason_phrase &&
		    NULL != descr_size_ret) {
			(*descr_size_ret) = reason_phrase_size_5xx[status_code];
		}
	}
	if (NULL == reason_phrase) {
		reason_phrase = reason_phrase_none;
		if (NULL != descr_size_ret) {
			(*descr_size_ret) = 0;
		}
	}
	return (reason_phrase);
}


uint32_t
http_get_method_fast(const uint8_t *m, size_t m_size) {

	switch (m_size) {
	case 3:
		switch ((*m)) {
		case 'G':
			if (0 == memcmp(m, HTTPReqMethod[HTTP_REQ_METHOD_GET], m_size))
				return (HTTP_REQ_METHOD_GET);
			return (HTTP_REQ_METHOD_UNKNOWN);
		case 'P':
			if (0 == memcmp(m, HTTPReqMethod[HTTP_REQ_METHOD_PUT], m_size))
				return (HTTP_REQ_METHOD_PUT);
			return (HTTP_REQ_METHOD_UNKNOWN);
		}
		return (HTTP_REQ_METHOD_UNKNOWN);
	case 4:
		switch ((*m)) {
		case 'H':
			if (0 == memcmp(m, HTTPReqMethod[HTTP_REQ_METHOD_HEAD], m_size))
				return (HTTP_REQ_METHOD_HEAD);
			return (HTTP_REQ_METHOD_UNKNOWN);
		case 'P':
			if (0 == memcmp(m, HTTPReqMethod[HTTP_REQ_METHOD_POST], m_size))
				return (HTTP_REQ_METHOD_POST);
			return (HTTP_REQ_METHOD_UNKNOWN);
		}
		return (HTTP_REQ_METHOD_UNKNOWN);
	case 5:
		if (0 == memcmp(m, HTTPReqMethod[HTTP_REQ_METHOD_TRACE], m_size))
			return (HTTP_REQ_METHOD_TRACE);
		return (HTTP_REQ_METHOD_UNKNOWN);
	case 6:
		switch ((*m)) {
		case 'D':
			if (0 == memcmp(m, HTTPReqMethod[HTTP_REQ_METHOD_DELETE], m_size))
				return (HTTP_REQ_METHOD_DELETE);
			return (HTTP_REQ_METHOD_UNKNOWN);
		case 'N':
			if (0 == memcmp(m, HTTPReqMethod[HTTP_REQ_METHOD_NOTIFY], m_size))
				return (HTTP_REQ_METHOD_NOTIFY);
			return (HTTP_REQ_METHOD_UNKNOWN);
		case 'M':
			if (0 == memcmp(m, HTTPReqMethod[HTTP_REQ_METHOD_M_POST], m_size))
				return (HTTP_REQ_METHOD_M_POST);
			return (HTTP_REQ_METHOD_UNKNOWN);
		}
		return (HTTP_REQ_METHOD_UNKNOWN);
	case 7:
		switch ((*m)) {
		case 'O':
			if (0 == memcmp(m, HTTPReqMethod[HTTP_REQ_METHOD_OPTIONS], m_size))
				return (HTTP_REQ_METHOD_OPTIONS);
			return (HTTP_REQ_METHOD_UNKNOWN);
		case 'C':
			if (0 == memcmp(m, HTTPReqMethod[HTTP_REQ_METHOD_CONNECT], m_size))
				return (HTTP_REQ_METHOD_CONNECT);
			return (HTTP_REQ_METHOD_UNKNOWN);
		}
		return (HTTP_REQ_METHOD_UNKNOWN);
	case 8:
		if (0 == memcmp(m, HTTPReqMethod[HTTP_REQ_METHOD_M_SEARCH], m_size))
			return (HTTP_REQ_METHOD_M_SEARCH);
		return (HTTP_REQ_METHOD_UNKNOWN);
	case 9:
		if (0 == memcmp(m, HTTPReqMethod[HTTP_REQ_METHOD_SUBSCRIBE], m_size))
			return (HTTP_REQ_METHOD_SUBSCRIBE);
		return (HTTP_REQ_METHOD_UNKNOWN);
	case 11:
		if (0 == memcmp(m, HTTPReqMethod[HTTP_REQ_METHOD_UNSUBSCRIBE], m_size))
			return (HTTP_REQ_METHOD_UNSUBSCRIBE);
		return (HTTP_REQ_METHOD_UNKNOWN);
	}
	return (HTTP_REQ_METHOD_UNKNOWN);
}

int
http_get_transfer_encoding_fast(uint8_t *c, size_t c_size) {

	switch (c_size) {
	case 4:
		if (0 == mem_cmpi(c, HTTPTransferEncoding[HTTP_REQ_TE_GZIP], c_size))
			return (HTTP_REQ_TE_GZIP);
		return (HTTP_REQ_TE_UNKNOWN);
	case 7:
		switch ((*c)) {
		case 'c':
		case 'C':
			if (0 == mem_cmpi(c, HTTPTransferEncoding[HTTP_REQ_TE_CHUNKED], c_size))
				return (HTTP_REQ_TE_CHUNKED);
			return (HTTP_REQ_TE_UNKNOWN);
		case 'd':
		case 'D':
			if (0 == mem_cmpi(c, HTTPTransferEncoding[HTTP_REQ_TE_DEFLATE], c_size))
				return (HTTP_REQ_TE_DEFLATE);
			return (HTTP_REQ_TE_UNKNOWN);
		}
		return (HTTP_REQ_TE_UNKNOWN);
	case 8:
		if (0 == mem_cmpi(c, HTTPTransferEncoding[HTTP_REQ_TE_COMPRESS], c_size))
			return (HTTP_REQ_TE_COMPRESS);
		return (HTTP_REQ_TE_UNKNOWN);
	}
	return (HTTP_REQ_TE_UNKNOWN);
}


int
http_req_sec_chk(const uint8_t *http_hdr, size_t hdr_size, uint32_t method_code) {
/* http://www.nestor.minsk.by/sr/2005/08/sr50806.html */
	const uint8_t *ptm, *hdr_max;
	size_t cl_count, te_count, tmp;

	/*
	 * Security checks:
	 * 1. SP':'
	 * 2. Control codes: < 32, !=CRLF !=tab, > 126
	 * 3. [CRLF]"Host" count > 1 !
	 * 4. [CRLF]"Content-Length" count == 1 !
	 * 5. GET has no "Content-Length"
	 * 6. [CRLF]"Transfer-Encoding" count == 1 !
	 * 7. Transfer-Encoding: chunked” and “Content-Length: 
	 * 8. host = uri host
	 */

	/* 1, 2 */
	hdr_max = (http_hdr + hdr_size);
	for (ptm = http_hdr; ptm < hdr_max; ptm ++) {
		if (126 < (*ptm))
			return (2); /* Control codes. */
		if (' ' == (*ptm) &&
		    hdr_max > (ptm + 1) &&
		    ':' == (*(ptm + 1)))
			return (1); /* SP':' */
		if (31 < (*ptm) ||
		    '\t' == (*ptm))
			continue;
		if ('\r' == (*ptm) &&
		    hdr_max > (ptm + 1) &&
		    '\n' == (*(ptm + 1))) {
			ptm ++; /* Skip CRLF. */
			continue;
		}
		return (2); /* Control codes. */
	}
	/* 3. */
	tmp = http_hdr_val_get_count(http_hdr, hdr_size, (const uint8_t*)"host", 4);
	if (1 < tmp)
		return (3);
	/* 4. */
	cl_count = http_hdr_val_get_count(http_hdr, hdr_size,
	    (const uint8_t*)"content-length", 14);
	if (1 < cl_count)
		return (4);
	/* 5. */
	if (0 != cl_count &&
	    HTTP_REQ_METHOD_GET == method_code)
		return (5);
	/* 6. */
	te_count = http_hdr_val_get_count(http_hdr, hdr_size,
	    (const uint8_t*)"transfer-encoding", 17);
	if (1 < te_count)
		return (6);
	/* 7. */
	if (0 != cl_count &&
	    0 != te_count)
		return (7);
	return (0);
}


/* 
 * Request-Line: method SP Request-URI SP HTTP-Version CRLF
 * GET /about.html HTTP/1.1
 * GET http://host.com/about.html HTTP/1.1
 */
/* <scheme>://<authority><path>?<query> */
/* Request-URI = "*" | absoluteURI | abs_path | authority */
/* http_URL = "http:" "//" host [ ":" port ] [ abs_path [ "?" query ]] */
int
http_parse_req_line(const uint8_t *http_hdr, size_t hdr_size,
    http_req_line_data_p req_data) {
	const uint8_t *line, *ptm, *pspace;
	size_t line_size, tm;

	if (NULL == http_hdr || 10 >= hdr_size || NULL == req_data)
		return (EINVAL);
	if ('A' > (*http_hdr) ||
	    'Z' < (*http_hdr))
		return (EBADMSG);
	mem_bzero(req_data, sizeof(http_req_line_data_t));
	/* Look for end of req line. */
	pspace = mem_find_cstr(http_hdr, hdr_size, CRLF);
	if (NULL == pspace) {
		pspace = (http_hdr + hdr_size);
	}

	line = http_hdr;
	line_size = (size_t)(pspace - line); /* REQ_SIZE */
	req_data->line_size = line_size;

	/* Method. */
	pspace = mem_chr(line, line_size, ' ');
	if (NULL == pspace)
		return (EBADMSG);
	req_data->method = line;
	req_data->method_size = (size_t)(pspace - line);
	req_data->method_code = http_get_method_fast(line, (size_t)(pspace - line));

	/* Request-URI. */
	skip_spwsp(pspace, (size_t)(line_size - (size_t)(pspace - line)), &ptm, NULL);
	pspace = mem_chr_ptr(ptm, line, line_size, ' ');
	if (NULL == pspace)
		return (EBADMSG);
	req_data->uri = ptm; /* Request-URI. */
	req_data->uri_size = (size_t)(pspace - req_data->uri); /* Request-URI SIZE. */
	/* URI parsing. */
	/* The authority form is only used by the CONNECT method. */
	if (HTTP_REQ_METHOD_CONNECT == req_data->method_code) { /* authority = host[:port] */
		req_data->host = req_data->uri;
		req_data->host_size = req_data->uri_size;
	} else {
		/* scheme, host, port */
		ptm = mem_find_cstr(req_data->uri, req_data->uri_size, "://");
		if (NULL != ptm) { /* scheme */
			req_data->scheme = req_data->uri;
			req_data->scheme_size = (size_t)(ptm - req_data->scheme);
			/* host & port */
			req_data->host = (ptm + 3);
			ptm = mem_chr_ptr(req_data->host,
			    req_data->uri, req_data->uri_size, '/');
			if (NULL == ptm) {
				ptm = pspace; // = (req_data->uri + req_data->uri_size);
			}
			req_data->host_size = (size_t)(ptm - req_data->host);
		} else {
			ptm = req_data->uri;
		}
		/* abs_path */
		/* Skip slash~s from head. */
		while (ptm < (pspace - 1) && '/' == ptm[1]) {
			ptm ++;
		}
		req_data->abs_path = ptm;
		ptm = mem_chr_ptr(req_data->abs_path,
		    req_data->uri, req_data->uri_size, '?');
		if (NULL == ptm) {
			/* Remove slash~s from tail. */
			ptm = (pspace - 1);
			while (req_data->abs_path < ptm && '/' == ptm[0]) {
				ptm --;
			}
			req_data->abs_path_size = (size_t)((ptm + 1) - req_data->abs_path);
		} else {
			req_data->abs_path_size = (size_t)(ptm - req_data->abs_path);
			req_data->query = (ptm + 1);
			req_data->query_size = (size_t)(pspace - req_data->query);
		}
	}

	/* HTTP-Version: HTTP/H.L */
	tm = 0;
	skip_spwsp(pspace, (size_t)(line_size - (size_t)(pspace - line)), &ptm, &tm);
	if (8 > tm ||
	    0 != memcmp("HTTP/", ptm, 5) ||
	    ('0' > ptm[5] || '9' < ptm[5]) ||
	    '.' != ptm[6] ||
	    ('0' > ptm[7] || '9' < ptm[7]))
		return (EBADMSG);
	req_data->proto_ver = MAKEDWORD((ptm[7] - '0'), (ptm[5] - '0'));

	return (0);
}


/*
 * Status-Line: HTTP-Version SP Status-Code SP Reason-Phrase CRLF 
 * HTTP/1.1 206 Partial Content
 */
int
http_parse_resp_line(const uint8_t *http_hdr, size_t hdr_size,
    http_resp_line_data_p resp_data) {
	const uint8_t *ptm;

	if (NULL == http_hdr || 14 > hdr_size || NULL == resp_data)
		return (EINVAL);
	if (0 != memcmp("HTTP/", http_hdr, 5) ||
	    ('0' > http_hdr[ 5] || '9' < http_hdr[ 5]) ||
	    '.' != http_hdr[ 6] ||
	    ('0' > http_hdr[ 7] || '9' < http_hdr[ 7]) ||
	    ' ' != http_hdr[ 8] ||
	    ('0' > http_hdr[ 9] || '9' < http_hdr[ 9]) ||
	    ('0' > http_hdr[10] || '9' < http_hdr[10]) ||
	    ('0' > http_hdr[11] || '9' < http_hdr[11]) ||
	    ' ' != http_hdr[12])
		return (EBADMSG);

	ptm = mem_find_cstr(http_hdr, hdr_size, CRLF);
	if (NULL == ptm) {
		ptm = (http_hdr + hdr_size);
	}
	resp_data->line_size = (size_t)(ptm - http_hdr); /* RESP_SIZE */;
	/* HTTP/H.L */
	resp_data->proto_ver = MAKEDWORD((http_hdr[7] - '0'), (http_hdr[5] - '0'));
	/* Status-Code. */
	resp_data->status_code = UStr8ToUNum32((http_hdr + 9), 3);
	/* Reason-Phrase. */
	resp_data->reason_phrase = (http_hdr + 13);
	resp_data->reason_phrase_size = (size_t)(resp_data->line_size - 13);

	return (0);
}

int
skip_spwsp(const uint8_t *buf, size_t buf_size,
    const uint8_t **buf_ret, size_t *buf_size_ret) {
	const uint8_t *buf_max;

	if (NULL == buf && 0 != buf_size)
		return (EINVAL);
	buf_max = (buf + buf_size);
	/* Skip head spaces. */
	for (; 33 > (*buf) && buf < buf_max; buf ++)
		;
	if (NULL != buf_ret) {
		(*buf_ret) = buf;
	}
	if (NULL != buf_size_ret) {
		(*buf_size_ret) = (size_t)(buf_max - buf);
	}
	return (0);
}
int
skip_spwsp2(const uint8_t *buf, size_t buf_size,
    const uint8_t **buf_ret, size_t *buf_size_ret) {
	const uint8_t *buf_max;

	if (NULL == buf && 0 != buf_size)
		return (EINVAL);
	buf_max = (buf + buf_size - 1);
	if (NULL != buf_ret) {
		/* Skip head spaces. */
		for (; 33 > (*buf) && buf <= buf_max; buf ++)
			;
		(*buf_ret) = buf;
	}
	if (NULL != buf_size_ret) {
		/* Skip tail spaces. */
		for (; 33 > (*buf_max) && buf <= buf_max; buf_max --)
			;
		(*buf_size_ret) = (size_t)((buf_max + 1) - buf);
	}
	return (0);
}


/* WSP->SP */
/* LWS = [CRLF] 1*( SP | HT ) */
int
wsp2sp(uint8_t *buf, size_t buf_size,
    uint8_t *ret_buf, size_t *buf_size_ret) {
	uint8_t *cur_rd_pos, *c_pos, *cur_wr_pos;
	size_t copy_size, ret_size;

	if (NULL == buf || 0 == buf_size || NULL == ret_buf)
		return (EINVAL);
	c_pos = buf;
	cur_rd_pos = buf;
	cur_wr_pos = ret_buf;
	ret_size = 0;
	for (;;) {
		c_pos = mem_find_ptr_cstr(c_pos, buf, (buf_size - 1), CRLF);
		if (NULL == c_pos) {
			copy_size = (size_t)((buf + buf_size) - cur_rd_pos);
			ret_size += copy_size;
			memmove(cur_wr_pos, cur_rd_pos, copy_size);
			break;
		}
		c_pos += 2;
		/* LWS: <US-ASCII HT, horizontal-tab (9)> ||
		 * <US-ASCII SP, space (32)> */
		if ('\t' == (*c_pos) ||
		    ' ' == (*c_pos)) {
			copy_size = (size_t)((c_pos - 2) - cur_rd_pos);
			c_pos ++;

			ret_size += (copy_size + 1);
			memmove(cur_wr_pos, cur_rd_pos, copy_size);
			cur_wr_pos += copy_size;
			cur_wr_pos[0] = ' '; /* SPace */
			cur_wr_pos ++;
			cur_rd_pos = c_pos;
		}
	}
	if (NULL != buf_size_ret) {
		(*buf_size_ret) = ret_size;
	}
	return (0);
}


/* Replace: HT->SP */
int
ht2sp(uint8_t *buf, size_t buf_size,
    uint8_t *ret_buf, size_t *buf_size_ret) {
	uint8_t *c_pos;

	if (NULL == buf || 0 == buf_size || NULL == ret_buf)
		return (EINVAL);
	if (buf != ret_buf) {
		memmove(ret_buf, buf, buf_size);
	}
	if (NULL != buf_size_ret) {
		(*buf_size_ret) = buf_size;
	}
	c_pos = buf;
	for (;;) {
		c_pos = mem_chr_ptr(c_pos, buf, buf_size, '\t'); /* TAB */
		if (NULL == c_pos)
			break;
		(*c_pos) = ' '; /* SPace */
		c_pos ++;
	}
	return (0);
}


int
http_hdr_val_get_ex(const uint8_t *http_hdr, size_t hdr_size,
    const uint8_t *val_name, size_t val_name_size, size_t offset,
    const uint8_t **val_ret, size_t *val_ret_size, size_t *offset_next) {
	const uint8_t *http_hdr_end, *name, *val, *separator;

	if ((NULL == http_hdr && 0 != hdr_size) ||
	    (NULL == val_name && 0 != val_name_size))
		return (EINVAL);
	/* Skip first line with request/responce / offset=prev fields. */
	name = mem_find_off_cstr(offset, http_hdr, hdr_size, CRLF);
	http_hdr_end = (http_hdr + hdr_size);
	for (; NULL != name; name = separator) {
		name += 2; /* 2 = separator=CRLF skip. */
		/* ':' - after value name. */
		val = mem_chr_ptr(name, http_hdr, hdr_size, ':');
		if (NULL == val)
			return (ESPIPE);
		val ++; /* Move ptr from ':' to first value byte. */
		/* Search for value end / next field name start,
		 * skip all LWS = [CRLF] 1*( SP | HT )	*/
		for (separator = val;; separator += 2) {
			separator = mem_find_ptr_cstr(separator, http_hdr,
			    hdr_size, CRLF);
			if (NULL == separator) {
				separator = http_hdr_end;
				break;
			}
			if ((separator + 2) >= http_hdr_end)
				break;
			if ('\t' == (*(separator + 2)) ||
			    ' ' == (*(separator + 2)))
				continue;
			break;
		}
		/* Compare val_name and data beetween [CRLF] and ':' */
		if (0 != mem_cmpin(name, (size_t)((val - name) - 1),
		    val_name, val_name_size))
			continue;
		/* Found! */
		skip_spwsp2(val, (size_t)(separator - val), val_ret, val_ret_size);
		if (NULL != offset_next) {
			(*offset_next) = (size_t)(separator - http_hdr);
		}
		return (0);
	}
	return (ESPIPE);
}

int
http_hdr_val_get(const uint8_t *http_hdr, size_t hdr_size,
    const uint8_t *val_name, size_t val_name_size,
    const uint8_t **val_ret, size_t *val_ret_size) {

	return (http_hdr_val_get_ex(http_hdr, hdr_size,
	    val_name, val_name_size, 0, val_ret, val_ret_size, NULL));
}


size_t
http_hdr_val_get_count(const uint8_t *http_hdr, size_t hdr_size,
    const uint8_t *val_name, size_t val_name_size) {
	size_t offset = 0, ret = 0;

	while (0 == http_hdr_val_get_ex(http_hdr, hdr_size,
	    val_name, val_name_size, offset, NULL, NULL, &offset)) {
		ret ++;/* Found! */
	}
	return (ret);
}


size_t 
http_hdr_val_remove(uint8_t *http_hdr, uint8_t *hdr_lcase, size_t hdr_size,
    size_t *phdr_size, const uint8_t *val_name, size_t val_name_size) {
	uint8_t *val, *val_end, *hdr_lcase_end;
	size_t val_size;
	size_t ret = 0;

	if (NULL == http_hdr || NULL == hdr_lcase || 0 == hdr_size ||
	    NULL == val_name || 0 == val_name_size)
		return (0);
	val = hdr_lcase;
	hdr_lcase_end = (hdr_lcase + hdr_size);
	for (;;) {
		val = mem_find_ptr(val, hdr_lcase, hdr_size, val_name, val_name_size);
		if (NULL == val)
			break;
		if (':' == (*((uint8_t*)(val + val_name_size))) &&
		    (val == hdr_lcase || ((val > (hdr_lcase + 2)) &&
		    0 == memcmp(CRLF, (val - 2), 2)))) {
			ret ++;
			val_end = mem_find_ptr_cstr((val + val_name_size + 1),
			    hdr_lcase, hdr_size, CRLF);
			if (NULL != val_end) {
				val_end += 2;
			} else {
				val_end = mem_chr_ptr((val + val_name_size + 1),
				    hdr_lcase, hdr_size, '\n'); /* LF */
				if (NULL != val_end) {
					val_end ++;
				} else {
					val_end = hdr_lcase_end;
					if (val > (hdr_lcase + 2) &&
					    0 == memcmp(CRLF, (val - 2), 2)) {
						val -= 2; /* Remove CRLF at the end. */
					}
				}
			}
			val_size = (size_t)(val_end - val);

			memmove(val, (val + val_size), (size_t)(hdr_lcase_end - val_end));
			if (NULL != http_hdr) {
				memmove((http_hdr + (val - hdr_lcase)),
				    ((http_hdr + (val - hdr_lcase)) + val_size),
				    (size_t)(hdr_lcase_end - val_end));
			}
			hdr_lcase_end -= val_size;
			hdr_size -= val_size;
		} else {
			val ++;
		}
	}
	if (NULL != phdr_size) {
		(*phdr_size) = hdr_size;
	}
	return (ret);
}

size_t
http_hdr_vals_remove(uint8_t *http_hdr, uint8_t *hdr_lcase, size_t hdr_size,
    size_t *phdr_size, size_t vals_count, const uint8_t **pvals_name,
    size_t *pvals_name_size) {
	size_t ret = 0, i;

	if (NULL == http_hdr || NULL == hdr_lcase || 0 == hdr_size ||
	    0 == vals_count || NULL == pvals_name || NULL == pvals_name_size)
		return (0);
	for (i = 0; i < vals_count; i ++) {
		ret += http_hdr_val_remove(http_hdr, hdr_lcase, hdr_size,
		    &hdr_size, pvals_name[i], pvals_name_size[i]);
	}
	if (NULL != phdr_size) {
		(*phdr_size) = hdr_size;
	}
	return (ret);
}


/* Get: [&]val_name=val[&] */
int
http_query_val_get_ex(const uint8_t *query, size_t query_size,
    const uint8_t *val_name, size_t val_name_size,
    const uint8_t **val_name_ret, const uint8_t **val_ret, size_t *val_ret_size) {
	const uint8_t *val, *val_end, *query_max;

	if ((NULL == query && 0 != query_size) ||
	    (NULL == val_name && 0 != val_name_size))
		return (EINVAL);
	val = query;
	query_max = (query + query_size);
	while (query_max > val && '&' == (*val)) {
		val ++; /* Skip '&' in buf start. */
	}
	for (;;) {
		val_end = mem_chr_ptr((val + 1), query, query_size, '=');
		if (NULL == val_end)
			return (ESPIPE);
		/* Compare val_name and data beetween ['&'] and '=' */
		if (0 == mem_cmpin(val, (size_t)(val_end - val),
		    val_name, val_name_size)) {
			/* Found! */
			if (NULL != val_name_ret) {
				(*val_name_ret) = val;
			}
			val = (val_end + 1);
			val_end = mem_chr_ptr(val, query, query_size, '&');
			if (NULL == val_end) {
				val_end = query_max;
			}
			if (NULL != val_ret) {
				(*val_ret) = val;
			}
			if (NULL != val_ret_size) {
				(*val_ret_size) = (size_t)(val_end - val);
			}
			return (0);
		}
		val = mem_chr_ptr(val_end, query, query_size, '&');
		if (NULL == val)
			return (ESPIPE);
		while (query_max > val && '&' == (*val)) {
			val ++;
		}
	}
	return (ESPIPE);
}

int
http_query_val_get(const uint8_t *query, size_t query_size,
    const uint8_t *val_name, size_t val_name_size,
    const uint8_t **val_ret, size_t *val_ret_size) {

	return (http_query_val_get_ex(query, query_size, val_name,
	    val_name_size, NULL, val_ret, val_ret_size));
}

size_t
http_query_val_del(uint8_t *query, size_t query_size, const uint8_t *val_name,
    size_t val_name_size, size_t *query_size_ret) {
	const uint8_t *val_data, *val_data_end, *query_max, *val_name_pos;
	size_t val_data_size;
	size_t del_cnt = 0;

	while (0 == http_query_val_get_ex(query, query_size, val_name,
	    val_name_size, &val_name_pos, &val_data, &val_data_size)) {
		query_max = (query + query_size);
		val_data_end = (val_data + val_data_size);
		/* Move to buf start (remove all '&' before value name). */
		while (val_name_pos > query && '&' == (*(val_name_pos - 1))) {
			val_name_pos --;
		}
		/* Move to buf end (remove all '&' after value data). */
		while (query_max > val_data_end && '&' == (*val_data_end)) {
			val_data_end ++;
		}
		/* Copy '&' after value data if remove not from buf start / end. */
		if (val_name_pos != query &&
		    query_max != val_data_end) {
			val_data_end --; /* Safe '&' */
		}
		/* Move all data after value data to value name start. */
		memmove(MK_RW_PTR(val_name_pos), val_data_end,
		    (size_t)(query_max - val_data_end));
		/* val_data_end - val_name_pos = val_name_size + 1 + val_data_size */
		query_size -= (size_t)(val_data_end - val_name_pos);
		del_cnt ++;
	}
	if (NULL != query_size_ret) {
		(*query_size_ret) = query_size;
	}
	return (del_cnt);
}

/* 
 * HexNumCRLF
 * dataCRLF
 * HexNum
 */
int
http_data_decode_chunked(uint8_t *data, size_t data_size,
    uint8_t **data_ret, size_t *data_ret_size) {
	uint8_t *cur_pos, *end_line, *max_pos;
	uint8_t *cur_wr_pos;
	size_t ret_size, tm;

	cur_pos = data;
	max_pos = (data + data_size);
	ret_size = 0;
	cur_wr_pos = NULL;
	for (;;) {
		end_line = mem_find_ptr_cstr(cur_pos, data, data_size, CRLF);
		if (NULL == end_line) {
			end_line = (data + data_size);
			if (0 != UStr8HexToUNum(cur_pos, (size_t)(max_pos - cur_pos)))
				return (EINVAL);
			break; /* Normal exit. */
		}
		tm = UStr8HexToUNum(cur_pos, (size_t)(end_line - cur_pos));
		if (0 == tm)
			break; /* Normal exit. */
		cur_pos = (end_line + 2 + tm);
		ret_size += tm;
		if (cur_pos > max_pos)
			return (EINVAL); /* Out of buf range. */
		/* No copy/move for first chunk, just change pointer. */
		if (NULL == cur_wr_pos) {
			(*data_ret) = (end_line + 2);
			cur_wr_pos = cur_pos; /* Next chunk will be after first. */
			continue;
		}
		memmove(cur_wr_pos, (end_line + 2), tm); /* Move data in buffer. */
		cur_wr_pos += tm;
	}
	(*data_ret_size) = ret_size;
	return (0);
}

#if 0
size_t
http_url_encode(int enc_all, uint8_t *url, size_t url_size, uint8_t *buf,
    size_t buf_size) {
	uint8_t val, *url_max = (url + url_size);
	uint8_t *buf_pos = buf, *buf_max = (buf + (buf_size - 4));

	if (NULL == url || 0 == url_size || NULL == buf ||
	    4 > buf_size)
		return (0);

	if (0 != enc_all) {
		for (; url < url_max && buf_pos < buf_max; url ++) {
			snprintf(buf_pos, 4, "%%%02x", (*url));
			buf_pos += 3;
		}
		return ((buf_pos - buf));
	}
	for (; url < url_max && buf_pos < buf_max; url ++) {
		val = (*url);
		if ((val >= 'A' && val <= 'Z') || (val >= 'a' && val <= 'z') ||
		    (val >= '0' && val <= '9') ||
		    val == '-' || val == '_' || val == '.' || val == '~') {
			(*buf_pos) = val;
			buf_pos ++;
		} else {
			snprintf(buf_pos, 4, "%%%02x", val);
			buf_pos += 3;
		}
	}
	(*buf_pos) = 0;
	return ((buf_pos - buf));
}
#endif
