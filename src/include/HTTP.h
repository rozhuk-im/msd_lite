/*-
 * Copyright (c) 2010 - 2014 Rozhuk Ivan <rozhuk.im@gmail.com>
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


#ifndef __HTTP_H__
#define __HTTP_H__



#define LF		"\n"
#define LFLF		"\n\n"
#define CRLF		"\r\n"
#define CRLFCRLF	"\r\n\r\n"
#define LWSHT		"\r\n\t"
#define LWSSP		"\r\n "

#ifndef MAKEDWORD
#define MAKEDWORD(a, b)	((uint32_t)(((uint16_t)(((uint32_t)(a)) & 0xffff)) | ((uint32_t)((uint16_t)(((uint32_t)(b)) & 0xffff))) << 16))
#endif
#ifndef LOWORD
#define LOWORD(a)	((uint16_t)(((uint32_t)(a)) & 0xffff))
#endif
#ifndef HIWORD
#define HIWORD(a)	((uint16_t)((((uint32_t)(a)) >> 16) & 0xffff))
#endif

#define HTTP_VER_1_0	MAKEDWORD(0, 1)
#define HTTP_VER_1_1	MAKEDWORD(1, 1)

#define HTTP_PORT	80
#define HTTPS_PORT	443


static const uint8_t *HTTPReqMethod[] = {
	(uint8_t*)"OPTIONS",	// 9.2
	(uint8_t*)"GET",	// 9.3
	(uint8_t*)"HEAD",	// 9.4
	(uint8_t*)"POST",	// 9.5
	(uint8_t*)"PUT",	// 9.6
	(uint8_t*)"DELETE",	// 9.7
	(uint8_t*)"TRACE",	// 9.8
	(uint8_t*)"CONNECT",	// 9.9
	(uint8_t*)"NOTIFY",	// UPnP
	(uint8_t*)"M-SEARCH",	// UPnP
	(uint8_t*)"M-POST",	// UPnP
	(uint8_t*)"SUBSCRIBE",	// UPnP
	(uint8_t*)"UNSUBSCRIBE",// UPnP
	NULL
};

static const size_t HTTPReqMethodSize[] = {
	7,	//"OPTIONS",	// 9.2
	3,	//"GET",	// 9.3
	4,	//"HEAD",	// 9.4
	4,	//"POST",	// 9.5
	3,	//"PUT",	// 9.6
	6,	//"DELETE",	// 9.7
	5,	//"TRACE",	// 9.8
	7,	//"CONNECT"	// 9.9
	6,	//"NOTIFY"	// UPnP
	8,	//"M-SEARCH"	// UPnP
	6,	//"M-POST"	// UPnP
	9,	//"SUBSCRIBE"	// UPnP
	11,	//"UNSUBSCRIBE"	// UPnP
	0
};

#define HTTP_REQ_METHOD_OPTIONS		0
#define HTTP_REQ_METHOD_GET		1
#define HTTP_REQ_METHOD_HEAD		2
#define HTTP_REQ_METHOD_POST		3
#define HTTP_REQ_METHOD_PUT		4
#define HTTP_REQ_METHOD_DELETE		5
#define HTTP_REQ_METHOD_TRACE		6
#define HTTP_REQ_METHOD_CONNECT		7
#define HTTP_REQ_METHOD_NOTIFY		8
#define HTTP_REQ_METHOD_M_SEARCH	9
#define HTTP_REQ_METHOD_M_POST		10
#define HTTP_REQ_METHOD_SUBSCRIBE	11
#define HTTP_REQ_METHOD_UNSUBSCRIBE	12
#define HTTP_REQ_METHOD_UNKNOWN		13




const char *http_get_err_descr(uint32_t status_code, size_t *descr_size_ret);

int	http_get_method_fast(uint8_t *m, size_t m_size);

int	http_req_sec_chk(uint8_t *http_hdr, size_t hdr_size, uint32_t method_code);

typedef struct http_req_line_data_s {
	size_t		line_size;
	uint8_t		*method;	/* Point to line start, allways. */
	size_t		method_size;
	uint32_t	method_code;
	uint8_t		*uri;
	size_t		uri_size;
	/* uri content */
	uint8_t		*scheme;
	size_t		scheme_size;
	uint8_t		*host;
	size_t		host_size;
	uint8_t		*abs_path;
	size_t		abs_path_size;
	uint8_t		*query;
	size_t		query_size;
	/* uri content */
	uint32_t	proto_ver;
} http_req_line_data_t, *http_req_line_data_p;

int	http_parse_req_line(uint8_t *http_hdr, size_t hdr_size, uint32_t flags,
	    http_req_line_data_p req_data);

int	http_parse_resp_line(uint8_t *http_hdr, size_t hdr_size,
	    uint32_t *ver, uint32_t *status_code, uint8_t **reason_phrase,
	    size_t *reason_phrase_size);

int	skeep_spwsp(uint8_t* buf, size_t buf_size, uint8_t **buf_ret, size_t *buf_size_ret);
int	skeep_spwsp2(uint8_t* buf, size_t buf_size, uint8_t **buf_ret, size_t *buf_size_ret);
int	wsp2sp(uint8_t *buf, size_t buf_size, uint8_t *ret_buf, size_t *buf_size_ret);
int	ht2sp(uint8_t *buf, size_t buf_size, uint8_t *ret_buf, size_t *buf_size_ret);

int	http_hdr_val_get_ex(uint8_t *http_hdr, size_t hdr_size,
	    const uint8_t *val_name, size_t val_name_size, size_t offset,
	    uint8_t **val_ret, size_t *val_ret_size, size_t *offset_next);
int	http_hdr_val_get(uint8_t *http_hdr, size_t hdr_size,
	    const uint8_t *val_name, size_t val_name_size,
	    uint8_t **val_ret, size_t *val_ret_size);
size_t	http_hdr_val_get_count(uint8_t *http_hdr, size_t hdr_size,
	    const uint8_t *val_name, size_t val_name_size);
size_t	http_hdr_val_remove(uint8_t *http_hdr, uint8_t *hdr_lcase,
	    size_t hdr_size, size_t *phdr_size, const uint8_t *val_name,
	    size_t val_name_size);
size_t	http_hdr_vals_remove(uint8_t *http_hdr, uint8_t *hdr_lcase,
	    size_t hdr_size, size_t *phdr_size, size_t vals_count,
	    const uint8_t **pvals_name, size_t *pvals_name_size);

int	http_query_val_get_ex(uint8_t *query, size_t query_size,
	    const uint8_t *val_name, size_t val_name_size,
	    uint8_t **val_name_ret, uint8_t **val_ret, size_t *val_ret_size);
int	http_query_val_get(uint8_t *query, size_t query_size,
	    const uint8_t *val_name, size_t val_name_size,
	    uint8_t **val_ret, size_t *val_ret_size);
size_t	http_query_val_del(uint8_t *query, size_t query_size,
	    const uint8_t *val_name, size_t val_name_size, size_t *query_size_ret);

int	http_data_decode_chunked(uint8_t *data, size_t data_size, uint8_t **data_ret,
	    size_t *data_ret_size);


#endif /* __HTTP_H__ */
