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


#ifndef __CORE_HTTP_SERVER_H__
#define __CORE_HTTP_SERVER_H__

#include <sys/types.h>
#include <sys/socket.h>

#include "HTTP.h"

#include "macro_helpers.h"
#include "core_thrp.h"
#include "core_io_task.h"
#include "core_io_buf.h"
#include "core_hostname.h"
#include "core_io_net.h"


#define HTTP_SRV_MAX_CUSTOM_HDRS_CNT	((IOV_MAX / 2) - 4) /* Limit for http_srv_snd() */


typedef struct http_srv_s		*http_srv_p;
typedef struct http_srv_bind_s		*http_srv_bind_p;
typedef struct http_srv_req_s		*http_srv_req_p;
typedef struct http_srv_responce_s	*http_srv_resp_p;
typedef struct http_srv_cli_s		*http_srv_cli_p;


typedef int (*http_srv_on_req_rcv_cb)(http_srv_cli_p cli, void *udata, http_srv_req_p req, http_srv_resp_p resp);
/* Called after HTTP request received, and data after POST request.
 * Return values
 * HTTP_SRV_CB_DESTROY - disconnect/drop client.
 * HTTP_SRV_CB_CONTINUE - send responce based on resp, process next request/http_srv_cli_free()
 * HTTP_SRV_CB_NONE - do nothing, you must call later: http_srv_resume_responce() / http_srv_cli_free() later, not in this call back.
 */

typedef int (*http_srv_on_resp_snd_cb)(http_srv_cli_p cli, void *udata, http_srv_resp_p resp);
/* Called after HTTP responce sended.
 * Return values
 * HTTP_SRV_CB_DESTROY - disconnect/drop client.
 * HTTP_SRV_CB_CONTINUE - process next request/http_srv_cli_free():  if
 * client not half closed and no "connection: close" then try receive
 * and handle next request.
 * HTTP_SRV_CB_NONE - do nothing, you must call later: http_srv_resume_next_request() / http_srv_cli_free() later, not in this call back.
 */
#define HTTP_SRV_CB_DESTROY	-2 /* Call http_srv_cli_free() except: returned from http_srv_on_conn_cb function. */
#define HTTP_SRV_CB_CONTINUE	-1 /* Continue requests processing. */
#define HTTP_SRV_CB_NONE	0 /* Stop client processing. This may need if some IO tasks must be processed before continue with client. */

typedef void (*http_srv_on_destroy_cb)(http_srv_cli_p cli, void *udata, http_srv_resp_p resp);

typedef struct http_srv_cli_callbacks_s {
	http_srv_on_req_rcv_cb	on_req_rcv; /* Client request received callback */
	http_srv_on_resp_snd_cb	on_rep_snd; /* Responce sended to client callback */
	http_srv_on_destroy_cb	on_destroy; /* Client destroyed callback */
} http_srv_cli_ccb_t, *http_srv_cli_ccb_p;


typedef int (*http_srv_on_conn_cb)(http_srv_bind_p bnd, void *srv_udata,
    uintptr_t skt, struct sockaddr_storage *addr, thrpt_p *thrpt,
    http_srv_cli_ccb_p ccb, void **udata);
/* Called after HTTP request received, and data after POST request.
 * Return values
 * HTTP_SRV_CB_DESTROY - disconnect/drop client and continue receiving new connections.
 * HTTP_SRV_CB_CONTINUE - allocate resources and receive data from client.
 * HTTP_SRV_CB_NONE - forget about socket and receive next connection.
 */




typedef struct http_srv_stat_s {
	volatile uint64_t	connections;
	volatile uint64_t	timeouts;
	volatile uint64_t	errors;
	volatile uint64_t	http_errors;
	volatile uint64_t	insecure_requests;
	volatile uint64_t	unhandled_requests;
	volatile uint64_t	requests[HTTP_REQ_METHOD__COUNT__];
	volatile uint64_t	requests_total;
	time_t			start_time;
	time_t			start_time_abs;
} http_srv_stat_t, *http_srv_stat_p;


typedef struct http_srv_settings_s { /* Settings */
	skt_opts_t	skt_opts;
	size_t		rcv_io_buf_init_size;	/* kb */
	size_t		rcv_io_buf_max_size;	/* kb, max request size (with data). */
	size_t		snd_io_buf_init_size;	/* kb, no hard limit */
	size_t		hdrs_reserve_size;	/* kb - !!! all standart and custom hdrs size */
	uint32_t	req_p_flags;	/* Request processing flags HTTP_SRV_RQ_P_F_*. */
	uint32_t	resp_p_flags;	/* Responce processing flags HTTP_SRV_RESP_P_F_*. */
	size_t		http_server_size; /* 'OS/version UPnP/1.0 product/version' */
	char		http_server[256]; /* 'OS/version UPnP/1.0 product/version' */
	hostname_list_p hst_name_lst;	/* List of host names on this server. */
} http_srv_settings_t, *http_srv_settings_p;
#define HTTP_SRV_S_SKT_OPTS_LOAD_MASK	(SO_F_BACKLOG |			\
					SO_F_KEEPALIVE_MASK |		\
					SO_F_RCVBUF |			\
					SO_F_RCVTIMEO |			\
					SO_F_SNDBUF |			\
					SO_F_SNDTIMEO |			\
					SO_F_TCP_CONGESTION)
#define HTTP_SRV_S_SKT_OPTS_INT_MASK	(SO_F_REUSEADDR |		\
					SO_F_REUSEPORT |		\
					SO_F_ACC_FILTER)
#define HTTP_SRV_S_SKT_OPTS_INT_VALS	HTTP_SRV_S_SKT_OPTS_INT_MASK
#define HTTP_SRV_S_SKT_OPTS_ACC_FILTER_NAME	"httpready"
#define HTTP_SRV_S_SKT_OPTS_ACC_FILTER_DEFER	(4)

/* Request processing flags. */
#define HTTP_SRV_REQ_P_F_CONNECTION	(((uint32_t)1) <<  0) /* process 'connection' header value. */
#define HTTP_SRV_REQ_P_F_HOST		(((uint32_t)1) <<  1) /* process 'host' header value. */
/* Responce processing flags. */
#define HTTP_SRV_RESP_P_F_CONN_CLOSE	(((uint32_t)1) <<  0) /* force 'Connection: close', use single IO_BUF for send and recv. */
#define HTTP_SRV_RESP_P_F_SERVER	(((uint32_t)1) <<  1) /* add 'Server' in answer. */
#define HTTP_SRV_RESP_P_F_CONTENT_LEN	(((uint32_t)1) <<  2) /* add 'Content-Length' in answer. */
#define HTTP_SRV_RESP_P_F_GEN_ERR_PAGES	(((uint32_t)1) << 31) /* Automatic generates error pages on 400 <= status_code < 600, ignory data and hdrs. */

/* Default values. */
#define HTTP_SRV_S_DEF_SKT_OPTS_MASK	(SO_F_RCVTIMEO | SO_F_SNDTIMEO) /* Opts that have def values. */
#define HTTP_SRV_S_DEF_SKT_OPTS_VALS	(0)
#define HTTP_SRV_S_DEF_SKT_OPTS_RCVTIMEO (30)
#define HTTP_SRV_S_DEF_SKT_OPTS_SNDTIMEO (30)
#define HTTP_SRV_S_DEF_RCV_IO_BUF_INIT	(4)
#define HTTP_SRV_S_DEF_RCV_IO_BUF_MAX	(64)
#define HTTP_SRV_S_DEF_SND_IO_BUF_INIT	(4)
#define HTTP_SRV_S_DEF_HDRS_SIZE	(1)
#define HTTP_SRV_S_DEF_RQ_P_FLAGS	(0)
#define HTTP_SRV_S_DEF_RESP_P_FLAGS	(HTTP_SRV_RESP_P_F_CONN_CLOSE | HTTP_SRV_RESP_P_F_SERVER | HTTP_SRV_RESP_P_F_CONTENT_LEN)

typedef struct http_srv_bind_settings_s {
	struct sockaddr_storage addr;	/* Bind address. */
	skt_opts_t	skt_opts;
	hostname_list_p	hst_name_lst;	/* List of host names on this bind. */
} http_srv_bind_settings_t, *http_srv_bind_settings_p;



/* http_URL = "http:" "//" host [ ":" port ] [ abs_path [ "?" query ]] */
typedef struct http_srv_req_s {
	const uint8_t	*hdr;		/* Header. */
	size_t		hdr_size;	/* Header size. */
	size_t		size;		/* Request size: header size + 4 + data size. */
	http_req_line_data_t line;	/* First request line. */
	const uint8_t	*data;		/* After CRLFCRLF. */
	size_t		data_size;	/* content-length */
	const uint8_t	*host;		/* From headers. */
	size_t		host_size;
	uint32_t	flags;		/* Flags */
} http_srv_req_t;
#define HTTP_SRV_RD_F_CONN_CLOSE	(((uint32_t)1) << 0) /* 'connection' header value is close or http 1.0 without connection: keep-alive. */
#define HTTP_SRV_RD_F_MORE_DATA_AVAIL	(((uint32_t)1) << 1) /* 'content-length' or 'transfer-encoding' set, data receiving not complete. */
#define HTTP_SRV_RD_F_HOST_IS_STR	(((uint32_t)1) << 2) /* 'host' header value is text/domain name. */
#define HTTP_SRV_RD_F_HOST_IS_LOCAL	(((uint32_t)1) << 3) /* 'host' header value point to this host. */


#define HTTP_SRV_RESP_HDS_MAX	16	/* Must be lower than HTTP_SRV_MAX_CUSTOM_HDRS_CNT. */
typedef struct http_srv_responce_s {
	uint32_t	status_code;	/* HTTP response status code. */
	uint32_t	p_flags;	/* Responce processing flags HTTP_SRV_RESP_P_F_*. */
	const char 	*reason_phrase;	/* HTTP response reason phrase. */
	size_t		reason_phrase_size;
	io_buf_p	buf;		/* Responce body buf. */
	size_t		hdrs_count;	 /* Custom headers count. */
	struct iovec 	hdrs[HTTP_SRV_RESP_HDS_MAX]; /* Custom headers. */
} http_srv_resp_t;



void	http_srv_def_settings(int add_os_ver, const char *app_ver, int add_lib_ver,
	    http_srv_settings_p s_ret);
void	http_srv_bind_def_settings(skt_opts_p skt_opts, http_srv_bind_settings_p s_ret);

#ifdef HTTP_SRV_XML_CONFIG
int	http_srv_xml_load_hostnames(const uint8_t *buf, size_t buf_size,
	    hostname_list_p hst_name_lst);
int	http_srv_xml_load_settings(const uint8_t *buf, size_t buf_size,
	    http_srv_settings_p s);
int	http_srv_xml_load_bind(const uint8_t *buf, size_t buf_size,
	    http_srv_bind_settings_p s);
int	http_srv_xml_load_start(const uint8_t *buf, size_t buf_size, thrp_p thrp,
	    http_srv_on_conn_cb on_conn, http_srv_cli_ccb_p ccb,
	    http_srv_settings_p srv_settings, void *udata,
	    http_srv_p *http_srv);
#endif

int	http_srv_create(thrp_p thrp,
	    http_srv_on_conn_cb on_conn, http_srv_cli_ccb_p ccb,
	    hostname_list_p hst_name_lst, http_srv_settings_p s, void *udata,
	    http_srv_p *srv_ret);
void	http_srv_shutdown(http_srv_p srv); /* Stop accept new clients. Optional. Allways call if radius auth used before destroy radius client. */
void	http_srv_destroy(http_srv_p srv);
size_t	http_srv_get_bind_count(http_srv_p srv);
int	http_srv_stat_get(http_srv_p srv, http_srv_stat_p stat);
thrp_p	http_srv_thrp_get(http_srv_p srv);
int	http_srv_thrp_set(http_srv_p srv, thrp_p thrp);
int	http_srv_on_conn_cb_set(http_srv_p srv, http_srv_on_conn_cb on_conn);
int	http_srv_ccb_get(http_srv_p srv, http_srv_cli_ccb_p ccb);
int	http_srv_ccb_set(http_srv_p srv, http_srv_cli_ccb_p ccb);
int	http_srv_on_destroy_cb_set(http_srv_p srv, http_srv_on_destroy_cb on_destroy);
int	http_srv_on_req_rcv_cb_set(http_srv_p srv, http_srv_on_req_rcv_cb on_req_rcv);
int	http_srv_on_rep_snd_cb_set(http_srv_p srv, http_srv_on_resp_snd_cb on_rep_snd);
void *	http_srv_get_udata(http_srv_p srv);
int	http_srv_set_udata(http_srv_p srv, void *udata);


int		http_srv_bind_add(http_srv_p srv, http_srv_bind_settings_p s,
		    hostname_list_p hst_name_lst, void *udata, http_srv_bind_p *acc_ret);
void		http_srv_bind_shutdown(http_srv_bind_p bnd);
void		http_srv_bind_remove(http_srv_bind_p bnd);
http_srv_p	http_srv_bind_get_srv(http_srv_bind_p bnd);
void *		http_srv_bind_get_udata(http_srv_bind_p bnd);
int		http_srv_bind_set_udata(http_srv_bind_p bnd, void *udata);
int		http_srv_bind_get_addr(http_srv_bind_p bnd, struct sockaddr_storage *addr);



void		http_srv_cli_free(http_srv_cli_p cli); /* Disconnect and free all resources. */

io_task_p	http_srv_cli_get_iotask(http_srv_cli_p cli);
io_task_p	http_srv_cli_export_iotask(http_srv_cli_p cli);
int		http_srv_cli_import_iotask(http_srv_cli_p cli,
		    io_task_p iotask, thrpt_p thrpt);

io_buf_p	http_srv_cli_get_buf(http_srv_cli_p cli);
/* Responce buffer management. */
int		http_srv_cli_buf_reset(http_srv_cli_p cli);
int		http_srv_cli_buf_realloc(http_srv_cli_p cli, int allow_decrease,
		    size_t new_size);
http_srv_bind_p	http_srv_cli_get_acc(http_srv_cli_p cli);
http_srv_p	http_srv_cli_get_srv(http_srv_cli_p cli);
http_srv_req_p	http_srv_cli_get_req(http_srv_cli_p cli);
http_srv_resp_p	http_srv_cli_get_resp(http_srv_cli_p cli);

int		http_srv_cli_ccb_get(http_srv_cli_p cli, http_srv_cli_ccb_p ccb);
int		http_srv_cli_ccb_set(http_srv_cli_p cli, http_srv_cli_ccb_p ccb);

http_srv_on_req_rcv_cb http_srv_cli_get_on_req_rcv(http_srv_cli_p cli);
int		http_srv_cli_set_on_req_rcv(http_srv_cli_p cli,
		    http_srv_on_req_rcv_cb on_req_rcv);

http_srv_on_resp_snd_cb http_srv_cli_get_on_rep_snd(http_srv_cli_p cli);
int		http_srv_cli_set_on_rep_snd(http_srv_cli_p cli,
		    http_srv_on_resp_snd_cb on_rep_snd);

http_srv_on_destroy_cb http_srv_cli_get_on_destroy(http_srv_cli_p cli);
int		http_srv_cli_set_on_destroy(http_srv_cli_p cli,
		    http_srv_on_destroy_cb on_destroy);

void *		http_srv_cli_get_udata(http_srv_cli_p cli);
int		http_srv_cli_set_udata(http_srv_cli_p cli, void *udata);

uint32_t	http_srv_cli_get_flags(http_srv_cli_p cli);
#define HTTP_SRV_CLI_F_HALF_CLOSED	(((uint32_t)1) << 0) /* Client call shutdown(, SHUT_WR) and can only receive data. */
#define HTTP_SRV_CLI_F_AUTHORIZED	(((uint32_t)1) << 1) /* . */

int		http_srv_cli_get_addr(http_srv_cli_p cli, struct sockaddr_storage *addr);


/* After cb function return HTTP_SRV_CB_NONE and some additional IO done,
 * to resume processing clint requests call one of these two functions.
 * If function return 0 - then do not any operations with cli and all
 * associated data.
 */
int		http_srv_resume_responce(http_srv_cli_p cli);
int		http_srv_resume_next_request(http_srv_cli_p cli);


#endif // __CORE_HTTP_SERVER_H__
