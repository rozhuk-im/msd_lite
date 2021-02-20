/*-
 * Copyright (c) 2015 - 2016 Rozhuk Ivan <rozhuk.im@gmail.com>
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


#ifndef __CORE_HTTP_CLIENT_H__
#define __CORE_HTTP_CLIENT_H__

#include <sys/types.h>
#include <sys/socket.h>

#include "HTTP.h"

#include "macro_helpers.h"
#include "core_thrp.h"
#include "core_io_task.h"
#include "core_net_hostaddr.h"
#include "core_io_net.h"

#define HTTP_CLI_MAX_CUSTOM_HDRS_CNT	((IOV_MAX / 2) - 4) /* Limit for http_cli_snd() */



typedef struct http_client_s		*http_cli_p;
typedef struct http_client_connection_s	*http_cli_conn_p;
typedef struct http_client_responce_s	*http_cli_resp_p;


typedef int (*http_cli_cb)(http_cli_conn_p cli_conn, void *udata, int error);

#define HTTP_CLI_CONN_STATE_DISCONNECTED	0
#define HTTP_CLI_CONN_STATE_CONNECTING		1 /* Start connecting... */
#define HTTP_CLI_CONN_STATE_CONNECTED		2 /* Connected. */
#define HTTP_CLI_CONN_STATE_REQ_HDRS_SENDING	3
#define HTTP_CLI_CONN_STATE_REQ_HDRS_SENDED	4
#define HTTP_CLI_CONN_STATE_REQ_PAYLOAD_SENDING	5
#define HTTP_CLI_CONN_STATE_REQ_PAYLOAD_SENDED	6
#define HTTP_CLI_CONN_STATE_RESP_HDRS_RCVING	7
#define HTTP_CLI_CONN_STATE_RESP_HDRS_RECEIVED	8
#define HTTP_CLI_CONN_STATE_RESP_PAYLOAD_RCVING	9





typedef struct http_client_settings_s { /* Settings */
	http_cli_ccb_t	ccb;			/* Default client callbacks. */
	skt_opts_t	skt_opts;
	uint32_t	flags;			/* Flags HTTP_CLI_F_*. */
	size_t		hdrs_reserve_size;	/* kb - !!! all standart and custom hdrs size */
	size_t		snd_io_buf_init_size;	/* kb, no hard limit */
	size_t		rcv_io_buf_init_size;	/* kb */
	size_t		rcv_io_buf_max_size;	/* kb, max request size (with data). */
	uint32_t	req_p_flags;		/* Request processing flags HTTP_CLI_RQ_P_F_*. */
	uint32_t	resp_p_flags;		/* Responce processing flags HTTP_CLI_RESP_P_F_*. */
	uint32_t	http_user_agent_size;	/* 'OS/version UPnP/1.0 product/version' */
	char		http_user_agent[256];	/* 'OS/version UPnP/1.0 product/version' */
} http_cli_settings_t, *http_cli_settings_p;
/* Flags. */
#define HTTP_CLI_F_EXT_TIMEOUT_CHK	(((uint32_t)1) << 0) /* Do not activate per
						  * handle timeout timer,
						  * external code will
						  * call http_cli_conn_timeout_chk(). */

#define HTTP_CLI_S_SKT_OPTS_LOAD_MASK	(SO_F_HALFCLOSE_WR |		\
					SO_F_KEEPALIVE_MASK |		\
					SO_F_RCV_MASK |			\
					SO_F_SND_MASK |			\
					SO_F_TCP_NODELAY)
#define HTTP_CLI_S_SKT_OPTS_INT_MASK	(0)
#define HTTP_CLI_S_SKT_OPTS_INT_VALS	(0)

/* Request processing flags. */
#define HTTP_CLI_REQ_P_F_HOST		(((uint32_t)1) << 0) /* add 'host' header. */
#define HTTP_CLI_REQ_P_F_CONN_CLOSE	(((uint32_t)1) << 1) /* force 'Connection: close', use single IO_BUF for send and recv. */
#define HTTP_CLI_REQ_P_F_USER_AGENT	(((uint32_t)1) << 2) /* add 'User-Agent' in request. */
#define HTTP_CLI_REQ_P_F_CONTENT_LEN	(((uint32_t)1) << 3) /* add 'Content-Length' in request. */
/* Responce processing flags. */
#define HTTP_CLI_RESP_P_F_CONNECTION	(((uint32_t)1) << 0) /* process 'connection' header value. */

/* Default values. */
#define HTTP_CLI_S_DEF_SKT_OPTS_MASK	(SO_F_RCVTIMEO | SO_F_SNDTIMEO) /* Opts that have def values. */
#define HTTP_CLI_S_DEF_SKT_OPTS_VALS	(0)
#define HTTP_CLI_S_DEF_SKT_OPTS_RCVTIMEO (30)
#define HTTP_CLI_S_DEF_SKT_OPTS_SNDTIMEO (30)
#define HTTP_CLI_S_DEF_HDRS_SIZE	(1)
#define HTTP_CLI_S_DEF_SND_IO_BUF_INIT	(4)
#define HTTP_CLI_S_DEF_RCV_IO_BUF_INIT	(4)
#define HTTP_CLI_S_DEF_RCV_IO_BUF_MAX	(128)
#define HTTP_CLI_S_DEF_REQ_P_FLAGS	(HTTP_CLI_REQ_P_F_USER_AGENT | HTTP_CLI_REQ_P_F_CONTENT_LEN
#define HTTP_CLI_S_DEF_RESP_P_FLAGS	(0)




typedef struct http_client_responce_s {
	uint8_t		*hdr;
	size_t		hdr_size;
	http_resp_line_data_t line;	/* First responce line. */
	uint8_t		*data;		/* After CRLFCRLF. */
	size_t		data_size;	/* content-length */
	uint32_t	flags;		/* Flags */
} http_cli_resp_t;
#define HTTP_CLI_RD_F_CONN_CLOSE	(((uint32_t)1) << 0) /* 'connection' header value is close or http 1.0 without connection: keep-alive. */
#define HTTP_CLI_RD_F_MORE_DATA_AVAIL	(((uint32_t)1) << 1) /* 'content-length' or 'transfer-encoding' set, data receiving not complete. */
#define HTTP_CLI_RD_F_TE_CHUNK		(((uint32_t)1) << 2) /* 'host' header value is text/domain name. */



void	http_cli_def_settings(int add_os_ver, const char *app_ver, int add_lib_ver,
	    http_cli_settings_p s_ret);

int	http_cli_create(http_cli_cb ccb, http_cli_settings_p s,
	    void *udata, http_cli_p *cli_ret);
void	http_cli_destroy(http_cli_p cli);
int	http_cli_ccb_get(http_cli_p cli, http_cli_cb *ccb);
int	http_cli_ccb_set(http_cli_p cli, http_cli_cb ccb);
void *	http_cli_get_udata(http_cli_p cli);
int	http_cli_set_udata(http_cli_p cli, void *udata);


int	http_cli_conn_create(http_cli_p cli, thrpt_p thrpt,
	    http_cli_cb ccb, void *udata, http_cli_conn_p *cli_conn);
void	http_cli_conn_free(http_cli_conn_p cli_conn); /* Disconnect and free resources. */

void	http_cli_conn_timeout_chk(http_cli_conn_p cli_conn);


/* Set remonte hostname / addr to connect. */
int	http_cli_conn_host_addr_set_str(http_cli_conn_p cli_conn,
	    uint8_t *host_name, size_t host_name_size);
int	http_cli_conn_host_addr_set_ss(http_cli_conn_p cli_conn,
	    struct sockaddr_storage *addr);
int	http_cli_conn_host_addr_set_ha(http_cli_conn_p cli_conn,
	    host_addr_p haddr);

/* Set connected to remonte host socket. */
/* flags - io task flags: IO_TASK_F_CLOSE_ON_DESTROY */
int	http_cli_conn_skt_set(http_cli_conn_p cli_conn, uint32_t flags,
	    uintptr_t ident);
io_task_p http_cli_conn_get_iotask(http_cli_conn_p cli_conn);
io_task_p http_cli_conn_export_iotask(http_cli_conn_p cli_conn);
int	http_cli_conn_io_task_set(http_cli_conn_p cli_conn, uint32_t flags,
	    io_task_p iotask);


int	http_cli_conn_req_head_set(http_cli_conn_p cli_conn, uint32_t req_p_flags,
	    uint8_t *method, size_t method_size, uint32_t method_code,
	    uint8_t *uri, size_t uri_size, uint32_t http_ver,
	    uint64_t content_len, uint32_t transfer_encoding_code,
	    struct iovec *custom_hdrs, size_t custom_hdrs_count);

int	http_cli_conn_req_payload_set(http_cli_conn_p cli_conn,
	    uint32_t req_p_flags, uint8_t *payload, size_t payload_size);

int	http_cli_conn_req_send(http_cli_conn_p cli_conn);



io_buf_p	http_cli_get_buf(http_cli_p cli);
/* Responce buffer management. */
int		http_cli_buf_reset(http_cli_p cli);
int		http_cli_buf_realloc(http_cli_p cli, int allow_decrease,
		    size_t new_size);


uint32_t	http_cli_get_flags(http_cli_p cli);
#define HTTP_CLI_CONN_F_HALF_CLOSED	(((uint32_t)1) << 0) /* Client call shutdown(, SHUT_WR) and can only receive data. */
#define HTTP_CLI_CONN_F_AUTHORIZED	(((uint32_t)1) << 1) /* . */

uint32_t	http_cli_get_resp_p_flags(http_cli_p cli);
uint32_t	http_cli_add_resp_p_flags(http_cli_p cli, uint32_t resp_p_flags);
uint32_t	http_cli_del_resp_p_flags(http_cli_p cli, uint32_t resp_p_flags);
void		http_cli_set_resp_p_flags(http_cli_p cli, uint32_t resp_p_flags);




#endif // __CORE_HTTP_CLIENT_H__
