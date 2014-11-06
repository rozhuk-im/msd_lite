/*-
 * Copyright (c) 2011 - 2014 Rozhuk Ivan <rozhuk.im@gmail.com>
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

#include "core_macro.h"
#include "core_thrp.h"
#include "core_io_task.h"
#include "core_hostname.h"
#include "core_net_helpers.h"
#include "core_radius_cli.h"

#define HTTP_SRV_MAX_CUSTOM_HDRS_CNT	((IOV_MAX / 2) - 4) /* Limit for http_srv_snd() */



typedef struct http_srv_s	*http_srv_p;
typedef struct http_srv_acc_s	*http_srv_acc_p;
typedef struct http_srv_req_s	*http_srv_req_p;
typedef struct http_srv_cli_s	*http_srv_cli_p;


typedef int (*http_srv_on_conn_cb)(http_srv_acc_p acc, void *acc_udata, uintptr_t skt,
    struct sockaddr_storage *addr, thrpt_p *thrpt, void **udata);
/* Called after HTTP reaquest received, and data after POST request.
 * Return values
 * HTTP_SRV_CB_DESTROY - disconnect/drop client and continue receiving new connections.
 * any other value - allocate resources and receive data from client.
 */

typedef void (*http_srv_on_destroy_cb)(http_srv_cli_p cli, void *udata);

typedef int (*http_srv_on_req_rcv_cb)(http_srv_cli_p cli, void *udata, http_srv_req_p req);
/* Called after HTTP reaquest received, and data after POST request.
 * Return values
 * HTTP_SRV_CB_DESTROY - disconnect/drop client.
 * HTTP_SRV_CB_NONE - do nothing, you must call: http_srv_snd() / http_srv_snd_err() / http_srv_cli_free().
 * > 0 - send HTTP error/reply with returned code.
 */

typedef int (*http_srv_on_resp_snd_cb)(http_srv_cli_p cli, void *udata);
/* Called after HTTP responce sended.
 * Return values
 * HTTP_SRV_CB_DESTROY - disconnect/drop client.
 * any other value - if client not half closed and no "connection: close" then 
 * try receive and handle next request.
 */
#define HTTP_SRV_CB_DESTROY	-1 /* Call http_srv_cli_free() except: returned from http_srv_on_conn_cb fuenction. */
#define HTTP_SRV_CB_NONE	0 /* Do nothink / All done, call done func, error = 0. */



typedef struct http_srv_stat_s {
	volatile uint64_t	connections;
	volatile uint64_t	timeouts;
	volatile uint64_t	errors;
	volatile uint64_t	http_errors;
	volatile uint64_t	insecure_requests;
	volatile uint64_t	unhandled_requests;
	volatile uint64_t	requests[HTTP_REQ_METHOD_UNKNOWN];
	volatile uint64_t	requests_total;
	time_t			start_time;
} http_srv_stat_t, *http_srv_stat_p;


typedef struct http_srv_settings_s { /* Settings */
	uint32_t	skt_rcv_buf;	/* kb */
	uint32_t	skt_snd_buf;	/* kb */
	uint32_t	rcv_timeout;	/* sec */
	uint32_t	snd_timeout;	/* sec */
	uint32_t	rcv_io_buf_init_size;	/* kb */
	uint32_t	rcv_io_buf_max_size;	/* kb, max request size (with data). */
	uint32_t	snd_io_buf_init_size;	/* kb, no hard limit */
	uint32_t	hdrs_reserve_size;	/* kb - !!! all standart and custom hdrs size */
	uint32_t	req_p_flags;	/* Request processing flags HTTP_SRV_RQ_P_F_*. */
	uint32_t	resp_p_flags;	/* Responce processing flags HTTP_SRV_RESP_P_F_*. */
	uint32_t	http_server_size; /* 'OS/version UPnP/1.0 product/version' */
	char		http_server[256]; /* 'OS/version UPnP/1.0 product/version' */
} http_srv_settings_t, *http_srv_settings_p;
/* Request processing flags. */
#define HTTP_SRV_REQ_P_F_CONNECTION	(1 << 0) /* process 'connection' header value. */
#define HTTP_SRV_REQ_P_F_HOST		(1 << 1) /* process 'host' header value. */
/* Responce processing flags. */
#define HTTP_SRV_RESP_P_F_CONN_CLOSE	(1 << 0) /* force 'Connection: close', use single IO_BUF for send and recv. */
#define HTTP_SRV_RESP_P_F_SERVER	(1 << 1) /* add 'Server' in answer. */
#define HTTP_SRV_RESP_P_F_CONTENT_SIZE	(1 << 2) /* add 'Content-Size' in answer. */

/* Default values. */
#define HTTP_SRV_S_DEF_SKT_RCV_BUF	(64)
#define HTTP_SRV_S_DEF_SKT_SND_BUF	(128)
#define HTTP_SRV_S_DEF_RCV_TIMEOUT	(30)
#define HTTP_SRV_S_DEF_SND_TIMEOUT	(30)
#define HTTP_SRV_S_DEF_RCV_IO_BUF_INIT	(4)
#define HTTP_SRV_S_DEF_RCV_IO_BUF_MAX	(64)
#define HTTP_SRV_S_DEF_SND_IO_BUF_INIT	(256)
#define HTTP_SRV_S_DEF_HDRS_SIZE	(1)
#define HTTP_SRV_S_DEF_RQ_P_FLAGS	(0)
#define HTTP_SRV_S_DEF_RESP_P_FLAGS	(HTTP_SRV_RESP_P_F_CONN_CLOSE | HTTP_SRV_RESP_P_F_SERVER | HTTP_SRV_RESP_P_F_CONTENT_SIZE)


/* http_URL = "http:" "//" host [ ":" port ] [ abs_path [ "?" query ]] */
typedef struct http_srv_req_s {
	uint8_t		*hdr;
	size_t		hdr_size;
	http_req_line_data_t line;	/* First request line. */
	uint8_t		*data;		/* After CRLFCRLF. */
	size_t		data_size;	/* content-length */
	uint8_t		*host;		/* From headers. */
	size_t		host_size;
	uint32_t	flags;		/* Flags */
} http_srv_req_t;
#define HTTP_SRV_RD_F_CONN_CLOSE	(1 << 0) /* 'connection' header value is close or http 1.0 without connection: keep-alive. */
#define HTTP_SRV_RD_F_HOST_IS_STR	(1 << 1) /* 'host' header value is text/domain name. */
#define HTTP_SRV_RD_F_HOST_IS_LOCAL	(1 << 2) /* 'host' header value point to this host. */



void	http_srv_def_settings(int add_os_ver, const char *app_ver, int add_lib_ver,
	    http_srv_settings_p s_ret);
#ifdef HTTP_SRV_XML_CONFIG
int	http_srv_xml_load_settings(uint8_t *buf, size_t buf_size,
	    http_srv_settings_p s);
int	http_srv_xml_load_hostnames(uint8_t *buf, size_t buf_size,
	    hostname_list_p hn_lst);
int	http_srv_xml_load_bind(uint8_t *buf, size_t buf_size,
	    struct sockaddr_storage *addr, uint32_t *flags, int *backlog,
	    char **tcp_cc, size_t *tcp_cc_size, hostname_list_p hn_lst);
#endif

int	http_srv_create(thrp_p thrp,
	    http_srv_on_conn_cb on_conn, http_srv_on_destroy_cb on_destroy,
	    http_srv_on_req_rcv_cb on_req_rcv, http_srv_on_resp_snd_cb on_rep_snd,
	    hostname_list_p hn_lst, http_srv_settings_p s, http_srv_p *srv_ret);
void	http_srv_shutdown(http_srv_p srv); /* Stop accept new clients. Optional. Allways call if radius auth used before destroy radius client. */
void	http_srv_destroy(http_srv_p srv);
size_t	http_srv_get_accept_count(http_srv_p srv);
int	http_srv_stat_get(http_srv_p srv, http_srv_stat_p stat);
thrp_p	http_srv_thrp_get(http_srv_p srv);
int	http_srv_thrp_set(http_srv_p srv, thrp_p thrp);
int	http_srv_on_conn_cb_set(http_srv_p srv, http_srv_on_conn_cb on_conn);
int	http_srv_on_destroy_cb_set(http_srv_p srv, http_srv_on_destroy_cb on_destroy);
int	http_srv_on_req_rcv_cb_set(http_srv_p srv, http_srv_on_req_rcv_cb on_req_rcv);
int	http_srv_on_rep_snd_cb_set(http_srv_p srv, http_srv_on_resp_snd_cb on_rep_snd);


int		http_srv_acc_add(http_srv_p srv, struct sockaddr_storage *addr,
		    uint32_t flags, int backlog,
		    const char *tcp_cc, size_t tcp_cc_size,
		    hostname_list_p hn_lst, void *udata,
		    http_srv_acc_p *acc_ret);
#define HTTP_SRV_ACC_A_F_ACC_FILTER	(1 << 0) /* SO_ACCEPTFILTER(httpready)/ TCP_DEFER_ACCEPT */
#define HTTP_SRV_ACC_A_F_TCP_NODELAY	(1 << 1) /* TCP_NODELAY */
#define HTTP_SRV_ACC_A_F_TCP_NOPUSH	(1 << 2) /* TCP_NOPUSH / TCP_CORK */
void		http_srv_acc_shutdown(http_srv_acc_p acc);
void		http_srv_acc_remove(http_srv_acc_p acc);
http_srv_p	http_srv_acc_get_srv(http_srv_acc_p acc);
void *		http_srv_acc_get_udata(http_srv_acc_p acc);
int		http_srv_acc_set_udata(http_srv_acc_p acc, void *udata);
uint64_t	http_srv_acc_get_conn_count(http_srv_acc_p acc);
int		http_srv_acc_get_addr(http_srv_acc_p acc, struct sockaddr_storage *addr);



void		http_srv_cli_free(http_srv_cli_p cli); /* Disconnect and free all resources. */

io_task_p	http_srv_cli_get_iotask(http_srv_cli_p cli);
io_task_p	http_srv_cli_export_iotask(http_srv_cli_p cli);

io_buf_p	http_srv_cli_get_buf(http_srv_cli_p cli);
/* Responce buffer management. */
int		http_srv_cli_buf_reset(http_srv_cli_p cli);
int		http_srv_cli_buf_realloc(http_srv_cli_p cli, int allow_decrease,
		    size_t new_size);
http_srv_acc_p	http_srv_cli_get_acc(http_srv_cli_p cli);
http_srv_p	http_srv_cli_get_srv(http_srv_cli_p cli);
http_srv_req_p	http_srv_cli_get_req(http_srv_cli_p cli);

void *		http_srv_cli_get_udata(http_srv_cli_p cli);
int		http_srv_cli_set_udata(http_srv_cli_p cli, void *udata);

uint32_t	http_srv_cli_get_flags(http_srv_cli_p cli);
#define HTTP_SRV_CLI_F_HALF_CLOSED	(1 << 0) /* Client call shutdown(, SHUT_WR) and can only receive data. */
#define HTTP_SRV_CLI_F_AUTHORIZED	(1 << 1) /* . */

uint32_t	http_srv_cli_get_resp_p_flags(http_srv_cli_p cli);
uint32_t	http_srv_cli_add_resp_p_flags(http_srv_cli_p cli, uint32_t resp_p_flags);
uint32_t	http_srv_cli_del_resp_p_flags(http_srv_cli_p cli, uint32_t resp_p_flags);
void		http_srv_cli_set_resp_p_flags(http_srv_cli_p cli, uint32_t resp_p_flags);

int		http_srv_cli_get_addr(http_srv_cli_p cli, struct sockaddr_storage *addr);


int	http_srv_gen_resp_hdrs(uint32_t http_ver, uint32_t status_code,
	    uint32_t resp_p_flags, const char *reason_phrase, size_t reason_phrase_size,
	    const char *http_server, size_t http_server_size,
	    uint64_t content_size, char *buf, size_t buf_size, size_t *buf_size_ret);
/*
 * resp_p_flags - HTTP_SRV_RESP_P_F_*
 */
int	http_srv_snd(http_srv_cli_p cli, uint32_t status_code,
	    const char *reason_phrase, size_t reason_phrase_size,
	    struct iovec *custom_hdrs, size_t custom_hdrs_count);
/* custom_hdrs_count < HTTP_SRV_MAX_CUSTOM_HDRS_CNT */
int	http_srv_snd_err(http_srv_cli_p cli, uint32_t status_code,
	    const char *reason_phrase, size_t reason_phrase_size);




typedef struct http_srv_auth_plugin_s	*http_srv_auth_plugin_p;

typedef int (*http_srv_auth_plugin_init_fn)(http_srv_auth_plugin_p plugin, void *arg1, size_t arg2);
typedef void (*http_srv_auth_plugin_destroy_fn)(http_srv_auth_plugin_p plugin);
typedef int (*http_srv_auth_plugin_cli_init_fn)(http_srv_cli_p cli);
typedef void (*http_srv_auth_plugin_cli_destroy_fn)(http_srv_cli_p cli);
typedef int (*http_srv_auth_plugin_cli_basic_fn)(http_srv_cli_p cli,
	uint8_t *login, size_t login_size, uint8_t *password, size_t password_size);


#define HTTP_SRV_AUTH_TYPE_UNKNOWN	0 /* none. */
#define HTTP_SRV_AUTH_TYPE_BASIC	1
#define HTTP_SRV_AUTH_TYPE_DIGEST	2
#define HTTP_SRV_AUTH_TYPE_URI_ARGS	3

#define HTTP_SRV_AUTH_TYPE_F_UNKNOWN	0
#define HTTP_SRV_AUTH_TYPE_F_BASIC	(1 << HTTP_SRV_AUTH_TYPE_BASIC)
#define HTTP_SRV_AUTH_TYPE_F_DIGEST	(1 << HTTP_SRV_AUTH_TYPE_DIGEST)
#define HTTP_SRV_AUTH_TYPE_F_AUTHORIZATION (HTTP_SRV_AUTH_TYPE_F_BASIC | HTTP_SRV_AUTH_TYPE_F_DIGEST)
#define HTTP_SRV_AUTH_TYPE_F_URI_ARGS	(1 << HTTP_SRV_AUTH_TYPE_URI_ARGS)


typedef struct http_srv_auth_plugin_s {
	http_srv_auth_plugin_init_fn	plugin_init;	/*  */
	http_srv_auth_plugin_destroy_fn	plugin_destroy;	/*  */
	http_srv_auth_plugin_cli_init_fn	client_init;	/* Client data initialization/allocation. */
	http_srv_auth_plugin_cli_destroy_fn	client_destroy;	/* Client data free. */
	http_srv_auth_plugin_cli_basic_fn	auth_basic;	/* Client auth basic. */
	uint8_t		*uri_arg_name_login;
	size_t		uri_arg_name_login_size;
	uint8_t		*uri_arg_name_password;
	size_t		uri_arg_name_password_size;
	uint32_t	allowed_types;	/* HTTP_SRV_AUTH_TYPE_F_* */
	uint32_t	flags;		/* Flags: HTTP_SRV_AUTH_PL_F_*. */
	void		*data;		/* Plugin associated data (radius_cli_p for radius). On create passed to plugin_init(). */
	size_t		data_size;	/* If == 0 then data point outside. On create passed to plugin_init(). */
	void		*settings;	/* Plugin associated settings (http_srv_auth_set_rad_p for radius). */
	size_t		settings_size;	/* If == 0 then settings point outside. Needed only on create. */
} http_srv_auth_plugin_t;
#define HTTP_SRV_AUTH_PL_F_REALM_INCLUDE_URL_ARGS	(1 << 0) /* Try do cheks even login and password not found in request. */
#define HTTP_SRV_AUTH_PL_F_TRY_WO_LOGIN_PWD		(1 << 1) /* Try do cheks even login and password not found in request. */

/* First argement as settings. Allocate and store in one place, call plugin_init() */
int	http_srv_auth_plugin_create(http_srv_auth_plugin_p s,
	    http_srv_auth_plugin_p *plugin_ret);
void	http_srv_auth_plugin_destroy(http_srv_auth_plugin_p plugin);



int	http_srv_auth_plugin_create_radius(
	    uint8_t *uri_arg_name_login, size_t uri_arg_name_login_size,
	    uint8_t *uri_arg_name_password, size_t uri_arg_name_password_size,
	    uint32_t allowed_types, uint32_t flags, radius_cli_p rad_cli,
	    http_srv_auth_plugin_p *plugin_ret);

/* RADIUS auth plugin. */
typedef struct http_srv_auth_plugin_settings_radius_s { /* Radius palugin specific settings. */
	uint32_t	type;		/* HTTP_SRV_AUTH_TYPE_* */
} http_srv_auth_set_rad_t, *http_srv_auth_set_rad_p;





#endif // __CORE_HTTP_SERVER_H__
