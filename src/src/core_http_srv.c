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


#include <sys/param.h>

#ifdef __linux__ /* Linux specific code. */
#define _GNU_SOURCE /* See feature_test_macros(7) */
#define __USE_GNU 1
#endif /* Linux specific code. */

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>

#include <stdlib.h> /* malloc, exit */
#include <unistd.h> /* close, write, sysconf */
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <stdio.h> /* snprintf, fprintf */
#include <time.h>
#include <errno.h>

#include "mem_find.h"
#include "buf_case.h"
#include "StrToNum.h"
#include "HTTP.h"

#include "core_macro.h"
#include "core_atomic.h"
#include "core_io_task.h"
#include "core_io_net.h"
#include "core_net_helpers.h"
#include "core_info.h"
#include "core_hostname.h"
#include "core_log.h"
#include "core_http_srv.h"
#ifdef HTTP_SRV_XML_CONFIG
#include "core_helpers.h"
#include "xml.h"
#endif


#define CORE_HTTP_LIB_NAME		"HTTP core server by Rozhuk Ivan"
#define CORE_HTTP_LIB_VER		"1.4"

#define HTTP_SRV_ALLOC_CNT		8




typedef struct http_srv_acc_s {
	io_task_p	iotask;		/* Accept incomming task. */
	http_srv_p	srv;		/* HTTP server */
	volatile uint64_t connections;	/* Ref count / connections that point to this instance. */
	uint32_t	flags;		/* Flags */
	char		cc_name[TCP_CA_NAME_MAX];/* tcp congestion control */
	void		*udata;		/* Acceptor associated data. */
	hostname_list_t	hn_lst;		/* List of host names on this bind. */
	struct sockaddr_storage	addr;	/* Bind address. */
} http_srv_acc_t;
#define HTTP_SRV_ACC_F_ACC_FILTER	(1 << 0) /* SO_ACCEPTFILTER(httpready)/ TCP_DEFER_ACCEPT */
#define HTTP_SRV_ACC_F_CUSTOM_CC	(1 << 1) /* Custom tcp.cc for sockets. */
#define HTTP_SRV_ACC_F_TCP_NODELAY	(1 << 2) /* TCP_NODELAY */
#define HTTP_SRV_ACC_F_TCP_NOPUSH	(1 << 3) /* TCP_NOPUSH / TCP_CORK */



typedef struct http_srv_s {
	thrp_p			thrp;
	http_srv_on_conn_cb	on_conn; /* New client connected callback */
	http_srv_on_destroy_cb	on_destroy; /* Client destroyed callback */
	http_srv_on_req_rcv_cb	on_req_rcv; /* Client request received callback */
	http_srv_on_resp_snd_cb	on_rep_snd; /* Responce sended to client callback */
	http_srv_stat_t		stat;
	size_t			accept_cnt;
	size_t			accept_allocated;
	http_srv_acc_p		*acc;	/* Acceptors pointers array. */
	hostname_list_t		hn_lst;	/* List of host names on this server. */
	http_srv_settings_t	s;	/* settings */
} http_srv_t;



typedef struct http_srv_cli_s {
	io_task_p	iotask;		/* recv/send from/to client, and socket container. */
	io_buf_p	rcv_buf;	/* Used for receive http request only. */
	io_buf_p	buf;		/* Used for send http responce only. */
	http_srv_acc_p	acc;		/*  */
	http_srv_req_t	req;		/* Parsed request data. */
	http_srv_auth_plugin_p auth_plugin; /* Auth plugin data. */
	void		*auth_plugin_data; /* Auth plugin associated client data (status, buffer...etc...). */
	void		*udata;		/* Client associated data. */
	uint32_t	flags;		/* Flags: HTTP_SRV_CLI_F_*. */
	uint32_t	resp_p_flags;	/* Responce processing flags HTTP_SRV_RESP_P_F_*. */
	struct sockaddr_storage addr;	/* Client address. */
} http_srv_cli_t;



http_srv_cli_p	http_srv_cli_alloc(http_srv_acc_p acc, thrpt_p thrpt, uintptr_t skt,
		    void *udata);
void		http_srv_cli_free(http_srv_cli_p cli);

static int	http_srv_new_conn_cb(io_task_p iotask, int error, uintptr_t skt,
		    struct sockaddr_storage *addr, void *arg);
static int	http_srv_recv_done_cb(io_task_p iotask, int error, io_buf_p buf,
		    int eof, size_t transfered_size, void *arg);
void		http_srv_cli_req_rcv_cb(http_srv_cli_p cli);
static int	http_srv_snd_done_cb(io_task_p iotask, int error,
		    io_buf_p buf, int eof, size_t transfered_size, void *arg);




void
http_srv_def_settings(int add_os_ver, const char *app_ver, int add_lib_ver,
    http_srv_settings_p s_ret) {
	size_t tm;

	if (NULL == s_ret)
		return;
	memset(s_ret, 0, sizeof(http_srv_settings_t));
	/* default settings */
	s_ret->skt_rcv_buf = HTTP_SRV_S_DEF_SKT_RCV_BUF;
	s_ret->skt_snd_buf = HTTP_SRV_S_DEF_SKT_SND_BUF;
	s_ret->rcv_timeout = HTTP_SRV_S_DEF_RCV_TIMEOUT;
	s_ret->snd_timeout = HTTP_SRV_S_DEF_SND_TIMEOUT;
	s_ret->rcv_io_buf_init_size = HTTP_SRV_S_DEF_RCV_IO_BUF_INIT;
	s_ret->rcv_io_buf_max_size = HTTP_SRV_S_DEF_RCV_IO_BUF_MAX;
	s_ret->snd_io_buf_init_size = HTTP_SRV_S_DEF_SND_IO_BUF_INIT;
	s_ret->hdrs_reserve_size = HTTP_SRV_S_DEF_HDRS_SIZE;
	s_ret->req_p_flags = HTTP_SRV_S_DEF_RQ_P_FLAGS;
	s_ret->resp_p_flags = HTTP_SRV_S_DEF_RESP_P_FLAGS;

	/* 'OS/version UPnP/1.1 product/version' */
	s_ret->http_server_size = 0;
	if (0 != add_os_ver) {
		if (0 == core_info_get_os_ver("/", 1, s_ret->http_server,
		    (sizeof(s_ret->http_server) - 1), &tm)) {
			s_ret->http_server_size = tm;
		} else {
			memcpy(s_ret->http_server, "Generic OS/1.0", 15);
			s_ret->http_server_size = 14;
		}
	}
	if (NULL != app_ver) {
		s_ret->http_server_size += snprintf(
		    (s_ret->http_server + s_ret->http_server_size),
		    ((sizeof(s_ret->http_server) - 1) - s_ret->http_server_size),
		    "%s%s",
		    ((0 != s_ret->http_server_size) ? " " : ""), app_ver);
	}
	if (0 != add_lib_ver) {
		s_ret->http_server_size += snprintf(
		    (s_ret->http_server + s_ret->http_server_size),
		    ((sizeof(s_ret->http_server) - 1) - s_ret->http_server_size),
		    "%s"CORE_HTTP_LIB_NAME"/"CORE_HTTP_LIB_VER,
		    ((0 != s_ret->http_server_size) ? " " : ""));
	}
	s_ret->http_server[s_ret->http_server_size] = 0;
}

#ifdef HTTP_SRV_XML_CONFIG
int
http_srv_xml_load_settings(uint8_t *buf, size_t buf_size, http_srv_settings_p s) {

	if (NULL == buf || 0 == buf_size || NULL == s)
		return (EINVAL);
	/* Read from config. */
	xml_get_val_int_args(buf, buf_size, NULL, (int32_t*)&s->skt_rcv_buf,
	    (const uint8_t*)"skt", "rcvBuf", NULL);
	xml_get_val_int_args(buf, buf_size, NULL, (int32_t*)&s->skt_snd_buf,
	    (const uint8_t*)"skt", "sndBuf", NULL);
	xml_get_val_int_args(buf, buf_size, NULL, (int32_t*)&s->rcv_timeout,
	    (const uint8_t*)"skt", "rcvTimeout", NULL);
	xml_get_val_int_args(buf, buf_size, NULL, (int32_t*)&s->snd_timeout,
	    (const uint8_t*)"skt", "sndTimeout", NULL);
	xml_get_val_int_args(buf, buf_size, NULL, (int32_t*)&s->rcv_io_buf_init_size,
	    (const uint8_t*)"ioBufInitSize", NULL);
	xml_get_val_int_args(buf, buf_size, NULL, (int32_t*)&s->rcv_io_buf_max_size,
	    (const uint8_t*)"ioBufMaxSize", NULL);
	return (0);
}
	
int
http_srv_xml_load_hostnames(uint8_t *buf, size_t buf_size, hostname_list_p hn_lst) {
	int error;
	uint8_t *data, *cur_pos;
	size_t data_size;
	char strbuf[256];

	if (NULL == buf || 0 == buf_size || NULL == hn_lst)
		return (EINVAL);
	/* Read hostnames. */
	hostname_list_init(hn_lst);
	cur_pos = NULL;
	while (0 == xml_get_val_args(buf, buf_size, &cur_pos, NULL, NULL,
	    &data, &data_size, (const uint8_t*)"hostnameList", "hostname", NULL)) {
		error = hostname_list_add(hn_lst, data, data_size);
		if (0 != error) {
			LOG_ERR(error, "hostname_list_add()");
			continue;
		}
		data_size = min(data_size, (sizeof(strbuf) - 1));
		memcpy(strbuf, data, data_size);
		strbuf[data_size] = 0;
		LOG_INFO_FMT("hostname: %s", strbuf);
	}
	return (0);
}

int
http_srv_xml_load_bind(uint8_t *buf, size_t buf_size,
    struct sockaddr_storage *addr, uint32_t *flags, int *backlog,
    char **tcp_cc, size_t *tcp_cc_size, hostname_list_p hn_lst) {
	int error;
	uint8_t *data;
	size_t data_size;
	uint32_t tm32;
	char straddr[STR_ADDR_LEN];

	if (NULL == buf || 0 == buf_size ||
	    NULL == addr || NULL == flags || NULL == backlog ||
	    NULL == tcp_cc || NULL == tcp_cc_size || NULL == hn_lst)
		return (EINVAL);
	(*flags) = 0;
	(*backlog) = -1;
	(*tcp_cc) = NULL;
	(*tcp_cc_size) = 0;
	hostname_list_init(hn_lst);
	/* address */
	if (0 != xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
	    &data, &data_size, (const uint8_t*)"address", NULL))
		return (EINVAL);
	if (0 != str_addr_port_to_ss((const char*)data, data_size, addr)) {
		memcpy(straddr, data, min((sizeof(straddr) - 1), data_size));
		straddr[min((sizeof(straddr) - 1), data_size)] = 0;
		LOG_EV_FMT("BIND: invalid addr: %s", straddr);
		return (EINVAL);
	}
	if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
	    &data, &data_size, (const uint8_t*)"ifName", NULL)) {
		tm32 = sain_p_get(addr);
		error = get_if_addr_by_name((const char*)data, data_size,
		    addr->ss_family, addr);
		if (0 != error) {
			memcpy(straddr, data, min((sizeof(straddr) - 1), data_size));
			straddr[min((sizeof(straddr) - 1), data_size)] = 0;
			LOG_EV_FMT("BIND: cant get addr for: %s", straddr);
			return (error);
		}
		sain_p_set(addr, tm32);
	}
	/* accept flags */
	if (0 == xml_get_val_args(buf, buf_size, NULL, (uint8_t**)&data, &data_size,
	    NULL, NULL, (const uint8_t*)"fAcceptFilter", NULL))
		yn_set_flag32(data, data_size, HTTP_SRV_ACC_A_F_ACC_FILTER, flags);
	/* backlog */
	xml_get_val_int_args(buf, buf_size, NULL, (int32_t*)backlog,
	    (const uint8_t*)"backlog", NULL);
	/* congestionControl */
	xml_get_val_args(buf, buf_size, NULL, NULL, NULL, (uint8_t**)tcp_cc, tcp_cc_size,
	    (const uint8_t*)"congestionControl", NULL);
	/* Read hostnames. */
	return (http_srv_xml_load_hostnames(buf, buf_size, hn_lst));
}
#endif



int
http_srv_create(thrp_p thrp, http_srv_on_conn_cb on_conn,
    http_srv_on_destroy_cb on_destroy, http_srv_on_req_rcv_cb on_req_rcv,
    http_srv_on_resp_snd_cb on_rep_snd, hostname_list_p hn_lst, http_srv_settings_p s,
    http_srv_p *srv_ret) {
	int error;
	http_srv_p srv = NULL;

	LOGD_EV("...");
	
	if (NULL == srv_ret) {
		error = EINVAL;
		goto err_out;
	}
	if (NULL != s) { /* Validate settings. */
		if ((s->hdrs_reserve_size + HTTP_SRV_S_DEF_HDRS_SIZE) >
		    s->snd_io_buf_init_size ||
		    sizeof(s->http_server) <= s->http_server_size) {
			error = EINVAL;
			goto err_out;
		}
	}
	/* Create. */
	srv = zalloc(sizeof(http_srv_t));
	if (NULL == srv) {
		error = ENOMEM;
		goto err_out;
	}
	srv->thrp = thrp;
	srv->on_conn = on_conn;
	srv->on_destroy = on_destroy;
	srv->on_req_rcv = on_req_rcv;
	srv->on_rep_snd = on_rep_snd;
	if (NULL != hn_lst)
		memcpy(&srv->hn_lst, hn_lst, sizeof(hostname_list_t));
	if (NULL == s) { /* Apply default settings */
		http_srv_def_settings(1, NULL, 1, &srv->s);
	} else {
		memcpy(&srv->s, s, sizeof(http_srv_settings_t));
	}
	/* kb -> bytes, sec -> msec */
	srv->s.skt_rcv_buf *= 1024;
	srv->s.skt_snd_buf *= 1024;
	srv->s.rcv_timeout *= 1000;
	srv->s.snd_timeout *= 1000;
	srv->s.rcv_io_buf_init_size *= 1024;
	srv->s.rcv_io_buf_max_size *= 1024;
	srv->s.snd_io_buf_init_size *= 1024;
	srv->s.hdrs_reserve_size *= 1024;
	srv->s.http_server[srv->s.http_server_size] = 0;

	srv->stat.start_time = thrpt_gettime(NULL, 0);

	(*srv_ret) = srv;
	return (0);
err_out:
	hostname_list_deinit(hn_lst);
	if (NULL != srv)
		free(srv);
	/* Error. */
	LOG_ERR(error, "err_out");
	return (error);
}

void
http_srv_shutdown(http_srv_p srv) {
	size_t i;

	LOGD_EV("...");
	if (NULL == srv || NULL != srv->acc)
		return;
	for (i = 0; i < srv->accept_cnt; i ++) {
		http_srv_acc_shutdown(srv->acc[i]);
	}
}

void
http_srv_destroy(http_srv_p srv) {
	size_t i;

	LOGD_EV("...");
	if (NULL == srv)
		return;
	if (NULL != srv->acc) {
		for (i = 0; i < srv->accept_cnt; i ++)
			http_srv_acc_remove(srv->acc[i]);
		free(srv->acc);
	}
	hostname_list_deinit(&srv->hn_lst);
	memfilld(srv, sizeof(http_srv_t));
	free(srv);
}

size_t
http_srv_get_accept_count(http_srv_p srv) {

	if (NULL == srv)
		return (0);
	return (srv->accept_cnt);
}

int
http_srv_stat_get(http_srv_p srv, http_srv_stat_p stat) {

	if (NULL == srv || NULL == stat)
		return (EINVAL);
	memcpy(stat, &srv->stat, sizeof(http_srv_stat_t));
	return (0);
}

thrp_p
http_srv_thrp_get(http_srv_p srv) {

	if (NULL == srv)
		return (NULL);
	return (srv->thrp);
}

int
http_srv_thrp_set(http_srv_p srv, thrp_p thrp) {

	if (NULL == srv)
		return (EINVAL);
	srv->thrp = thrp;
	return (0);
}

int
http_srv_on_conn_cb_set(http_srv_p srv, http_srv_on_conn_cb on_conn) {

	if (NULL == srv)
		return (EINVAL);
	srv->on_conn = on_conn;
	return (0);
}

int
http_srv_on_destroy_cb_set(http_srv_p srv, http_srv_on_destroy_cb on_destroy) {

	if (NULL == srv)
		return (EINVAL);
	srv->on_destroy = on_destroy;
	return (0);
}

int
http_srv_on_req_rcv_cb_set(http_srv_p srv, http_srv_on_req_rcv_cb on_req_rcv) {

	if (NULL == srv)
		return (EINVAL);
	srv->on_req_rcv = on_req_rcv;
	return (0);
}

int
http_srv_on_rep_snd_cb_set(http_srv_p srv, http_srv_on_resp_snd_cb on_rep_snd) {

	if (NULL == srv)
		return (EINVAL);
	srv->on_rep_snd = on_rep_snd;
	return (0);
}


/* HTTP Acceptor */
int
http_srv_acc_add(http_srv_p srv, struct sockaddr_storage *addr, uint32_t flags,
    int backlog, const char *tcp_cc, size_t tcp_cc_size, hostname_list_p hn_lst,
    void *udata, http_srv_acc_p *acc_ret) {
	int error;
	http_srv_acc_p acc = NULL, *acc_new;
	uintptr_t skt = -1;

	LOGD_EV("...");
	if (NULL == srv || NULL == addr) {
		error = EINVAL;
		goto err_out;
	}

	acc = zalloc(sizeof(http_srv_acc_t));
	if (NULL == acc) {
		error = ENOMEM;
		goto err_out;
	}
	error = io_net_bind(addr, SOCK_STREAM, &skt);
	if (0 != error)
		goto err_out;
	error = io_net_listen(skt, backlog);
	if (0 != error)
		goto err_out;
	if (0 != (HTTP_SRV_ACC_A_F_ACC_FILTER & flags)) {
		error = io_net_set_accept_filter(skt, "httpready", 9);
		if (0 == error) {
			acc->flags |= HTTP_SRV_ACC_F_ACC_FILTER;
		} else {
			LOG_ERR(error, "io_net_set_accept_filter() fail, this is not fatal.");
		}
	}
	if (NULL != tcp_cc && 0 != tcp_cc_size) {
		if (0 != io_net_is_tcp_cc_avail(tcp_cc, tcp_cc_size)) {
			acc->flags |= HTTP_SRV_ACC_F_CUSTOM_CC;
			memcpy(acc->cc_name, tcp_cc, tcp_cc_size);
		} else {
			LOG_ERR(EINVAL, "io_net_is_tcp_cc_avail() fail, this is not fatal.");
		}
	}
	if (0 != (HTTP_SRV_ACC_A_F_TCP_NODELAY & flags))
		acc->flags |= HTTP_SRV_ACC_F_TCP_NODELAY;
	if (0 != (HTTP_SRV_ACC_A_F_TCP_NOPUSH & flags))
		acc->flags |= HTTP_SRV_ACC_F_TCP_NOPUSH;
	acc->srv = srv;
	sa_copy(addr, &acc->addr);
	acc->udata = udata;
	if (NULL != hn_lst)
		memcpy(&acc->hn_lst, hn_lst, sizeof(hostname_list_t));
	
	error = io_task_create_accept(thrp_thread_get_rr(srv->thrp), skt,
	    IO_TASK_F_CLOSE_ON_DESTROY, 0, http_srv_new_conn_cb, acc, &acc->iotask);
	if (0 != error)
		goto err_out;
	if (NULL != acc_ret)
		(*acc_ret) = acc;
	if (srv->accept_allocated == srv->accept_cnt) { /* realloc acceptors pointers. */
		srv->accept_allocated += HTTP_SRV_ALLOC_CNT;
		acc_new = realloc(srv->acc, (sizeof(http_srv_acc_p) * srv->accept_allocated));
		if (NULL == acc_new) { /* Realloc fail! */
			srv->accept_allocated -= HTTP_SRV_ALLOC_CNT;
			error = ENOMEM;
			goto err_out;
		}
		srv->acc = acc_new;
	}
	srv->acc[srv->accept_cnt] = acc;
	srv->accept_cnt ++;

	return (0);
err_out:
	close(skt);
	hostname_list_deinit(hn_lst);
	if (NULL != acc) {
		io_task_destroy(acc->iotask);
		free(acc);
	}
	/* Error. */
	LOG_ERR(error, "err_out");
	return (error);
}

void
http_srv_acc_shutdown(http_srv_acc_p acc) {

	LOGD_EV("...");
	if (NULL == acc)
		return;
	io_task_destroy(acc->iotask);
	acc->iotask = NULL;
}

void
http_srv_acc_remove(http_srv_acc_p acc) {
	size_t i;
	http_srv_p srv;

	LOGD_EV("...");
	if (NULL == acc)
		return;
	srv = acc->srv;
	for (i = 0; i < srv->accept_cnt; i ++) {
		if (srv->acc[i] == acc) {
			srv->acc[i] = NULL;
			if (i == srv->accept_cnt)
				srv->accept_cnt --;
			break;
		}
	}

	io_task_destroy(acc->iotask);
	hostname_list_deinit(&acc->hn_lst);
	memfilld(acc, sizeof(http_srv_acc_t));
	free(acc);
}

http_srv_p
http_srv_acc_get_srv(http_srv_acc_p acc) {

	if (NULL == acc)
		return (NULL);
	return (acc->srv);
}

void *
http_srv_acc_get_udata(http_srv_acc_p acc) {

	if (NULL == acc)
		return (NULL);
	return (acc->udata);
}

int
http_srv_acc_set_udata(http_srv_acc_p acc, void *udata) {

	if (NULL == acc)
		return (EINVAL);
	acc->udata = udata;
	return (0);
}

uint64_t
http_srv_acc_get_conn_count(http_srv_acc_p acc) {

	if (NULL == acc)
		return (0);
	return (atomic_load_acq_64(&acc->connections));
}

int
http_srv_acc_get_addr(http_srv_acc_p acc, struct sockaddr_storage *addr) {

	if (NULL == acc || NULL == addr)
		return (EINVAL);
	sa_copy(&acc->addr, addr);
	return (0);
}


/* HTTP Client */
http_srv_cli_p
http_srv_cli_alloc(http_srv_acc_p acc, thrpt_p thrpt, uintptr_t skt, void *udata) {
	http_srv_cli_p cli;

	LOGD_EV("...");

	cli = zalloc(sizeof(http_srv_cli_t));
	if (NULL == cli)
		return (cli);
	cli->rcv_buf = io_buf_alloc(acc->srv->s.rcv_io_buf_init_size);
	cli->buf = cli->rcv_buf;
	if (NULL == cli->rcv_buf)
		goto err_out;
	if (0 != io_task_create(thrpt, skt, io_task_sr_handler,
	    (IO_TASK_F_CLOSE_ON_DESTROY | IO_TASK_F_CB_AFTER_EVERY_READ),
	    cli, &cli->iotask))
		goto err_out;
	cli->acc = acc;
	cli->udata = udata;
	/* Map resp_p_flags. */
	cli->resp_p_flags = acc->srv->s.resp_p_flags;

	atomic_add_rel_64(&acc->connections, 1);
	atomic_add_rel_64(&acc->srv->stat.connections, 1);

	return (cli);
err_out:
	http_srv_cli_free(cli);
	return (NULL);
}

void
http_srv_cli_free(http_srv_cli_p cli) {

	LOGD_EV("...");

	if (NULL == cli)
		return;
	atomic_subtract_rel_64(&cli->acc->srv->stat.connections, 1);
	atomic_subtract_rel_64(&cli->acc->connections, 1);
	if (NULL != cli->acc->srv->on_destroy) /* Call back handler. */
		cli->acc->srv->on_destroy(cli, cli->udata);
	io_task_destroy(cli->iotask);
	io_buf_free(cli->rcv_buf);
	if (cli->buf != cli->rcv_buf)
		io_buf_free(cli->buf);
	memfilld(cli, sizeof(http_srv_cli_t));
	free(cli);
}

io_task_p
http_srv_cli_get_iotask(http_srv_cli_p cli) {

	if (NULL == cli)
		return (NULL);
	return (cli->iotask);
}

io_task_p
http_srv_cli_export_iotask(http_srv_cli_p cli) {
	io_task_p iotask;

	if (NULL == cli)
		return (NULL);
	iotask = cli->iotask;
	cli->iotask = NULL;
	return (iotask);
}

io_buf_p
http_srv_cli_get_buf(http_srv_cli_p cli) {

	if (NULL == cli)
		return (NULL);
	return (cli->buf);
}

int
http_srv_cli_buf_reset(http_srv_cli_p cli) {

	if (NULL == cli || NULL == cli->buf)
		return (EINVAL);
	IO_BUF_BUSY_SIZE_SET(cli->buf, cli->acc->srv->s.hdrs_reserve_size);
	return (0);
}

int
http_srv_cli_buf_realloc(http_srv_cli_p cli, int allow_decrease, size_t new_size) {

	if (NULL == cli || NULL == cli->buf)
		return (EINVAL);
	new_size += cli->acc->srv->s.hdrs_reserve_size;
	if (new_size > cli->buf->size || /* Need more space! */
	    (0 != allow_decrease && (new_size * 2) < cli->buf->size)) { /* Space too mach. */
		return (io_buf_realloc(&cli->buf, new_size));
	}
	return (0);
}

http_srv_acc_p
http_srv_cli_get_acc(http_srv_cli_p cli) {

	if (NULL == cli)
		return (NULL);
	return (cli->acc);
}

http_srv_p
http_srv_cli_get_srv(http_srv_cli_p cli) {

	if (NULL == cli)
		return (NULL);
	if (NULL == cli->acc)
		return (NULL);
	return (cli->acc->srv);
}

http_srv_req_p
http_srv_cli_get_req(http_srv_cli_p cli) {

	if (NULL == cli)
		return (NULL);
	return (&cli->req);
}

void *
http_srv_cli_get_udata(http_srv_cli_p cli) {

	if (NULL == cli)
		return (NULL);
	return (cli->udata);
}

int
http_srv_cli_set_udata(http_srv_cli_p cli, void *udata) {

	if (NULL == cli)
		return (EINVAL);
	cli->udata = udata;
	return (0);
}

uint32_t
http_srv_cli_get_flags(http_srv_cli_p cli) {

	if (NULL == cli)
		return (0);
	return (cli->flags);
}

uint32_t
http_srv_cli_get_resp_p_flags(http_srv_cli_p cli) {

	if (NULL == cli)
		return (0);
	return (cli->resp_p_flags);
}

uint32_t
http_srv_cli_add_resp_p_flags(http_srv_cli_p cli, uint32_t resp_p_flags) {

	if (NULL == cli)
		return (0);
	cli->resp_p_flags |= resp_p_flags;
	return (cli->resp_p_flags);
}

uint32_t
http_srv_cli_del_resp_p_flags(http_srv_cli_p cli, uint32_t resp_p_flags) {

	if (NULL == cli)
		return (0);
	cli->resp_p_flags &= ~resp_p_flags;
	return (cli->resp_p_flags);
}

void
http_srv_cli_set_resp_p_flags(http_srv_cli_p cli, uint32_t resp_p_flags) {

	if (NULL == cli)
		return;
	cli->resp_p_flags = resp_p_flags;
}

int
http_srv_cli_get_addr(http_srv_cli_p cli, struct sockaddr_storage *addr) {

	if (NULL == cli || NULL == addr)
		return (EINVAL);
	sa_copy(&cli->addr, addr);
	return (0);
}




/* New connection received. */
static int
http_srv_new_conn_cb(io_task_p iotask __unused, int error, uintptr_t skt,
    struct sockaddr_storage *addr, void *arg) {
	http_srv_cli_p cli;
	http_srv_acc_p acc = (http_srv_acc_p)arg;
	http_srv_p srv;
	thrpt_p thrpt;
	void *udata = NULL;
	char straddr[STR_ADDR_LEN];

	srv = acc->srv;

	if (0 != error) {
		close(skt);
		srv->stat.errors ++;
		LOG_ERR(error, "on new conn");
		return (IO_TASK_CB_CONTINUE);
	}
	thrpt = thrp_thread_get_rr(srv->thrp);
	if (NULL != srv->on_conn) { /* Call back handler. */
		if (HTTP_SRV_CB_DESTROY ==
		    srv->on_conn(acc, acc->udata, skt, addr, &thrpt, &udata)) {
			close(skt);
			return (IO_TASK_CB_CONTINUE);
		}
	}
	if (0 != LOG_IS_ENABLED()) {
		ss_to_str_addr_port(addr, straddr, sizeof(straddr), NULL);
		LOGD_INFO_FMT("New client: %s", straddr);
	}

	cli = http_srv_cli_alloc(acc, thrpt, skt, udata);
	if (NULL == cli) {
		if (NULL != srv->on_destroy) /* Call back handler. */
			srv->on_destroy(NULL, udata);
		close(skt);
		srv->stat.errors ++;
		LOG_ERR_FMT(ENOMEM, "%s: http_srv_cli_alloc()", straddr);
		return (IO_TASK_CB_CONTINUE);
	}
	sa_copy(addr, &cli->addr);
	/* Tune socket for receive. */
	error = io_net_snd_tune(skt, srv->s.skt_snd_buf, 1);
	if (0 != error)
		LOG_ERR_FMT(error, "%s: io_net_snd_tune(), this is not fatal.", straddr);
	error = io_net_rcv_tune(skt, srv->s.skt_rcv_buf, 1);
	if (0 != error)
		LOG_ERR_FMT(error, "%s: io_net_rcv_tune(), this is not fatal.", straddr);

	if (0 != (HTTP_SRV_ACC_F_CUSTOM_CC & acc->flags)) {
		error = io_net_set_tcp_cc(skt, acc->cc_name, TCP_CA_NAME_MAX);
		if (0 != error)
			LOG_ERR_FMT(error, "%s: io_net_set_tcp_cc() fail, this is not fatal.", straddr);
	}
	error = io_net_set_tcp_nodelay(skt, (0 != (HTTP_SRV_ACC_F_TCP_NODELAY & acc->flags)));
	if (0 != error)
		LOG_ERR_FMT(error, "%s: io_net_set_tcp_nodelay() fail, this is not fatal.", straddr);
	error = io_net_set_tcp_nopush(skt, (0 != (HTTP_SRV_ACC_F_TCP_NOPUSH & acc->flags)));
	if (0 != error)
		LOG_ERR_FMT(error, "%s: io_net_set_tcp_nopush() fail, this is not fatal.", straddr);
	/* Receive http request. */
	IO_BUF_MARK_TRANSFER_ALL_FREE(cli->rcv_buf);
	/* Shedule data receive / Receive http request. */
	error = io_task_start_ex(
	    ((0 != (HTTP_SRV_ACC_F_ACC_FILTER & acc->flags)) ? 0 : 1), cli->iotask,
	    THRP_EV_READ, 0, srv->s.rcv_timeout, 0, cli->rcv_buf,
	    http_srv_recv_done_cb);
	if (0 != error) { /* Error. */
		srv->stat.errors ++;
		http_srv_cli_free(cli);
		LOG_ERR_FMT(error, "client ip: %s", straddr);
	}
	return (IO_TASK_CB_CONTINUE);
}


/* http request from client is received now, process it. */
static int
http_srv_recv_done_cb(io_task_p iotask, int error, io_buf_p buf, int eof,
    size_t transfered_size, void *arg) {
	http_srv_cli_p cli = (http_srv_cli_p)arg;
	http_srv_acc_p acc;
	http_srv_p srv;
	char straddr[STR_ADDR_LEN];
	uint8_t *ptm;
	uint16_t host_port;
	size_t i, tm;
	int action;
	struct sockaddr_storage addr;

	LOGD_EV("...");

	acc = cli->acc;
	srv = acc->srv;
	/* iotask == cli->iotask !!! */
	/* buf == cli->rcv_buf !!! */
	// buf->used = buf->offset;
	action = io_task_cb_check(buf, eof, transfered_size);
	if (0 != error || IO_TASK_CB_ERROR == action) { /* Fail! :( */
err_out:
		if (0 != error && 0 != LOG_IS_ENABLED()) {
			ss_to_str_addr_port(&cli->addr, straddr, sizeof(straddr), NULL);
			LOG_ERR_FMT(error, "client ip: %s", straddr);
		}
		switch (error) {
		case 0:
			break;
		case ETIMEDOUT:
			srv->stat.timeouts ++;
			break;
		default:
			srv->stat.errors ++;
			break;
		}
		http_srv_cli_free(cli);
		return (IO_TASK_CB_NONE);
	}

	if (0 != (IO_TASK_IOF_F_SYS & eof)) { /* Client call shutdown(, SHUT_WR) and can only receive data. */
		cli->flags |= HTTP_SRV_CLI_F_HALF_CLOSED;
		cli->resp_p_flags |= HTTP_SRV_RESP_P_F_CONN_CLOSE;
	}

	if (NULL != cli->req.data) { /* Header allready received in prev call, continue receve data. */
		if (IO_TASK_CB_CONTINUE == action && 0 != IO_BUF_TR_SIZE_GET(buf))
			goto continue_recv; /* Continue receive request data. */
		goto req_received; /* Have HTTP headers and (all data / OEF).  */
	}

	/* Analize HTTP header. */
	ptm = mem_find(0, buf->data, buf->used, CRLFCRLF, 4);
	if (NULL == ptm) { /* No HTTP headers end found. */
		if (IO_TASK_CB_CONTINUE != action) { /* Cant receive more, drop. */
drop_cli_without_hdr:
			if (0 != LOG_IS_ENABLED()) {
				ss_to_str_addr_port(&cli->addr, straddr, sizeof(straddr), NULL);
				LOG_INFO_FMT("error: no http header, client ip: %s", straddr);
			}
			srv->stat.http_errors ++;
			http_srv_cli_free(cli);
			return (IO_TASK_CB_NONE);
		}
continue_recv:
		/* Realloc buf if needed. */
		if (0 != IO_BUF_FREE_SIZE(buf))
			return (IO_TASK_CB_CONTINUE); /* Continue receive. */
		/* Not enough buf space, try realloc more. */
		if (buf->size >= srv->s.rcv_io_buf_max_size)
			goto drop_cli_without_hdr; /* Request too big. */
		error = io_buf_realloc(&cli->rcv_buf, srv->s.rcv_io_buf_max_size);
		if (0 == error)
			goto err_out;
		io_task_buf_set(iotask, cli->rcv_buf);
		return (IO_TASK_CB_CONTINUE); /* Continue receive. */
	}
	/* CRLFCRLF - end headers marker found. */
	cli->req.hdr = buf->data;
	cli->req.hdr_size = (ptm - buf->data);
	cli->req.data = (ptm + 4);

	/* Parse request line. */
	if (0 != http_parse_req_line(cli->req.hdr, cli->req.hdr_size, 0, &cli->req.line)) {
		if (0 != LOG_IS_ENABLED()) {
			ss_to_str_addr_port(&cli->addr, straddr, sizeof(straddr), NULL);
			LOG_INFO_FMT("http_parse_req_line(): %s", straddr);
		}
		error = 400;
drop_cli_with_http_err:
		io_task_stop(iotask);
		http_srv_snd_err(cli, error, NULL, 0);
		return (IO_TASK_CB_NONE);
	}

	/* Do security cheks. */
	if (0 != http_req_sec_chk(cli->req.hdr, cli->req.hdr_size,
	    cli->req.line.method_code)) {
		/* Something wrong in headers. */
		if (0 != LOG_IS_ENABLED()) {
			ss_to_str_addr_port(&cli->addr, straddr, sizeof(straddr), NULL);
			LOG_INFO_FMT("http_req_sec_chk(): %s !!!", straddr);
		}
		srv->stat.insecure_requests ++;
		error = 400;
		goto drop_cli_with_http_err;
	}

	/* Request methods additional handling. */
	switch (cli->req.line.method_code) {
	case HTTP_REQ_METHOD_GET:
	case HTTP_REQ_METHOD_SUBSCRIBE:
		cli->req.data_size = 0; /* No data in get requests. */
		break;
	case HTTP_REQ_METHOD_POST:
		if (0 != http_hdr_val_get(cli->req.hdr, cli->req.hdr_size,
		    (uint8_t*)"content-length", 14, &ptm, &tm)) {
			error = 411; /* Length Required. */
			goto drop_cli_with_http_err;
		}
		cli->req.data_size = UStr8ToUNum(ptm, tm);
		tm = (buf->used - (cli->req.data - buf->data));
		if (cli->req.data_size <= tm) /* All data received. */
			break;
		if (cli->req.data_size >= srv->s.rcv_io_buf_max_size) {
			error = 413; /* Request Entity Too Large. */
			goto drop_cli_with_http_err;
		}
		/* Need receive nore data. */
		if (IO_TASK_CB_CONTINUE != action ||
		    0 != (HTTP_SRV_CLI_F_HALF_CLOSED & cli->flags)) { /* But we cant! */
			error = 400; /* Bad request. */
			goto drop_cli_with_http_err;
		}
		io_task_flags_del(iotask, IO_TASK_F_CB_AFTER_EVERY_READ);
		IO_BUF_TR_SIZE_SET(buf, (cli->req.data_size - tm));
		if (IO_BUF_FREE_SIZE(buf) < IO_BUF_TR_SIZE_GET(buf)) { /* Reallocate buf. */
			error = io_buf_realloc(&cli->rcv_buf, 
			    ((32 + IO_BUF_TR_SIZE_GET(buf)) - IO_BUF_FREE_SIZE(buf)));
			if (0 != error)
				goto err_out;
			io_task_buf_set(iotask, cli->rcv_buf);
		}
		//LOGD_EV_FMT("tm = %zu, buf->transfer_size = %zu...", tm, IO_BUF_TR_SIZE_GET(buf));
		goto continue_recv;
		break;
	case HTTP_REQ_METHOD_UNKNOWN: /* Not Implemented */
		error = 501; /* Not Implemented. */
		goto drop_cli_with_http_err;
		break;
	}
	
req_received: /* Full request received! */
	io_task_stop(iotask);
	if (0 != IO_BUF_FREE_SIZE(buf))
		(*((uint8_t*)IO_BUF_FREE_GET(buf))) = 0;
	LOGD_EV_FMT("req in: size=%zu, req line size = %zu, hdr_size = %zu"
	    "\n==========================================="
	    "\n%s"
	    "\n===========================================",
	    buf->used, cli->req.line.line_size, cli->req.hdr_size, buf->data);

	srv->stat.requests[cli->req.line.method_code] ++;
	srv->stat.requests_total ++;

	/* Process some headers. */
	/* Process 'connection' header value. */
	if (0 == (HTTP_SRV_REQ_P_F_CONNECTION & srv->s.req_p_flags))
		goto skeep_connection_hdr;
	if (0 != http_hdr_val_get(cli->req.hdr, cli->req.hdr_size,
	    (uint8_t*)"connection", 10, &ptm, &tm)) {
		if (HTTP_VER_1_0 == cli->req.line.proto_ver) {
			cli->req.flags |= HTTP_SRV_RD_F_CONN_CLOSE;
		}
		goto skeep_connection_hdr;
	}
	if (0 == buf_cmpi(ptm, tm, "close", 5)) {
		cli->req.flags |= HTTP_SRV_RD_F_CONN_CLOSE;
	}
skeep_connection_hdr:
	
	/* Process 'host' header value. */
	if (0 == (HTTP_SRV_REQ_P_F_HOST & srv->s.req_p_flags))
		goto skeep_host_hdr;
	if (0 != http_hdr_val_get(cli->req.hdr, cli->req.hdr_size,
	    (uint8_t*)"host", 4, &cli->req.host, &cli->req.host_size)) { /* No "host" hdr. */
		if (HTTP_VER_1_0 == cli->req.line.proto_ver)
			cli->req.flags |= HTTP_SRV_RD_F_HOST_IS_LOCAL;
		goto skeep_host_hdr;
	}
	/* Is 'host' from request line and from header euqual? */
	if (NULL != cli->req.line.host) {
		if (0 != buf_cmp(cli->req.host, cli->req.host_size,
		    cli->req.line.host, cli->req.line.host_size)) {
			if (0 != LOG_IS_ENABLED()) {
				ss_to_str_addr_port(&cli->addr, straddr, sizeof(straddr), NULL);
				cli->req.host[cli->req.host_size] = 0;
				cli->req.line.host[cli->req.line.host_size] = 0;
				LOG_INFO_FMT("%s: host in request line: \"$s\" "
				    "does not euqual host in headers: \"$s\"",
				    cli->req.line.host, cli->req.host, straddr);
			}
			srv->stat.insecure_requests ++;
			http_srv_snd_err(cli, 400, NULL, 0);
			return (IO_TASK_CB_NONE);
		}
	}
	if (0 == str_addr_port_to_ss((const char*)cli->req.host,
	    cli->req.host_size, &addr)) { /* Binary host address. */
		/* Is connection to loopback from ext host? */
		if (0 != sa_is_addr_loopback(&addr) && /* To loopback */
		    0 == sa_is_addr_loopback(&cli->addr)) { /* From net */
conn_from_net_to_loopback:
			if (0 != LOG_IS_ENABLED()) {
				ss_to_str_addr_port(&cli->addr, straddr,
				    sizeof(straddr), NULL);
				LOG_INFO_FMT("HACKING ATTEMPT: %s set in host header loopback address.", straddr);
			}
			srv->stat.insecure_requests ++;
			http_srv_snd_err(cli, 403, NULL, 0);
			return (IO_TASK_CB_NONE);
		}
		host_port = sain_p_get(&addr);
		if (0 == host_port) /* Def http port. */
			host_port = HTTP_PORT;
		if (sain_p_get(&acc->addr) == host_port &&
		    (0 == hostname_list_check_any(&acc->hn_lst) ||
		    0 == hostname_list_check_any(&srv->hn_lst))) {
			cli->req.flags |= HTTP_SRV_RD_F_HOST_IS_LOCAL;
			goto skeep_host_hdr;
		}
		ptm = NULL; /* Addr info cache. */
		for (i = 0; i < srv->accept_cnt; i ++) {
			if (srv->acc[i]->addr.ss_family != addr.ss_family ||
			    sain_p_get(&srv->acc[i]->addr) != host_port) /* not equal port! */
				continue;
			if (0 == sa_is_addr_specified(&srv->acc[i]->addr)) {
				/* Binded to: 0.0.0.0 or [::]. */
				if (0 == is_host_addr_ex(&addr, (void**)&ptm))
					continue;
			} else { /* Binded to IP addr. */
				if (0 == is_addrs_euqual(&srv->acc[i]->addr, &addr))
					continue;
			}
			cli->req.flags |= HTTP_SRV_RD_F_HOST_IS_LOCAL;
			break;
		}
		is_host_addr_ex_free(ptm);
	} else { /* Text host address. */
		cli->req.flags |= HTTP_SRV_RD_F_HOST_IS_STR;
		ptm = mem_find_byte(0, cli->req.host, cli->req.host_size, ':');
		host_port = HTTP_PORT;
		if (NULL == ptm) {
			tm = cli->req.host_size;
		} else {
			ptm ++;
			tm = (ptm - cli->req.host);
			if (cli->req.host_size > tm) 
				host_port = UStr8ToUNum32(ptm, (cli->req.host_size - tm));
			tm --;
		}
		action = (0 == buf_cmpi(cli->req.host, tm, "localhost", 9));
		/* Is connection to loopback from ext host? */
		if (0 != action && 0 == sa_is_addr_loopback(&cli->addr)) /* from ext host? */
			goto conn_from_net_to_loopback;
		/* Is hostname point to this host? */
		if (sain_p_get(&acc->addr) == host_port &&
		    (0 != action ||
		    0 == hostname_list_check(&acc->hn_lst, cli->req.host, tm) ||
		    0 == hostname_list_check(&srv->hn_lst, cli->req.host, tm)))
			cli->req.flags |= HTTP_SRV_RD_F_HOST_IS_LOCAL;
	}
skeep_host_hdr:

	/* Delayed allocation buffer for answer */
	/* cli->buf != cli->rcv_buf!!!: if cb func realloc buf, then rcv_buf became invalid. */
	if (NULL == cli->buf || cli->buf == cli->rcv_buf) {
		cli->buf = io_buf_alloc(srv->s.snd_io_buf_init_size);
		if (NULL == cli->buf) { /* Allocate fail, send error. */
			/* Force 'connection: close'. */
			cli->resp_p_flags |= HTTP_SRV_RESP_P_F_CONN_CLOSE;
			cli->buf = cli->rcv_buf;
			srv->stat.errors ++;
			srv->stat.http_errors --; /* http_srv_snd_err() will increase it.*/
			http_srv_snd_err(cli, 500, NULL, 0);
			return (IO_TASK_CB_NONE);
		}
	}
	/* Reserve space for HTTP headers. */
	IO_BUF_BUSY_SIZE_SET(cli->buf, srv->s.hdrs_reserve_size);

	http_srv_cli_req_rcv_cb(cli);

	return (IO_TASK_CB_NONE);
}

void
http_srv_cli_req_rcv_cb(http_srv_cli_p cli) {
	int action;
	http_srv_p srv = cli->acc->srv;

	if (NULL != srv->on_req_rcv) { /* Call back handler. */
		action = srv->on_req_rcv(cli, cli->udata, &cli->req);
	} else {
		action = 404; /* Default action. */
	}

	/* Handle call back function return code. */
	switch (action) {
	case HTTP_SRV_CB_DESTROY:
		http_srv_cli_free(cli);
		break;
	case HTTP_SRV_CB_NONE:
		break;
	default: /* Send HTTP code. */
		http_srv_snd_err(cli, action, NULL, 0);
	}
}

#if 0



int
http_srv_auth_plugin_create(http_srv_auth_plugin_p s,
    http_srv_auth_plugin_p *plugin_ret) {
	int error;
	http_srv_auth_plugin_p plugin;
	uint8_t *ptm;

	if (NULL == s || NULL == s->on_req_rcv || NULL == s->client_init ||
	    0 == ((HTTP_SRV_AUTH_TYPE_F_AUTHORIZATION | HTTP_SRV_AUTH_TYPE_F_URI_ARGS) & s->allowed_types) ||
	    NULL == plugin_ret)
		return (EINVAL);
	plugin = zalloc((sizeof(http_srv_auth_plugin_t) + uri_arg_name_login_size +
	    uri_arg_name_password_size + ((NULL == s->plugin_init) ? data_size : 0) +
	    settings_size + 64));
	if (NULL == plugin)
		return (ENOMEM);
	ptm = (uint8_t*)(plugin + 1);
	plugin->on_req_rcv = s->on_req_rcv;
	plugin->plugin_init = s->plugin_init;
	plugin->plugin_destroy = s->plugin_destroy;
	plugin->client_init = s->client_init;
	if (NULL != s->uri_arg_name_login && 0 != s->uri_arg_name_login_size) {
		plugin->uri_arg_name_login = ptm;
		plugin->uri_arg_name_login_size = s->uri_arg_name_login_size;
		memcpy(plugin->uri_arg_name_login, s->uri_arg_name_login,
		    s->uri_arg_name_login_size);
		ptm += (s->uri_arg_name_login_size + 1);
	}
	if (NULL != s->uri_arg_name_password && 0 != s->uri_arg_name_password_size) {
		plugin->uri_arg_name_password = ptm;
		plugin->uri_arg_name_password_size = s->uri_arg_name_password_size;
		memcpy(plugin->uri_arg_name_password, s->uri_arg_name_password,
		    s->uri_arg_name_password_size);
		ptm += (s->uri_arg_name_password_size + 1);
	}
	plugin->allowed_types = s->allowed_types;
	plugin->flags = s->flags;
	if (NULL == s->plugin_init) {
		plugin->data = s->data;
		plugin->data_size = s->data_size;
		if (NULL != s->data && 0 != s->data_size) {
			ptm = ALIGNEX_PTR(ptm, sizeof(void*));
			plugin->data = ptm;
			memcpy(plugin->data, s->data, s->data_size);
			ptm += (s->data_size + 1);
		}
	} else {
		error = s->plugin_init(plugin, s->data, s->data_size);
		if (0 != error) {
			free(plugin);
			return (error);
		}
	}
	plugin->settings = s->settings;
	plugin->settings_size = s->settings_size;
	if (NULL != s->settings && 0 != s->settings_size) {
		ptm = ALIGNEX_PTR(ptm, sizeof(void*));
		plugin->settings = ptm;
		memcpy(plugin->settings, s->settings, s->settings_size);
		ptm += (s->settings_size + 1);
	}
	
	return (0);
}

void
http_srv_auth_plugin_destroy(http_srv_auth_plugin_p plugin) {

	if (NULL == plugin)
		return;
	if (NULL != plugin->plugin_destroy)
		plugin->plugin_destroy(plugin);
	free(plugin);
}

int
http_srv_auth_plugin_cli_init(http_srv_auth_plugin_p plugin, http_srv_cli_p cli) {
	int error = 0;

	if (NULL == plugin || NULL == cli || NULL != cli->auth_plugin)
		return (EINVAL);
	cli->auth_plugin = plugin;
	cli->auth_plugin_data = NULL;
	if (NULL != plugin->client_init) {
		error = plugin->client_init(cli);
		if (0 != error)
			cli->auth_plugin = NULL;
	}
	return (error);
}

void
http_srv_auth_plugin_cli_destroy(http_srv_cli_p cli) {

	if (NULL == cli)
		return;
	if (NULL != cli->auth_plugin_data) {
		if (NULL != plugin->client_destroy)
			plugin->client_destroy(cli);
	}
	cli->auth_plugin = NULL;
	cli->auth_plugin_data = NULL;
}


int
http_srv_auth_plugin_cli_handler(http_srv_cli_p cli) {
	int error;
	uint8_t *ptm, *login, *password;
	uint8_t tmbuf[512];
	size_t tm, login_size, password_size;
	char *reason_phrase;
	size_t reason_phrase_size;
	http_srv_auth_plugin_p plugin;
	struct iovec iov[1];

	LOGD_EV("...");
	if (NULL == cli || NULL == cli->auth_plugin_data)
		return (EINVAL);
	plugin = cli->auth_plugin;

	login = NULL;
	login_size = 0;
	password = NULL;
	password_size = 0;

	/* Process "Authorization" header. */
	if (0 == (plugin->allowed_types & HTTP_SRV_AUTH_TYPE_F_AUTHORIZATION))
		goto no_authorization_hdr;
	/* Extract "Authorization" field data. */
	if (0 != http_hdr_val_get(cli->req->hdr, cli->req->hdr_size,
	    (uint8_t*)"authorization", 13, &ptm, &tm))
		goto no_authorization_hdr;
	if (6 < tm && 0 == buf_cmpi(ptm, 6, "basic ", 6)) {
		ptm += 6;
		tm -= 6;
		skeep_spwsp(ptm, tm, &ptm, &tm);
		error = base64_decode(ptm, tm, (uint8_t*)tmbuf,
		    sizeof(tmbuf), &tm);
		if (0 != error)
			goto no_authorization_hdr;
		password = mem_find_byte(0, (uint8_t*)tmbuf, tm, ':');
		if (NULL == password)
			goto no_authorization_hdr;
		login = (uint8_t*)tmbuf;
		login_size = (password - login);
		password ++;
		password_size = ((login + tm) - password);
		//data->type = HTTP_SRV_CLI_AUTH_TYPE_BASIC;
		goto login_password_ok;
	} else if (7 < tm && 0 == buf_cmpi(ptm, 7, "digest ", 7)) {
		ptm += 7;
		tm -= 7;
		skeep_spwsp(ptm, tm, &ptm, &tm);
		//...
		//data->type = HTTP_SRV_CLI_AUTH_TYPE_DIGEST;
	}
no_authorization_hdr:

	/* Process login and password in uri args. */
	if (0 == (plugin->allowed_types & HTTP_SRV_AUTH_TYPE_F_URI_ARGS))
		goto no_auth_url_args;
	if (0 != http_query_val_get(cli->req->query, cli->req->query_size,
	    plugin->uri_arg_name_login, plugin->uri_arg_name_login_size,
	    &login, &login_size))
		goto no_auth_url_args;
	http_query_val_get(cli->req->query, cli->req->query_size,
	    plugin->uri_arg_name_password, plugin->uri_arg_name_password_size,
	    &password, &password_size); /* Allow empty password. */

no_auth_url_args:
#if 0
	/* Login and password not found. */
	if (0 == (plugin->flags & HTTP_SRV_AUTH_PL_F_TRY_WO_LOGIN_PWD)) {
		reason_phrase = http_get_err_descr(401, &reason_phrase_size);
		/* HTTP header. */
		iov[0].iov_base = (void*)
		    "Content-Type: text/html\r\n"
		    "Pragma: no-cache";
		iov[0].iov_len = 41;
		IO_BUF_BUSY_SIZE_SET(cli->buf, (iov[0].iov_len + 4));
		/* Data. */
		IO_BUF_PRINTF(cli->buf,
		    "<html>\r\n"
		    "	<head><title>%i %s</title></head>\r\n"
		    "	<body bgcolor=\"white\">\r\n"
		    "		<center><h1>%i %s</h1></center>\r\n"
		    "		<hr><center>"CORE_HTTP_LIB_NAME"/"CORE_HTTP_LIB_VER"</center>\r\n"
		    "	</body>\r\n"
		    "</html>\r\n",
		    401, reason_phrase, 401, reason_phrase);

		// send answer to cli
		return (http_srv_snd(cli, 401, reason_phrase, reason_phrase_size,
		    (struct iovec*)&iov, 1));
	}
#endif
login_password_ok:

	int (*http_srv_auth_plugin_cli_basic_fn)(cli, login, login_size, password, password_size);
	
}


typedef struct http_srv_auth_radius_data_s { /* Per user auth data. */
	io_buf_p	buf;		/* Used for send radius packets. */
	uint32_t	type;		/* HTTP_SRV_AUTH_TYPE_* */
	uint32_t	state;
	io_buf_t	buf_c;
	/* io_buf data... */
} http_srv_auth_rad_data_t, *http_srv_auth_rad_data_p;


int
http_srv_auth_plugin_create_radius(
    uint8_t *uri_arg_name_login, size_t uri_arg_name_login_size,
    uint8_t *uri_arg_name_password, size_t uri_arg_name_password_size,
    uint32_t allowed_types, uint32_t flags, radius_cli_p rad_cli,
    http_srv_auth_plugin_p *plugin_ret) {
	http_srv_auth_plugin_t plugin;
	
	memset(&plugin, 0, sizeof(http_srv_auth_plugin_t));

	plugin.on_req_rcv = http_srv_auth_radius_handler;
	//plugin.plugin_init;
	//plugin.plugin_destroy;
	plugin->client_init = http_srv_auth_radius_cli_init;
	plugin.client_destroy = free;
	plugin.uri_arg_name_login = uri_arg_name_login;
	plugin.uri_arg_name_login_size = uri_arg_name_login_size;
	plugin.uri_arg_name_password = uri_arg_name_password;
	plugin.uri_arg_name_password_size = uri_arg_name_password_size;
	plugin.allowed_types = allowed_types;
	plugin.flags = flags;
	plugin.data = rad_cli;
	//plugin.data_size;
	//plugin.settings;
	//plugin.settings_size;
	return (http_srv_auth_plugin_create(&plugin, plugin_ret))
}

int
http_srv_auth_radius_cli_init(http_srv_cli_p cli) {
	http_srv_auth_rad_data_p data;

	if (NULL == cli || NULL == cli->auth_plugin || NULL != cli->auth_plugin_data)
		return (EINVAL);
	data = zalloc((sizeof(http_srv_auth_rad_data_t) +
	    RADIUS_PKT_MAX_SIZE + sizeof(void*)));
	if (NULL == data)
		return (ENOMEM);
	data->buf = io_buf_init_mem(&data->buf_c, RADIUS_PKT_MAX_SIZE);
	cli->auth_plugin_data = data;

	return (0);
}

int
http_srv_auth_radius_handler(http_srv_cli_p cli, uint8_t *login, size_t login_size,
    uint8_t *password, size_t password_size) {
	int error;
	uint8_t *ptm;
	size_t tm;
	http_srv_auth_plugin_p plugin;
	http_srv_auth_rad_data_p data;
	radius_cli_p rad_cli;
	io_buf_p buf;
	rad_pkt_hdr_p pkt;

	LOGD_EV("...");
	if (NULL == cli || NULL == cli->auth_plugin_data)
		return (EINVAL);
	plugin = cli->auth_plugin;
	rad_cli = (radius_cli_p)plugin->data;
	data = (http_srv_auth_rad_data_p)cli->auth_plugin_data;
	buf = data->buf;
	pkt = (rad_pkt_hdr_p)buf->data;

	error = radius_pkt_init(pkt, buf->size, &buf->used,
	    RADIUS_PKT_TYPE_ACCOUNTING_REQUEST, 0, NULL);
	if (0 != error) {
		LOG_ERR(error, "radius_pkt_init()");
		return (error);
	}

	if (NULL != login && 0 != login_size) { /* 1: login */
		error = radius_pkt_attr_add(pkt, buf->size, &buf->used,
		    RADIUS_ATTR_TYPE_USER_NAME, login_size, login, NULL);
	}
	if (NULL != password && 0 != password_size) { /* 2: password */
		error = radius_pkt_attr_add(pkt, buf->size, &buf->used,
		    RADIUS_ATTR_TYPE_USER_PASSWORD, password_size, password, NULL);
	}
	/* 6: 1 */
	error = radius_pkt_attr_add_uint32(pkt, buf->size, &buf->used,
	    RADIUS_ATTR_TYPE_SERVICE_TYPE, RADIUS_A_T_SERVICE_TYPE_LOGIN, NULL);
	/* 14 / 98 - auto select. */
	error = radius_pkt_attr_add_addr(pkt, buf->size, &buf->used,
	    RADIUS_ATTR_TYPE_LOGIN_IP_HOST, RADIUS_ATTR_TYPE_LOGIN_IPV6_HOST,
	    &cli->addr, NULL);
	/* 61: 5 */
	error = radius_pkt_attr_add_uint32(pkt, buf->size, &buf->used,
	    RADIUS_ATTR_TYPE_NAS_PORT_TYPE, RADIUS_A_T_NAS_PORT_TYPE_VIRTUAL, NULL);
	/* Implementation Specific attributes. */
	/* 224: URI path. */
	error = radius_pkt_attr_add(pkt, buf->size, &buf->used,
	    224, cli->req->line.abs_path_size, cli->req->line.abs_path, NULL);
	/* 225: "User-Agent". */
	if (0 == http_hdr_val_get(cli->req->hdr, cli->req->hdr_size,
	    (uint8_t*)"user-agent", 10, &ptm, &tm)) {
		error = radius_pkt_attr_add(pkt, buf->size, &buf->used,
		    225, tm, ptm, NULL);
	}

	error = radius_client_query(rad_cli,
	    io_task_thrpt_get(cli->iotask),
	    RADIUS_CLIENT_QUERY_ID_AUTO, buf,
	    http_srv_radius_cli_auth_cb, cli, NULL);
	if (0 != error) {
		LOG_ERR(error, "radius_client_query()");
		return (error);
	}
	return (0);
}

void http_srv_radius_cli_auth_cb(radius_cli_query_p query, rad_pkt_hdr_p pkt,
    int error, io_buf_p buf, void *arg) {
	http_srv_cli_p cli = (http_srv_cli_p)arg;
	http_srv_auth_plugin_p plugin;
	http_srv_auth_rad_data_p data;
	struct iovec iov[1];
	uint8_t *ptm;
	size_t offset, tm;
	uint8_t tmbuf[1024];

	LOGD_EV("...");
	if (NULL == cli || NULL == cli->auth_plugin_data)
		return;
	plugin = cli->auth_plugin;
	data = (http_srv_auth_rad_data_p)cli->auth_plugin_data;

	if (0 != error) {
		cli->resp_p_flags |= HTTP_SRV_RESP_P_F_CONN_CLOSE;
		http_srv_snd_err(cli, 500, NULL, 0); /* Internal Server Error. */
		LOG_ERR(error, "http_srv_radius_cli_auth_cb()");
		return;
	}
	switch (pkt->code) {
	case RADIUS_PKT_TYPE_ACCESS_ACCEPT:
		LOGD_EV("RADIUS_PKT_TYPE_ACCESS_ACCEPT...");
		cli->flags |= HTTP_SRV_CLI_F_AUTHORIZED;
		http_srv_cli_req_rcv_cb(cli);
		break;
	case RADIUS_PKT_TYPE_ACCESS_REJECT:
		LOGD_EV("RADIUS_PKT_TYPE_ACCESS_REJECT...");
		//cli->resp_p_flags |= HTTP_SRV_RESP_P_F_CONN_CLOSE;
		http_srv_snd_err(cli, 401, NULL, 0); /* Unauthorized. - Retry */
		return;
		break;
	case RADIUS_PKT_TYPE_ACCESS_CHALLENGE:
		LOGD_EV("RADIUS_PKT_TYPE_ACCESS_CHALLENGE...");
		iov[0].iov_base = (void*)tmbuf;
		memcpy(iov[0].iov_base, "WWW-Authenticate: Basic realm=\"", 31);
		iov[0].iov_len = 31;

		error = radius_pkt_attr_get_data_to_buf(pkt, 0, 0,
		    RADIUS_ATTR_TYPE_REPLY_MESSAGE,
		    (((uint8_t*)iov[0].iov_base) + iov[0].iov_len),
		    (sizeof(tmbuf) - (iov[0].iov_len + 4)), &tm);
		iov[0].iov_len += tm;
		memcpy((((uint8_t*)iov[0].iov_base) + iov[0].iov_len), "\"", 2);
		iov[0].iov_len += 1;


		http_srv_snd(cli, 401, NULL, 0, (struct iovec*)&iov, 1);
		break;
	}
}
#endif



/* http answer to cli is sended, work done. */
static int
http_srv_snd_done_cb(io_task_p iotask __unused, int error, io_buf_p buf __unused,
    int eof, size_t transfered_size __unused, void *arg) {
	http_srv_cli_p cli = (http_srv_cli_p)arg;
	http_srv_p srv;
	char straddr[STR_ADDR_LEN];
	int action;
	size_t tm;

	LOGD_EV("...");

	srv = cli->acc->srv;
	if (0 != error) { /* Fail! :( */
		if (0 != LOG_IS_ENABLED()) {
			ss_to_str_addr_port(&cli->addr, straddr,
			    sizeof(straddr), NULL);
			LOG_ERR_FMT(error, "client: %s", straddr);
		}
		switch (error) {
		case 0:
			break;
		case ETIMEDOUT:
			srv->stat.timeouts ++;
			break;
		default:
			srv->stat.errors ++;
			break;
		}
		http_srv_cli_free(cli);
		return (IO_TASK_CB_NONE);
	}

	if (0 != eof) { /* Client call shutdown(, SHUT_WR) and can only receive data. */
		cli->flags |= HTTP_SRV_CLI_F_HALF_CLOSED;
	}

	if (NULL != srv->on_rep_snd) { /* Call back handler. */
		action = srv->on_rep_snd(cli, cli->udata);
	} else {
		action = HTTP_SRV_CB_NONE;
	}
	if (0 != (HTTP_SRV_CLI_F_HALF_CLOSED & cli->flags) ||
	    0 != (HTTP_SRV_RESP_P_F_CONN_CLOSE & cli->resp_p_flags) ||
	    0 != (HTTP_SRV_RD_F_CONN_CLOSE & cli->req.flags))
		action = HTTP_SRV_CB_DESTROY; /* Force destroy. */

	/* Handle call back function return code. */
	if (HTTP_SRV_CB_DESTROY == action) { /* Free resourses */
		http_srv_cli_free(cli);
		return (IO_TASK_CB_NONE);
	}
	/* Reuse connection. */
	/* Move data to buf start. */
	cli->req.data += cli->req.data_size; /* Move pointer to next request. */
	tm = (cli->rcv_buf->used - (cli->req.data - cli->rcv_buf->data));
	memmove(cli->rcv_buf->data, cli->req.data, tm);
	/* Re init client. */
	memset(&cli->req, 0, sizeof(http_srv_req_t));
	cli->resp_p_flags = 0;
	/* Receive next http request. */
	IO_BUF_BUSY_SIZE_SET(cli->rcv_buf, tm);
	IO_BUF_MARK_TRANSFER_ALL_FREE(cli->rcv_buf);
	/* Shedule data receive / Receive http request / Process next. */
	error = io_task_start_ex(0, cli->iotask,
	    THRP_EV_READ, 0, srv->s.rcv_timeout, 0, cli->rcv_buf,
	    http_srv_recv_done_cb);
	if (0 != error) { /* Error. */
		srv->stat.errors ++;
		http_srv_cli_free(cli);
		LOG_ERR_FMT(error, "client ip: %s", straddr);
	}

	return (IO_TASK_CB_NONE);
}


int
http_srv_gen_resp_hdrs(uint32_t http_ver, uint32_t status_code,
    uint32_t resp_p_flags, const char *reason_phrase, size_t reason_phrase_size,
    const char *http_server, size_t http_server_size,
    uint64_t content_size, char *buf, size_t buf_size, size_t *buf_size_ret) {
	size_t hdrs_size;

	if (NULL == buf || 0 == buf_size)
		return (EINVAL);
	if (NULL == reason_phrase || 0 == reason_phrase_size)
		reason_phrase = http_get_err_descr(status_code, &reason_phrase_size);
	if (NULL == http_server || 0 == http_server_size)
		resp_p_flags &= ~HTTP_SRV_RESP_P_F_SERVER; /* Unset flag. */
	if (buf_size < (9 + 8 + reason_phrase_size + 
	    ((0 != (HTTP_SRV_RESP_P_F_SERVER & resp_p_flags)) ? (10 + http_server_size) : 0) +
	    ((0 != (HTTP_SRV_RESP_P_F_CONTENT_SIZE & resp_p_flags)) ? 32 : 0) +
	    ((0 != (HTTP_SRV_RESP_P_F_CONN_CLOSE & resp_p_flags)) ? 19 : 0)))
		return (ENOMEM); /* Not enough space in buf. */
	buf_size --;
	/* HTTP header. */
	if (HTTP_VER_1_1 == http_ver) { /* HTTP/1.1 client. */
		memcpy(buf, "HTTP/1.1 ", 9);
	} else { /* HTTP/1.0 client. */
		memcpy(buf, "HTTP/1.0 ", 9);
	}
	hdrs_size = 9;
	hdrs_size += snprintf((buf + hdrs_size), (buf_size - hdrs_size),
	    "%"PRIu32" ", status_code);
	memcpy((buf + hdrs_size), reason_phrase, reason_phrase_size);
	hdrs_size += reason_phrase_size;
	
	if (0 != (resp_p_flags & HTTP_SRV_RESP_P_F_SERVER)) {
		memcpy((buf + hdrs_size), "\r\nServer: ", 10);
		hdrs_size += 10;
		memcpy((buf + hdrs_size), http_server, http_server_size);
		hdrs_size += http_server_size;
	}
	if (0 != (resp_p_flags & HTTP_SRV_RESP_P_F_CONTENT_SIZE)) {
		hdrs_size += snprintf((buf + hdrs_size), (buf_size - hdrs_size),
		    "\r\nContent-Size: %"PRIu64, content_size);
	}
	if (0 != (HTTP_SRV_RESP_P_F_CONN_CLOSE & resp_p_flags)) { /* Conn close. */
		memcpy((buf + hdrs_size), "\r\nConnection: close", 19);
		hdrs_size += 19;
	}
	buf[hdrs_size] = 0;
	if (NULL != buf_size_ret)
		(*buf_size_ret) = hdrs_size;
	return (0);
}


/* Offset must pont to data start, size = data offset + data size. */
int
http_srv_snd(http_srv_cli_p cli, uint32_t status_code,
    const char *reason_phrase, size_t reason_phrase_size,
    struct iovec *custom_hdrs, size_t custom_hdrs_count) {
	int error;
	http_srv_p srv;
	uint8_t	*wr_pos;
	char hdrs[1024];
	size_t hdrs_size, data_size, i;
	ssize_t ios = 0;
	struct iovec iov[IOV_MAX];
	struct msghdr mhdr;

	if (NULL == cli)
		return (EINVAL);
	srv = cli->acc->srv;
	if (404 == status_code)
		srv->stat.unhandled_requests ++;
	if (cli->buf->used < cli->buf->offset ||
	    HTTP_SRV_MAX_CUSTOM_HDRS_CNT < custom_hdrs_count) { /* Limit custom hdrs count. */
		error = EINVAL;
		goto err_out;
	}
	data_size = (cli->buf->used - cli->buf->offset);
	if (0 != (HTTP_SRV_CLI_F_HALF_CLOSED & cli->flags) ||
	    0 != (HTTP_SRV_RD_F_CONN_CLOSE & cli->req.flags)) {
		cli->resp_p_flags |= HTTP_SRV_RESP_P_F_CONN_CLOSE;
	}

	/* HTTP header. */
	error = http_srv_gen_resp_hdrs(cli->req.line.proto_ver, status_code,
	    cli->resp_p_flags, reason_phrase, reason_phrase_size, srv->s.http_server,
	    srv->s.http_server_size, data_size, (char*)hdrs, sizeof(hdrs),
	    &hdrs_size);
	if (0 != error)
		goto err_out;
	/* Custom headers pre process. */
	if (NULL == custom_hdrs)
		custom_hdrs_count = 0;
	LOGD_EV_FMT("\r\n%s", hdrs);
	//LOGD_EV(custom_hdrs);
	//LOGD_EV((cli->buf->data + cli->buf->offset));
	//LOGD_EV_FMT("offset: %zu, used: %zu", cli->buf->offset, cli->buf->used);

	/* Send data... */
	/* Try "zero copy" send first. */
	memset(&mhdr, 0, sizeof(mhdr));
	mhdr.msg_iov = iov;
	mhdr.msg_iovlen ++;
	iov[0].iov_base = hdrs;
	iov[0].iov_len = hdrs_size;
	for (i = 0; i < custom_hdrs_count; i ++) { /* Add custom headers. */
		if (NULL == custom_hdrs[i].iov_base || 0 == custom_hdrs[i].iov_len)
			continue; /* Skeep empty header part. */
		iov[mhdr.msg_iovlen].iov_base = (void*)"\r\n";
		iov[mhdr.msg_iovlen].iov_len = 2;
		memcpy(&iov[(1 + mhdr.msg_iovlen)], &custom_hdrs[i], sizeof(struct iovec));
		mhdr.msg_iovlen += 2;
		hdrs_size += (2 + custom_hdrs[i].iov_len); /* Hdr size + CRLF count */
	}
	iov[mhdr.msg_iovlen].iov_base = (void*)"\r\n\r\n";
	iov[mhdr.msg_iovlen].iov_len = 4;
	hdrs_size += 4;
	iov[(1 + mhdr.msg_iovlen)].iov_base = IO_BUF_OFFSET_GET(cli->buf);
	iov[(1 + mhdr.msg_iovlen)].iov_len = data_size;
	mhdr.msg_iovlen += 2;
	//LOGD_EV_FMT("mhdr.msg_iovlen: %zu, data_size: %zu", mhdr.msg_iovlen, data_size);
	/* Try send (write to socket buf).*/
	ios = sendmsg(io_task_ident_get(cli->iotask), &mhdr,
	    (MSG_DONTWAIT | MSG_NOSIGNAL));
	if (-1 == ios) {
		error = errno;
		goto err_out;
	}
	if ((hdrs_size + data_size) == (size_t)ios) { /* OK, all done. */
		http_srv_snd_done_cb(cli->iotask, 0, cli->buf, 0, ios, cli);
		return (0);
	}
	/* Not all data send. */
	if (hdrs_size > (size_t)ios) { /* Not all headers send. */
		/* Copy http headers to buffer before data. */
		hdrs_size -= ios;
		IO_BUF_TR_SIZE_SET(cli->buf, (hdrs_size + data_size));
		if (hdrs_size > cli->buf->offset) { /* Worst case :( */
			/* Not enough space before data, move data. */
			/* Check buf free space!!! */
			if ((hdrs_size - cli->buf->offset) >
			    IO_BUF_FREE_SIZE(cli->buf)) {
				error = ENOMEM;
				LOG_ERR(error, "Not enough space in socket buffer and in io_buf for HTTP headers, increace skt_snd_buf or/and hdrs_reserve_size.");
				goto err_out;
			}
			memmove((cli->buf->data + hdrs_size),
			    IO_BUF_OFFSET_GET(cli->buf), data_size);
			cli->buf->used = (hdrs_size + data_size);
			cli->buf->offset = 0;
		} else {
			IO_BUF_OFFSET_DEC(cli->buf, hdrs_size);
		}
		wr_pos = IO_BUF_OFFSET_GET(cli->buf);
		for (i = 0; i < (size_t)(mhdr.msg_iovlen - 1); i ++) {
			if ((size_t)ios > iov[i].iov_len) { /* Skeep sended. */
				ios -= iov[i].iov_len;
				continue;
			}
			if (0 != ios) { /* Part of iov buf. */
				iov[i].iov_base = (void*)(((size_t)iov[i].iov_base) + ios);
				iov[i].iov_len -= ios;
				ios = 0;
			}
			memcpy(wr_pos, iov[i].iov_base, iov[i].iov_len);
			wr_pos += iov[i].iov_len;
		}
	} else { /* All headers sended, send body. */
		IO_BUF_OFFSET_INC(cli->buf, (ios - hdrs_size));
		IO_BUF_TR_SIZE_SET(cli->buf, (cli->buf->used - cli->buf->offset));
	}
	// send answer to cli
	error = io_task_start(cli->iotask, THRP_EV_WRITE, 0, srv->s.snd_timeout,
	    0, cli->buf, http_srv_snd_done_cb);
	if (0 == error) /* No Error. */
		return (0);

err_out:
	/* Error. */
	http_srv_snd_done_cb(cli->iotask, error, cli->buf, 0, ios, cli);
	LOG_ERR(error, "err_out");
	return (error);
}

int
http_srv_snd_err(http_srv_cli_p cli, uint32_t status_code,
    const char *reason_phrase, size_t reason_phrase_size) {
	struct iovec iov[1];

	LOGD_EV_FMT("return code: %i", status_code);
	if (200 == status_code)
		return (http_srv_snd(cli, status_code,
		    reason_phrase, reason_phrase_size, NULL, 0));

	cli->acc->srv->stat.http_errors ++;
	if (NULL == reason_phrase)
		reason_phrase = http_get_err_descr(status_code, &reason_phrase_size);
	/* HTTP header. */
	iov[0].iov_base = (void*)
	    "Content-Type: text/html\r\n"
	    "Pragma: no-cache";
	iov[0].iov_len = 41;
	IO_BUF_BUSY_SIZE_SET(cli->buf, (iov[0].iov_len + 4));
	/* Data. */
	IO_BUF_PRINTF(cli->buf,
	    "<html>\r\n"
	    "	<head><title>%i %s</title></head>\r\n"
	    "	<body bgcolor=\"white\">\r\n"
	    "		<center><h1>%i %s</h1></center>\r\n"
	    "		<hr><center>"CORE_HTTP_LIB_NAME"/"CORE_HTTP_LIB_VER"</center>\r\n"
	    "	</body>\r\n"
	    "</html>\r\n",
	    status_code, reason_phrase, status_code, reason_phrase);

	// send answer to cli
	return (http_srv_snd(cli, status_code, reason_phrase, reason_phrase_size,
	    (struct iovec*)&iov, 1));
}
