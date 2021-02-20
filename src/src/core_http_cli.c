/*-
 * Copyright (c) 2015  - 2016 Rozhuk Ivan <rozhuk.im@gmail.com>
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
#	define _GNU_SOURCE /* See feature_test_macros(7) */
#	define __USE_GNU 1
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

#include "mem_helpers.h"
#include "StrToNum.h"
#include "HTTP.h"

#include "macro_helpers.h"
#include "core_io_task.h"
#include "core_io_net.h"
#include "core_net_helpers.h"
#include "core_info.h"
#include "core_hostname.h"
#include "core_log.h"
#include "core_http_cli.h"



#define CORE_HTTP_CLI_LIB_NAME		"HTTP core client by Rozhuk Ivan"
#define CORE_HTTP_CLI_LIB_VER		"1.0"

#define HTTP_CLI_ALLOC_CNT		8




typedef struct http_client_s {
	http_cli_cb	ccb;	/* Client callbacks. */
	void		*udata;	/* Associated data. */
	http_srv_settings_t s;	/* Settings. */
} http_cli_t;



typedef struct http_client_connection_s {
	io_task_p	iotask;		/* recv/send from/to client, and socket container. */
	io_buf_t	snd_hdrs_buf;	/* Used for send http request and responce. */
	io_buf_t	snd_data_buf;	/* Used for send http request and responce. */
	io_buf_t	rcv_hdrs_buf;	/* Used for send http request and responce. */
	io_buf_t	rcv_data_buf;	/* Used for send http request and responce. */
	http_cli_resp_t	resp;		/* Parsed responce data. */
	http_cli_cb	ccb;		/* Custom client callbacks. */
	void		*udata;		/* Client associated data. */
	uint32_t	state;	/* Client connection state. */
	uint32_t	flags;		/* Flags: HTTP_CLI_CONN_F_*. */
	uint32_t	resp_p_flags;	/* Responce processing flags HTTP_CLI_RESP_P_F_*. */
	host_addr_p	haddr;		/* Hostname and addrs (with port). */
	size_t		haddr_idx;	/* Index of current IP addr. */
	thrpt_p		thrpt;
	http_cli_p	cli;
} http_cli_conn_t;



static int	http_srv_new_conn_cb(io_task_p iotask, int error, uintptr_t skt,
		    struct sockaddr_storage *addr, void *arg);
static int	http_cli_snd_done_cb(io_task_p iotask, int error,
		    io_buf_p buf, int eof, size_t transfered_size, void *arg);
static int	http_cli_recv_done_cb(io_task_p iotask, int error,
		    io_buf_p buf, int eof, size_t transfered_size, void *arg);




void
http_cli_def_settings(int add_os_ver, const char *app_ver, int add_lib_ver,
    http_cli_settings_p s_ret) {
	size_t tm;

	if (NULL == s_ret)
		return;
	/* Init. */
	mem_bzero(s_ret, sizeof(http_cli_settings_t));
	io_net_skt_opts_init(HTTP_CLI_S_SKT_OPTS_INT_MASK,
	    HTTP_CLI_S_SKT_OPTS_INT_VALS, &s_ret->skt_opts);
	s_ret->skt_opts.mask |= SO_F_NONBLOCK;
	s_ret->skt_opts.bit_vals |= SO_F_NONBLOCK;

	/* Default settings. */
	s_ret->skt_opts.mask |= HTTP_CLI_S_DEF_SKT_OPTS_MASK;
	s_ret->skt_opts.bit_vals |= HTTP_CLI_S_DEF_SKT_OPTS_VALS;
	s_ret->skt_opts.rcv_timeout = HTTP_CLI_S_DEF_SKT_OPTS_RCVTIMEO;
	s_ret->skt_opts.snd_timeout = HTTP_CLI_S_DEF_SKT_OPTS_SNDTIMEO;
	s_ret->hdrs_reserve_size = HTTP_CLI_S_DEF_HDRS_SIZE;
	s_ret->snd_io_buf_init_size = HTTP_CLI_S_DEF_SND_IO_BUF_INIT;
	s_ret->rcv_io_buf_init_size = HTTP_CLI_S_DEF_RCV_IO_BUF_INIT;
	s_ret->rcv_io_buf_max_size = HTTP_CLI_S_DEF_RCV_IO_BUF_MAX;
	s_ret->req_p_flags = HTTP_CLI_S_DEF_REQ_P_FLAGS;
	s_ret->resp_p_flags = HTTP_CLI_S_DEF_RESP_P_FLAGS;

	/* 'OS/version UPnP/1.1 product/version' */
	s_ret->http_user_agent_size = 0;
	if (0 != add_os_ver) {
		if (0 == core_info_get_os_ver("/", 1, s_ret->http_user_agent,
		    (sizeof(s_ret->http_user_agent) - 1), &tm)) {
			s_ret->http_user_agent_size = tm;
		} else {
			memcpy(s_ret->http_user_agent, "Generic OS/1.0", 15);
			s_ret->http_user_agent_size = 14;
		}
	}
	if (NULL != app_ver) {
		s_ret->http_user_agent_size += snprintf(
		    (s_ret->http_user_agent + s_ret->http_user_agent_size),
		    (sizeof(s_ret->http_user_agent) - s_ret->http_user_agent_size),
		    "%s%s",
		    ((0 != s_ret->http_user_agent_size) ? " " : ""), app_ver);
	}
	if (0 != add_lib_ver) {
		s_ret->http_user_agent_size += snprintf(
		    (s_ret->http_user_agent + s_ret->http_user_agent_size),
		    (sizeof(s_ret->http_user_agent) - s_ret->http_user_agent_size),
		    "%s"CORE_HTTP_LIB_NAME"/"CORE_HTTP_LIB_VER,
		    ((0 != s_ret->http_user_agent_size) ? " " : ""));
	}
	s_ret->http_user_agent[s_ret->http_user_agent_size] = 0;
}



int
http_cli_create(http_cli_cb ccb, http_cli_settings_p s, void *udata,
    http_cli_p *cli_ret) {
	int error;
	http_cli_p cli = NULL;

	LOGD_EV("...");
	
	if (NULL == cli_ret) {
		error = EINVAL;
		goto err_out;
	}
	if (NULL != s) { /* Validate settings. */
		if ((s->hdrs_reserve_size + HTTP_CLI_S_DEF_HDRS_SIZE) >
		    s->snd_io_buf_init_size ||
		    sizeof(s->http_user_agent) <= s->http_user_agent_size) {
			error = EINVAL;
			goto err_out;
		}
	}
	/* Create. */
	cli = zalloc(sizeof(http_cli_t));
	if (NULL == cli) {
		error = ENOMEM;
		goto err_out;
	}
	cli->ccb = ccb;
	cli->udata = udata;
	if (NULL == s) { /* Apply default settings */
		http_cli_def_settings(1, NULL, 1, &cli->s);
	} else {
		memcpy(&cli->s, s, sizeof(http_cli_settings_t));
	}
	/* kb -> bytes, sec -> msec */
	io_net_skt_opts_cvt(IO_NET_SKT_OPTS_MULT_K, &cli->s.skt_opts);
	cli->s.hdrs_reserve_size *= 1024;
	cli->s.snd_io_buf_init_size *= 1024;
	cli->s.rcv_io_buf_init_size *= 1024;
	cli->s.rcv_io_buf_max_size *= 1024;
	cli->s.http_user_agent[cli->s.http_user_agent_size] = 0;


	(*cli_ret) = cli;
	return (0);
err_out:
	if (NULL != cli)
		free(cli);
	/* Error. */
	LOG_ERR(error, "err_out");
	return (error);
}

void
http_cli_destroy(http_cli_p cli) {
	size_t i;

	LOGD_EV("...");
	if (NULL == cli)
		return;
	mem_filld(cli, sizeof(http_cli_t));
	free(cli);
}

int
http_cli_ccb_get(http_cli_p cli, http_cli_cb *ccb) {

	if (NULL == cli || NULL == ccb)
		return (EINVAL);
	(*ccb) = cli->ccb;
	return (0);
}

int
http_cli_ccb_set(http_cli_p cli, http_cli_cb ccb) {

	if (NULL == cli || NULL == ccb)
		return (EINVAL);
	cli->ccb = ccb;
	return (0);
}

void *
http_cli_get_udata(http_cli_p cli) {

	if (NULL == cli)
		return (NULL);
	return (cli->udata);
}

int
http_cli_set_udata(http_cli_p cli, void *udata) {

	if (NULL == cli)
		return (EINVAL);
	cli->udata = udata;
	return (0);
}


int
http_cli_conn_create(http_cli_p cli, thrpt_p thrpt, http_cli_cb ccb,
    void *udata, http_cli_conn_p *cli_conn_ret) {
	http_cli_conn_p conn;
	
	if (NULL == cli || NULL == cli_conn_ret)
		return (EINVAL);
	cli_conn = zalloc(sizeof(http_cli_conn_t));
	if (NULL == cli_conn)
		return (errno);

	io_buf_init(&cli_conn->snd_hdrs_buf, IO_BUF_F_DATA_ALLOC, NULL, 0);
	io_buf_init(&cli_conn->snd_data_buf, IO_BUF_F_DATA_ALLOC, NULL, 0);
	io_buf_init(&cli_conn->rcv_hdrs_buf, IO_BUF_F_DATA_ALLOC, NULL, 0);
	io_buf_init(&cli_conn->rcv_data_buf, IO_BUF_F_DATA_ALLOC, NULL, 0);
	if (NULL != ccb) {
		cli_conn->ccb = ccb;
	} else {
		cli_conn->ccb = cli->ccb;
	}
	cli_conn->udata = udata;
	cli_conn->state = HTTP_CLI_CONN_STATE_DISCONNECTED;
	/* Map resp_p_flags. */
	cli_conn->resp_p_flags = cli->s.resp_p_flags;
	cli_conn->thrpt = thrpt;
	cli_conn->cli = cli;
	
	(*cli_conn_ret) = cli_conn;

	return (0);
}

void
http_cli_conn_free(http_cli_conn_p cli_conn) {

	if (NULL == cli_conn)
		return;
	io_task_destroy(cli_conn->iotask);
	io_buf_free(&cli_conn->snd_hdrs_buf);
	io_buf_free(&cli_conn->snd_data_buf);
	io_buf_free(&cli_conn->rcv_hdrs_buf);
	io_buf_free(&cli_conn->rcv_data_buf);
	host_addr_free(cli_conn->haddr);
	mem_filld(cli_conn, sizeof(http_cli_conn_t));
	free(cli_conn);
	
}

void
http_cli_conn_timeout_chk(http_cli_conn_p cli_conn) {


}

/* Set remonte hostname / addr to connect. */
int
http_cli_conn_host_addr_set_str(http_cli_conn_p cli_conn,
    uint8_t *host_name, size_t host_name_size) {

	if (NULL == cli_conn || NULL == host_name || 0 == host_name_size)
		return (EINVAL);
	cli_conn->haddr = host_addr_alloc(host_name, host_name_size, HTTP_PORT);
	if (NULL == cli_conn->haddr)
		return (errno);
	return (0);
}

int
http_cli_conn_host_addr_set_ss(http_cli_conn_p cli_conn,
    struct sockaddr_storage *addr) {
	int error;
	char straddr[STR_ADDR_LEN];
	size_t straddr_size;

	if (NULL == cli_conn || NULL == addr)
		return (EINVAL);
	error = sa_addr_port_to_str(addr, straddr, sizeof(straddr),
	    &straddr_size);
	if (0 != error)
		return (error);
	error = http_cli_conn_host_addr_set_str(cli_conn, straddr,
	    straddr_size);
	if (0 != error)
		return (error);
	return (host_addr_add_addr(cli_conn->haddr, addr));
}

int
http_cli_conn_host_addr_set_ha(http_cli_conn_p cli_conn,
    host_addr_p haddr) {

	if (NULL == cli_conn || NULL == haddr)
		return (EINVAL);
	cli_conn->haddr = host_addr_clone(haddr);
	if (NULL == cli_conn->haddr)
		return (errno);
	return (0);
}


/* Set connected to remonte host socket. */
/* flags - io task flags: IO_TASK_F_CLOSE_ON_DESTROY */
int
http_cli_conn_skt_set(http_cli_conn_p cli_conn, uint32_t flags,
    uintptr_t ident) {

	if (NULL == cli_conn || (uintptr_t)-1 == ident)
		return (EINVAL);
	flags &= IO_TASK_F_CLOSE_ON_DESTROY;
	flags |= IO_TASK_F_CB_AFTER_EVERY_READ;
	io_task_destroy(cli_conn->iotask);

	return (io_task_create(cli_conn->thrpt, ident, io_task_sr_handler,
	    flags, cli_conn, &cli_conn->iotask));
}

io_task_p
http_cli_conn_get_iotask(http_cli_conn_p cli_conn) {

	if (NULL == cli_conn)
		return (NULL);
	return (cli_conn->iotask);
}

io_task_p
http_cli_conn_export_iotask(http_cli_conn_p cli_conn) {
	io_task_p iotask;

	if (NULL == cli_conn)
		return (NULL);
	iotask = cli_conn->iotask;
	cli_conn->iotask = NULL;
	return (iotask);
}

int
http_cli_conn_io_task_set(http_cli_conn_p cli_conn, uint32_t flags,
    io_task_p iotask) {

	if (NULL == cli_conn || NULL == iotask)
		return (EINVAL);
	flags &= IO_TASK_F_CLOSE_ON_DESTROY; /* Filter flags. */
	flags |= IO_TASK_F_CB_AFTER_EVERY_READ; /* Add flag. */
	io_task_destroy(cli_conn->iotask);
	cli_conn->iotask = iotask;
	io_task_flags_set(iotask, flags);

	return (0);
}


int
http_cli_conn_req_head_set(http_cli_conn_p cli_conn, uint32_t req_p_flags,
    uint8_t *method, size_t method_size, uint32_t method_code,
    uint8_t *uri, size_t uri_size, uint32_t http_ver,
    uint64_t content_len, uint32_t transfer_encoding_code,
    struct iovec *custom_hdrs, size_t custom_hdrs_count) {
	int error;
	size_t i, buf_size;

	if (NULL == cli_conn ||
	    ((NULL == method || 0 == method_size) &&
	     (HTTP_REQ_METHOD_UNKNOWN == method_code || HTTP_REQ_METHOD__LAST__ < method_code)) ||
	    NULL == uri || uri_size == 0 ||
	    (HTTP_VER_1_0 != http_ver && HTTP_VER_1_1 != http_ver) ||
	    (NULL == custom_hdrs && 0 != custom_hdrs_count) ||
	    (HTTP_REQ_TE__LAST__ > transfer_encoding_code))
		return (EINVAL);

	/* Additional cheks and calc headers buf size. */
	if (NULL == method || 0 == method_size) {
		method = HTTPReqMethod[method_code];
		method_size = HTTPReqMethodSize[method_code];
	}
	if (0 == cli_conn->s.http_user_agent_size)
		req_p_flags &= ~HTTP_CLI_REQ_P_F_USER_AGENT; /* Unset flag. */
	buf_size = (method_size + 1 + uri_size + 9 + 2 + iovec_calc_size(custom_hdrs, custom_hdrs_count) + 64);
	if (0 != (HTTP_CLI_REQ_P_F_HOST & req_p_flags))
		buf_size += (6 /* "host: " */ + cli_conn->haddr->name_size + 2);
	if (0 != (HTTP_CLI_REQ_P_F_CONN_CLOSE & req_p_flags))
		buf_size += 19; /* "Connection: close\r\n" */
	if (0 != (HTTP_CLI_REQ_P_F_USER_AGENT & req_p_flags))
		buf_size += (12 /* "User-Agent: " */ + cli_conn->s.http_user_agent_size + 2);
	if (0 != (HTTP_CLI_REQ_P_F_CONTENT_LEN & req_p_flags))
		buf_size += 48; /* "Content-Length: \r\n" */
	if (HTTP_REQ_TE_UNKNOWN != transfer_encoding_code)
		buf_size += 64;

	buf_size = ALIGNEX(buf_size, 1024);
	error = io_buf_realloc(&cli_conn->snd_hdrs_buf,
	    IO_BUF_F_DATA_ALLOC, buf_size);
	if (0 != error)
		return (error);

	/* HTTP request line. */
	/* Method. */
	io_buf_copyin(&cli_conn->snd_hdrs_buf, method, method_size);
	IO_BUF_COPYIN_CSTR(&cli_conn->snd_hdrs_buf, " ");
	/* URI. */
	io_buf_copyin(&cli_conn->snd_hdrs_buf, uri, uri_size);
	/* HTTP version. */
	if (HTTP_VER_1_1 == http_ver) {
		IO_BUF_COPYIN_CSTR(&cli_conn->snd_hdrs_buf,
		    " HTTP/1.1\r\n");
	} else { /* HTTP/1.0 client. */
		IO_BUF_COPYIN_CSTR(&cli_conn->snd_hdrs_buf,
		    " HTTP/1.0\r\n");
	}
	
	/* HTTP headers. */
	/* host */
	if (0 != (HTTP_CLI_REQ_P_F_HOST & req_p_flags)) {
		IO_BUF_COPYIN_CSTR(&cli_conn->snd_hdrs_buf, "host: ");
		io_buf_copyin(&cli_conn->snd_hdrs_buf, cli_conn->haddr->name,
		    cli_conn->haddr->name_size);
		IO_BUF_COPYIN_CRLF(&cli_conn->snd_hdrs_buf);
	}
	/* Connection: close */
	if (0 != (HTTP_CLI_REQ_P_F_CONN_CLOSE & req_p_flags)) {
		IO_BUF_COPYIN_CSTR(&cli_conn->snd_hdrs_buf,
		    "Connection: close\r\n");
	}
	/* User-Agent */
	if (0 != (HTTP_CLI_REQ_P_F_HOST & req_p_flags)) {
		IO_BUF_COPYIN_CSTR(&cli_conn->snd_hdrs_buf,
		    "User-Agent: ");
		io_buf_copyin(&cli_conn->snd_hdrs_buf,
		    cli_conn->s.http_user_agent,
		    cli_conn->s.http_user_agent_size);
		IO_BUF_COPYIN_CRLF(&cli_conn->snd_hdrs_buf);
	}
	/* Content-Length */
	if (0 != (HTTP_CLI_REQ_P_F_CONN_CLOSE & req_p_flags)) {
		IO_BUF_PRINTF(&cli_conn->snd_hdrs_buf,
		    "Content-Length: %"PRIu64"\r\n",
		    content_len);
	}
	/* Transfer-Encoding */
	if (HTTP_REQ_TE_UNKNOWN != transfer_encoding_code) {
		IO_BUF_PRINTF(&cli_conn->snd_hdrs_buf,
		    "Transfer-Encoding: %s\r\n",
		    HTTPTransferEncoding[transfer_encoding_code]);
	}

	for (i = 0; i < custom_hdrs_count; i ++) { /* Add custom headers. */
		if (NULL == custom_hdrs[i].iov_base || 3 > custom_hdrs[i].iov_len)
			continue; /* Skeep empty header part. */
		io_buf_copyin(&cli_conn->snd_hdrs_buf,
		    custom_hdrs[i].iov_base,
		    custom_hdrs[i].iov_len);
		if (0 == memcmp((((uint8_t*)custom_hdrs[i].iov_base) +
		    (custom_hdrs[i].iov_len - 2)), "\r\n", 2))
			continue; /* No need to add tailing CRLF. */
		IO_BUF_COPYIN_CRLF(&cli_conn->snd_hdrs_buf);
	}
	/* Final empty line - headers end. */
	IO_BUF_COPYIN_CRLF(&cli_conn->snd_hdrs_buf);

	return (0);
}


int
http_cli_conn_req_payload_add(http_cli_conn_p cli_conn,
    uint32_t req_p_flags, uint8_t *payload, size_t payload_size) {
	int error;

	if (NULL == cli_conn)
		return (EINVAL);

	error = io_buf_realloc(&cli_conn->snd_data_buf, 0,
	    (cli_conn->snd_data_buf.used + payload_size + sizeof(void*)));
	if (0 != error)
		return (error);
	return (io_buf_copyin(&cli_conn->snd_data_buf, payload, payload_size));
}


int
http_cli_conn_req_send(http_cli_conn_p cli_conn) {
	int error;

	if (NULL == cli_conn)
		return (EINVAL);

	cli_conn->haddr_idx = 0;
	/* Try connect to server... */
	if (0 != cli_conn->haddr->count) {
		error = http_cli_conn_connet(cli_conn);
	} else {
		error = dns_resolv_hostaddr(g_data.dns_rslvr,
		    cli_conn->haddr->name, cli_conn->haddr->name_size,
		    DNS_R_F_IP_ALL, http_cli_dns_reslv_done_cb,
		    cli_conn, NULL);
	}
}


/* Connect to server... */
int
http_cli_conn_connet(http_cli_conn_p cli_conn) {
	int error;
	uintptr_t ident;

try_conn_next_addr: /* Try connect to another host address. */
	error = EADDRNOTAVAIL;
	while (cli_conn->haddr_idx < cli_conn->haddr->count) {
		error = io_net_connect(
		    &cli_conn->haddr->addrs[cli_conn->haddr_idx],
		    SOCK_STREAM, IPPROTO_TCP, (SO_F_NONBLOCK), &ident);
		cli_conn->haddr_idx ++;
		if (0 == error)
			break;
		LOG_ERR_FMT(error, "Tracker: %s",
		    cli_conn->haddr->name);
	}

	if (0 == error) {
		IO_BUF_MARK_TRANSFER_ALL_USED(&cli_conn->buf_c);
		io_task_ident_set(cli_conn->iotask, ident);
		error = io_task_start(cli_conn->iotask, THRP_EV_WRITE, 0,
			TR_HOST_CONN_SEND_TIMEOUT, 0, cli_conn->buf_c,
			(io_task_cb)io_send_http_to_tracker_done_cb);
		if (0 != error) {
			LOG_ERR_FMT(error, "Tracker: %s",
			    cli_conn->haddr->name);
			goto try_conn_next_addr;
		}
	}

	return (error);
}

/* Custom step, for user requested tracker. */
int
http_cli_dns_reslv_done_cb(dns_rslvr_task_p task __unused, int error,
    struct sockaddr_storage *addrs, size_t addrs_count, void *arg) {
	size_t i;
	http_cli_conn_p cli_conn = arg;

	LOG_ERR_FMT(error, "Tracker: %s (%s)",
	    cli_conn->haddr->name, cli_conn->descr);

	for (i = 0; i < addrs_count; i ++) {
		host_addr_add_addr(cli_conn->haddr, &addrs[i]);
	}

	error = http_cli_conn_connet(cli_conn);
	if (0 != error) /* Error. */
		io_recv_http_from_tracker_done_cb(NULL, 0, NULL, 0, 0, cli_conn);
	return (0);
}

/* Now we connected to tracker, and send to them http request */
/* http request is send to tracker, start recv reply. */
int
io_send_http_to_tracker_done_cb(io_task_p iotask, int error, io_buf_p buf __unused,
    int eof __unused, size_t transfered_size __unused, void *arg) {
	bt_tr_conn_p bt_tr_conn = arg;

	if (0 != error) { /* On error try connect to other host address. */
		io_task_ident_close(iotask);
		error = http_cli_conn_connet(bt_tr_conn); /* Retry with next addr. */
	} else { /* Request sended, receiving responce... */
		io_task_stop(iotask); /* Stop write. */

		IO_BUF_MARK_AS_EMPTY(&bt_tr_conn->buf_c);
		IO_BUF_MARK_TRANSFER_ALL_FREE(&bt_tr_conn->buf_c);
		error = io_task_start(iotask, THRP_EV_READ, 0, TR_HOST_RECV_TIMEOUT,
		    0, &bt_tr_conn->buf_c, io_recv_http_from_tracker_done_cb);
		if (0 != error) {
			bt_tr_conn->tp_stat_tr->send_error ++;
			LOG_ERR_FMT(error, "Tracker: %s (%s)",
			    bt_tr_conn->bt_tracker->haddr->name,
			    bt_tr_conn->bt_tracker->descr);
		}
	}

	if (0 != error) /* Error. */
		io_recv_http_from_tracker_done_cb(NULL, 0, NULL, 0, 0, bt_tr_conn);
	return (IO_TASK_CB_NONE);
}



























io_buf_p
http_cli_get_buf(http_cli_p cli) {

	if (NULL == cli)
		return (NULL);
	return (cli->buf);
}

int
http_cli_buf_reset(http_cli_p cli) {

	if (NULL == cli || NULL == cli->buf)
		return (EINVAL);
	IO_BUF_BUSY_SIZE_SET(cli->buf, cli->bnd->srv->s.hdrs_reserve_size);
	return (0);
}

int
http_cli_buf_realloc(http_cli_p cli, int allow_decrease, size_t new_size) {

	if (NULL == cli || NULL == cli->buf)
		return (EINVAL);
	new_size += cli->bnd->srv->s.hdrs_reserve_size;
	if (new_size > cli->buf->size || /* Need more space! */
	    (0 != allow_decrease && (new_size * 2) < cli->buf->size)) { /* Space too mach. */
		return (io_buf_realloc(&cli->buf, 0, new_size));
	}
	return (0);
}

http_srv_p
http_cli_get_srv(http_cli_p cli) {

	if (NULL == cli)
		return (NULL);
	if (NULL == cli->bnd)
		return (NULL);
	return (cli->bnd->srv);
}

http_srv_req_p
http_cli_get_req(http_cli_p cli) {

	if (NULL == cli)
		return (NULL);
	return (&cli->req);
}

int
http_cli_ccb_get(http_cli_p cli, http_cli_cb ccb) {

	if (NULL == cli || NULL == ccb)
		return (EINVAL);
	(*ccb) = cli->ccb;
	return (0);
}

int
http_cli_ccb_set(http_cli_p cli, http_cli_cb ccb) {

	if (NULL == cli || NULL == ccb)
		return (EINVAL);
	cli->ccb = (*ccb);
	return (0);
}

void *
http_cli_get_udata(http_cli_p cli) {

	if (NULL == cli)
		return (NULL);
	return (cli->udata);
}

int
http_cli_set_udata(http_cli_p cli, void *udata) {

	if (NULL == cli)
		return (EINVAL);
	cli->udata = udata;
	return (0);
}

uint32_t
http_cli_get_flags(http_cli_p cli) {

	if (NULL == cli)
		return (0);
	return (cli->flags);
}

uint32_t
http_cli_get_resp_p_flags(http_cli_p cli) {

	if (NULL == cli)
		return (0);
	return (cli->resp_p_flags);
}

uint32_t
http_cli_add_resp_p_flags(http_cli_p cli, uint32_t resp_p_flags) {

	if (NULL == cli)
		return (0);
	cli->resp_p_flags |= resp_p_flags;
	return (cli->resp_p_flags);
}

uint32_t
http_cli_del_resp_p_flags(http_cli_p cli, uint32_t resp_p_flags) {

	if (NULL == cli)
		return (0);
	cli->resp_p_flags &= ~resp_p_flags;
	return (cli->resp_p_flags);
}

void
http_cli_set_resp_p_flags(http_cli_p cli, uint32_t resp_p_flags) {

	if (NULL == cli)
		return;
	cli->resp_p_flags = resp_p_flags;
}

int
http_cli_get_addr(http_cli_p cli, struct sockaddr_storage *addr) {

	if (NULL == cli || NULL == addr)
		return (EINVAL);
	sa_copy(&cli->addr, addr);
	return (0);
}




/* New connection received. */
static int
http_srv_new_conn_cb(io_task_p iotask, int error, uintptr_t skt,
    struct sockaddr_storage *addr, void *arg) {
	http_cli_p cli;
	http_srv_bind_p bnd = (http_srv_bind_p)arg;
	http_srv_p srv;
	thrpt_p thrpt;
	http_cli_ccb_t ccb;
	void *udata;
	char straddr[STR_ADDR_LEN];

	srv = bnd->srv;
	if (0 != error) {
		close(skt);
		srv->stat.errors ++;
		LOG_ERR(error, "on new conn");
		return (IO_TASK_CB_CONTINUE);
	}

	/* Default values for new client. */
	if (IO_NET_SKT_OPTS_IS_FLAG_ACTIVE(&bnd->s.skt_opts, SO_F_REUSEPORT)) {
		thrpt = io_task_thrpt_get(iotask);
	} else {
		thrpt = thrp_thread_get_rr(srv->thrp);
	}
	ccb = srv->ccb; /* memcpy */
	udata = srv->udata;

	/* Call back handler. */
	if (NULL != srv->on_conn) {
		if (HTTP_CLI_CB_DESTROY == srv->on_conn(bnd, srv->udata,
		    skt, addr, &thrpt, &ccb, &udata)) {
			close(skt);
			return (IO_TASK_CB_CONTINUE);
		}
	}
	if (0 != LOG_IS_ENABLED()) {
		sa_addr_port_to_str(addr, straddr, sizeof(straddr), NULL);
		LOGD_INFO_FMT("New client: %s (fd: %zu)", straddr, skt);
	}

	cli = http_cli_alloc(bnd, thrpt, skt, &ccb, udata);
	if (NULL == cli) {
		if (NULL != ccb.on_destroy) /* Call back handler. */
			ccb.on_destroy(NULL, udata);
		close(skt);
		srv->stat.errors ++;
		LOG_ERR_FMT(ENOMEM, "%s: http_cli_alloc()", straddr);
		return (IO_TASK_CB_CONTINUE);
	}
	sa_copy(addr, &cli->addr);
	/* Tune socket. */
	error = io_net_skt_opts_set_ex(skt, SO_F_TCP_ES_CONN_MASK,
	    &bnd->s.skt_opts, NULL);
	if (0 != error)
		LOG_ERR_FMT(error, "%s: io_net_skt_opts_set_ex(), this is not fatal.", straddr);
	/* Receive http request. */
	IO_BUF_MARK_TRANSFER_ALL_FREE(cli->rcv_buf);
	/* Shedule data receive / Receive http request. */
	error = io_task_start_ex(IO_NET_SKT_OPTS_IS_FLAG_ACTIVE(&bnd->s.skt_opts, SO_F_ACC_FILTER),
	    cli->iotask, THRP_EV_READ, 0, bnd->s.skt_opts.rcv_timeout, 0, cli->rcv_buf,
	    http_srv_recv_done_cb);
	if (0 != error) { /* Error. */
		srv->stat.errors ++;
		http_cli_free(cli);
		LOG_ERR_FMT(error, "client ip: %s", straddr);
	}
	return (IO_TASK_CB_CONTINUE);
}


/* http request from client is received now, process it. */
static int
http_cli_recv_done_cb(io_task_p iotask, int error, io_buf_p buf, int eof,
    size_t transfered_size, void *arg) {
	http_cli_p cli = (http_cli_p)arg;
	http_srv_bind_p bnd;
	http_srv_p srv;
	char straddr[STR_ADDR_LEN];
	uint8_t *ptm;
	uint16_t host_port;
	size_t i, tm;
	int action;
	struct sockaddr_storage addr;

	LOGD_EV("...");

	bnd = cli->bnd;
	srv = bnd->srv;
	/* iotask == cli->iotask !!! */
	/* buf == cli->rcv_buf !!! */
	// buf->used = buf->offset;
	action = io_task_cb_check(buf, eof, transfered_size);
	if (0 != error || IO_TASK_CB_ERROR == action) { /* Fail! :( */
err_out:
		if (0 != error && 0 != LOG_IS_ENABLED()) {
			sa_addr_port_to_str(&cli->addr, straddr, sizeof(straddr), NULL);
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
		http_cli_free(cli);
		return (IO_TASK_CB_NONE);
	}

	if (0 != (IO_TASK_IOF_F_SYS & eof)) { /* Client call shutdown(, SHUT_WR) and can only receive data. */
		cli->flags |= HTTP_CLI_CLI_F_HALF_CLOSED;
		cli->resp_p_flags |= HTTP_CLI_RESP_P_F_CONN_CLOSE;
	}

	if (NULL != cli->req.data) { /* Header allready received in prev call, continue receve data. */
		if (IO_TASK_CB_CONTINUE == action && 0 != IO_BUF_TR_SIZE_GET(buf))
			goto continue_recv; /* Continue receive request data. */
		goto req_received; /* Have HTTP headers and (all data / OEF). */
	}

	/* Analize HTTP header. */
	ptm = mem_find_cstr(buf->data, buf->used, CRLFCRLF);
	if (NULL == ptm) { /* No HTTP headers end found. */
		if (IO_TASK_CB_CONTINUE != action) { /* Cant receive more, drop. */
drop_cli_without_hdr:
			if (0 != LOG_IS_ENABLED()) {
				sa_addr_port_to_str(&cli->addr, straddr, sizeof(straddr), NULL);
				LOG_INFO_FMT("error: no http header, client ip: %s", straddr);
			}
			srv->stat.http_errors ++;
			http_cli_free(cli);
			return (IO_TASK_CB_NONE);
		}
continue_recv:
		/* Realloc buf if needed. */
		if (0 != IO_BUF_FREE_SIZE(buf))
			return (IO_TASK_CB_CONTINUE); /* Continue receive. */
		/* Not enough buf space, try realloc more. */
		if (buf->size >= srv->s.rcv_io_buf_max_size)
			goto drop_cli_without_hdr; /* Request too big. */
		error = io_buf_realloc(&cli->rcv_buf, 0, srv->s.rcv_io_buf_max_size);
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
	if (0 != http_parse_req_line(cli->req.hdr, cli->req.hdr_size, &cli->req.line)) {
		if (0 != LOG_IS_ENABLED()) {
			sa_addr_port_to_str(&cli->addr, straddr, sizeof(straddr), NULL);
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
			sa_addr_port_to_str(&cli->addr, straddr, sizeof(straddr), NULL);
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
		    0 != (HTTP_CLI_CLI_F_HALF_CLOSED & cli->flags)) { /* But we cant! */
			error = 400; /* Bad request. */
			goto drop_cli_with_http_err;
		}
		io_task_flags_del(iotask, IO_TASK_F_CB_AFTER_EVERY_READ);
		IO_BUF_TR_SIZE_SET(buf, (cli->req.data_size - tm));
		if (IO_BUF_FREE_SIZE(buf) < IO_BUF_TR_SIZE_GET(buf)) { /* Reallocate buf. */
			error = io_buf_realloc(&cli->rcv_buf, 0,
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
	if (0 == (HTTP_CLI_REQ_P_F_CONNECTION & srv->s.req_p_flags))
		goto skeep_connection_hdr;
	if (0 != http_hdr_val_get(cli->req.hdr, cli->req.hdr_size,
	    (uint8_t*)"connection", 10, &ptm, &tm)) {
		if (HTTP_VER_1_0 == cli->req.line.proto_ver) {
			cli->req.flags |= HTTP_CLI_RD_F_CONN_CLOSE;
		}
		goto skeep_connection_hdr;
	}
	if (0 == mem_cmpin_cstr("close", ptm, tm)) {
		cli->req.flags |= HTTP_CLI_RD_F_CONN_CLOSE;
	}
skeep_connection_hdr:
	
	/* Process 'host' header value. */
	if (0 == (HTTP_CLI_REQ_P_F_HOST & srv->s.req_p_flags))
		goto skeep_host_hdr;
	if (0 != http_hdr_val_get(cli->req.hdr, cli->req.hdr_size,
	    (uint8_t*)"host", 4, &cli->req.host, &cli->req.host_size)) { /* No "host" hdr. */
		if (HTTP_VER_1_0 == cli->req.line.proto_ver)
			cli->req.flags |= HTTP_CLI_RD_F_HOST_IS_LOCAL;
		goto skeep_host_hdr;
	}
	/* Is 'host' from request line and from header euqual? */
	if (NULL != cli->req.line.host) {
		if (0 != mem_cmpn(cli->req.host, cli->req.host_size,
		    cli->req.line.host, cli->req.line.host_size)) {
			if (0 != LOG_IS_ENABLED()) {
				sa_addr_port_to_str(&cli->addr, straddr, sizeof(straddr), NULL);
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
	if (0 == sa_addr_port_from_str(&addr, (const char*)cli->req.host,
	    cli->req.host_size)) { /* Binary host address. */
		/* Is connection to loopback from ext host? */
		if (0 != sa_addr_is_loopback(&addr) && /* To loopback */
		    0 == sa_addr_is_loopback(&cli->addr)) { /* From net */
conn_from_net_to_loopback:
			if (0 != LOG_IS_ENABLED()) {
				sa_addr_port_to_str(&cli->addr, straddr,
				    sizeof(straddr), NULL);
				LOG_INFO_FMT("HACKING ATTEMPT: %s set in host header loopback address.", straddr);
			}
			srv->stat.insecure_requests ++;
			http_srv_snd_err(cli, 403, NULL, 0);
			return (IO_TASK_CB_NONE);
		}
		host_port = sa_port_get(&addr);
		if (0 == host_port) /* Def http port. */
			host_port = HTTP_PORT;
		if (sa_port_get(&bnd->s.addr) == host_port &&
		    (0 == hostname_list_check_any(&bnd->hst_name_lst) ||
		    0 == hostname_list_check_any(&srv->hst_name_lst))) {
			cli->req.flags |= HTTP_CLI_RD_F_HOST_IS_LOCAL;
			goto skeep_host_hdr;
		}
		ptm = NULL; /* Addr info cache. */
		for (i = 0; i < srv->bind_count; i ++) {
			if (srv->bnd[i]->s.addr.ss_family != addr.ss_family ||
			    sa_port_get(&srv->bnd[i]->s.addr) != host_port) /* not equal port! */
				continue;
			if (0 == sa_addr_is_specified(&srv->bnd[i]->s.addr)) {
				/* Binded to: 0.0.0.0 or [::]. */
				if (0 == is_host_addr_ex(&addr, (void**)&ptm))
					continue;
			} else { /* Binded to IP addr. */
				if (0 == sa_addr_is_eq(&srv->bnd[i]->s.addr, &addr))
					continue;
			}
			cli->req.flags |= HTTP_CLI_RD_F_HOST_IS_LOCAL;
			break;
		}
		is_host_addr_ex_free(ptm);
	} else { /* Text host address. */
		cli->req.flags |= HTTP_CLI_RD_F_HOST_IS_STR;
		ptm = mem_chr(cli->req.host, cli->req.host_size, ':');
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
		action = (0 == mem_cmpin_cstr(c"localhost", li->req.host, tm));
		/* Is connection to loopback from ext host? */
		if (0 != action && 0 == sa_addr_is_loopback(&cli->addr)) /* from ext host? */
			goto conn_from_net_to_loopback;
		/* Is hostname point to this host? */
		if (sa_port_get(&bnd->s.addr) == host_port &&
		    (0 != action ||
		    0 == hostname_list_check(&bnd->hst_name_lst, cli->req.host, tm) ||
		    0 == hostname_list_check(&srv->hst_name_lst, cli->req.host, tm)))
			cli->req.flags |= HTTP_CLI_RD_F_HOST_IS_LOCAL;
	}
skeep_host_hdr:

	/* Delayed allocation buffer for answer */
	/* cli->buf != cli->rcv_buf!!!: if cb func realloc buf, then rcv_buf became invalid. */
	if (NULL == cli->buf || cli->buf == cli->rcv_buf) {
		cli->buf = io_buf_alloc(IO_BUF_FLAGS_STD, srv->s.snd_io_buf_init_size);
		if (NULL == cli->buf) { /* Allocate fail, send error. */
			/* Force 'connection: close'. */
			cli->resp_p_flags |= HTTP_CLI_RESP_P_F_CONN_CLOSE;
			cli->buf = cli->rcv_buf;
			srv->stat.errors ++;
			srv->stat.http_errors --; /* http_srv_snd_err() will increase it.*/
			http_srv_snd_err(cli, 500, NULL, 0);
			return (IO_TASK_CB_NONE);
		}
	}
	/* Reserve space for HTTP headers. */
	IO_BUF_BUSY_SIZE_SET(cli->buf, srv->s.hdrs_reserve_size);

	/* Call client custom on_req_rcv cb. */
	if (NULL != cli->ccb.on_req_rcv) { /* Call back handler. */
		action = cli->ccb.on_req_rcv(cli, cli->udata, &cli->req);
	} else {
		action = 404; /* Default action. */
	}
	
	/* Handle call back function return code. */
	switch (action) {
	case HTTP_CLI_CB_DESTROY:
		http_cli_free(cli);
		break;
	case HTTP_CLI_CB_NONE:
		break;
	default: /* Send HTTP code. */
		http_srv_snd_err(cli, action, NULL, 0);
	}

	return (IO_TASK_CB_NONE);
}




int
http_srv_gen_resp_hdrs(uint32_t http_ver, uint32_t status_code,
    uint32_t resp_p_flags, const char *reason_phrase, size_t reason_phrase_size,
    const char *http_user_agent, size_t http_user_agent_size,
    uint64_t content_len, char *buf, size_t buf_size, size_t *buf_size_ret) {
	size_t hdrs_size;

	if (NULL == buf || 0 == buf_size)
		return (EINVAL);
	if (NULL != reason_phrase && 0 != reason_phrase_size) {
		/* Remove CRLF from tail. */
		while (0 < reason_phrase_size &&
		    ('\r' == reason_phrase[(reason_phrase_size - 1)] ||
		    '\n' == reason_phrase[(reason_phrase_size - 1)]))
			reason_phrase_size --;
	}
	if (NULL == reason_phrase || 0 == reason_phrase_size)
		reason_phrase = http_get_err_descr(status_code, &reason_phrase_size);
	if (NULL == http_user_agent || 0 == http_user_agent_size)
		resp_p_flags &= ~HTTP_CLI_RESP_P_F_SERVER; /* Unset flag. */
	if (buf_size < (9 + 8 + reason_phrase_size + 
	    ((0 != (HTTP_CLI_RESP_P_F_SERVER & resp_p_flags)) ? (10 + http_user_agent_size) : 0) +
	    ((0 != (HTTP_CLI_RESP_P_F_CONTENT_SIZE & resp_p_flags)) ? 32 : 0) +
	    ((0 != (HTTP_CLI_RESP_P_F_CONN_CLOSE & resp_p_flags)) ? 19 : 0)))
		return (ENOMEM); /* Not enough space in buf. */
	buf_size --; /* Keep last byte for zero. */
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
	memcpy((buf + hdrs_size), "\r\n", 2);
	hdrs_size += 2;
	
	if (0 != (resp_p_flags & HTTP_CLI_RESP_P_F_SERVER)) {
		memcpy((buf + hdrs_size), "Server: ", 8);
		hdrs_size += 8;
		memcpy((buf + hdrs_size), http_user_agent, http_user_agent_size);
		hdrs_size += http_user_agent_size;
		memcpy((buf + hdrs_size), "\r\n", 2);
		hdrs_size += 2;
	}
	if (0 != (resp_p_flags & HTTP_CLI_RESP_P_F_CONTENT_SIZE)) {
		hdrs_size += snprintf((buf + hdrs_size), (buf_size - hdrs_size),
		    "Content-Length: %"PRIu64"\r\n", content_len);
	}
	if (0 != (HTTP_CLI_RESP_P_F_CONN_CLOSE & resp_p_flags)) { /* Conn close. */
		memcpy((buf + hdrs_size), "Connection: close\r\n", 19);
		hdrs_size += 19;
	}
	buf[hdrs_size] = 0;
	if (NULL != buf_size_ret)
		(*buf_size_ret) = hdrs_size;
	return (0);
}


/* Offset must pont to data start, size = data offset + data size. */
int
http_srv_snd(http_cli_p cli, uint32_t status_code,
    const char *reason_phrase, size_t reason_phrase_size,
    struct iovec *custom_hdrs, size_t custom_hdrs_count) {
	int error;
	http_srv_p srv;
	uint8_t	*wr_pos;
	char hdrs[1024], *crlf = (char*)"\r\n";
	size_t hdrs_size, data_size, i;
	ssize_t ios = 0;
	struct iovec iov[IOV_MAX];
	struct msghdr mhdr;

	if (NULL == cli)
		return (EINVAL);
	srv = cli->bnd->srv;
	if (404 == status_code)
		srv->stat.unhandled_requests ++;
	if (cli->buf->used < cli->buf->offset ||
	    HTTP_CLI_MAX_CUSTOM_HDRS_CNT < custom_hdrs_count) { /* Limit custom hdrs count. */
		error = EINVAL;
		goto err_out;
	}
	data_size = (cli->buf->used - cli->buf->offset);
	if (0 != (HTTP_CLI_CLI_F_HALF_CLOSED & cli->flags) ||
	    0 != (HTTP_CLI_RD_F_CONN_CLOSE & cli->req.flags)) {
		cli->resp_p_flags |= HTTP_CLI_RESP_P_F_CONN_CLOSE;
	}

	/* HTTP header. */
	error = http_srv_gen_resp_hdrs(cli->req.line.proto_ver, status_code,
	    cli->resp_p_flags, reason_phrase, reason_phrase_size, srv->s.http_user_agent,
	    srv->s.http_user_agent_size, data_size, (char*)hdrs, sizeof(hdrs),
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
	mem_bzero(&mhdr, sizeof(mhdr));
	mhdr.msg_iov = iov;
	mhdr.msg_iovlen ++;
	iov[0].iov_base = hdrs;
	iov[0].iov_len = hdrs_size;
	for (i = 0; i < custom_hdrs_count; i ++) { /* Add custom headers. */
		if (NULL == custom_hdrs[i].iov_base || 3 > custom_hdrs[i].iov_len)
			continue; /* Skeep empty header part. */
		iov[mhdr.msg_iovlen].iov_base = custom_hdrs[i].iov_base;
		iov[mhdr.msg_iovlen].iov_len = custom_hdrs[i].iov_len;
		mhdr.msg_iovlen ++;
		hdrs_size += custom_hdrs[i].iov_len;
		if (0 == memcmp((((uint8_t*)custom_hdrs[i].iov_base) +
		    (custom_hdrs[i].iov_len - 2)), crlf, 2))
			continue; /* No need to add tailing CRLF. */
		iov[mhdr.msg_iovlen].iov_base = (void*)crlf;
		iov[mhdr.msg_iovlen].iov_len = 2;
		mhdr.msg_iovlen ++;
		hdrs_size += 2;
	}
	iov[mhdr.msg_iovlen].iov_base = (void*)crlf;
	iov[mhdr.msg_iovlen].iov_len = 2;
	hdrs_size += 2;
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
	error = io_task_start(cli->iotask, THRP_EV_WRITE, 0,
	    cli->bnd->s.skt_opts.snd_timeout, 0, cli->buf, http_srv_snd_done_cb);
	if (0 == error) /* No Error. */
		return (0);

err_out:
	/* Error. */
	http_srv_snd_done_cb(cli->iotask, error, cli->buf, 0, ios, cli);
	LOG_ERR(error, "err_out");
	return (error);
}


/* http answer to cli is sended, work done. */
static int
http_cli_snd_done_cb(io_task_p iotask __unused, int error, io_buf_p buf __unused,
    int eof, size_t transfered_size __unused, void *arg) {
	http_cli_p cli = (http_cli_p)arg;
	http_srv_p srv;
	char straddr[STR_ADDR_LEN];
	int action;
	size_t tm;

	LOGD_EV("...");

	srv = cli->bnd->srv;
	if (0 != error) { /* Fail! :( */
		if (0 != LOG_IS_ENABLED()) {
			sa_addr_port_to_str(&cli->addr, straddr,
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
		http_cli_free(cli);
		return (IO_TASK_CB_NONE);
	}

	if (0 != eof) { /* Client call shutdown(, SHUT_WR) and can only receive data. */
		cli->flags |= HTTP_CLI_CLI_F_HALF_CLOSED;
	}

	if (NULL != cli->ccb.on_rep_snd) { /* Call back handler. */
		action = cli->ccb.on_rep_snd(cli, cli->udata);
	} else {
		action = HTTP_CLI_CB_NONE;
	}
	if (0 != (HTTP_CLI_CLI_F_HALF_CLOSED & cli->flags) ||
	    0 != (HTTP_CLI_RESP_P_F_CONN_CLOSE & cli->resp_p_flags) ||
	    0 != (HTTP_CLI_RD_F_CONN_CLOSE & cli->req.flags))
		action = HTTP_CLI_CB_DESTROY; /* Force destroy. */

	/* Handle call back function return code. */
	if (HTTP_CLI_CB_DESTROY == action) { /* Free resourses */
		http_cli_free(cli);
		return (IO_TASK_CB_NONE);
	}
	/* Reuse connection. */
	/* Move data to buf start. */
	cli->req.data += cli->req.data_size; /* Move pointer to next request. */
	tm = (cli->rcv_buf->used - (cli->req.data - cli->rcv_buf->data));
	memmove(cli->rcv_buf->data, cli->req.data, tm);
	/* Re init client. */
	mem_bzero(&cli->req, sizeof(http_srv_req_t));
	cli->resp_p_flags = 0;
	/* Receive next http request. */
	IO_BUF_BUSY_SIZE_SET(cli->rcv_buf, tm);
	IO_BUF_MARK_TRANSFER_ALL_FREE(cli->rcv_buf);
	/* Shedule data receive / Receive http request / Process next. */
	error = io_task_start_ex(0, cli->iotask, THRP_EV_READ, 0,
	    cli->bnd->s.skt_opts.rcv_timeout, 0, cli->rcv_buf, http_srv_recv_done_cb);
	if (0 != error) { /* Error. */
		srv->stat.errors ++;
		http_cli_free(cli);
		LOG_ERR_FMT(error, "client ip: %s", straddr);
	}

	return (IO_TASK_CB_NONE);
}
