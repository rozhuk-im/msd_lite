/*-
 * Copyright (c) 2012 - 2016 Rozhuk Ivan <rozhuk.im@gmail.com>
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
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/stat.h> /* For mode constants */
#include <sys/file.h> /* flock */

#include <stdlib.h> /* malloc, exit */
#include <pthread.h>
#include <stdio.h> /* snprintf, fprintf */
#include <unistd.h> /* close, write, sysconf */
#include <fcntl.h> /* For O_* constants */
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <time.h>
#include <errno.h>

#include "macro_helpers.h"
#include "core_thrp.h"
#include "core_thrp_msg.h"
#include "core_io_task.h"
#include "core_io_net.h"
#include "core_net_helpers.h"
#include "core_info.h"
#include "core_helpers.h"
#include "core_log.h"
#include "rtp.h"
#include "mpeg2ts.h"
#include "md5.h"
#include "mem_helpers.h"
#include "HTTP.h"
#include "stream_sys.h"

/* Internal constants. */
#define STR_HUB_CLI_RECV_BUF		4096
#define STR_HUB_CLI_RECV_LOWAT		1
#define STR_SRC_UDP_PKT_SIZE_STD	1500
#define STR_SRC_UDP_PKT_SIZE_MAX	65612 /* 349 * 188 */


typedef struct str_hub_cli_attach_cb_data_s {
	str_hubs_bckt_p	shbskt;
	str_hub_cli_p	strh_cli;
	uint8_t		*hub_name;
	size_t		hub_name_size;
	str_src_conn_params_t src_conn_params;
} str_hub_cli_attach_cb_data_t, *str_hub_cli_attach_cb_data_p;



typedef struct str_hubs_bckt_enum_data_s { /* thread message sync data. */
	str_hubs_bckt_p		shbskt;
	str_hubs_bckt_enum_cb	enum_cb;
	void			*udata;
	thrpt_msg_done_cb	done_cb;
} str_hubs_bckt_enum_data_t, *str_hubs_bckt_enum_data_p;



thrpt_p	str_hub_thrpt_get_by_name(thrp_p thrp, const uint8_t *name, size_t name_size);

static void	str_hubs_bckt_destroy_msg_cb(thrpt_p thrpt, void *udata);

static void	str_hubs_bckt_enum_msg_cb(thrpt_p thrpt, void *udata);
static void	str_hubs_bckt_enum_done_cb(thrpt_p thrpt, size_t send_msg_cnt,
		    size_t error_cnt, void *udata);

void		str_hubs_bckt_timer_service(str_hubs_bckt_p shbskt,
		    str_hub_p str_hub, str_hubs_stat_p stat);
static void	str_hubs_bckt_timer_msg_cb(thrpt_p thrpt, void *udata);
static void	str_hubs_bckt_timer_cb(thrp_event_p ev, thrp_udata_p thrp_udata);

int	str_hub_create_int(str_hubs_bckt_p shbskt, thrpt_p thrpt,
	    uint8_t *name, size_t name_size,
	    str_src_conn_params_p src_conn_params, str_hub_p *str_hub_ret);
void	str_hub_destroy_int(str_hub_p str_hub);

void	str_hub_cli_attach_msg_cb(thrpt_p thrpt, void *udata);

int	str_hub_send_to_client(str_hub_p str_hub, str_hub_cli_p strh_cli,
	    size_t *transfered_size);
int	str_hub_send_to_clients(str_hub_p str_hub);
static int str_src_recv_mc_cb(io_task_p iotask, int error, uint32_t eof,
	    size_t data2transfer_size, void *arg);
int	str_src_r_buf_alloc(str_hub_p str_hub);
void	str_src_r_buf_free(str_hub_p str_hub);



/* XXX Thread pool balancer */
thrpt_p
str_hub_thrpt_get_by_name(thrp_p thrp, const uint8_t *name, size_t name_size) {
	size_t thread_num, thread_cnt;
	uint8_t hash[MD5_HASH_SIZE];

	md5_get_digest(name, name_size, hash);

	thread_cnt = thrp_thread_count_max_get(thrp);
	//thread_num = (/*(hash / thread_cnt) ^*/ (hash % thread_cnt));
	thread_num = ((thread_cnt * data_xor8(hash, sizeof(hash))) / 256);
	if (thread_cnt < thread_num) {
		thread_num = (thread_cnt - 1);
	}

	return (thrp_thread_get(thrp, thread_num));
}


void
str_hub_settings_def(str_hub_settings_p p_ret) {

	if (NULL == p_ret)
		return;
	mem_bzero(p_ret, sizeof(str_hub_settings_t));
	p_ret->flags = STR_HUB_S_DEF_FLAGS;
	p_ret->ring_buf_size = STR_HUB_S_DEF_RING_BUF_SIZE;
	p_ret->precache = STR_HUB_S_DEF_PRECAHE;
	p_ret->snd_block_min_size = STR_HUB_S_DEF_SND_BLOCK_MIN_SIZE;
	p_ret->skt_snd_buf = STR_HUB_S_DEF_SKT_SND_BUF;
}

void
str_src_settings_def(str_src_settings_p p_ret) {
	
	if (NULL == p_ret)
		return;
	mem_bzero(p_ret, sizeof(str_src_settings_t));
	p_ret->skt_rcv_buf = STR_SRC_S_DEF_SKT_RCV_BUF;
	p_ret->skt_rcv_lowat = STR_SRC_S_DEF_SKT_RCV_LOWAT;
	p_ret->rcv_timeout = STR_SRC_S_DEF_UDP_RCV_TIMEOUT;
}

void
str_src_conn_def(str_src_conn_params_p src_conn_params) {

	if (NULL == src_conn_params)
		return;
	mem_bzero(src_conn_params, sizeof(str_src_conn_params_t));
	src_conn_params->mc.if_index = STR_SRC_CONN_DEF_IFINDEX;
}


int
str_hubs_bckt_create(thrp_p thrp, const char *app_ver, str_hub_settings_p hub_params,
    str_src_settings_p src_params, str_hubs_bckt_p *shbskt_ret) {
	int error;
	str_hubs_bckt_p shbskt;
	char osver[128];
	size_t i, thread_count_max;

	if (NULL == shbskt_ret)
		return (EINVAL);
	shbskt = zalloc(sizeof(str_hubs_bckt_t) + hub_params->cust_http_hdrs_size + sizeof(void*));
	if (NULL == shbskt)
		return (ENOMEM);
	thread_count_max = thrp_thread_count_max_get(thrp);
	shbskt->thr_data = zalloc((sizeof(str_hub_thrd_t) * thread_count_max));
	if (NULL == shbskt->thr_data) {
		error = ENOMEM;
		goto err_out;
	}
	for (i = 0; i < thread_count_max; i ++) {
		TAILQ_INIT(&shbskt->thr_data[i].hub_head);
	}
	/* Stream Hub Params */
	memcpy(&shbskt->hub_params, hub_params, sizeof(str_hub_settings_t));
	/* Copy custom HTTP headers to new buffer. */
	shbskt->hub_params.cust_http_hdrs = (uint8_t*)(shbskt + 1);
	if (NULL != hub_params->cust_http_hdrs &&
	    0 != hub_params->cust_http_hdrs_size) {
		/* Custom headers body. */
		memcpy(shbskt->hub_params.cust_http_hdrs,
		    hub_params->cust_http_hdrs,
		    hub_params->cust_http_hdrs_size);
		if (0 != memcmp((shbskt->hub_params.cust_http_hdrs +
		    (shbskt->hub_params.cust_http_hdrs_size - 2)), "\r\n", 2)) {
			/* Add CRLF. */
			memcpy((shbskt->hub_params.cust_http_hdrs +
			    shbskt->hub_params.cust_http_hdrs_size), "\r\n", 2);
			shbskt->hub_params.cust_http_hdrs_size += 2;
		}
	}
	/* Add final CRLF + zero. */
	memcpy((shbskt->hub_params.cust_http_hdrs +
	    shbskt->hub_params.cust_http_hdrs_size), "\r\n", 3);
	shbskt->hub_params.cust_http_hdrs_size += 2;
	/* sec->ms, kb -> bytes */
	hub_params = &shbskt->hub_params; /* Use short name. */
	hub_params->ring_buf_size *= 1024;
	hub_params->precache *= 1024;
	hub_params->snd_block_min_size *= 1024;
	hub_params->skt_snd_buf *= 1024;
	/* Correct values. */
	if (hub_params->precache > hub_params->ring_buf_size) {
		hub_params->precache = hub_params->ring_buf_size;
	}
	if (hub_params->snd_block_min_size > hub_params->skt_snd_buf) {
		hub_params->snd_block_min_size = hub_params->skt_snd_buf;
	}

	/* Stream src Params */
	memcpy(&shbskt->src_params, src_params, sizeof(str_src_settings_t));
	/* Use short name. */
	src_params = &shbskt->src_params;
	/* Correct values. */
	src_params->skt_rcv_lowat = min(src_params->skt_rcv_lowat, src_params->skt_rcv_buf);
	/* sec->ms, kb -> bytes */
	src_params->skt_rcv_buf *= 1024;
	src_params->skt_rcv_lowat *= 1024;
	//src_params->rcv_timeout =; // In seconds!
	
	/* Base HTTP headers. */
	if (0 != core_info_get_os_ver("/", 1, osver,
	    (sizeof(osver) - 1), NULL))
		memcpy(osver, "Generic OS/1.0", 15);
	shbskt->base_http_hdrs_size = (size_t)snprintf((char*)shbskt->base_http_hdrs,
	    sizeof(shbskt->base_http_hdrs),
	    "Server: %s %s HTTP stream hub by Rozhuk Ivan\r\n"
	    "Connection: close\r\n",
	    osver, app_ver);
	/* Timer */
	shbskt->thrp = thrp;
	shbskt->service_tmr.cb_func = str_hubs_bckt_timer_cb;
	shbskt->service_tmr.ident = (uintptr_t)shbskt;
	error = thrpt_ev_add_ex(thrp_thread_get_rr(shbskt->thrp), THRP_EV_TIMER,
	    0, 0, 1000 /* 1 sec. */, &shbskt->service_tmr);
	if (0 != error) {
		LOGD_ERR(error, "thrpt_ev_add_ex()");
		goto err_out;
	}

	(*shbskt_ret) = shbskt;

	return (0);

err_out:
	free(shbskt->thr_data);
	free(shbskt);
	return (error);
}

void
str_hubs_bckt_destroy(str_hubs_bckt_p shbskt) {

	if (NULL == shbskt)
		return;
	thrpt_ev_del(THRP_EV_TIMER, &shbskt->service_tmr);
	/* Broadcast to all threads. */
	thrpt_msg_bsend(shbskt->thrp, NULL,
	    (THRP_MSG_F_SELF_DIRECT | THRP_MSG_F_FORCE | THRP_MSG_F_FAIL_DIRECT | THRP_BMSG_F_SYNC),
	    str_hubs_bckt_destroy_msg_cb, shbskt);

	free(shbskt->thr_data);
	mem_filld(shbskt, sizeof(str_hubs_bckt_t));
	free(shbskt);
}
static void
str_hubs_bckt_destroy_msg_cb(thrpt_p thrpt, void *udata) {
	str_hubs_bckt_p shbskt = (str_hubs_bckt_p)udata;
	str_hub_p str_hub, str_hub_temp;
	size_t thread_num;

	//LOGD_EV("...");
	thread_num = thrp_thread_get_num(thrpt);

	TAILQ_FOREACH_SAFE(str_hub, &shbskt->thr_data[thread_num].hub_head, next,
	    str_hub_temp) {
		str_hub_destroy_int(str_hub);
	}
}


int
str_hubs_bckt_enum(str_hubs_bckt_p shbskt, str_hubs_bckt_enum_cb enum_cb,
    void *udata, thrpt_msg_done_cb done_cb) {
	int error;
	str_hubs_bckt_enum_data_p enum_data;

	if (NULL == shbskt || NULL == enum_cb)
		return (EINVAL);
	enum_data = malloc(sizeof(str_hubs_bckt_enum_data_t));
	if (NULL == enum_data)
		return (ENOMEM);
	enum_data->shbskt = shbskt;
	enum_data->enum_cb = enum_cb;
	enum_data->udata = udata;
	enum_data->done_cb = done_cb;

	error = thrpt_msg_cbsend(shbskt->thrp, NULL,
	    (THRP_CBMSG_F_ONE_BY_ONE), str_hubs_bckt_enum_msg_cb,
	    enum_data, str_hubs_bckt_enum_done_cb);
	if (0 != error) {
		free(enum_data);
	}

	return (error);
}
static void
str_hubs_bckt_enum_msg_cb(thrpt_p thrpt, void *udata) {
	str_hubs_bckt_enum_data_p enum_data = udata;
	str_hubs_bckt_p shbskt = enum_data->shbskt;
	str_hub_p str_hub, str_hub_temp;
	size_t thread_num;

	//LOGD_EV("...");
	thread_num = thrp_thread_get_num(thrpt);

	TAILQ_FOREACH_SAFE(str_hub, &shbskt->thr_data[thread_num].hub_head, next,
	    str_hub_temp) {
		enum_data->enum_cb(thrpt, str_hub, enum_data->udata);
	}
}
static void
str_hubs_bckt_enum_done_cb(thrpt_p thrpt, size_t send_msg_cnt, size_t error_cnt,
    void *udata) {
	str_hubs_bckt_enum_data_p enum_data = udata;

	if (NULL != enum_data->done_cb)
		enum_data->done_cb(thrpt, send_msg_cnt, error_cnt, enum_data->udata);
	free(enum_data);
}


int
str_hubs_bckt_stat_summary(str_hubs_bckt_p shbskt, str_hubs_stat_p stat) {
	size_t i, thread_cnt;

	if (NULL == shbskt || NULL == stat)
		return (EINVAL);
	thread_cnt = thrp_thread_count_max_get(shbskt->thrp);
	mem_bzero(stat, sizeof(str_hubs_stat_t));
	for (i = 0; i < thread_cnt; i ++) {
		stat->str_hub_count += shbskt->thr_data[i].stat.str_hub_count;
		stat->cli_count += shbskt->thr_data[i].stat.cli_count;
		stat->baud_rate_in += shbskt->thr_data[i].stat.baud_rate_in;
		stat->baud_rate_out += shbskt->thr_data[i].stat.baud_rate_out;
	}
	return (0);
}


void
str_hubs_bckt_timer_service(str_hubs_bckt_p shbskt, str_hub_p str_hub,
    str_hubs_stat_p stat) {
	str_src_settings_p src_params = &shbskt->src_params;
	struct timespec *tp = &shbskt->tp_last_tmr_next;
	uint64_t tm64;
	time_t tmt;


	/* Stat update. */
	/* Update stream hub clients baud rate. */
	if (0 == (tp->tv_sec & 1)) { /* every 2 second */
		tm64 = (1000000000 * ((uint64_t)tp->tv_sec - (uint64_t)shbskt->tp_last_tmr.tv_sec));
		tm64 += ((uint64_t)tp->tv_nsec - (uint64_t)shbskt->tp_last_tmr.tv_nsec);
		if (0 == tm64) /* Prevent division by zero. */
			tm64 ++;
		str_hub->baud_rate_out = ((str_hub->sended_count * 4000000000) / tm64);
		str_hub->baud_rate_in = ((str_hub->received_count * 4000000000) / tm64);
		str_hub->sended_count = 0;
		str_hub->received_count = 0;
	}
	/* Per Thread stat. */
	stat->str_hub_count ++;
	stat->cli_count += str_hub->cli_count;
	stat->baud_rate_out += str_hub->baud_rate_out;
	stat->baud_rate_in += str_hub->baud_rate_in;

	/* Check hub. */
	if (0 == str_hub->cli_count) {
		LOG_EV_FMT("%s: No more clients, selfdestroy.", str_hub->name);
		str_hub_destroy_int(str_hub);
		return;
	}
	/* No traffic check. */
	if (0 != src_params->rcv_timeout) {
		tmt = (str_hub->tp_last_recv.tv_sec + (time_t)src_params->rcv_timeout);
		if (tmt < tp->tv_sec ||
		    (tmt == tp->tv_sec && str_hub->tp_last_recv.tv_nsec < tp->tv_nsec)) {
			str_hub_destroy_int(str_hub);
			return;
		}
	}
}
static void
str_hubs_bckt_timer_msg_cb(thrpt_p thrpt, void *udata) {
	str_hubs_bckt_p shbskt = (str_hubs_bckt_p)udata;
	str_hub_p str_hub, str_hub_temp;
	str_hubs_stat_t stat;
	size_t thread_num;

	//LOGD_EV("...");
	thread_num = thrp_thread_get_num(thrpt);
	mem_bzero(&stat, sizeof(str_hubs_stat_t));

	/* Enum all Stream Hubs associated with this thread. */
	TAILQ_FOREACH_SAFE(str_hub, &shbskt->thr_data[thread_num].hub_head, next,
	    str_hub_temp) {
		str_hubs_bckt_timer_service(shbskt, str_hub, &stat);
	}
	/* Update stat. */
	memcpy(&shbskt->thr_data[thread_num].stat, &stat, sizeof(str_hubs_stat_t));
}
static void
str_hubs_bckt_timer_cb(thrp_event_p ev __unused, thrp_udata_p thrp_udata) {
	str_hubs_bckt_p shbskt = (str_hubs_bckt_p)thrp_udata->ident;

	//LOGD_EV("...");
	if (NULL == shbskt)
		return;
	memcpy(&shbskt->tp_last_tmr, &shbskt->tp_last_tmr_next, sizeof(struct timespec));
	thrpt_gettimev(thrp_udata->thrpt, 0, &shbskt->tp_last_tmr_next);
	/* Broadcast to all threads. */
	thrpt_msg_bsend(shbskt->thrp, thrp_udata->thrpt,
	    THRP_MSG_F_SELF_DIRECT, str_hubs_bckt_timer_msg_cb, shbskt);
}


int
str_hub_create_int(str_hubs_bckt_p shbskt, thrpt_p thrpt, uint8_t *name, size_t name_size,
    str_src_conn_params_p src_conn_params, str_hub_p *str_hub_ret) {
	int error;
	str_hub_p str_hub;
	uintptr_t skt;
	str_src_settings_p src_params;
	str_src_conn_udp_p conn_udp;

	LOGD_EV("...");

	if (NULL == shbskt || NULL == name || 0 == name_size || NULL == str_hub_ret)
		return (EINVAL);
	str_hub = zalloc((sizeof(str_hub_t) + name_size + sizeof(void*)));
	if (NULL == str_hub)
		return (ENOMEM);

	str_hub->shbskt = shbskt;
	str_hub->name = (uint8_t*)(str_hub + 1);
	str_hub->name_size = name_size;
	memcpy(str_hub->name, name, name_size);
	TAILQ_INIT(&str_hub->cli_head);
	str_hub->thrpt = thrpt;
	thrpt_gettimev(str_hub->thrpt, 0, &str_hub->tp_last_recv);
	str_hub->r_buf_fd = (uintptr_t)-1;

	src_params = &shbskt->src_params;
	memcpy(&str_hub->src_conn_params, src_conn_params, sizeof(str_src_conn_params_t));
	conn_udp = &src_conn_params->udp;
	error = io_net_bind(&conn_udp->addr, SOCK_DGRAM, IPPROTO_UDP,
	    (SO_F_NONBLOCK | SO_F_REUSEADDR | SO_F_REUSEPORT),
	    &skt);
	if (0 != error) /* Bind to mc addr fail, try bind inaddr_any. */
		error = io_net_bind_ap(conn_udp->addr.ss_family,
		    NULL, sa_port_get(&conn_udp->addr),
		    SOCK_DGRAM, IPPROTO_UDP,
		    (SO_F_NONBLOCK | SO_F_REUSEADDR | SO_F_REUSEPORT),
		    &skt);
	if (0 != error) {
		skt = (uintptr_t)-1;
		LOG_ERR(error, "io_net_mc_bind()");
		goto err_out;
	}
	/* Join to multicast group. */
	error = io_net_mc_join(skt, 1, src_conn_params->mc.if_index,
	    &conn_udp->addr);
	if (0 != error) {
		LOG_ERR(error, "io_net_mc_join()");
		goto err_out;
	}
	/* Tune socket. */
	error = io_net_rcv_tune(skt, src_params->skt_rcv_buf, src_params->skt_rcv_lowat);
	if (0 != error) {
		LOG_ERR(error, "io_net_rcv_tune()");
		goto err_out;
	}
	/* Create IO task for socket. */
	error = io_task_notify_create(str_hub->thrpt, skt,
	    IO_TASK_F_CLOSE_ON_DESTROY, THRP_EV_READ, 0, str_src_recv_mc_cb,
	    str_hub, &str_hub->iotask);
	if (0 != error) {
		LOG_ERR(error, "io_task_notify_create()");
		goto err_out;
	}

	TAILQ_INSERT_HEAD(&shbskt->thr_data[thrp_thread_get_num(thrpt)].hub_head,
	    str_hub, next);

	LOG_INFO_FMT("%s: Created. (fd: %zu)", str_hub->name, skt);

	(*str_hub_ret) = str_hub;
	return (0);

err_out:
	/* Error. */
	close((int)skt);
	str_hub_destroy_int(str_hub);
	(*str_hub_ret) = NULL;
	LOG_ERR(error, "...");
	return (error);
}

void
str_hub_destroy_int(str_hub_p str_hub) {
	str_hub_cli_p strh_cli, strh_cli_temp;

	LOGD_EV("...");

	if (NULL == str_hub)
		return;
	/* Leave multicast group. */
	io_task_destroy(str_hub->iotask);

	TAILQ_REMOVE(&str_hub->shbskt->thr_data[thrp_thread_get_num(str_hub->thrpt)].hub_head,
	    str_hub, next);

	/* Destroy all connected clients. */
	TAILQ_FOREACH_SAFE(strh_cli, &str_hub->cli_head, next, strh_cli_temp) {
		str_hub_cli_destroy(str_hub, strh_cli);
	}

	LOG_INFO_FMT("%s: Destroyed.", str_hub->name);

	str_src_r_buf_free(str_hub);

	mem_filld(str_hub, (sizeof(str_hub_t) + str_hub->name_size));
	free(str_hub);
}


str_hub_cli_p
str_hub_cli_alloc(uintptr_t skt, const char *ua, size_t ua_size) {
	str_hub_cli_p strh_cli;

	LOGD_EV("...");

	if (STR_HUB_CLI_USER_AGENT_MAX_SIZE < ua_size)
		ua_size = STR_HUB_CLI_USER_AGENT_MAX_SIZE;
	strh_cli = zalloc(sizeof(str_hub_cli_t) + ua_size + sizeof(void*));
	if (NULL == strh_cli)
		return (NULL);
	/* Set. */
	strh_cli->skt = skt;
	strh_cli->user_agent = (uint8_t*)(strh_cli + 1);
	if (NULL != ua && 0 != ua_size) {
		strh_cli->user_agent_size = ua_size;
		memcpy(strh_cli->user_agent, ua, ua_size);
		strh_cli->user_agent[ua_size] = 0;
	}

	return (strh_cli);
}

void
str_hub_cli_destroy(str_hub_p str_hub, str_hub_cli_p strh_cli) {
	char straddr[STR_ADDR_LEN];
	struct msghdr mhdr;
	struct iovec iov[4];

	LOGD_EV("...");

	if (NULL == strh_cli)
		return;
	if (NULL != str_hub) {
		if (0 != LOG_IS_ENABLED()) {
			sa_addr_port_to_str(&strh_cli->remonte_addr, straddr,
			    sizeof(straddr), NULL);
			LOG_INFO_FMT("%s - %s: deattached, cli_count = %zu",
			    str_hub->name, straddr, (str_hub->cli_count - 1));
		}
		/* Remove from stream hub. */
		TAILQ_REMOVE(&str_hub->cli_head, strh_cli, next);
		str_hub->cli_count --;
	}

	/* Send HTTP headers if needed. */
	if (0 == (STR_HUB_CLI_STATE_F_HTTP_HDRS_SENDED & strh_cli->flags) &&
	    0 == strh_cli->offset) {
		iov[0].iov_base = MK_RW_PTR("HTTP/1.1 503 Service Unavailable\r\n");
		iov[0].iov_len = 34;
		iov[1].iov_base = str_hub->shbskt->base_http_hdrs;
		iov[1].iov_len = str_hub->shbskt->base_http_hdrs_size;
		iov[2].iov_base = MK_RW_PTR("\r\n");
		iov[2].iov_len = 2;
		mem_bzero(&mhdr, sizeof(mhdr));
		mhdr.msg_iov = (struct iovec*)iov;
		mhdr.msg_iovlen = 3;
		sendmsg((int)strh_cli->skt, &mhdr, (MSG_DONTWAIT | MSG_NOSIGNAL));
	}

	close((int)strh_cli->skt);
	mem_filld(strh_cli, sizeof(str_hub_cli_t));
	free(strh_cli);
}


int
str_hub_cli_attach(str_hubs_bckt_p shbskt, str_hub_cli_p strh_cli,
    uint8_t *hub_name, size_t hub_name_size, str_src_conn_params_p src_conn_params) {
	int error;
	thrpt_p thrpt;
	str_hub_cli_attach_cb_data_p cli_data;

	if (NULL == shbskt || NULL == strh_cli || NULL == hub_name ||
	    0 == hub_name_size || NULL == src_conn_params)
		return (EINVAL);
	cli_data = zalloc(sizeof(str_hub_cli_attach_cb_data_t) + hub_name_size + sizeof(void*));
	if (NULL == cli_data)
		return (ENOMEM);
	cli_data->shbskt = shbskt;
	cli_data->strh_cli = strh_cli;
	cli_data->hub_name = (uint8_t*)(cli_data + 1);
	memcpy(cli_data->hub_name, hub_name, hub_name_size);
	cli_data->hub_name[hub_name_size] = 0;
	cli_data->hub_name_size = hub_name_size;
	memcpy(&cli_data->src_conn_params, src_conn_params, sizeof(str_src_conn_params_t));
	
	thrpt = str_hub_thrpt_get_by_name(shbskt->thrp, hub_name, hub_name_size);
	error = thrpt_msg_send(thrpt, NULL, THRP_MSG_F_SELF_DIRECT,
	    str_hub_cli_attach_msg_cb, cli_data);
	if (0 != error) {
		free(cli_data);
	}

	return (error);
}
void
str_hub_cli_attach_msg_cb(thrpt_p thrpt, void *udata) {
	str_hub_cli_attach_cb_data_p cli_data = udata;
	str_hub_p str_hub, str_hub_temp;
	str_hub_cli_p strh_cli;
	str_hub_settings_p hub_params;
	char straddr[STR_ADDR_LEN];
	size_t thread_num;
	int error = -1;

	LOGD_EV("...");

	thread_num = thrp_thread_get_num(thrpt);
	TAILQ_FOREACH_SAFE(str_hub, &cli_data->shbskt->thr_data[thread_num].hub_head,
	    next, str_hub_temp) {
		if (str_hub->name_size != cli_data->hub_name_size)
			continue;
		if (0 == memcmp(str_hub->name, cli_data->hub_name, cli_data->hub_name_size)) {
			error = 0;
			break;
		}
	}
	if (0 != error) { /* Create new... */
		error = str_hub_create_int(cli_data->shbskt, thrpt,
		    cli_data->hub_name, cli_data->hub_name_size,
		    &cli_data->src_conn_params, &str_hub);
		if (0 != error) {
			str_hub_cli_destroy(NULL, cli_data->strh_cli);
			close((int)cli_data->strh_cli->skt);
			free(cli_data);
			LOG_ERR(error, "str_hub_create()");
			return;
		}
	}

	strh_cli = cli_data->strh_cli;
	hub_params = &cli_data->shbskt->hub_params;
	/* Set. */
	strh_cli->conn_time = thrpt_gettime(str_hub->thrpt, 0);
	/* Tune socket. */
	/* Reduce kernel memory usage. */
	error = io_net_rcv_tune(strh_cli->skt, STR_HUB_CLI_RECV_BUF, STR_HUB_CLI_RECV_LOWAT);
	if (0 != error) {
		if (0 != LOG_IS_ENABLED()) {
			sa_addr_port_to_str(&strh_cli->remonte_addr, straddr, sizeof(straddr), NULL);
			LOG_ERR_FMT(error, "%s - %s: io_net_rcv_tune()",
			    str_hub->name, straddr);
		}
	}
	error = io_net_snd_tune(strh_cli->skt, hub_params->skt_snd_buf, 1);
	if (0 != error) {
		if (0 != LOG_IS_ENABLED()) {
			sa_addr_port_to_str(&strh_cli->remonte_addr, straddr, sizeof(straddr), NULL);
			LOG_ERR_FMT(error, "%s - %s: io_net_snd_tune()",
			    str_hub->name, straddr);
		}
	}
	if (0 != (STR_HUB_S_F_SKT_HALFCLOSED & hub_params->flags)) {
		if (0 != shutdown((int)strh_cli->skt, SHUT_RD) &&
		    0 != LOG_IS_ENABLED()) {
			error = errno;
			sa_addr_port_to_str(&strh_cli->remonte_addr, straddr, sizeof(straddr), NULL);
			LOG_ERR_FMT(error, "%s - %s: shutdown(..., SHUT_RD)",
			    str_hub->name, straddr);
		}
	}
	error = io_net_set_tcp_nodelay(strh_cli->skt, (STR_HUB_S_F_SKT_TCP_NODELAY & hub_params->flags));
	if (0 != error && 0 != LOG_IS_ENABLED()) {
		sa_addr_port_to_str(&strh_cli->remonte_addr, straddr, sizeof(straddr), NULL);
		LOG_ERR_FMT(error, "%s - %s: io_net_set_tcp_nodelay()",
		    str_hub->name, straddr);
	}
	error = io_net_set_tcp_nopush(strh_cli->skt, (STR_HUB_S_F_SKT_TCP_NOPUSH & hub_params->flags));
	if (0 != error && 0 != LOG_IS_ENABLED()) {
		sa_addr_port_to_str(&strh_cli->remonte_addr, straddr, sizeof(straddr), NULL);
		LOG_ERR_FMT(error, "%s - %s: io_net_set_tcp_nopush()",
		    str_hub->name, straddr);
	}
	if (0 != hub_params->cc_name_size) {
		error = io_net_set_tcp_cc(strh_cli->skt, hub_params->cc_name,
	            hub_params->cc_name_size);
		if (0 != error && 0 != LOG_IS_ENABLED()) {
			sa_addr_port_to_str(&strh_cli->remonte_addr, straddr, sizeof(straddr), NULL);
			LOG_ERR_FMT(error, "%s - %s: io_net_set_tcp_cc()",
			    str_hub->name, straddr);
		}
	}

	if (0 != LOG_IS_ENABLED()) {
		sa_addr_port_to_str(&strh_cli->remonte_addr, straddr, sizeof(straddr), NULL);
		LOG_INFO_FMT("%s - %s: attached, cli_count = %zu",
		    str_hub->name, straddr, (str_hub->cli_count + 1));
	}

	TAILQ_INSERT_HEAD(&str_hub->cli_head, strh_cli, next);
	str_hub->cli_count ++;
	free(cli_data);
}



int
str_hub_send_to_client(str_hub_p str_hub, str_hub_cli_p strh_cli,
    size_t *transfered_size) {
	int error = 0;
	off_t sbytes = 0;
	size_t data2send, i, iov_cnt, drop_size, tr_size = 0;
	struct iovec iov[4];

	/* Get data avail for client. */
	data2send = r_buf_data_avail_size(str_hub->r_buf, &strh_cli->rpos, &drop_size);
	if (str_hub->shbskt->hub_params.snd_block_min_size > data2send)
		return (0); /* Not enough data for this client. */
	if (data2send > str_hub->shbskt->hub_params.skt_snd_buf) {
		data2send = str_hub->shbskt->hub_params.skt_snd_buf;
	}
	iov_cnt = r_buf_data_get(str_hub->r_buf, &strh_cli->rpos, data2send,
	    (iovec_p)iov, 4, &drop_size, NULL);
	if (0 == iov_cnt) { /* Nothink to send? */
		if (0 != drop_size)
			error = -1;
		goto err_out;
	}
	/* Send. */
	r_buf_data_get_conv2off(str_hub->r_buf, (iovec_p)iov, iov_cnt);
	for (i = 0; i < iov_cnt; i ++) {
		error = io_net_sendfile(str_hub->r_buf_fd, strh_cli->skt,
		    (off_t)iov[i].iov_base, iov[i].iov_len,
		    (IO_NET_SF_F_NODISKIO), &sbytes);
		tr_size += (size_t)sbytes;
		if (0 != error)
			break;
	}
	/* Supress some errors. */
	error = IO_NET_ERR_FILTER(error);
	/* Update client read pos. */
	r_buf_rpos_inc(str_hub->r_buf, &strh_cli->rpos, tr_size);

err_out:
	if (NULL != transfered_size) {
		(*transfered_size) = tr_size;
	}

	return (error);
}

int
str_hub_send_to_clients(str_hub_p str_hub) {
	int error;
	str_hub_cli_p strh_cli, strh_cli_temp;
	struct msghdr mhdr;
	struct iovec iov[4];
	ssize_t ios;
	size_t transfered_size;
	char straddr[STR_ADDR_LEN];

	TAILQ_FOREACH_SAFE(strh_cli, &str_hub->cli_head, next, strh_cli_temp) {
		transfered_size = 0;
		/* Send HTTP headers if needed. */
		if (0 == (STR_HUB_CLI_STATE_F_HTTP_HDRS_SENDED & strh_cli->flags)) {
			mem_bzero(&mhdr, sizeof(mhdr));
			mhdr.msg_iov = (struct iovec*)iov;
			mhdr.msg_iovlen = 3;
			iov[0].iov_base = MK_RW_PTR("HTTP/1.1 200 OK\r\n");
			iov[0].iov_len = 17;
			iov[1].iov_base = str_hub->shbskt->base_http_hdrs;
			iov[1].iov_len = str_hub->shbskt->base_http_hdrs_size;
			iov[2].iov_base = str_hub->shbskt->hub_params.cust_http_hdrs;
			iov[2].iov_len = str_hub->shbskt->hub_params.cust_http_hdrs_size;
			/* Skip allready sended data. */
			iovec_set_offset(mhdr.msg_iov, (size_t)mhdr.msg_iovlen, strh_cli->offset);
			ios = sendmsg((int)strh_cli->skt, &mhdr, (MSG_DONTWAIT | MSG_NOSIGNAL));
			if (-1 == ios) { /* Error happen. */
				/* Supress some errors. */
				error = IO_NET_ERR_FILTER(errno);
				goto error_on_send;
			}
			LOGD_EV_FMT("HTTP hdr: %zu", ios);
			strh_cli->offset += (size_t)ios;
			if (iovec_calc_size(mhdr.msg_iov, (size_t)mhdr.msg_iovlen) >
			    (size_t)ios) /* Not all HTTP headers sended. */
				continue; /* Try to send next headers part later. */
			strh_cli->offset = 0;
			strh_cli->flags |= STR_HUB_CLI_STATE_F_HTTP_HDRS_SENDED;
		}
		/* Init uninitialized client rpos. */
		if (0 == (STR_HUB_CLI_STATE_F_RPOS_INITIALIZED & strh_cli->flags)) {
			strh_cli->flags |= STR_HUB_CLI_STATE_F_RPOS_INITIALIZED;
			r_buf_rpos_init(str_hub->r_buf, &strh_cli->rpos,
			    str_hub->shbskt->hub_params.precache);
		}
		error = str_hub_send_to_client(str_hub, strh_cli, &transfered_size);
error_on_send:
		if (0 != error) {
			if (0 != LOG_IS_ENABLED()) {
				sa_addr_port_to_str(&strh_cli->remonte_addr, straddr, sizeof(straddr), NULL);
				LOG_ERR_FMT(error, "%s - %s: disconnected.",
				    str_hub->name, straddr);
			}
			if (-1 != error ||
			    0 != (STR_HUB_S_F_DROP_SLOW_CLI & str_hub->shbskt->hub_params.flags))
				str_hub_cli_destroy(str_hub, strh_cli);
			continue;
		}
		str_hub->sended_count += transfered_size;
	}

	return (0);
}


/* MPEG payload-type constants - adopted from VLC 0.8.6 */
#define P_MPGA		0x0E /* MPEG audio */
#define P_MPGV		0x20 /* MPEG video */

static int
str_src_recv_mc_cb(io_task_p iotask, int error, uint32_t eof __unused,
    size_t data2transfer_size, void *arg) {
	str_hub_p str_hub = arg;
	uintptr_t ident;
	ssize_t ios;
	uint8_t *buf;
	size_t transfered_size = 0, req_buf_size, buf_size, start_off = 0, end_off = 0;

	if (0 != error) {
err_out:
		LOG_ERR(error, "on receive");
		str_hub_destroy_int(str_hub);
		return (IO_TASK_CB_NONE); /* Receiver destroyed. */
	}
	if (NULL == str_hub->r_buf) { /* Delay ring buf allocation. */
		error = str_src_r_buf_alloc(str_hub);
		if (0 != error)
			goto err_out;
	}

	ident = io_task_ident_get(iotask);
	req_buf_size = STR_SRC_UDP_PKT_SIZE_STD;
	while (transfered_size < data2transfer_size) { /* recv loop. */
		buf_size = r_buf_wbuf_get(str_hub->r_buf, req_buf_size, &buf);
		ios = recv((int)ident, buf, buf_size, MSG_DONTWAIT);
		if (-1 == ios) {
			error = errno;
			if (0 == error)
				error = EINVAL;
			error = IO_NET_ERR_FILTER(error);
			if (0 == error && STR_SRC_UDP_PKT_SIZE_MAX > buf_size) {
				/* Possible not enough buf space. */
				req_buf_size = STR_SRC_UDP_PKT_SIZE_MAX;
				continue; /* Retry! */
			}
			break;
		}
		if (0 == ios)
			break;
		transfered_size += (size_t)ios;
		if (MPEG2_TS_PKT_SIZE_MIN > (size_t)ios)
			continue; /* Packet to small, drop. */
		if (MPEG2_TS_HDR_IS_VALID((mpeg2_ts_hdr_p)buf)) { /* Test_ for RTP. */
			buf_size = (size_t)ios;
		} else if (0 == rtp_payload_get(buf, (size_t)ios, &start_off, &end_off)) {
			/* XXX skip payload bulk data. */
			if (P_MPGA == ((rtp_hdr_p)buf)->pt ||
			    P_MPGV == ((rtp_hdr_p)buf)->pt)
				start_off += 4;
			buf_size = ((size_t)ios - (start_off + end_off));
			if (MPEG2_TS_PKT_SIZE_MIN > buf_size)
				continue; /* Packet to small, drop. */
			/* Prevent fragmentation, zero move: buf += start_off; */
			memmove(buf, (buf + start_off), buf_size);
		} else {
			continue; /* Packet unknown, drop. */
		}
		r_buf_wbuf_set2(str_hub->r_buf, buf, buf_size, NULL);
	} /* end recv while */
	if (0 != error) {
		LOG_ERR(error, "recv()");
		if (0 == transfered_size)
			goto rcv_next;
	}
	/* Calc speed. */
	str_hub->received_count += transfered_size;
	thrpt_gettimev(str_hub->thrpt, 0, &str_hub->tp_last_recv);
	
#ifdef __linux__ /* Linux specific code. */
	/* Ring buf LOWAT emulator. */
	str_hub->r_buf_rcvd += transfered_size;
	if (str_hub->r_buf_rcvd < str_hub->shbskt->src_params.skt_rcv_lowat)
		goto rcv_next;
	str_hub->r_buf_rcvd = 0;
#endif /* Linux specific code. */
	str_hub_send_to_clients(str_hub);

rcv_next:
	return (IO_TASK_CB_CONTINUE);
}


int
str_src_r_buf_alloc(str_hub_p str_hub) {
	int error;
	char hash[(MD5_HASH_STR_SIZE + 1)], filename[128];
	struct timespec tv_now;

	/* Create buf */
	thrpt_gettimev(str_hub->thrpt, 0, &tv_now);
	md5_get_digest_strA((char*)&tv_now, sizeof(tv_now), (char*)hash);
	snprintf(filename, sizeof(filename), "/tmp/msd-%zu-%s.tmp",
	    (size_t)getpid(), hash);
	str_hub->r_buf_fd = (uintptr_t)open(filename, (O_CREAT | O_EXCL | O_RDWR), 0600);
	if ((uintptr_t)-1 == str_hub->r_buf_fd) {
		error = errno;
		LOG_ERR_FMT(error, "open(): %s", filename);
		goto err_out;
	}
	if (0 != flock((int)str_hub->r_buf_fd, LOCK_EX)) {
		LOG_ERR_FMT(errno, "flock(): %s", filename);
	}

	/* Truncate it to the correct size */
	if (0 != ftruncate((int)str_hub->r_buf_fd, (off_t)str_hub->shbskt->hub_params.ring_buf_size)) {
		error = errno;
		LOG_ERR_FMT(error, "ftruncate(): %s", filename);
		goto err_out;
	}
	str_hub->r_buf = r_buf_alloc(str_hub->r_buf_fd, str_hub->shbskt->hub_params.ring_buf_size,
	    1024/*MPEG2_TS_PKT_SIZE_188*/);
	if (NULL == str_hub->r_buf) {
		error = errno;
		LOGD_ERR(error, "r_buf_alloc()");
		goto err_out;
	}
	unlink(filename);
	
	return (0);

err_out:
	/* Error. */
	flock((int)str_hub->r_buf_fd, LOCK_UN);
	close((int)str_hub->r_buf_fd);
	unlink(filename);
	LOG_ERR(error, "...");
	return (error);
}

void
str_src_r_buf_free(str_hub_p str_hub) {

	if (NULL == str_hub)
		return;
	flock((int)str_hub->r_buf_fd, LOCK_UN);
	close((int)str_hub->r_buf_fd);
	str_hub->r_buf_fd = (uintptr_t)-1;
	r_buf_free(str_hub->r_buf);
	str_hub->r_buf = NULL;
}
