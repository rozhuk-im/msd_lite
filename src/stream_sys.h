/*-
 * Copyright (c) 2012-2023 Rozhuk Ivan <rozhuk.im@gmail.com>
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


#ifndef __CORE_STREAM_SYS_H__
#define __CORE_STREAM_SYS_H__


#include <sys/queue.h>
#include <time.h>

#include "utils/macro.h"
#include "threadpool/threadpool.h"
#include "utils/io_buf.h"
#include "threadpool/threadpool_task.h"
#include "utils/ring_buffer.h"


typedef struct str_hub_s	*str_hub_p;
typedef struct str_hubs_bckt_s	*str_hubs_bckt_p;
typedef struct str_src_s	*str_src_p;



typedef struct str_hub_cli_s {
	TAILQ_ENTRY(str_hub_cli_s) next; /* For list. */
	uintptr_t	skt;		/* socket */
	r_buf_rpos_t	rpos;		/* Ring buf read pos. */
	time_t		conn_time;	/* Connection start time. */
	size_t		offset;		/* For HTTP headers. */
	uint32_t	flags;		/* Flags. */
	/* HTTP specific data. */
	uint8_t		*user_agent;
	size_t		user_agent_size;
	struct sockaddr_storage remonte_addr; /* Client address. */
	struct sockaddr_storage	xreal_addr;
} str_hub_cli_t, *str_hub_cli_p;
TAILQ_HEAD(str_hub_cli_head, str_hub_cli_s);

/* Flags. */
#define STR_HUB_CLI_STATE_F_RPOS_INITIALIZED	(((uint32_t)1) << 0)
#define STR_HUB_CLI_STATE_F_HTTP_HDRS_SENDED	(((uint32_t)1) << 8)
/* Limit for User-Agent len. */
#define STR_HUB_CLI_USER_AGENT_MAX_SIZE	256

/*
 * 1. Client connect via http, create/find mc receiver, ref_count ++;
 * 2. Client send http headers, add self to add_cli_list_head and ref_count --;
 * 3. Mc receiver move client from add_cli_list_head to cli_list_head and start
 * send stream.
 */



typedef struct str_hub_settings_s {
	uint32_t	flags;
	uint32_t	skt_snd_buf;	/* For receiver clients. */
	/* Client settings and defaults. */
	size_t		cc_name_size;
	char		cc_name[TCP_CA_NAME_MAX];/* tcp congestion control forced for client. */
	/* End Client settings and defaults. */
	size_t		ring_buf_size;	/* Size of ring buf. */
	size_t		precache;
	size_t		snd_block_min_size;
	uint8_t		*cust_http_hdrs;
	size_t		cust_http_hdrs_size;
} str_hub_settings_t, *str_hub_settings_p;
/* Flags. */
#define STR_HUB_S_F_DROP_SLOW_CLI		(((uint32_t)1) <<  5) /* Disconnect lagged clients. */
#define STR_HUB_S_F_SKT_HALFCLOSED		(((uint32_t)1) << 10) /* Enable shutdown(SHUT_RD) for clients. */
#define STR_HUB_S_F_SKT_TCP_NODELAY		(((uint32_t)1) << 11) /* Enable TCP_NODELAY for clients. */
#define STR_HUB_S_F_SKT_TCP_NOPUSH		(((uint32_t)1) << 12) /* Enable TCP_NOPUSH for clients. */
/* Default values. */
#define STR_HUB_S_DEF_FLAGS		(0)
#define STR_HUB_S_DEF_RING_BUF_SIZE	(1 * 1024) /* kb */
#define STR_HUB_S_DEF_PRECAHE		(1 * 1024) /* kb */
#define STR_HUB_S_DEF_SND_BLOCK_MIN_SIZE (64) /* kb */
#define STR_HUB_S_DEF_SKT_SND_BUF	(256)	/* kb */


/* Connection info */
/* UDP source */
typedef struct str_src_conn_udp_s {
	struct sockaddr_storage	addr;
} str_src_conn_udp_t, *str_src_conn_udp_p;

/* Multicast [rtp] source */
typedef struct str_src_conn_mc_s {
	str_src_conn_udp_t udp;
	uint32_t	if_index;
	uint32_t	rejoin_time;
} str_src_conn_mc_t, *str_src_conn_mc_p;
#define STR_SRC_CONN_DEF_IFINDEX	((uint32_t)-1)

typedef union str_src_conn_params_s {
	str_src_conn_udp_t	udp;
	str_src_conn_mc_t	mc;
} str_src_conn_params_t, *str_src_conn_params_p;

typedef struct str_src_settings_s {
	uint32_t	skt_rcv_buf;	/* For receiver. */
	uint32_t	skt_rcv_lowat;	/* For receiver. */
	uint64_t	rcv_timeout;	/* No multicast time to self destroy. */
} str_src_settings_t, *str_src_settings_p;
/* Default values. */
#define STR_SRC_S_DEF_SKT_RCV_BUF	(512)	/* kb */
#define STR_SRC_S_DEF_SKT_RCV_LOWAT	(48)	/* kb */
#define STR_SRC_S_DEF_UDP_RCV_TIMEOUT	(2)	/* s */


/*
 * Auto generated channel name:
 * /udp/IPv4MC:PORT@IF_NAME
 */

typedef struct str_hub_s {
	TAILQ_ENTRY(str_hub_s) next;
	str_hubs_bckt_p	shbskt;
	uint8_t		*name;		/* Stream hub unique name. */
	size_t		name_size;	/* Name size. */
	struct str_hub_cli_head cli_head; /* List with clients. */
	size_t		cli_count;	/* Count clients. */
	/* For stat */
	/* Baud rate calculation. */
	struct timespec tp_last_recv;	/* For baud rate calculation and status. */
	uint64_t	received_count;	/* Accumulator for baud rate calculation. */
	uint64_t	sended_count;	/* Accumulator for baud rate calculation. */
	uint64_t	baud_rate_in;	/* Total rate in (megabit per sec). */
	uint64_t	baud_rate_out;	/* Total rate out (megabit per sec). */
	uint64_t	dropped_count;	/* Dropped clients count. */
	/* -- stat */
	tp_task_p	tptask;		/* Data/Packets receiver. */
	uintptr_t	r_buf_fd;	/* r_buf shared memory file descriptor */
	r_buf_p		r_buf;		/* Ring buf, write pos. */
#ifdef __linux__ /* Linux specific code. */
	size_t		r_buf_rcvd;	/* Ring buf LOWAT emulator. */
#endif /* Linux specific code. */
	time_t		next_rejoin_time; /* Next time to send leave+join. */

	tpt_p		tpt;		/* Thread data for all IO operations. */
	str_src_conn_params_t src_conn_params;	/* Point to str_src_conn_XXX */
} str_hub_t;
TAILQ_HEAD(str_hub_head, str_hub_s);


/* Per thread and summary stats. */
typedef struct str_hubs_stat_s {
	size_t		str_hub_count;	/* Stream hubs count. */
	size_t		cli_count;	/* Total clients count. */
	uint64_t	baud_rate_in;	/* Total rate in (megabit per sec). */
	uint64_t	baud_rate_out;	/* Total rate out (megabit per sec). */
} str_hubs_stat_t, *str_hubs_stat_p;

/* Per thread data */
typedef struct str_hub_thread_data_s {
	struct str_hub_head	hub_head;	/* List with stream hubs per thread. */
	str_hubs_stat_t		stat;
} str_hub_thrd_t, *str_hub_thrd_p;


typedef struct str_hubs_bckt_s {
	tp_p		tp;
	struct timespec	tp_last_tmr;	/* For baud rate calculation. */
	struct timespec	tp_last_tmr_next; /* For baud rate calculation. */
	tp_udata_t	service_tmr;	/* Service timer. */
	str_hub_thrd_p	thr_data;	/* Per thread hubs + stat. */
	size_t		base_http_hdrs_size;
	uint8_t		base_http_hdrs[512];
	str_hub_settings_t hub_params;	/* Settings. */
	str_src_settings_t src_params;	/* Settings. */
} str_hubs_bckt_t;


void	str_hub_settings_def(str_hub_settings_p p_ret);
void	str_src_settings_def(str_src_settings_p p_ret);
void	str_src_conn_def(str_src_conn_params_p src_conn_params);


int	str_hubs_bckt_create(tp_p tp, const char *app_ver,
	    str_hub_settings_p hub_params, str_src_settings_p src_params,
	    str_hubs_bckt_p *shbskt_ret);
void	str_hubs_bckt_destroy(str_hubs_bckt_p shbskt);

typedef void (*str_hubs_bckt_enum_cb)(tpt_p tpt, str_hub_p str_hub, void *udata);
int	str_hubs_bckt_enum(str_hubs_bckt_p shbskt, str_hubs_bckt_enum_cb enum_cb,
	    void *udata, tpt_msg_done_cb done_cb);
int	str_hubs_bckt_stat_summary(str_hubs_bckt_p shbskt, str_hubs_stat_p stat);


str_hub_cli_p str_hub_cli_alloc(uintptr_t skt, const char *ua, size_t ua_size);
void	str_hub_cli_destroy(str_hub_p str_hub, str_hub_cli_p strh_cli);

int	str_hub_cli_attach(str_hubs_bckt_p shbskt, str_hub_cli_p strh_cli,
	    uint8_t *hub_name, size_t hub_name_size,
	    str_src_conn_params_p src_conn_params);



#endif // __CORE_STREAM_SYS_H__
