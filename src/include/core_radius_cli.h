/*-
 * Copyright (c) 2014 - 2015 Rozhuk Ivan <rozhuk.im@gmail.com>
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


#ifndef __CORE_RADIUS_CLIENT_H__
#define __CORE_RADIUS_CLIENT_H__


#include "core_thrp.h"
#include "radius_pkt.h"



typedef struct radius_cli_s		*radius_cli_p; /* thread pool */
typedef struct radius_cli_query_s	*radius_cli_query_p; /* thread pool */

typedef struct radius_cli_settings_s {
	size_t		servers_max;		/* Maximum number of servers. */
	size_t		thr_queue_max;		/* Minimum number of queries in queue per thread. */
	size_t		thr_sockets_min;	/* Minimum number of sockets. */
	size_t		thr_sockets_max;	/* Maximum number of sockets. */
	uint32_t	skt_rcv_buf;		/* kb */
	uint32_t	skt_snd_buf;		/* kb */
	uint8_t		NAS_Identifier[RADIUS_ATTR_DATA_SIZE_MAX];
	size_t		NAS_Identifier_size;
} radius_cli_settings_t, *radius_cli_settings_p;
/* Default values. */
#define RADIUS_CLIENT_S_DEF_SERVERS_MAX		(8)
#define RADIUS_CLIENT_S_DEF_THR_QUEUE_MAX	(1024)
#define RADIUS_CLIENT_S_DEF_THR_SOCKETS_MIN	(1)
#define RADIUS_CLIENT_S_DEF_THR_SOCKETS_MAX	(8)
#define RADIUS_CLIENT_S_DEF_SKT_RCV_BUF		(256)
#define RADIUS_CLIENT_S_DEF_SKT_SND_BUF		(128)

typedef struct radius_cli_server_settings_s {
	uint8_t		shared_secret[RADIUS_A_T_USER_PASSWORD_MAX_LEN];
	size_t		shared_secret_size;
	/* Retransmission params from rfc5080. */
	uint64_t	retrans_time_init; /* IRT - Initial retransmission time in ms. */
	uint64_t	retrans_time_max; /* MRT - Maximum retransmission time in ms. */
	uint64_t	retrans_duration_max; /* MRD - Maximum retransmission duration in ms. */
	size_t		retrans_count_max; /* MRC - Maximum retransmission count. */
	struct sockaddr_storage	addr;	/* Server addr. */
} radius_cli_srv_settings_t, *radius_cli_srv_settings_p;
/* Default values. */
#define RADIUS_CLIENT_SRV_S_DEF_IRT		(2000)
#define RADIUS_CLIENT_SRV_S_DEF_MRT		(16000)
#define RADIUS_CLIENT_SRV_S_DEF_MRD		(30000)
#define RADIUS_CLIENT_SRV_S_DEF_MRC		(5)



typedef void (*radius_cli_cb)(radius_cli_query_p query, rad_pkt_hdr_p pkt,
    int error, io_buf_p buf, void *arg);


void	radius_client_def_settings(radius_cli_settings_p s);
#ifdef RADIUS_CLIENT_XML_CONFIG
int	radius_client_xml_load_settings(const uint8_t *buf, size_t buf_size,
	    radius_cli_settings_p s);
int	radius_client_server_xml_load_settings(const uint8_t *buf, size_t buf_size,
	    radius_cli_srv_settings_p s);
int	radius_client_xml_load_start(const uint8_t *buf, size_t buf_size,
	    thrp_p thrp,
	    radius_cli_settings_p cli_settings,
	    radius_cli_srv_settings_p cli_srv_settings,
	    radius_cli_p *rad_cli);
#endif


int	radius_client_create(thrp_p thrp, radius_cli_settings_p s,
	    radius_cli_p *rad_cli_ret);
void	radius_client_destroy(radius_cli_p rad_cli);

void	radius_client_server_def_settings(radius_cli_srv_settings_p s);
int	radius_client_server_add(radius_cli_p rad_cli, radius_cli_srv_settings_p s);
void	radius_client_server_remove_by_addr(radius_cli_p rad_cli,
	    struct sockaddr_storage *addr);


int	radius_client_query(radius_cli_p rad_cli, thrpt_p thrpt, size_t query_id,
	    io_buf_p buf, radius_cli_cb cb_func, void *arg,
	    radius_cli_query_p *query_ret);
#define RADIUS_CLIENT_QUERY_ID_AUTO	(~((size_t)0))

void	radius_client_query_cancel(radius_cli_query_p query);




#endif // __CORE_RADIUS_CLIENT_H__
