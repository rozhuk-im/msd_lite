/*-
 * Copyright (c) 2012 - 2014 Rozhuk Ivan <rozhuk.im@gmail.com>
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
//#include <sys/stat.h> /* For mode constants */
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/tcp.h>


#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h> /* snprintf, fprintf */
#include <time.h>
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */

#include "core_macro.h"
#include "core_io_buf.h"
#include "core_io_task.h"
#include "core_io_net.h"
#include "core_net_helpers.h"
#include "core_helpers.h"
#include "core_http_srv.h"
#include "stream_sys.h"
#include "core_info.h"
#include "msd_lite_stat_text.h"



int		gen_sock_tcp_stat_text(uintptr_t skt, char *tabs, io_buf_p buf);
static void	gen_hub_stat_text_entry_enum_cb(thrpt_p thrpt, str_hub_p str_hub,
		    void *udata);
static void	gen_hub_stat_text_enum_done_cb(thrpt_p thrpt, size_t send_msg_cnt,
		    size_t error_cnt, void *udata);



int
gen_sock_tcp_stat_text(uintptr_t skt, char *tabs, io_buf_p buf) {
	socklen_t optlen;
	struct tcp_info info;
	char tcpi_opts[64];
	size_t tm;

	if (NULL == buf)
		return (EINVAL);
	optlen = sizeof(info);
	if (0 != getsockopt(skt, IPPROTO_TCP, TCP_INFO, &info, &optlen))
		return (errno);
	if (10 < info.tcpi_state)
		info.tcpi_state = 11; /* unknown */
	tm = 0;
	if (0 != (info.tcpi_options & TCPI_OPT_TIMESTAMPS))
		tm += snprintf((tcpi_opts + tm), ((sizeof(tcpi_opts) - 1) - tm), "TIMESTAMPS ");
	if (0 != (info.tcpi_options & TCPI_OPT_SACK))
		tm += snprintf((tcpi_opts + tm), ((sizeof(tcpi_opts) - 1) - tm), "SACK ");
	if (0 != (info.tcpi_options & TCPI_OPT_WSCALE))
		tm += snprintf((tcpi_opts + tm), ((sizeof(tcpi_opts) - 1) - tm), "WSCALE ");
	if (0 != (info.tcpi_options & TCPI_OPT_ECN))
		tm += snprintf((tcpi_opts + tm), ((sizeof(tcpi_opts) - 1) - tm), "ECN ");

#ifdef BSD /* BSD specific code. */
	char *tcpi_state[] = {
		(char*)"CLOSED",
		(char*)"LISTEN",
		(char*)"SYN_SENT",
		(char*)"SYN_RECEIVED",
		(char*)"ESTABLISHED",
		(char*)"CLOSE_WAIT",
		(char*)"FIN_WAIT_1",
		(char*)"CLOSING",
		(char*)"LAST_ACK",
		(char*)"FIN_WAIT_2",
		(char*)"TIME_WAIT",
		(char*)"UNKNOWN"
	};

	if (0 != (info.tcpi_options & TCPI_OPT_TOE))
		tm += snprintf((tcpi_opts + tm), ((sizeof(tcpi_opts) - 1) - tm), "TOE ");

	IO_BUF_PRINTF(buf,
	    "%sTCP FSM state: %s\r\n"
	    "%sOptions enabled on conn: %s\r\n"
	    "%sRFC1323 send shift value: %"PRIu8"\r\n"
	    "%sRFC1323 recv shift value: %"PRIu8"\r\n"
	    "%sRetransmission timeout (usec): %"PRIu32"\r\n"
	    "%sMax segment size for send: %"PRIu32"\r\n"
	    "%sMax segment size for receive: %"PRIu32"\r\n"
	    "%sTime since last recv data (usec): %"PRIu32"\r\n"
	    "%sSmoothed RTT in usecs: %"PRIu32"\r\n"
	    "%sRTT variance in usecs: %"PRIu32"\r\n"
	    "%sSlow start threshold: %"PRIu32"\r\n"
	    "%sSend congestion window: %"PRIu32"\r\n"
	    "%sAdvertised recv window: %"PRIu32"\r\n"
	    "%sAdvertised send window: %"PRIu32"\r\n"
	    "%sNext egress seqno: %"PRIu32"\r\n"
	    "%sNext ingress seqno: %"PRIu32"\r\n"
	    "%sHWTID for TOE endpoints: %"PRIu32"\r\n"
	    "%sRetransmitted packets: %"PRIu32"\r\n"
	    "%sOut-of-order packets: %"PRIu32"\r\n"
	    "%sZero-sized windows sent: %"PRIu32"\r\n",
	    tabs, tcpi_state[info.tcpi_state], tabs, tcpi_opts,
	    tabs, info.tcpi_snd_wscale, tabs, info.tcpi_rcv_wscale,
	    tabs, info.tcpi_rto, tabs, info.tcpi_snd_mss, tabs, info.tcpi_rcv_mss,
	    tabs, info.tcpi_last_data_recv,
	    tabs, info.tcpi_rtt, tabs, info.tcpi_rttvar,
	    tabs, info.tcpi_snd_ssthresh, tabs, info.tcpi_snd_cwnd, 
	    tabs, info.tcpi_rcv_space,
	    tabs, info.tcpi_snd_wnd,
	    tabs, info.tcpi_snd_nxt, tabs, info.tcpi_rcv_nxt,
	    tabs, info.tcpi_toe_tid, tabs, info.tcpi_snd_rexmitpack,
	    tabs, info.tcpi_rcv_ooopack, tabs, info.tcpi_snd_zerowin);
#endif /* BSD specific code. */
#ifdef __linux__ /* Linux specific code. */
	char *tcpi_state[] = {
		(char*)"ESTABLISHED",
		(char*)"SYN_SENT",
		(char*)"SYN_RECEIVED",
		(char*)"FIN_WAIT_1",
		(char*)"FIN_WAIT_2",
		(char*)"TIME_WAIT",
		(char*)"CLOSED",
		(char*)"CLOSE_WAIT",
		(char*)"LAST_ACK",
		(char*)"LISTEN",
		(char*)"CLOSING",
		(char*)"UNKNOWN"
	};

	IO_BUF_PRINTF(buf,
	    "%sTCP FSM state: %s\r\n"
	    "%sca_state: %"PRIu8"\r\n"
	    "%sretransmits: %"PRIu8"\r\n"
	    "%sprobes: %"PRIu8"\r\n"
	    "%sbackoff: %"PRIu8"\r\n"
	    "%sOptions enabled on conn: %s\r\n"
	    "%sRFC1323 send shift value: %"PRIu8"\r\n"
	    "%sRFC1323 recv shift value: %"PRIu8"\r\n"
	    "%sRetransmission timeout (usec): %"PRIu32"\r\n"
	    "%sato (usec): %"PRIu32"\r\n"
	    "%sMax segment size for send: %"PRIu32"\r\n"
	    "%sMax segment size for receive: %"PRIu32"\r\n"
	    "%sunacked: %"PRIu32"\r\n"
	    "%ssacked: %"PRIu32"\r\n"
	    "%slost: %"PRIu32"\r\n"
	    "%sretrans: %"PRIu32"\r\n"
	    "%sfackets: %"PRIu32"\r\n"
	    "%slast_data_sent: %"PRIu32"\r\n"
	    "%slast_ack_sent: %"PRIu32"\r\n"
	    "%sTime since last recv data (usec): %"PRIu32"\r\n"
	    "%slast_ack_recv: %"PRIu32"\r\n"
	    "%spmtu: %"PRIu32"\r\n"
	    "%srcv_ssthresh: %"PRIu32"\r\n"
	    "%srtt: %"PRIu32"\r\n"
	    "%srttvar: %"PRIu32"\r\n"
	    "%ssnd_ssthresh: %"PRIu32"\r\n"
	    "%ssnd_cwnd: %"PRIu32"\r\n"
	    "%sadvmss: %"PRIu32"\r\n"
	    "%sreordering: %"PRIu32"\r\n"
	    "%srcv_rtt: %"PRIu32"\r\n"
	    "%srcv_space: %"PRIu32"\r\n"
	    "%stotal_retrans: %"PRIu32"\r\n",
	    tabs, tcpi_state[info.tcpi_state], tabs, info.tcpi_ca_state,
	    tabs, info.tcpi_retransmits, tabs, info.tcpi_probes,
	    tabs, info.tcpi_backoff, tabs, tcpi_opts,
	    tabs, info.tcpi_snd_wscale, tabs, info.tcpi_rcv_wscale,
	    tabs, info.tcpi_rto, tabs, info.tcpi_ato,
	    tabs, info.tcpi_snd_mss, tabs, info.tcpi_rcv_mss,
	    tabs, info.tcpi_unacked, tabs, info.tcpi_sacked,
	    tabs, info.tcpi_lost, tabs, info.tcpi_retrans,
	    tabs, info.tcpi_fackets, tabs, info.tcpi_last_data_sent,
	    tabs, info.tcpi_last_ack_sent, tabs, info.tcpi_last_data_recv,
	    tabs, info.tcpi_last_ack_recv, tabs, info.tcpi_pmtu,
	    tabs, info.tcpi_rcv_ssthresh,
	    tabs, info.tcpi_rtt, tabs, info.tcpi_rttvar,
	    tabs, info.tcpi_snd_ssthresh, tabs, info.tcpi_snd_cwnd,
	    tabs, info.tcpi_advmss,
	    tabs, info.tcpi_reordering, tabs, info.tcpi_rcv_rtt,
	    tabs, info.tcpi_rcv_space, tabs, info.tcpi_total_retrans
	    );
#endif /* Linux specific code. */
	return (0);
}



int
gen_hub_stat_text_send_async(str_hubs_bckt_p shbskt, http_srv_cli_p cli) {
	int error;
	size_t tm;
	str_hubs_stat_t hstat;

	error = str_hubs_bckt_stat_summary(shbskt, &hstat);
	if (0 != error)
		return (error);
	tm = (16384 +
	    (hstat.str_hub_count * 1024) +
	    1024 +
	    (hstat.cli_count * (160 + 256 + 1024))
	    );
	error = http_srv_cli_buf_realloc(cli, 0, tm);
	if (0 != error) /* Need more space! */
		return (error);

	error = str_hubs_bckt_enum(shbskt, gen_hub_stat_text_entry_enum_cb, cli,
	    gen_hub_stat_text_enum_done_cb);

	return (error);
}
static void
gen_hub_stat_text_entry_enum_cb(thrpt_p thrpt, str_hub_p str_hub, void *udata) {
	http_srv_cli_p cli = udata;
	io_buf_p buf = http_srv_cli_get_buf(cli);
	str_hub_cli_p strh_cli, strh_cli_temp;
	time_t cur_time, time_conn;
	char straddr[STR_ADDR_LEN], straddr2[STR_ADDR_LEN], ifname[(IFNAMSIZ + 1)], str_time[64];
	uint32_t i;
	//str_hub_src_conn_udp_tcp_p conn_udp_tcp;
	str_src_conn_mc_p conn_mc;

	cur_time = thrpt_gettime(thrpt, 0);
	IO_BUF_PRINTF(buf,
	    "\r\n"
	    "Stream hub: %s		[thread: %zu @ cpu %i, clients: %zu, dropped clients: %"PRIu64"]\r\n",
	    str_hub->name,
	    thrp_thread_get_num(thrpt), thrp_thread_get_cpu_id(thrpt),
	    str_hub->cli_count, str_hub->dropped_count);
	/* Sources. */
	IO_BUF_COPYIN_CSTR(buf, "  Source: multicast");
	conn_mc = &str_hub->src_conn_params.mc;
	if (0 != ss_to_str_addr_port(&conn_mc->udp.addr, straddr,
	    sizeof(straddr), NULL))
		memcpy(straddr, "<unable to format>", 20);
	ifname[0] = 0;
	if_indextoname(conn_mc->if_index, ifname);
	IO_BUF_PRINTF(buf, " %s@%s	",
	    straddr, ifname);

	IO_BUF_PRINTF(buf,
	    "[state: OK, status: 0, rate: %"PRIu64"]\r\n",
	    str_hub->baud_rate_in);

	/* Clients. */
	TAILQ_FOREACH_SAFE(strh_cli, &str_hub->cli_head, next, strh_cli_temp) {
		if (0 != ss_to_str_addr_port(&strh_cli->remonte_addr,
		    straddr, sizeof(straddr), NULL))
			memcpy(straddr, "<unable to format>", 20);
		if (0 != ss_to_str_addr_port(&strh_cli->xreal_addr,
		    straddr2, sizeof(straddr2), NULL))
			memcpy(straddr, "<unable to format>", 20);
		//&cli_ud->xreal_addr
		time_conn = difftime(cur_time, strh_cli->conn_time);
		fmt_as_uptime(&time_conn, str_time, sizeof(str_time));
		
		if (0 != io_net_get_tcp_cc(strh_cli->skt,
		    ifname, sizeof(ifname), NULL))
			memcpy(ifname, "<unable to get>", 16);
		if (0 != io_net_get_tcp_maxseg(strh_cli->skt,
		    (int*)&i))
			i = 0;

		IO_BUF_PRINTF(buf,
		    "	%s (%s)	[conn time: %s, flags: %u, cc: %s, maxseg: %"PRIu32"]	[user agent: %s]\r\n",
		    straddr, straddr2, str_time, strh_cli->flags, ifname, i,
		    (char*)strh_cli->user_agent
		);
		gen_sock_tcp_stat_text(strh_cli->skt,
		    (char*)"	    ", buf);
	}
}
static void
gen_hub_stat_text_enum_done_cb(thrpt_p thrpt __unused, size_t send_msg_cnt __unused,
    size_t error_cnt, void *udata) {
	http_srv_cli_p cli = udata;
	struct iovec iov[1];

	if (0 == error_cnt) {
		http_srv_cli_add_resp_p_flags(cli, HTTP_SRV_RESP_P_F_CONTENT_SIZE);
		iov[0].iov_base = (void*)
		    "Content-Type: text/plain\r\n"
		    "Pragma: no-cache";
		iov[0].iov_len = 42;
		http_srv_snd(cli, 200, NULL, 0, (struct iovec*)&iov, 1);
	} else {
		http_srv_snd(cli, 500, NULL, 0, NULL, 0);
	}
}


int
gen_stat_text(const char *package_name, const char *package_version,
    str_hubs_bckt_p shbskt, core_info_sysres_p sysres,
    uint8_t *sysinfo, size_t sysinfo_size, uint8_t *syslimits, size_t syslimits_size,
    http_srv_cli_p cli) {
	int error;
	char straddr[STR_ADDR_LEN], start_time[64];
	time_t time_work;
	size_t i, thread_cnt, tm;
	http_srv_p http_srv;
	thrp_p thrp;
	io_buf_p buf;
	str_hubs_stat_t hstat, *stat;
	http_srv_stat_t http_srv_stat;


	error = str_hubs_bckt_stat_summary(shbskt, &hstat);
	if (0 != error)
		return (error);
	http_srv = http_srv_cli_get_srv(cli);
	error = http_srv_stat_get(http_srv, &http_srv_stat);
	if (0 != error)
		return (error);
	thrp = http_srv_thrp_get(http_srv);
	thread_cnt = thrp_thread_count_max_get(thrp);
	tm = (4096 + (4096 * thread_cnt) + syslimits_size + sysinfo_size);
	error = http_srv_cli_buf_realloc(cli, 0, tm);
	if (0 != error) /* Need more space! */
		return (error);
	buf = http_srv_cli_get_buf(cli);

	time_work = difftime(thrpt_gettime(NULL, 0), http_srv_stat.start_time);
	if (0 == time_work) /* Prevent division by zero. */
		time_work ++;
	/* Server stat. */
	ctime_r(&http_srv_stat.start_time, start_time);
	start_time[24] = 0; /* Remove CRLF from end. */
	fmt_as_uptime(&time_work, straddr, (sizeof(straddr) - 1));
	IO_BUF_PRINTF(buf,
	    "Server: %s %s ("__DATE__" "__TIME__")\r\n"
	    "start time: %s\r\n"
	    "running time: %s\r\n"
	    "connections online: %"PRIu64"\r\n"
	    "timeouts: %"PRIu64"\r\n"
	    "errors: %"PRIu64"\r\n"
	    "HTTP errors: %"PRIu64"\r\n"
	    "insecure requests: %"PRIu64"\r\n"
	    "unhandled requests (404): %"PRIu64"\r\n"
	    "requests per sec: %"PRIu64"\r\n"
	    "requests total: %"PRIu64"\r\n"
	    "\r\n\r\n",
	    package_name, package_version,
	    start_time, straddr,
	    http_srv_stat.connections,
	    http_srv_stat.timeouts,
	    http_srv_stat.errors,
	    http_srv_stat.http_errors,
	    http_srv_stat.insecure_requests,
	    http_srv_stat.unhandled_requests,
	    (http_srv_stat.requests_total / time_work),
	    http_srv_stat.requests_total);
	IO_BUF_PRINTF(buf, "Per Thread stat\r\n");
	for (i = 0; i < thread_cnt; i ++) {
		/* Per Thread stat. */
		stat = &shbskt->thr_data[i].stat;
		IO_BUF_PRINTF(buf,
		    "Thread: %zu @ cpu %i\r\n"
		    "Stream hub count: %zu\r\n"
		    "Clients count: %zu\r\n"
		    "Rate in: %"PRIu64" mbps\r\n"
		    "Rate out: %"PRIu64" mbps\r\n"
		    "Total rate: %"PRIu64" mbps\r\n"
		    "\r\n",
		    i, thrp_thread_get_cpu_id(thrp_thread_get(thrp, i)),
		    stat->str_hub_count,
		     stat->cli_count,
		    ( stat->baud_rate_in / (1024 * 1024)),
		    ( stat->baud_rate_out / (1024 * 1024)),
		    (( stat->baud_rate_in +
		       stat->baud_rate_out) / (1024 * 1024)));
	}
	/* Total stat. */
	IO_BUF_PRINTF(buf,
	    "Summary\r\n"
	    "Stream hub count: %zu\r\n"
	    "Clients count: %zu\r\n"
	    "Rate in: %"PRIu64" mbps\r\n"
	    "Rate out: %"PRIu64" mbps\r\n"
	    "Total rate: %"PRIu64" mbps\r\n"
	    "\r\n\r\n",
	    hstat.str_hub_count,
	    hstat.cli_count,
	    (hstat.baud_rate_in / (1024 * 1024)),
	    (hstat.baud_rate_out / (1024 * 1024)),
	    ((hstat.baud_rate_in + hstat.baud_rate_out) / (1024 * 1024)));

	error = core_info_sysres(sysres, IO_BUF_FREE_GET(buf), IO_BUF_FREE_SIZE(buf), &tm);
	if (0 != error) /* Err... */
		return (error);
	IO_BUF_USED_INC(buf, tm);

	io_buf_copyin(buf, syslimits, syslimits_size);

	IO_BUF_COPYIN_CRLFCRLF(buf);
	io_buf_copyin(buf, sysinfo, sysinfo_size);
	return (0);
}

