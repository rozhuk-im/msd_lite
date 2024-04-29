/*-
 * Copyright (c) 2012-2024 Rozhuk Ivan <rozhuk.im@gmail.com>
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

#include "utils/macro.h"
#include "utils/sys.h"
#include "utils/io_buf.h"
#include "threadpool/threadpool_task.h"
#include "net/socket.h"
#include "net/socket_address.h"
#include "net/utils.h"
#include "utils/buf_str.h"
#include "proto/http_server.h"
#include "stream_sys.h"
#include "utils/info.h"
#include "msd_lite_stat_text.h"



static void	gen_hub_stat_text_entry_enum_cb(tpt_p tpt, str_hub_p str_hub,
		    void *udata);
static void	gen_hub_stat_text_enum_done_cb(tpt_p tpt, size_t send_msg_cnt,
		    size_t error_cnt, void *udata);

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
gen_hub_stat_text_entry_enum_cb(tpt_p tpt, str_hub_p str_hub, void *udata) {
	http_srv_cli_p cli = udata;
	io_buf_p buf = http_srv_cli_get_buf(cli);
	str_hub_cli_p strh_cli, strh_cli_temp;
	time_t cur_time, time_conn;
	char straddr[STR_ADDR_LEN], straddr2[STR_ADDR_LEN], ifname[(IFNAMSIZ + 1)], str_time[64];
	uint32_t i;
	size_t stm;
	//str_hub_src_conn_udp_tcp_p conn_udp_tcp;
	str_src_conn_mc_p conn_mc;

	cur_time = gettime_monotonic();
	io_buf_printf(buf,
	    "\r\n"
	    "Stream hub: %s		[thread: %zu @ cpu %i, clients: %zu, dropped clients: %"PRIu64"]\r\n",
	    str_hub->name,
	    tp_thread_get_num(tpt), tp_thread_get_cpu_id(tpt),
	    str_hub->cli_count, str_hub->dropped_count);
	/* Sources. */
	IO_BUF_COPYIN_CSTR(buf, "  Source: multicast");
	conn_mc = &str_hub->src_conn_params.mc;
	if (0 != sa_addr_port_to_str(&conn_mc->udp.addr, straddr,
	    sizeof(straddr), NULL)) {
		memcpy(straddr, "<unable to format>", 19);
	}
	ifname[0] = 0;
	if_indextoname(conn_mc->if_index, ifname);
	io_buf_printf(buf, " %s@%s	",
	    straddr, ifname);

	io_buf_printf(buf,
	    "[state: OK, status: 0, rate: %"PRIu64"]\r\n",
	    str_hub->baud_rate_in);

	/* Clients. */
	TAILQ_FOREACH_SAFE(strh_cli, &str_hub->cli_head, next, strh_cli_temp) {
		if (0 != sa_addr_port_to_str(&strh_cli->remonte_addr,
		    straddr, sizeof(straddr), NULL)) {
			memcpy(straddr, "<unable to format>", 19);
		}
		if (0 != sa_addr_port_to_str(&strh_cli->xreal_addr,
		    straddr2, sizeof(straddr2), NULL)) {
			memcpy(straddr, "<unable to format>", 19);
		}
		//&cli_ud->xreal_addr
		time_conn = (cur_time - strh_cli->conn_time);
		fmt_as_uptime(&time_conn, str_time, sizeof(str_time));
		
		if (0 != skt_get_tcp_cc(strh_cli->skt,
		    ifname, sizeof(ifname), NULL)) {
			memcpy(ifname, "<unable to get>", 16);
		}
		if (0 != skt_get_tcp_maxseg(strh_cli->skt, (int*)&i)) {
			i = 0;
		}

		io_buf_printf(buf,
		    "	%s (%s)	[conn time: %s, flags: %u, cc: %s, maxseg: %"PRIu32"]	[user agent: %s]\r\n",
		    straddr, straddr2, str_time, strh_cli->flags, ifname, i,
		    (char*)strh_cli->user_agent
		);
		/* Add soscket TCP stat. */
		if (0 == skt_tcp_stat_text(strh_cli->skt, "	    ",
		    (char*)IO_BUF_FREE_GET(buf),
		    IO_BUF_FREE_SIZE(buf), &stm)) {
			IO_BUF_USED_INC(buf, stm);
		}
	}
}
static void
gen_hub_stat_text_enum_done_cb(tpt_p tpt __unused, size_t send_msg_cnt __unused,
    size_t error_cnt, void *udata) {
	http_srv_cli_p cli = udata;
	http_srv_resp_p	resp = http_srv_cli_get_resp(cli);
	static const char *cttype = 	"Content-Type: text/plain\r\n"
					"Pragma: no-cache";

	if (0 == error_cnt) {
		resp->status_code = 200;
		resp->p_flags |= HTTP_SRV_RESP_P_F_CONTENT_LEN;
		resp->hdrs_count = 1;
		resp->hdrs[0].iov_base = MK_RW_PTR(cttype);
		resp->hdrs[0].iov_len = 42;
	} else {
		resp->status_code = 500;
	}
	http_srv_resume_responce(cli);
}


int
gen_stat_text(const char *package_name, const char *package_version,
    str_hubs_bckt_p shbskt, info_sysres_p sysres,
    uint8_t *sysinfo, size_t sysinfo_size, uint8_t *syslimits, size_t syslimits_size,
    http_srv_cli_p cli) {
	int error;
	char straddr[STR_ADDR_LEN], start_time[64];
	time_t time_work;
	size_t i, thread_cnt, tm;
	http_srv_p http_srv;
	tp_p tp;
	io_buf_p buf;
	struct tm stime;
	str_hubs_stat_t hstat, *stat;
	http_srv_stat_t http_srv_stat;


	error = str_hubs_bckt_stat_summary(shbskt, &hstat);
	if (0 != error)
		return (error);
	http_srv = http_srv_cli_get_srv(cli);
	error = http_srv_stat_get(http_srv, &http_srv_stat);
	if (0 != error)
		return (error);
	tp = http_srv_tp_get(http_srv);
	thread_cnt = tp_thread_count_max_get(tp);
	tm = (4096 + (4096 * thread_cnt) + syslimits_size + sysinfo_size);
	error = http_srv_cli_buf_realloc(cli, 0, tm);
	if (0 != error) /* Need more space! */
		return (error);
	buf = http_srv_cli_get_buf(cli);

	time_work = (gettime_monotonic() - http_srv_stat.start_time_abs);
	if (0 == time_work) { /* Prevent division by zero. */
		time_work ++;
	}
	/* Server stat. */
	localtime_r(&http_srv_stat.start_time, &stime);
	strftime(start_time, sizeof(start_time),
	    "%d.%m.%Y %H:%M:%S", &stime);
	fmt_as_uptime(&time_work, straddr, (sizeof(straddr) - 1));
	io_buf_printf(buf,
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
	    (http_srv_stat.requests_total / (uint64_t)time_work),
	    http_srv_stat.requests_total);
	io_buf_printf(buf, "Per Thread stat\r\n");
	for (i = 0; i < thread_cnt; i ++) {
		/* Per Thread stat. */
		stat = &shbskt->thr_data[i].stat;
		io_buf_printf(buf,
		    "Thread: %zu @ cpu %i\r\n"
		    "Stream hub count: %zu\r\n"
		    "Clients count: %zu\r\n"
		    "Rate in: %"PRIu64" mbps\r\n"
		    "Rate out: %"PRIu64" mbps\r\n"
		    "Total rate: %"PRIu64" mbps\r\n"
		    "\r\n",
		    i, tp_thread_get_cpu_id(tp_thread_get(tp, i)),
		    stat->str_hub_count,
		     stat->cli_count,
		    ( stat->baud_rate_in / (1024 * 1024)),
		    ( stat->baud_rate_out / (1024 * 1024)),
		    (( stat->baud_rate_in +
		       stat->baud_rate_out) / (1024 * 1024)));
	}
	/* Total stat. */
	io_buf_printf(buf,
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

	error = info_sysres(sysres, (char*)IO_BUF_FREE_GET(buf),
	    IO_BUF_FREE_SIZE(buf), &tm);
	if (0 != error)
		return (error);
	IO_BUF_USED_INC(buf, tm);

	io_buf_copyin(buf, syslimits, syslimits_size);

	IO_BUF_COPYIN_CRLFCRLF(buf);
	io_buf_copyin(buf, sysinfo, sysinfo_size);
	return (0);
}
