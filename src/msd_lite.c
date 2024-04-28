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
#include <sys/mman.h> /* for demo mode */
//#include <sys/stat.h> /* For mode constants */

#include <sys/socket.h>
#include <sys/ioctl.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/tcp.h>

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h> /* snprintf, fprintf */
#include <time.h>
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <stdlib.h> /* malloc, exit */
#include <unistd.h> /* close, write, sysconf */
#include <fcntl.h> /* open, fcntl */
#include <signal.h> /* SIGNAL constants. */
#include <syslog.h>


#include "utils/mem_utils.h"
#include "utils/str2num.h"
#include "proto/http.h"
#include "utils/xml.h"

#include "utils/macro.h"
#include "utils/io_buf.h"
#include "net/socket.h"
#include "net/socket_address.h"
#include "net/utils.h"
#include "threadpool/threadpool_task.h"
#include "utils/buf_str.h"
#include "utils/sys.h"
#include "proto/http_server.h"
#include "utils/info.h"
#include "utils/cmd_line_daemon.h"
#include "utils/sys_res_limits_xml.h"
#include "msd_lite_stat_text.h"



#include "config.h"
#undef PACKAGE_NAME
#define PACKAGE_NAME		"Multi stream daemon lite"
#define CFG_FILE_MAX_SIZE	(128 * 1024)



struct prog_settings {
	http_srv_p	http_srv;	/* HTTP server. */
	str_hubs_bckt_p shbskt;		/* Stream hubs. */

	uint8_t		sysinfo[1024];	/* System info */
	uint8_t		syslimits[1024]; /* System limits */
	size_t		sysinfo_size;	/* System info size */
	size_t		syslimits_size;	/* System limits size */
	info_sysres_t sysres;	/* System resources statistic data. */


	str_hub_settings_t	hub_params; /* Stream hub params. */
	str_src_settings_t	src_params; /* Stream hub source params. */
	str_src_conn_params_t	src_conn_params; /* Stream hub source connection params. */

	uintptr_t	log_fd;		// log file descriptor
};
static struct prog_settings g_data;

int		msd_http_cust_hdrs_load(const uint8_t *buf, size_t buf_size,
		    uint8_t **hdrs, size_t *hdrs_size_ret);
int		msd_hub_profile_load(const uint8_t *data, size_t data_size,
		    str_hub_settings_p params);
int		msd_src_profile_load(const uint8_t *data, size_t data_size,
		    str_src_settings_p params);
int		msd_src_conn_profile_load(const uint8_t *data, size_t data_size,
		    void *conn_params);



int		msd_http_srv_hub_attach(http_srv_cli_p cli,
		    uint8_t *hub_name, size_t hub_name_size,
		    str_src_conn_params_p src_conn_params);
uint32_t	msd_http_req_url_parse(http_srv_req_p req,
		    struct sockaddr_storage *ssaddr,
		    uint32_t *if_index, uint32_t *rejoin_time,
		    uint8_t *hub_name, size_t hub_name_size,
		    size_t *hub_name_size_ret);


static int	msd_http_srv_on_req_rcv_cb(http_srv_cli_p cli, void *udata,
		    http_srv_req_p req, http_srv_resp_p resp);


#define MSD_CFG_CALC_VAL_COUNT(args...)					\
	xml_calc_tag_count_args(cfg_file_buf, cfg_file_buf_size,	\
	    (const uint8_t*)"msd", ##args)
#define MSD_CFG_GET_VAL_DATA(next_pos, data, data_size, args...)	\
	xml_get_val_args(cfg_file_buf, cfg_file_buf_size, next_pos,	\
	    NULL, NULL, data, data_size, (const uint8_t*)"msd", ##args)
#define MSD_CFG_GET_VAL_UINT(next_pos, val_ret, args...)		\
	xml_get_val_uint32_args(cfg_file_buf, cfg_file_buf_size, next_pos, \
	    val_ret, (const uint8_t*)"msd", ##args)
#define MSD_CFG_GET_VAL_SIZE(next_pos, val_ret, args...)		\
	xml_get_val_size_t_args(cfg_file_buf, cfg_file_buf_size, next_pos, \
	    val_ret, (const uint8_t*)"msd", ##args)


int
msd_http_cust_hdrs_load(const uint8_t *buf, size_t buf_size,
    uint8_t **hdrs, size_t *hdrs_size_ret) {
	const uint8_t *cur_pos, *ptm;
	uint8_t *cur_w_pos;
	size_t tm, hdrs_size;

	if (NULL == buf || 0 == buf_size || NULL == hdrs || NULL == hdrs_size_ret)
		return (EINVAL);

	/* First pass: calc buffer size for headers. */
	hdrs_size = 0;
	cur_pos = NULL;
	while (0 == xml_get_val_args(buf, buf_size, &cur_pos, NULL, NULL,
	    &ptm, &tm, (const uint8_t*)"header", NULL)) {
		hdrs_size += (tm + 2); /* 2 = crlf. */
	}

	if (0 == hdrs_size) { /* No custom headers. */
		(*hdrs) = NULL;
		(*hdrs_size_ret) = 0;
		return (ESPIPE);
	}

	(*hdrs) = malloc((hdrs_size + sizeof(void*)));
	if (NULL == (*hdrs))
		return (ENOMEM);
	/* Second pass: copy headers to buffer. */
	cur_pos = NULL;
	cur_w_pos = (*hdrs);
	while (0 == xml_get_val_args(buf, buf_size, &cur_pos, NULL, NULL,
	    &ptm, &tm, (const uint8_t*)"header", NULL)) {
		memcpy(cur_w_pos, ptm, tm);
		cur_w_pos += tm;
		memcpy(cur_w_pos, "\r\n", 2);
		cur_w_pos += 2;
	}
	(*hdrs)[hdrs_size] = 0;
	(*hdrs_size_ret) = hdrs_size;
	return (0);
}

int
msd_hub_profile_load(const uint8_t *data, size_t data_size, str_hub_settings_p params) {
	const uint8_t *ptm;
	size_t tm;

	if (NULL == data || 0 == data_size || NULL == params)
		return (EINVAL);

	/* Read from config. */
	if (0 == xml_get_val_args(data, data_size, NULL, NULL, NULL, &ptm, &tm,
	    (const uint8_t*)"fDropSlowClients", NULL)) {
		yn_set_flag32(ptm, tm, STR_HUB_S_F_DROP_SLOW_CLI, &params->flags);
	}
	if (0 == xml_get_val_args(data, data_size, NULL, NULL, NULL, &ptm, &tm,
	    (const uint8_t*)"fSocketHalfClosed", NULL)) {
		yn_set_flag32(ptm, tm, STR_HUB_S_F_SKT_HALFCLOSED, &params->flags);
	}
	if (0 == xml_get_val_args(data, data_size, NULL, NULL, NULL, &ptm, &tm,
	    (const uint8_t*)"fSocketTCPNoDelay", NULL)) {
		yn_set_flag32(ptm, tm, STR_HUB_S_F_SKT_TCP_NODELAY, &params->flags);
	}
	if (0 == xml_get_val_args(data, data_size, NULL, NULL, NULL, &ptm, &tm,
	    (const uint8_t*)"fSocketTCPNoPush", NULL)) {
		yn_set_flag32(ptm, tm, STR_HUB_S_F_SKT_TCP_NOPUSH, &params->flags);
	}
	
	xml_get_val_size_t_args(data, data_size, NULL, &params->ring_buf_size,
	    (const uint8_t*)"ringBufSize", NULL);
	xml_get_val_size_t_args(data, data_size, NULL, &params->precache,
	    (const uint8_t*)"precache", NULL);
	xml_get_val_size_t_args(data, data_size, NULL, &params->snd_block_min_size,
	    (const uint8_t*)"sndBlockSize", NULL);

	xml_get_val_uint32_args(data, data_size, NULL, &params->skt_snd_buf,
	    (const uint8_t*)"skt", "sndBuf", NULL);

	/* Load custom http headers. */
	if (0 == xml_get_val_args(data, data_size, NULL, NULL, NULL,
	    &ptm, &tm, (const uint8_t*)"headersList", NULL)) {
		msd_http_cust_hdrs_load(ptm, tm, &params->cust_http_hdrs,
		    &params->cust_http_hdrs_size);
	}
	return (0);
}

int
msd_src_profile_load(const uint8_t *data, size_t data_size, str_src_settings_p params) {

	if (NULL == data || 0 == data_size || NULL == params)
		return (EINVAL);

	/* Read from config. */
	/* TODO: use socket_options.c */
	xml_get_val_uint32_args(data, data_size, NULL, &params->skt_rcv_buf,
	    (const uint8_t*)"skt", "rcvBuf", NULL);
	xml_get_val_uint32_args(data, data_size, NULL, &params->skt_rcv_lowat,
	    (const uint8_t*)"skt", "rcvLoWatermark", NULL);
	xml_get_val_uint64_args(data, data_size, NULL, &params->rcv_timeout,
	    (const uint8_t*)"skt", "rcvTimeout", NULL);

	return (0);
}

int
msd_src_conn_profile_load(const uint8_t *data, size_t data_size, void *conn) {
	const uint8_t *ptm = NULL;
	size_t tm = 0;
	char if_name[(IFNAMSIZ + 1)];

	if (NULL == data || 0 == data_size || NULL == conn)
		return (EINVAL);

	/* Read from config. */
	if (0 == xml_get_val_args(data, data_size, NULL, NULL, NULL,
	    &ptm, &tm, (const uint8_t*)"udp", "address", NULL)) {
		sa_addr_port_from_str(&((str_src_conn_udp_p)conn)->addr,
		    (const char*)ptm, tm);
	}
	if (0 == xml_get_val_args(data, data_size, NULL, NULL, NULL,
	    &ptm, &tm, (const uint8_t*)"multicast", "ifName", NULL)) {
		memcpy(if_name, ptm, MIN(IFNAMSIZ, tm));
		if_name[MIN(IFNAMSIZ, tm)] = 0;
		((str_src_conn_mc_p)conn)->if_index = if_nametoindex(if_name);
	}
	xml_get_val_uint32_args(data, data_size, NULL,
	    &((str_src_conn_mc_p)conn)->rejoin_time,
	    (const uint8_t*)"multicast", "rejoinTime", NULL);

	return (0);
}



int
main(int argc, char *argv[]) {
	int error = 0;
	uint8_t *cfg_file_buf = NULL;
	size_t tm, cfg_file_buf_size = 0;
	tp_p tp;
	cmd_line_data_t cmd_line_data;


	memset(&g_data, 0x00, sizeof(g_data));
	if (0 != cmd_line_parse(argc, argv, &cmd_line_data)) {
		cmd_line_usage(PACKAGE_DESCRIPTION, PACKAGE_VERSION,
		    "Rozhuk Ivan <rozhuk.im@gmail.com>",
		    PACKAGE_URL);
		return (0);
	}
	if (0 != cmd_line_data.daemon) {
		make_daemon();
		openlog(PACKAGE_NAME,
		    (LOG_NDELAY | LOG_PID | ((0 != cmd_line_data.verbose) ? LOG_PERROR : 0)),
		    LOG_DAEMON);
	} else {
		openlog(PACKAGE_NAME,
		    (LOG_NDELAY | LOG_PID | LOG_PERROR), LOG_USER);
	}
	setlogmask(LOG_UPTO(cmd_line_data.log_level));

    { /* Process config file. */
	const uint8_t *data;
	size_t data_size;
	tp_settings_t tp_s;
	http_srv_cli_ccb_t ccb;
	http_srv_settings_t http_s;

	error = read_file(cmd_line_data.cfg_file_name, 0, 0, 0,
	    CFG_FILE_MAX_SIZE, &cfg_file_buf, &cfg_file_buf_size);
	if (0 != error) {
		SYSLOG_ERR(LOG_CRIT, error, "config read_file().");
		goto err_out;
	}
	if (0 != xml_get_val_args(cfg_file_buf, cfg_file_buf_size,
	    NULL, NULL, NULL, NULL, NULL,
	    (const uint8_t*)"msd", NULL)) {
		syslog(LOG_CRIT, "Config file XML format invalid.");
		goto err_out;
	}

	/* Log level. */
	if (0 == MSD_CFG_GET_VAL_UINT(NULL, (uint32_t*)&cmd_line_data.log_level,
	    "log", "level", NULL)) {
		setlogmask(LOG_UPTO(cmd_line_data.log_level));
	}
	syslog(LOG_NOTICE, PACKAGE_STRING": started!");
#ifdef DEBUG
	syslog(LOG_INFO, "Build: "__DATE__" "__TIME__", DEBUG.");
#else
	syslog(LOG_INFO, "Build: "__DATE__" "__TIME__", Release.");
#endif
	syslog(LOG_INFO, "CPU count: %d.", get_cpu_count());
	syslog(LOG_INFO, "Descriptor table size: %d (max files).", getdtablesize());


	/* System resource limits. */
	if (0 == MSD_CFG_GET_VAL_DATA(NULL, &data, &data_size,
	    "systemResourceLimits", NULL)) {
		sys_res_limits_xml(data, data_size);
	}

	/* Thread pool settings. */
	tp_settings_def(&tp_s);
	if (0 == MSD_CFG_GET_VAL_DATA(NULL, &data, &data_size,
	    "threadPool", NULL)) {
		tp_settings_load_xml(data, data_size, &tp_s);
	}
	error = tp_create(&tp_s, &tp);
	if (0 != error) {
		SYSLOG_ERR(LOG_CRIT, error, "tp_create().");
		goto err_out;
	}
	tp_threads_create(tp, 1); /* XXX exit rewrite. */


	/* HTTP server settings. */
	/* Read from config. */
	if (0 != MSD_CFG_GET_VAL_DATA(NULL, &data, &data_size, "HTTP", NULL)) {
		syslog(LOG_NOTICE, "No HTTP server settings, nothink to do...");
		goto err_out;
	}
	http_srv_def_settings(1, PACKAGE_NAME"/"PACKAGE_VERSION, 1, &http_s);
	http_s.req_p_flags = (HTTP_SRV_REQ_P_F_CONNECTION | HTTP_SRV_REQ_P_F_HOST);
	http_s.resp_p_flags = (HTTP_SRV_RESP_P_F_CONN_CLOSE | HTTP_SRV_RESP_P_F_SERVER | HTTP_SRV_RESP_P_F_CONTENT_LEN);
	ccb.on_req_rcv = msd_http_srv_on_req_rcv_cb;
	ccb.on_rep_snd = NULL;
	ccb.on_destroy = NULL;

	error = http_srv_xml_load_start(data, data_size, tp,
	    NULL, &ccb, &http_s, &g_data,
	    &g_data.http_srv);
 	if (0 != error) {
		SYSLOG_ERR(LOG_CRIT, error, "http_srv_xml_load_start().");
		goto err_out;
	}

	/* Default settings. */
	/* Stream hub defaults. */
	g_data.hub_params.flags = STR_HUB_S_DEF_FLAGS;
	g_data.hub_params.skt_snd_buf = STR_HUB_S_DEF_SKT_SND_BUF;
	/* Stream source defaults params. */
	str_src_conn_def(&g_data.src_conn_params);
	str_src_settings_def(&g_data.src_params);

	/* Stream hub params. */
	if (0 == MSD_CFG_GET_VAL_DATA(NULL, &data, &data_size,
	    "hubProfileList", "hubProfile", NULL)) {
		msd_hub_profile_load(data, data_size, &g_data.hub_params);
	}
	/* Stream source params. */
	if (0 == MSD_CFG_GET_VAL_DATA(NULL, &data, &data_size,
	    "sourceProfileList", "sourceProfile", NULL)) {
		msd_src_profile_load(data, data_size, &g_data.src_params);
		msd_src_conn_profile_load(data, data_size, &g_data.src_conn_params);
	}
	error = str_hubs_bckt_create(tp, PACKAGE_NAME"/"PACKAGE_VERSION, &g_data.hub_params,
	    &g_data.src_params, &g_data.shbskt);
	if (0 != error) {
		SYSLOG_ERR(LOG_CRIT, error, "str_hubs_bckt_create().");
		goto err_out;
	}
	free(cfg_file_buf);
    } /* Done with config. */


	if (0 == info_limits((char*)g_data.syslimits,
	    (sizeof(g_data.syslimits) - 1), &tm)) {
		g_data.syslimits_size = tm;
	}
	if (0 == info_sysinfo((char*)g_data.sysinfo,
	    sizeof(g_data.sysinfo), &tm)) {
		g_data.sysinfo_size = tm;
	}
	info_sysres(&g_data.sysres, NULL, 0, NULL);

	tp_signal_handler_add_tp(tp);
	signal_install(tp_signal_handler);

	write_pid(cmd_line_data.pid_file_name); /* Store pid to file. */
	set_user_and_group(cmd_line_data.pw_uid, cmd_line_data.pw_gid); /* Drop rights. */

	/* Receive and process packets. */
	tp_thread_attach_first(tp);
	tp_shutdown_wait(tp);

	/* Deinitialization... */
	http_srv_shutdown(g_data.http_srv); /* No more new clients. */
	http_srv_destroy(g_data.http_srv); /* AFTER radius is shut down! */
	str_hubs_bckt_destroy(g_data.shbskt);
	if (NULL != cmd_line_data.pid_file_name) {
		unlink(cmd_line_data.pid_file_name); // Remove pid file
	}

	tp_destroy(tp);
	syslog(LOG_NOTICE, "Exiting.");
	closelog();

err_out:
	return (error);
}


/*
 * tcpcc = congestion ctrl name
 */
int
msd_http_srv_hub_attach(http_srv_cli_p cli, uint8_t *hub_name, size_t hub_name_size,
    str_src_conn_params_p src_conn_params) {
	int error;
	str_hub_cli_p strh_cli;
	http_srv_req_p req;
	const uint8_t *ptm;
	size_t tm;
	tp_task_p tptask;
	uintptr_t skt;

	SYSLOGD_EX(LOG_DEBUG, "...");

	if (NULL == cli || NULL == hub_name)
		return (EINVAL);

	tptask = http_srv_cli_get_tptask(cli);
	skt = tp_task_ident_get(tptask);
	/* Extract tcpCC, "User-Agent". */
	req = http_srv_cli_get_req(cli);
	/* tcpcc. */
	if (0 == http_query_val_get(req->line.query, req->line.query_size,
	    (const uint8_t*)"tcpcc", 5, &ptm, &tm)) {
		skt_set_tcp_cc(skt, (const char*)ptm, tm);
	}
	/* Extract "User-Agent". */
	if (0 != http_hdr_val_get(req->hdr, req->hdr_size,
	    (const uint8_t*)"user-agent", 10, &ptm, &tm)) {
		ptm = NULL;
		tm = 0;
	}
	strh_cli = str_hub_cli_alloc(skt, (const char*)ptm, tm);
	if (NULL == strh_cli) {
		syslog(LOG_ERR, "str_hub_cli_alloc().");
		return (ENOMEM);
	}
	/*
	 * Set stream hub client data: some form http server client other from
	 * http request.
	 */
	http_srv_cli_get_addr(cli, &strh_cli->remonte_addr);

	/* Client IP: get "X-Real-IP" from headers. */
	if (0 != http_hdr_val_get(req->hdr, req->hdr_size,
	    (const uint8_t*)"x-real-ip", 9, &ptm, &tm) ||
	    0 != sa_addr_from_str(&strh_cli->xreal_addr, (const char*)ptm, tm) ||
	    0 != sa_addr_is_loopback(&strh_cli->xreal_addr)) { /* No or bad addr. */
		sa_copy(&strh_cli->remonte_addr, &strh_cli->xreal_addr);
	}

	SYSLOGD_EX(LOG_DEBUG, "%s - : attach...", hub_name);
	error = str_hub_cli_attach(g_data.shbskt, strh_cli, hub_name, hub_name_size,
	    src_conn_params);
	/* Do not read/write to stream hub client, stream hub is new owner! */
	if (0 != error) {
		strh_cli->skt = (uintptr_t)-1;
		str_hub_cli_destroy(NULL, strh_cli);
		SYSLOG_ERR(LOG_ERR, error, "str_hub_cli_attach().");
	} else {
		tp_task_flags_del(tptask, TP_TASK_F_CLOSE_ON_DESTROY);
		http_srv_cli_free(cli);
	}
	return (error);
}

uint32_t
msd_http_req_url_parse(http_srv_req_p req, struct sockaddr_storage *ssaddr,
    uint32_t *if_index, uint32_t *rejoin_time,
    uint8_t *hub_name, size_t hub_name_size, size_t *hub_name_size_ret) {
	const uint8_t *ptm;
	size_t tm;
	uint32_t ifindex, rejointime;
	char straddr[STR_ADDR_LEN], ifname[(IFNAMSIZ + 1)];
	struct sockaddr_storage ss;

	SYSLOGD_EX(LOG_DEBUG, "...");

	if (NULL == req || NULL == hub_name || 0 == hub_name_size)
		return (500);
	/* Get multicast address. */
	if (0 != sa_addr_port_from_str(&ss, (const char*)(req->line.abs_path + 5),
	    (req->line.abs_path_size - 5)))
		return (400);
	if (0 == sa_port_get(&ss)) { /* Def udp port. */
		sa_port_set(&ss, 1234);
	}
	/* ifname, ifindex. */
	if (0 == http_query_val_get(req->line.query, req->line.query_size,
	    (const uint8_t*)"ifname", 6, &ptm, &tm) && IFNAMSIZ > tm) {
		memcpy(ifname, ptm, tm);
		ifname[tm] = 0;
		ifindex = if_nametoindex(ifname);
	} else {
		if (0 == http_query_val_get(req->line.query, 
		    req->line.query_size, (const uint8_t*)"ifindex", 7,
		    &ptm, &tm)) {
			ifindex = ustr2u32(ptm, tm);
		} else { /* Default value. */
			if (NULL != if_index) {
				ifindex = (*if_index);
			} else {
				ifindex = (uint32_t)-1;
			}
		}
		ifname[0] = 0;
		if_indextoname(ifindex, ifname);
	}

	/* rejoin_time. */
	if (0 == http_query_val_get(req->line.query, 
	    req->line.query_size, (const uint8_t*)"rejoin_time", 11,
	    &ptm, &tm)) {
		rejointime = ustr2u32(ptm, tm);
	} else { /* Default value. */
		if (NULL != if_index) {
			rejointime = (*rejoin_time);
		} else {
			rejointime = 0;
		}
	}

	if (0 != sa_addr_port_to_str(&ss, straddr, sizeof(straddr), NULL))
		return (400);
	tm = (size_t)snprintf((char*)hub_name, hub_name_size,
	    "/udp/%s@%s", straddr, ifname);
	if (NULL != ssaddr) {
		sa_copy(&ss, ssaddr);
	}
	if (NULL != if_index) {
		(*if_index) = ifindex;
	}
	if (NULL != rejoin_time) {
		(*rejoin_time) = rejointime;
	}
	if (NULL != hub_name_size_ret) {
		(*hub_name_size_ret) = tm;
	}

	return (200);
}



/* http request from client is received now, process it. */
/* http_srv_on_req_rcv_cb */
static int
msd_http_srv_on_req_rcv_cb(http_srv_cli_p cli, void *udata __unused,
    http_srv_req_p req, http_srv_resp_p resp) {
	size_t buf_size;
	int error;
	uint8_t buf[512];
	str_src_conn_params_t src_conn_params;
	static const char *cttype = 	"Content-Type: text/plain\r\n"
					"Pragma: no-cache";

	SYSLOGD_EX(LOG_DEBUG, "...");

	if (HTTP_REQ_METHOD_GET != req->line.method_code &&
	    HTTP_REQ_METHOD_HEAD != req->line.method_code) {
		resp->status_code = 400;
		return (HTTP_SRV_CB_CONTINUE);
	}
	if (0 == (req->flags & HTTP_SRV_RD_F_HOST_IS_LOCAL)) {
		resp->status_code = 403;
		return (HTTP_SRV_CB_CONTINUE);
	}

	/* Statistic request. */
	if (HTTP_REQ_METHOD_GET == req->line.method_code &&
	    0 == mem_cmpin_cstr("/stat", req->line.abs_path, req->line.abs_path_size)) {
		error = gen_stat_text(PACKAGE_NAME, PACKAGE_VERSION,
		    g_data.shbskt, &g_data.sysres,
		    (uint8_t*)g_data.sysinfo, g_data.sysinfo_size,
		    (uint8_t*)g_data.syslimits, g_data.syslimits_size, cli);
		if (0 == error) {
			resp->status_code = 200;
			resp->hdrs_count = 1;
			resp->hdrs[0].iov_base = MK_RW_PTR(cttype);
			resp->hdrs[0].iov_len = 42;
		} else {
			resp->status_code = 500;
		}
		return (HTTP_SRV_CB_CONTINUE);
	}
	/* Stream Hub statistic request. */
	if (HTTP_REQ_METHOD_GET == req->line.method_code &&
	    7 < req->line.abs_path_size &&
	    0 == mem_cmpi_cstr("/hubstat", req->line.abs_path)) {
		error = gen_hub_stat_text_send_async(g_data.shbskt, cli);
		if (0 != error) {
			resp->status_code = 500;
			return (HTTP_SRV_CB_CONTINUE);
		}
		/* Will send reply later... */
		return (HTTP_SRV_CB_NONE);
	}

	if (12 < req->line.abs_path_size &&
	    (0 == memcmp(req->line.abs_path, "/udp/", 5) ||
	    0 == memcmp(req->line.abs_path, "/rtp/", 5))) {
		/* Default value. */
		memcpy(&src_conn_params, &g_data.src_conn_params, sizeof(str_src_conn_mc_t));
		/* Get multicast address, ifindex, hub name. */
		resp->status_code = msd_http_req_url_parse(req,
		    &src_conn_params.udp.addr,
		    &src_conn_params.mc.if_index,
		    &src_conn_params.mc.rejoin_time,
		    buf, sizeof(buf), &buf_size);
		if (200 != resp->status_code)
			return (HTTP_SRV_CB_CONTINUE);
		if (HTTP_REQ_METHOD_HEAD == req->line.method_code) {
			/* Send HTTP headers only... */
			resp->status_code = 200;
			resp->p_flags &= ~HTTP_SRV_RESP_P_F_CONTENT_LEN;
			if (6 < g_data.hub_params.cust_http_hdrs_size) {
				resp->hdrs_count = 1;
				resp->hdrs[0].iov_base = g_data.hub_params.cust_http_hdrs;
				resp->hdrs[0].iov_len = g_data.hub_params.cust_http_hdrs_size;
			}
			return (HTTP_SRV_CB_CONTINUE);
		}
		if (0 != msd_http_srv_hub_attach(cli, buf, buf_size, &src_conn_params)) {
			resp->status_code = 500;
			return (HTTP_SRV_CB_CONTINUE);
		}
		/* Will send reply later... */
		return (HTTP_SRV_CB_NONE);
	} /* "/udp/" / "/rtp/" */

	/* URL not found. */
	resp->status_code = 404;

	return (HTTP_SRV_CB_CONTINUE);
}
