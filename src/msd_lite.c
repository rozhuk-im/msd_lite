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
#include <sys/mman.h> /* for demo mode */
//#include <sys/stat.h> /* For mode constants */
#include <sys/resource.h>

#ifdef BSD /* BSD specific code. */
#include <sys/rtprio.h>
#endif /* BSD specific code. */

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


#include "mem_find.h"
#include "StrToNum.h"
#include "buf_case.h"
#include "HTTP.h"
#include "xml.h"

#include "core_macro.h"
#include "core_io_buf.h"
#include "core_io_net.h"
#include "core_io_task.h"
#include "core_helpers.h"
#include "core_net_helpers.h"
#include "core_log.h"
#include "core_http_srv.h"
#include "core_info.h"
#include "msd_lite_stat_text.h"



#ifdef BSD /* BSD specific code. */
#include <malloc_np.h>
#ifdef DEBUG
const char *_malloc_options = "AJMPX";
#else
const char *_malloc_options = "M";
#endif
#endif /* BSD specific code. */


#include <config.h>
#undef PACKAGE_NAME
#define PACKAGE_NAME		"Multi stream daemon lite"
#define CFG_FILE_MAX_SIZE	(128 * 1024)



struct prog_settings {
	thrp_p		thrp;
	http_srv_p	http_srv;	/* HTTP server. */
	str_hubs_bckt_p shbskt;		/* Stream hubs. */

	uint8_t		sysinfo[1024];	/* System info */
	uint8_t		syslimits[1024]; /* System limits */
	size_t		sysinfo_size;	/* System info size */
	size_t		syslimits_size;	/* System limits size */
	core_info_sysres_t sysres;	/* System resources statistic data. */


	str_hub_params_t	hub_params; /* Stream hub params. */
	str_src_params_t	src_params; /* Stream hub source params. */
	str_src_conn_params_t	src_conn_params; /* Stream hub source connection params. */

	int		log_fd;		// log file descriptor
	cmd_line_data_t	cmd_line_data;	/*  */
};
static struct prog_settings g_data;

int		msd_http_cust_hdrs_load(uint8_t *buf, size_t buf_size,
		    uint8_t **hdrs, size_t *hdrs_size_ret);
int		msd_hub_profile_load(uint8_t *data, size_t data_size,
		    str_hub_params_p params);
int		msd_src_profile_load(uint8_t *data, size_t data_size,
		    str_src_params_p params);
int		msd_src_conn_profile_load(uint8_t *data, size_t data_size,
		    void *conn_params);

static void	SigInstall(void);
static void	SigHandler(int iSigNum);



typedef struct msd_cli_udata_s {
	uint8_t		*user_agent;
	size_t		user_agent_size;
	struct sockaddr_storage	xreal_addr;
} msd_cli_udata_t, *msd_cli_udata_p;

int		msd_http_srv_hub_attach(http_srv_cli_p cli,
		    uint8_t *hub_name, size_t hub_name_size,
		    str_src_conn_params_p src_conn_params);
int		msd_http_req_url_parse(http_srv_req_p req,
		    struct sockaddr_storage *ssaddr, uint32_t *if_index,
		    uint8_t *hub_name, size_t hub_name_size,
		    size_t *hub_name_size_ret);


static int	msd_http_srv_on_req_rcv_cb(http_srv_cli_p cli, void *udata,
		    http_srv_req_p req);


#define MSD_CFG_CALC_VAL_COUNT(args...)						\
	xml_calc_tag_count_args(cfg_file_buf, cfg_file_buf_size,		\
	    (const uint8_t*)"msd", ##args)
#define MSD_CFG_GET_VAL_DATA(next_pos, data, data_size, args...)		\
	xml_get_val_args(cfg_file_buf, cfg_file_buf_size, next_pos,		\
	    NULL, NULL, data, data_size, (const uint8_t*)"msd", ##args)
#define MSD_CFG_GET_VAL_INT(next_pos, val_ret, args...)				\
	xml_get_val_int_args(cfg_file_buf, cfg_file_buf_size, next_pos,		\
	    (int32_t*)val_ret, (const uint8_t*)"msd", ##args)
#define MSD_CFG_GET_VAL_SSIZE(next_pos, val_ret, args...)			\
	xml_get_val_ssize_t_args(cfg_file_buf, cfg_file_buf_size, next_pos,	\
	    (ssize_t*)val_ret, (const uint8_t*)"msd", ##args)


int
msd_http_cust_hdrs_load(uint8_t *buf, size_t buf_size,
    uint8_t **hdrs, size_t *hdrs_size_ret) {
	uint8_t *cur_pos, *ptm, *cur_w_pos;
	size_t tm, hdrs_size;

	if (NULL == buf || 0 == buf_size || NULL == hdrs || NULL == hdrs_size_ret)
		return (EINVAL);

	/* First pass: calc buffer size for headers. */
	hdrs_size = 0;
	cur_pos = NULL;
	while (0 == xml_get_val_args(buf, buf_size, &cur_pos, NULL, NULL,
	    (uint8_t**)&ptm, &tm, (const uint8_t*)"header", NULL)) {
		hdrs_size += (tm + 2); /* 2 = crlf. */
	}

	if (0 == hdrs_size) { /* No custom headers. */
		(*hdrs) = NULL;
		(*hdrs_size_ret) = 0;
		return (ESPIPE);
	}

	hdrs_size -= 2; /* Remove last crlf. */
	(*hdrs) = zalloc((hdrs_size + 8));
	if (NULL == (*hdrs))
		return (ENOMEM);
	/* Second pass: copy headers to buffer. */
	cur_pos = NULL;
	cur_w_pos = (*hdrs);
	while (0 == xml_get_val_args(buf, buf_size, &cur_pos, NULL, NULL,
	    (uint8_t**)&ptm, &tm, (const uint8_t*)"header", NULL)) {
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
msd_hub_profile_load(uint8_t *data, size_t data_size, str_hub_params_p params) {
	uint8_t *ptm;
	size_t tm;

	if (NULL == data || 0 == data_size || NULL == params)
		return (EINVAL);

	/* Read from config. */
	if (0 == xml_get_val_args(data, data_size, NULL, NULL, NULL, &ptm, &tm,
	    (const uint8_t*)"fDropSlowClients", NULL))
		yn_set_flag32(ptm, tm, STR_HUB_P_F_DROP_SLOW_CLI, &params->flags);
	if (0 == xml_get_val_args(data, data_size, NULL, NULL, NULL, &ptm, &tm,
	    (const uint8_t*)"fSocketHalfClosed", NULL))
		yn_set_flag32(ptm, tm, STR_HUB_P_F_SKT_HALFCLOSED, &params->flags);
	if (0 == xml_get_val_args(data, data_size, NULL, NULL, NULL, &ptm, &tm,
	    (const uint8_t*)"fSocketTCPNoDelay", NULL))
		yn_set_flag32(ptm, tm, STR_HUB_P_F_SKT_TCP_NODELAY, &params->flags);
	if (0 == xml_get_val_args(data, data_size, NULL, NULL, NULL, &ptm, &tm,
	    (const uint8_t*)"fSocketTCPNoPush", NULL))
		yn_set_flag32(ptm, tm, STR_HUB_P_F_SKT_TCP_NOPUSH, &params->flags);
	
	xml_get_val_int_args(data, data_size, NULL, (int32_t*)&params->ring_buf_size,
	    (const uint8_t*)"ringBufSize", NULL);
	xml_get_val_int_args(data, data_size, NULL, (int32_t*)&params->snd_block_min_size,
	    (const uint8_t*)"sndBlockSize", NULL);

	    xml_get_val_int_args(data, data_size, NULL, (int32_t*)&params->skt_snd_buf,
	    (const uint8_t*)"skt", "sndBuf", NULL);

	/* Load custom http headers. */
	if (0 == xml_get_val_args(data, data_size, NULL, NULL, NULL,
	    &ptm, &tm, (const uint8_t*)"headersList", NULL))
		msd_http_cust_hdrs_load(ptm, tm, &params->cust_http_hdrs,
		    &params->cust_http_hdrs_size);

	return (0);
}

int
msd_src_profile_load(uint8_t *data, size_t data_size, str_src_params_p params) {

	if (NULL == data || 0 == data_size || NULL == params)
		return (EINVAL);

	/* Read from config. */
	xml_get_val_int_args(data, data_size, NULL, (int32_t*)&params->skt_rcv_buf,
	    (const uint8_t*)"skt", "rcvBuf", NULL);
	xml_get_val_int_args(data, data_size, NULL, (int32_t*)&params->skt_rcv_lowat,
	    (const uint8_t*)"skt", "rcvLowat", NULL);
	xml_get_val_ssize_t_args(data, data_size, NULL, (ssize_t*)&params->rcv_timeout,
	    (const uint8_t*)"skt", "rcvTimeout", NULL);

	return (0);
}

int
msd_src_conn_profile_load(uint8_t *data, size_t data_size, void *conn) {
	uint8_t *ptm = NULL;
	size_t tm = 0;
	char if_name[(IFNAMSIZ + 1)];

	if (NULL == data || 0 == data_size || NULL == conn)
		return (EINVAL);

	/* Read from config. */
	if (0 == xml_get_val_args(data, data_size, NULL, NULL, NULL,
	    &ptm, &tm, (const uint8_t*)"udp", "address", NULL)) {
		str_addr_port_to_ss((char*)ptm, tm, &((str_src_conn_udp_p)conn)->addr);
	}
	if (0 == xml_get_val_args(data, data_size, NULL, NULL, NULL,
	    &ptm, &tm, (const uint8_t*)"multicast", "ifName", NULL)) {
		memcpy(if_name, ptm, min(IFNAMSIZ, tm));
		if_name[min(IFNAMSIZ, tm)] = 0;
		((str_src_conn_mc_p)conn)->if_index = if_nametoindex(if_name);
	}

	return (0);
}



int
main(int argc, char *argv[]) {
	int error = 0;
	uint8_t *cfg_file_buf = NULL;
	size_t tm, cfg_file_buf_size = 0;


	memset(&g_data, 0, sizeof(g_data));
	g_data.log_fd = -1;
	if (0 != cmd_line_parse(argc, argv, &g_data.cmd_line_data)) {
		cmd_line_usage(PACKAGE_NAME, PACKAGE_VERSION);
		return (0);
	}

    { // process config file
	uint8_t *data, *cur_pos;
	char *cc_name;
	char straddr[STR_ADDR_LEN], strbuf[1024];
	int backlog;
	size_t val_count, data_size, cc_name_size;
	uint32_t flags, tm32;
	struct sockaddr_storage addr;
	struct rlimit rlp;
	hostname_list_t hn_lst;
	http_srv_settings_t http_s;


	error = read_file(g_data.cmd_line_data.cfg_file_name, 0, CFG_FILE_MAX_SIZE,
	    &cfg_file_buf, &cfg_file_buf_size);
	if (0 != error) {
		core_log_fd = open("/dev/stdout", (O_WRONLY | O_APPEND));;
		LOG_ERR(error, "config read_file()");
		goto err_out;
	}
	if (0 != xml_get_val_args(cfg_file_buf, cfg_file_buf_size,
	    NULL, NULL, NULL, NULL, NULL,
	    (const uint8_t*)"msd", NULL)) {
		core_log_fd = open("/dev/stdout", (O_WRONLY | O_APPEND));;
		LOG_INFO("Config file XML format invalid.");
		goto err_out;
	}

	/* Log file */
	if (0 == g_data.cmd_line_data.verbose &&
	    0 == MSD_CFG_GET_VAL_DATA(NULL, &data, &data_size,
	    "log", "file", NULL)) {
		if (sizeof(strbuf) > data_size) {
			memcpy(strbuf, data, data_size);
			strbuf[data_size] = 0;
			backlog = open(strbuf, (O_WRONLY | O_APPEND | O_CREAT), 0644);
			if (-1 != backlog) {
				g_data.log_fd = backlog;
				core_log_fd = g_data.log_fd;
			} else {
				core_log_fd = open("/dev/stdout", (O_WRONLY | O_APPEND));;
				LOG_ERR(errno, "Fail to open log file.");
				core_log_fd = -1;
			}
		} else {
			core_log_fd = open("/dev/stdout", (O_WRONLY | O_APPEND));;
			LOG_ERR(EINVAL, "Log file name too long.");
			core_log_fd = -1;
		}
	} else if (0 != g_data.cmd_line_data.verbose) {
		g_data.log_fd = open("/dev/stdout", (O_WRONLY | O_APPEND));
		core_log_fd = g_data.log_fd;
	}
	log_write("\n\n\n\n", 4);
	LOG_INFO(PACKAGE_NAME" "PACKAGE_VERSION": started");
	LOG_INFO_FMT("Build: "__DATE__" "__TIME__", "
#ifdef DEBUG
	    "DEBUG"
#else
	    "Release"
#endif
	);
	LOG_INFO_FMT("CPU count: %d", get_cpu_count());
	LOG_INFO_FMT("descriptor table size: %d (max files)", getdtablesize());
	
	/* Thread pool settings. */
	flags = 0; /* Flags. */
	cc_name_size = 0; /* Threads count = auto. */
	val_count = 1; /* Timer interval */
	MSD_CFG_GET_VAL_SSIZE(NULL, &cc_name_size,
	    "threadPool", "threadsCount", NULL);
	if (0 == MSD_CFG_GET_VAL_DATA(NULL, &data, &data_size,
	    "threadPool", "fBindToCPU", NULL))
		yn_set_flag32(data, data_size, THRP_C_F_BIND2CPU, &flags);
	if (0 == MSD_CFG_GET_VAL_DATA(NULL, &data, &data_size,
	    "threadPool", "fCacheGetTimeSyscall", NULL))
		yn_set_flag32(data, data_size, THRP_C_F_CACHE_TIME_SYSC, &flags);
	MSD_CFG_GET_VAL_SSIZE(NULL, &val_count,
	    "threadPool", "timerGranularity", NULL);
	error = thrp_create(flags, cc_name_size, val_count, &g_data.thrp);
	if (0 != error) {
		LOG_ERR(error, "thrp_create()");
		goto err_out;
	}
	thrp_threads_create(g_data.thrp, 1);// XXX exit rewrite

	/* System resource limits. */
	if (0 != MSD_CFG_GET_VAL_DATA(NULL, NULL, NULL,
	    "systemResourceLimits", NULL))
		goto no_sys_reslimits;
	if (0 == MSD_CFG_GET_VAL_SSIZE(NULL, &tm,
	    "systemResourceLimits", "maxOpenFiles", NULL)) {
		rlp.rlim_cur = tm;
		rlp.rlim_max = tm;
		if (0 != setrlimit(RLIMIT_NOFILE, &rlp))
			LOG_ERR(errno, "setrlimit(RLIMIT_NOFILE)");
	}
	if (0 == MSD_CFG_GET_VAL_DATA(NULL, &data, &data_size,
	    "systemResourceLimits", "maxCoreFileSize", NULL) &&
	    0 < data_size) {
		if (0 == buf_cmpi(data, data_size, "unlimited", 9))
			rlp.rlim_cur = RLIM_INFINITY;
		else
			rlp.rlim_cur = (UStr8ToUNum(data, data_size) * 1024); /* in kb */
		rlp.rlim_max = rlp.rlim_cur;
		if (0 != setrlimit(RLIMIT_CORE, &rlp))
			LOG_ERR(errno, "setrlimit(RLIMIT_CORE)");
	}
	if (0 == MSD_CFG_GET_VAL_INT(NULL, &tm32,
	    "systemResourceLimits", "processPriority", NULL)) {
		if (0 != setpriority(PRIO_PROCESS, 0, tm32))
			LOG_ERR(errno, "setpriority()");
	}
	if (0 == MSD_CFG_GET_VAL_INT(NULL, &tm32,
	    "systemResourceLimits", "processPriority2", NULL)) {
#ifdef BSD /* BSD specific code. */
		struct rtprio rtp;
		rtp.type = RTP_PRIO_REALTIME;
		rtp.prio = tm32;
		if (0 != rtprio(RTP_SET, 0, &rtp))
			LOG_ERR(errno, "rtprio()");
#endif /* BSD specific code. */
	}
no_sys_reslimits:


	/* HTTP server settings. */
	val_count = MSD_CFG_CALC_VAL_COUNT("HTTP", "bindList", "bind", NULL);
	if (0 == val_count)
		goto no_http_svr;
	/* Default settings. */
	http_srv_def_settings(1, PACKAGE"/"VERSION, 1, &http_s);
	hostname_list_init(&hn_lst);
	/* Read from config. */
	if (0 == MSD_CFG_GET_VAL_DATA(NULL, &data, &data_size, "HTTP", NULL)) {
		http_srv_xml_load_settings(data, data_size, &http_s);
		/* Read hostnames. */
		http_srv_xml_load_hostnames(data, data_size, &hn_lst);
	}
	http_s.req_p_flags = (HTTP_SRV_REQ_P_F_CONNECTION | HTTP_SRV_REQ_P_F_HOST);
	http_s.resp_p_flags = (HTTP_SRV_RESP_P_F_CONN_CLOSE | HTTP_SRV_RESP_P_F_SERVER | HTTP_SRV_RESP_P_F_CONTENT_SIZE);
	error = http_srv_create(g_data.thrp, NULL, NULL, msd_http_srv_on_req_rcv_cb,
	    NULL, &hn_lst, &http_s, &g_data.http_srv);
	if (0 != error) {
		LOG_ERR(error, "http_srv_create()");
		hostname_list_deinit(&hn_lst);
		goto err_out;
	}
	cur_pos = NULL;
	while (0 == MSD_CFG_GET_VAL_DATA(&cur_pos, &data, &data_size,
	    "HTTP", "bindList", "bind", NULL)) {
		error = http_srv_xml_load_bind(data, data_size, &addr, &flags,
		    &backlog, &cc_name, &cc_name_size, &hn_lst);
		if (0 != error) {
			LOG_ERR(error, "http_srv_xml_load_bind()");
			continue;
		}			
		ss_to_str_addr_port(&addr, straddr, sizeof(straddr), NULL);
		/* cc name for log fmt. */
		memcpy(strbuf, cc_name, min((sizeof(strbuf) - 1), cc_name_size));
		strbuf[min((sizeof(strbuf) - 1), cc_name_size)] = 0;
		/* Try bind... */
		error = http_srv_acc_add(g_data.http_srv, &addr, flags,
		    backlog, cc_name, cc_name_size, &hn_lst, &g_data, NULL);
		if (0 != error) {
			LOG_ERR_FMT(error, "http_srv_acc_add(): %s,"
			    " backlog = %i, cc_name = %s",
			    straddr, backlog, strbuf);
			continue;
		}
		LOG_INFO_FMT("bind %s, backlog = %i, cc_name = %s",
		    straddr, backlog, strbuf);
	}
	if (0 == http_srv_get_accept_count(g_data.http_srv)) {
no_http_svr:
		LOG_INFO("no bind address specified, nothink to do...");
		goto err_out;
	}

	//http_srv_thrp_set(g_data.http_srv, g_data.thrp);
	//http_srv_on_req_rcv_cb_set(g_data.http_srv, msd_http_srv_on_req_rcv_cb);

	/* Default settings. */
	/* Stream hub defaults. */
	g_data.hub_params.flags = STR_HUB_P_DEF_FLAGS;
	g_data.hub_params.skt_snd_buf = STR_HUB_P_DEF_SKT_SND_BUF;
	/* Stream source defaults params. */
	str_src_conn_def(&g_data.src_conn_params);
	str_src_params_def(&g_data.src_params);

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
	error = str_hubs_bckt_create(g_data.thrp, PACKAGE"/"VERSION, &g_data.hub_params,
	    &g_data.src_params, &g_data.shbskt);
	if (0 != error) {
		LOG_ERR(error, "str_hubs_bckt_create()");
		goto err_out;
	}
    } /* Done with config. */


	if (0 == core_info_limits(g_data.syslimits, (sizeof(g_data.syslimits) - 1), &tm))
		g_data.syslimits_size = tm;
	if (0 == core_info_sysinfo(g_data.sysinfo, (sizeof(g_data.sysinfo) - 1), &tm))
		g_data.sysinfo_size = tm;
	core_info_sysres(&g_data.sysres, NULL, 0, NULL);

	SigInstall();
	write_pid(g_data.cmd_line_data.pid_file_name); // Store pid to file

	set_user_and_group(g_data.cmd_line_data.pw_uid, g_data.cmd_line_data.pw_gid); // drop rights

	/* Receive and process packets. */
	thrp_thread_attach_first(g_data.thrp);
	thrp_shutdown_wait(g_data.thrp);

	/* Deinitialization... */
	http_srv_shutdown(g_data.http_srv); /* No more new clients. */
	http_srv_destroy(g_data.http_srv); /* AFTER radius is shut down! */
	str_hubs_bckt_destroy(g_data.shbskt);
	if (NULL != g_data.cmd_line_data.pid_file_name)
		unlink(g_data.cmd_line_data.pid_file_name); // Remove pid file

	thrp_destroy(g_data.thrp);
	LOG_INFO("exiting.");
	close(g_data.log_fd);
	free(cfg_file_buf);

err_out:
	return (error);
}

static void
SigInstall() {
	signal(SIGINT,	SigHandler);
	signal(SIGTERM,	SigHandler);
	signal(SIGKILL,	SigHandler);
	signal(SIGHUP,	SigHandler);
	signal(SIGUSR1,	SigHandler);
	signal(SIGUSR2,	SigHandler);
	signal(SIGPIPE,	SIG_IGN);
}

static void
SigHandler(int iSigNum) {

	switch (iSigNum) {
	case SIGINT:
	case SIGTERM:
	case SIGKILL:
		//exit(1);
		thrp_shutdown(g_data.thrp);
		break;
	case SIGHUP:
	case SIGUSR1:
	case SIGUSR2:
		break;
	}
}





/* Offset must pont to data start, size = data offset + data size. */
static void
send_http_to_cli(http_srv_cli_p cli, uint32_t status_code) {
	struct iovec iov[1];
	str_hub_params_p params;

	switch (status_code) {
	case 200: /* Send data... */
		if (HTTP_REQ_METHOD_GET == http_srv_cli_get_req(cli)->line.method_code)
			http_srv_cli_add_resp_p_flags(cli, HTTP_SRV_RESP_P_F_CONTENT_SIZE);
		else
			http_srv_cli_del_resp_p_flags(cli, HTTP_SRV_RESP_P_F_CONTENT_SIZE);
		iov[0].iov_base = (void*)
		    "Content-Type: text/plain\r\n"
		    "Pragma: no-cache";
		iov[0].iov_len = 42;
		http_srv_snd(cli, 200, NULL, 0, (struct iovec*)&iov, 1);
		break;
	case 2000: /* Send HTTP headers only... */
		params = http_srv_cli_get_udata(cli);
		http_srv_cli_set_udata(cli, NULL);
		http_srv_cli_del_resp_p_flags(cli, HTTP_SRV_RESP_P_F_CONTENT_SIZE);

		if (6 < params->cust_http_hdrs_size) {
			iov[0].iov_base = (void*)(params->cust_http_hdrs + 2);
			iov[0].iov_len = (params->cust_http_hdrs_size - 6);
		} else {
			iov[0].iov_base = NULL;
			iov[0].iov_len = 0;
		}
		http_srv_snd(cli, 200, NULL, 0, (struct iovec*)&iov, 1);
		break;
	default:
		http_srv_snd(cli, status_code, NULL, 0, NULL, 0);
		break;
	}

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
	uint8_t *ptm;
	size_t tm;
	io_task_p iotask;
	uintptr_t skt;

	LOGD_EV("...");

	if (NULL == cli || NULL == hub_name)
		return (EINVAL);

	iotask = http_srv_cli_get_iotask(cli);
	skt = io_task_ident_get(iotask);
	/* Extract tcpCC, "User-Agent". */
	req = http_srv_cli_get_req(cli);
	/* tcpcc. */
	if (0 == http_query_val_get(req->line.query, req->line.query_size,
	    (uint8_t*)"tcpcc", 5, &ptm, &tm)) {
		io_net_set_tcp_cc(skt, (char*)ptm, tm);
	}
	/* Extract "User-Agent". */
	if (0 != http_hdr_val_get(req->hdr, req->hdr_size,
	    (uint8_t*)"user-agent", 10, &ptm, &tm)) {
		ptm = NULL;
		tm = 0;
	}
	strh_cli = str_hub_cli_alloc(skt, (const char*)ptm, tm);
	if (NULL == strh_cli) {
		LOG_ERR(ENOMEM, "str_hub_cli_alloc()");
		http_srv_cli_free(cli);
		return (ENOMEM);
	}
	/*
	 * Set stream hub client data: some form http server client other from
	 * http request.
	 */
	http_srv_cli_get_addr(cli, &strh_cli->remonte_addr);

	/* Client IP: get "X-Real-IP" from headers. */
	if (0 != http_hdr_val_get(req->hdr, req->hdr_size,
	    (uint8_t*)"x-real-ip", 9, &ptm, &tm) ||
	    0 != str_addr_port_to_ss((char*)ptm, tm, &strh_cli->xreal_addr) ||
	    0 != sa_is_addr_loopback(&strh_cli->xreal_addr)) { /* No or bad addr. */
		sa_copy(&strh_cli->remonte_addr, &strh_cli->xreal_addr);
	}

	LOGD_INFO_FMT("%s - : attach...", hub_name);
	error = str_hub_cli_attach(g_data.shbskt, strh_cli, hub_name, hub_name_size,
	    src_conn_params);
	/* Do not read/write to stream hub client, stream hub is new owner! */
	if (0 != error) {
		str_hub_cli_destroy(NULL, strh_cli);
		io_task_flags_del(iotask, IO_TASK_F_CLOSE_ON_DESTROY);
		http_srv_cli_free(cli);
		LOG_ERR(error, "str_hub_cli_attach()");
	}
	return (error);
}

int
msd_http_req_url_parse(http_srv_req_p req, struct sockaddr_storage *ssaddr,
    uint32_t *if_index,
    uint8_t *hub_name, size_t hub_name_size, size_t *hub_name_size_ret) {
	uint8_t *ptm;
	size_t tm;
	uint32_t ifindex;
	char straddr[STR_ADDR_LEN], ifname[(IFNAMSIZ + 1)];
	struct sockaddr_storage ss;

	LOGD_EV("...");

	if (NULL == req || NULL == hub_name || 0 == hub_name_size)
		return (500);
	/* Get multicast address. */
	if (0 != str_addr_port_to_ss((const char*)(req->line.abs_path + 5),
	    (req->line.abs_path_size - 5), &ss))
		return (400);
	if (0 == sain_p_get(&ss)) /* Def udp port. */
		sain_p_set(&ss, 1234);
	/* ifname, ifindex. */
	if (0 == http_query_val_get(req->line.query, req->line.query_size,
	    (uint8_t*)"ifname", 6, &ptm, &tm) && IFNAMSIZ > tm) {
		memcpy(ifname, ptm, tm);
		ifname[tm] = 0;
		ifindex = if_nametoindex(ifname);
	} else {
		if (0 == http_query_val_get(req->line.query, 
		    req->line.query_size, (uint8_t*)"ifindex", 7,
		    &ptm, &tm)) {
			ifindex = UStr8ToUNum32(ptm, tm);
		} else { /* Default value. */
			if (NULL != if_index)
				ifindex = (*if_index);
			else
				ifindex = -1;
		}
		ifname[0] = 0;
		if_indextoname(ifindex, ifname);
	}

	if (0 != ss_to_str_addr_port(&ss, straddr, sizeof(straddr), NULL))
		return (400);
	tm = snprintf((char*)hub_name, hub_name_size,
	    "/udp/%s@%s", straddr, ifname);
	if (NULL != ssaddr)
		sa_copy(&ss, ssaddr);
	if (NULL != if_index)
		(*if_index) = ifindex;


	if (NULL != hub_name_size_ret)
		(*hub_name_size_ret) = tm;
	return (HTTP_SRV_CB_NONE);
}



/* http request from client is received now, process it. */
static int
msd_http_srv_on_req_rcv_cb(http_srv_cli_p cli, void *udata __unused,
    http_srv_req_p req) {
	size_t buf_size;
	int error;
	uint8_t buf[512];
	str_src_conn_params_t src_conn_params;

	LOGD_EV("...");

	if (HTTP_REQ_METHOD_GET != req->line.method_code &&
	    HTTP_REQ_METHOD_HEAD != req->line.method_code)
		return (400);
	if (0 == (req->flags & HTTP_SRV_RD_F_HOST_IS_LOCAL))
		return (403);

	/* Statistic request. */
	if (HTTP_REQ_METHOD_GET == req->line.method_code &&
	    0 == buf_cmpi(req->line.abs_path, req->line.abs_path_size, "/stat", 5)) {
		error = gen_stat_text(PACKAGE_NAME, PACKAGE_VERSION,
		    g_data.shbskt, &g_data.sysres,
		    (uint8_t*)g_data.sysinfo, g_data.sysinfo_size,
		    (uint8_t*)g_data.syslimits, g_data.syslimits_size, cli);
		if (0 != error)
			return (500);
		send_http_to_cli(cli, 200);
		return (HTTP_SRV_CB_NONE);
	}
	/* Stream Hub statistic request. */
	if (HTTP_REQ_METHOD_GET == req->line.method_code &&
	    7 < req->line.abs_path_size &&
	    0 == buf_cmpi(req->line.abs_path, 8, "/hubstat", 8)) {
		error = gen_hub_stat_text_send_async(g_data.shbskt, cli);
		if (0 != error)
			return (500);
		return (HTTP_SRV_CB_NONE);
	}

	if (12 < req->line.abs_path_size &&
	    (0 == memcmp(req->line.abs_path, "/udp/", 5) ||
	    0 == memcmp(req->line.abs_path, "/rtp/", 5))) {
		/* Default value. */
		memcpy(&src_conn_params, &g_data.src_conn_params, sizeof(str_src_conn_mc_t));
		/* Get multicast address, ifindex, hub name. */
		error = msd_http_req_url_parse(req, &src_conn_params.udp.addr,
		    &src_conn_params.mc.if_index, buf, sizeof(buf), &buf_size);
		if (HTTP_SRV_CB_NONE != error)
			return (error);
		if (HTTP_REQ_METHOD_HEAD == req->line.method_code) {
			http_srv_cli_set_udata(cli, &g_data.hub_params);
			send_http_to_cli(cli, 2000);
			return (HTTP_SRV_CB_NONE);
		}
		if (0 != msd_http_srv_hub_attach(cli, buf, buf_size, &src_conn_params))
			return (500);
		return (HTTP_SRV_CB_NONE);
	} /* "/udp/" / "/rtp/" */

	return (404);
}
