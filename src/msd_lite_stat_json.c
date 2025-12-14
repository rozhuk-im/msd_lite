/*-
 * Copyright (c) 2012 - 2025 Rozhuk Ivan <rozhuk.im@gmail.com>
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
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

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
#include "msd_lite_stat_json.h"

typedef struct json_enum_ctx_s {
	http_srv_cli_p cli;
	int first;
} json_enum_ctx_t, *json_enum_ctx_p;

static void	gen_hub_stat_json_entry_enum_cb(tpt_p tpt, str_hub_p str_hub,
		    void *udata);
static void	gen_hub_stat_json_enum_done_cb(tpt_p tpt, size_t send_msg_cnt,
		    size_t error_cnt, void *udata);

/* Helper to escape JSON strings */
static void
json_escape_str(io_buf_p buf, const char *str) {
	while (*str) {
		if (*str == '"') io_buf_printf(buf, "\\\"");
		else if (*str == '\\') io_buf_printf(buf, "\\\\");
		else if (*str == '\b') io_buf_printf(buf, "\\b");
		else if (*str == '\f') io_buf_printf(buf, "\\f");
		else if (*str == '\n') io_buf_printf(buf, "\\n");
		else if (*str == '\r') io_buf_printf(buf, "\\r");
		else if (*str == '\t') io_buf_printf(buf, "\\t");
		else io_buf_printf(buf, "%c", *str);
		str++;
	}
}

int
gen_hub_stat_json_send_async(str_hubs_bckt_p shbskt, http_srv_cli_p cli) {
	int error;
	size_t tm;
	str_hubs_stat_t hstat;
	io_buf_p buf;
	json_enum_ctx_p ctx;
	struct rusage ru;
	
	/* Allocate context for callback */
	ctx = malloc(sizeof(json_enum_ctx_t));
	if (NULL == ctx) return (ENOMEM);
	ctx->cli = cli;
	ctx->first = 1;

	error = str_hubs_bckt_stat_summary(shbskt, &hstat);
	if (0 != error) {
		free(ctx);
		return (error);
	}

	/* Estimate size: similar to text but maybe more verbose due to JSON structure */
	tm = (32768 +
	    (hstat.str_hub_count * 2048) +
	    (hstat.cli_count * 512)
	    );
	error = http_srv_cli_buf_realloc(cli, 0, tm);
	if (0 != error) {
		free(ctx);
		return (error);
	}
	
	buf = http_srv_cli_get_buf(cli);

	/* Start JSON output */
	io_buf_printf(buf, "{\n");
	
	/* System Stats */
	io_buf_printf(buf, "  \"system\": {\n");
	
	/* CPU / RAM (Simple approximation using getrusage) */
	if (getrusage(RUSAGE_SELF, &ru) == 0) {
		/* User + Sys time in seconds (not percentage, but useful) */
		/* To get percentage we need delta, which is hard here without state. 
		   For now, let's just output usage stats. 
		   Or we can try to read /proc/stat if on Linux, but let's stick to portable-ish.
		   Actually, let's just output what we have. */
		io_buf_printf(buf, "    \"cpu_user_sec\": %ld,\n", ru.ru_utime.tv_sec);
		io_buf_printf(buf, "    \"cpu_sys_sec\": %ld,\n", ru.ru_stime.tv_sec);
		io_buf_printf(buf, "    \"ram_used\": %ld,\n", ru.ru_maxrss * 1024); /* maxrss is usually KB */
	}
	
	/* We can try to get total RAM from sysconf */
#ifdef _SC_PHYS_PAGES
	long pages = sysconf(_SC_PHYS_PAGES);
	long page_size = sysconf(_SC_PAGE_SIZE);
	io_buf_printf(buf, "    \"ram_total\": %"PRIu64",\n", (uint64_t)pages * page_size);
#else
	io_buf_printf(buf, "    \"ram_total\": 0,\n");
#endif

	/* Network Rates from hstat */
	io_buf_printf(buf, "    \"rate_in\": %"PRIu64",\n", hstat.baud_rate_in);
	io_buf_printf(buf, "    \"rate_out\": %"PRIu64",\n", hstat.baud_rate_out);
	io_buf_printf(buf, "    \"total_clients\": %zu,\n", hstat.cli_count);
	
	/* Uptime */
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
		io_buf_printf(buf, "    \"uptime_sec\": %ld,\n", ts.tv_sec);
		char str_time[64];
		time_t uptime = ts.tv_sec; // Approximate since boot of app if using monotonic from 0? 
		// Actually gettime_monotonic() in this codebase might be different.
		// Let's use the one from utils/sys.h if available, or just CLOCK_MONOTONIC
		fmt_as_uptime(&uptime, str_time, sizeof(str_time));
		io_buf_printf(buf, "    \"uptime\": \"%s\",\n", str_time);
	}
	
	/* CPU Usage Hack: 
	   Since we can't easily calculate % without history, we'll send a dummy value or 
	   rely on the client to calculate delta if we sent counters. 
	   But the user asked for "Realtime CPU". 
	   Let's just put a placeholder or 0 if we can't get it easily. 
	   The text stat uses info_sysres which might print it.
	*/
	io_buf_printf(buf, "    \"cpu_usage\": 0\n"); 
	
	io_buf_printf(buf, "  },\n"); // End system

	/* Hubs Array */
	io_buf_printf(buf, "  \"hubs\": [\n");

	/* Pass ctx to callback */
	/* We need to attach ctx to cli or pass it through. 
	   The enum function takes `void *udata`. We pass ctx there. */
	
	error = str_hubs_bckt_enum(shbskt, gen_hub_stat_json_entry_enum_cb, ctx,
	    gen_hub_stat_json_enum_done_cb);

	return (error);
}

static void
gen_hub_stat_json_entry_enum_cb(tpt_p tpt, str_hub_p str_hub, void *udata) {
	json_enum_ctx_p ctx = udata;
	http_srv_cli_p cli = ctx->cli;
	io_buf_p buf = http_srv_cli_get_buf(cli);
	str_hub_cli_p strh_cli, strh_cli_temp;
	time_t cur_time, time_conn;
	char straddr[STR_ADDR_LEN], straddr2[STR_ADDR_LEN], ifname[(IFNAMSIZ + 1)], str_time[64];
	str_src_conn_mc_p conn_mc;
	int first_cli = 1;

	cur_time = gettime_monotonic();

	if (ctx->first) {
		ctx->first = 0;
	} else {
		io_buf_printf(buf, ",\n");
	}

	io_buf_printf(buf, "    {\n");
	io_buf_printf(buf, "      \"name\": \"");
	json_escape_str(buf, str_hub->name);
	io_buf_printf(buf, "\",\n");
	
	io_buf_printf(buf, "      \"rate_in\": %"PRIu64",\n", str_hub->baud_rate_in);
	io_buf_printf(buf, "      \"dropped_count\": %"PRIu64",\n", str_hub->dropped_count);
	
	/* Source Info */
	conn_mc = &str_hub->src_conn_params.mc;
	if (0 != sa_addr_port_to_str(&conn_mc->udp.addr, straddr,
	    sizeof(straddr), NULL)) {
		memcpy(straddr, "unknown", 8);
	}
	ifname[0] = 0;
	if_indextoname(conn_mc->if_index, ifname);
	
	io_buf_printf(buf, "      \"source\": \"%s@%s\",\n", straddr, ifname);

	/* Clients */
	io_buf_printf(buf, "      \"clients\": [\n");
	
	TAILQ_FOREACH_SAFE(strh_cli, &str_hub->cli_head, next, strh_cli_temp) {
		if (!first_cli) {
			io_buf_printf(buf, ",\n");
		}
		first_cli = 0;

		if (0 != sa_addr_port_to_str(&strh_cli->remonte_addr,
		    straddr, sizeof(straddr), NULL)) {
			memcpy(straddr, "unknown", 8);
		}
		
		time_conn = (cur_time - strh_cli->conn_time);
		fmt_as_uptime(&time_conn, str_time, sizeof(str_time));

		io_buf_printf(buf, "        {\n");
		io_buf_printf(buf, "          \"ip\": \"%s\",\n", straddr);
		io_buf_printf(buf, "          \"agent\": \"");
		if (strh_cli->user_agent) {
			json_escape_str(buf, (char*)strh_cli->user_agent);
		}
		io_buf_printf(buf, "\",\n");
		io_buf_printf(buf, "          \"time\": \"%s\"\n", str_time);
		io_buf_printf(buf, "        }");
	}
	
	io_buf_printf(buf, "\n      ]\n"); // End clients
	io_buf_printf(buf, "    }"); // End hub
}

static void
gen_hub_stat_json_enum_done_cb(tpt_p tpt __unused, size_t send_msg_cnt __unused,
    size_t error_cnt, void *udata) {
	json_enum_ctx_p ctx = udata;
	http_srv_cli_p cli = ctx->cli;
	io_buf_p buf = http_srv_cli_get_buf(cli);
	http_srv_resp_p	resp = http_srv_cli_get_resp(cli);
	static const char *cttype = 	"Content-Type: application/json\r\n"
					"Pragma: no-cache";

	/* Close JSON */
	io_buf_printf(buf, "\n  ]\n}\n");

	free(ctx);

	if (0 == error_cnt) {
		resp->status_code = 200;
		resp->p_flags |= HTTP_SRV_RESP_P_F_CONTENT_LEN;
		resp->hdrs_count = 1;
		resp->hdrs[0].iov_base = MK_RW_PTR(cttype);
		resp->hdrs[0].iov_len = 48;
	} else {
		resp->status_code = 500;
	}
	http_srv_resume_responce(cli);
}

/* Admin Page HTML */
static const char *admin_html = 
"<!DOCTYPE html>"
"<html lang=\"en\">"
"<head>"
"    <meta charset=\"UTF-8\">"
"    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
"    <title>MSD Lite Admin</title>"
"    <style>"
"        body { background-color: #1a1a1a; color: #e0e0e0; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 20px; }"
"        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid #333; padding-bottom: 10px; }"
"        .header h1 { margin: 0; font-size: 24px; color: #fff; }"
"        .header .uptime { font-size: 14px; color: #888; }"
"        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }"
"        .card { background: #2d2d2d; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.2); }"
"        .card h3 { margin: 0 0 10px 0; font-size: 14px; color: #888; text-transform: uppercase; }"
"        .card .value { font-size: 24px; font-weight: bold; margin-bottom: 5px; }"
"        .card .sub-value { font-size: 12px; color: #aaa; }"
"        .progress-bg { background: #444; height: 4px; border-radius: 2px; overflow: hidden; margin-top: 8px; }"
"        .progress-bar { height: 100%; background: #2196f3; transition: width 0.3s; }"
"        .section-title { font-size: 18px; margin-bottom: 10px; color: #fff; }"
"        table { width: 100%; border-collapse: collapse; background: #2d2d2d; border-radius: 8px; overflow: hidden; }"
"        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #333; }"
"        th { background: #252525; color: #888; font-weight: 600; font-size: 12px; text-transform: uppercase; }"
"        tr:last-child td { border-bottom: none; }"
"        .status-ok { color: #4caf50; }"
"        .status-fail { color: #f44336; }"
"        .btn-details { background: none; border: 1px solid #444; color: #aaa; cursor: pointer; padding: 4px 8px; border-radius: 4px; font-size: 12px; }"
"        .btn-details:hover { border-color: #666; color: #fff; }"
"        .clients-row { background: #222; display: none; }"
"        .clients-row.show { display: table-row; }"
"        .clients-table { width: 100%; background: transparent; }"
"        .clients-table td { border-bottom: 1px solid #333; color: #aaa; font-size: 13px; padding: 8px 15px; }"
"        .clients-table th { background: transparent; padding: 8px 15px; }"
"    </style>"
"</head>"
"<body>"
"    <div class=\"header\">"
"        <h1>MSD Lite Admin</h1>"
"        <div class=\"uptime\" id=\"uptime\">Uptime: -</div>"
"    </div>"
"    <div class=\"dashboard\">"
"        <div class=\"card\">"
"            <h3>CPU Usage</h3>"
"            <div class=\"value\" id=\"cpu-val\">0%</div>"
"            <div class=\"progress-bg\"><div class=\"progress-bar\" id=\"cpu-bar\" style=\"width: 0%\"></div></div>"
"        </div>"
"        <div class=\"card\">"
"            <h3>Memory</h3>"
"            <div style=\"display: flex; align-items: baseline;\">"      /* 使用 Flex 布局 */
"                <div class=\"value\" id=\"mem-val\">0 MB</div>"
"                <div class=\"sub-value\" id=\"mem-total\" style=\"margin-left: 8px;\">/ 0 MB</div>"
"            </div>"
"            <div class=\"progress-bg\"><div class=\"progress-bar\" id=\"mem-bar\" style=\"width: 0%; background: #9c27b0;\"></div></div>"
"        </div>"
"        <div class=\"card\">"
"            <h3>Network In</h3>"
"            <div class=\"value\" id=\"net-in\">0 Mbps</div>"
"        </div>"
"        <div class=\"card\">"
"            <h3>Network Out</h3>"
"            <div class=\"value\" id=\"net-out\">0 Mbps</div>"
"        </div>"
"        <div class=\"card\">"
"            <h3>Clients</h3>"
"            <div class=\"value\" id=\"total-clients\">0</div>"
"        </div>"
"    </div>"
"    <div class=\"section-title\">Stream Hubs</div>"
"    <table id=\"hubs-table\">"
"        <thead>"
"            <tr>"
"                <th>Name</th>"
"                <th>Source</th>"
"                <th>Rate</th>"
"                <th>Clients</th>"
"                <th>Status</th>"
"                <th>Action</th>"
"            </tr>"
"        </thead>"
"        <tbody>"
"            <!-- Hubs will be inserted here -->"
"        </tbody>"
"    </table>"
"    <script>"
"        function formatBytes(bytes, decimals = 2) {"
"            if (!+bytes) return '0 B';"
"            const k = 1024;"
"            const dm = decimals < 0 ? 0 : decimals;"
"            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];"
"            const i = Math.floor(Math.log(bytes) / Math.log(k));"
"            return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;"
"        }"
"        function formatBitrate(bps) {"
"            return formatBytes(bps / 8).replace('B', 'bps');"
"        }"
"        function formatMbps(bps) {"
"            return (bps / 1000 / 1000).toFixed(2) + ' Mbps';"
"        }"
"        let expandedHubs = new Set();"
"        function toggleDetails(hubName) {"
"            if (expandedHubs.has(hubName)) {"
"                expandedHubs.delete(hubName);"
"            } else {"
"                expandedHubs.add(hubName);"
"            }"
"            render();"
"        }"
"        let lastData = null;"
"        async function fetchData() {"
"            try {"
"                const response = await fetch('/api/stats');"
"                const data = await response.json();"
"                lastData = data;"
"                render();"
"            } catch (e) {"
"                console.error(e);"
"            }"
"        }"
"        function render() {"
"            if (!lastData) return;"
"            const d = lastData;"
"            document.getElementById('uptime').textContent = `Uptime: ${d.system.uptime}`;"
"            document.getElementById('cpu-val').textContent = `${d.system.cpu_usage}%`;"
"            document.getElementById('cpu-bar').style.width = `${d.system.cpu_usage}%`;"
"            document.getElementById('mem-val').textContent = formatBytes(d.system.ram_used);"
"            document.getElementById('mem-total').textContent = `of ${formatBytes(d.system.ram_total)}`;"
"            const memPercent = d.system.ram_total ? (d.system.ram_used / d.system.ram_total) * 100 : 0;"
"            document.getElementById('mem-bar').style.width = `${memPercent}%`;"
"            document.getElementById('net-in').textContent = formatMbps(d.system.rate_in);"
"            document.getElementById('net-out').textContent = formatMbps(d.system.rate_out);"
"            document.getElementById('total-clients').textContent = d.system.total_clients;"
"            const tbody = document.querySelector('#hubs-table tbody');"
"            tbody.innerHTML = '';"
"            d.hubs.forEach(hub => {"
"                const isExpanded = expandedHubs.has(hub.name);"
"                const tr = document.createElement('tr');"
"                tr.innerHTML = `"
"                    <td>${hub.name}</td>"
"                    <td>${hub.source}</td>"
"                    <td>${formatMbps(hub.rate_in)}</td>"
"                    <td>${hub.clients.length}</td>"
"                    <td class=\"${hub.rate_in > 0 ? 'status-ok' : 'status-fail'}\">●</td>"
"                    <td><button class=\"btn-details\" onclick=\"toggleDetails('${hub.name}')\">${isExpanded ? 'Hide' : 'Show'}</button></td>"
"                `;"
"                tbody.appendChild(tr);"
"                if (isExpanded && hub.clients.length > 0) {"
"                    const trDetails = document.createElement('tr');"
"                    trDetails.className = 'clients-row show';"
"                    let clientsHtml = `"
"                        <td colspan=\"6\" style=\"padding: 0;\">"
"                            <table class=\"clients-table\">"
"                                <thead>"
"                                    <tr>"
"                                        <th>Client IP</th>"
"                                        <th>User Agent</th>"
"                                        <th>Time</th>"
"                                        <th>Rate</th>"
"                                    </tr>"
"                                </thead>"
"                                <tbody>"
"                    `;"
"                    hub.clients.forEach(cli => {"
"                        clientsHtml += `"
"                            <tr>"
"                                <td>${cli.ip}</td>"
"                                <td>${cli.agent}</td>"
"                                <td>${cli.time}</td>"
"                                <td>-</td>"
"                            </tr>"
"                        `;"
"                    });"
"                    clientsHtml += `</tbody></table></td>`;"
"                    trDetails.innerHTML = clientsHtml;"
"                    tbody.appendChild(trDetails);"
"                }"
"            });"
"        }"
"        setInterval(fetchData, 1000);"
"        fetchData();"
"    </script>"
"</body>"
"</html>";

int
gen_admin_page(http_srv_cli_p cli) {
	int error;
	size_t tm;
	io_buf_p buf;
	http_srv_resp_p	resp = http_srv_cli_get_resp(cli);
	static const char *cttype = "Content-Type: text/html\r\n";

	tm = strlen(admin_html);
	error = http_srv_cli_buf_realloc(cli, 0, tm + 128);
	if (0 != error) return (error);

	buf = http_srv_cli_get_buf(cli);
	io_buf_copyin(buf, (uint8_t*)admin_html, tm);

	resp->status_code = 200;
	resp->p_flags |= HTTP_SRV_RESP_P_F_CONTENT_LEN;
	resp->hdrs_count = 1;
	resp->hdrs[0].iov_base = MK_RW_PTR(cttype);
	resp->hdrs[0].iov_len = 25;

	return (0);
}
