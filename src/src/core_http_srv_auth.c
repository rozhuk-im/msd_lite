/*-
 * Copyright (c) 2015 - 2016 Rozhuk Ivan <rozhuk.im@gmail.com>
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

#include <stdlib.h> /* malloc, exit */
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <stdio.h> /* snprintf, fprintf */
#include <errno.h>

#include "mem_helpers.h"
#include "HTTP.h"

#include "macro_helpers.h"
#include "core_log.h"
#include "core_http_srv.h"
#include "core_http_srv_auth.h"
#ifdef HTTP_SRV_XML_CONFIG
#include "core_helpers.h"
#include "xml.h"
#endif



typedef struct http_srv_cli_auth_ctx_s { /* Per user auth data = new udata. */
	auth_pl_p		plugin;	/* Auth plugin. */
	void			*plugin_ctx; /* Per user auth current state. */
	http_srv_cli_ccb_t	ccb;
	void			*udata_old;
} http_srv_cli_auth_ctx_t, *http_srv_cli_auth_ctx_p;



int	http_srv_auth_on_req_rcv_cb(http_srv_cli_p cli, void *udata,
	    http_srv_req_p req);
int	http_srv_auth_on_rep_snd_cb(http_srv_cli_p cli, void *udata);
void	http_srv_auth_on_destroy_cb(http_srv_cli_p cli, void *udata);

int	http_srv_auth_ok(http_srv_cli_p cli, http_srv_cli_auth_ctx_p auth_ctx);

void	http_srv_auth_cleanup(http_srv_cli_p cli, http_srv_cli_auth_ctx_p auth_ctx);


static http_srv_cli_ccb_t http_srv_cli_auth_ccb = {
	.on_req_rcv = http_srv_auth_on_req_rcv_cb;
	.on_rep_snd = http_srv_auth_on_rep_snd_cb;
	.on_destroy = http_srv_auth_on_destroy_cb;
};



/* http_srv_on_req_rcv_cb */
int
http_srv_auth_on_req_rcv_cb(http_srv_cli_p cli, void *udata,
    http_srv_req_p req) {
	int error;
	uint8_t *ptm, *login, *password;
	uint8_t tmbuf[512];
	size_t tm, login_size, password_size, params_count = 0;
	auth_pl_p plugin;
	http_srv_cli_auth_ctx_p auth_ctx;
	auth_pl_param_t params[8];
	sockaddr_storage addr;

	LOGD_EV("...");
	if (NULL == cli || NULL == udata || NULL == req)
		return (500);
	auth_ctx = udata;
	plugin = auth_ctx->plugin;
	if (NULL == plugin)
		return (500);

	login = NULL;
	login_size = 0;
	password = NULL;
	password_size = 0;

	/* Process "Authorization" header. */
	if (0 == (plugin->allowed_types & HTTP_SRV_AUTH_TYPE_F_AUTHORIZATION))
		goto no_authorization_hdr;
	/* Extract "Authorization" field data. */
	if (0 != http_hdr_val_get(req->hdr, req->hdr_size,
	    (uint8_t*)"authorization", 13, &ptm, &tm))
		goto no_authorization_hdr;
	if (6 < tm && 0 == mem_cmpi_cstr("basic ", ptm)) {
		ptm += 6;
		tm -= 6;
		skeep_spwsp(ptm, tm, &ptm, &tm);
		error = base64_decode(ptm, tm, (uint8_t*)tmbuf,
		    sizeof(tmbuf), &tm);
		if (0 != error)
			goto no_authorization_hdr;
		password = mem_chr((uint8_t*)tmbuf, tm, ':');
		if (NULL == password)
			goto no_authorization_hdr;
		login = (uint8_t*)tmbuf;
		login_size = (password - login);
		password ++;
		password_size = ((login + tm) - password);
		
		method = AUTH_PL_METHOD_BASIC;
		goto login_password_ok;
	} else if (7 < tm && 0 == mem_cmpi_cstr("digest ", ptm)) {
		ptm += 7;
		tm -= 7;
		skeep_spwsp(ptm, tm, &ptm, &tm);
		//...
		//data->type = HTTP_SRV_CLI_AUTH_TYPE_DIGEST;
		method = AUTH_PL_METHOD_DIGEST;
	}
no_authorization_hdr:

	/* Process login and password in uri args. */
	if (0 == (plugin->allowed_types & HTTP_SRV_AUTH_TYPE_F_URI_ARGS))
		goto no_auth_url_args;
	if (0 != http_query_val_get(req->query, req->query_size,
	    plugin->uri_arg_name_login, plugin->uri_arg_name_login_size,
	    &login, &login_size))
		goto no_auth_url_args;
	http_query_val_get(req->query, req->query_size,
	    plugin->uri_arg_name_password, plugin->uri_arg_name_password_size,
	    &password, &password_size); /* Allow empty password. */

no_auth_url_args:
#if 0
	/* Login and password not found. */
	if (0 == (plugin->flags & HTTP_SRV_AUTH_PL_F_TRY_WO_LOGIN_PWD)) {
		return (401);
	}
#endif
	method = AUTH_PL_METHOD_BASIC;
	//goto login_password_ok;

login_password_ok:

	/* Login. */
	params[params_count].type = AUTH_PL_PARAM_TYPE_LOGIN;
	params[params_count].size = login_size;
	params[params_count].data = login;
	params_count ++;
	/* Password. */
	params[params_count].type = AUTH_PL_PARAM_TYPE_PASSWORD;
	params[params_count].size = password_size;
	params[params_count].data = password;
	params_count ++;
	/* Cli addr. */
	if (0 == http_srv_cli_get_addr(cli, &addr)) {
		params[params_count].type = AUTH_PL_PARAM_TYPE_CLI_ADDR;
		params[params_count].size = sizeof(addr);
		params[params_count].data = &addr;
		params_count ++;
	}
	/* URI path. */
	params[params_count].type = AUTH_PL_PARAM_TYPE_URI;
	params[params_count].size = req->line.abs_path_size;
	params[params_count].data = req->line.abs_path;
	params_count ++;
	/* "User-Agent". */
	if (0 == http_hdr_val_get(req->hdr, req->hdr_size,
	    (uint8_t*)"user-agent", 10, &ptm, &tm)) {
		params[params_count].type = AUTH_PL_PARAM_TYPE_USER_AGENT;
		params[params_count].size = tm;
		params[params_count].data = ptm;
		params_count ++;
	}

	error = plugin->challenge_fn(plugin, auth_ctx->plugin_ctx,
	    method, &params, params_count);
	switch (error) {
	case 0: /* Auth OK. */
		return (http_srv_auth_ok(cli, auth_ctx));
		break;
	case EINPROGRESS: /* Will continue later. */
		return (HTTP_SRV_CB_NONE);
		break;
	case EAUTH: /* Bad login/password. */
		return (401); /* Retry. */
		break;
	}
	LOG_ERR(error, "auth_basic pluin error");
	return (500);
}

void
http_srv_auth_on_auth_pl_responce_cb(auth_pl_p plugin, void *cr_ctx,
    size_t method, int error, void *udata,
    auth_pl_param_p params, size_t params_count) {
	http_srv_cli_p cli = (http_srv_cli_p)udata;
	http_srv_cli_auth_ctx_p auth_ctx;
	struct iovec iov[4];
	size_t iov_cnt = 0;

	LOGD_EV("...");
	if (NULL == cli)
		return;
	auth_ctx = (http_srv_cli_auth_ctx_p)http_srv_cli_get_udata(cli);

	if (0 != error) {
		cli->resp_p_flags |= HTTP_SRV_RESP_P_F_CONN_CLOSE;
		http_srv_snd_err(cli, 500, NULL, 0); /* Internal Server Error. */
		LOG_ERR(error, "auth_plugin_radius_auth_cb()");
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





/* http_srv_on_resp_snd_cb */
int
http_srv_auth_on_rep_snd_cb(http_srv_cli_p cli, void *udata) {

	LOGD_EV("...");
	return (HTTP_SRV_CB_NONE);
}

/* http_srv_on_destroy_cb */
void
http_srv_auth_on_destroy_cb(http_srv_cli_p cli, void *udata) {
	http_srv_cli_auth_ctx_p auth_ctx;
	http_srv_on_destroy_cb on_destroy_old;
	void *udata_old;

	LOGD_EV("...");
	if (NULL == udata)
		return;
	auth_ctx = udata;
	/* Remember(cache) destroy_cb and udata.  */
	on_destroy_old = auth_ctx->ccb.on_destroy_old;
	udata_old = auth_ctx->udata_old;
	/* Restore original cb and clean up. */
	http_srv_auth_cleanup(cli, auth_ctx);
	/* Call next destroy_cb. */
	if (NULL == on_destroy_old)
		return;
	on_destroy_old(cli, udata_old);
}


int
http_srv_auth_ok(http_srv_cli_p cli, http_srv_cli_auth_ctx_p auth_ctx) {
	http_srv_on_req_rcv_cb on_req_rcv_old;
	void *udata_old;

	LOGD_EV("...");
	if (NULL == auth_ctx)
		return (500);
	/* Remember(cache) on_req_rcv_cb and udata.  */
	on_req_rcv_old = auth_ctx->ccb.on_req_rcv_old;
	udata_old = auth_ctx->udata_old;
	/* Restore original cb and clean up. */
	http_srv_auth_cleanup(cli, auth_ctx);
	/* Call next on_req_rcv_cb. */
	if (NULL == on_req_rcv_old)
		return (404);
	return (on_req_rcv_old(cli, udata_old, http_srv_cli_get_req(cli)));
}



int
http_srv_auth_start(http_srv_cli_p cli, auth_pl_p plugin,
    http_srv_req_p req) {
	http_srv_cli_auth_ctx_p auth_ctx;

	LOGD_EV("...");
	if (NULL == cli || NULL == plugin || NULL == req)
		return (500);
	if (http_srv_auth_on_req_rcv_cb == http_srv_cli_get_on_req_rcv(cli))
		return (508);
	auth_ctx = zalloc(sizeof(http_srv_cli_auth_ctx_t));
	if (NULL == auth_ctx)
		return (500);
	auth_ctx->plugin = plugin;
	if (NULL != plugin->cr_ctx_alloc_fn) {
		auth_ctx->plugin_ctx = plugin->cr_ctx_alloc_fn(plugin,
		    io_task_thrpt_get(http_srv_cli_get_iotask(iotask)),
		    http_srv_auth_on_auth_pl_responce_cb ,cli);
		if (NULL == auth_ctx->plugin_ctx) {
			free(auth_ctx);
			return (500);
		}
	}
	/* Save prev custom handler. */
	http_srv_cli_ccb_get(cli, &auth_ctx->ccb);
	auth_ctx->udata_old = http_srv_cli_get_udata(cli);
	/* Set new custom handlers. */
	http_srv_cli_ccb_set(cli, &http_srv_cli_auth_ccb);
	http_srv_cli_set_udata(cli, auth_ctx);

	return (http_srv_auth_on_req_rcv_cb(cli, auth_ctx, req));
}

void
http_srv_auth_cleanup(http_srv_cli_p cli, http_srv_cli_auth_ctx_p auth_ctx) {

	LOGD_EV("...");
	if (NULL == auth_ctx)
		return;
	if (NULL != auth_ctx->plugin) {
		if (NULL != auth_ctx->plugin->cr_ctx_free_fn) {
			auth_ctx->plugin->cr_ctx_free_fn(auth_ctx->plugin_ctx);
		}
	}
	/* Restore handlers. */
	http_srv_cli_ccb_set(cli, &auth_ctx->ccb);
	http_srv_cli_set_udata(cli, auth_ctx->udata_old);
	free(auth_plugin);
}



