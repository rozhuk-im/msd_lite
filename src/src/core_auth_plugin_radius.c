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

#include "macro_helpers.h"
#include "core_log.h"
#include "core_thrp.h"
#include "core_io_buf.h"
#include "core_radius_cli.h"
#include "core_auth_plugin.h"
#ifdef HTTP_SRV_XML_CONFIG
#include "core_helpers.h"
#include "xml.h"
#endif



typedef struct auth_pl_radius_cr_ctx_s { /* Per challenge-responce auth data. */
	auth_pl_p	plugin;
	io_buf_t	buf;		/* Used for send radius packets. */
	size_t		method;		/* AUTH_PL_PARAM_TYPE_METHOD_* */
	thrpt_p		thrpt;
	auth_plugin_responce_cb responce_cb; /* responce cb. */
	void		*udata;
	uint8_t		buf_data[sizeof(void*)]; /* io_buf data... */
	/* io_buf data... */
} auth_pl_rad_cr_ctx_t, *auth_pl_rad_cr_ctx_p;


void	*auth_plugin_radius_cr_ctx_alloc_fn(auth_pl_p plugin, void *thrpt, void *udata);
void	auth_plugin_radius_cr_ctx_free_fn(void *cr_ctx);
void	auth_plugin_radius_ctx_free_fn(void *plugin_ctx);
int	auth_plugin_radius_challenge_fn(auth_pl_p plugin, void *plugin_ctx,
	    auth_pl_param_p params, size_t params_count);
void	auth_plugin_radius_auth_cb(radius_cli_query_p query,
	    rad_pkt_hdr_p pkt, int error, io_buf_p buf, void *arg);


int
auth_plugin_radius_init(auth_pl_p plugin, radius_cli_p rad_cli) {

	if (NULL == plugin || NULL == rad_cli)
		return (EINVAL);
	plugin->cr_ctx_alloc_fn = auth_plugin_radius_cr_ctx_alloc_fn;
	plugin->cr_ctx_free_fn = auth_plugin_radius_cr_ctx_free_fn;
	plugin->challenge_fn = auth_plugin_radius_challenge_fn;
	plugin->data = rad_cli;

	return (0);
}


void *
auth_plugin_radius_cr_ctx_alloc_fn(auth_pl_p plugin, void *thrpt,
    auth_plugin_responce_cb responce_cb, void *udata) {
	auth_pl_rad_cr_ctx_p rad_cr_ctx;

	if (NULL == plugin)
		return (NULL);
	rad_cr_ctx = zalloc((sizeof(auth_pl_rad_cr_ctx_t) + RADIUS_PKT_MAX_SIZE));
	if (NULL == rad_cr_ctx)
		return (NULL);
	rad_cr_ctx->plugin = plugin;
	io_buf_init(&rad_cr_ctx->buf, 0, rad_cr_ctx->buf_data, RADIUS_PKT_MAX_SIZE);
	rad_cr_ctx->method = (size_t)~0;
	rad_cr_ctx->thrpt = (thrpt_p)thrpt;
	rad_cr_ctx->responce_cb = responce_cb;
	rad_cr_ctx->udata = udata;

	return (rad_cr_ctx);
}

void
auth_plugin_radius_cr_ctx_free_fn(void *cr_ctx) {

	free(cr_ctx);
}

int
auth_plugin_radius_challenge_fn(auth_pl_p plugin, void *cr_ctx,
    size_t method, auth_pl_param_p params, size_t params_count) {
	int error;
	auth_pl_rad_cr_ctx_p rad_cr_ctx;
	auth_pl_param_p prm;
	io_buf_p buf;
	rad_pkt_hdr_p pkt;


	LOGD_EV("...");
	if (NULL == plugin || NULL == cr_ctx ||
	    AUTH_PL_METHOD_DIGEST_LAST < method)
		return (EINVAL);
	rad_cr_ctx = (auth_pl_rad_cr_ctx_p)cr_ctx;
	buf = &rad_cr_ctx->buf;
	pkt = (rad_pkt_hdr_p)buf->data;
	
	if ((size_t)~0 == rad_cr_ctx->method) { /* First call. */
		rad_cr_ctx->method = method;
	} else { /* Check auth method. */
		if (rad_cr_ctx->method != method) /* Auth method wrong!!! */
			return (EINVAL);
	}

	error = radius_pkt_init(pkt, buf->size, &buf->used,
	    RADIUS_PKT_TYPE_ACCESS_REQUEST, 0, NULL);
	if (0 != error) {
		LOG_ERR(error, "radius_pkt_init()");
		return (error);
	}

	switch (method) {
	case AUTH_PL_METHOD_BASIC:
		/* 1: login */
		prm = auth_plugin_param_find_ptr(params, params_count, AUTH_PL_PARAM_TYPE_LOGIN);
		if (NULL != prm) {
			error = radius_pkt_attr_add(pkt, buf->size, &buf->used,
			    RADIUS_ATTR_TYPE_USER_NAME,
			    prm->size, prm->data, NULL);
		}
		/* 2: password */
		prm = auth_plugin_param_find_ptr(params, params_count, AUTH_PL_PARAM_TYPE_PASSWORD);
		if (NULL != prm) {
			error = radius_pkt_attr_add(pkt, buf->size, &buf->used,
			    RADIUS_ATTR_TYPE_USER_PASSWORD,
			    prm->size, prm->data, NULL);
		}
		break;
	case AUTH_PL_METHOD_DIGEST:
		/* TODO! */
		return (EINVAL);
		break;
	}
	/* 6: 1 */
	error = radius_pkt_attr_add_uint32(pkt, buf->size, &buf->used,
	    RADIUS_ATTR_TYPE_SERVICE_TYPE, RADIUS_A_T_SERVICE_TYPE_LOGIN, NULL);
	/* 14 / 98 - auto select. */
	prm = auth_plugin_param_find_ptr(params, params_count, AUTH_PL_PARAM_TYPE_CLI_ADDR);
	if (NULL != prm) {
		error = radius_pkt_attr_add_addr(pkt, buf->size, &buf->used,
		    RADIUS_ATTR_TYPE_LOGIN_IP_HOST, RADIUS_ATTR_TYPE_LOGIN_IPV6_HOST,
		    prm->data, NULL);
	}
	/* 61: 5 */
	error = radius_pkt_attr_add_uint32(pkt, buf->size, &buf->used,
	    RADIUS_ATTR_TYPE_NAS_PORT_TYPE, RADIUS_A_T_NAS_PORT_TYPE_VIRTUAL, NULL);
	/* Implementation Specific attributes. */
	/* 224: URI path. */
	prm = auth_plugin_param_find_ptr(params, params_count, AUTH_PL_PARAM_TYPE_URI);
	if (NULL != prm) {
		error = radius_pkt_attr_add(pkt, buf->size, &buf->used,
		    224, prm->size, prm->data, NULL);
	}
	/* 225: "User-Agent". */
	prm = auth_plugin_param_find_ptr(params, params_count, AUTH_PL_PARAM_TYPE_USER_AGENT);
	if (NULL != prm) {
		error = radius_pkt_attr_add(pkt, buf->size, &buf->used,
		    225, prm->size, prm->data, NULL);
	}

	error = radius_client_query(((radius_cli_p)plugin->data),
	    rad_cr_ctx->thrpt,
	    RADIUS_CLIENT_QUERY_ID_AUTO, buf,
	    auth_plugin_radius_auth_cb, rad_cr_ctx, NULL);
	if (0 != error) {
		LOG_ERR(error, "radius_client_query()");
		return (error);
	}
	return (EINPROGRESS);
}

void
auth_plugin_radius_auth_cb(radius_cli_query_p query, rad_pkt_hdr_p pkt,
    int error, io_buf_p buf, void *arg) {
	auth_pl_rad_cr_ctx_p rad_cr_ctx;
	auth_pl_p plugin;
	size_t tm, params_count = 0;
	auth_pl_param_t params[8];
	uint8_t tmbuf[RADIUS_PKT_MAX_SIZE];

	LOGD_EV("...");
	if ((NULL == pkt && 0 == error) || NULL == arg)
		return;
	rad_cr_ctx = (auth_pl_rad_cr_ctx_p)arg;
	plugin = rad_cr_ctx->plugin;

	if (0 != error) { /* Error happen. */
		if (EAUTH == error ||
		    EINPROGRESS == error)
			error = EINVAL; /* Filter=replace specific error codes. */
		LOG_ERR(error, "auth_plugin_radius_auth_cb()");
		goto call_cb;
	}
	/* Normal responce. */
	switch (pkt->code) {
	case RADIUS_PKT_TYPE_ACCESS_ACCEPT:
		error = 0;
		LOGD_EV("RADIUS_PKT_TYPE_ACCESS_ACCEPT...");
		break;
	case RADIUS_PKT_TYPE_ACCESS_REJECT:
		error = EAUTH;
		LOGD_EV("RADIUS_PKT_TYPE_ACCESS_REJECT...");
		break;
	case RADIUS_PKT_TYPE_ACCESS_CHALLENGE:
		error = EINPROGRESS;
		LOGD_EV("RADIUS_PKT_TYPE_ACCESS_CHALLENGE...");

		switch (rad_cr_ctx->method) {
		case AUTH_PL_PARAM_TYPE_METHOD_BASIC:
			/* REPLY_MESSAGE. */
			if (0 == radius_pkt_attr_get_data_to_buf(pkt, 0, 0,
			    RADIUS_ATTR_TYPE_REPLY_MESSAGE, tmbuf, sizeof(tmbuf), &tm)) {
				params[params_count].type = AUTH_PL_PARAM_TYPE_REPLY_MESSAGE;
				params[params_count].size = tm;
				params[params_count].data = (void*)tmbuf;
				params_count ++;
			}
			break;
		case AUTH_PL_PARAM_TYPE_METHOD_DIGEST:
			/* TODO! */
			break;
		}
		break;
	}

call_cb:
	rad_cr_ctx->responce_cb(plugin, rad_cr_ctx, rad_cr_ctx->method,
	    error, rad_cr_ctx->udata, &params, params_count);

}

