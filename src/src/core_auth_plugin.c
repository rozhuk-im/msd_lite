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

#include "core_auth_plugin.h"
#ifdef HTTP_SRV_XML_CONFIG
#include "core_helpers.h"
#include "xml.h"
#endif




int
auth_plugin_create(auth_pl_p s,
    auth_pl_p *plugin_ret) {
	int error;
	auth_pl_p plugin;
	uint8_t *ptm;

	if (NULL == s || NULL == s->on_req_rcv || NULL == s->ctx_alloc_fn ||
	    0 == ((HTTP_SRV_AUTH_TYPE_F_AUTHORIZATION | HTTP_SRV_AUTH_TYPE_F_URI_ARGS) & s->allowed_types) ||
	    NULL == plugin_ret)
		return (EINVAL);
	plugin = zalloc((sizeof(auth_pl_t) + uri_arg_name_login_size +
	    uri_arg_name_password_size + ((NULL == s->plugin_init) ? data_size : 0) +
	    settings_size + 64));
	if (NULL == plugin)
		return (ENOMEM);
	ptm = (uint8_t*)(plugin + 1);
	plugin->on_req_rcv = s->on_req_rcv;
	plugin->plugin_init = s->plugin_init;
	plugin->plugin_destroy = s->plugin_destroy;
	plugin->ctx_alloc_fn = s->ctx_alloc_fn;
	if (NULL != s->uri_arg_name_login && 0 != s->uri_arg_name_login_size) {
		plugin->uri_arg_name_login = ptm;
		plugin->uri_arg_name_login_size = s->uri_arg_name_login_size;
		memcpy(plugin->uri_arg_name_login, s->uri_arg_name_login,
		    s->uri_arg_name_login_size);
		ptm += (s->uri_arg_name_login_size + 1);
	}
	if (NULL != s->uri_arg_name_password && 0 != s->uri_arg_name_password_size) {
		plugin->uri_arg_name_password = ptm;
		plugin->uri_arg_name_password_size = s->uri_arg_name_password_size;
		memcpy(plugin->uri_arg_name_password, s->uri_arg_name_password,
		    s->uri_arg_name_password_size);
		ptm += (s->uri_arg_name_password_size + 1);
	}
	plugin->allowed_types = s->allowed_types;
	plugin->flags = s->flags;
	if (NULL == s->plugin_init) {
		plugin->data = s->data;
		plugin->data_size = s->data_size;
		if (NULL != s->data && 0 != s->data_size) {
			ptm = ALIGNEX_PTR(ptm, sizeof(void*));
			plugin->data = ptm;
			memcpy(plugin->data, s->data, s->data_size);
			ptm += (s->data_size + 1);
		}
	} else {
		error = s->plugin_init(plugin, s->data, s->data_size);
		if (0 != error) {
			free(plugin);
			return (error);
		}
	}
	plugin->settings = s->settings;
	plugin->settings_size = s->settings_size;
	if (NULL != s->settings && 0 != s->settings_size) {
		ptm = ALIGNEX_PTR(ptm, sizeof(void*));
		plugin->settings = ptm;
		memcpy(plugin->settings, s->settings, s->settings_size);
		ptm += (s->settings_size + 1);
	}
	
	return (0);
}

void
auth_plugin_destroy(auth_pl_p plugin) {

	if (NULL == plugin)
		return;
	if (NULL != plugin->plugin_destroy)
		plugin->plugin_destroy(plugin);
	free(plugin);
}


