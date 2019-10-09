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

/*
 * HTTP server -> HTTP server auth plugin -> auth plugin -> auth plugin XXX
 * Hook received data, translate it to auth plugin params, call auth plugin...
 * ... receive auth plugin responce, decode data (params) and send to client
 * or send access accept/reject responce.
 */

#ifndef __CORE_HTTP_SERVER_AUTH_H__
#define __CORE_HTTP_SERVER_AUTH_H__

#include <sys/types.h>


#include "macro_helpers.h"
#include "core_http_srv.h"
#include "core_auth_plugin.h"


typedef struct http_srv_auth_plugin_s {
	auth_pl_p 	plugin;
	uint8_t		*uri_arg_name_login;
	size_t		uri_arg_name_login_size;
	uint8_t		*uri_arg_name_password;
	size_t		uri_arg_name_password_size;
	uint32_t	allowed_types;	/* HTTP_SRV_AUTH_TYPE_F_* */
	uint32_t	flags;		/* Flags: HTTP_SRV_AUTH_PL_F_*. */
	void		*data;		/* Plugin associated data (radius_cli_p for radius). On create passed to plugin_init(). */
	size_t		data_size;	/* If == 0 then data point outside. On create passed to plugin_init(). */
	void		*settings;	/* Plugin associated settings (http_srv_auth_set_rad_p for radius). */
	size_t		settings_size;	/* If == 0 then settings point outside. Needed only on create. */
} http_srv_auth_pl_t, *http_srv_auth_pl_p;
#define HTTP_SRV_AUTH_TYPE_F_UNKNOWN	0 /* none. */
#define HTTP_SRV_AUTH_TYPE_F_BASIC	(((uint32_t)1) << 1)
#define HTTP_SRV_AUTH_TYPE_F_DIGEST	(((uint32_t)1) << 2)
#define HTTP_SRV_AUTH_TYPE_F_AUTHORIZATION (HTTP_SRV_AUTH_TYPE_F_BASIC | HTTP_SRV_AUTH_TYPE_F_DIGEST)
#define HTTP_SRV_AUTH_TYPE_F_URI_ARGS	(((uint32_t)1) << 3) /* Like basic, but login and password in uri args. */

#define HTTP_SRV_AUTH_PL_F_REALM_INCLUDE_URL_ARGS	(((uint32_t)1) << 0) /* Try do cheks even login and password not found in request. */
#define HTTP_SRV_AUTH_PL_F_TRY_WO_LOGIN_PWD		(((uint32_t)1) << 1) /* Try do cheks even login and password not found in request. */



int	http_srv_auth_start(http_srv_cli_p cli, auth_pl_p plugin,
	    http_srv_req_p req);
/* Return values: see http_srv_on_req_rcv_cb */




#endif // __CORE_HTTP_SERVER_AUTH_H__
