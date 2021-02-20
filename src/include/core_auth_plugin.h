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

 /* Universal auth api, like PAM.
  * NO I/O here!
  * challenge-responce model:
  * client fill params and send challenge */


#ifndef __CORE_AUTH_PLUGIN_H__
#define __CORE_AUTH_PLUGIN_H__

#include <sys/types.h>
#include <errno.h>

#include "macro_helpers.h"




typedef struct auth_plugin_s	*auth_pl_p;

/* Parameters to pass/get to/from auth func. */
typedef struct auth_plugin_auth_param_s {
	size_t	type; /* AUTH_PL_PARAM_TYPE_* */
	size_t	size;
	void	*data;
} auth_pl_param_t, *auth_pl_param_p;
#define AUTH_PL_PARAM_TYPE_RESPONCE	1 /* responce */
#define AUTH_PL_PARAM_TYPE_RESPONCE_ACCEPT	0
#define AUTH_PL_PARAM_TYPE_RESPONCE_REJECT	1
#define AUTH_PL_PARAM_TYPE_RESPONCE_CHALLENGE	2
#define AUTH_PL_PARAM_TYPE_RESPONCE_ERROR	3
#define AUTH_PL_PARAM_TYPE_REPLY_MESSAGE 8 /* responce: realm for basic */

#define AUTH_PL_PARAM_TYPE_LOGIN	255
#define AUTH_PL_PARAM_TYPE_PASSWORD	256
#define AUTH_PL_PARAM_TYPE_CLI_ADDR	512
#define AUTH_PL_PARAM_TYPE_URI		1024
#define AUTH_PL_PARAM_TYPE_USER_AGENT	1025



#define AUTH_PL_METHOD_BASIC		0
#define AUTH_PL_METHOD_DIGEST		1
#define AUTH_PL_METHOD_DIGEST_LAST	AUTH_PL_METHOD_DIGEST


typedef void (*auth_plugin_responce_cb)(auth_pl_p plugin, void *cr_ctx,
	    size_t method, int error, void *udata,
	    auth_pl_param_p params, size_t params_count);
typedef void *(*auth_plugin_cr_ctx_alloc_fn)(auth_pl_p plugin, void *thrpt, auth_plugin_responce_cb responce_cb, void *udata); /* Allocate challenge-responce ctx. */
typedef void (*auth_plugin_cr_ctx_free_fn)(void *cr_ctx); /* Free challenge-responce ctx. */
typedef int (*auth_plugin_challenge_fn)(auth_pl_p plugin, void *cr_ctx,
	    size_t method, auth_pl_param_p params, size_t params_count);
/* Return values:
 * 0 - auth ok
 * EINPROGRESS - will call back later (or allready), responce_cb
 * EAUTH - bad login/password // EACCES
 * other err codes...
 */


typedef struct auth_plugin_s {
	auth_plugin_cr_ctx_alloc_fn	cr_ctx_alloc_fn;/* challenge-responce data initialization/allocation. */
	auth_plugin_cr_ctx_free_fn	cr_ctx_free_fn;	/* challenge-responce data free. */
	auth_plugin_challenge_fn	challenge_fn;	/* challenge. */
	void				*data;		/* Plugin internal data. */
} auth_pl_t;



static inline size_t
auth_plugin_param_find(auth_pl_param_p params, size_t params_count,
    size_t type, size_t start) {
	size_t i;

	if (NULL == params || start >= params_count)
		return ((size_t)~0);
	for (i = start; i < params_count; i ++) {
		if (type == params[i].type)
			return (i);
	}
	return ((size_t)~0);
}

static inline auth_pl_param_p
auth_plugin_param_find_ptr(auth_pl_param_p params, size_t params_count,
    size_t type, size_t start) {
	size_t i;

	if (NULL == params || start >= params_count)
		return ((size_t)~0);
	for (i = start; i < params_count; i ++) {
		if (type == params[i].type)
			return (&params[i]);
	}
	return (NULL);
}


#endif // __CORE_AUTH_PLUGIN_H__
