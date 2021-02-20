/*-
 * Copyright (c) 2013 - 2016 Rozhuk Ivan <rozhuk.im@gmail.com>
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
#include <stdio.h> /* for snprintf, fprintf */
#include <errno.h>

#include "macro_helpers.h"
#include "core_io_buf.h"
#include "core_upnp_base.h"
#include "core_upnp.h"
#include "core_upnp_svc_conn_mngr.h"




int
upnp_svc_conn_mngr_ctrl_cb(upnp_device_p dev __unused, upnp_service_p svc __unused,
    http_srv_cli_p cli, int action,
    uint8_t *req_data __unused, size_t req_data_size __unused) {

	switch (action) {
	case CONN_MNGR_ACTION_GetProtocolInfo: /* GetProtocolInfo */
		IO_BUF_PRINTF(cli->buf,
		    "			<Source>");
		/*for(int i = 0; protocol_list[i]; i ++) {
			if (i) fprintf(stderr, ",");
			fprintf(stderr, "%s*", protocol_list[i]);
		}//*/
		IO_BUF_PRINTF(cli->buf,
		    "</Source>\n"
		    "			<Sink></Sink>\n");
		return (200);
		break;
	case CONN_MNGR_ACTION_GetCurrentConnectionIDs: /* GetCurrentConnectionIDs */
		IO_BUF_PRINTF(cli->buf,
		    "			<ConnectionIDs></ConnectionIDs>\n");
		return (200);
		break;
	case CONN_MNGR_ACTION_GetCurrentConnectionInfo: /* GetCurrentConnectionInfo */
		IO_BUF_PRINTF(cli->buf,
		    "			<ConnectionID>0</ConnectionID>\n"
		    "			<RcsID>-1</RcsID>\n"
		    "			<AVTransportID>-1</AVTransportID>\n"
		    "			<ProtocolInfo></ProtocolInfo>\n"
		    "			<PeerConnectionManager></PeerConnectionManager>\n"
		    "			<PeerConnectionID>-1</PeerConnectionID>\n"
		    "			<Direction>Output</Direction>\n"
		    "			<Status>OK</Status>\n");
		return (200);
		break;
	//case 1: /* PrepareForConnection */
	//case 2: /* ConnectionComplete */
	}

	return (602);
}

