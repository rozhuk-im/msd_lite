/*-
 * Copyright (c) 2013 Rozhuk Ivan <rozhuk.im@gmail.com>
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
/* ConnectionManager */


#ifndef __CORE_UPNP_SVC_CONNECTIONMANAGER_H__
#define __CORE_UPNP_SVC_CONNECTIONMANAGER_H__

#include "core_upnp_base.h"



int 		upnp_svc_conn_mngr_ctrl_cb(upnp_device_p dev, upnp_service_p svc,
		    http_srv_cli_p cli, int action,
		    uint8_t *req_data, size_t req_data_size);


static const char *upnp_svc_conn_mngr_ConnectionStatus_allowedValueList[] = {
	"OK",
	"ContentFormatMismatch",
	"InsufficientBandwidth",
	"UnreliableChannel",
	"Unknown",
	NULL
};
static const char *upnp_svc_conn_mngr_Direction_allowedValueList[] = {
	"Input",
	"Output",
	NULL
};
static upnp_service_state_var_t upnp_svc_conn_mngr_st_var[] = {
	{ // 0
		.sendEvents = 1,
		.name = "SourceProtocolInfo",
		.dataType = "string",
	},{ // 1
		.sendEvents = 1,
		.name = "SinkProtocolInfo",
		.dataType = "string",
	},{ // 2
		.sendEvents = 1,
		.name = "CurrentConnectionIDs",
		.dataType = "string",
	},{ // 3
		.name = "A_ARG_TYPE_ConnectionStatus",
		.dataType = "string",
		.allowedValueList = upnp_svc_conn_mngr_ConnectionStatus_allowedValueList,
	},{ // 4
		.name = "A_ARG_TYPE_ConnectionManager",
		.dataType = "string",
	},{ // 5
		.name = "A_ARG_TYPE_Direction",
		.dataType = "string",
		.allowedValueList = upnp_svc_conn_mngr_Direction_allowedValueList,
	},{ // 6
		.name = "A_ARG_TYPE_ProtocolInfo",
		.dataType = "string",
	},{ // 7
		.name = "A_ARG_TYPE_ConnectionID",
		.dataType = "i4",
	},{ // 8
		.name = "A_ARG_TYPE_AVTransportID",
		.dataType = "i4",
	},{ // 9
		.name = "A_ARG_TYPE_RcsID",
		.dataType = "i4",
	},{
		.sendEvents = 0,
		.multicast = 0,
		.name = NULL,
		.dataType_type = NULL,
		.dataType = NULL,
		.defaultValue = NULL,
		.allowedValueList = NULL,
		.allowedValueRange_min = NULL,
		.allowedValueRange_max = NULL,
		.allowedValueRange_step = NULL
	}
};
#define CONN_MNGR_ST_VAR_SourceProtocolInfo		0
#define CONN_MNGR_ST_VAR_SinkProtocolInfo		1
#define CONN_MNGR_ST_VAR_CurrentConnectionIDs		2
#define CONN_MNGR_ST_VAR_A_ARG_TYPE_ConnectionStatus	3
#define CONN_MNGR_ST_VAR_A_ARG_TYPE_ConnectionManager	4
#define CONN_MNGR_ST_VAR_A_ARG_TYPE_Direction		5
#define CONN_MNGR_ST_VAR_A_ARG_TYPE_ProtocolInfo	6
#define CONN_MNGR_ST_VAR_A_ARG_TYPE_ConnectionID	7
#define CONN_MNGR_ST_VAR_A_ARG_TYPE_AVTransportID	8
#define CONN_MNGR_ST_VAR_A_ARG_TYPE_RcsID		9


static upnp_service_action_arg_t upnp_svc_conn_mngr_action_GetProtocolInfo_args[] = {
	{
		.name = "Source",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_conn_mngr_st_var[CONN_MNGR_ST_VAR_SourceProtocolInfo]
	},{
		.name = "Sink",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_conn_mngr_st_var[CONN_MNGR_ST_VAR_SinkProtocolInfo]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_conn_mngr_action_PrepareForConnection_args[] = {
	{
		.name = "RemoteProtocolInfo",
		.relatedStateVariable = &upnp_svc_conn_mngr_st_var[CONN_MNGR_ST_VAR_A_ARG_TYPE_ProtocolInfo]
	},{
		.name = "PeerConnectionManager",
		.relatedStateVariable = &upnp_svc_conn_mngr_st_var[CONN_MNGR_ST_VAR_A_ARG_TYPE_ConnectionManager]
	},{
		.name = "PeerConnectionID",
		.relatedStateVariable = &upnp_svc_conn_mngr_st_var[CONN_MNGR_ST_VAR_A_ARG_TYPE_ConnectionID]
	},{
		.name = "Direction",
		.relatedStateVariable = &upnp_svc_conn_mngr_st_var[CONN_MNGR_ST_VAR_A_ARG_TYPE_Direction]
	},{
		.name = "ConnectionID",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_conn_mngr_st_var[CONN_MNGR_ST_VAR_A_ARG_TYPE_ConnectionID]
	},{
		.name = "AVTransportID",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_conn_mngr_st_var[CONN_MNGR_ST_VAR_A_ARG_TYPE_AVTransportID]
	},{
		.name = "RcsID",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_conn_mngr_st_var[CONN_MNGR_ST_VAR_A_ARG_TYPE_RcsID]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_conn_mngr_action_ConnectionComplete_args[] = {
	{
		.name = "ConnectionID",
		.relatedStateVariable = &upnp_svc_conn_mngr_st_var[CONN_MNGR_ST_VAR_A_ARG_TYPE_ConnectionID]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_conn_mngr_action_GetCurrentConnectionIDs_args[] = {
	{
		.name = "ConnectionIDs",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_conn_mngr_st_var[CONN_MNGR_ST_VAR_CurrentConnectionIDs]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_conn_mngr_action_GetCurrentConnectionInfo_args[] = {
	{
		.name = "ConnectionID",
		.relatedStateVariable = &upnp_svc_conn_mngr_st_var[CONN_MNGR_ST_VAR_A_ARG_TYPE_ConnectionID]
	},{
		.name = "RcsID",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_conn_mngr_st_var[CONN_MNGR_ST_VAR_A_ARG_TYPE_RcsID]
	},{
		.name = "AVTransportID",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_conn_mngr_st_var[CONN_MNGR_ST_VAR_A_ARG_TYPE_AVTransportID]
	},{
		.name = "ProtocolInfo",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_conn_mngr_st_var[CONN_MNGR_ST_VAR_A_ARG_TYPE_ProtocolInfo]
	},{
		.name = "PeerConnectionManager",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_conn_mngr_st_var[CONN_MNGR_ST_VAR_A_ARG_TYPE_ConnectionManager]
	},{
		.name = "PeerConnectionID",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_conn_mngr_st_var[CONN_MNGR_ST_VAR_A_ARG_TYPE_ConnectionID]
	},{
		.name = "Direction",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_conn_mngr_st_var[CONN_MNGR_ST_VAR_A_ARG_TYPE_Direction]
	},{
		.name = "Status",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_conn_mngr_st_var[CONN_MNGR_ST_VAR_A_ARG_TYPE_ConnectionStatus]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};


static upnp_service_action_t upnp_svc_conn_mngr_actions[] = {
	{
		.name = "GetProtocolInfo",
		.name_size = 15,
		.argumentList = upnp_svc_conn_mngr_action_GetProtocolInfo_args
	},{
		.name = "PrepareForConnection",
		.name_size = 20,
		.argumentList = upnp_svc_conn_mngr_action_PrepareForConnection_args
	},{
		.name = "ConnectionComplete",
		.name_size = 18,
		.argumentList = upnp_svc_conn_mngr_action_ConnectionComplete_args
	},{
		.name = "GetCurrentConnectionIDs",
		.name_size = 23,
		.argumentList = upnp_svc_conn_mngr_action_GetCurrentConnectionIDs_args
	},{
		.name = "GetCurrentConnectionInfo",
		.name_size = 24,
		.argumentList = upnp_svc_conn_mngr_action_GetCurrentConnectionInfo_args
	},{
		.name = NULL, .name_size = 0, .argumentList = NULL
	}
};

#define CONN_MNGR_ACTION_GetProtocolInfo		0
#define CONN_MNGR_ACTION_PrepareForConnection		1
#define CONN_MNGR_ACTION_ConnectionComplete		2
#define CONN_MNGR_ACTION_GetCurrentConnectionIDs	3
#define CONN_MNGR_ACTION_GetCurrentConnectionInfo	4



static upnp_service_t upnp_svc_conn_mngr = {
	.domain_name = "schemas-upnp-org",
	.type = "ConnectionManager",
	.ver = 2,
	.actionList = upnp_svc_conn_mngr_actions,
	.serviceStateTable = upnp_svc_conn_mngr_st_var,
	.ctrl_cb_func = upnp_svc_conn_mngr_ctrl_cb,
	.ev_cb_func = NULL
};





#endif // __CORE_UPNP_SVC_CONNECTIONMANAGER_H__
