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
/* X_MS_MediaReceiverRegistrar */


#ifndef __CORE_UPNP_SVC_X_MS_MEDIARECEIVERREGISTRAR_H__
#define __CORE_UPNP_SVC_X_MS_MEDIARECEIVERREGISTRAR_H__

#include "core_upnp_base.h"




int 		upnp_svc_ms_media_rcvr_reg_ctrl_cb(upnp_device_p dev, upnp_service_p svc,
		    http_srv_cli_p cli, int action,
		    uint8_t *req_data, size_t req_data_size);



static upnp_service_state_var_t upnp_svc_ms_media_rcvr_reg_st_var[] = {
	{ // 0
		.name = "A_ARG_TYPE_DeviceID",
		.dataType = "string",
	},{ // 1
		.name = "A_ARG_TYPE_Result",
		.dataType = "int",
	},{ // 2
		.name = "A_ARG_TYPE_RegistrationReqMsg",
		.dataType = "bin.base64",
	},{ // 3
		.name = "A_ARG_TYPE_RegistrationRespMsg",
		.dataType = "bin.base64",
	},{ // 4
		.name = "AuthorizationGrantedUpdateID",
		.dataType = "ui4",
	},{ // 5
		.name = "AuthorizationDeniedUpdateID",
		.dataType = "ui4",
	},{ // 6
		.name = "ValidationSucceededUpdateID",
		.dataType = "ui4",
	},{ // 7
		.name = "ValidationRevokedUpdateID",
		.dataType = "ui4",
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
static upnp_service_action_arg_t upnp_svc_ms_media_rcvr_reg_action_IsAuthorized_args[] = {
	{
		.name = "DeviceID",
		.relatedStateVariable = &upnp_svc_ms_media_rcvr_reg_st_var[0]
	},{
		.name = "Result",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_ms_media_rcvr_reg_st_var[1]
	},{
		.name = NULL,
		.direction = 0,
		.retval = 0,
		.relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_ms_media_rcvr_reg_action_RegisterDevice_args[] = {
	{
		.name = "RegistrationReqMsg",
		.relatedStateVariable = &upnp_svc_ms_media_rcvr_reg_st_var[2]
	},{
		.name = "RegistrationRespMsg",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_ms_media_rcvr_reg_st_var[3]
	},{
		.name = NULL,
		.direction = 0,
		.retval = 0,
		.relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_ms_media_rcvr_reg_action_IsValidated_args[] = {
	{
		.name = "DeviceID",
		.relatedStateVariable = &upnp_svc_ms_media_rcvr_reg_st_var[0]
	},{
		.name = "Result",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_ms_media_rcvr_reg_st_var[1]
	},{
		.name = NULL,
		.direction = 0,
		.retval = 0,
		.relatedStateVariable = NULL
	}
};
static upnp_service_action_t upnp_svc_ms_media_rcvr_reg_actions[] = {
	{
		.name = "IsAuthorized",
		.name_size = 12,
		.argumentList = upnp_svc_ms_media_rcvr_reg_action_IsAuthorized_args
	},{
		.name = "RegisterDevice",
		.name_size = 14,
		.argumentList = upnp_svc_ms_media_rcvr_reg_action_RegisterDevice_args
	},{
		.name = "IsValidated",
		.name_size = 11,
		.argumentList = upnp_svc_ms_media_rcvr_reg_action_IsValidated_args
	},{
		.name = NULL,
		.name_size = 0,
		.argumentList = NULL
	}
};

static upnp_service_t upnp_svc_ms_media_rcvr = {
	.domain_name = "microsoft.com", // This violate UPnP specification
	.type = "X_MS_MediaReceiverRegistrar",
	.ver = 1,
	.actionList = upnp_svc_ms_media_rcvr_reg_actions,
	.serviceStateTable = upnp_svc_ms_media_rcvr_reg_st_var,
	.ctrl_cb_func = upnp_svc_ms_media_rcvr_reg_ctrl_cb,
	.ev_cb_func = NULL
};





#endif // __CORE_UPNP_SVC_X_MS_MEDIARECEIVERREGISTRAR_H__
