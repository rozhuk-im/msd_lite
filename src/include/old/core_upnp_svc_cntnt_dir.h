/*-
 * Copyright (c) 2013 Rozhuk Ivan <rozhuk.im@gmail.com>
 * All rights reserved.
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
/* ContentDirectory */


#ifndef __CORE_UPNP_SVC_CONTENTDIRECTORY_H__
#define __CORE_UPNP_SVC_CONTENTDIRECTORY_H__

#include "core_upnp_base.h"



int 		upnp_svc_cntnt_dir_ctrl_cb(upnp_device_p dev, upnp_service_p svc,
		    http_srv_cli_p cli, int action,
		    uint8_t *req_data, size_t req_data_size);


static const char *upnp_svc_cntnt_dir_BrowseFlag_allowedValueList[] = {
	"BrowseMetadata",
	"BrowseDirectChildren",
	NULL
};
static const char *upnp_svc_cntnt_dir_TransferStatus_allowedValueList[] = {
	"COMPLETED",
	"ERROR",
	"IN_PROGRESS",
	"STOPPED",
	NULL
};


static upnp_service_state_var_t upnp_svc_cntnt_dir_st_var[] = {
	{ // 0
		.name = "SearchCapabilities",
		.dataType = "string",
	},{ // 1
		.name = "SortCapabilities",
		.dataType = "string",
	},{ // 2
		.name = "SortExtensionCapabilities",
		.dataType = "string",
	},{ // 3
		.sendEvents = 1,
		.name = "SystemUpdateID",
		.dataType = "ui4",
	},{ // 4
		.sendEvents = 1,
		.name = "ContainerUpdateIDs",
		.dataType = "string",
	},{ // 5
		.name = "ServiceResetToken",
		.dataType = "string",
	},{ // 6
		.sendEvents = 1,
		.name = "LastChange",
		.dataType = "string",
	},{ // 7
		.sendEvents = 1,
		.name = "TransferIDs",
		.dataType = "string",
	},{ // 8
		.name = "FeatureList",
		.dataType = "string",
	},{ // 9
		.name = "A_ARG_TYPE_ObjectID",
		.dataType = "string",
	},{ // 10
		.name = "A_ARG_TYPE_Result",
		.dataType = "string",
	},{ // 11
		.name = "A_ARG_TYPE_SearchCriteria",
		.dataType = "string",
	},{ // 12
		.name = "A_ARG_TYPE_BrowseFlag",
		.dataType = "string",
		.allowedValueList = upnp_svc_cntnt_dir_BrowseFlag_allowedValueList,
	},{ // 13
		.name = "A_ARG_TYPE_Filter",
		.dataType = "string",
	},{ // 14
		.name = "A_ARG_TYPE_SortCriteria",
		.dataType = "string",
	},{ // 15
		.name = "A_ARG_TYPE_Index",
		.dataType = "ui4",
	},{ // 16
		.name = "A_ARG_TYPE_Count",
		.dataType = "ui4",
	},{ // 17
		.name = "A_ARG_TYPE_UpdateID",
		.dataType = "ui4",
	},{ // 18
		.name = "A_ARG_TYPE_TransferID",
		.dataType = "ui4",
	},{ // 19
		.name = "A_ARG_TYPE_TransferStatus",
		.dataType = "string",
		.allowedValueList = upnp_svc_cntnt_dir_TransferStatus_allowedValueList,
	},{ // 20
		.name = "A_ARG_TYPE_TransferLength",
		.dataType = "string",
	},{ // 21
		.name = "A_ARG_TYPE_TransferTotal",
		.dataType = "string",
	},{ // 22
		.name = "A_ARG_TYPE_TagValueList",
		.dataType = "string",
	},{ // 23
		.name = "A_ARG_TYPE_URI",
		.dataType = "uri",
	},{ // 24
		.name = "A_ARG_TYPE_CDSView",
		.dataType = "ui4",
	},{ // 25
		.name = "A_ARG_TYPE_QueryRequest",
		.dataType = "string",
	},{ // 26
		.name = "A_ARG_TYPE_QueryResult",
		.dataType = "string",
	},{ // 27
		.name = "A_ARG_TYPE_FFQCapabilities",
		.dataType = "string",
	},{ // 28
		.name = "A_ARG_TYPE_Featurelist",
		.dataType = "string",
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

#define CNTNT_DIR_ST_VAR_SearchCapabilities		0
#define CNTNT_DIR_ST_VAR_SortCapabilities		1
#define CNTNT_DIR_ST_VAR_SortExtensionCapabilities	2
#define CNTNT_DIR_ST_VAR_SystemUpdateID			3
#define CNTNT_DIR_ST_VAR_ContainerUpdateIDs		4
#define CNTNT_DIR_ST_VAR_ServiceResetToken		5
#define CNTNT_DIR_ST_VAR_LastChange			6
#define CNTNT_DIR_ST_VAR_TransferIDs			7
#define CNTNT_DIR_ST_VAR_FeatureList			8
#define CNTNT_DIR_ST_VAR_A_ARG_TYPE_ObjectID		9
#define CNTNT_DIR_ST_VAR_A_ARG_TYPE_Result		10
#define CNTNT_DIR_ST_VAR_A_ARG_TYPE_SearchCriteria	11
#define CNTNT_DIR_ST_VAR_A_ARG_TYPE_BrowseFlag		12
#define CNTNT_DIR_ST_VAR_A_ARG_TYPE_Filter		13
#define CNTNT_DIR_ST_VAR_A_ARG_TYPE_SortCriteria	14
#define CNTNT_DIR_ST_VAR_A_ARG_TYPE_Index		15
#define CNTNT_DIR_ST_VAR_A_ARG_TYPE_Count		16
#define CNTNT_DIR_ST_VAR_A_ARG_TYPE_UpdateID		17
#define CNTNT_DIR_ST_VAR_A_ARG_TYPE_TransferID		18
#define CNTNT_DIR_ST_VAR_A_ARG_TYPE_TransferStatus	19
#define CNTNT_DIR_ST_VAR_A_ARG_TYPE_TransferLength	20
#define CNTNT_DIR_ST_VAR_A_ARG_TYPE_TransferTotal	21
#define CNTNT_DIR_ST_VAR_A_ARG_TYPE_TagValueList	22
#define CNTNT_DIR_ST_VAR_A_ARG_TYPE_URI			23
#define CNTNT_DIR_ST_VAR_A_ARG_TYPE_CDSView		24
#define CNTNT_DIR_ST_VAR_A_ARG_TYPE_QueryRequest	25
#define CNTNT_DIR_ST_VAR_A_ARG_TYPE_QueryResult		26
#define CNTNT_DIR_ST_VAR_A_ARG_TYPE_FFQCapabilities	27
#define CNTNT_DIR_ST_VAR_A_ARG_TYPE_Featurelist		28




static upnp_service_action_arg_t upnp_svc_cntnt_dir_action_GetSearchCapabilities_args[] = {
	{
		.name = "SearchCaps",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_SearchCapabilities]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_cntnt_dir_action_GetSortCapabilities_args[] = {
	{
		.name = "SortCaps",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_SortCapabilities]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_cntnt_dir_action_GetSortExtensionCapabilities_args[] = {
	{
		.name = "SortExtensionCaps",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_SortExtensionCapabilities]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_cntnt_dir_action_GetFeatureList_args[] = {
	{
		.name = "FeatureList",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_FeatureList]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_cntnt_dir_action_GetSystemUpdateID_args[] = {
	{
		.name = "Id",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_SystemUpdateID]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_cntnt_dir_action_GetServiceResetToken_args[] = {
	{
		.name = "ResetToken",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_ServiceResetToken]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_cntnt_dir_action_Browse_args[] = {
	{
		.name = "ObjectID",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_ObjectID]
	},{
		.name = "BrowseFlag",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_BrowseFlag]
	},{
		.name = "Filter",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_Filter]
	},{
		.name = "StartingIndex",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_Index]
	},{
		.name = "RequestedCount",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_Count]
	},{
		.name = "SortCriteria",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_SortCriteria]
	},{
		.name = "Result",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_Result]
	},{
		.name = "NumberReturned",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_Count]
	},{
		.name = "TotalMatches",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_Count]
	},{
		.name = "UpdateID",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_UpdateID]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_cntnt_dir_action_Search_args[] = {
	{
		.name = "ContainerID",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_ObjectID]
	},{
		.name = "SearchCriteria",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_SearchCriteria]
	},{
		.name = "Filter",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_Filter]
	},{
		.name = "StartingIndex",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_Index]
	},{
		.name = "RequestedCount",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_Count]
	},{
		.name = "SortCriteria",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_SortCriteria]
	},{
		.name = "Result",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_Result]
	},{
		.name = "NumberReturned",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_Count]
	},{
		.name = "TotalMatches",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_Count]
	},{
		.name = "UpdateID",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_UpdateID]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_cntnt_dir_action_CreateObject_args[] = {
	{
		.name = "ContainerID",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_ObjectID]
	},{
		.name = "Elements",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_Result]
	},{
		.name = "ObjectID",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_ObjectID]
	},{
		.name = "Result",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_Result]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_cntnt_dir_action_DestroyObject_args[] = {
	{
		.name = "ObjectID",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_ObjectID]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_cntnt_dir_action_UpdateObject_args[] = {
	{
		.name = "ObjectID",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_ObjectID]
	},{
		.name = "CurrentTagValue",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_TagValueList]
	},{
		.name = "NewTagValue",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_TagValueList]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_cntnt_dir_action_MoveObject_args[] = {
	{
		.name = "ObjectID",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_ObjectID]
	},{
		.name = "NewParentID",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_ObjectID]
	},{
		.name = "NewObjectID",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_ObjectID]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_cntnt_dir_action_ImportResource_args[] = {
	{
		.name = "SourceURI",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_URI]
	},{
		.name = "DestinationURI",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_URI]
	},{
		.name = "TransferID",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_TransferID]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_cntnt_dir_action_ExportResource_args[] = {
	{
		.name = "SourceURI",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_URI]
	},{
		.name = "DestinationURI",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_URI]
	},{
		.name = "TransferID",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_TransferID]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_cntnt_dir_action_StopTransferResource_args[] = {
	{
		.name = "TransferID",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_TransferID]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_cntnt_dir_action_DeleteResource_args[] = {
	{
		.name = "ResourceURI",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_URI]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_cntnt_dir_action_GetTransferProgress_args[] = {
	{
		.name = "TransferID",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_TransferID]
	},{
		.name = "TransferStatus",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_TransferStatus]
	},{
		.name = "TransferLength",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_TransferLength]
	},{
		.name = "TransferTotal",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_TransferTotal]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_cntnt_dir_action_CreateReference_args[] = {
	{
		.name = "ContainerID",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_ObjectID]
	},{
		.name = "ObjectID",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_ObjectID]
	},{
		.name = "NewID",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_ObjectID]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_cntnt_dir_action_FreeFormQuery_args[] = {
	{
		.name = "ContainerID",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_ObjectID]
	},{
		.name = "CDSView",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_CDSView]
	},{
		.name = "QueryRequest",
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_QueryRequest]
	},{
		.name = "QueryResult",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_QueryResult]
	},{
		.name = "UpdateID",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_UpdateID]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_cntnt_dir_action_GetFreeFormQueryCapabilities_args[] = {
	{
		.name = "FFQCapabilities",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_FFQCapabilities]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};
static upnp_service_action_arg_t upnp_svc_cntnt_dir_action_X_GetFeatureList_args[] = {
	{
		.name = "FeatureList",
		.direction = 1,
		.relatedStateVariable = &upnp_svc_cntnt_dir_st_var[CNTNT_DIR_ST_VAR_A_ARG_TYPE_Featurelist]
	},{
		.name = NULL, .direction = 0, .retval = 0, .relatedStateVariable = NULL
	}
};


static upnp_service_action_t upnp_svc_cntnt_dir_actions[] = {
	{
		.name = "GetSearchCapabilities", /*  */
		.name_size = 21,
		.argumentList = upnp_svc_cntnt_dir_action_GetSearchCapabilities_args
	},{
		.name = "GetSortCapabilities", /*  */
		.name_size = 19,
		.argumentList = upnp_svc_cntnt_dir_action_GetSortCapabilities_args
	},{
		.name = "GetSortExtensionCapabilities", /*  */
		.name_size = 28,
		.argumentList = upnp_svc_cntnt_dir_action_GetSortExtensionCapabilities_args
	},{
		.name = "GetFeatureList", /*  */
		.name_size = 14,
		.argumentList = upnp_svc_cntnt_dir_action_GetFeatureList_args
	},{
		.name = "GetSystemUpdateID", /*  */
		.name_size = 17,
		.argumentList = upnp_svc_cntnt_dir_action_GetSystemUpdateID_args
	},{
		.name = "GetServiceResetToken", /*  */
		.name_size = 20,
		.argumentList = upnp_svc_cntnt_dir_action_GetServiceResetToken_args
	},{
		.name = "Browse", /*  */
		.name_size = 6,
		.argumentList = upnp_svc_cntnt_dir_action_Browse_args
	},{
		.name = "Search", /*  */
		.name_size = 6,
		.argumentList = upnp_svc_cntnt_dir_action_Search_args
	},{
		.name = "CreateObject", /*  */
		.name_size = 12,
		.argumentList = upnp_svc_cntnt_dir_action_CreateObject_args
	},{
		.name = "DestroyObject", /*  */
		.name_size = 13,
		.argumentList = upnp_svc_cntnt_dir_action_DestroyObject_args
	},{
		.name = "UpdateObject", /*  */
		.name_size = 12,
		.argumentList = upnp_svc_cntnt_dir_action_UpdateObject_args
	},{
		.name = "MoveObject", /*  */
		.name_size = 10,
		.argumentList = upnp_svc_cntnt_dir_action_MoveObject_args
	},{
		.name = "ImportResource", /*  */
		.name_size = 14,
		.argumentList = upnp_svc_cntnt_dir_action_ImportResource_args
	},{
		.name = "ExportResource", /*  */
		.name_size = 14,
		.argumentList = upnp_svc_cntnt_dir_action_ExportResource_args
	},{
		.name = "StopTransferResource", /*  */
		.name_size = 20,
		.argumentList = upnp_svc_cntnt_dir_action_StopTransferResource_args
	},{
		.name = "DeleteResource", /*  */
		.name_size = 14,
		.argumentList = upnp_svc_cntnt_dir_action_DeleteResource_args
	},{
		.name = "GetTransferProgress", /*  */
		.name_size = 19,
		.argumentList = upnp_svc_cntnt_dir_action_GetTransferProgress_args
	},{
		.name = "CreateReference", /*  */
		.name_size = 15,
		.argumentList = upnp_svc_cntnt_dir_action_CreateReference_args
	},{
		.name = "FreeFormQuery", /*  */
		.name_size = 13,
		.argumentList = upnp_svc_cntnt_dir_action_FreeFormQuery_args
	},{
		.name = "GetFreeFormQueryCapabilities", /*  */
		.name_size = 28,
		.argumentList = upnp_svc_cntnt_dir_action_GetFreeFormQueryCapabilities_args
	},{ // samsung
		.name = "X_GetFeatureList", /*  */
		.name_size = 16,
		.argumentList = upnp_svc_cntnt_dir_action_X_GetFeatureList_args
	},{
		.name = NULL, .name_size = 0, .argumentList = NULL
	}
};

#define CNTNT_DIR_ACTION_GetSearchCapabilities		0
#define CNTNT_DIR_ACTION_GetSortCapabilities		1
#define CNTNT_DIR_ACTION_GetSortExtensionCapabilities	2
#define CNTNT_DIR_ACTION_GetFeatureList			3
#define CNTNT_DIR_ACTION_GetSystemUpdateID		4
#define CNTNT_DIR_ACTION_GetServiceResetToken		5
#define CNTNT_DIR_ACTION_Browse				6
#define CNTNT_DIR_ACTION_Search				7
#define CNTNT_DIR_ACTION_CreateObject			8
#define CNTNT_DIR_ACTION_DestroyObject			9
#define CNTNT_DIR_ACTION_UpdateObject			10
#define CNTNT_DIR_ACTION_MoveObject			11
#define CNTNT_DIR_ACTION_ImportResource			12
#define CNTNT_DIR_ACTION_ExportResource			13
#define CNTNT_DIR_ACTION_StopTransferResource		14
#define CNTNT_DIR_ACTION_DeleteResource			15
#define CNTNT_DIR_ACTION_GetTransferProgress		16
#define CNTNT_DIR_ACTION_CreateReference		17
#define CNTNT_DIR_ACTION_FreeFormQuery			18
#define CNTNT_DIR_ACTION_GetFreeFormQueryCapabilities	19
#define CNTNT_DIR_ACTION_X_GetFeatureList		20



static upnp_service_t upnp_svc_cntnt_dir = {
	.domain_name = "schemas-upnp-org",
	.type = "ContentDirectory",
	.ver = 3,
	.actionList = upnp_svc_cntnt_dir_actions,
	.serviceStateTable = upnp_svc_cntnt_dir_st_var,
	.ctrl_cb_func = upnp_svc_cntnt_dir_ctrl_cb,
	.ev_cb_func = NULL
};






#endif // __CORE_UPNP_SVC_CONTENTDIRECTORY_H__
