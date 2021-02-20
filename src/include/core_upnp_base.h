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


#ifndef __CORE_UPNP_BASE_H__
#define __CORE_UPNP_BASE_H__

#include "core_io_task.h"
#include "core_io_buf.h"
#include "core_http_srv.h"



/*
 * Required = RQ
 * Recommended = RC
 * Optional = OP
 * localized = LOC
 */

/* Additional structs. */
/* 2. Description */
typedef struct upnp_icon_s {
	const char	*mimetype;	/* RQ. Icon's MIME type (cf. RFC 2045, 2046, and 2387) */
	const uint32_t	width;		/* RQ. Horizontal dimension of icon in pixels. Integer. */
	const uint32_t	height;		/* RQ. Vertical dimension of icon in pixels. Integer. */
	const uint32_t	depth;		/* RQ. Number of color bits per pixel. Integer. */
	const char	*url;		/* RQ. Pointer to icon image. */
} upnp_icon_t, *upnp_icon_p;


typedef struct upnp_service_state_var_s {
	/* Attributes. */
	const uint32_t	sendEvents;	/* OP. ("yes"/"no") Defines whether event messages will be generated when the value of this state variable changes. */
	const uint32_t	multicast;	/* OP. ("yes"/"no") Defines whether event messages will be delivered using multicast eventing. */
	/* Sub elements. */
	const char	*name;		/* RQ. (MAX 32) Name of formal parameter. */
	const char	*dataType_type;	/* OP. attribute. */
	const char	*dataType;	/* RQ. Same as data types defined by XML Schema, Part 2: Datatypes. */
	const char	*defaultValue;	/* RC. Expected, initial value. */
	const char	**allowedValueList;/* RC. Enumerates legal string values. */
	const char	*allowedValueRange_min; /* RQ. Inclusive lower bound. */
	const char	*allowedValueRange_max; /* RQ. Inclusive upper bound. */
	const char	*allowedValueRange_step; /* RC. */
} upnp_service_state_var_t, *upnp_service_state_var_p;


typedef struct upnp_service_action_arg_s {
	const char	*name;		/* RQ. Name of formal parameter. */
	const uint32_t	direction;	/* RQ. ("in"/"out") Defines whether argument is an input or output parameter.*/
	const uint32_t	retval;		/* OP. Identifies at most one output argument as the return value. */
	const upnp_service_state_var_p relatedStateVariable; /* RQ. Name of a state variable. */
} upnp_service_action_arg_t, *upnp_service_action_arg_p;

typedef struct upnp_service_action_s {
	const char	*name;		/* RQ. Name of action. */
	const uint32_t	name_size;
	const upnp_service_action_arg_p argumentList;	/* OP. */
} upnp_service_action_t, *upnp_service_action_p;




/* Main structs */
typedef struct upnp_device_s *upnp_device_p;
typedef struct upnp_service_s *upnp_service_p;



typedef int (*upnp_service_ctrl_cb)(upnp_device_p dev, upnp_service_p svc,
	http_srv_cli_p cli, int action,
	uint8_t *req_data, size_t req_data_size);
typedef int (*upnp_service_ev_cb)(upnp_device_p dev, upnp_service_p svc,
	http_srv_cli_p cli, uint8_t *soap_act_name, size_t soap_act_name_size,
	uint8_t *req_data, size_t req_data_size);


typedef struct upnp_service_s {
	/* 1. Discovery / SSDP */
	const char	*domain_name;	/* domain-name */
	const char	*type;		/* serviceType */
	const uint32_t	ver;		/* version */
	/* 2. Description */
	//char		*SCPDURL;	/* URL to service description */
	//char		*controlURL;	/* URL for control */
	//char		*eventSubURL;	/* URL for eventing */
	const upnp_service_action_p actionList; /* RQ. if and only if the service has actions. */
	const upnp_service_state_var_p serviceStateTable; /* RQ. */
	const upnp_service_ctrl_cb ctrl_cb_func;
	const upnp_service_ev_cb ev_cb_func;
} upnp_service_t;


typedef struct upnp_device_s {
	/* 1. Discovery / SSDP */
	const char	*uuid;		/* device-UUID */
	/* URL to the UPnP description of the root device - auto generated. */
	const char	*domain_name;	/* domain-name */
	const char	*type;		/* deviceType */
	const uint32_t	ver;		/* version */
	const upnp_service_p *serviceList;
	const upnp_device_p deviceList;	/* embedded deviceList */
	/* 2. Description */
	const char	*friendlyName;	/* RQ, LOC. (MAX 64) Manufacturer's name. Specified by UPnP vendor. String. */
	const char	*manufacturer;	/* RQ, LOC. (MAX 64) Manufacturer's name. Specified by UPnP vendor. String. */
	const char	*manufacturerURL; /* OP, LOC. Web site for Manufacturer. May be relative to base URL. Specified by UPnP vendor. Single URL. */
	const char	*modelDescription; /* RC, LOC. (MAX 128) Long description for end user. Specified by UPnP vendor. String. */
	const char	*modelName;	/* RQ, LOC. (MAX 32) Model name. Specified by UPnP vendor. String. */
	const char	*modelNumber;	/* RC, LOC. (MAX 32) Model number. Specified by UPnP vendor. String. */
	const char	*modelURL;	/* OP, LOC. Web site for model. May be relative to base URL. Specified by UPnP vendor. Single URL. */
	const char	*serialNumber;	/* RC, LOC. (MAX 64) Serial number. Specified by UPnP vendor. String. */
	// ->uuid char		*UDN;	/* RQ. Unique Device Name. Universally-unique identifier for the device, whether root or embedded. */
	const char	*UPC;		/* OP. Universal Product Code. 12-digit, all-numeric code that identifies the consumer package. Managed by the Uniform Code Council. */
	const upnp_icon_p iconList;	/* Required if and only if device has one or more icons. Specified by UPnP vendor. */
	// serviceList
	// deviceList
	// presentationURL-> pref+uuid; /* RC. URL to presentation for device (cf. section on Presentation). May be relative to base URL. Specified by UPnP vendor. Single URL. */
	void		*ssdp_dev;	/* Used for SSDP annonces. */
} upnp_device_t;






#endif // __CORE_UPNP_BASE_H__
