/*-
 * Copyright (c) 2012 - 2016 Rozhuk Ivan <rozhuk.im@gmail.com>
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


#include <sys/param.h>
#ifdef __linux__ /* Linux specific code. */
#	define _GNU_SOURCE /* See feature_test_macros(7) */
#	define __USE_GNU 1
#endif /* Linux specific code. */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <netinet/in.h>

#include <stdlib.h> /* malloc, exit */
#include <unistd.h> /* close, write, sysconf */
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <stdio.h> /* for snprintf, fprintf */
#include <time.h>
#include <errno.h>

#include "mem_helpers.h"
#include "StrToNum.h"
#include "HTTP.h"
#include "xml.h"

#include "macro_helpers.h"
#include "core_io_task.h"
#include "core_io_net.h"
#include "core_net_helpers.h"
#include "core_log.h"
#include "core_upnp_base.h"
#include "core_upnp_dev.h"
#include "core_upnp_svc_cntnt_dir.h"
#include "core_upnp_svc_conn_mngr.h"
#include "core_upnp_svc_ms_media_rcvr_reg.h"
#include "core_upnp_ssdp.h"
#include "core_http_srv.h"
#include "core_upnp.h"


#define PRODUCT		"UPnP by Rozhuk Ivan"
#define PRODUCT_VER	"1.0"


#define UPNP_UUID_SIZE			36
#define UPNP_HTTP_PORT			51900	// default value
#define UPNP_HTTP_BACKLOG		64	// default value
#define UPNP_ANNOUNCE_INTERVAL		5	// default value
#define UPNP_MAX_AGE			1800	// default value


#define UPNP_SSDP_DESCR_PATH		"/descr/"
#define UPNP_SSDP_DESCR_UUID_PATH_SIZE	((sizeof(UPNP_SSDP_DESCR_PATH) - 1) + UPNP_UUID_SIZE)
#define UPNP_SSDP_ICONS_PATH		"/icons/"
#define UPNP_SSDP_CONTROL_PATH		"/control/"
#define UPNP_SSDP_CONTROL_PATH_SIZE	((sizeof(UPNP_SSDP_CONTROL_PATH) - 1) + UPNP_UUID_SIZE)
#define UPNP_SSDP_EVENT_PATH		"/event/"
#define UPNP_SSDP_EVENT_PATH_SIZE	((sizeof(UPNP_SSDP_EVENT_PATH) - 1) + UPNP_UUID_SIZE)
#define UPNP_SSDP_PRESENTATION_PATH	"/presentation/"



typedef struct upnp_s {
	thrp_p		thp;
	upnp_device_p	root_devs;
	/* 1. Discovery / SSDP */
	upnp_ssdp_p	ssdp;
	uint32_t	ssdp_config_id;
	/* 2. Description */
	http_srv_p	http_srv;	/*  */
	uint16_t	http_port;
} upnp_t;



/* Signifies an improper request. */
static const char *upnp_reason_phrase_4xx[] = {
	"Incompatible header fields",			/* 400 */
	"Invalid Action",				/* 401 */
	"Invalid args",					/* 402 */
};
static const size_t upnp_reason_phrase_size_4xx[] = {
	26,						/* 400 */
	14,						/* 401 */
	12,						/* 402 */
};

/* Signifies a processing error for a valid request. */
static const char *upnp_reason_phrase_5xx[] = {
	NULL,
	"Action failed",				/* 501 */
};
static const size_t upnp_reason_phrase_size_5xx[] = {
	0,
	13,						/* 501 */
};

static const char *upnp_reason_phrase_6xx[] = {
	"Argument Value Invalid",			/* 600 */
	"Argument Value Out of Range",			/* 601 */
	"Optional Action Not Implemented",		/* 602 */
	"Out of Memory",				/* 603 */
	"Human Intervention Required",			/* 604 */
	"String Argument Too Long",			/* 605 */
};
static const size_t upnp_reason_phrase_size_6xx[] = {
	22,						/* 600 */
	27,						/* 601 */
	31,						/* 602 */
	13,						/* 603 */
	27,						/* 604 */
	24,						/* 605 */
};


int		upnp_dev_by_uuid(upnp_device_p root_dev, uint8_t *uuid,
		    upnp_device_p *dev_ret);
int		upnp_service_by_name(upnp_device_p dev, uint8_t *serviceType,
		    size_t serviceType_size, upnp_service_p *svc_ret);


const char 	*upnp_http_get_err_descr(uint32_t status_code, size_t *descr_size_ret);
static int	upnp_http_srv_on_conn_cb(http_srv_accept_p acc, thrpt_p *thpt,
		    uintptr_t skt, struct sockaddr_storage *addr, void **udata);
static int	upnp_http_srv_on_destroy_cb(http_srv_cli_p cli);
static int	upnp_http_srv_on_req_rcv_cb(http_srv_cli_p cli);
static int	upnp_http_srv_on_rep_snd_cb(http_srv_cli_p cli);


int		upnp_descr_dev_gen_send(http_srv_cli_p cli, upnp_device_p dev);
int		upnp_descr_svc_gen_send(http_srv_cli_p cli, upnp_service_p svc);

/* 3 Control */
static int	upnp_http_soap_err_to_cli(http_srv_cli_p cli, uint32_t status_code);
int		upnp_ctrl_svc_handle(upnp_device_p dev, upnp_service_p svc,
		    http_srv_cli_p cli,
		    uint8_t *soap_act_name, size_t soap_act_name_size,
		    uint8_t *req_data, size_t req_data_size);



int
upnp_create(thrp_p thp, upnp_ssdp_settings_p ssdpd_s, http_srv_settings_p http_s,
    uint16_t port, uint16_t backlog, char *accf, size_t accf_size,
    uint32_t max_age, uint32_t ann_interval, upnp_p *upnp_ret) {
	upnp_p upnp;
	upnp_device_p dev;
	upnp_service_p *svc;
	struct sockaddr_storage addr;
	int error;

	LOG_EV_FMT("...");
	
	if (NULL == upnp_ret)
		return (EINVAL);
		
	upnp = zalloc(sizeof(upnp_t));
	if (NULL == upnp)
		return (errno);
	upnp->thp = thp;
	upnp->root_devs = upnp_deviceList;
	/* 1. SSDP init. */
	error = upnp_ssdp_create(thp, ssdpd_s, &upnp->ssdp); // XXX
	if (0 != error)
		goto err_out;
	/* Apply default settings */
	if (0 == port)
		port = UPNP_HTTP_PORT;
	if (0 == backlog)
		backlog = UPNP_HTTP_BACKLOG;
	if (0 == max_age)
		max_age = UPNP_ANNOUNCE_INTERVAL;
	if (0 == ann_interval)
		ann_interval = UPNP_MAX_AGE;

	//upnp->ssdp_boot_id = time(NULL);
	upnp->http_port = port;
	upnp->ssdp_config_id = 1;

	/* 2-4 http init. */
	http_s->flags = (HTTP_SRV_S_F_CONN_CLOSE | HTTP_SRV_S_F_SERVER | HTTP_SRV_S_F_CONTENT_LEN);
	error = http_srv_create(thp, upnp_http_srv_on_conn_cb,
	    upnp_http_srv_on_destroy_cb, upnp_http_srv_on_req_rcv_cb,
	    upnp_http_srv_on_rep_snd_cb, http_s, &upnp->http_srv);
	if (0 != error)
		goto err_out;

	sain4_init(&addr);
	sain4_p_set(&addr, upnp->http_port);
	error = http_srv_accept_add(upnp->http_srv, &addr, backlog, accf, accf_size,
	    upnp, NULL);
	if (0 != error)
		goto err_out;
	sain6_init(&addr);
	sain6_p_set(&addr, upnp->http_port);
	error = http_srv_accept_add(upnp->http_srv, &addr, backlog, accf, accf_size,
	    upnp, NULL);
	if (0 != error)
		goto err_out;

	dev = upnp->root_devs;
	while (NULL != dev && NULL != dev->uuid) {
		error = upnp_ssdp_dev_add(upnp->ssdp, dev->uuid, dev->domain_name, 0,
		    dev->type, 0, dev->ver, time(NULL), upnp->ssdp_config_id, 
		    max_age, ann_interval, (upnp_ssdp_dev_p*)&dev->ssdp_dev);
		if (0 != error)
			goto err_out;
		svc = (upnp_service_p*)dev->serviceList;
		while (NULL != (*svc)) {
			error = upnp_ssdp_svc_add(dev->ssdp_dev,
			    (*svc)->domain_name, 0, (*svc)->type, 0, (*svc)->ver);
			if (0 != error)
				goto err_out;
			svc ++;
		}
		dev ++;
	}

	(*upnp_ret) = upnp;
	return (0);

err_out:
	/* Error. */
	LOG_ERR(error, "err_out");
	upnp_destroy(upnp);
	return (error);
}

void
upnp_destroy(upnp_p upnp) {

	LOG_EV_FMT("...");
	if (NULL == upnp)
		return;
	http_srv_destroy(upnp->http_srv);
	upnp_ssdp_destroy(upnp->ssdp); /* Auto destroy all ssdp_dev~s. */
	free(upnp);
}


int
upnp_iface_add(upnp_p upnp, const char *if_name, size_t if_name_size,
    const char *if_ann_name, size_t if_ann_name_size) {
	int error;
	upnp_device_p dev;
	struct sockaddr_storage addr;
	char straddr4[STR_ADDR_LEN] = {0}, straddr6[STR_ADDR_LEN] = {0};
	char url4[512], url6[512];
	size_t straddr4_size = 0, straddr6_size = 0, url4_size, url6_size;

	LOG_EV_FMT("...");
	if (NULL == upnp)
		return (EINVAL);
	if (NULL == if_ann_name || 0 == if_ann_name_size) {
		if_ann_name = if_name;
		if_ann_name_size = if_name_size;
	}

	if (0 == get_if_addr_by_name(if_ann_name, if_ann_name_size, AF_INET, &addr)) {
		sain4_p_set(&addr, upnp->http_port);
		ss_to_str_addr_port(&addr, straddr4, STR_ADDR_LEN, &straddr4_size);
	}
	if (0 == get_if_addr_by_name(if_ann_name, if_ann_name_size, AF_INET6, &addr)) {
		sain6_p_set(&addr, upnp->http_port);
		ss_to_str_addr_port(&addr, straddr6, STR_ADDR_LEN, &straddr6_size);
	}
	if (0 == straddr4_size && 0 == straddr6_size) { /* No iface addrs avaible. */
		error = ESPIPE;
		goto err_out;
	}
	//LOG_EV_FMT("iface: %s: addr4: %s, addr6: %s", if_ann_name, straddr4, straddr6);
	
	dev = upnp->root_devs;
	while (NULL != dev && NULL != dev->uuid) {
		url4_size = snprintf(url4, sizeof(url4), "http://%s"UPNP_SSDP_DESCR_PATH"%s",
		    straddr4, dev->uuid);
		url6_size = snprintf(url6, sizeof(url6), "http://%s"UPNP_SSDP_DESCR_PATH"%s",
		    straddr6, dev->uuid);
		error = upnp_ssdp_dev_if_add(upnp->ssdp, dev->ssdp_dev,
		    if_name, if_name_size, url4, url4_size, url6, url6_size);
		if (0 != error)
			goto err_out;
		dev ++;
	}

	return (0);
err_out:
	/* Error. */
	LOG_ERR(error, "err_out");
	return (error);
}


void
upnp_send_notify(upnp_p upnp) {

	if (NULL == upnp)
		return;
	upnp_ssdp_send_notify(upnp->ssdp);
}


int
upnp_dev_by_uuid(upnp_device_p root_dev, uint8_t *uuid, upnp_device_p *dev_ret) {
	upnp_device_p dev = root_dev;

	while (NULL != dev && NULL != dev->uuid) {
		if (0 == memcmp(dev->uuid, uuid, UPNP_UUID_SIZE)) {
			(*dev_ret) = dev;
			return (0);
		}
		dev ++;
	}
	return (-1);
}

int
upnp_service_by_name(upnp_device_p dev, uint8_t *serviceType, size_t serviceType_size,
    upnp_service_p *svc_ret) {
	upnp_service_p *svc;

	if (NULL == dev)
		return (EINVAL);
	svc = (upnp_service_p*)dev->serviceList;
	while (NULL != (*svc)) {
		if (0 == strncmp((*svc)->type, (char*)serviceType, serviceType_size)) {
			(*svc_ret) = (*svc);
			return (0);
		}
		svc ++;
	}
	return (-1);
}


const char *
upnp_http_get_err_descr(uint32_t status_code, size_t *descr_size_ret) {
	const char *reason_phrase = NULL;

	if (400 > status_code) { /* 0 - 399 */
	}else if (500 > status_code) { /* 400 - 499 */
		status_code -= 400;
		if (sizeof(upnp_reason_phrase_4xx) > status_code)
			reason_phrase = upnp_reason_phrase_4xx[status_code];
		if (NULL != reason_phrase && NULL != descr_size_ret)
			(*descr_size_ret) = upnp_reason_phrase_size_4xx[status_code];
	}else if (600 > status_code) { /* 500 - 599 */
		status_code -= 500;
		if (sizeof(upnp_reason_phrase_5xx) > status_code)
			reason_phrase = upnp_reason_phrase_5xx[status_code];
		if (NULL != reason_phrase && NULL != descr_size_ret)
			(*descr_size_ret) = upnp_reason_phrase_size_5xx[status_code];
	}else if (700 > status_code) { /* 600 - 699 */
		status_code -= 600;
		if (sizeof(upnp_reason_phrase_6xx) > status_code)
			reason_phrase = upnp_reason_phrase_6xx[status_code];
		if (NULL != reason_phrase && NULL != descr_size_ret)
			(*descr_size_ret) = upnp_reason_phrase_size_6xx[status_code];
	}
	if (NULL == reason_phrase)
		reason_phrase = http_get_err_descr(status_code, descr_size_ret);
	return (reason_phrase);
}


/* New connection received. */
static int
upnp_http_srv_on_conn_cb(http_srv_accept_p acc, thrpt_p *thpt __unused,
    uintptr_t skt __unused, struct sockaddr_storage *addr __unused, void **udata) {

	LOG_EV_FMT("...");
	(*udata) = acc->udata;
	return (0);
}

static int
upnp_http_srv_on_destroy_cb(http_srv_cli_p cli __unused) {

	LOG_EV_FMT("...");
	return (0);
}

/* http request from client is received now, process it. */
static int
upnp_http_srv_on_req_rcv_cb(http_srv_cli_p cli) {
	upnp_p upnp = (upnp_p)cli->udata;
	uint8_t *ptm;
	uint8_t *soap_act, *soap_service, *soap_act_name;
	size_t soap_act_size, soap_service_size, soap_act_name_size;
	upnp_device_p dev;
	upnp_service_p svc;

	LOG_EV_FMT("...");

	// XXX !!!
	if (HTTP_REQ_METHOD_SUBSCRIBE == cli->req.method) {
		const char *hdrs;
		size_t hdrs_size;

		/* HTTP header. */
		hdrs =
		    "Pragma: no-cache\r\n"
		    "SID: uuid:7CF21CB0-2266-47BE-A608-3CC1F5210BB4\r\n"
		    "Timeout: Second-1800";
		hdrs_size = strlen(hdrs);
		http_srv_snd(cli, 200, NULL, 0, hdrs, hdrs_size);
		return (0);
	}
	if (HTTP_REQ_METHOD_UNSUBSCRIBE == cli->req.method)
		return (200);

	/* Descriptions request. */
	if (UPNP_SSDP_DESCR_UUID_PATH_SIZE <= cli->req.uri_path_size &&
	    0 == memcmp(cli->req.uri_path, UPNP_SSDP_DESCR_PATH,
	     (sizeof(UPNP_SSDP_DESCR_PATH) - 1))) {
		if (HTTP_REQ_METHOD_GET != cli->req.method)
			return (405);
		ptm = (cli->req.uri_path + (sizeof(UPNP_SSDP_DESCR_PATH) - 1));
		if (0 != upnp_dev_by_uuid(upnp->root_devs, ptm, &dev))
			return (404);
		/* Point to service name, if exist. */
		if ((UPNP_SSDP_DESCR_UUID_PATH_SIZE + 1) < cli->req.uri_path_size &&
		    0 == upnp_service_by_name(dev, (ptm + UPNP_UUID_SIZE + 1),
		    (cli->req.uri_path_size - (UPNP_SSDP_DESCR_UUID_PATH_SIZE + 1)), &svc)) {
			upnp_descr_svc_gen_send(cli, svc);
		} else {
			upnp_descr_dev_gen_send(cli, dev);
		}
		return (0);
	}
	/* Controls request. */
	if (UPNP_SSDP_CONTROL_PATH_SIZE <= cli->req.uri_path_size &&
	    0 == memcmp(cli->req.uri_path, UPNP_SSDP_CONTROL_PATH,
	     (sizeof(UPNP_SSDP_CONTROL_PATH) - 1))) {
		if (HTTP_REQ_METHOD_POST != cli->req.method)
			return (405);
		/* Process SOAPACTION httpheader. */
		if (0 != http_hdr_val_get(cli->req.hdr, cli->req.hdr_size,
		    (uint8_t*)"soapaction", 10, &soap_act, &soap_act_size) ||
		    36 > soap_act_size ||
		    0 != memcmp(soap_act, "\"urn:", 5)) {
			LOG_EV_FMT("soapaction size = %zu, %s", soap_act_size, soap_act);
			return (401);
		}
		soap_service = mem_find_off_cstr(5, soap_act, soap_act_size, ":service:");
		soap_service ++;
		ptm = mem_chr_ptr(soap_service, soap_act, soap_act_size, ':');
		soap_service_size = (ptm - soap_service);
		soap_act_name = mem_chr_ptr(soap_service, soap_act, soap_act_size, '#');
		soap_act_name ++;
		soap_act_name_size = ((soap_act + soap_act_size) - (soap_act_name + 1));
		//LOG_EV_FMT("soap service size = %zu, %s", soap_service_size, soap_service);
		//LOG_EV_FMT("soap action name size = %zu, %s", soap_act_name_size, soap_act_name);

		ptm = (cli->req.uri_path + (sizeof(UPNP_SSDP_CONTROL_PATH) - 1));
		if (0 != upnp_dev_by_uuid(upnp->root_devs, ptm, &dev))
			return (404);
		/* Point to service name. */
		if ((UPNP_SSDP_CONTROL_PATH_SIZE + 1) >= cli->req.uri_path_size ||
		    0 != upnp_service_by_name(dev, (ptm + UPNP_UUID_SIZE + 1),
		    (cli->req.uri_path_size - (UPNP_SSDP_CONTROL_PATH_SIZE + 1)), &svc))
			return (404);
		upnp_ctrl_svc_handle(dev, svc, cli, soap_act_name,
		    soap_act_name_size, cli->req.data, cli->req.data_size);
		return (0);
	}
	
	return (404);
}

static int
upnp_http_srv_on_rep_snd_cb(http_srv_cli_p cli __unused) {

	LOG_EV_FMT("...");
	return (0);
}



/* 2. Description */
int
upnp_descr_dev_gen_send(http_srv_cli_p cli, upnp_device_p dev) {
	upnp_p upnp = (upnp_p)cli->udata;
	upnp_icon_p iconList;
	const upnp_service_p *svc;
	const char *hdrs;
	size_t hdrs_size;

	/* HTTP header. */
	hdrs =
	    "Content-Type: text/xml; charset=\"utf-8\"";
	hdrs_size = strlen(hdrs);
	/* Device description. */
	IO_BUF_PRINTF(cli->buf,
	    "<?xml version=\"1.0\"?>\n"
	    "<root xmlns=\"urn:schemas-upnp-org:device-1-0\" configId=\"%"PRIu32"\">\n"
	    "	<specVersion>\n"
	    "		<major>1</major>\n"
	    "		<minor>1</minor>\n"
	    "	</specVersion>\n"
	    "	<device>\n"
	    "		<deviceType>urn:%s:device:%s:%"PRIu32"</deviceType>\n"
	    "		<friendlyName>%s</friendlyName>\n"
	    "		<manufacturer>%s</manufacturer>\n"
	    "		<manufacturerURL>%s</manufacturerURL>\n"
	    "		<modelDescription>%s</modelDescription>\n"
	    "		<modelName>%s</modelName>\n"
	    "		<modelNumber>%s</modelNumber>\n"
	    "		<modelURL>%s</modelURL>\n"
	    "		<serialNumber>%s</serialNumber>\n"
	    "		<UDN>uuid:%s</UDN>\n"
	    "		<UPC>%s</UPC>\n"
	    "		<dlna:X_DLNADOC xmlns:dlna=\"urn:schemas-dlna-org:device-1-0\">DMS-1.50</dlna:X_DLNADOC>\n",
	    upnp->ssdp_config_id,
	    dev->domain_name, dev->type, dev->ver,
	    dev->friendlyName,
	    dev->manufacturer,
	    dev->manufacturerURL,
	    dev->modelDescription,
	    dev->modelName,
	    dev->modelNumber,
	    dev->modelURL,
	    dev->serialNumber,
	    dev->uuid,
	    dev->UPC);
	/* device icons */
	if (NULL == dev->iconList)
		goto no_icons;
	IO_BUF_PRINTF(cli->buf,
	    "		<iconList>\n");
	iconList = dev->iconList;
	while (NULL != iconList->mimetype) {
		IO_BUF_PRINTF(cli->buf,
		    "			<icon>\n"
		    "				<mimetype>image/%s</mimetype>\n"
		    "				<width>%"PRIu32"</width>\n"
		    "				<height>%"PRIu32"</height>\n"
		    "				<depth>%"PRIu32"</depth>\n"
		    "				<url>"UPNP_SSDP_ICONS_PATH"%s/%s</url>\n"
		    "			</icon>\n",
		    iconList->mimetype,
		    iconList->height,
		    iconList->width,
		    iconList->depth,
		    dev->uuid, iconList->url);
		iconList ++;
	}
	IO_BUF_PRINTF(cli->buf,
	    "		</iconList>\n");

no_icons:
	/* Device serviceList */
	if (NULL == dev->serviceList)
		goto no_serviceList;
	IO_BUF_PRINTF(cli->buf,
	    "		<serviceList>\n");
	svc = (upnp_service_p*)dev->serviceList;
	while (NULL != (*svc)) {
		IO_BUF_PRINTF(cli->buf,
		    "			<service>\n"
		    "				<serviceType>urn:%s:service:%s:%"PRIu32"</serviceType>\n"
		    "				<serviceId>urn:%s:serviceId:%s</serviceId>\n"
		    "				<SCPDURL>"UPNP_SSDP_DESCR_PATH"%s/%s</SCPDURL>\n"
		    "				<controlURL>"UPNP_SSDP_CONTROL_PATH"%s/%s</controlURL>\n"
		    "				<eventSubURL>"UPNP_SSDP_EVENT_PATH"%s/%s</eventSubURL>\n"
		    "			</service>\n",
		    (*svc)->domain_name, (*svc)->type, (*svc)->ver,
		    ((0 == strcmp((*svc)->domain_name, "schemas-upnp-org")) ? "upnp-org" : (*svc)->domain_name), (*svc)->type,
		    dev->uuid, (*svc)->type,
		    dev->uuid, (*svc)->type,
		    dev->uuid, (*svc)->type);
		svc ++;
	}
	IO_BUF_PRINTF(cli->buf,
	    "		</serviceList>\n");

no_serviceList:
	IO_BUF_PRINTF(cli->buf,
	    "		<presentationURL>"UPNP_SSDP_PRESENTATION_PATH"%s</presentationURL>\n"
	    "	</device>\n"
	    "</root>\n",
	    dev->uuid);

	// send answer to cli
	return (http_srv_snd(cli, 200, NULL, 0, hdrs, hdrs_size));
}

int
upnp_descr_svc_gen_send(http_srv_cli_p cli, upnp_service_p svc) {
	const char *hdrs;
	upnp_p upnp = (upnp_p)cli->udata;
	size_t hdrs_size;
	upnp_service_action_p actionList;
	upnp_service_action_arg_p argumentList;
	upnp_service_state_var_p serviceStateTable;
	const char **allowedValueList;

	/* HTTP header. */
	hdrs =
	    "Content-Type: text/xml; charset=\"utf-8\"";
	hdrs_size = strlen(hdrs);
	/* Data. */
	/* Service description. */
	IO_BUF_PRINTF(cli->buf,
	    "<?xml version=\"1.0\"?>\n"
	    "<scpd xmlns=\"urn:schemas-upnp-org:service-1-0\" configId=\"%"PRIu32"\">\n"
	    "	<specVersion>\n"
	    "		<major>1</major>\n"
	    "		<minor>1</minor>\n"
	    "	</specVersion>\n",
	    upnp->ssdp_config_id);
	/* service actions */
	if (NULL == svc->actionList)
		goto no_actionList;
	IO_BUF_PRINTF(cli->buf,
	    "	<actionList>\n");
	actionList = svc->actionList;
	while (NULL != actionList->name) {
		IO_BUF_PRINTF(cli->buf,
		    "		<action>\n"
		    "			<name>%s</name>\n",
		    actionList->name);
		if (NULL == actionList->argumentList)
			goto no_argumentList;
		IO_BUF_PRINTF(cli->buf,
		    "			<argumentList>\n");
		argumentList = actionList->argumentList;
		while (NULL != argumentList->name) {
			IO_BUF_PRINTF(cli->buf,
			    "				<argument>\n"
			    "					<name>%s</name>\n"
			    "					<direction>%s</direction>\n",
			    argumentList->name,
			    ((0 == argumentList->direction) ? "in" : "out"));
			if (0 != argumentList->retval)
				IO_BUF_PRINTF(cli->buf,
				    "					<retval/>\n");
			IO_BUF_PRINTF(cli->buf,
			    "					<relatedStateVariable>%s</relatedStateVariable>\n"
			    "				</argument>\n",
			    argumentList->relatedStateVariable->name);
			argumentList ++;
		} // argumentList
		IO_BUF_PRINTF(cli->buf,
		    "			</argumentList>\n");
no_argumentList:
		IO_BUF_PRINTF(cli->buf,
		    "		</action>\n");
		actionList ++;
	}// actionList
	IO_BUF_PRINTF(cli->buf,
	    "	</actionList>\n");

no_actionList:
	/* Device serviceList */
	if (NULL == svc->serviceStateTable)
		goto no_serviceStateTable;
	IO_BUF_PRINTF(cli->buf,
	    "	<serviceStateTable>\n");
	serviceStateTable = svc->serviceStateTable;
	while (NULL != serviceStateTable->name) {
		IO_BUF_PRINTF(cli->buf,
		    "		<stateVariable sendEvents=\"%s\" multicast=\"%s\">\n"
		    "			<name>%s</name>\n",
		    ((0 == serviceStateTable->sendEvents) ? "no" : "yes"),
		    ((0 == serviceStateTable->multicast) ? "no" : "yes"),
		    serviceStateTable->name);
		if (NULL != serviceStateTable->dataType_type) {
			IO_BUF_PRINTF(cli->buf,
			    "			<dataType type=\"%s\">string</dataType>\n",
			    serviceStateTable->dataType_type);
			goto dataType_type_present;
		}
		IO_BUF_PRINTF(cli->buf,
		    "			<dataType>%s</dataType>\n",
		    serviceStateTable->dataType);
		if (NULL != serviceStateTable->defaultValue) {
			IO_BUF_PRINTF(cli->buf,
			    "			<defaultValue>%s</defaultValue>\n",
			    serviceStateTable->defaultValue);
		}
		if (NULL != serviceStateTable->allowedValueList) {
			allowedValueList = serviceStateTable->allowedValueList;
			IO_BUF_PRINTF(cli->buf,
			    "			<allowedValueList>\n");
			while (NULL != (*allowedValueList)) {
				IO_BUF_PRINTF(cli->buf,
				    "				<allowedValue>%s</allowedValue>\n",
				    (*allowedValueList));
				allowedValueList ++;
			}
			IO_BUF_PRINTF(cli->buf,
			    "			</allowedValueList>\n");
		}
dataType_type_present:
		IO_BUF_PRINTF(cli->buf,
		    "		</stateVariable>\n");
		serviceStateTable ++;
	}
	IO_BUF_PRINTF(cli->buf,
	    "	</serviceStateTable>\n");

no_serviceStateTable:
	IO_BUF_PRINTF(cli->buf,
	    "</scpd>\n");

	// send answer to cli
	return (http_srv_snd(cli, 200, NULL, 0, hdrs, hdrs_size));
}




/* 3 Control */
static int
upnp_http_soap_err_to_cli(http_srv_cli_p cli, uint32_t status_code) {
	const char *rp, *hdrs;
	size_t rp_size, hdrs_size;

	LOG_EV_FMT("return code: %i", status_code);
	rp = upnp_http_get_err_descr(status_code, &rp_size);
	/* HTTP header. */
	hdrs =
	    "Content-Type: text/xml; charset=\"utf-8\"\r\n"
	    "Pragma: no-cache";
	hdrs_size = strlen(hdrs);
	/* Data. */
	IO_BUF_PRINTF(cli->buf,
	    "<?xml version=\"1.0\"?>\n"
	    "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n"
	    "	<s:Body>\n"
	    "		<s:Fault>\n"
	    "			<faultcode>s:Client</faultcode>\n"
	    "			<faultstring>UPnPError</faultstring>\n"
	    "			<detail>\n"
	    "				<UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\">\n"
	    "					<errorCode>%i</errorCode>\n"
	    "					<errorDescription>%s</errorDescription>\n"
	    "				</UPnPError>\n"
	    "			</detail>\n"
	    "		</s:Fault>\n"
	    "	</s:Body>\n"
	    "</s:Envelope>\n",
	    status_code, rp);

	// send answer to cli
	return (http_srv_snd(cli, status_code, rp, rp_size, hdrs, hdrs_size));
}


int
upnp_ctrl_svc_handle(upnp_device_p dev, upnp_service_p svc, http_srv_cli_p cli,
    uint8_t *soap_act_name, size_t soap_act_name_size,
    uint8_t *req_data, size_t req_data_size) {
	int ret_code, i, action = -1;
	upnp_service_action_p actionList;
	uint8_t *name_space[4] = {NULL}, ns[4][64], *attr = NULL, *value = NULL;
	size_t name_space_size[4] = {0}, attr_size = 0, value_size = 0;
	const char *hdrs;
	size_t hdrs_size;


	LOG_EV_FMT("...");
	// XXX service version!!!
	if (NULL == svc->actionList)
		return (upnp_http_soap_err_to_cli(cli, 401));
	actionList = svc->actionList;
	for (i = 0; NULL != actionList[i].name; i ++) {
		if (0 == mem_cmpn(soap_act_name, soap_act_name_size,
		    actionList[i].name, actionList[i].name_size)) {
			action = i;
			break;
		}
	}
	if (-1 == action) /* Invalid action. */
		return (upnp_http_soap_err_to_cli(cli, 401));
	LOG_EV_FMT("action: %s", actionList[action].name);
	
	if (0 != xml_get_val_ns_args(req_data, req_data_size, NULL,
	    (uint8_t**)&name_space, (size_t*)&name_space_size,
	    &attr, &attr_size, &value, &value_size,
	    (const uint8_t*)"Envelope", "Body", actionList[action].name, NULL))
		return (upnp_http_soap_err_to_cli(cli, 402));
	LOG_EV_FMT("...");
	for (i = 0; i < 3; i ++) {
		if (63 < name_space_size[i]) /* XML Name space too long. */
			return (upnp_http_soap_err_to_cli(cli, 501));
		memcpy(&ns[i], name_space[i], name_space_size[i]);
		ns[i][name_space_size[i]] = 0;
		LOG_EV_FMT("name space %i: %s", i, ns[i]);
	}
	/* HTTP header. */
	hdrs =
	    "Content-Type: text/xml; charset=\"utf-8\"";
	hdrs_size = strlen(hdrs);
	/* Data. */
	IO_BUF_PRINTF(cli->buf,
	    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	    "<%s:Envelope xmlns:%s=\"http://schemas.xmlsoap.org/soap/envelope/\" %s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n"
	    "	<%s:Body>\n"
	    "		<%s:%sResponse xmlns:%s=\"urn:%s:service:%s:%"PRIu32"\">\n",
	    ns[0], ns[0], ns[0],
	    ns[1],
	    ns[2], actionList[action].name, ns[2], svc->domain_name, svc->type, svc->ver);
	ret_code = svc->ctrl_cb_func(dev, svc, cli, action, value, value_size);
	if (200 != ret_code)
		return (upnp_http_soap_err_to_cli(cli, ret_code));
	IO_BUF_PRINTF(cli->buf,
	    "		</%s:%sResponse>\n"
	    "	</%s:Body>\n"
	    "</%s:Envelope>\n",
	    ns[2], actionList[action].name, ns[1], ns[0]);

	return (http_srv_snd(cli, 200, NULL, 0, hdrs, hdrs_size));
}

