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


#ifndef __CORE_UPNP_DEV_H__
#define __CORE_UPNP_DEV_H__

#include "core_upnp_base.h"
#include "core_upnp_svc_cntnt_dir.h"
#include "core_upnp_svc_conn_mngr.h"
#include "core_upnp_svc_ms_media_rcvr_reg.h"



static upnp_service_p upnp_media_srv_svcs[] = {
	&upnp_svc_cntnt_dir,
	&upnp_svc_conn_mngr,
	&upnp_svc_ms_media_rcvr,
	NULL
};

static upnp_icon_t upnp_media_srv_icons[] = {
	{
		.mimetype = "png",
		.height = 48,
		.width = 48,
		.depth = 8,
		.url = "icon-48x48.png"
	},{
		.mimetype = NULL,
		.height = 0,
		.width = 0,
		.depth = 0,
		.url = NULL
	}
};

static upnp_device_t upnp_deviceList[] = {
	{
		.uuid = "89c11c71-ba2a-56ee-6fd1-830ff56f149f",
		.domain_name = "schemas-upnp-org",
		.type = "MediaServer",
		.ver = 3,
		.serviceList = upnp_media_srv_svcs,
		.deviceList = NULL,
		/* 2. Description */
		.friendlyName = "MediaServer",
		.manufacturer = "Rozhuk Ivan",
		.manufacturerURL = "http://www.netlab.linkpc.net",
		.modelDescription = "UPnP media service for sharing content.",
		.modelName = "mc2http UPnP sevice",
		.modelNumber = "1.0",
		.modelURL = "http://www.netlab.linkpc.net/forum/",
		.serialNumber = "1",
		// ->uuid UDN
		.UPC = "",
		.iconList = upnp_media_srv_icons,
		// -> serviceList serviceList
		// -> deviceList deviceList
		.ssdp_dev = NULL,
	},{
		.uuid = NULL,
		.domain_name = NULL,
		.type = NULL,
		.ver = 0,
		.serviceList = NULL,
		.deviceList = NULL,
		.ssdp_dev = NULL,
	}
};



#endif // __CORE_UPNP_DEV_H__
