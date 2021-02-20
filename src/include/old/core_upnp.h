/*-
 * Copyright (c) 2012 - 2013 Rozhuk Ivan <rozhuk.im@gmail.com>
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


#ifndef __CORE_UPNP_H__
#define __CORE_UPNP_H__

#include "core_thrp.h"
#include "core_upnp_base.h"
#include "core_upnp_ssdp.h"
#include "core_http_srv.h"


typedef struct upnp_s *upnp_p;



int	upnp_create(thrp_p thp, upnp_ssdp_settings_p ssdpd_s,
	    http_srv_settings_p http_s, uint16_t port, uint16_t backlog,
	    char *accf, size_t accf_size, uint32_t max_age, uint32_t ann_interval,
	    upnp_p *upnp_ret);
void	upnp_destroy(upnp_p upnp);

int	upnp_iface_add(upnp_p upnp, const char *if_name, size_t if_name_size,
	    const char *if_ann_name, size_t if_ann_name_size);
	/* if_name - iface were announces send,
	 * if_ann_name - iface for get addrs to announce.
	 */
void	upnp_send_notify(upnp_p upnp);


#endif // __CORE_UPNP_H__
