/*-
 * Copyright (c) 2012 Rozhuk Ivan <rozhuk.im@gmail.com>
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


#ifndef __CORE_SAP_RECEIVER_H__
#define __CORE_SAP_RECEIVER_H__


#include "core_thrp.h"

typedef struct sap_rcvr_s	*sap_rcvr_p;


int	sap_receiver_create(thrp_p thp, uint32_t skt_recv_buf_size,
	    uint32_t cache_time, uint32_t cache_clean_interval,
	    sap_rcvr_p *sap_rcvr_ret);
void	sap_receiver_destroy(sap_rcvr_p srcvr);
int	sap_receiver_listener_add4(sap_rcvr_p srcvr, const char *ifname,
	    size_t ifname_size, const char *mcaddr, size_t mcaddr_size);

//int	sap_receiver_cache_text_dump(sap_rcvr_p srcvr, char *buf, size_t buf_size,
//	    size_t *size_ret);




#endif // __CORE_SAP_RECEIVER_H__
