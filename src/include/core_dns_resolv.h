/*-
 * Copyright (c) 2011 - 2016 Rozhuk Ivan <rozhuk.im@gmail.com>
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


#ifndef __CORE_DNS_RESOLV_H__
#define __CORE_DNS_RESOLV_H__


#include "core_thrp.h"



typedef struct dns_rslvr_s	*dns_rslvr_p; /* thread pool */
typedef struct dns_rslvr_task_s	*dns_rslvr_task_p; /* thread pool */

#define DNS_R_F_IPV4	(((uint16_t)1) << 0) /* IPv4 */
#define DNS_R_F_IPV6	(((uint16_t)1) << 1) /* IPv6 */
#define DNS_R_F_IP_ALL	(DNS_R_F_IPV4 | DNS_R_F_IPV6)



typedef int (*dns_resolv_cb)(dns_rslvr_task_p task, int error,
    struct sockaddr_storage *addrs, size_t addrs_count, void *arg);

int	dns_resolver_create(thrp_p thrp, const struct sockaddr_storage *dns_addrs,
	    uint16_t dns_addrs_count, uintptr_t timeout, uint16_t retry_count,
	    uint32_t neg_cache, dns_rslvr_p *dns_rslvr_ret);
void	dns_resolver_destroy(dns_rslvr_p rslvr);

thrpt_p	dns_resolver_thrpt_get(dns_rslvr_p rslvr);
int	dns_resolver_cache_text_dump(dns_rslvr_p rslvr, char *buf, size_t buf_size,
	    size_t *size_ret);

int	dns_resolv_hostaddr(dns_rslvr_p rslvr, uint8_t *name, size_t name_size,
	    uint16_t flags, dns_resolv_cb cb_func, void *arg,
	    dns_rslvr_task_p *task_ret);
void	dns_resolv_cancel(dns_rslvr_task_p task);




#endif // __CORE_DNS_RESOLV_H__
