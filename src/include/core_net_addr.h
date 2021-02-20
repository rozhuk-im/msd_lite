/*-
 * Copyright (c) 2011 - 2012 Rozhuk Ivan <rozhuk.im@gmail.com>
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



#ifndef __CORE_NET_ADDR_H__
#define __CORE_NET_ADDR_H__


#define CORE_NET_ADDR_PREALLOC	8



typedef struct net_addr_v4 {
	struct in_addr	addr;
	struct in_addr	mask;
} net_addr_v4_t;


typedef struct net_addr_v6 {
	struct in6_addr	addr;
	struct in6_addr	mask;
} net_addr_v6_t;



typedef struct net_addr_list {
	size_t		v4_allocated;
	size_t		v4_count;
	net_addr_v4_t	*v4;

	size_t		v6_allocated;
	size_t		v6_count;
	net_addr_v6_t	*v6;
} net_addrs_t, *net_addrs_p;




net_addrs_p net_addrs_alloc(void);
void	net_addrs_free(net_addrs_p net_addr);
int	net_addrs_add_str(net_addrs_p net_addr, const char *buf, size_t buf_size);
int	net_addrs_add(net_addrs_p net_addr, const struct sockaddr_storage *net,
	    const uint16_t preflen);
int	net_addrs_is_in_net(net_addrs_p net_addr, const struct sockaddr_storage *addr);










#endif /* __CORE_NET_ADDR_H__ */
