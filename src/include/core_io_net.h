/*-
 * Copyright (c) 2011 - 2014 Rozhuk Ivan <rozhuk.im@gmail.com>
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

 
#ifndef __CORE_IO_NET_H__
#define __CORE_IO_NET_H__


#include "core_thrp.h"


/*
 * callback then new connection received
 */
int	io_net_bind(struct sockaddr_storage *addr, int type, uintptr_t *skt_ret);
int	io_net_bind_ap(int type, int family, void *addr, uint16_t port,
	    uintptr_t *skt_ret);
ssize_t	io_net_recvfrom(uintptr_t skt, void *buf, size_t buf_size, int flags,
	    struct sockaddr_storage *from, uint32_t *if_index);

#ifdef BSD /* BSD specific code. */
#define IO_NET_SF_F_NODISKIO	SF_NODISKIO
#define IO_NET_SF_F_MNOWAIT	SF_MNOWAIT
#define IO_NET_SF_F_SYNC	SF_SYNC
#else /* BSD specific code. */
#define IO_NET_SF_F_NODISKIO	0
#define IO_NET_SF_F_MNOWAIT	0
#define IO_NET_SF_F_SYNC	0
#endif
int	io_net_sendfile(uintptr_t fd, uintptr_t skt, off_t offset, size_t size,
	    int flags, off_t *transfered_size);

int	io_net_mc_join(uintptr_t skt, int join, uint32_t if_index,
	    struct sockaddr_storage *mc_addr);
int	io_net_mc_join_ifname(uintptr_t skt, int join, const char *ifname,
	    size_t ifname_size, struct sockaddr_storage *mc_addr);

int	io_net_enable_recv_ifindex(uintptr_t skt, int enable);
int	io_net_rcv_tune(uintptr_t skt, uint32_t buf_size, uint32_t lowat);
int	io_net_snd_tune(uintptr_t skt, uint32_t buf_size, uint32_t lowat);
int	io_net_set_tcp_cc(uintptr_t skt, const char *cc, size_t cc_size);
int	io_net_get_tcp_cc(uintptr_t skt, char *cc, size_t cc_size, size_t *cc_size_ret);
int	io_net_get_tcp_maxseg(uintptr_t skt, int *val_ret);
int	io_net_set_tcp_nodelay(uintptr_t skt, int val);
int	io_net_set_tcp_nopush(uintptr_t skt, int val);
int	io_net_set_accept_filter(uintptr_t skt, const char *accf, size_t accf_size);

int	io_net_listen(uintptr_t skt, int backlog);

int	io_net_connect(struct sockaddr_storage *addr, uintptr_t *skt_ret);
int	io_net_is_connect_error(int error);

int	io_net_is_tcp_cc_avail(const char *cc, size_t cc_size);

int	io_net_sync_resolv(const char *hname, uint16_t port, int ai_family,
	    struct sockaddr_storage *addrs, size_t addrs_count,
	    size_t *addrs_count_ret);
int	io_net_sync_resolv_connect(const char *hname, uint16_t port, int ai_family,
	    uintptr_t *skt_ret);


#endif // __CORE_IO_NET_H__
