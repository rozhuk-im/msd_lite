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

 
#ifndef __CORE_IO_NET_H__
#define __CORE_IO_NET_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "core_thrp.h"

#ifndef TCP_CA_NAME_MAX /* For stupid linux. */
#define TCP_CA_NAME_MAX 16
#endif

/* EBUSY - for sendfile() */
#define IO_NET_ERR_FILTER(error)						\
    ((EAGAIN == error || EWOULDBLOCK == error || EBUSY == error || EINTR == error) ? \
    0 : error)



typedef struct socket_options_s {
	uint32_t	mask;		/* Flags: mask to set */
	uint32_t	bit_vals;	/* Bitmask values for: SO_F_BIT_VAL_MASK */
	int		backlog;	/* Listen queue len. */
	uint32_t	rcv_buf;	/* SO_RCVBUF kb */
	uint32_t	rcv_lowat;	/* SO_RCVLOWAT kb */
	uint64_t	rcv_timeout;	/* SO_RCVTIMEO sec */
	uint32_t	snd_buf;	/* SO_SNDBUF kb */
	uint32_t	snd_lowat;	/* SO_SNDLOWAT kb */
	uint64_t	snd_timeout;	/* SO_SNDTIMEO sec */
#ifdef SO_ACCEPTFILTER
	struct accept_filter_arg tcp_acc_filter; /* SO_ACCEPTFILTER */
#elif defined(TCP_DEFER_ACCEPT)
	uint32_t	tcp_acc_defer;	/* TCP_DEFER_ACCEPT sec */
#endif
	uint32_t	tcp_keep_idle;	/* TCP_KEEPIDLE only if SO_KEEPALIVE set */
	uint32_t	tcp_keep_intvl;	/* TCP_KEEPINTVL only if SO_KEEPALIVE set */
	uint32_t	tcp_keep_cnt;	/* TCP_KEEPCNT only if SO_KEEPALIVE set */
	char 		tcp_cc[TCP_CA_NAME_MAX]; /* TCP congestion control TCP_CONGESTION. */
	socklen_t	tcp_cc_size;
} skt_opts_t, *skt_opts_p;

#define SO_F_NONBLOCK		(((uint32_t)1) <<  0) /* SOCK_NONBLOCK */
#define SO_F_HALFCLOSE_RD	(((uint32_t)1) <<  1) /* shutdown(SHUT_RD) */
#define SO_F_HALFCLOSE_WR	(((uint32_t)1) <<  2) /* shutdown(SHUT_WR) */
#define SO_F_HALFCLOSE_RDWR	(SO_F_HALFCLOSE_RD | SO_F_HALFCLOSE_WR) /* shutdown(SHUT_RDWR) */
#define SO_F_BACKLOG		(((uint32_t)1) <<  3) /* backlog is readed from config. */
#define SO_F_BROADCAST		(((uint32_t)1) <<  4) /* SO_BROADCAST */
#define SO_F_REUSEADDR		(((uint32_t)1) <<  5) /* SO_REUSEADDR */
#define SO_F_REUSEPORT		(((uint32_t)1) <<  6) /* SO_REUSEPORT */
#define SO_F_KEEPALIVE		(((uint32_t)1) <<  7) /* SO_KEEPALIVE */
#define SO_F_RCVBUF		(((uint32_t)1) <<  8) /* SO_RCVBUF */
#define SO_F_RCVLOWAT		(((uint32_t)1) <<  9) /* SO_RCVLOWAT */
#define SO_F_RCVTIMEO		(((uint32_t)1) << 10) /* SO_RCVTIMEO - no set to skt */
#define SO_F_SNDBUF		(((uint32_t)1) << 11) /* SO_SNDBUF */
#define SO_F_SNDLOWAT		(((uint32_t)1) << 12) /* SO_SNDLOWAT */
#define SO_F_SNDTIMEO		(((uint32_t)1) << 13) /* SO_SNDTIMEO - no set to skt */

#define SO_F_ACC_FILTER		(((uint32_t)1) << 15) /* SO_ACCEPTFILTER(httpready) / TCP_DEFER_ACCEPT */
#define SO_F_TCP_KEEPIDLE	(((uint32_t)1) << 16) /* TCP_KEEPIDLE only if SO_KEEPALIVE set */
#define SO_F_TCP_KEEPINTVL	(((uint32_t)1) << 17) /* TCP_KEEPINTVL only if SO_KEEPALIVE set */
#define SO_F_TCP_KEEPCNT	(((uint32_t)1) << 18) /* TCP_KEEPCNT only if SO_KEEPALIVE set */
#define SO_F_TCP_NODELAY	(((uint32_t)1) << 19) /* TCP_NODELAY */
#define SO_F_TCP_NOPUSH		(((uint32_t)1) << 20) /* TCP_NOPUSH / TCP_CORK */
#define SO_F_TCP_CONGESTION	(((uint32_t)1) << 21) /* TCP_CONGESTION */

#define SO_F_FAIL_ON_ERR	(((uint32_t)1) << 31) /* Return on first set error. */

#define SO_F_KEEPALIVE_MASK	(SO_F_KEEPALIVE | SO_F_TCP_KEEPIDLE |	\
				SO_F_TCP_KEEPINTVL | SO_F_TCP_KEEPCNT)

#define SO_F_BIT_VALS_MASK	(SO_F_NONBLOCK | SO_F_BROADCAST |	\
				SO_F_REUSEADDR | SO_F_REUSEPORT | 	\
				SO_F_KEEPALIVE | SO_F_ACC_FILTER |	\
				SO_F_TCP_NODELAY | SO_F_TCP_NOPUSH)
#define SO_F_ALL_MASK		(0xffffffff & ~SO_F_FAIL_ON_ERR)
/* Apply masks. */
/* AF = after bind */
#define SO_F_RCV_MASK		(SO_F_RCVBUF | SO_F_RCVLOWAT | SO_F_RCVTIMEO)
#define SO_F_SND_MASK		(SO_F_SNDBUF | SO_F_SNDLOWAT | SO_F_SNDTIMEO)
#define SO_F_UDP_BIND_AF_MASK	(SO_F_RCV_MASK | SO_F_SND_MASK)
#define SO_F_TCP_ES_CONN_MASK	(SO_F_HALFCLOSE_RDWR |			\
				SO_F_KEEPALIVE_MASK |			\
				SO_F_RCV_MASK |				\
				SO_F_SND_MASK |				\
				SO_F_TCP_NODELAY |			\
				SO_F_TCP_NOPUSH |			\
				SO_F_TCP_CONGESTION)
/* AF = after listen */
#define SO_F_TCP_LISTEN_AF_MASK	(SO_F_ACC_FILTER | SO_F_KEEPALIVE_MASK)

#ifdef IO_NET_XML_CONFIG
int	io_net_skt_opts_xml_load(const uint8_t *buf, size_t buf_size,
	    uint32_t mask, skt_opts_p opts);
#endif
void	io_net_skt_opts_init(uint32_t mask, uint32_t bit_vals, skt_opts_p opts);
void	io_net_skt_opts_cvt(int mult, skt_opts_p opts);
#define IO_NET_SKT_OPTS_MULT_NONE	0
#define IO_NET_SKT_OPTS_MULT_K		1
#define IO_NET_SKT_OPTS_MULT_M		2
#define IO_NET_SKT_OPTS_MULT_G		3

int	io_net_skt_opts_set_ex(uintptr_t skt, uint32_t mask,
	    skt_opts_p opts, uint32_t *err_mask);
int	io_net_skt_opts_set(uintptr_t skt, uint32_t mask, uint32_t bit_vals);
/* Set only SO_F_BIT_VALS_MASK. */

#define IO_NET_SKT_OPTS_GET_FLAGS_VALS(opts, fmask)			\
	    ((fmask) & SO_F_BIT_VALS_MASK & (opts)->mask & (opts)->bit_vals)
#define IO_NET_SKT_OPTS_IS_FLAG_ACTIVE(opts, flag)			\
	    (0 != ((flag) & (opts)->mask & (opts)->bit_vals))


int	io_net_rcv_tune(uintptr_t skt, uint32_t buf_size, uint32_t lowat);
int	io_net_snd_tune(uintptr_t skt, uint32_t buf_size, uint32_t lowat);
int	io_net_set_tcp_cc(uintptr_t skt, const char *cc, size_t cc_size);
int	io_net_get_tcp_cc(uintptr_t skt, char *cc, size_t cc_size, size_t *cc_size_ret);
int	io_net_is_tcp_cc_avail(const char *cc, size_t cc_size);
int	io_net_get_tcp_maxseg(uintptr_t skt, int *val_ret);
int	io_net_set_tcp_nodelay(uintptr_t skt, int val);
int	io_net_set_tcp_nopush(uintptr_t skt, int val);
int	io_net_set_accept_filter(uintptr_t skt, const char *accf, size_t accf_size);
int	io_net_enable_recv_ifindex(uintptr_t skt, int enable);

int	io_net_mc_join(uintptr_t skt, int join, uint32_t if_index,
	    const struct sockaddr_storage *mc_addr);
int	io_net_mc_join_ifname(uintptr_t skt, int join, const char *ifname,
	    size_t ifname_size, const struct sockaddr_storage *mc_addr);



int	io_net_socket(int domain, int type, int protocol, uint32_t flags,
	    uintptr_t *skt_ret);
int	io_net_accept(uintptr_t skt, struct sockaddr_storage *addr,
	    socklen_t *addrlen, uint32_t flags, uintptr_t *skt_ret);
#define  IO_NET_SKT_FLAG_MASK	(SO_F_NONBLOCK | SO_F_BROADCAST)

int	io_net_bind(const struct sockaddr_storage *addr, int type,
	    int protocol, uint32_t flags, uintptr_t *skt_ret);
int	io_net_bind_ap(int family, void *addr, uint16_t port,
	    int type, int protocol, uint32_t flags, uintptr_t *skt_ret);
#define  IO_NET_BIND_FLAG_MASK	(IO_NET_SKT_FLAG_MASK | SO_F_REUSEADDR | SO_F_REUSEPORT)

int	io_net_listen(uintptr_t skt, int backlog);

int	io_net_connect(const struct sockaddr_storage *addr,
	    int type, int protocol, uint32_t flags, uintptr_t *skt_ret);
int	io_net_is_connect_error(int error);

int	io_net_sync_resolv(const char *hname, uint16_t port, int ai_family,
	    struct sockaddr_storage *addrs, size_t addrs_count,
	    size_t *addrs_count_ret);
int	io_net_sync_resolv_connect(const char *hname, uint16_t port,
	    int domain, int type, int protocol, uintptr_t *skt_ret);

ssize_t	io_net_recvfrom(uintptr_t skt, void *buf, size_t buf_size, int flags,
	    struct sockaddr_storage *from, uint32_t *if_index);

int	io_net_sendfile(uintptr_t fd, uintptr_t skt, off_t offset, size_t size,
	    int flags, off_t *transfered_size);
#ifdef BSD /* BSD specific code. */
#define IO_NET_SF_F_NODISKIO	SF_NODISKIO
#define IO_NET_SF_F_MNOWAIT	SF_MNOWAIT
#define IO_NET_SF_F_SYNC	SF_SYNC
#else /* BSD specific code. */
#define IO_NET_SF_F_NODISKIO	0
#define IO_NET_SF_F_MNOWAIT	0
#define IO_NET_SF_F_SYNC	0
#endif


#endif /* __CORE_IO_NET_H__ */
