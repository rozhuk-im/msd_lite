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


#include <sys/param.h>

#ifdef __linux__ /* Linux specific code. */
#define _GNU_SOURCE /* See feature_test_macros(7) */
#define __USE_GNU 1
#endif /* Linux specific code. */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>

#ifdef BSD /* BSD specific code. */
#include <sys/uio.h> /* sendfile */
#include <net/if_dl.h>
#endif /* BSD specific code. */

#ifdef __linux__ /* Linux specific code. */
#include <sys/sendfile.h>
//#include <linux/ipv6.h>
#endif /* Linux specific code. */

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <inttypes.h>
#include <unistd.h> /* close, write, sysconf */
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <stdio.h>  /* snprintf, fprintf */
#include <errno.h>

#include "core_macro.h"
#include "core_helpers.h"
#include "core_net_helpers.h"
#include "core_io_net.h"



uintptr_t
io_net_socket(int domain, int type, int protocol) {
	uintptr_t skt;
	int on = 1;

#ifdef SOCK_NONBLOCK_EMULATE /* Standart / BSD */
	skt = socket(domain, (type & ~SOCK_NONBLOCK), protocol);
	if (0 != (SOCK_NONBLOCK & type))
		fd_set_nonblocking(skt, 1);
#else /* Linux / FreeBSD10+ */
	skt = socket(domain, type, protocol);
#endif
	if ((uintptr_t)-1 == skt)
		return (skt);
#ifdef SO_NOSIGPIPE
	setsockopt(skt, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(int));
#endif
	if (AF_INET6 == domain) /* Disable IPv4 via IPv6 socket. */
		setsockopt(skt, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(int));
	return (skt);
}

uintptr_t
io_net_accept(uintptr_t s, struct sockaddr *addr, socklen_t *addrlen, int flags) {
	uintptr_t skt;

#ifdef SOCK_NONBLOCK_EMULATE /* Standart / BSD */
	skt = accept(s, addr, addrlen);
	fd_set_nonblocking(skt, (0 != (SOCK_NONBLOCK & flags)));
#else /* Linux / FreeBSD10+ */
	/*
	 * On Linux, the new socket returned by accept() does not
	 * inherit file status flags such as O_NONBLOCK and O_ASYNC
	 * from the listening socket.
	 */
	skt = accept4(s, addr, addrlen, flags);
#endif
	if ((uintptr_t)-1 == skt)
		return (skt);
#ifdef SO_NOSIGPIPE
	int on = 1;
	setsockopt(skt, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(int));
#endif
	return (skt);
}

int
io_net_bind(struct sockaddr_storage *addr, int type, uintptr_t *skt_ret) {
	uintptr_t skt;
	int error, on = 1;

	if (NULL == addr || NULL == skt_ret)
		return (EINVAL);
		
	skt = io_net_socket(addr->ss_family, (type | SOCK_NONBLOCK), 0);
	if ((uintptr_t)-1 == skt) {
		error = errno;
		goto err_out;
	}
	/* Make reusable: we can fail here, but bind() may success. */
	setsockopt(skt, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));
#ifdef SO_REUSEPORT
	setsockopt(skt, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(int));
#endif
	if (-1 == bind(skt, (struct sockaddr*)addr, sa_type2size(addr))) {
		error = errno;
		goto err_out;
	}
	(*skt_ret) = skt;
	return (0);

err_out:
	/* Error. */
	close(skt);
	return (error);
}

int
io_net_bind_ap(int type, int family, void *addr, uint16_t port, uintptr_t *skt_ret) {
	struct sockaddr_storage sa;
	uintptr_t skt = (uintptr_t)-1;
	int error;

	switch (family) {
	case AF_INET:
		sain4_init(&sa);
		if (NULL != addr)
			sain4_a_set(&sa, addr);
		sain4_p_set(&sa, port);
		break;
	case AF_INET6:
		sain6_init(&sa);
		if (NULL != addr)
			sain6_a_set(&sa, addr);
		sain6_p_set(&sa, port);
		break;
	default:
		return (EINVAL);
		break;
	}
	error = io_net_bind(&sa, type, &skt);

	(*skt_ret) = skt;
	return (error);
}

ssize_t
io_net_recvfrom(uintptr_t skt, void *buf, size_t buf_size, int flags,
    struct sockaddr_storage *from, uint32_t *if_index) {
	ssize_t transfered_size;
	struct msghdr mhdr;
	struct iovec rcviov;
	struct cmsghdr *cm;
	uint8_t rcvcmsgbuf[1024 +
#if defined(IP_RECVIF) /* FreeBSD */
		CMSG_SPACE(sizeof(struct sockaddr_dl))
#endif
#if defined(IP_PKTINFO) /* Linux/win */
		CMSG_SPACE(sizeof(struct in_pktinfo))
#endif
#if (defined(IP_RECVIF) || defined(IP_PKTINFO))
		+
#endif
		CMSG_SPACE(sizeof(struct in6_pktinfo))
		];

	/* Initialize msghdr for receiving packets. */
	//memset(&rcvcmsgbuf, 0, sizeof(struct cmsghdr));
	rcviov.iov_base = buf;
	rcviov.iov_len = buf_size;
	mhdr.msg_name = from; /* dst addr. */
	mhdr.msg_namelen = ((NULL == from) ? 0 : sizeof(struct sockaddr_storage));
	mhdr.msg_iov = &rcviov;
	mhdr.msg_iovlen = 1;
	mhdr.msg_control = rcvcmsgbuf;
	mhdr.msg_controllen = sizeof(rcvcmsgbuf);
	mhdr.msg_flags = 0;

	transfered_size = recvmsg(skt, &mhdr, flags);
	if (-1 == transfered_size || NULL == if_index)
		return (transfered_size);
	(*if_index) = 0;
	/* Handle additional IP packet data. */
	for (cm = CMSG_FIRSTHDR(&mhdr); NULL != cm; cm = CMSG_NXTHDR(&mhdr, cm)) {
#ifdef IP_RECVIF /* FreeBSD */
		if (IPPROTO_IP == cm->cmsg_level &&
		    IP_RECVIF == cm->cmsg_type &&
		    CMSG_LEN(sizeof(struct sockaddr_dl)) <= cm->cmsg_len) {
			MEMCPY_STRUCT_FIELD(if_index, CMSG_DATA(cm),
			    struct sockaddr_dl, sdl_index);
			break;
		}
#endif
#ifdef IP_PKTINFO /* Linux/win */
		if (IPPROTO_IP == cm->cmsg_level &&
		    IP_PKTINFO == cm->cmsg_type &&
		    CMSG_LEN(sizeof(struct in_pktinfo)) <= cm->cmsg_len) {
			MEMCPY_STRUCT_FIELD(if_index, CMSG_DATA(cm),
			    struct in_pktinfo, ipi_ifindex);
			break;
		}
#endif
		if (IPPROTO_IPV6 == cm->cmsg_level && (
#ifdef IPV6_2292PKTINFO
		    IPV6_2292PKTINFO == cm->cmsg_type ||
#endif
		    IPV6_PKTINFO == cm->cmsg_type) &&
		    CMSG_LEN(sizeof(struct in6_pktinfo)) <= cm->cmsg_len) {
			MEMCPY_STRUCT_FIELD(if_index, CMSG_DATA(cm),
			    struct in6_pktinfo, ipi6_ifindex);
			break;
		}
	}
	return (transfered_size);
}


int
io_net_sendfile(uintptr_t fd, uintptr_t skt, off_t offset, size_t size, int flags,
    off_t *transfered_size) {
	int error;

	/* This is for Linux behavour: zero size - do nothing.
	 * Under Linux save 1 syscall. */
	if (0 == size) {
		error = 0;
		goto err_out;
	}

#ifdef BSD /* BSD specific code. */
	if (0 == sendfile(fd, skt, offset, size, NULL, transfered_size, flags))
		return (0); /* OK. */
	/* Error, but some data possible transfered. */
	/* transfered_size - is set by sendfile() */
	return (errno);
#endif /* BSD specific code. */
#ifdef __linux__ /* Linux specific code. */
	ssize_t ios = sendfile(skt, fd, &offset, size);
	if (-1 != ios) { /* OK. */
		if (NULL != transfered_size)
			(*transfered_size) = (off_t)ios;
		return (0);
	}
	/* Error. */
	error = errno;
#endif /* Linux specific code. */

err_out:
	if (NULL != transfered_size)
		(*transfered_size) = 0;
	return (error);
}


int
io_net_mc_join(uintptr_t skt, int join, uint32_t if_index,
    struct sockaddr_storage *mc_addr) {
	struct group_req mc_group;

	if (NULL == mc_addr)
		return (EINVAL);

	/* Join to multicast group. */
	memset(&mc_group, 0, sizeof(mc_group));
	mc_group.gr_interface = if_index;
	sa_copy(mc_addr, &mc_group.gr_group);
	if (0 != setsockopt(skt,
	    ((AF_INET == mc_addr->ss_family) ? IPPROTO_IP : IPPROTO_IPV6),
	    ((0 != join) ? MCAST_JOIN_GROUP : MCAST_LEAVE_GROUP),
	    &mc_group, sizeof(mc_group)))
		return (errno);
	return (0);
}

int
io_net_mc_join_ifname(uintptr_t skt, int join, const char *ifname, size_t ifname_size,
    struct sockaddr_storage *mc_addr) {
	struct ifreq ifr;

	if (NULL == ifname || IFNAMSIZ < ifname_size)
		return (EINVAL);

	// if_nametoindex(ifname);
	memcpy(ifr.ifr_name, ifname, ifname_size);
	ifr.ifr_name[ifname_size] = 0;
	if (-1 == ioctl(skt, SIOCGIFINDEX, &ifr))
		return (errno); /* Cant get if index */

	return (io_net_mc_join(skt, join, ifr.ifr_ifindex, mc_addr));
}

int
io_net_enable_recv_ifindex(uintptr_t skt, int enable) {
	socklen_t addrlen;
	struct sockaddr_storage ssaddr;

	/* First, we detect socket address family: ipv4 or ipv6. */
	ssaddr.ss_family = 0;
	addrlen = sizeof(ssaddr);
	if (0 != getsockname(skt, (struct sockaddr*)&ssaddr, &addrlen))
		return (errno);
	switch (ssaddr.ss_family) {
	case AF_INET:
		if (
#ifdef IP_RECVIF /* FreeBSD */
		    0 != setsockopt(skt, IPPROTO_IP, IP_RECVIF, &enable, sizeof(int))
#endif
#if (defined(IP_RECVIF) && defined(IP_PKTINFO))
		    &&
#endif
#ifdef IP_PKTINFO /* Linux/win */
		    0 != setsockopt(skt, IPPROTO_IP, IP_PKTINFO, &enable, sizeof(int))
#endif
		)
			return (errno);
		break;
	case AF_INET6:
		if (
#ifdef IPV6_RECVPKTINFO /* Not exist in old versions. */
		    0 != setsockopt(skt, IPPROTO_IPV6, IPV6_RECVPKTINFO, &enable, sizeof(int))
#else /* old adv. API */
		    0 != setsockopt(skt, IPPROTO_IPV6, IPV6_PKTINFO, &enable, sizeof(int))
#endif
#ifdef IPV6_2292PKTINFO /* "backup", avail in linux. */
		    && 0 != setsockopt(skt, IPPROTO_IPV6, IPV6_2292PKTINFO, &enable, sizeof(int))
#endif
		)
			return (errno);
		break;
	default:
		return (EAFNOSUPPORT);
		break;
	}
	return (0);
}

int
io_net_rcv_tune(uintptr_t skt, uint32_t buf_size, uint32_t lowat) {

	if (0 == lowat)
		lowat = 1;
	if (0 != setsockopt(skt, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(int)))
		return (errno);
	if (0 != setsockopt(skt, SOL_SOCKET, SO_RCVLOWAT, &lowat, sizeof(int)))
		return (errno);
	return (0);
}

int
io_net_snd_tune(uintptr_t skt, uint32_t buf_size, uint32_t lowat) {

	if (0 == lowat)
		lowat = 1;
	if (0 != setsockopt(skt, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(int)))
		return (errno);
#ifdef BSD /* Linux allways fail on set SO_SNDLOWAT. */
	if (0 != setsockopt(skt, SOL_SOCKET, SO_SNDLOWAT, &lowat, sizeof(int)))
		return (errno);
#endif /* BSD specific code. */
	return (0);
}

/* Set congestion control algorithm for socket. */
int
io_net_set_tcp_cc(uintptr_t skt, const char *cc, size_t cc_size) {

	if (NULL == cc || 0 == cc_size || TCP_CA_NAME_MAX < cc_size)
		return (EINVAL);
	if (0 != setsockopt(skt, IPPROTO_TCP, TCP_CONGESTION, cc, cc_size))
		return (errno);
	return (0);
}

int
io_net_get_tcp_cc(uintptr_t skt, char *cc, size_t cc_size, size_t *cc_size_ret) {
	socklen_t optlen;

	if (NULL == cc || 0 == cc_size)
		return (EINVAL);
	optlen = cc_size;
	if (0 != getsockopt(skt, IPPROTO_TCP, TCP_CONGESTION, cc, &optlen))
		return (errno);
	if (NULL != cc_size_ret)
		(*cc_size_ret) = optlen;
	return (0);
}

int
io_net_get_tcp_maxseg(uintptr_t skt, int *val_ret) {
	socklen_t optlen;

	if (NULL == val_ret)
		return (EINVAL);
	optlen = sizeof(int);
	if (0 != getsockopt(skt, IPPROTO_TCP, TCP_MAXSEG, val_ret, &optlen))
		return (errno);
	return (0);
}

int
io_net_set_tcp_nodelay(uintptr_t skt, int val) {

	if (0 != setsockopt(skt, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val)))
		return (errno);
	return (0);
}

int
io_net_set_tcp_nopush(uintptr_t skt, int val) {

#ifdef TCP_NOPUSH
	if (0 != setsockopt(skt, IPPROTO_TCP, TCP_NOPUSH, &val, sizeof(val)))
		return (errno);
#endif
#ifdef TCP_CORK
	if (0 != setsockopt(skt, IPPROTO_TCP, TCP_CORK, &val, sizeof(val)))
		return (errno);
#endif
	return (0);
}

int
io_net_set_accept_filter(uintptr_t skt, const char *accf, size_t accf_size) {

	if (NULL == accf || 0 == accf_size)
		return (EINVAL);
#ifdef SO_ACCEPTFILTER
	struct accept_filter_arg afa;

	memset(&afa, 0, sizeof(afa));
	accf_size = ((sizeof(afa.af_name) - 1) > accf_size) ?
	    accf_size : (sizeof(afa.af_name) - 1);
	memcpy(afa.af_name, accf, accf_size);
	if (0 != setsockopt(skt, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa)))
		return (errno);
#endif
#ifdef TCP_DEFER_ACCEPT
	int ival = (int)accf_size;
	if (0 != setsockopt(skt, IPPROTO_TCP, TCP_DEFER_ACCEPT, &ival, sizeof(int)))
		return (errno);
#endif
	return (0);
}

int
io_net_listen(uintptr_t skt, int backlog) {

	if (-1 == listen(skt, backlog))
		return (errno);
	return (0);
}

int
io_net_connect(struct sockaddr_storage *addr, uintptr_t *skt_ret) {
	uintptr_t skt;
	int error;

	if (NULL == addr || NULL == skt_ret)
		return (EINVAL);

	skt = io_net_socket(addr->ss_family, (SOCK_STREAM | SOCK_NONBLOCK), 0);
	if ((uintptr_t)-1 == skt) {
		error = errno;
		goto err_out;
	}
	if (-1 == connect(skt, (struct sockaddr*)addr, sa_type2size(addr))) {
		error = errno;
		if (EINPROGRESS != error && EINTR != error)
			goto err_out;
	}

	(*skt_ret) = skt;
	return (0);

err_out:
	/* Error. */
	close(skt);
	return (error);
}

int
io_net_is_connect_error(int error) {

	switch (error) {
#ifdef BSD /* BSD specific code. */
	case EADDRNOTAVAIL:
	case ECONNRESET:
	case EHOSTUNREACH:
#endif /* BSD specific code. */
	case EADDRINUSE:
	case ETIMEDOUT:
	case ENETUNREACH:
	case EALREADY:
	case ECONNREFUSED:
	case EISCONN:
		return (1);
		break;
	}
	return (0);
}


/* Check is congestion control algorithm avaible. */
int
io_net_is_tcp_cc_avail(const char *cc, size_t cc_size) {
	uintptr_t skt;
	int res = 0;

	if (NULL == cc || 0 == cc_size || TCP_CA_NAME_MAX < cc_size)
		return (0);

	skt = socket(AF_INET, SOCK_STREAM, 0);
	if ((uintptr_t)-1 == skt)
		skt = socket(AF_INET6, SOCK_STREAM, 0); /* Re try with IPv6 socket. */
	if ((uintptr_t)-1 == skt)
		return (0);
	res = (0 == setsockopt(skt, IPPROTO_TCP, TCP_CONGESTION, cc, cc_size));
	close(skt);
	return (res);
}


/*
 * Very simple resolver
 * work slow, block thread, has no cache
 * ai_family: PF_UNSPEC, AF_INET, AF_INET6
 */
int
io_net_sync_resolv(const char *hname, uint16_t port, int ai_family,
    struct sockaddr_storage *addrs, size_t addrs_count, size_t *addrs_count_ret) {
	int error;
	size_t i;
	struct addrinfo hints, *res, *res0;
	char servname[8];

	if (NULL == hname)
		return (EINVAL);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = ai_family;
	hints.ai_flags = AI_NUMERICSERV;
	snprintf(servname, sizeof(servname),"%hu", port);
	error = getaddrinfo(hname, servname, &hints, &res0);
	if (0 != error)  /* NOTREACHED */
		return (error);
	for (i = 0, res = res0; NULL != res && i < addrs_count; res = res->ai_next, i ++) {
		if (AF_INET != res->ai_family && AF_INET6 != res->ai_family)
			continue;
		sa_copy(res->ai_addr, &addrs[i]);
	}
	freeaddrinfo(res0);
	if (NULL != addrs_count_ret)
		(*addrs_count_ret) = i;
	return (0);
}

int
io_net_sync_resolv_connect(const char *hname, uint16_t port, int ai_family,
    uintptr_t *skt_ret) {
	int error = 0;
	uintptr_t skt = (uintptr_t)-1;
	struct addrinfo hints, *res, *res0;
	char servname[8];

	if (NULL == hname || NULL == skt_ret)
		return (EINVAL);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = ai_family;
	hints.ai_flags = AI_NUMERICSERV;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(servname, sizeof(servname),"%hu", port);
	error = getaddrinfo(hname, servname, &hints, &res0);
	if (0 != error)  /* NOTREACHED */
		return (error);
	for (res = res0; NULL != res; res = res->ai_next) {
		skt = io_net_socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if ((uintptr_t)-1 == skt) {
			error = errno;
			continue;
		}
		if (connect(skt, res->ai_addr, res->ai_addrlen) < 0) {
			error = errno;
			close(skt);
			skt = (uintptr_t)-1;
			continue;
		}
		break;  /* okay we got one */
	}
	freeaddrinfo(res0);
	if ((uintptr_t)-1 == skt)
		return (error);
	(*skt_ret) = skt;
	return (0);
}


