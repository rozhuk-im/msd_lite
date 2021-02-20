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



#ifndef __CORE_NET_HELPERS_H__
#define __CORE_NET_HELPERS_H__

#include <sys/param.h>

#ifdef __linux__ /* Linux specific code. */
#define _GNU_SOURCE /* See feature_test_macros(7) */
#define __USE_GNU 1
#endif /* Linux specific code. */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#ifndef TCP_CA_NAME_MAX /* For stupid linux. */
#define TCP_CA_NAME_MAX 16
#endif

#define STR_ADDR_LEN	64

#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

#ifndef IN_LOOPBACK
#define IN_LOOPBACK(i)		(((u_int32_t)(i) & 0xff000000) == 0x7f000000)
#endif

#ifndef in_nullhost
#define	in_nullhost(x)	((x).s_addr == INADDR_ANY)
#endif

#ifndef ifr_ifindex
#define ifr_ifindex ifr_ifru.ifru_index
#endif

/* EBUSY - for sendfile() */
#define NET_IO_ERR_FILTER(error)						\
    ((EAGAIN == error || EWOULDBLOCK == error || EBUSY == error || EINTR == error) ? \
    0 : error)



#ifdef DEBUG_gfhjfg
#define sain4_t	struct sockaddr_in *
#define sain6_t	struct sockaddr_in6 *
#else
#define sain4_t	void *
#define sain6_t	void *
#endif


void	sa_copy(const void *src, void *dst);
size_t	sa_type2size(void *addr);
void	*sa_type2addr(void *addr);
size_t	sa_type2addrsize(void *addr);
uint16_t sa_get_port(void *addr);
uint32_t sa_hash32(void *addr);
int	sa_is_addr_loopback(void *addr);
int	sa_is_addr_specified(void *addr);
int	is_soaddrs_euqual(const void *addr1, const void *addr2);
int	is_addrs_euqual(const void *addr1, const void *addr2);

void	net_addr_truncate_preflen(struct sockaddr_storage *net_addr, uint16_t preflen);
void	net_addr_truncate_mask(int family, uint32_t *net, uint32_t *mask);
int	is_addr_in_net(int family, const uint32_t *net, const uint32_t *mask,
	    const uint32_t *addr);

int	inet_len2mask(int len, struct in_addr *mask);
int	inet_mask2len(const struct in_addr *mask);

int	inet6_len2mask(int len, struct in6_addr *mask);
int	inet6_mask2len(const struct in6_addr *mask);

int	str_net_to_ss(const char *buf, size_t buf_size, struct sockaddr_storage *addr,
	    uint16_t *preflen_ret);
int	str_addr_port_to_ss(const char *buf, size_t buf_size,
	    struct sockaddr_storage *addr);
int	ss_to_str_addr(struct sockaddr_storage *addr, char *buf, size_t buf_size,
	    size_t *buf_size_ret);
int	ss_to_str_addr_port(struct sockaddr_storage *addr, char *buf, size_t buf_size,
	    size_t *buf_size_ret);

int	get_if_addr_by_name(const char *if_name, size_t if_name_size, sa_family_t family,
	    struct sockaddr_storage *addr);
int	is_host_addr(struct sockaddr_storage *addr);
int	is_host_addr_ex(struct sockaddr_storage *addr, void **data);
void	is_host_addr_ex_free(void *data);

size_t	iovec_calc_size(struct iovec *iov, size_t iov_cnt);
void	iovec_set_offset(struct iovec *iov, size_t iov_cnt, size_t iov_off);


static inline void
sain4_init(sain4_t addr) {

	memset(addr, 0, sizeof(struct sockaddr_in));
#ifdef BSD /* BSD specific code. */
	((struct sockaddr_in*)addr)->sin_len = sizeof(struct sockaddr_in);
#endif /* BSD specific code. */
	((struct sockaddr_in*)addr)->sin_family = AF_INET;
	//addr->sin_port = 0;
	//addr->sin_addr
}

static inline void
sain4_p_set(sain4_t addr, uint16_t port) {
	((struct sockaddr_in*)addr)->sin_port = htons(port);
}

static inline uint16_t
sain4_p_get(sain4_t addr) {
	return (ntohs(((struct sockaddr_in*)addr)->sin_port));
}

static inline void
sain4_a_set(sain4_t addr, void *sin_addr) {
	memcpy(&((struct sockaddr_in*)addr)->sin_addr, sin_addr,
	    sizeof(struct in_addr));
}

static inline void
sain4_a_set_val(sain4_t addr, uint32_t sin_addr) {
	((struct sockaddr_in*)addr)->sin_addr.s_addr = sin_addr;
}


static inline void
sain4_astr_set(sain4_t addr, const char *straddr) {
	((struct sockaddr_in*)addr)->sin_addr.s_addr = inet_addr(straddr);
}


static inline void
sain6_init(sain6_t addr) {

	memset(addr, 0, sizeof(struct sockaddr_in6));
#ifdef BSD /* BSD specific code. */
	((struct sockaddr_in6*)addr)->sin6_len = sizeof(struct sockaddr_in6);
#endif /* BSD specific code. */
	((struct sockaddr_in6*)addr)->sin6_family = AF_INET6;
	//((struct sockaddr_in6*)addr)->sin6_port = 0;
	//((struct sockaddr_in6*)addr)->sin6_flowinfo = 0;
	//((struct sockaddr_in6*)addr)->sin6_addr
	//((struct sockaddr_in6*)addr)->sin6_scope_id = 0;
}

static inline void
sain6_p_set(sain6_t addr, uint16_t port) {
	((struct sockaddr_in6*)addr)->sin6_port = htons(port);
}

static inline uint16_t
sain6_p_get(sain6_t addr) {
	return (ntohs(((struct sockaddr_in6*)addr)->sin6_port));
}

static inline void
sain6_a_set(sain6_t addr, void *sin6_addr) {
	memcpy(&((struct sockaddr_in6*)addr)->sin6_addr, sin6_addr,
	    sizeof(struct in6_addr));
}



/* IPv4/IPv6 auto. */
static inline void
sain_p_set(struct sockaddr_storage *addr, uint16_t port) {

	switch (addr->ss_family) {
	case AF_INET:
		sain4_p_set((sain4_t)addr, port);
		return;
		break;
	case AF_INET6:
		sain6_p_set((sain6_t)addr, port);
		return;
		break;
	}
}

static inline uint16_t
sain_p_get(struct sockaddr_storage *addr) {

	switch (addr->ss_family) {
	case AF_INET:
		return (sain4_p_get((sain4_t)addr));
		break;
	case AF_INET6:
		return (sain6_p_get((sain6_t)addr));
		break;
	}
	return (0);
}



#endif /* __CORE_NET_HELPERS_H__ */
