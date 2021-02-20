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



#ifndef __CORE_NET_ADDR_H__
#define __CORE_NET_ADDR_H__

#include <sys/param.h>
#ifdef __linux__ /* Linux specific code. */
#	define _GNU_SOURCE /* See feature_test_macros(7) */
#	define __USE_GNU 1
#endif /* Linux specific code. */
#include <sys/types.h>
#include <errno.h>
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <stdlib.h> /* malloc, exit */

#include "macro_helpers.h"
#include "mem_helpers.h"
#include "core_net_helpers.h"


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




static inline net_addrs_p
net_addrs_alloc(void) {

	return (zalloc(sizeof(net_addrs_t)));
}


static inline void
net_addrs_free(net_addrs_p net_addr) {

	if (NULL == net_addr)
		return;

	if (NULL != net_addr->v4)
		free(net_addr->v4);
	if (NULL != net_addr->v6)
		free(net_addr->v6);
	free(net_addr);
}


static inline int
net_addrs_add_str(net_addrs_p net_addr, const char *buf, size_t buf_size) {
	int error;
	uint16_t preflen;
	struct sockaddr_storage net;

	error = str_net_to_ss(buf, buf_size, &net, &preflen);
	if (0 != error)
		return (error);
	error = net_addrs_add(net_addr, &net, preflen);

	return (error);
}

static inline int
net_addrs_add(net_addrs_p net_addr, const struct sockaddr_storage *net,
    const uint16_t preflen) {
	int error;
	size_t i;
	struct in_addr	mask4;
	struct in6_addr	mask6;


	if (NULL == net_addr || NULL == net)
		return (EINVAL);

	// is we need to add ?
	switch (net->ss_family) {
	case AF_INET:
		error = inet_len2mask(preflen, &mask4);
		if (0 != error)
			return (error);
		/* Is allready added? */
		for (i = 0; i < net_addr->v4_count; i ++) {
			if (0 != memcmp(&((struct sockaddr_in*)net)->sin_addr,
			    &net_addr->v4[i].addr, sizeof(struct in_addr)) ||
			    0 != memcmp(&mask4, &net_addr->v4[i].mask,
			    sizeof(struct in_addr)))
				continue;
			return (0);// allready added
		}
		// need more space?
		error = realloc_items((void**)&net_addr->v4,
		    sizeof(net_addr_v4_t), &net_addr->v4_allocated,
		    CORE_NET_ADDR_PREALLOC, net_addr->v4_count);
		if (0 != error)
			return (error);
		// copy new data to list
		memcpy(&net_addr->v4[net_addr->v4_count].addr,
		    &((struct sockaddr_in*)net)->sin_addr, sizeof(struct in_addr));
		memcpy(&net_addr->v4[net_addr->v4_count].mask, &mask4,
		    sizeof(struct in_addr));
		net_addr_truncate_mask(AF_INET,
		    (uint32_t*)&net_addr->v4[net_addr->v4_count].addr,
		    (uint32_t*)&net_addr->v4[net_addr->v4_count].mask);
		net_addr->v4_count ++;
		break;
	case AF_INET6:
		error = inet6_len2mask(preflen, &mask6);
		if (0 != error)
			return (error);
		/* Is allready added? */
		for (i = 0; i < net_addr->v6_count; i ++) {
			if (0 != memcmp(&((struct sockaddr_in6*)net)->sin6_addr,
			    &net_addr->v6[i].addr, sizeof(struct in6_addr)) ||
			    0 != memcmp(&mask6, &net_addr->v6[i].mask,
			    sizeof(struct in6_addr)))
				continue;
			return (0);// allready added!
		}
		// need more space?
		error = realloc_items((void**)&net_addr->v6,
		    sizeof(net_addr_v6_t), &net_addr->v6_allocated,
		    CORE_NET_ADDR_PREALLOC, net_addr->v6_count);
		if (0 != error)
			return (error);
		// copy new data to list
		memcpy(&net_addr->v6[net_addr->v6_count].addr,
		    &((struct sockaddr_in6*)net)->sin6_addr, sizeof(struct in6_addr));
		memcpy(&net_addr->v6[net_addr->v6_count].mask, &mask6,
		    sizeof(struct in6_addr));
		net_addr_truncate_mask(AF_INET6,
		    (uint32_t*)&net_addr->v6[net_addr->v6_count].addr,
		    (uint32_t*)&net_addr->v6[net_addr->v6_count].mask);
		net_addr->v6_count ++;
		break;
	default:
		return (EINVAL);
		break;
	}

	return (0);
}


static inline int
net_addrs_is_in_net(net_addrs_p net_addr, const struct sockaddr_storage *addr) {
	size_t i;

	if (NULL == net_addr || NULL == addr)
		return (0);

	switch (addr->ss_family) {
	case AF_INET:
		for (i = 0; i < net_addr->v4_count; i ++) {
			if (0 != is_addr_in_net(AF_INET,
			    (uint32_t*)&net_addr->v4[i].addr,
			    (uint32_t*)&net_addr->v4[i].mask,
			    (uint32_t*)&((struct sockaddr_in*)addr)->sin_addr))
				return (1);
		}
		break;
	case AF_INET6:
		for (i = 0; i < net_addr->v6_count; i ++) {
			if (0 != is_addr_in_net(AF_INET6,
			    (uint32_t*)&net_addr->v6[i].addr,
			    (uint32_t*)&net_addr->v6[i].mask,
			    (uint32_t*)&((struct sockaddr_in6*)addr)->sin6_addr))
				return (1);
		}
		break;
	}

	return (0);
}



#endif /* __CORE_NET_ADDR_H__ */
