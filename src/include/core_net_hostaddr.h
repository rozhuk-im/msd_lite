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


#ifndef __CORE_HOST_ADDR_H__
#define __CORE_HOST_ADDR_H__


#define HOST_ADDR_PREALLOC	8



typedef struct host_addr_s {
	struct sockaddr_storage *addrs;	/* proto:addr:port */
	uint8_t		*name;		/* Hostname. */
	uint16_t	name_size;	/* Host name size. */
	uint16_t	port;		/* Port. */
	uint16_t	allocated;	/* Num of avaible struct sockaddr_storage. */
	uint16_t	count;		/* Num of used struct sockaddr_storage. */
} host_addr_t, *host_addr_p;



host_addr_p host_addr_alloc(const uint8_t *name, uint16_t name_size, uint16_t def_port);
void	host_addr_free(host_addr_p haddr);
int	host_addr_is_host_soaddr(host_addr_p haddr, const struct sockaddr_storage *addr);
int	host_addr_is_host_addr(host_addr_p haddr, const struct sockaddr_storage *addr);
int	host_addr_add_addr(host_addr_p haddr, const struct sockaddr_storage *addr);
int	host_addr_resolv(host_addr_p haddr);




#endif /* __CORE_HOST_ADDR_H__ */
