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

/*
 * 
 * This is a simple, non recursive resolver, local cache, but asinc
 * maximum concurrent tasks_tmr is 65534
 * use only one UDP socket to communicate with DNS servers
 * 
 */


#include <sys/param.h>

#ifdef __linux__ /* Linux specific code. */
#	define _GNU_SOURCE /* See feature_test_macros(7) */
#	define __USE_GNU 1
#endif /* Linux specific code. */

#include <sys/types.h>
#include <unistd.h> /* close, write, sysconf */
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <errno.h>
#include <stdio.h> /* snprintf, fprintf */
#include <time.h>

#include "hash_bucket.h"
#include "mem_helpers.h"
#include "DNSMessage.h"

#include "core_io_task.h"
#include "core_io_net.h"
#include "core_helpers.h"
#include "macro_helpers.h"
#include "core_net_helpers.h"
#include "core_log.h"
#include "core_dns_resolv.h"


#define DNS_RESOLVER_SKT_RCV_SIZE	(128 * 1024)
#define DNS_RESOLVER_SKT_SND_SIZE	(128 * 1024)
#define DNS_RESOLVER_MAX_UDP_MSG_SIZE	(64 * 1024)
#define DNS_RESOLVER_OPT_UDP_SIZE	(16 * 1024)
#define DNS_RESOLVER_MAX_TASKS		65536
#define DNS_RESOLVER_CACHE_ALLOC	8
#define DNS_RESOLVER_MAX_ADDRS		64
#define DNS_RESOLVER_TTL_MIN		4
#define ERESTART			(-1)		/* restart syscall */


typedef struct dns_rslvr_cache_entry_s	*dns_rslvr_cache_entry_p;




typedef struct dns_rslvr_task_s {
	dns_rslvr_p	rslvr;		/*  */
	thrpt_p		thrpt;		/* Need for timers and correct callback. */
	dns_rslvr_cache_entry_p cache_entry; /* Used for update existing cache item. */
	dns_rslvr_task_p next_task;	/* Next task to notify in cache_entry queue. */
	uint16_t	task_id;	/* ID in dns msg and Index in tasks_tmr array. */
	uint16_t	flags;		/* DNS_R_F_* */
	uint16_t	timeouts;	/* Num with current NS server. */
	uint16_t	cur_srv_idx;	/* Idx of cur DNS server (see dns_addrs) */
	uint16_t	loop_count;	/* CName loop count. */
	dns_resolv_cb	cb_func;	/* Called after resolv done. */
	void		*udata;		/* Passed as arg to check and done funcs. */
} dns_rslvr_task_t;

// DNS_R_F_*
#define DNS_R_TSK_F_QUEUED		(((uint16_t)1) << 10) /* This task is wait another task complete work and will be notifyed. */


typedef struct dns_rslvr_s {
	thrpt_p		thrp;		/* Need for timers. */
	hbucket_p	hbskt;		/* Cache resolved records. */
	time_t		next_clean_time;
	uint32_t	clean_interval;

	io_task_p	io_pkt_rcvr4;	/* Packet receiver IPv4 skt. */
	//io_task_p	io_pkt_rcvr6;	/* Packet receiver IPv4 skt. */
	uintptr_t	sktv4;		/* IPv4 UDP socket. */
	//uintptr_t	sktv6;		/* IPv6 UDP socket. */
	io_buf_t	buf;		/* Buffer for recv reply. */
	uintptr_t	timeout;	/* Timeout for request to NS server. */
	uint32_t	neg_cache;	/* Time for negative cache. */
	struct sockaddr_storage	*dns_addrs; /* Upstream DNS servers. */
	uint16_t	dns_addrs_count;
	uint16_t	retry_count;	/* Num of timeout retry req to NS server. */
	uint16_t	tasks_count;	/* Now resolving for ... hosts. */
	uint16_t	tasks_index;	/* Next task item index. */
	thrp_udata_t	tasks_tmr[DNS_RESOLVER_MAX_TASKS]; /* Index in this array
							* used as ID in dns msg. */
	uint8_t		buf_data[DNS_RESOLVER_MAX_UDP_MSG_SIZE];
} dns_rslvr_t;


typedef struct dns_rslvr_cache_addr_s { // 8 + 4 + 16 = 28 bytes
	time_t		valid_untill;
	uint32_t	family;		/* Addr family. */
	union {
		struct in_addr	addr4;	// IPv4 address 4 bytes
		struct in6_addr	addr6;	// IPv6 address 16 bytes
	};
} __attribute__((__packed__)) dns_rslvr_cache_addr_t, *dns_rslvr_cache_addr_p;


typedef struct dns_rslvr_cache_entry_s {
	hbucket_entry_t entry;		/* For store in cache. */
	uint8_t		*name;		/* Hostname. */
	size_t		name_size;	/* Host name size. */
	size_t		data_count;	/* Num of used struct sockaddr_storage / alias len. */
	size_t		data_allocated;	/* Avaible size to store data. */
	uint16_t	flags;		/* Flags + DNS_R_F_*. */
	time_t		last_upd;
	time_t		valid_untill;
	volatile uint64_t returned_count; /* For stat. */
	union {
		uint8_t	*pdata;
		uint8_t *data_alias_name;
		dns_rslvr_cache_addr_p	addrs;
	};
	dns_rslvr_task_p task;		/* Tasks to call back after resolv done. */
	size_t		tasks_count;
	// name[]
} dns_rslvr_cache_entry_t;

// DNS_R_F_*
#define DNS_R_CD_F_UPDATING	(((uint16_t)1) << 8) /* Update in progress. Prevent cache cleanp delete. */
#define DNS_R_CD_F_CNAME	(((uint16_t)1) << 9) /* Data is cname - alias name. */



/* Used for DNS cache dump callback. */
typedef struct dns_rslvr_cache_dump_s {
	char *buf;
	size_t buf_size;
	size_t cur_off;
} dns_rslvr_cache_dump_t;


int		dns_resolv_hostaddr_int(dns_rslvr_p rslvr, int send_request,
		    uint8_t *name, size_t name_size, uint16_t flags,
		    dns_resolv_cb cb_func, void *arg, dns_rslvr_task_p *task_ret);
int		data_cache_enum_cb_fn(void *udata, hbucket_entry_p entry);
static void	dns_resolver_task_done(dns_rslvr_task_p task, int error,
		    dns_rslvr_cache_addr_p addrs, size_t addrs_count,
		    time_t valid_untill);
static int	dns_resolver_send(dns_rslvr_task_p task);
static void	dns_resolver_task_timeout_cb(thrp_event_p ev, thrp_udata_p thrp_udata);
static int	dns_resolver_recv_cb(io_task_p iotask, int error,
		    struct sockaddr_storage *addr, io_buf_p buf,
		    size_t transfered_size, void *arg);


/* Staff for data_cache. */
uint32_t	dns_resolver_data_cache_hash(void *udata, const uint8_t *key,
		    size_t key_size);
int		dns_resolver_data_cache_cmp_data(void *udata, const uint8_t *key,
		    size_t key_size, void *data);
int		dns_resolver_destroy_entry_enum_cb(void *udata,
		    hbucket_entry_p entry);

int		dns_rslvr_cache_entry_alloc(uint8_t *name, size_t name_size,
		    dns_rslvr_cache_entry_p *cache_entry_ret);
void		dns_rslvr_cache_entry_free(dns_rslvr_cache_entry_p cache_entry);
int		dns_rslvr_cache_entry_data_add(dns_rslvr_cache_entry_p cache_entry,
		    void *data, uint16_t data_count, uint16_t flags,
		    time_t valid_untill);

int		dns_rslvr_task_alloc(dns_rslvr_p rslvr, dns_resolv_cb cb_func,
		    void *arg, dns_rslvr_task_p *task_ret);
void		dns_rslvr_task_free(dns_rslvr_task_p task);
void		dns_rslvr_task_notify_chain(dns_rslvr_task_p task, uint8_t *name,
		    size_t name_size);




static inline int
dns_rslvr_cache_addr_cmp(dns_rslvr_cache_addr_p a1, dns_rslvr_cache_addr_p a2) {

	if (a1->family != a2->family)
		return (1);
	switch (a1->family) {
	case AF_INET:
		return (memcmp(&a1->addr4, &a2->addr4, sizeof(struct in_addr)));
		break;
	case AF_INET6:
		return (memcmp(&a1->addr6, &a2->addr6, sizeof(struct in6_addr)));
		break;
	}
	return (1);
}

static inline int
dns_rslvr_cache_addr_cp(dns_rslvr_cache_addr_p caddrs, size_t addrs_count,
    struct sockaddr_storage *addrs) {
	size_t i;

	for (i = 0; i < addrs_count; i ++) {
		switch (caddrs[i].family) {
		case AF_INET:
			sain4_init(&addrs[i]);
			//sain4_p_set(&addrs[i], 0);
			sain4_a_set(&addrs[i], &caddrs[i].addr4);
			continue;
			break;
		case AF_INET6:
			sain6_init(&addrs[i]);
			//sain6_p_set(&addrs[i], 0);
			sain6_a_set(&addrs[i], &caddrs[i].addr6);
			continue;
			break;
		}
	}
	return (0);
}

uint32_t
dns_resolver_data_cache_hash(void *udata __unused, const uint8_t *key,
    size_t key_size) {
	register uint32_t ret = 0;
	register size_t i;
	register uint8_t cur_byte;

	if (NULL == key || 0 == key_size)
		return (ret);
	for (i = 0; i < key_size; i ++) {
		cur_byte = (uint8_t)key[i];
		if ('A' <= cur_byte && 'Z' >= cur_byte) 
			cur_byte |= 32;
		ret ^= cur_byte;
	}
	return (ret);
}

int
dns_resolver_data_cache_cmp_data(void *udata __unused, const uint8_t *key,
    size_t key_size, void *data) {

	return (mem_cmpin(key, key_size, ((dns_rslvr_cache_entry_p)data)->name,
	    ((dns_rslvr_cache_entry_p)data)->name_size));
}

int
dns_resolver_destroy_entry_enum_cb(void *udata __unused, hbucket_entry_p entry) {

	dns_rslvr_cache_entry_free(entry->data);
	return (0);
}


int
dns_rslvr_cache_entry_alloc(uint8_t *name, size_t name_size,
    dns_rslvr_cache_entry_p *cache_entry_ret) {
	dns_rslvr_cache_entry_p cache_entry;

	if (NULL == name || 0 == name_size || DNS_MAX_NAME_LENGTH < name_size) {
		LOGD_ERR_FMT(EINVAL, "name = %s, name_size = %zu", name, name_size);
		return (EINVAL);
	}
	cache_entry = zalloc((sizeof(dns_rslvr_cache_entry_t) + name_size + sizeof(void*)));
	if (NULL == cache_entry)
		return (ENOMEM);
	cache_entry->entry.data = cache_entry;
	cache_entry->name = (uint8_t*)(cache_entry + 1);
	cache_entry->name_size = name_size;
	//cache_entry->data_count = 0;
	//cache_entry->data_allocated = 0;
	//cache_entry->flags = 0;
	cache_entry->last_upd = time(NULL);
	cache_entry->valid_untill = cache_entry->last_upd;
	cache_entry->returned_count = 1;
	//cache_entry->pdata = NULL;
	//cache_entry->task = NULL;
	//cache_entry->tasks_count = 0;
	memcpy(cache_entry->name, name, name_size);
	cache_entry->name[name_size] = 0;
	(*cache_entry_ret) = cache_entry;
	return (0);
}

void
dns_rslvr_cache_entry_free(dns_rslvr_cache_entry_p cache_entry) {
	dns_rslvr_task_p task;
	uint8_t name[DNS_MAX_NAME_LENGTH + 4];
	size_t name_size = 0;

	if (NULL == cache_entry)
		return;
	hbucket_entry_remove(&cache_entry->entry);
	task = cache_entry->task;
	if (NULL != task) {
		name_size = cache_entry->name_size;
		memcpy(name, cache_entry->name, name_size);
		name[name_size] = 0;
	}
	if (NULL != cache_entry->pdata)
		free(cache_entry->pdata);
	free(cache_entry);

	dns_rslvr_task_notify_chain(task, name, name_size);
}

int
dns_rslvr_cache_entry_data_add(dns_rslvr_cache_entry_p cache_entry, void *data,
    uint16_t data_count, uint16_t flags, time_t valid_untill) {
	uint8_t *tm = NULL;
	size_t data_size, i, j, first_free;
	time_t time_now;
	dns_rslvr_cache_addr_p addrs, caddr;
	dns_rslvr_task_p task;
	int error = 0, add;

	if (NULL == cache_entry) {
		LOGD_ERR_FMT(EINVAL, "cache_entry = NULL.");
		return (EINVAL);
	}
	time_now = time(NULL);
	data_size = data_count;
	flags &= DNS_R_CD_F_CNAME;
	if (0 != data_size && 0 == (DNS_R_CD_F_CNAME & flags))
		data_size *= sizeof(dns_rslvr_cache_addr_t);

	hbucket_entry_lock(&cache_entry->entry);
	if (0 == data_count)
		goto data_upd_done;
	/* Cname <-> IP conversion. */
	if ((DNS_R_CD_F_CNAME & cache_entry->flags) != (flags & DNS_R_CD_F_CNAME) &&
	    NULL != cache_entry->pdata) {
		free(cache_entry->pdata);
		cache_entry->data_count = 0;
		cache_entry->data_allocated = 0;
		cache_entry->pdata = NULL;
		LOGD_EV_FMT("%s <-> %s Cname <-> IP!!!", cache_entry->name, data);
	}
	/* Cname set. */
	if (DNS_R_CD_F_CNAME & flags) {
		if (0 == mem_cmpin(cache_entry->name, cache_entry->name_size,
		    data, data_count)) { /* Cname point to itself!. */
			hbucket_entry_unlock(&cache_entry->entry);
			error = ELOOP;
			LOGD_ERR_FMT(error, "%s ELOOP!!!", cache_entry->name);
			goto notify_out;
		}
		/* If cname - delete all IP addrs, copy new data. */
		if (cache_entry->data_allocated != data_count) { /* diff name size.*/
			tm = realloc(cache_entry->pdata, (data_count + 2));
			if (NULL == tm) {
				hbucket_entry_unlock(&cache_entry->entry);
				error = ENOMEM;
				LOG_ERR_FMT(error, "%s realloc() fail.", cache_entry->name);
				goto notify_out;
			}
			cache_entry->pdata = tm;
			cache_entry->data_count = data_count;
			cache_entry->data_allocated = data_count;
		}
		memcpy(cache_entry->pdata, data, data_count);
		mem_bzero((cache_entry->pdata + data_count), 2);
		goto data_upd_done;
	}
	/* IP addrs set. */
	/* Merge/update. */
	flags = 0;
	addrs = data;
	first_free = 0;
	for (i = 0; i < data_count; i ++) { /* enum new data data */
		add = 1;
		first_free = cache_entry->data_count;
		for (j = 0; j < cache_entry->data_count; j ++) { /* enum existing data */
			caddr = &cache_entry->addrs[j];
			if (0 == dns_rslvr_cache_addr_cmp(caddr, &addrs[i])) {
				/* Udpate existing. */
				caddr->valid_untill = addrs[i].valid_untill;
				add = 0;
				break;
			}
			if (caddr->valid_untill < time_now) /* Mark as free. */
				first_free = min(j, first_free);
		}
		if (0 == add)
			continue;
		// add new
		/* Increace mem if needed. */
		error = realloc_items((void**)&cache_entry->pdata,
		    sizeof(dns_rslvr_cache_addr_t), &cache_entry->data_allocated,
		    DNS_RESOLVER_CACHE_ALLOC, cache_entry->data_count);
		if (0 != error) {
			hbucket_entry_unlock(&cache_entry->entry);
			error = ENOMEM;
			LOG_ERR_FMT(error, "%s reallocarray() 2 fail.", cache_entry->name);
			goto notify_out;
		}
		memcpy(&cache_entry->addrs[cache_entry->data_count], &addrs[i],
		    sizeof(dns_rslvr_cache_addr_t));
		cache_entry->data_count ++;
	}
	valid_untill = cache_entry->addrs[0].valid_untill;
	for (j = 0; j < cache_entry->data_count; j ++) { /* enum existing data */
		caddr = &cache_entry->addrs[j];
		if (caddr->valid_untill < time_now) { /* Delete outdated. */
			cache_entry->data_count --;
			memmove(caddr, (caddr + 1),
			    ((cache_entry->data_count - j) *
			    sizeof(dns_rslvr_cache_addr_t)));
			j --;
			continue;
		}
		switch (caddr->family) {
		case AF_INET:
			flags |= DNS_R_F_IPV4;
			break;
		case AF_INET6:
			flags |= DNS_R_F_IPV6;
			break;
		}
		valid_untill = min(valid_untill, caddr->valid_untill);
	}

data_upd_done:
	cache_entry->last_upd = time_now;
	cache_entry->valid_untill = valid_untill;
notify_out:
	/* Tasks to call back after resolv done. */
	task = cache_entry->task;
	cache_entry->flags = flags;
	cache_entry->task = NULL;
	cache_entry->tasks_count = 0;
	hbucket_entry_unlock(&cache_entry->entry);

	dns_rslvr_task_notify_chain(task, cache_entry->name, cache_entry->name_size);

	return (error);
}

/* Zone MUST BE LOCKED!!! */
static inline void
dns_rslvr_cache_entry_task_n_add(dns_rslvr_cache_entry_p cache_entry,
    dns_rslvr_task_p task) {

	task->cache_entry = NULL;//cache_entry;
	task->flags |= DNS_R_TSK_F_QUEUED;
	task->next_task = cache_entry->task;
	cache_entry->task = task;
	cache_entry->tasks_count ++;
}


int
dns_rslvr_task_alloc(dns_rslvr_p rslvr, dns_resolv_cb cb_func, void *arg,
    dns_rslvr_task_p *task_ret) {
	dns_rslvr_task_p task;
	int error;
	uint16_t task_id;

	if (NULL == rslvr || NULL == cb_func || NULL == task_ret)
		return (EINVAL);
	/* XXX Lock */
	if (0xffff == rslvr->tasks_count)
		return (EAGAIN); /* No free task slot. */
	for (task_id = rslvr->tasks_index;
	    task_id != (rslvr->tasks_index - 1); task_id ++) {
		if (0 == task_id)
			continue;
		if (0 == rslvr->tasks_tmr[task_id].ident)
			break;
	}
	if (0 != rslvr->tasks_tmr[task_id].ident)
		return (EAGAIN); /* No free task slot. */
	task = zalloc(sizeof(dns_rslvr_task_t));
	if (NULL == task)
		return (ENOMEM);
	rslvr->tasks_index = task_id;
	rslvr->tasks_tmr[task_id].ident = (uintptr_t)task;
	rslvr->tasks_count ++;
	/* XXX UnLock */

	task->rslvr = rslvr;
	//task->cache_entry = cache_entry;
	task->task_id = task_id;
	//task->flags = flags;
	//task->timeouts = 0;
	//task->cur_srv_idx = 0;
	//task->loop_count = 0;
	task->cb_func = cb_func;
	task->udata = arg;
	error = thrpt_ev_add_ex(thrp_thread_get_pvt(rslvr->thrp), THRP_EV_TIMER, THRP_F_DISPATCH, 0,
	    rslvr->timeout, &rslvr->tasks_tmr[task_id]);
	if (0 != error) {
		dns_rslvr_task_free(task);
		return (error);
	}
	thrpt_ev_enable(0, THRP_EV_TIMER, &rslvr->tasks_tmr[task_id]);
	(*task_ret) = task;

	return (0);
}

void
dns_rslvr_task_free(dns_rslvr_task_p task) {
	dns_rslvr_p rslvr;

	if (NULL == task)
		return;
	rslvr = task->rslvr;
	thrpt_ev_del(THRP_EV_TIMER, &rslvr->tasks_tmr[task->task_id]);
	/* XXX Lock */
	rslvr->tasks_tmr[task->task_id].ident = 0;
	rslvr->tasks_count --;
	/* XXX UnLock */
	mem_filld(task, sizeof(dns_rslvr_task_t));
	free(task);
}

void
dns_rslvr_task_notify_chain(dns_rslvr_task_p task, uint8_t *name, size_t name_size) {
	dns_rslvr_p rslvr;
	dns_rslvr_task_p next_task;

	if (NULL == task)
		return;
	rslvr = task->rslvr;
	while (NULL != task) {
		next_task = task->next_task;
		task->next_task = NULL;
		task->flags &= ~DNS_R_TSK_F_QUEUED;
		dns_resolv_hostaddr_int(rslvr, 1, name, name_size, 0, NULL, NULL, &task);
		task = next_task;
	}
}

int
dns_resolver_create(thrp_p thrp, const struct sockaddr_storage *dns_addrs, 
    uint16_t dns_addrs_count, uintptr_t timeout, uint16_t retry_count,
    uint32_t neg_cache, dns_rslvr_p *dns_rslvr_ret) {
	dns_rslvr_p rslvr;
	int buf = DNS_RESOLVER_SKT_SND_SIZE;
	int rcv_buf = DNS_RESOLVER_SKT_RCV_SIZE, on = 1;
	int error;
	size_t i;

	if (NULL == thrp || NULL == dns_addrs || 0 == dns_addrs_count ||
	    DNS_TTL_MAX < neg_cache || DNS_RESOLVER_TTL_MIN > neg_cache ||
	    NULL == dns_rslvr_ret)
		return (EINVAL);
		
	rslvr = zalloc(sizeof(dns_rslvr_t));
	if (NULL == rslvr)
		return (ENOMEM);
	rslvr->dns_addrs = zalloc((sizeof(struct sockaddr_storage) * dns_addrs_count));
	if (NULL == rslvr->dns_addrs) {
		error = ENOMEM;
		goto err_out;
	}
	io_buf_init(&rslvr->buf, 0, rslvr->buf_data, sizeof(rslvr->buf_data));
	IO_BUF_MARK_TRANSFER_ALL_FREE(&rslvr->buf);

	rslvr->sktv4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ((uintptr_t)-1 == rslvr->sktv4) {
		error = errno;
		goto err_out;
	}
	error = fd_set_nonblocking(rslvr->sktv4, 1);
	if (0 != error)
		goto err_out;
	/* Tune socket. */
#ifdef SO_NOSIGPIPE
	setsockopt(rslvr->sktv4, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(int));
#endif
	error = io_net_snd_tune(rslvr->sktv4, buf, 1);
	if (0 != error)
		goto err_out;
	error = io_net_rcv_tune(rslvr->sktv4, rcv_buf, 1);
	if (0 != error)
		goto err_out;

	mem_bzero(rslvr->dns_addrs,
	    (sizeof(struct sockaddr_storage) * dns_addrs_count));
	rslvr->dns_addrs_count = dns_addrs_count;
	for (i = 0; i < dns_addrs_count; i ++)
		sa_copy(&dns_addrs[i], &rslvr->dns_addrs[i]);
	rslvr->thrp = thrp;
	rslvr->timeout = timeout;
	rslvr->neg_cache = neg_cache;
	rslvr->retry_count = retry_count;
	for (i = 0; i < DNS_RESOLVER_MAX_TASKS; i ++)
		rslvr->tasks_tmr[i].cb_func = dns_resolver_task_timeout_cb;


	error = io_task_pkt_rcvr_create(thrp_thread_get_pvt(thrp), rslvr->sktv4,
	    0, 0, &rslvr->buf, dns_resolver_recv_cb, rslvr, &rslvr->io_pkt_rcvr4);
	if (0 != error)
		goto err_out;
	error = hbucket_create(1, 256, rslvr, dns_resolver_data_cache_hash,
	    dns_resolver_data_cache_cmp_data, &rslvr->hbskt);
	if (0 != error)
		goto err_out;
	rslvr->next_clean_time = (time(NULL) + (neg_cache * 2));;
	rslvr->clean_interval = (neg_cache * 2);

	(*dns_rslvr_ret) = rslvr;
	return (0);

err_out:
	/* Error. */
	dns_resolver_destroy(rslvr);
	return (error);
}

void
dns_resolver_destroy(dns_rslvr_p rslvr) {
	size_t i;

	if (NULL == rslvr)
		return;

	io_task_destroy(rslvr->io_pkt_rcvr4);
	close(rslvr->sktv4);

	/* Destroy all tasks. */
	/* XXX Lock */
	for (i = 0; i < 0xffff; i ++) {
		if (0 == rslvr->tasks_tmr[i].ident)
			continue;
		dns_rslvr_task_free((dns_rslvr_task_p)rslvr->tasks_tmr[i].ident);
	}
	dns_rslvr_task_free((dns_rslvr_task_p)rslvr->tasks_tmr[0xffff].ident);
	/* XXX Lock */
	/* XXX Lock destroy */

	if (NULL != rslvr->dns_addrs)
		free(rslvr->dns_addrs);
	io_buf_free(&rslvr->buf);
	hbucket_destroy(rslvr->hbskt, dns_resolver_destroy_entry_enum_cb, rslvr);
	mem_filld(rslvr, sizeof(dns_rslvr_t));
	free(rslvr);
}

thrpt_p
dns_resolver_thrpt_get(dns_rslvr_p rslvr) {

	if (NULL == rslvr)
		return (NULL);
	return (rslvr->thrp);
}


int
data_cache_enum_cb_fn(void *udata, hbucket_entry_p entry) {
	dns_rslvr_cache_dump_t *cd = udata;
	dns_rslvr_cache_entry_p cache_entry = entry->data;

	if ((cd->buf_size - cd->cur_off) < DNS_MAX_NAME_LENGTH)
		return (1); /* No buf space, stop enum. */
	if (DNS_R_CD_F_CNAME & cache_entry->flags) {
		cd->cur_off += snprintf((cd->buf + cd->cur_off), (cd->buf_size - cd->cur_off),
		    "%-32s [ addrs: cn,	ttl: %-2"PRIi32",	"
		    "upd/task q len: %zu,	ret count: %"PRIu64",	data: %s ]\r\n",
		    cache_entry->name,
		    (int32_t)(cache_entry->valid_untill - time(NULL)),
		    ((DNS_R_CD_F_UPDATING & cache_entry->flags) ? (1 + cache_entry->tasks_count) : 0),
		    cache_entry->returned_count, cache_entry->data_alias_name);
	} else {
		cd->cur_off += snprintf((cd->buf + cd->cur_off), (cd->buf_size - cd->cur_off),
		    "%-32s [ addrs: %"PRIu16",	ttl: %-2"PRIi32",	"
		    "upd/task q len: %zu,	ret count: %"PRIu64",	data: IPs ]\r\n",
		    cache_entry->name, cache_entry->data_count,
		    (int32_t)(cache_entry->valid_untill - time(NULL)),
		    ((DNS_R_CD_F_UPDATING & cache_entry->flags) ? (1 + cache_entry->tasks_count) : 0),
		    cache_entry->returned_count);
	}

	return (0);
}

int
dns_resolver_cache_text_dump(dns_rslvr_p rslvr, char *buf, size_t buf_size,
    size_t *size_ret) {
	dns_rslvr_cache_dump_t cache_dump;

	if (NULL == rslvr)
		return (EINVAL);

	cache_dump.buf = buf;
	cache_dump.buf_size = buf_size;
	cache_dump.cur_off = 0;
	hbucket_entry_enum(rslvr->hbskt, data_cache_enum_cb_fn, &cache_dump);
	cache_dump.cur_off += snprintf((cache_dump.buf + cache_dump.cur_off),
	    (cache_dump.buf_size - cache_dump.cur_off),
	    "entries count: %zu\r\n"
	    "tasks queued count: %"PRIu16"\r\n",
	    rslvr->hbskt->count, rslvr->tasks_count);
	(*size_ret) = cache_dump.cur_off;

	return (0);
}


int
dns_resolv_hostaddr_int(dns_rslvr_p rslvr, int send_request,
    uint8_t *name, size_t name_size, uint16_t flags, dns_resolv_cb cb_func,
    void *arg, dns_rslvr_task_p *task_ret) {
	dns_rslvr_task_p task = NULL;
	dns_rslvr_cache_entry_p cache_entry = NULL;
	hbucket_zone_p zone = NULL;
	hbucket_entry_p entry;
	time_t time_now = time(NULL);
	size_t loop_count = 0, addrs_count;
	int error, cache_entry_updating = 0;
	struct sockaddr_storage ssaddrs[DNS_RESOLVER_MAX_ADDRS];

	if (NULL != task_ret && NULL != (*task_ret)) {
		task = (*task_ret);
		rslvr = task->rslvr;
		flags = task->flags;
		cb_func = task->cb_func;
		arg = task->udata;
		loop_count = task->loop_count;
	}
	if (NULL == rslvr || NULL == cb_func)
		return (EINVAL);
	if (NULL == name || 0 == name_size || DNS_MAX_NAME_LENGTH < name_size) {
		error = EINVAL;
		LOGD_ERR_FMT(error, "name = %s, name_size = %zu", name, name_size);
		goto err_out;
	}
	/* In cache search. */
	while (loop_count < DNS_MAX_NAME_CYCLES) {
		error = hbucket_entry_get(rslvr->hbskt, HBUCKET_GET_F_F_LOCK,
		    name, name_size, &zone, &entry);
		if (0 != error)
			break; /* Zone is LOCKED!!! */
		/* Existing... */
		cache_entry = entry->data;
		cache_entry->returned_count ++;
		if (DNS_R_CD_F_UPDATING & cache_entry->flags) {
			/* Add Task to call back queue in cache entry after resolv done. */
			cache_entry_updating = 1;
			goto task_alloc; /* Zone is LOCKED!!! */
		}
		if (cache_entry->valid_untill < time_now) { /* Cached data outdate. */
			cache_entry->flags |= DNS_R_CD_F_UPDATING;
			hbucket_zone_unlock(zone);
			goto task_alloc;
		}
		if (DNS_R_CD_F_CNAME & cache_entry->flags) {
			/* Search in cache addrs for cname. */
			/* After unlock entry can be deleted, 
			 * so save it in temp local buf. */
			name = (uint8_t*)ssaddrs;
			name_size = cache_entry->data_count;
			memcpy(name, cache_entry->data_alias_name, name_size);
			name[name_size] = 0;
			hbucket_zone_unlock(zone);
			loop_count ++;
			continue;
		}
		/* FOUND!!! */
		addrs_count = min(cache_entry->data_count, SIZEOF(ssaddrs));
		dns_rslvr_cache_addr_cp(cache_entry->addrs, addrs_count, ssaddrs);
		hbucket_zone_unlock(zone);
		cb_func(task, 0, ssaddrs, addrs_count, arg);
		dns_rslvr_task_free(task); /* Free if called from: dns_resolver_recv_cb() */
		return (0);
	}
	if (loop_count >= DNS_MAX_NAME_CYCLES) {
		error = ELOOP; /* Loop detected. */
		goto err_out;
	}
	/* Alloc new cache entry. / Not found, create new.. */
	error = dns_rslvr_cache_entry_alloc(name, name_size, &cache_entry);
	if (0 != error) {
		hbucket_zone_unlock(zone);
		goto err_out;
	}
	cache_entry->flags |= DNS_R_CD_F_UPDATING;
	hbucket_entry_add(rslvr->hbskt, HBUCKET_ADD_F_NO_LOCK, zone, NULL, 0,
	    &cache_entry->entry); /* Zone unlocked after add!!! */
task_alloc:
	if (NULL == task) {
		error = dns_rslvr_task_alloc(rslvr, cb_func, arg, &task);
		if (0 != error) {
			if (0 != cache_entry_updating)
				hbucket_zone_unlock(zone);
			goto err_out;
		}
		task->flags = flags;
	}
	task->cache_entry = cache_entry;
	task->timeouts = 0;
	task->cur_srv_idx = 0;
	task->loop_count = loop_count;
	if (0 != cache_entry_updating) {
		dns_rslvr_cache_entry_task_n_add(cache_entry, task);
		hbucket_zone_unlock(zone);
		goto ok_out;
	}
	if (0 == send_request) /* Return to dns_resolver_recv_cb() and restart search. */
		return (ERESTART);
	error = dns_resolver_send(task);
	if (0 != error)
		goto err_out;
ok_out:
	if (NULL != task_ret)
		(*task_ret) = task;

	return (0);

err_out:
	LOG_ERR_FMT(error, "failed");
	if (0 != send_request) /* Called from: dns_resolver_recv_cb() need callback. */
		cb_func(task, error, NULL, 0, arg);
	dns_rslvr_task_free(task);
	return (error);
}

int
dns_resolv_hostaddr(dns_rslvr_p rslvr, uint8_t *name, size_t name_size,
    uint16_t flags, dns_resolv_cb cb_func, void *arg, dns_rslvr_task_p *task_ret) {

	return (dns_resolv_hostaddr_int(rslvr, 1, name, name_size, flags, cb_func,
	    arg, task_ret));
}

void
dns_resolv_cancel(dns_rslvr_task_p task) {

	if (NULL == task)
		return;

	task->cb_func = NULL;
	task->udata = NULL;
}


static void
dns_resolver_task_done(dns_rslvr_task_p task, int error, 
    dns_rslvr_cache_addr_p addrs, size_t addrs_count, time_t valid_untill) {
	//dns_rslvr_p rslvr = task->rslvr;
	struct sockaddr_storage ssaddrs[DNS_RESOLVER_MAX_ADDRS];

	/* Udpate cache data. */
	dns_rslvr_cache_entry_data_add(task->cache_entry, addrs, addrs_count, 0,
	    valid_untill);

	if (NULL != task->cb_func) {
		addrs_count = min(addrs_count, SIZEOF(ssaddrs));
		dns_rslvr_cache_addr_cp(addrs, addrs_count, ssaddrs);
		task->cb_func(task, error, ssaddrs, addrs_count, task->udata);
	}
	dns_rslvr_task_free(task);

	//data_cache_clean(rslvr->dcache);
}


static int
dns_resolver_send(dns_rslvr_task_p task) {
	uint8_t dns_msg_buf[4096];
	dns_hdr_p dns_hdr;
	dns_hdr_flags_t dns_hdr_flags;
	dns_ex_flags_t dns_ex_flags;
	size_t msgbuf_size, msg_size;

	if (NULL == task || task->cur_srv_idx >= task->rslvr->dns_addrs_count)
		return (EINVAL);

	dns_hdr_flags.u16 = 0;
	dns_hdr_flags.bits.rd = 1; //Q- // Recursion Desired
	dns_hdr_flags.bits.opcode = DNS_HDR_FLAG_OPCODE_QUERY;
	dns_hdr_flags.bits.qr = DNS_HDR_FLAG_QR_QUERY;
	dns_hdr_flags.bits.cd = 1;

	dns_ex_flags.u16 = 0;
	dns_ex_flags.bits.d0 = 1;

	dns_hdr = (dns_hdr_p)dns_msg_buf;
	msgbuf_size = sizeof(dns_msg_buf);
	msg_size = 0;

	dns_hdr_create((uint16_t)task->task_id, dns_hdr_flags.u16, dns_hdr,
	    msgbuf_size, &msg_size);
	dns_msg_question_add(dns_hdr, msg_size, msgbuf_size, 0, task->cache_entry->name,
	    task->cache_entry->name_size, DNS_RR_TYPE_A, DNS_RR_CLASS_IN, &msg_size);
	//dns_msg_question_add(dns_hdr, msg_size, msgbuf_size, 0, task->cache_entry->name,
	//    task->cache_entry->name_size, DNS_RR_TYPE_AAAA, DNS_RR_CLASS_IN, &msg_size);
	dns_msg_optrr_add(dns_hdr, msg_size, msgbuf_size, DNS_RESOLVER_OPT_UDP_SIZE,
	    0, 0, dns_ex_flags.u16, 0, NULL, &msg_size);
	dns_hdr_ar_inc(dns_hdr, 1);

	if ((ssize_t)msg_size != sendto(task->rslvr->sktv4, dns_hdr,
	    msg_size, (MSG_DONTWAIT | MSG_NOSIGNAL),
	    &task->rslvr->dns_addrs[task->cur_srv_idx],
	    sa_type2size(&task->rslvr->dns_addrs[task->cur_srv_idx])))
		return (errno);
	thrpt_ev_enable_ex(1, THRP_EV_TIMER, THRP_F_DISPATCH, 0,
	    task->rslvr->timeout, &task->rslvr->tasks_tmr[task->task_id]);

	return (0);
}


static void
dns_resolver_task_timeout_cb(thrp_event_p ev __unused, thrp_udata_p thrp_udata) {
	dns_rslvr_task_p task = (dns_rslvr_task_p)thrp_udata->ident;
	int error;

	thrpt_ev_enable(0, THRP_EV_TIMER, thrp_udata);
	if (NULL == task) /* Task already done/removed. */
		return;

	//LOGD_EV_FMT("task %i - %s", task->task_id, task->cache_entry->name);
	error = ETIMEDOUT;
	task->timeouts ++;
	if (task->timeouts <= task->rslvr->retry_count) /* Re send query. */
		error = dns_resolver_send(task);

	/* If timeout retry exeed or error on send - try next server. */
	while ((task->cur_srv_idx + 1) < task->rslvr->dns_addrs_count &&
	    0 != error) { /* Try next DNS servers. */
		task->timeouts = 0;
		task->cur_srv_idx ++;
		error = dns_resolver_send(task);
	}
	if (0 != error) /* Report about error and destroy task. */
		dns_resolver_task_done(task, error, NULL, 0,
		    (time(NULL) + task->rslvr->neg_cache));
}

static int
dns_resolver_recv_cb(io_task_p iotask, int error, struct sockaddr_storage *addr,
    io_buf_p buf, size_t transfered_size, void *arg) {
	dns_rslvr_p rslvr = arg;
	dns_rslvr_task_p task;
	size_t tm, rr_count, Offset, rr_size = 0;
	size_t qd_off, an_off = 0, ns_off, ar_off, total_rr_count = 0, msg_size = 0;
	size_t addrs_count = 0;
	dns_hdr_p dns_hdr;
	uint8_t *rr_data;
	time_t time_now, valid_untill = 0;
	int restarted = 0; /* Found cname in answer, call dns_resolv_hostaddr_int() and now looking for another name. */
	uint32_t rr_ttl = 0;
	uint16_t rr_type = 0, rr_class = 0, rr_data_size = 0;
	dns_rslvr_cache_addr_t addrs[DNS_RESOLVER_MAX_ADDRS];


	if (0 != error)
		goto rcv_next;
	dns_hdr = (dns_hdr_p)buf->data;
	error = dns_msg_info_get(dns_hdr, transfered_size, &qd_off, &an_off, &ns_off,
	    &ar_off, &total_rr_count, &msg_size);
	if (0 != error)
		goto rcv_next;
	/* task_id */
	task = (dns_rslvr_task_p)rslvr->tasks_tmr[dns_hdr_id_get(dns_hdr)].ident;
	if (NULL == task)
		goto rcv_next;
	/* Filter packets by from addr. */
	if (0 == sa_addr_port_is_eq(addr, &rslvr->dns_addrs[task->cur_srv_idx]))
		goto rcv_next;

	/* Looks like answer for resolv task... */
	thrpt_ev_enable(0, THRP_EV_TIMER, &rslvr->tasks_tmr[task->task_id]);

	time_now = time(NULL);
	valid_untill = (time_now + rslvr->neg_cache);
	Offset = an_off;
	rr_count = total_rr_count;
	if (0 == rr_count ||
	    DNS_HDR_FLAG_RCODE_NOERROR != dns_hdr->flags.bits.rcode) {
		LOGD_EV_FMT("%s, rcode = %i", task->cache_entry->name, dns_hdr->flags.bits.rcode);
		if (DNS_HDR_FLAG_RCODE_NXDOMAIN != dns_hdr->flags.bits.rcode) {
			/* Send query to next dns server. */
			LOGD_EV_FMT("%s - Send query to next dns server.", task->cache_entry->name);
			task->cur_srv_idx ++;
			error = dns_resolver_send(task);
		} else {
			while (0 == dns_msg_rr_get_data(dns_hdr, msg_size, Offset,
			    NULL, 0, &rr_type, &rr_class, &rr_ttl, &rr_data_size,
			    &rr_data, &rr_size)) {
				Offset += rr_size;
				if (DNS_RR_TYPE_SOA != rr_type)
					continue;
				/* SOA decoder, try get MINIMUN feild. */
				/* Skeep MName. */
				if (0 != SequenceOfLabelsGetSize(rr_data, rr_data_size, &tm))
					break;
				rr_data += tm;
				rr_data_size -= tm;
				/* Skeep RName. */
				if (0 != SequenceOfLabelsGetSize(rr_data, rr_data_size, &tm))
					break;
				rr_data += tm;
				rr_data_size -= tm;
				if ((sizeof(uint32_t) * 5) > rr_data_size)
					break;
				/* Skeep: Serial, Refresh, Retry, Expire. */
				rr_data += (sizeof(uint32_t) * 4);
				valid_untill = (time_now +
				    min(rr_ttl, ntohl((*((uint32_t*)rr_data)))));
				LOGD_EV_FMT("%s, SOA ttl = %i, minimum = %i",
				task->cache_entry->name, rr_ttl, ntohl((*((uint32_t*)rr_data))));
				break;
			}
			error = EFAULT;//error = dns_hdr->Flags.bits.rcode;
			LOGD_ERR_FMT(error, "%s - NXDOMAIN", task->cache_entry->name);
		}
		if (0 != error) /* Report error. */
			goto call_cb;
		goto rcv_next;
	}

	while (SIZEOF(addrs) > addrs_count) {
		error = dns_msg_rr_find(dns_hdr, msg_size, &Offset, &rr_count,
		    task->cache_entry->name, task->cache_entry->name_size, &rr_type,
		    &rr_class, &rr_ttl, &rr_data_size, &rr_data, &rr_size);
		if (0 != error) {
			//LOGD_ERR_FMT(error, "dns_msg_rr_find(): %s, err = %i, total_rr_count = %zu, rr_count = %zu, msg_size = %zu, Offset = %zu", task->cache_entry->name, error, total_rr_count, rr_count, msg_size, Offset);
			if (ESPIPE == error)
				error = 0;
			break;
		}
		Offset += rr_size;
		rr_ttl = min(DNS_TTL_MAX, rr_ttl); /* Fix abnormal ttl. */
		rr_ttl = max(DNS_RESOLVER_TTL_MIN, rr_ttl); /* Fix abnormal ttl. */
		switch (rr_type) {
		case DNS_RR_TYPE_A:
			if (4 != rr_data_size)
				continue;
			addrs[addrs_count].valid_untill = (time_now + rr_ttl);
			addrs[addrs_count].family = AF_INET;
			memcpy(&addrs[addrs_count].addr4, rr_data, rr_data_size);
			addrs_count ++;
			break;
		case DNS_RR_TYPE_AAAA:
			if (16 != rr_data_size)
				continue;
			addrs[addrs_count].valid_untill = (time_now + rr_ttl);
			addrs[addrs_count].family = AF_INET6;
			memcpy(&addrs[addrs_count].addr6, rr_data, rr_data_size);
			addrs_count ++;
			break;
		case DNS_RR_TYPE_CNAME:
			if (0 != addrs_count)
				continue;
			error = dns_msg_sequence_of_labels2name(dns_hdr,
			    transfered_size, ((size_t)rr_data - (size_t)dns_hdr),
			    (uint8_t*)addrs, sizeof(addrs), &tm);
			if (0 != error || DNS_MAX_NAME_LENGTH < tm)
				continue;
			if (0 == mem_cmpin(addrs, tm, task->cache_entry->name,
			    task->cache_entry->name_size)) {
				/* Cname point to itself!. */
				error = ELOOP;
				goto call_cb;
			}
			/* Name have an alias and no addr, store alias to cache and
			 * try to find addrs for alias name. */
			dns_rslvr_cache_entry_data_add(task->cache_entry, addrs, tm,
			    DNS_R_CD_F_CNAME, (time_now + rr_ttl));// XXX ret error handle
			/* Update resolv task. */
			task->cache_entry = NULL;
			task->loop_count ++;
			/* On error will call back. */
			error = dns_resolv_hostaddr_int(rslvr, 0, (uint8_t*)addrs, tm,
			    0, NULL, NULL, &task);
			if (ERESTART != error)
				goto rcv_next;

			restarted = 1;
			addrs_count = 0;
			Offset = an_off; // restart adrs search in answer
			rr_count = total_rr_count;
			continue;
			break;
		}
	} /* while. */
	if ((0 != restarted || 0 != error) && 0 == addrs_count) { /* No addr for cname in answer, request it. */
		if (0 != error) /* Try next dns server if answer with errors. */
			task->cur_srv_idx ++;
		error = dns_resolver_send(task);
		if (0 == error)
			goto rcv_next;
		/* Fail, callback and end. */
	}

call_cb:
	dns_resolver_task_done(task, error, addrs, addrs_count, valid_untill);

rcv_next:
	IO_BUF_MARK_AS_EMPTY(buf);
	IO_BUF_MARK_TRANSFER_ALL_FREE(buf);
	return (IO_TASK_CB_CONTINUE);
}
