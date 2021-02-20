/*-
 * Copyright (c) 2012 - 2014 Rozhuk Ivan <rozhuk.im@gmail.com>
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
 * Hash bucket template.
 * kernel and user space.
 */

#ifndef __HASH_BASKET_H__
#define __HASH_BASKET_H__


#include <sys/param.h>

#ifdef __linux__ /* Linux specific code. */
#define _GNU_SOURCE /* See feature_test_macros(7) */
#define __USE_GNU 1
#endif /* Linux specific code. */

#include <sys/types.h>
#include <sys/queue.h>
#include <inttypes.h>

#ifdef _KERNEL /* Kernel space */
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mutex.h>

MALLOC_DEFINE(M_HASH_BUCKET, "hash_bucket", "hash bucket");
#define HB_ALLOC(size)		malloc(size, M_HASH_BUCKET, (M_NOWAIT | M_ZERO))
#define HB_FREE(mem)		free(mem, M_HASH_BUCKET)

#define HB_MTX_S		struct mtx
#define HB_MTX_INIT(mutex)	mtx_init(mutex, NULL, NULL, HB_MTX_RECURSE)
#define HB_MTX_DESTROY(mutex)	mtx_destroy(mutex)
#define HB_MTX_LOCK(mutex)	mtx_lock(mutex)
#define HB_MTX_TRYLOCK(mutex)	mtx_trylock(mutex)
#define HB_MTX_UNLOCK(mutex)	mtx_unlock(mutex)

#else /* User space */
#include <pthread.h>
#include <errno.h>
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <stdlib.h> /* malloc, exit */

#define HB_ALLOC(size)		malloc(size)
#define HB_FREE(mem)		free(mem)

#define HB_MTX_S		pthread_mutex_t

#define HB_MTX_INIT(mutex) {						\
	pthread_mutexattr_t attr;					\
	pthread_mutexattr_init(&attr);					\
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);	\
	pthread_mutex_init(mutex, &attr);				\
	pthread_mutexattr_destroy(&attr);				\
}
#define HB_MTX_DESTROY(mutex)	pthread_mutex_destroy(mutex)
#define HB_MTX_LOCK(mutex)	pthread_mutex_lock(mutex)
#define HB_MTX_TRYLOCK(mutex)	pthread_mutex_trylock(mutex)
#define HB_MTX_UNLOCK(mutex)	pthread_mutex_unlock(mutex)

#endif


#ifndef TAILQ_FOREACH_SAFE
#define	TAILQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = TAILQ_FIRST((head));				\
	    (var) && ((tvar) = TAILQ_NEXT((var), field), 1);		\
	    (var) = (tvar))
#endif



typedef struct hbucket_zone_s *hbucket_zone_p;
typedef struct hbucket_s *hbucket_p;


typedef struct hbucket_entry_s {
	TAILQ_ENTRY(hbucket_entry_s) next;
	hbucket_zone_p	zone;	/* Point to backet were object stored. */
	void		*data;	/* Bucket entry data. */
} hbucket_entry_t, *hbucket_entry_p;

TAILQ_HEAD(hbucket_entry_head, hbucket_entry_s);

/* Internal use: bucket hash zone. */
typedef struct hbucket_zone_s {	/* Bucket hash zone. */
	HB_MTX_S	*pmtx;
	HB_MTX_S	mtx;	/* add/delete/get entry lock. */
	struct hbucket_entry_head entry_head;
	hbucket_p	hbskt;
	volatile size_t	count;	/* Enries count in hash zone. */
} hbucket_zone_t;


/* Creates hash (zone index) from key data. */
typedef uint32_t (*hbucket_entry_hash_fn)(void *udata, const uint8_t *key,
    size_t key_size);
/* Compares data with key: return 0 on euqual, like memcmp, bcmp. */
typedef int (*hbucket_entry_cmp_fn)(void *udata, const uint8_t *key,
    size_t key_size, void *data);
/*
 * Hash bucket data enum callback.
 * hbucket_entry_enum() / hbucket_zone_entry_enum() will call until entry_enum_cb 
 * return 0
 */
typedef int (*hbucket_entry_enum_cb)(void *udata, hbucket_entry_p entry);

/* Contain hbucket_zone_t~s and additional data.  */
typedef struct hbucket_s {
	hbucket_zone_p	zones;
	volatile size_t	count; /* Total entries count in bucket. */
	uint32_t	hashsize; /* zones_count */
	uint32_t	hashmask;
	void		*udata;
	hbucket_entry_hash_fn hash_fn;
	hbucket_entry_cmp_fn cmp_fn;
} hbucket_t;



/*
 * Safe and fast unique entry add:
 * hbucket_entry_get(HBUCKET_GET_F_F_LOCK, &zone);
 * - if no entry, then zone is locked on return
 * ...create entry...
 * hbucket_entry_add(HBUCKET_ADD_F_NO_LOCK, zone);
 * - add to locked zone and unlock it.
 */
// hbucket_entry_get()
#define HBUCKET_GET_F_NO_LOCK	(1 << 0) /* Do not lock bucket before get. */
#define HBUCKET_GET_F_S_UNLOCK	(1 << 1) /* Unlock bucket if found, be careful! */
#define HBUCKET_GET_F_F_LOCK	(1 << 2) /* Do not unlock bucket if not found. */

/* If zone != NULL then key and key_size ignored. */
// hbucket_entry_add()
#define HBUCKET_ADD_F_NO_LOCK	(1 << 0) /* Do not lock bucket before add. */
#define HBUCKET_ADD_F_NO_UNLOCK	(1 << 1) /* Do not unlock bucket after add. */




static inline int
hbucket_create(int multi_thread, uint32_t hashsize, void *udata,
    hbucket_entry_hash_fn hash_fn, hbucket_entry_cmp_fn cmp_fn,
    hbucket_p *hbskt_ret) {
	hbucket_p hbskt;
	uint32_t i;

	if (0 == hashsize || NULL == hash_fn || NULL == cmp_fn || NULL == hbskt_ret)
		return (EINVAL);
	if (!powerof2(hashsize))
		return (EINVAL);

	i = (sizeof(hbucket_t) + (sizeof(hbucket_zone_t) * hashsize));
	hbskt = HB_ALLOC(i);
	if (NULL == hbskt)
		return (ENOMEM);
	memset(hbskt, 0, i);
	hbskt->zones = (hbucket_zone_p)(hbskt + 1);
	hbskt->hashsize = hashsize;
	hbskt->hashmask = (hashsize - 1);
	hbskt->udata = udata;
	hbskt->hash_fn = hash_fn;
	hbskt->cmp_fn = cmp_fn;
	/* Initialize the hash buckets. */
	for (i = 0; i < hashsize; i ++) {
		TAILQ_INIT(&hbskt->zones[i].entry_head);
		hbskt->zones[i].hbskt = hbskt;
		if (0 == multi_thread)
			continue;
		/* Init mutex for multithread mode. */
		hbskt->zones[i].pmtx = &hbskt->zones[i].mtx;
		HB_MTX_INIT(&hbskt->zones[i].mtx);
	}
	(*hbskt_ret) = hbskt;
	return (0);
}

static inline void
hbucket_destroy(hbucket_p hbskt, hbucket_entry_enum_cb enum_cb, void *udata) {
	hbucket_zone_p zone;
	hbucket_entry_p entry, entry_temp;
	uint32_t i;

	if (NULL == hbskt)
		return;
	for (i = 0; i < hbskt->hashsize; i ++) {
		zone = &hbskt->zones[i];
		if (NULL != zone->pmtx)
			HB_MTX_LOCK(zone->pmtx);
		TAILQ_FOREACH_SAFE(entry, &zone->entry_head, next, entry_temp) {
			TAILQ_REMOVE(&zone->entry_head, entry, next);
			entry->zone = NULL;
			if (NULL != enum_cb)
				enum_cb(udata, entry);
		}
		if (NULL != zone->pmtx) {
			HB_MTX_UNLOCK(zone->pmtx);
			HB_MTX_DESTROY(zone->pmtx);
		}
	}
	HB_FREE(hbskt);
}

static inline size_t
hbucket_get_entries_count(hbucket_p hbskt) {

	if (NULL == hbskt)
		return (0);
	return (hbskt->count);
}


static inline hbucket_zone_p
hbucket_get_zone(hbucket_p hbskt, const uint8_t *key, size_t key_size) {
	uint32_t hash;

	hash = (hbskt->hash_fn(hbskt->udata, key, key_size) & hbskt->hashmask);
	return (&hbskt->zones[hash]);
}


static inline void
hbucket_zone_lock(hbucket_zone_p zone) {

	if (NULL == zone || NULL == zone->pmtx)
		return;
	HB_MTX_LOCK(zone->pmtx);
}

static inline void
hbucket_zone_unlock(hbucket_zone_p zone) {

	if (NULL == zone || NULL == zone->pmtx)
		return;
	HB_MTX_UNLOCK(zone->pmtx);
}

static inline size_t
hbucket_zone_get_entries_count(hbucket_zone_p zone) {

	if (NULL == zone)
		return (0);
	return (zone->count);
}

static inline void
hbucket_entry_lock(hbucket_entry_p entry) {

	if (NULL == entry)
		return;
	hbucket_zone_lock(entry->zone);
}

static inline void
hbucket_entry_unlock(hbucket_entry_p entry) {

	if (NULL == entry)
		return;
	hbucket_zone_unlock(entry->zone);
}

static inline int
hbucket_zone_entry_enum(hbucket_zone_p zone, hbucket_entry_enum_cb enum_cb,
    void *udata) {
	hbucket_entry_p entry, entry_temp;
	int ret = 0;

	if (NULL == zone || NULL == enum_cb)
		return (EINVAL);

	if (NULL != zone->pmtx)
		HB_MTX_LOCK(zone->pmtx);
	TAILQ_FOREACH_SAFE(entry, &zone->entry_head, next, entry_temp) {
		ret = enum_cb(udata, entry);
		if (0 != ret)
			break;
	}
	if (NULL != zone->pmtx)
		HB_MTX_UNLOCK(zone->pmtx);

	return (ret);
}

static inline int
hbucket_entry_enum(hbucket_p hbskt, hbucket_entry_enum_cb enum_cb, void *udata) {
	uint32_t i;
	int ret = 0;

	if (NULL == hbskt || NULL == enum_cb)
		return (EINVAL);

	for (i = 0; i < hbskt->hashsize && 0 == ret; i ++)
		ret = hbucket_zone_entry_enum(&hbskt->zones[i], enum_cb, udata);

	return (ret);
}

static inline void
hbucket_entry_remove(hbucket_entry_p entry) {
	HB_MTX_S *pmtx;

	if (NULL == entry || NULL == entry->zone)
		return;
	pmtx = entry->zone->pmtx;
	if (NULL != pmtx)
		HB_MTX_LOCK(pmtx);
	TAILQ_REMOVE(&entry->zone->entry_head, entry, next);
	entry->zone->count --;
	entry->zone->hbskt->count --;
	entry->zone = NULL;
	if (NULL != pmtx)
		HB_MTX_UNLOCK(pmtx);
}

static inline int
hbucket_entry_get(hbucket_p hbskt, uint32_t flags, const uint8_t *key,
    size_t key_size, hbucket_zone_p *zone_ret, hbucket_entry_p *entry_ret) {
	hbucket_zone_p zone;
	hbucket_entry_p entry;

	if (NULL == hbskt || NULL == entry_ret)
		return (EINVAL);
	/* Get zone. */
	zone = hbucket_get_zone(hbskt, key, key_size);
	if (NULL != zone_ret)
		(*zone_ret) = zone;

	if (NULL != zone->pmtx && 0 == (HBUCKET_GET_F_NO_LOCK & flags))
		HB_MTX_LOCK(zone->pmtx);
	TAILQ_FOREACH(entry, &zone->entry_head, next) {
		if (0 == hbskt->cmp_fn(hbskt->udata, key, key_size, entry->data)) {
			(*entry_ret) = entry;
			if (NULL != zone->pmtx &&
			    0 != (HBUCKET_GET_F_S_UNLOCK & flags))
				HB_MTX_UNLOCK(zone->pmtx);
			return (0); /* Found! */
		}
	}
	if (NULL != zone->pmtx && 0 == (HBUCKET_GET_F_F_LOCK & flags))
		HB_MTX_UNLOCK(zone->pmtx);
	(*entry_ret) = NULL;

	return (-1); /* Not found. */
}

/* add to zone */
static inline int
hbucket_entry_add(hbucket_p hbskt, uint32_t flags, hbucket_zone_p zone,
    const uint8_t *key, size_t key_size, hbucket_entry_p entry) {

	if ((NULL == hbskt && NULL == zone) || NULL == entry)
		return (EINVAL);

	if (NULL == zone)
		zone = hbucket_get_zone(hbskt, key, key_size);
	if (NULL != zone->pmtx && 0 == (HBUCKET_ADD_F_NO_LOCK & flags))
		HB_MTX_LOCK(zone->pmtx);
	entry->zone = zone;
	TAILQ_INSERT_HEAD(&zone->entry_head, entry, next);
	zone->count ++;
	zone->hbskt->count ++;
	if (NULL != zone->pmtx && 0 == (HBUCKET_ADD_F_NO_UNLOCK & flags))
		HB_MTX_UNLOCK(zone->pmtx);

	return (0);
}


#endif /* __HASH_BASKET_H__ */
