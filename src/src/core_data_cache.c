/*-
 * Copyright (c) 2012 - 2016 Rozhuk Ivan <rozhuk.im@gmail.com>
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
#	define _GNU_SOURCE /* See feature_test_macros(7) */
#	define __USE_GNU 1
#endif /* Linux specific code. */
#include <sys/types.h>
#include <sys/queue.h>
#include <errno.h>
#include <time.h>
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <stdlib.h> /* malloc, exit */

#include "macro_helpers.h"
#include "mem_helpers.h"
#include "core_data_cache.h"




typedef struct data_cache_bucket_s {
	//struct mtx			rw_lock; /* add/delete/get item lock. */
	struct data_cache_item_head	items_head;
	data_cache_p			dcache;
} data_cache_bucket_t;


typedef struct data_cache_s {
	data_cache_alloc_data_func	alloc_data_fn;
	data_cache_free_data_func	free_data_fn;
	data_cache_hash_func		hash_fn;
	data_cache_cmp_data_func	cmp_data_fn;
	time_t				next_clean_time;
	uint32_t			clean_interval;
	data_cache_bucket_t		buckets[CORE_DATA_CACHE_BUCKETS];
} data_cache_t;



data_cache_bucket_p data_cache_get_bucket(data_cache_p dcache, const uint8_t *key,
		    size_t key_size);


int
data_cache_create(data_cache_p *dcache, data_cache_alloc_data_func alloc_data_fn,
    data_cache_free_data_func free_data_fn, data_cache_hash_func hash_fn,
    data_cache_cmp_data_func cmp_data_fn, uint32_t clean_interval) {
	data_cache_p dcache_ret;
	int i;

	if (NULL == dcache)
		return (EINVAL);
	dcache_ret = zalloc(sizeof(data_cache_t));
	if (NULL == dcache_ret)
		return (ENOMEM);
	dcache_ret->alloc_data_fn = alloc_data_fn;
	dcache_ret->free_data_fn = free_data_fn;
	dcache_ret->hash_fn = hash_fn;
	dcache_ret->cmp_data_fn = cmp_data_fn;
	dcache_ret->next_clean_time = (time(NULL) + clean_interval);
	dcache_ret->clean_interval = clean_interval;
	for (i = 0; i < CORE_DATA_CACHE_BUCKETS; i ++) {
		//mtx_init(&h_store->buckets[i].rw_lock, "data_cache", NULL, MTX_DEF);
		TAILQ_INIT(&dcache_ret->buckets[i].items_head);
		dcache_ret->buckets[i].dcache = dcache_ret;
	}
	(*dcache) = dcache_ret;
	return (0);
}

void
data_cache_destroy(data_cache_p dcache) {
	data_cache_item_p dc_item, dc_item_temp;
	int i;

	if (NULL == dcache)
		return;
	for (i = 0; i < CORE_DATA_CACHE_BUCKETS; i ++) {
		//mtx_lock(&dcache->buckets[i].rw_lock);
		TAILQ_FOREACH_SAFE(dc_item, &dcache->buckets[i].items_head, next,
		    dc_item_temp)
			data_cache_item_free(dc_item);
		//mtx_unlock(&dcache->buckets[i].rw_lock);
		//mtx_destroy(&dcache->buckets[i].rw_lock);
	}
	mem_filld(dcache, sizeof(data_cache_t));
	free(dcache);
}


void
data_cache_clean(data_cache_p dcache) {
	data_cache_item_p dc_item, dc_item_temp;
	size_t i;
	time_t time_now;

	if (NULL == dcache)
		return;
	time_now = time(NULL);
	if (time_now < dcache->next_clean_time)
		return;
	for (i = 0; i < CORE_DATA_CACHE_BUCKETS; i ++) {
		//mtx_lock(&dcache->buckets[i].rw_lock);
		TAILQ_FOREACH_SAFE(dc_item, &dcache->buckets[i].items_head, next,
		    dc_item_temp) {
			/* Host item LOCKED! */
			/* Keep in cache some time outdated recods. */
			if ((time_t)(dcache->clean_interval + dc_item->valid_untill) >
			    time_now ||
			    0 != dc_item->updating)
				continue;
			/* Delete item by timeout. */
			data_cache_item_free(dc_item);
		}
		//mtx_unlock(&dcache->buckets[i].rw_lock);
	}
	dcache->next_clean_time = (time_now + dcache->clean_interval);
}


int
data_cache_enum(data_cache_p dcache, data_cache_enum_cb enum_cb, void *udata) {
	data_cache_item_p dc_item;
	size_t i;

	if (NULL == dcache || NULL == enum_cb)
		return (EINVAL);

	for (i = 0; i < CORE_DATA_CACHE_BUCKETS; i ++) {
		//mtx_lock(&dcache->buckets[i].rw_lock);
		TAILQ_FOREACH(dc_item, &dcache->buckets[i].items_head, next) {
			/* Host item LOCKED! */
			if (0 != enum_cb(udata, dc_item)) {
				i = CORE_DATA_CACHE_BUCKETS;
				break;
			}
		}
		//mtx_unlock(&dcache->buckets[i].rw_lock);
	}

	return (0);
}


data_cache_bucket_p
data_cache_get_bucket(data_cache_p dcache, const uint8_t *key, size_t key_size) {

	return (&dcache->buckets[dcache->hash_fn(key, key_size)]);
}


/* Bucket must be locked! */
void
data_cache_item_free(data_cache_item_p dc_item) {

	if (NULL == dc_item)
		return;
	TAILQ_REMOVE(&dc_item->bucket->items_head, dc_item, next);
	dc_item->bucket->dcache->free_data_fn(dc_item->data);
	mem_filld(dc_item, sizeof(data_cache_item_t));
	free(dc_item);
}

void
data_cache_item_lock(data_cache_item_p dc_item) {

	if (NULL == dc_item)
		return;

	//mtx_lock(&dc_item->bucket->rw_lock);
}

void
data_cache_item_unlock(data_cache_item_p dc_item) {

	if (NULL == dc_item)
		return;

	//mtx_unlock(&dc_item->bucket->rw_lock);
}

int
data_cache_item_get(data_cache_p dcache, const uint8_t *key, size_t key_size,
    data_cache_item_p *dc_item) {
	data_cache_bucket_p bucket;
	data_cache_item_p dc_item_ret;

	if (NULL == dcache || NULL == key || 0 == key_size || NULL == dc_item)
		return (EINVAL);
	/* Get bucket. */
	bucket = data_cache_get_bucket(dcache, key, key_size);
	if (NULL == bucket) {
		(*dc_item) = NULL;
		return (EINVAL);
	}

	//mtx_lock(&bucket->rw_lock);
	TAILQ_FOREACH(dc_item_ret, &bucket->items_head, next) {
		if (0 == dcache->cmp_data_fn(key, key_size, dc_item_ret->data)) {
			(*dc_item) = dc_item_ret;
			return (0); /* Found! */
		}
	}
	//mtx_unlock(&bucket->rw_lock);
	(*dc_item) = NULL;

	return (-1); /* Not found. */
}

int
data_cache_item_add(data_cache_p dcache, const uint8_t *key, size_t key_size,
    data_cache_item_p *dc_item) {
	data_cache_bucket_p bucket;
	data_cache_item_p dc_item_ret;

	if (NULL == dc_item)
		return (EINVAL);
	bucket = data_cache_get_bucket(dcache, key, key_size);
	if (NULL == bucket) {
		(*dc_item) = NULL;
		return (EINVAL);
	}

	/* Try find exicting. */
	//mtx_lock(&bucket->rw_lock);
	TAILQ_FOREACH(dc_item_ret, &bucket->items_head, next) {
		/* TODO: add timeout check and delete. */
		if (0 == dcache->cmp_data_fn(key, key_size, dc_item_ret->data)) {
			(*dc_item) = dc_item_ret;
			return (0); /* Found! */
		}
	}
	////mtx_unlock(&bucket->rw_lock);

	/* Not found. */
	dc_item_ret = zalloc(sizeof(data_cache_item_t));
	if (NULL == dc_item_ret)
		return (ENOMEM);
	dc_item_ret->data = dcache->alloc_data_fn(key, key_size);
	if (NULL == dc_item_ret->data) {
		free(dc_item_ret);
		return (ENOMEM);
	}
	(*dc_item) = dc_item_ret;
	dc_item_ret->bucket = bucket;

	/* add to bucket */
	////mtx_lock(&bucket->rw_lock);
	TAILQ_INSERT_HEAD(&bucket->items_head, dc_item_ret, next);
	////mtx_unlock(&bucket->rw_lock);

	return (0);
}

