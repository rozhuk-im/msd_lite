/*-
 * Copyright (c) 2012 Rozhuk Ivan <rozhuk.im@gmail.com>
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


#ifndef __CORE_DATA_CACHE_H__
#define __CORE_DATA_CACHE_H__

#include <inttypes.h>
#include <sys/queue.h>


#define CORE_DATA_CACHE_BUCKETS	256

typedef struct data_cache_bucket_s *data_cache_bucket_p;
typedef struct data_cache_s *data_cache_p;


typedef struct data_cache_item_s {
	TAILQ_ENTRY(data_cache_item_s)	next;
	data_cache_bucket_p	bucket;
	/* item data */
	time_t		valid_untill;
	volatile uint64_t returned_count;
	uint32_t	updating; /* Update in progress. Prevent cache cleanp delete. */

	void		*data;
} data_cache_item_t, *data_cache_item_p;

TAILQ_HEAD(data_cache_item_head, data_cache_item_s);


/* Custom allocate and free data. */
typedef void* (*data_cache_alloc_data_func)(const uint8_t *key, size_t key_size);
typedef void (*data_cache_free_data_func)(void *data);
/* Creates hash (bucket index) from key. */
typedef uint32_t (*data_cache_hash_func)(const uint8_t *key, size_t key_size);
/* Compares data with key */
typedef int (*data_cache_cmp_data_func)(const uint8_t *key, size_t key_size, void *data);
/* Cache data enum callback: return 0 on euqual, like memcmp, bcmp */
typedef int (*data_cache_enum_cb)(void *udata, data_cache_item_p dc_item);

int	data_cache_create(data_cache_p *dcache,
	    data_cache_alloc_data_func alloc_data_fn,
	    data_cache_free_data_func free_data_fn, data_cache_hash_func hash_fn,
	    data_cache_cmp_data_func cmp_data_fn,
	    uint32_t clean_interval);
void	data_cache_destroy(data_cache_p dcache);
void	data_cache_clean(data_cache_p dcache);
int	data_cache_enum(data_cache_p dcache, data_cache_enum_cb enum_cb,
	    void *udata);

void	data_cache_item_free(data_cache_item_p dc_item);
void	data_cache_item_lock(data_cache_item_p dc_item);
void	data_cache_item_unlock(data_cache_item_p dc_item);
int	data_cache_item_get(data_cache_p dcache, const uint8_t *key, size_t key_size,
	    data_cache_item_p *dc_item);
int	data_cache_item_add(data_cache_p dcache, const uint8_t *key, size_t key_size,
	    data_cache_item_p *dc_item);


#endif /* __CORE_DATA_CACHE_H__ */
