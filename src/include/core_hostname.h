/*-
 * Copyright (c) 2013 Rozhuk Ivan <rozhuk.im@gmail.com>
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


#ifndef __CORE_HOSTNAME_H__
#define __CORE_HOSTNAME_H__

#include "buf_case.h"

#define HOSTNAME_PREALLOC	8


typedef struct hostname_s {
	size_t		size;	/* Host name size. */
	uint8_t		*name;	/* Hostname. */
} hostname_t, *hostname_p;

typedef struct hostname_list_s {
	size_t		allocated; /* Num of avaible struct hostname_p. */
	size_t		count;	/* Num of used struct hostname_p. */
	hostname_p	*names;
	int		any_name; /* name = '*' */
} hostname_list_t, *hostname_list_p;




static inline int
hostname_list_init(hostname_list_p hn_lst) {

	if (NULL == hn_lst)
		return (EINVAL);
	memset(hn_lst, 0, sizeof(hostname_list_t));
	/*hn_lst->names = malloc((HOSTNAME_PREALLOC * sizeof(hostname_p)));
	if (NULL == hn_lst->names)
		return (ENOMEM);
	hn_lst->allocated = HOSTNAME_PREALLOC;
	hn_lst->count = 0;*/
	return (0);
}

static inline void
hostname_list_deinit(hostname_list_p hn_lst) {
	size_t i;

	if (NULL == hn_lst)
		return;
	if (NULL != hn_lst->names) {
		for (i = 0; i <	hn_lst->count; i ++) {
			if (NULL == hn_lst->names[i])
				continue;
			free(hn_lst->names[i]);
		}
		free(hn_lst->names);
		hn_lst->allocated = 0;
	}
}

static inline hostname_list_p
hostname_list_alloc() {
	hostname_list_p hn_lst;

	hn_lst = malloc(sizeof(hostname_list_t));
	if (NULL == hn_lst)
		return (hn_lst);
	if (0 != hostname_list_init(hn_lst)) {
		free(hn_lst);
		return (NULL);
	}
	return (hn_lst);
}

static inline void
hostname_list_free(hostname_list_p hn_lst) {

	if (NULL == hn_lst)
		return;
	hostname_list_deinit(hn_lst);
	free(hn_lst);
}

static inline int
hostname_list_check_any(hostname_list_p hn_lst) {

	if (NULL == hn_lst)
		return (EINVAL);
	if (0 != hn_lst->any_name)
		return (ENOENT);
	return (0);
}

static inline int
hostname_list_check(hostname_list_p hn_lst, uint8_t *name, size_t size) {
	size_t i;

	if (NULL == hn_lst || NULL == name || 0 == size)
		return (EINVAL);

	if (0 != hn_lst->any_name)
		return (0);
	if (NULL == hn_lst->names || 0 == hn_lst->count)
		return (ENOENT);
	for (i = 0; i <	hn_lst->count; i ++) {
		if (NULL == hn_lst->names[i])
			continue;
		if (0 == buf_cmpi(hn_lst->names[i]->name, hn_lst->names[i]->size,
		    name, size))
			return (0);
	}
	return (ENOENT);
}

static inline int
hostname_list_find(hostname_list_p hn_lst, uint8_t *name, size_t size) {
	size_t i;

	if (NULL == hn_lst || NULL == name || 0 == size)
		return (EINVAL);

	if (NULL == hn_lst->names || 0 == hn_lst->count)
		return (ENOENT);
	for (i = 0; i <	hn_lst->count; i ++) {
		if (NULL == hn_lst->names[i])
			continue;
		if (0 != buf_cmpi(hn_lst->names[i]->name, hn_lst->names[i]->size,
		    name, size))
			continue;
		return (0);
	}
	return (ENOENT);
}

static inline int
hostname_list_add(hostname_list_p hn_lst, uint8_t *name, size_t size) {
	hostname_p *names_new;

	if (NULL == hn_lst || NULL == name || 0 == size)
		return (EINVAL);
	if (1 == size && '*' == (*name)) {
		hn_lst->any_name = 1;
		return (0);
	}
	if (0 == hostname_list_find(hn_lst, name, size)) /* Prevent duplicates. */
		return (0);
	/* Add new item. */
	if (hn_lst->allocated == hn_lst->count) { /* realloc pointers. */
		hn_lst->allocated += HOSTNAME_PREALLOC;
		names_new = realloc(hn_lst->names, (sizeof(hostname_p) *
		    hn_lst->allocated));
		if (NULL == names_new) /* Realloc fail! */
			return (ENOMEM);
		hn_lst->names = names_new;
	}
	hn_lst->names[hn_lst->count] = malloc((sizeof(hostname_t) + size + 4));
	if (NULL == hn_lst->names[hn_lst->count])
		return (ENOMEM);
	hn_lst->names[hn_lst->count]->name = (uint8_t*)(hn_lst->names[hn_lst->count] + 1);
	memcpy(hn_lst->names[hn_lst->count]->name, name, size);
	hn_lst->names[hn_lst->count]->name[size] = 0;
	hn_lst->names[hn_lst->count]->size = size;
	hn_lst->count ++;
	return (0);
}


#endif /* __CORE_HOSTNAME_H__ */
