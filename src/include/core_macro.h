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


#ifndef __CORE_MACRO_H__
#define __CORE_MACRO_H__


#include <sys/param.h>

#ifdef __linux__ /* Linux specific code. */
#define _GNU_SOURCE /* See feature_test_macros(7) */
#define __USE_GNU 1
#endif /* Linux specific code. */

#include <sys/types.h>
#include <inttypes.h>

#ifndef IOV_MAX
#include <limits.h>
#include <bits/xopen_lim.h>
#include <bits/stdio_lim.h>
#endif




#ifndef SIZEOF
#define SIZEOF(X)	(sizeof(X) / sizeof(X[0]))
#endif

#ifndef ALIGNEX
#define ALIGNEX(size, align_size)					\
	(((size) + ((size_t)align_size) - 1) & ~(((size_t)align_size) - 1))
#define ALIGNEX_PTR(ptr, align_size)					\
	((((uint8_t*)ptr) + ((size_t)align_size) - 1) & ~(((size_t)align_size) - 1))
#endif

#ifndef min
#define min(a,b)	(((a) < (b)) ? (a) : (b))
#endif

#ifndef max
#define max(a,b)	(((a) > (b)) ? (a) : (b))
#endif

#ifndef limit_val
#define limit_val(val, min, max)					\
	(((val) > (max)) ? (max) : (((val) < (min)) ? (min) : (val)) )
#endif

#ifndef MAKEDWORD
#define MAKEDWORD(a, b)							\
	((uint32_t)(((uint16_t)(((uint32_t)(a)) & 0xffff)) |		\
	 ((uint32_t)((uint16_t)(((uint32_t)(b)) & 0xffff))) << 16))
#endif

#ifndef LOWORD
#define LOWORD(a)	((uint16_t)(((uint32_t)(a)) & 0xffff))
#endif

#ifndef HIWORD
#define HIWORD(a)	((uint16_t)((((uint32_t)(a)) >> 16) & 0xffff))
#endif


#ifndef __unused /* Linux has not this macro. */
#define	__unused	__attribute__((__unused__))
#endif


#ifndef TAILQ_FOREACH_SAFE /* Linux has not this macro. */
#define	TAILQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = TAILQ_FIRST((head));				\
	    (var) && ((tvar) = TAILQ_NEXT((var), field), 1);		\
	    (var) = (tvar))
#endif

#ifndef TAILQ_SWAP /* Linux has not this macro. */
#define TAILQ_SWAP(head1, head2, type, field) do {			\
	struct type *swap_first = (head1)->tqh_first;			\
	struct type **swap_last = (head1)->tqh_last;			\
	(head1)->tqh_first = (head2)->tqh_first;			\
	(head1)->tqh_last = (head2)->tqh_last;				\
	(head2)->tqh_first = swap_first;				\
	(head2)->tqh_last = swap_last;					\
	if ((swap_first = (head1)->tqh_first) != NULL)			\
		swap_first->field.tqe_prev = &(head1)->tqh_first;	\
	else								\
		(head1)->tqh_last = &(head1)->tqh_first;		\
	if ((swap_first = (head2)->tqh_first) != NULL)			\
		swap_first->field.tqe_prev = &(head2)->tqh_first;	\
	else								\
		(head2)->tqh_last = &(head2)->tqh_first;		\
} while (0)
#endif



#define is_space(c)	((c) == ' ' || ((c) >= '\t' && (c) <= '\r'))


#ifndef offsetof /* offsetof struct field */
#define	offsetof(type, field)						\
	((size_t)((const volatile void*)&((type*)0)->field))
#endif

#ifndef fieldsetof /* sizeof struct field */
#define	fieldsetof(type, field)						\
	((size_t)sizeof(((type*)0)->field))
#endif

#define MEMCPY_STRUCT_FIELD(dst, sdata, stype, sfield)			\
	memcpy(dst, (((char*)sdata) + offsetof(stype, sfield)),		\
	    fieldsetof(stype, sfield))


/* From linux: dirent.h */
#ifndef _D_EXACT_NAMLEN
#ifdef _DIRENT_HAVE_D_NAMLEN
# define _D_EXACT_NAMLEN(d) ((d)->d_namlen)
# define _D_ALLOC_NAMLEN(d) (_D_EXACT_NAMLEN (d) + 1)
#else
# define _D_EXACT_NAMLEN(d) (strlen ((d)->d_name))
# ifdef _DIRENT_HAVE_D_RECLEN
#  define _D_ALLOC_NAMLEN(d) (((char*) (d) + (d)->d_reclen) - &(d)->d_name[0])
# else
#  define _D_ALLOC_NAMLEN(d)						\
	((sizeof(d)->d_name > 1) ? sizeof (d)->d_name : _D_EXACT_NAMLEN (d) + 1)
# endif
#endif
#endif /* _D_EXACT_NAMLEN */



#define zalloc(size)	calloc(1, size)
#ifdef DEBUG
#include <stdio.h>  /* snprintf, fprintf */
static inline void memfilld(void *mem, size_t size) {

	memset(mem, 0xab, size);
	if (0xab != (*((uint8_t*)mem)))
		fprintf(stderr, "memfilld() crazy!\n");
}
#else
#define memfilld(mem, size)
#endif


#ifndef MTX_S
//#include <pthread.h>

#define MTX_S			pthread_mutex_t

#define MTX_INIT(mutex)	{						\
	pthread_mutexattr_t attr;					\
	pthread_mutexattr_init(&attr);					\
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);	\
	pthread_mutex_init(mutex, &attr);				\
	pthread_mutexattr_destroy(&attr);				\
}
#define MTX_DESTROY(mutex)	pthread_mutex_destroy(mutex)
#define MTX_LOCK(mutex)		pthread_mutex_lock(mutex)
#define MTX_TRYLOCK(mutex)	pthread_mutex_trylock(mutex)
#define MTX_UNLOCK(mutex)	pthread_mutex_unlock(mutex)

#endif



#endif /* __CORE_MACRO_H__ */
