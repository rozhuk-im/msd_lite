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


#ifndef __MACRO_HELPERS_H__
#define __MACRO_HELPERS_H__


#include <sys/param.h>

#ifdef __linux__ /* Linux specific code. */
#	define _GNU_SOURCE /* See feature_test_macros(7) */
#	define __USE_GNU 1
#endif /* Linux specific code. */

#include <sys/types.h>
#include <inttypes.h>

#ifndef IOV_MAX
#include <limits.h>
#include <bits/xopen_lim.h>
#include <bits/stdio_lim.h>
#endif



#ifndef SIZEOF
#	define SIZEOF(__val)	(sizeof(__val) / sizeof(__val[0]))
#endif

#ifndef ALIGNEX
#	define ALIGNEX(__size, __align_size)				\
		(((__size) + ((size_t)(__align_size)) - 1) & ~(((size_t)(__align_size)) - 1))
#	define ALIGNEX_PTR(__ptr, __align_size)				\
		((((char*)(__ptr)) + ((size_t)(__align_size)) - 1) & ~(((size_t)(__align_size)) - 1))
#endif

#ifndef min
#	define min(__a, __b)	(((__a) < (__b)) ? (__a) : (__b))
#endif

#ifndef max
#	define max(__a, __b)	(((__a) > (__b)) ? (__a) : (__b))
#endif

#ifndef limit_val
#	define limit_val(__val, __min, __max)				\
		(((__val) > (__max)) ? (__max) : (((__val) < (__min)) ? (__min) : (__val)) )
#endif

#ifndef MAKEDWORD
#	define MAKEDWORD(__lo, __hi)					\
		((((uint32_t)(__lo)) & 0xffff) | ((((uint32_t)(__hi)) & 0xffff) << 16))
#endif

#ifndef LOWORD
#	define LOWORD(__val)	((uint16_t)(((uint32_t)(__val)) & 0xffff))
#endif

#ifndef HIWORD
#	define HIWORD(__val)	((uint16_t)((((uint32_t)(__val)) >> 16) & 0xffff))
#endif


#define UINT32_BIT(__bit)		(((uint32_t)1) << (__bit))
#define UINT32_BIT_SET(__mask, __bit)	(__mask) |= UINT32_BIT((__bit))
#define UINT32_BIT_IS_SET(__mask, __bit) (0 != ((__mask) & UINT32_BIT((__bit))))

#define UINT64_BIT(__bit)		(((uint64_t)1) << (__bit))
#define UINT64_BIT_SET(__mask, __bit)	(__mask) |= UINT64_BIT((__bit))
#define UINT64_BIT_IS_SET(__mask, __bit) (0 != ((__mask) & UINT64_BIT((__bit))))


#ifndef __unused /* Linux has not this macro. */
#	define	__unused	__attribute__((__unused__))
#endif


#ifndef MK_RW_PTR /* Linux has not this macro. */
#	define	MK_RW_PTR(__ptr)	((void*)(size_t)(__ptr))
#endif


#ifndef TAILQ_FOREACH_SAFE /* Linux has not this macro. */
#define	TAILQ_FOREACH_SAFE(__var, __head, __field, __tvar)		\
	for ((__var) = TAILQ_FIRST((__head));				\
	    (__var) && ((__tvar) = TAILQ_NEXT((__var), __field), 1);	\
	    (__var) = (__tvar))
#endif

#ifndef TAILQ_SWAP /* Linux has not this macro. */
#define TAILQ_SWAP(__head1, __head2, __type, __field) {			\
	struct __type *swap_first = (__head1)->tqh_first;		\
	struct __type **swap_last = (__head1)->tqh_last;		\
	(__head1)->tqh_first = (__head2)->tqh_first;			\
	(__head1)->tqh_last = (__head2)->tqh_last;			\
	(__head2)->tqh_first = swap_first;				\
	(__head2)->tqh_last = swap_last;				\
	if (NULL != (swap_first = (__head1)->tqh_first)) {		\
		swap_first->__field.tqe_prev = &(__head1)->tqh_first;	\
	} else {							\
		(__head1)->tqh_last = &(__head1)->tqh_first;		\
	}								\
	if (NULL != (swap_first = (__head2)->tqh_first)) {		\
		swap_first->__field.tqe_prev = &(__head2)->tqh_first;	\
	} else {							\
		(__head2)->tqh_last = &(__head2)->tqh_first;		\
	}								\
}
#endif



#define is_space(__c)	(' ' == (__c) || ('\t' <= (__c) && '\r' >= (__c)))

#define IS_NAME_DOTS(__name)	((__name)[0] == '.' &&			\
				 ((__name)[1] == '\0' || 		\
				 ((__name)[1] == '.' && (__name)[2] == '\0')))


#ifndef offsetof /* offsetof struct field */
#	define	offsetof(__type, __field)				\
		((size_t)((const volatile void*)&((__type*)0)->__field))
#endif

#ifndef fieldsetof /* sizeof struct field */
#	define	fieldsetof(__type, __field) ((size_t)sizeof(((__type*)0)->__field))
#endif

#define MEMCPY_STRUCT_FIELD(__dst, __sdata, __stype, __sfield)		\
	memcpy(__dst,							\
	    (((const char*)(__sdata)) + offsetof(__stype, __sfield)),	\
	    fieldsetof(__stype, __sfield))


/* From linux: dirent.h */
#ifndef _D_EXACT_NAMLEN
#ifdef _DIRENT_HAVE_D_NAMLEN
#	define _D_EXACT_NAMLEN(__de)	((__de)->d_namlen)
#else
#	define _D_EXACT_NAMLEN(__de)	(strnlen((__de)->d_name, sizeof((__de)->d_name)))
#endif
#endif /* _D_EXACT_NAMLEN */




#ifndef MTX_S
//#include <pthread.h>

#define MTX_S			pthread_mutex_t

#define MTX_INIT(__mutex) {						\
	pthread_mutexattr_t attr;					\
	pthread_mutexattr_init(&attr);					\
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);	\
	pthread_mutex_init((__mutex), &attr);				\
	pthread_mutexattr_destroy(&attr);				\
}
#define MTX_DESTROY(__mutex)	pthread_mutex_destroy((__mutex))
#define MTX_LOCK(__mutex)	pthread_mutex_lock((__mutex))
#define MTX_TRYLOCK(__mutex)	pthread_mutex_trylock((__mutex))
#define MTX_UNLOCK(__mutex)	pthread_mutex_unlock((__mutex))

#endif



__attribute__((gnu_inline, always_inline))
static inline int
debug_break(void) {
#ifdef _MSC_VER
#	include <intrin.h>
	__debugbreak();
#elif 1
	__builtin_trap();
#else
#	include <signal.h>
	raise(SIGTRAP);
#endif
}

#define debug_break_if(__a)	if ((__a)) debug_break()

#ifdef DEBUG
#	define debugd_break	debug_break
#	define debugd_break_if	debug_break_if
#else
#	define debugd_break()
#	define debugd_break_if(__a)
#endif



#endif /* __MACRO_HELPERS_H__ */
