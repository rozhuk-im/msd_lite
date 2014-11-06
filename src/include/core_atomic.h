/*-
 * Copyright (c) 2014 Rozhuk Ivan <rozhuk.im@gmail.com>
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


#ifndef __CORE_ATOMIC_H__
#define __CORE_ATOMIC_H__


#include <sys/param.h>
#include <sys/types.h>

#ifdef BSD /* BSD specific code. */
#include <machine/atomic.h>
#endif /* BSD specific code. */

#ifdef __linux__ /* Linux specific code. */
#define _GNU_SOURCE /* See feature_test_macros(7) */
#define __USE_GNU 1
#endif /* Linux specific code. */


#define HAL_REORDER_BARRIER()		asm volatile ( "" : : : "memory" )

#ifdef __linux__ /* Linux specific code. */

static inline uintptr_t
atomic_load_acq_ptr(volatile uintptr_t *p) {

	HAL_REORDER_BARRIER();
	return (*p);
}

static inline uint64_t
atomic_load_acq_64(volatile uint64_t *p) {

	HAL_REORDER_BARRIER();
	return (*p);
}


static inline void
atomic_add_rel_ptr(volatile uintptr_t *p, uintptr_t v) {

	HAL_REORDER_BARRIER();
	(*p) += v;
	HAL_REORDER_BARRIER();
}

static inline void
atomic_add_rel_64(volatile uint64_t *p, uint64_t v) {

	HAL_REORDER_BARRIER();
	(*p) += v;
	HAL_REORDER_BARRIER();
}


static inline void
atomic_subtract_rel_ptr(volatile uintptr_t *p, uintptr_t v) {

	HAL_REORDER_BARRIER();
	(*p) -= v;
	HAL_REORDER_BARRIER();
}

static inline void
atomic_subtract_rel_64(volatile uint64_t *p, uint64_t v) {

	HAL_REORDER_BARRIER();
	(*p) -= v;
	HAL_REORDER_BARRIER();
}


#endif /* Linux specific code. */


#endif /* __CORE_ATOMIC_H__ */
