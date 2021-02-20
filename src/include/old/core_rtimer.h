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
 /* Ring Timer Queue */


#ifndef __CORE_RING_TIMER_QUEUE_H__
#define __CORE_RING_TIMER_QUEUE_H__


#include <sys/queue.h> /* list, slist */
#include "core_thrp.h"



typedef struct rtq_s		*rtq_p; /* Timers queue. */
typedef struct rtq_timer_s	*rtq_timer_p; /* One timer. */
typedef struct rtq_item_s	*rtq_item_p; /* Ring item with timers. */

typedef int (*rtq_cb)(thrpt_p thrpt, rtq_timer_p timer, void *udata);

/* One timer. */
typedef struct rtq_timer_s {
	TAILQ_ENTRY(rtq_timer_s) next;	/* For rings list. */
	rtq_item_p	rng_item;	/* Pointer to ring item were timer is. */
	uintptr_t	cycle_count;	/* number of cycles, before done. */
	uintptr_t	interval;	/* timer interval, 0 - if one shot timer (no repeats) */
	rtq_cb		cb_func;	/* function that called at time. */
	void		*udata;		/* user defined data, per thread pool. */
	uint32_t	flags;		/* RT_TIMER_F_* */
} rtq_timer_t;

TAILQ_HEAD(rtq_timer_head, rtq_timer_s);

#define RT_TIMER_F_ALLOCATED	(((uint32_t)1) << 0) /* Internal use. */
#define RT_TIMER_F_PERIODIC	(((uint32_t)1) << 1)



int	rtq_create(thrpt_p thrpt, uintptr_t tick_time, rtq_p *rtimerq_ret);
void	rtq_destroy(rtq_p rtimerq);

rtq_timer_p rtq_timer_alloc(void);
void	rtq_timer_free(rtq_timer_p timer);

void	rtq_timer_start(rtq_p rtimerq, rtq_timer_p timer, uintptr_t interval,
	    int periodic, rtq_cb cb_func, void *udata);
void	rtq_timer_stop(rtq_timer_p timer);





#endif // __CORE_RING_TIMER_QUEUE_H__
