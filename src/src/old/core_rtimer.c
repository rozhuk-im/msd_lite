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


#include <sys/param.h>
#ifdef __linux__ /* Linux specific code. */
#	define _GNU_SOURCE /* See feature_test_macros(7) */
#	define __USE_GNU 1
#endif /* Linux specific code. */
#include <sys/types.h>
#include <sys/queue.h> // list, slist
//#include <sys/lock.h>
//#include <sys/mutex.h>
#include <inttypes.h>
#include <stdlib.h> /* malloc, exit */
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <time.h>
#include <errno.h>

#include "macro_helpers.h"
#include "core_thrp.h"
#include "core_rtimer.h"


/*
 * 
 * [timer]
 * -rings - deprecated
 * --ring items
 * ---timers
 */


#define RTIMER_RING_ITEMS_COUNT	0xffff



/* Ring item with timers. */
typedef struct rtq_item_s {
	/* rwlock may be here. */
	struct rtq_timer_head	timers;
	rtq_p		rtimerq;	/* Pointer to ring timer. */
} rtq_item_t;


/* Ring timer queue. */
typedef struct rtq_s {
	thrp_udata_t	thrp_data; /* socket, file, etc... = pointer to this struct */
	thrpt_p		thrpt; /* Thread pool handle. */
	uintptr_t	tick_time; /* One tick time. */
	uintptr_t	cur_ri; /* Current ring item with timers to execute, so if add timer with timeout=0 it will cir_ri timer list */
	rtq_item_t	ring_items[RTIMER_RING_ITEMS_COUNT]; /* static allocated ring items */
} rtq_t;




static void	io_timer_callback(thrp_event_p ev, thrp_udata_p thrp_udata);




int
rtq_create(thrpt_p thrpt, uintptr_t tick_time, rtq_p *rtimerq_ret) {
	rtq_p rtimerq;
	int error, i;

	if (NULL == thrpt || 0 == tick_time || NULL == rtimerq_ret)
		return (EINVAL);
	rtimerq = (rtq_p)zalloc(sizeof(rtq_t));
	if (NULL == rtimerq)
		return (ENOMEM);
	rtimerq->thrp_data.cb_func = io_timer_callback;
	rtimerq->thrp_data.ident = (uintptr_t)rtimerq;
	rtimerq->thrpt = thrpt;
	rtimerq->tick_time = tick_time;
	rtimerq->cur_ri = 0;
	
	/* Init ring items. */
	for (i = 0; i < RTIMER_RING_ITEMS_COUNT; i ++) {
		//mtx_init(&rtimerq->ring_items[i].rw_lock, "rtimerq", NULL, MTX_DEF);
		TAILQ_INIT(&rtimerq->ring_items[i].timers);
		rtimerq->ring_items[i].rtimerq = rtimerq;
	}

	error = thrpt_ev_add_ex(thrpt, THRP_EV_TIMER, 0, 0, tick_time, &rtimerq->thrp_data);
	if (0 != error) {
		free(rtimerq);
		return (error);
	}

	(*rtimerq_ret) = rtimerq;
	return (0);
}

void
rtq_destroy(rtq_p rtimerq) {
	rtq_item_p item;
	rtq_timer_p timer;//, timer_tmp;
	int i;

	if (NULL == rtimerq)
		return;

	thrpt_ev_del(THRP_EV_TIMER, &rtimerq->thrp_data);

	/* We dont need walk trouth rings, we have all ring items. */
	/* Now we free all rtq_timer in timers lists. */
	for (i = 0; i < RTIMER_RING_ITEMS_COUNT; i ++) {
		item = &rtimerq->ring_items[i];// current ring item
		//mtx_lock(&item->rw_lock);// rwlock may be here
		while (NULL != (timer = TAILQ_FIRST(&item->timers))) {
		//TAILQ_FOREACH_SAFE(timer, &item->timers, next, timer_tmp) {
			rtq_timer_stop(timer);
			//rtq_timer_free(timer);
		}
		//mtx_unlock(&item->rw_lock);
		//mtx_destroy(&item->rw_lock);
	}

	mem_filld(rtimerq, sizeof(rtq_t));
	free(rtimerq);
}





rtq_timer_p
rtq_timer_alloc(void) {
	rtq_timer_p timer;

	timer = (rtq_timer_p)zalloc(sizeof(rtq_timer_t));
	if (NULL == timer)
		return (timer);
	timer->flags |= RT_TIMER_F_ALLOCATED;

	return (timer);
}

void
rtq_timer_free(rtq_timer_p timer) {

	rtq_timer_stop(timer);
	if ((RT_TIMER_F_ALLOCATED & timer->flags) == 0) {
		mem_bzero(timer, sizeof(rtq_timer_t));
		return;
	}
	mem_filld(timer, sizeof(rtq_timer_t));
	free(timer);
}



void
rtq_timer_start(rtq_p rtimerq, rtq_timer_p timer, uintptr_t interval, int periodic,
    rtq_cb cb_func, void *udata) {
	uintptr_t index;

	interval = (interval / rtimerq->tick_time);
	if (0 != periodic) {
		timer->interval = interval;
		timer->flags |= RT_TIMER_F_PERIODIC;
	} else {
		timer->flags &= ~RT_TIMER_F_PERIODIC;
	}
	timer->cb_func = cb_func;
	timer->udata = udata;

	timer->cycle_count = (interval / RTIMER_RING_ITEMS_COUNT);
	index = (rtimerq->cur_ri + (interval - (timer->cycle_count * RTIMER_RING_ITEMS_COUNT)));
	if (index > RTIMER_RING_ITEMS_COUNT)
		index -= RTIMER_RING_ITEMS_COUNT;
	timer->rng_item = &rtimerq->ring_items[index]; // pointer to ring item were timer is
	//mtx_lock(&timer->rng_item->rw_lock);
	TAILQ_INSERT_HEAD(&timer->rng_item->timers, timer, next);
	//mtx_unlock(&timer->rng_item->rw_lock);
}

void
rtq_timer_stop(rtq_timer_p timer) {
	rtq_item_p item;

	item = timer->rng_item;

	//mtx_lock(&item->rw_lock);
	TAILQ_REMOVE(&item->timers, timer, next);
	//mtx_unlock(&item->rw_lock);
}




void
io_timer_callback(thrp_event_p ev, thrp_udata_p thrp_udata) {
	rtq_p rtimerq = (rtq_p)thrp_udata;
	rtq_item_p item;
	rtq_timer_p timer, timer_tmp;
	uintptr_t index;


	if (ev->event != THRP_EV_TIMER || thrp_udata->ident != (uintptr_t)rtimerq)
		return;

	/* Execute current timers. */
	item = &rtimerq->ring_items[rtimerq->cur_ri];// current ring item
	//mtx_lock(&item->rw_lock);// rwlock may be here
	TAILQ_FOREACH_SAFE(timer, &item->timers, next, timer_tmp) {
		if (timer->cycle_count > 0) {
			timer->cycle_count --;
			continue;
		}

		/* Now timer time to work! */
		/* Execute timer proc */
		timer->cb_func(thrp_udata->thrpt, timer, timer->udata);

		// remove timer from ring
		TAILQ_REMOVE(&item->timers, timer, next);

		if (RT_TIMER_F_PERIODIC & timer->flags) {// reshedule periodic timer
			timer->cycle_count = (timer->interval / RTIMER_RING_ITEMS_COUNT);
			index = (rtimerq->cur_ri + (timer->interval - (timer->cycle_count * RTIMER_RING_ITEMS_COUNT)));
			if (index > RTIMER_RING_ITEMS_COUNT)
				index -= RTIMER_RING_ITEMS_COUNT;
			timer->rng_item = &rtimerq->ring_items[index]; // pointer to ring item were timer is
			/* XXX potential deadlock! */
			//mtx_lock(&timer->rng_item->rw_lock);
			TAILQ_INSERT_HEAD(&timer->rng_item->timers, timer, next);
			//mtx_unlock(&timer->rng_item->rw_lock);
		}
	}
	//mtx_unlock(&item->rw_lock);

	/* Rotate ring items with timers. */
	rtimerq->cur_ri ++; // rotate ring (items)
	if (RTIMER_RING_ITEMS_COUNT == rtimerq->cur_ri)
		rtimerq->cur_ri = 0;

}


