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


 
#ifndef __CORE_THREAD_POOL_H__
#define __CORE_THREAD_POOL_H__

#include <sys/param.h>

#ifdef __linux__ /* Linux specific code. */
#	define _GNU_SOURCE /* See feature_test_macros(7) */
#	define __USE_GNU 1
#endif /* Linux specific code. */

#include <sys/types.h>
#include <inttypes.h>
#include <time.h>




typedef struct thread_pool_s		*thrp_p;	/* Thread pool. */
typedef struct thread_pool_thread_s	*thrpt_p;	/* Thread pool thread. */
typedef struct thread_pool_udata_s	*thrp_udata_p;	/* Thread pool user data. */



typedef struct thrp_event_s { /* Thread pool event. */
	uint16_t	event;	/* Filter for event. */
	uint16_t	flags;	/* Action flags. */
	uint32_t	fflags;	/* Filter flag value. */
	uint64_t	data;	/* Filter data value: Read: ioctl(FIONREAD), write: ioctl(FIONSPACE) FIONWRITE, SIOCGIFBUFS, (SIOCOUTQ/SIOCINQ TIOCOUTQ/TIOCINQ + getsockopt(s, SOL_SOCKET, SO_SNDBUF, ...))? */
} thrp_event_t, *thrp_event_p;

/* Events		val	FreeBSD		__linux__ */
#define THRP_EV_READ	0 /* EVFILT_READ	EPOLLET | EPOLLIN | EPOLLRDHUP | EPOLLERR */
#define THRP_EV_WRITE	1 /* EVFILT_WRITE	EPOLLET | EPOLLOUT | EPOLLERR */
#define THRP_EV_TIMER	2 /* EVFILT_TIMER	THRP_EV_READ + timerfd_create */
#define THRP_EV_LAST	THRP_EV_TIMER
#define THRP_EV_MASK	0x0003 /* For internal use. */
#define THRP_EV_NONE	0xffff /* Recerved for internal use. */

/* Event flags. */
/* Only for set.		val			FreeBSD		__linux__ */
#define THRP_F_ONESHOT	(((uint16_t)1) << 0) /* Set: EV_ONESHOT		EPOLLONESHOT */ /* Delete event after recv. */
#define THRP_F_DISPATCH	(((uint16_t)1) << 1) /* Set: EV_DISPATCH	EPOLLONESHOT */ /* DISABLE event after recv. */
#define THRP_F_EDGE	(((uint16_t)1) << 2) /* Set: EV_CLEAR		EPOLLET */ /* Report only if avaible data changed.*/
 									/* If not set will report if data/space avaible untill disable/delete event. */
#define THRP_F_S_MASK	0x0007 /* For internal use - flags set mask. */
/* Return only. */
#define THRP_F_EOF	(((uint16_t)1) << 3) /* Ret: EV_EOF		EPOLLRDHUP */
#define THRP_F_ERROR	(((uint16_t)1) << 4) /* Ret: EV_EOF+fflags	EPOLLERR +  getsockopt(SO_ERROR) */ /* fflags contain error code. */



typedef void (*thrpt_cb)(thrp_event_p ev, thrp_udata_p thrp_udata);
typedef void (*thrpt_msg_cb)(thrpt_p thrpt, void *udata);
typedef void (*thrpt_msg_done_cb)(thrpt_p thrpt, size_t send_msg_cnt,
    size_t error_cnt, void *udata);


typedef struct thread_pool_udata_s { /* Thread pool ident and opaque user data. */
	thrpt_cb	cb_func;/* Function to handle IO complete/err. */
	uintptr_t	ident;	/* Identifier for this event: socket, file, etc.
				 * For timer ident can be ponter to mem or any
				 * unique number. */
	thrpt_p		thrpt;	/* Internal data, do not use!!! Pointer to thread data. */
	uint64_t	tpdata;	/* Internal data, do not use!!!
				 * Linux: timer - timer file handle;
				 * read/write/timer - event: THRP_EV_*;
				 * THRP_F_* flags. */
	/* Opaque user data ... */
} thrp_udata_t;


int	thrp_signal_handler_add_thrp(thrp_p thrp);
void	thrp_signal_handler(int sig);



typedef struct thrp_settings_s { /* Settings */
	uint32_t	flags;	/* THRP_S_F_* */
	size_t		threads_max;
	uint64_t	tick_time;
} thrp_settings_t, *thrp_settings_p;

#define THRP_S_F_BIND2CPU	(((uint32_t)1) << 0) /* Bind threads to CPUs */
#define THRP_S_F_CACHE_TIME_SYSC (((uint32_t)1) << 8) /* Cache thrpt_gettimev() syscals. */
//--#define THRP_S_F_SHARE_EVENTS	(((uint32_t)1) << 1) /* Not affected if threads_max = 1 */

/* Default values. */
#define THRP_S_DEF_FLAGS	(THRP_S_F_BIND2CPU)
#define THRP_S_DEF_THREADS_MAX	(0)
#define THRP_S_DEF_TICK_TIME	(10)

void	thrp_def_settings(thrp_settings_p s_ret);

#ifdef THRP_XML_CONFIG
int	thrp_xml_load_settings(const uint8_t *buf, size_t buf_size,
	    thrp_settings_p s);
#endif



int	thrp_init(void);
int	thrp_create(thrp_settings_p s, thrp_p *pthrp);

void	thrp_shutdown(thrp_p thrp);
void	thrp_shutdown_wait(thrp_p thrp);
void	thrp_destroy(thrp_p thrp);

int	thrp_threads_create(thrp_p thrp, int skip_first);
int	thrp_thread_attach_first(thrp_p thrp);
int	thrp_thread_dettach(thrpt_p thrpt);
size_t	thrp_thread_count_max_get(thrp_p thrp);
size_t	thrp_thread_count_get(thrp_p thrp);

thrpt_p	thrp_thread_get_current(void);
thrpt_p	thrp_thread_get(thrp_p thrp, size_t thread_num);
thrpt_p	thrp_thread_get_rr(thrp_p thrp);
thrpt_p	thrp_thread_get_pvt(thrp_p thrp); /* Shared virtual thread. */
int	thrp_thread_get_cpu_id(thrpt_p thrpt);
size_t	thrp_thread_get_num(thrpt_p thrpt);

thrp_p	thrpt_get_thrp(thrpt_p thrpt);
size_t	thrpt_is_running(thrpt_p thrpt);
void	*thrpt_get_msg_queue(thrpt_p thrpt);



int	thrpt_ev_add(thrpt_p thrpt, uint16_t event, uint16_t flags,
	    thrp_udata_p thrp_udata);
int	thrpt_ev_add_ex(thrpt_p thrpt, uint16_t event, uint16_t flags,
	    uint32_t fflags, uint64_t data, thrp_udata_p thrp_udata);
int	thrpt_ev_add2(thrpt_p thrpt, thrp_event_p ev, thrp_udata_p thrp_udata);
/*
 * flags - allowed: THRP_F_ONESHOT, THRP_F_DISPATCH, THRP_F_EDGE
 */
int	thrpt_ev_del(uint16_t event, thrp_udata_p thrp_udata);
int	thrpt_ev_enable(int enable, uint16_t event, thrp_udata_p thrp_udata);
int	thrpt_ev_enable_ex(int enable, uint16_t event, uint16_t flags,
	    uint32_t fflags, uint64_t data, thrp_udata_p thrp_udata);

#ifdef NOT_YET__FreeBSD__ /* Per thread queue functions. Only for kqueue! */
int	thrpt_ev_q_add(thrpt_p thrpt, uint16_t event, uint16_t flags,
	    thrp_udata_p thrp_udata);
int	thrpt_ev_q_del(uint16_t event, thrp_udata_p thrp_udata);
int	thrpt_ev_q_enable(int enable, uint16_t event, thrp_udata_p thrp_udata);
int	thrpt_ev_q_enable_ex(int enable, uint16_t event, uint16_t flags,
	    uint32_t fflags, uint64_t data, thrp_udata_p thrp_udata);
int	thrpt_ev_q_flush(thrpt_p thrpt);
#else
#define	thrpt_ev_q_add		thrpt_ev_add
#define	thrpt_ev_q_del		thrpt_ev_del
#define	thrpt_ev_q_enable	thrpt_ev_enable
#define	thrpt_ev_q_enable_ex	thrpt_ev_enable_ex
#define	thrpt_ev_q_flush

#endif

/* Thread cached time functions. */
int	thrpt_gettimev(thrpt_p thrpt, int real_time, struct timespec *tp);
time_t	thrpt_gettime(thrpt_p thrpt, int real_time);


#endif /* __CORE_THREAD_POOL_H__ */
