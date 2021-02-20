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


 
#ifndef __CORE_THREADP_H__
#define __CORE_THREADP_H__

#include <sys/param.h>

#ifdef __linux__ /* Linux specific code. */
#define _GNU_SOURCE /* See feature_test_macros(7) */
#define __USE_GNU 1
#endif /* Linux specific code. */

#include <sys/types.h>
#include <inttypes.h>
#include <time.h>




typedef struct thrp_s		*thrp_p;	/* Thread pool. */
typedef struct thrp_thread_s	*thrpt_p;	/* Thread pool thread. */
typedef struct thrp_udata_s	*thrp_udata_p;	/* Thread pool user data. */


typedef struct thrp_event_s { /* Thread pool event. */
	uint16_t	event;	/* Filter for event. */
	uint16_t	flags;	/* Action flags. */
	u_int		fflags;	/* Filter flag value. */
	intptr_t	data;	/* Filter data value: Read: ioctl(FIONREAD), write: ioctl(FIONSPACE) FIONWRITE, SIOCGIFBUFS, (SIOCOUTQ/SIOCINQ TIOCOUTQ/TIOCINQ + getsockopt(s, SOL_SOCKET, SO_SNDBUF, ...))? */
} thrp_event_t, *thrp_event_p;

typedef void (*thrpt_cb)(thrp_event_p ev, thrp_udata_p udata);
typedef void (*thrpt_msg_cb)(thrpt_p thrpt, void *udata);
typedef void (*thrpt_msg_done_cb)(thrpt_p thrpt, size_t send_msg_cnt,
    size_t error_cnt, void *udata);


/* Events		val	FreeBSD		__linux__	*/
#define THRP_EV_READ	0 /* EVFILT_READ	EPOLLET | EPOLLIN | EPOLLRDHUP | EPOLLERR */
#define THRP_EV_WRITE	1 /* EVFILT_WRITE	EPOLLET | EPOLLOUT | EPOLLERR */
#define THRP_EV_TIMER	2 /* EVFILT_TIMER	THRP_EV_READ + timerfd_create */
#define THRP_EV_LAST	THRP_EV_TIMER
#define THRP_EV_NONE	0xffff /* recerved for internal use */

/* Event flags. */
#define THRP_F_ONESHOT	(1 << 0) /* Set: EV_ONESHOT	EPOLLONESHOT + del */ /* DELete event after recv. */
#define THRP_F_DISPATCH	(1 << 1) /* Set: EV_DISPATCH	EPOLLONESHOT */ /* DISABLE event after recv. */
#define THRP_F_CLEAR	(1 << 2) /* Set: EV_CLEAR	-- */
#define THRP_F_EOF	(1 << 3) /* Ret: EV_EOF		EPOLLRDHUP */
#define THRP_F_ERROR	(1 << 4) /* Ret: EV_EOF+fflags	EPOLLERR +  getsockopt(SO_ERROR) */
				 /* fflags contain error code. */

typedef struct thrp_udata_s {	/* Thread pool ident and opaque user data. */
	thrpt_cb	cb_func;/* Function to handle IO complete/err. */
	uintptr_t	ident;	/* Identifier for this event: socket, file, etc.
				 * For timer ident can be ponter to mem or any
				 * unique number. */
	thrpt_p		thrpt;	/* Internal data, do not use!!! Pointer to thread data. */
	uintptr_t	tpdata;	/* Internal data, do not use!!!
				 * Linux: timer - timer file handle;
				 * read/write - event: THRP_EV_* */
	/* Opaque user data ... */
} thrp_udata_t;


int	thrp_init(void);
int	thrp_create(uint32_t flags, size_t threads_max, uintptr_t tick_time,
	    thrp_p *pthrp);
#define THRP_C_F_BIND2CPU	(1 << 0) /* Bind threads to CPUs */
#define THRP_C_F_CACHE_TIME_SYSC (1 << 8) /* Cache thrpt_gettimev() syscals. */

//--#define THRP_C_F_SHARE_EVENTS	(1 << 1) /* Not affected if threads_max = 1 */
void	thrp_shutdown(thrp_p thrp);
void	thrp_shutdown_wait(thrp_p thrp);
void	thrp_destroy(thrp_p thrp);

int	thrp_threads_create(thrp_p thrp, int skeep_first);
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

/* Thread messages. Unicast and Broadcast. */
/* Only threads from pool can receive messages. */
int	thrpt_msg_send(thrpt_p dst, thrpt_p src, uint32_t flags, thrpt_msg_cb msg_cb,
	    void *udata);
/* thrpt_msg_send() return:
 * 0 = no errors, message sended
 * EINVAL - on invalid arg
 * EHOSTDOWN - dst thread not running and THRP_MSG_F_FORCE flag not set
 * other err codes from kevent() on BSD and write() on linux
 */
int	thrpt_msg_bsend_ex(thrp_p thrp, thrpt_p src, uint32_t flags, thrpt_msg_cb msg_cb,
	    void *udata, size_t *send_msg_cnt, size_t *error_cnt);
#define thrpt_msg_bsend(thrp, src, flags, msg_cb, udata)			\
	    thrpt_msg_bsend_ex(thrp, src, flags, msg_cb, udata, NULL, NULL)
/* thrpt_msg_bsend_ex() return:
 * 0 = no errors, at least 1 message sended
 * EINVAL - on invalid arg
 * ESPIPE - no messages sended, all send operations fail
 * + errors count, + send_msg_cnt
 */
int	thrpt_msg_cbsend(thrp_p thrp, thrpt_p src, uint32_t flags, thrpt_msg_cb msg_cb,
	    void *udata, thrpt_msg_done_cb done_cb);
/* thrpt_msg_cbsend() return:
 * error code if none messages sended,
 * 0 if at least one message sended + sended messages and errors count on done cb. */
/* Unicast + broadcast messages flags. */
#define THRP_MSG_F_SELF_DIRECT	(1 << 0) /* Directly call cb func for calling thread. */
#define THRP_MSG_F_FORCE	(1 << 1) /* If thread mark as not running - directly call cb func.
					  * WARNING! if thread not running - thrpt will be ignored. */
#define THRP_MSG_F_FAIL_DIRECT	(1 << 2) /* Directly call cb func if fail to send. */
/* Broadcast flags. */
#define THRP_BMSG_F_SELF_SKEEP	(1 << 8) /* Do not send mesg to caller thread. */
#define THRP_BMSG_F_SYNC	(1 << 9) /* Wait before all thread process message before return.
					  * WARNING! This deadlock, frizes possible. */
#define THRP_BMSG_F_SYNC_USLEEP	(1 << 10)/* Wait before all thread process message before return. */
/* Broadcast with result cb. */
#define THRP_CBMSG_F_SELF_SKEEP	THRP_BMSG_F_SELF_SKEEP
#define THRP_CBMSG_F_ONE_BY_ONE	(1 << 16) /* Send message to next thread after current thread process message. */


int	thrpt_ev_add(thrpt_p thrpt, uint16_t event, uint16_t flags,
	    thrp_udata_p udata);
int	thrpt_ev_add_ex(thrpt_p thrpt, uint16_t event, uint16_t flags, u_int fflags, 
	    intptr_t data, thrp_udata_p udata);
/*
 * flags - allowed: THRP_F_ONESHOT, THRP_F_CLEAR, THRP_F_DISPATCH
 */
int	thrpt_ev_add2(thrpt_p thrpt, thrp_event_p ev, thrp_udata_p udata);
int	thrpt_ev_del(uint16_t event, thrp_udata_p udata);
int	thrpt_ev_enable(int enable, uint16_t event, thrp_udata_p udata);
int	thrpt_ev_enable_ex(int enable, uint16_t event, uint16_t flags,
	    u_int fflags, intptr_t data, thrp_udata_p udata);

#ifdef NOT_YET__FreeBSD__ /* Per thread queue functions. Only for kqueue! */
int	thrpt_ev_q_add(thrpt_p thrpt, uint16_t event, uint16_t flags,
	    thrp_udata_p udata);
int	thrpt_ev_q_del(uint16_t event, thrp_udata_p udata);
int	thrpt_ev_q_enable(int enable, uint16_t event, thrp_udata_p udata);
int	thrpt_ev_q_enable_ex(int enable, uint16_t event, uint16_t flags,
	    u_int fflags, intptr_t data, thrp_udata_p udata);
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


#endif // __CORE_THREADP_H__
