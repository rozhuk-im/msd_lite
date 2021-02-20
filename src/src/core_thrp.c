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

#ifdef BSD /* BSD specific code. */
#	include <sys/event.h>
#	include <pthread_np.h>
	typedef cpuset_t cpu_set_t;
#endif /* BSD specific code. */

#ifdef __linux__ /* Linux specific code. */
#	include <sys/epoll.h>
#	include <sys/timerfd.h>
#	include <sys/ioctl.h>
#	include <sys/socket.h>
#endif /* Linux specific code. */

#include <sys/queue.h>
#include <sys/fcntl.h> /* open, fcntl */
#include <inttypes.h>
#include <stdlib.h> /* malloc, exit */
#include <unistd.h> /* close, write, sysconf */
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>

#include "macro_helpers.h"
#include "mem_helpers.h"
#include "core_log.h"
#include "core_thrp.h"
#include "core_thrp_msg.h"

#ifdef THRP_XML_CONFIG
#	include "xml.h"
#	include "core_helpers.h"
#endif



/* Initialize Thread Local Storage. */
static pthread_key_t thrp_tls_key_thrpt;
static int thrp_tls_key_thrpt_error = EAGAIN;
static thrp_p g_thrp = NULL;


/* Operation. */
#define THRP_CTL_ADD		0
#define THRP_CTL_DEL		1
#define THRP_CTL_ENABLE		2
#define THRP_CTL_DISABLE	3
#define THRP_CTL_LAST		THRP_CTL_DISABLE


#ifdef BSD /* BSD specific code. */

#define THRPT_ITEM_EV_COUNT	64

static const u_short thrp_op_to_flags_kq_map[] = {
	(EV_ADD | EV_ENABLE),	/* 0: THRP_CTL_ADD */
	EV_DELETE,		/* 1: THRP_CTL_DEL */
	EV_ENABLE,		/* 2: THRP_CTL_ENABLE */
	EV_DISABLE,		/* 3: THRP_CTL_DISABLE */
	0
};

static const short thrp_event_to_kq_map[] = {
	EVFILT_READ,		/* 0: THRP_EV_READ */
	EVFILT_WRITE,		/* 1: THRP_EV_WRITE */
	EVFILT_TIMER,		/* 2: THRP_EV_TIMER */
	0
};

#define CORE_THRP_CLOCK_REALTIME	CLOCK_REALTIME_FAST
#define CORE_THRP_CLOCK_MONOTONIC	CLOCK_MONOTONIC_FAST

#endif /* BSD specific code. */


#ifdef __linux__ /* Linux specific code. */
//#define CORE_THRP_LINUX_MULTIPLE_EVENTS

#define EPOLL_INOUT		(EPOLLIN | EPOLLOUT)
#define EPOLL_OUT		(EPOLLOUT)
#define EPOLL_IN		(EPOLLIN | EPOLLRDHUP | EPOLLPRI)
#define EPOLL_HUP		(EPOLLHUP | EPOLLRDHUP)

static const uint32_t thrp_event_to_ep_map[] = {
	EPOLL_IN,		/* 0: THRP_EV_READ */
	EPOLL_OUT,		/* 1: THRP_EV_WRITE */
	0,			/* 2: THRP_EV_TIMER */
	0
};

/* Single event. */
#define U64_BITS_MASK(__bits)		((((uint64_t)1) << (__bits)) - 1)
#define U64_BITS_GET(__u64, __off, __len)				\
    (((__u64) >> (__off)) & U64_BITS_MASK(__len))
#define U64_BITS_SET(__u64, __off, __len, __data)			\
    (__u64) = (((__u64) & ~(U64_BITS_MASK(__len) << (__off))) |		\
	(((__data) & U64_BITS_MASK(__len)) << (__off)))

#define TPDATA_TFD_GET(__u64)		(int)U64_BITS_GET(__u64, 0, 32)
#define TPDATA_TFD_SET(__u64, __tfd)	U64_BITS_SET(__u64, 0, 32, ((uint32_t)(__tfd)))
#define TPDATA_EVENT_GET(__u64)		U64_BITS_GET(__u64, 32, 3)
#define TPDATA_EVENT_SET(__u64, __ev)	U64_BITS_SET(__u64, 32, 3, __ev)
#define TPDATA_FLAGS_GET(__u64, __ev)	U64_BITS_GET(__u64, (35 + (3 * (__ev))), 3)
#define TPDATA_FLAGS_SET(__u64, __ev, __fl)				\
    U64_BITS_SET(__u64, (35 + (3 * (__ev))), 3, __fl)
#define TPDATA_EV_FL_SET(__u64, __ev, __fl) {				\
    TPDATA_EVENT_SET(__u64, __ev);					\
    TPDATA_FLAGS_SET(__u64, __ev, __fl);				\
}
#define TPDATA_F_DISABLED		(((uint64_t)1) << 63) /* Make sure that disabled event never call cb func. */


#define CORE_THRP_CLOCK_REALTIME	CLOCK_REALTIME
#define CORE_THRP_CLOCK_MONOTONIC	CLOCK_MONOTONIC

#endif /* Linux specific code. */




typedef struct thread_pool_thread_s { /* thread pool thread info */
	volatile size_t running; /* running */
	volatile size_t tick_cnt; /* For detecting hangs thread. */
	uintptr_t	io_fd;	/* io handle: kqueue (per thread) */
#ifdef BSD /* BSD specific code. */
	int		ev_nchanges; /* passed to kevent */
	struct kevent	ev_changelist[THRPT_ITEM_EV_COUNT]; /* passed to kevent */
#endif /* BSD specific code. */
	pthread_t	pt_id;	/* thread id */
	int		cpu_id;	/* cpu num or -1 if no bindings */
	size_t		thread_num; /* num in array, short internal thread id. */
	void		*msg_queue; /* Queue specific. */
#ifdef __linux__ /* Linux specific code. */
	thrp_udata_t	pvt_udata;	/* Pool virtual thread support */
#endif	/* Linux specific code. */
	thrp_p		thrp;	/*  */
} thrp_thread_t;


typedef struct thread_pool_s { /* thread pool */
	thrpt_p		pvt;		/* Pool virtual thread. */
	size_t		rr_idx;
	uint32_t	flags;
	size_t		cpu_count;
	uintptr_t	fd_count;
	thrp_udata_t	thrp_timer;	/* Cached time update timer: ident=pointer to tp_cached. */
	struct timespec	tp_time_cached[2]; /* 0: MONOTONIC, 1: REALTIME */
	size_t		threads_max;
	volatile size_t	threads_cnt;	/* worker threads count */
	thrp_thread_t	threads[];	/* worker threads */
} thrp_t;


typedef struct thrpt_msg_data_s { /* thread message sync data. */
	thrpt_msg_cb	msg_cb;
	void		*udata;
	MTX_S		lock;	/* For count exclusive access. */
	volatile size_t	active_thr_count;
	size_t		cur_thr_idx; /*  */
	uint32_t	flags;
	volatile size_t	send_msg_cnt;
	volatile size_t	error_cnt;
	thrpt_p		thrpt;	/* Caller context, for done_cb. */
	thrpt_msg_done_cb done_cb;
} thrpt_msg_data_t, *thrpt_msg_data_p;



static int	thrpt_ev_post(int op, uint16_t event, uint16_t flags,
		    thrp_event_p ev, thrp_udata_p thrp_udata);
static int	thrpt_data_event_init(thrpt_p thrpt);
static void	thrpt_data_event_destroy(thrpt_p thrpt);
static void	thrpt_loop(thrpt_p thrpt);

int		thrpt_data_create(thrp_p thrp, int cpu_id, size_t thread_num,
		    thrpt_p thrpt);
void		thrpt_data_destroy(thrpt_p thrpt);

static void	*thrp_thread_proc(void *data);

void		thrpt_msg_shutdown_cb(thrpt_p thrpt, void *udata);

void		thrpt_cached_time_update_cb(thrp_event_p ev, thrp_udata_p thrp_udata);



/*
 * FreeBSD specific code.
 */
#ifdef BSD /* BSD specific code. */

/* Translate thread pool flags <-> kqueue flags */
static inline u_short
thrp_flags_to_kq(uint16_t flags) {
	u_short ret = 0;

	if (0 == flags)
		return (0);
	if (0 != (THRP_F_ONESHOT & flags)) {
		ret |= EV_ONESHOT;
	}
	if (0 != (THRP_F_DISPATCH & flags)) {
		ret |= EV_DISPATCH;
	}
	if (0 != (THRP_F_EDGE & flags)) {
		ret |= EV_CLEAR;
	}
	return (ret);
}

static int
thrpt_data_event_init(thrpt_p thrpt) {
	struct kevent kev;

	thrpt->io_fd = (uintptr_t)kqueue();
	if ((uintptr_t)-1 == thrpt->io_fd)
		return (errno);
	/* Init threads message exchange. */
	thrpt->msg_queue = thrpt_msg_queue_create(thrpt);
	if (NULL == thrpt->msg_queue)
		return (errno);
	if (NULL != thrpt->thrp->pvt &&
	    thrpt != thrpt->thrp->pvt) {
		/* Add pool virtual thread to normal thread. */
		kev.ident = thrpt->thrp->pvt->io_fd;
		kev.filter = EVFILT_READ;
		kev.flags = (EV_ADD | EV_ENABLE | EV_CLEAR); /* Auto clear event. */
		kev.fflags = 0;
		kev.data = 0;
		kev.udata = NULL;
		if (-1 == kevent((int)thrpt->io_fd, &kev, 1, NULL, 0, NULL))
			return (errno);
	}
	return (0);
}

static void
thrpt_data_event_destroy(thrpt_p thrpt) {

	thrpt_msg_queue_destroy(thrpt->msg_queue);
}

static int
thrpt_ev_post(int op, uint16_t event, uint16_t flags, thrp_event_p ev,
    thrp_udata_p thrp_udata) {
	struct kevent kev;

	if (THRP_CTL_LAST < op ||
	    NULL == thrp_udata ||
	    (uintptr_t)-1 == thrp_udata->ident ||
	    NULL == thrp_udata->thrpt)
		return (EINVAL);
	if (NULL != ev) {
		event = ev->event;
		flags = ev->flags;
		kev.fflags = (u_int)ev->fflags;
		kev.data = (intptr_t)ev->data;
	} else {
		kev.fflags = 0;
		kev.data = 0;
	}
	if (THRP_EV_LAST < event)
		return (EINVAL); /* Bad event. */
	kev.ident = thrp_udata->ident;
	kev.filter = thrp_event_to_kq_map[event];
	kev.flags = (thrp_op_to_flags_kq_map[op] | thrp_flags_to_kq(flags));
	kev.udata = (void*)thrp_udata;
	if (THRP_EV_TIMER == event) { /* Timer: force update. */
		if (0 != ((EV_ADD | EV_ENABLE) & kev.flags)) {
			if (NULL == ev) /* Params required for add/mod. */
				return (EINVAL);
			kev.flags |= (EV_ADD | EV_ENABLE);
		}
	} else { /* Read/write. */
		if (thrp_udata->thrpt->thrp->fd_count <= thrp_udata->ident)
			return (EBADF); /* Bad FD. */
	}
	if (-1 == kevent((int)thrp_udata->thrpt->io_fd, &kev, 1, NULL, 0, NULL))
		return (errno);
	return (0);
}

#if 0 /* XXX may be in future... */
int
thrpt_ev_q_add(thrpt_p thrpt, uint16_t event, uint16_t flags,
    thrp_udata_p thrp_udata) {
	/*thrpt_p thrpt;

	if (NULL == thrpt)
		return (EINVAL);
	if (THRPT_ITEM_EV_COUNT <= thrpt->ev_nchanges)
		return (-1);

	EV_SET(&thrpt->ev_changelist[thrpt->ev_nchanges], ident, filter,
	    flags, fflags, data, thrp_udata);
	thrpt->ev_nchanges ++;

	return (0);*/
	return (thrpt_ev_add(thrpt, event, flags, thrp_udata));
}

int
thrpt_ev_q_del(uint16_t event, thrp_udata_p thrp_udata) {
	/*int i, ev_nchanges, ret;
	thrpt_p thrpt;

	if (NULL == thrpt || (uintptr_t)-1 == ident)
		return (EINVAL);

	ret = 0;
	ev_nchanges = thrpt->ev_nchanges;
	for (i = 0; i < ev_nchanges; i ++) {
		if (thrpt->ev_changelist[i].ident != ident ||
		    thrpt->ev_changelist[i].filter != filter)
			continue;

		ret ++;
		ev_nchanges --;
		if (i < ev_nchanges) {
			memmove(&thrpt->ev_changelist[i], 
			    &thrpt->ev_changelist[(i + 1)], 
			    (sizeof(struct kevent) * (ev_nchanges - i))); // move items, except last
		}
		mem_bzero(&thrpt->ev_changelist[(ev_nchanges + 1)],
		    sizeof(struct kevent));// zeroize last
	}
	thrpt->ev_nchanges = ev_nchanges;

	return (ret);*/
	return (thrpt_ev_del(event, thrp_udata));
}

int
thrpt_ev_q_enable(int enable, uint16_t event, thrp_udata_p thrp_udata) {

	return (thrpt_ev_enable(enable, event, thrp_udata));
}

int
thrpt_ev_q_enable_ex(int enable, uint16_t event, uint16_t flags,
    uint32_t fflags, intptr_t data, thrp_udata_p thrp_udata) {

	return (thrpt_ev_enable_ex(enable, event, flags, fflags, data, thrp_udata));
}

int
thrpt_ev_q_flush(thrpt_p thrpt) {

	if (NULL == thrpt)
		return (EINVAL);
	if (0 == thrpt->ev_nchanges)
		return (0);
	if (-1 == kevent(thrpt->io_fd, thrpt->ev_changelist,
	    thrpt->ev_nchanges, NULL, 0, NULL))
		return (errno);
	return (0);
}
#endif /* XXX may be in future... */

static void
thrpt_loop(thrpt_p thrpt) {
	thrpt_p pvt;
	int cnt;
	struct kevent kev;
	thrp_event_t ev;
	thrp_udata_p thrp_udata;
	struct timespec ke_timeout;

	pvt = thrpt->thrp->pvt;
	thrpt->ev_nchanges = 0;
	mem_bzero(&ke_timeout, sizeof(ke_timeout));

	/* Main loop. */
	while (0 != thrpt->running) {
		thrpt->tick_cnt ++; /* Tic-toc */
		cnt = kevent((int)thrpt->io_fd, thrpt->ev_changelist, 
		    thrpt->ev_nchanges, &kev, 1, NULL /* infinite wait. */);
		if (0 != thrpt->ev_nchanges) {
			mem_bzero(thrpt->ev_changelist,
			    (sizeof(struct kevent) * (size_t)thrpt->ev_nchanges));
			thrpt->ev_nchanges = 0;
		}
		if (0 == cnt) { /* Timeout */
			LOGD_EV("kevent: cnt = 0");
			continue;
		}
		if (0 > cnt) { /* Error / Exit */
			LOG_ERR(errno, "kevent()");
			break;
		}
		if (pvt->io_fd == kev.ident) { /* Pool virtual thread */
			//memcpy(&thrpt->ev_changelist[thrpt->ev_nchanges], &kev,
			//    sizeof(kev));
			thrpt->ev_changelist[thrpt->ev_nchanges].ident = kev.ident;
			thrpt->ev_changelist[thrpt->ev_nchanges].filter = EVFILT_READ;
			thrpt->ev_changelist[thrpt->ev_nchanges].flags = EV_CLEAR;
			thrpt->ev_nchanges ++;

			cnt = kevent((int)pvt->io_fd, NULL, 0, &kev, 1, &ke_timeout);
			if (1 != cnt) /* Timeout or error. */
				continue;
		}
		if (NULL == kev.udata) {
			LOG_EV_FMT("kevent with invalid user data, ident = %zu", kev.ident);
			debugd_break();
			continue;
		}
		thrp_udata = (thrp_udata_p)kev.udata;
		if (thrp_udata->ident != kev.ident) {
			LOG_EV_FMT("kevent with invalid ident, kq_ident = %zu, thr_ident = %zu",
			    kev.ident, thrp_udata->ident);
			debugd_break();
			continue;
		}
		if (thrp_udata->thrpt != thrpt &&
		    thrp_udata->thrpt != pvt) {
			LOG_EV_FMT("kevent with invalid thrpt, thrpt = %zu, thr_thrpt = %zu",
			    thrpt, thrp_udata->thrpt);
			debugd_break();
			//continue;
		}
		if (NULL == thrp_udata->cb_func) {
			LOG_EV_FMT("kevent with invalid user cb_func, ident = %zu", kev.ident);
			debugd_break();
			continue;
		}
		/* Translate kq event to thread poll event. */
		switch (kev.filter) {
		case EVFILT_READ:
			ev.event = THRP_EV_READ;
			break;
		case EVFILT_WRITE:
			ev.event = THRP_EV_WRITE;
			break;
		case EVFILT_TIMER:
			ev.event = THRP_EV_TIMER;
			break;
		default:
			LOG_EV_FMT("kevent with invalid filter = %i, ident = %zu",
			    kev.filter, kev.ident);
			debugd_break();
			continue;
		}
		ev.flags = 0;
		if (0 != (EV_EOF & kev.flags)) {
			ev.flags |= THRP_F_EOF;
			if (0 != kev.fflags) { /* For socket: closed, and error present. */
				ev.flags |= THRP_F_ERROR;
			}
		}
		ev.fflags = (uint32_t)kev.fflags;
		ev.data = (uint64_t)kev.data;

		thrp_udata->cb_func(&ev, thrp_udata);
	} /* End Main loop. */
	return;
}
#endif /* BSD specific code. */


#ifdef __linux__ /* Linux specific code. */
#define THRP_EV_OTHER(event)						\
    (THRP_EV_READ == (event) ? THRP_EV_WRITE : THRP_EV_READ)

/* Translate thread pool flags <-> epoll flags */
static inline uint32_t
thrp_flags_to_ep(uint16_t flags) {
	uint32_t ret = 0;

	if (0 == flags)
		return (0);
	if (0 != ((THRP_F_ONESHOT | THRP_F_DISPATCH) & flags)) {
		ret |= EPOLLONESHOT;
	}
	if (0 != (THRP_F_EDGE & flags)) {
		ret |= EPOLLET;
	}
	return (ret);
}

static int
thrpt_data_event_init(thrpt_p thrpt) {
	int error;

	thrpt->io_fd = epoll_create(thrpt->thrp->fd_count);
	if ((uintptr_t)-1 == thrpt->io_fd)
		return (errno);
	/* Init threads message exchange. */
	thrpt->msg_queue = thrpt_msg_queue_create(thrpt);
	if (NULL == thrpt->msg_queue)
		return (errno);
	if (NULL != thrpt->thrp->pvt &&
	    thrpt != thrpt->thrp->pvt) {
		/* Add pool virtual thread to normal thread. */
		thrpt->pvt_udata.cb_func = NULL;
		thrpt->pvt_udata.ident = thrpt->thrp->pvt->io_fd;
		thrpt->pvt_udata.thrpt = thrpt;
		error = thrpt_ev_post(THRP_CTL_ADD, THRP_EV_READ, 0,
		    NULL, &thrpt->pvt_udata);
		if (0 != error)
			return (error);
	}
	return (0);
}

static void
thrpt_data_event_destroy(thrpt_p thrpt) {

	thrpt_msg_queue_destroy(thrpt->msg_queue);
}

static inline int
epoll_ctl_ex(int epfd, int op, int fd, struct epoll_event *event) {
	int error;

	switch (op) {
	case EPOLL_CTL_ADD: /* Try to add event to epoll. */
		if (0 == epoll_ctl(epfd, EPOLL_CTL_ADD, fd, event))
			return (0);
		error = errno;
		if (EEXIST != error)
			return (error);
		if (0 == epoll_ctl(epfd, EPOLL_CTL_MOD, fd, event))
			return (0);
		break;
	case EPOLL_CTL_MOD: /* Try to modify existing. */
		if (0 == epoll_ctl(epfd, EPOLL_CTL_MOD, fd, event))
			return (0);
		error = errno;
		if (ENOENT != error)
			return (error);
		if (0 == epoll_ctl(epfd, EPOLL_CTL_ADD, fd, event))
			return (0);
		break;
	case EPOLL_CTL_DEL:
		if (0 == epoll_ctl(epfd, EPOLL_CTL_DEL, fd, event))
			return (0);
		break;
	default:
		return (EINVAL);
	}
	return (errno);
}

static int
thrpt_ev_post(int op, uint16_t event, uint16_t flags, thrp_event_p ev,
    thrp_udata_p thrp_udata) {
	int error = 0;
	int tfd;
	struct itimerspec new_tmr;
	struct epoll_event epev;

	if (THRP_CTL_LAST < op ||
	    NULL == thrp_udata ||
	    (uintptr_t)-1 == thrp_udata->ident ||
	    NULL == thrp_udata->thrpt)
		return (EINVAL);
	if (NULL != ev) {
		event = ev->event;
		flags = ev->flags;
	}
	if (THRP_EV_LAST < event)
		return (EINVAL); /* Bad event. */

	epev.events = (EPOLLHUP | EPOLLERR);
	epev.data.ptr = (void*)thrp_udata;

	if (THRP_EV_TIMER == event) { /* Special handle for timer. */
		tfd = TPDATA_TFD_GET(thrp_udata->tpdata);
		if (THRP_CTL_DEL == op) { /* Delete timer. */
			if (0 == tfd)
				return (ENOENT);
			error = 0;
err_out_timer:
			close(tfd); /* no need to epoll_ctl(EPOLL_CTL_DEL) */
			thrp_udata->tpdata = 0;
			return (error);
		}
		if (THRP_CTL_DISABLE == op) {
			if (0 == tfd)
				return (ENOENT);
			thrp_udata->tpdata |= TPDATA_F_DISABLED;
			mem_bzero(&new_tmr, sizeof(new_tmr));
			if (-1 == timerfd_settime(tfd, 0, &new_tmr, NULL)) {
				error = 0;
				goto err_out_timer;
			}
			return (0);
		}
		/* THRP_CTL_ADD, THRP_CTL_ENABLE */
		if (NULL == ev) /* Params required for add/mod. */
			return (EINVAL);
		if (0 == tfd) { /* Create timer, if needed. */
			tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
			if (-1 == tfd) {
				thrp_udata->tpdata = 0;
				return (errno);
			}
			TPDATA_TFD_SET(thrp_udata->tpdata, tfd);
			TPDATA_EV_FL_SET(thrp_udata->tpdata, event, flags); /* Remember original event and flags. */
			/* Adding to epoll. */
			epev.events |= EPOLLIN; /* Not set EPOLLONESHOT, control timer. */
			if (0 != epoll_ctl((int)thrp_udata->thrpt->io_fd,
			    EPOLL_CTL_ADD, tfd, &epev)) {
				error = errno;
				goto err_out_timer;
			}
		}
		thrp_udata->tpdata &= ~TPDATA_F_DISABLED;
		new_tmr.it_value.tv_sec = (ev->data / 1000);
		new_tmr.it_value.tv_nsec = ((ev->data % 1000) * 1000000);
		if (0 != ((THRP_F_ONESHOT | THRP_F_DISPATCH) & flags)) { /* Onetime. */
			mem_bzero(&new_tmr.it_interval, sizeof(struct timespec));
		} else { /* Periodic. */
			new_tmr.it_interval = new_tmr.it_value; /* memcpy(). */
		}
		if (-1 == timerfd_settime(tfd, 0, &new_tmr, NULL)) {
			error = errno;
			goto err_out_timer;
		}
		return (0);
	}

	/* Read/Write events. */
	if (thrp_udata->thrpt->thrp->fd_count <= thrp_udata->ident)
		return (EBADF); /* Bad FD. */
	/* Single event. */
	if (THRP_CTL_DEL == op) {
		thrp_udata->tpdata = 0;
		if (0 == epoll_ctl((int)thrp_udata->thrpt->io_fd,
		    EPOLL_CTL_DEL, (int)thrp_udata->ident, &epev))
			return (0);
		return (errno);
	}

	tfd = ((0 == thrp_udata->tpdata) ? EPOLL_CTL_ADD : EPOLL_CTL_MOD);
	TPDATA_TFD_SET(thrp_udata->tpdata, 0);
	TPDATA_EV_FL_SET(thrp_udata->tpdata, event, flags); /* Remember original event and flags. */
	if (THRP_CTL_DISABLE == op) { /* Disable event. */
		thrp_udata->tpdata |= TPDATA_F_DISABLED;
		epev.events |= EPOLLET; /* Mark as level trig, to only once report HUP/ERR. */
	} else {
		thrp_udata->tpdata &= ~TPDATA_F_DISABLED;
		epev.events |= (thrp_event_to_ep_map[event] | thrp_flags_to_ep(flags));
	}
	error = epoll_ctl_ex((int)thrp_udata->thrpt->io_fd,
	    tfd, (int)thrp_udata->ident, &epev);
	if (0 != error) {
		thrp_udata->tpdata = 0;
	}
	return (error);
}

static void
thrpt_loop(thrpt_p thrpt) {
	thrpt_p pvt;
	thrp_p thrp;
	int cnt, itm, tfd;
	uint16_t tpev_flags;
	struct epoll_event epev;
	thrp_event_t ev;
	thrp_udata_p thrp_udata;
	socklen_t optlen;

	thrp = thrpt->thrp;
	pvt = thrp->pvt;
	/* Main loop. */
	while (0 != thrpt->running) {
		thrpt->tick_cnt ++; /* Tic-toc */
		cnt = epoll_wait((int)thrpt->io_fd, &epev, 1, -1 /* infinite wait. */);
		if (0 == cnt) /* Timeout */
			continue;
		if (-1 == cnt) { /* Error / Exit */
			LOG_ERR(errno, "epoll_wait()");
			debugd_break();
			break;
		}
		/* Single event. */
		if (NULL == epev.data.ptr) {
			LOG_EV("epoll event with invalid user data, epev.data.ptr = NULL");
			debugd_break();
			continue;
		}
		thrp_udata = (thrp_udata_p)epev.data.ptr;
		if (NULL == thrp_udata->cb_func) {
			if (pvt->io_fd == thrp_udata->ident) { /* Pool virtual thread. */
				cnt = epoll_wait((int)pvt->io_fd, &epev, 1, 0);
				if (1 != cnt ||
				    NULL == epev.data.ptr) /* Timeout or error. */
					continue;
				thrp_udata = (thrp_udata_p)epev.data.ptr;
			}
			if (NULL == thrp_udata->cb_func) {
				LOG_EV_FMT("epoll event with invalid user cb_func, "
				    "epev.data.u64 = %"PRIu64,
				    epev.data.u64);
				debugd_break();
				continue;
			}
		}
		if (0 != (TPDATA_F_DISABLED & thrp_udata->tpdata))
			continue; /* Do not process disabled events. */
		/* Translate ep event to thread poll event. */
		ev.event = TPDATA_EVENT_GET(thrp_udata->tpdata);
		tpev_flags = TPDATA_FLAGS_GET(thrp_udata->tpdata, ev.event);
		ev.flags = 0;
		ev.fflags = 0;
		if (0 != (THRP_F_DISPATCH & tpev_flags)) { /* Mark as disabled. */
			thrp_udata->tpdata |= TPDATA_F_DISABLED;
		}
		if (THRP_EV_TIMER == ev.event) { /* Timer. */
			tfd = TPDATA_TFD_GET(thrp_udata->tpdata);
			itm = read(tfd, &ev.data, sizeof(uint64_t));
			if (0 != (THRP_F_ONESHOT & tpev_flags)) { /* Onetime. */
				close(tfd); /* no need to epoll_ctl(EPOLL_CTL_DEL) */
				thrp_udata->tpdata = 0;
			}
			thrp_udata->cb_func(&ev, thrp_udata);
			continue;
		}
		/* Read/write. */
		ev.data = UINT64_MAX; /* Transfer as many as you can. */
		if (0 != (EPOLL_HUP & epev.events)) {
			ev.flags |= THRP_F_EOF;
		}
		if (0 != (EPOLLERR & epev.events)) { /* Try to get error code. */
			ev.flags |= THRP_F_ERROR;
			ev.fflags = errno;
			optlen = sizeof(int);
			if (0 == getsockopt((int)thrp_udata->ident,
			    SOL_SOCKET, SO_ERROR, &itm, &optlen)) {
				ev.fflags = itm;
			}
			if (0 == ev.fflags) {
				ev.fflags = EINVAL;
			}
		}
		if (0 != (THRP_F_ONESHOT & tpev_flags)) { /* Onetime. */
			epoll_ctl((int)thrpt->io_fd, EPOLL_CTL_DEL,
			    (int)thrp_udata->ident, &epev);
			thrp_udata->tpdata = 0;
		}

		thrp_udata->cb_func(&ev, thrp_udata);
	} /* End Main loop. */
	return;
}
#endif /* Linux specific code. */





/*
 * Shared code.
 */
int
thrp_signal_handler_add_thrp(thrp_p thrp) {
	
	/* XXX: need modify to handle multiple threads pools. */
	g_thrp = thrp;
	
	return (0);
}

void
thrp_signal_handler(int sig) {

	switch (sig) {
	case SIGINT:
	case SIGTERM:
	case SIGKILL:
		thrp_shutdown(g_thrp);
		g_thrp = NULL;
		break;
	case SIGHUP:
	case SIGUSR1:
	case SIGUSR2:
		break;
	}
}


void
thrp_def_settings(thrp_settings_p s_ret) {

	if (NULL == s_ret)
		return;
	/* Init. */
	mem_bzero(s_ret, sizeof(thrp_settings_t));

	/* Default settings. */
	s_ret->flags = THRP_S_DEF_FLAGS;
	s_ret->threads_max = THRP_S_DEF_THREADS_MAX;
	s_ret->tick_time = THRP_S_DEF_TICK_TIME;
}

#ifdef THRP_XML_CONFIG
int
thrp_xml_load_settings(const uint8_t *buf, size_t buf_size, thrp_settings_p s) {
	const uint8_t *data;
	size_t data_size;

	if (NULL == buf || 0 == buf_size || NULL == s)
		return (EINVAL);
	/* Read from config. */
	/* Flags. */
	if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
	    &data, &data_size,
	    (const uint8_t*)"fBindToCPU", NULL)) {
		yn_set_flag32(data, data_size, THRP_S_F_BIND2CPU, &s->flags);
	}
	if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
	    &data, &data_size,
	    (const uint8_t*)"fCacheGetTimeSyscall", NULL)) {
		yn_set_flag32(data, data_size, THRP_S_F_CACHE_TIME_SYSC, &s->flags);
	}

	/* Other. */
	xml_get_val_size_t_args(buf, buf_size, NULL, &s->threads_max,
	    (const uint8_t*)"threadsCountMax", NULL);
	xml_get_val_uint64_args(buf, buf_size, NULL, &s->tick_time,
	    (const uint8_t*)"timerGranularity", NULL);

	return (0);
}
#endif


int
thrp_init(void) {

	if (0 != thrp_tls_key_thrpt_error) { /* Try to reinit TLS. */
		thrp_tls_key_thrpt_error = pthread_key_create(&thrp_tls_key_thrpt, NULL);
	}
	return (thrp_tls_key_thrpt_error);
}

int
thrp_create(thrp_settings_p s, thrp_p *pthrp) {
	int error, cur_cpu;
	uintptr_t fd_max_count;
	size_t i, cpu_count;
	thrp_p thrp;
	thrp_settings_t s_def;
	thrp_event_t ev;

	error = thrp_init();
	if (0 != error) {
		LOGD_ERR(error, "thrp_init()");
		return (error);
	}

	if (NULL == pthrp)
		return (EINVAL);
	if (NULL == s) {
		thrp_def_settings(&s_def);
	} else {
		memcpy(&s_def, s, sizeof(s_def));
	}
	s = &s_def;

	cpu_count = (size_t)sysconf(_SC_NPROCESSORS_CONF);
	if ((size_t)-1 == cpu_count) {
		cpu_count = 1; /* At least 1 processor avaible. */
	}
	if (0 == s->threads_max) {
		s->threads_max = cpu_count;
	}
	thrp = (thrp_p)zalloc((sizeof(thrp_t) + ((s->threads_max + 1) * sizeof(thrp_thread_t))));
	if (NULL == thrp)
		return (ENOMEM);
	fd_max_count = (uintptr_t)getdtablesize();
	thrp->flags = s->flags;
	thrp->cpu_count = cpu_count;
	thrp->threads_max = s->threads_max;
	thrp->fd_count = fd_max_count;
	thrp->pvt = &thrp->threads[s->threads_max];
	error = thrpt_data_create(thrp, -1, (size_t)~0, &thrp->threads[s->threads_max]);
	if (0 != error) {
		LOGD_ERR(error, "thrpt_data_create() - pvt");
		goto err_out;
	}
	for (i = 0, cur_cpu = 0; i < s->threads_max; i ++, cur_cpu ++) {
		if (0 != (s->flags & THRP_S_F_BIND2CPU)) {
			if ((size_t)cur_cpu >= cpu_count) {
				cur_cpu = 0;
			}
		} else {
			cur_cpu = -1;
		}
		error = thrpt_data_create(thrp, cur_cpu, i, &thrp->threads[i]);
		if (0 != error) {
			LOGD_ERR(error, "thrpt_data_create() - threads");
			goto err_out;
		}
	}
	
	if (0 != (s->flags & THRP_S_F_CACHE_TIME_SYSC)) {
		thrp->thrp_timer.cb_func = thrpt_cached_time_update_cb;
		thrp->thrp_timer.ident = (uintptr_t)&thrp->tp_time_cached;
		error = thrpt_ev_add_ex(&thrp->threads[0], THRP_EV_TIMER,
		    0, 0, s->tick_time, &thrp->thrp_timer);
		if (0 != error) {
			LOGD_ERR(error, "thrpt_ev_add_ex(threads[0], THRP_EV_TIMER, tick_time)");
			goto err_out;
		}
		/* Update time. */
		mem_bzero(&ev, sizeof(ev));
		ev.event = THRP_EV_TIMER;
		thrpt_cached_time_update_cb(&ev, &thrp->thrp_timer);
	}

	(*pthrp) = thrp;
	return (0);

err_out:
	thrp_destroy(thrp);
	return (error);
}

void
thrp_shutdown(thrp_p thrp) {
	size_t i;

	if (NULL == thrp)
		return;
	if (0 != (THRP_S_F_CACHE_TIME_SYSC & thrp->flags)) {
		thrpt_ev_del(THRP_EV_TIMER, &thrp->thrp_timer);
	}
	/* Shutdown threads. */
	for (i = 0; i < thrp->threads_max; i ++) {
		if (0 == thrp->threads[i].running)
			continue;
		thrpt_msg_send(&thrp->threads[i], NULL, 0,
		    thrpt_msg_shutdown_cb, NULL);
	}
}
void
thrpt_msg_shutdown_cb(thrpt_p thrpt, void *udata __unused) {

	thrpt->running = 0;
}

void
thrp_shutdown_wait(thrp_p thrp) {
	size_t cnt;
	struct timespec rqtp;

	if (NULL == thrp)
		return;
	/* Wait all threads before return. */
	rqtp.tv_sec = 0;
	rqtp.tv_nsec = 100000000; /* 1 sec = 1000000000 nanoseconds */
	cnt = thrp->threads_cnt;
	while (0 != cnt) {
		cnt = thrp_thread_count_get(thrp);
		nanosleep(&rqtp, NULL);
	}
}

void
thrp_destroy(thrp_p thrp) {
	size_t i;

	if (NULL == thrp)
		return;
	/* Wait all threads before free mem. */
	thrp_shutdown_wait(thrp);
	/* Free resources. */
	thrpt_data_destroy(thrp->pvt);
	for (i = 0; i < thrp->threads_max; i ++) {
		thrpt_data_destroy(&thrp->threads[i]);
	}
	mem_filld(thrp, sizeof(thrp_t));
	free(thrp);
}


int
thrp_threads_create(thrp_p thrp, int skip_first) {
	size_t i;
	thrpt_p thrpt;

	if (NULL == thrp)
		return (EINVAL);
	if (0 != skip_first) {
		thrp->threads_cnt ++;
	}
	for (i = ((0 != skip_first) ? 1 : 0); i < thrp->threads_max; i ++) {
		thrpt = &thrp->threads[i];
		if (NULL == thrpt->thrp)
			continue;
		thrpt->running = 1;
		if (0 == pthread_create(&thrpt->pt_id, NULL, thrp_thread_proc, thrpt)) {
			thrp->threads_cnt ++;
		} else {
			thrpt->running = 0;
		}
	}
	return (0);
}

int
thrp_thread_attach_first(thrp_p thrp) {
	thrpt_p thrpt;

	if (NULL == thrp)
		return (EINVAL);
	thrpt = &thrp->threads[0];
	if (0 != thrpt->running)
		return (ESPIPE);
	thrpt->running = 2;
	thrpt->pt_id = pthread_self();
	thrp_thread_proc(thrpt);
	return (0);
}

int
thrp_thread_dettach(thrpt_p thrpt) {

	if (NULL == thrpt)
		return (EINVAL);
	thrpt->running = 0;
	return (0);
}

static void *
thrp_thread_proc(void *data) {
	thrpt_p thrpt = data;
	sigset_t sig_set;
	cpu_set_t cs;

	if (NULL == thrpt) {
		LOG_ERR(EINVAL, "invalid data");
		return (NULL);
	}
	pthread_setspecific(thrp_tls_key_thrpt, (const void*)thrpt);

	thrpt->running ++;
	LOG_INFO_FMT("Thread %zu started...", thrpt->thread_num);

	sigemptyset(&sig_set);
	sigaddset(&sig_set, SIGPIPE);
	if (0 != pthread_sigmask(SIG_BLOCK, &sig_set, NULL)) {
		LOG_ERR(errno, "can't block the SIGPIPE signal");
	}
	if (-1 != thrpt->cpu_id) {
		/* Bind this thread to a single cpu. */
		CPU_ZERO(&cs);
		CPU_SET(thrpt->cpu_id, &cs);
		if (0 == pthread_setaffinity_np(pthread_self(),
		    sizeof(cpu_set_t), &cs)) {
			LOG_INFO_FMT("Bind thread %zu to CPU %i",
			    thrpt->thread_num, thrpt->cpu_id);
		}
	}
	thrpt_loop(thrpt);

	thrpt->pt_id = 0;
	thrpt->thrp->threads_cnt --;
	pthread_setspecific(thrp_tls_key_thrpt, NULL);
	LOG_INFO_FMT("Thread %zu exited...", thrpt->thread_num);

	return (NULL);
}



size_t
thrp_thread_count_max_get(thrp_p thrp) {

	if (NULL == thrp)
		return (0);
	return (thrp->threads_max);
}

size_t
thrp_thread_count_get(thrp_p thrp) {
	size_t i, cnt;

	if (NULL == thrp)
		return (0);
	for (i = 0, cnt = 0; i < thrp->threads_max; i ++) {
		if (0 != thrp->threads[i].pt_id) {
			cnt ++;
		}
	}
	return (cnt);
}


thrpt_p
thrp_thread_get_current(void) {
	/* TLS magic. */
	return ((thrpt_p)pthread_getspecific(thrp_tls_key_thrpt));
}

thrpt_p
thrp_thread_get(thrp_p thrp, size_t thread_num) {

	if (NULL == thrp)
		return (NULL);
	if (thrp->threads_max <= thread_num) {
		thread_num = (thrp->threads_max - 1);
	}
	return (&thrp->threads[thread_num]);
}

thrpt_p
thrp_thread_get_rr(thrp_p thrp) {

	if (NULL == thrp)
		return (NULL);
	thrp->rr_idx ++;
	if (thrp->threads_max <= thrp->rr_idx) {
		thrp->rr_idx = 0;
	}
	return (&thrp->threads[thrp->rr_idx]);
}

/* Return io_fd that handled by all threads */
thrpt_p
thrp_thread_get_pvt(thrp_p thrp) {

	if (NULL == thrp)
		return (NULL);
	return (thrp->pvt /* thrp->threads[0] */);
}

int
thrp_thread_get_cpu_id(thrpt_p thrpt) {

	if (NULL == thrpt)
		return (-1);
	return (thrpt->cpu_id);
}

size_t
thrp_thread_get_num(thrpt_p thrpt) {

	if (NULL == thrpt)
		return ((size_t)-1);
	return (thrpt->thread_num);
}



thrp_p
thrpt_get_thrp(thrpt_p thrpt) {

	if (NULL == thrpt)
		return (NULL);
	return (thrpt->thrp);
}

size_t
thrpt_is_running(thrpt_p thrpt) {

	if (NULL == thrpt)
		return (0);
	return (thrpt->running);
}

void *
thrpt_get_msg_queue(thrpt_p thrpt) {

	if (NULL == thrpt)
		return (NULL);
	return (thrpt->msg_queue);
}


int
thrpt_data_create(thrp_p thrp, int cpu_id, size_t thread_num, thrpt_p thrpt) {
	int error;

	if (NULL == thrp || NULL == thrpt)
		return (EINVAL);
	mem_bzero(thrpt, sizeof(thrp_thread_t));
	thrpt->thrp = thrp;
	thrpt->cpu_id = cpu_id;
	thrpt->thread_num = thread_num;
	error = thrpt_data_event_init(thrpt);
	if (0 != error) {
		thrpt_data_destroy(thrpt);
		return (error);
	}
	return (0);
}

void
thrpt_data_destroy(thrpt_p thrpt) {

	if (NULL == thrpt || NULL == thrpt->thrp)
		return;
	thrpt_data_event_destroy(thrpt);
	close((int)thrpt->io_fd);
	mem_bzero(thrpt, sizeof(thrp_thread_t));
}


int
thrpt_ev_add(thrpt_p thrpt, uint16_t event, uint16_t flags,
    thrp_udata_p thrp_udata) {

	if (NULL == thrp_udata || NULL == thrp_udata->cb_func)
		return (EINVAL);
	thrp_udata->thrpt = thrpt;
	return (thrpt_ev_post(THRP_CTL_ADD, event, flags, NULL, thrp_udata));
}

int
thrpt_ev_add_ex(thrpt_p thrpt, uint16_t event, uint16_t flags,
    uint32_t fflags, uint64_t data, thrp_udata_p thrp_udata) {
	thrp_event_t ev;

	ev.event = event;
	ev.flags = flags;
	ev.fflags = fflags;
	ev.data = data;
	return (thrpt_ev_add2(thrpt, &ev, thrp_udata));
}

int
thrpt_ev_add2(thrpt_p thrpt, thrp_event_p ev, thrp_udata_p thrp_udata) {

	if (NULL == ev || NULL == thrp_udata || NULL == thrp_udata->cb_func)
		return (EINVAL);
	thrp_udata->thrpt = thrpt;
	return (thrpt_ev_post(THRP_CTL_ADD, THRP_EV_NONE, 0, ev, thrp_udata));
}

int
thrpt_ev_del(uint16_t event, thrp_udata_p thrp_udata) {

	//thrpt_ev_q_del(event, thrp_udata);
	return (thrpt_ev_post(THRP_CTL_DEL, event, 0, NULL, thrp_udata));
}

int
thrpt_ev_enable(int enable, uint16_t event, thrp_udata_p thrp_udata) {

	return (thrpt_ev_post(((0 != enable) ? THRP_CTL_ENABLE : THRP_CTL_DISABLE),
	    event, 0, NULL, thrp_udata));
}

int
thrpt_ev_enable_ex(int enable, uint16_t event, uint16_t flags,
    uint32_t fflags, uint64_t data, thrp_udata_p thrp_udata) {
	thrp_event_t ev;

	ev.event = event;
	ev.flags = flags;
	ev.fflags = fflags;
	ev.data = data;

	return (thrpt_ev_post(((0 != enable) ? THRP_CTL_ENABLE : THRP_CTL_DISABLE),
	    THRP_EV_NONE, 0, &ev, thrp_udata));
}


void
thrpt_cached_time_update_cb(thrp_event_p ev, thrp_udata_p thrp_udata) {
	struct timespec *tp;

	debugd_break_if(NULL == ev);
	debugd_break_if(THRP_EV_TIMER != ev->event);
	debugd_break_if(NULL == thrp_udata);

	tp = (struct timespec*)thrp_udata->ident;
	clock_gettime(CORE_THRP_CLOCK_MONOTONIC, &tp[0]);
	clock_gettime(CORE_THRP_CLOCK_REALTIME, &tp[1]);
}

int
thrpt_gettimev(thrpt_p thrpt, int real_time, struct timespec *tp) {

	if (NULL == tp)
		return (EINVAL);
	if (NULL == thrpt ||
	    0 == (THRP_S_F_CACHE_TIME_SYSC & thrpt->thrp->flags)) { /* No caching. */
		if (0 != real_time)
			return (clock_gettime(CORE_THRP_CLOCK_REALTIME, tp));
		return (clock_gettime(CORE_THRP_CLOCK_MONOTONIC, tp));
	}
	if (0 != real_time) {
		memcpy(tp, &thrpt->thrp->tp_time_cached[1], sizeof(struct timespec));
	} else {
		memcpy(tp, &thrpt->thrp->tp_time_cached[0], sizeof(struct timespec));
	}
	return (0);
}

time_t
thrpt_gettime(thrpt_p thrpt, int real_time) {
	struct timespec tp;

	thrpt_gettimev(thrpt, real_time, &tp);
	return (tp.tv_sec);
}
