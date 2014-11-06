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



#include <sys/param.h>

#ifdef __linux__ /* Linux specific code. */
#define _GNU_SOURCE /* See feature_test_macros(7) */
#define __USE_GNU 1
#endif /* Linux specific code. */

#include <sys/types.h>

#ifdef BSD /* BSD specific code. */
#include <sys/event.h>
#endif /* BSD specific code. */

#ifdef __linux__ /* Linux specific code. */
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h> /* open, fcntl */
#include <sys/socket.h>
#endif /* Linux specific code. */

#include <sys/queue.h>
#include <inttypes.h>
#include <stdlib.h> /* malloc, exit */
#include <unistd.h> /* close, write, sysconf */
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <errno.h>
//#include <stdio.h> /* snprintf, fprintf */
#include <signal.h>
#include <pthread.h>
#include <time.h>

#include "core_macro.h"
#include "core_helpers.h"
#include "core_log.h"
#include "core_thrp.h"

/* Initialize Thread Local Storage. */
static pthread_key_t thrp_tls_key_thrpt;
static int thrp_tls_key_thrpt_error = EAGAIN;



/* Operation. */
#define THRP_CTL_ADD		0
#define THRP_CTL_DEL		1
#define THRP_CTL_ENABLE		2
#define THRP_CTL_DISABLE	3
#define THRP_CTL_LAST		THRP_CTL_DISABLE


#ifdef BSD /* BSD specific code. */
#define THREADP_ITEM_EV_LIST_SIZE	64

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
//#define CORE_THRP_LINUX_EPOLL_ET	1

#ifdef CORE_THRP_LINUX_EPOLL_ET
#define EPOLL_ET		EPOLLET
#else
#define EPOLL_ET		0
#endif

#define EPOLL_INOUT		(EPOLLIN | EPOLLOUT)
#define EPOLL_OUT		(EPOLLOUT /*| EPOLL_ET*/)
#define EPOLL_IN		(EPOLLIN | EPOLLRDHUP | EPOLLPRI | EPOLL_ET)
#define EPOLL_HUP		(EPOLLHUP | EPOLLRDHUP)

#define THRP_EV_OTHER(event)	(THRP_EV_READ == (event) ?			\
					THRP_EV_WRITE : THRP_EV_READ)

static const int thrp_op_to_op_ep_map[] = {
	EPOLL_CTL_ADD,		/* 0: THRP_CTL_ADD */
	EPOLL_CTL_DEL,		/* 1: THRP_CTL_DEL */
	EPOLL_CTL_ADD,		/* 2: THRP_CTL_ENABLE */
	EPOLL_CTL_DEL,		/* 3: THRP_CTL_DISABLE */
	0
};

static const uint32_t thrp_event_to_ep_map[] = {
	EPOLL_IN,		/* 0: THRP_EV_READ */
	EPOLL_OUT,		/* 1: THRP_EV_WRITE */
	0,			/* 2: THRP_EV_TIMER */
	0
};


#ifdef CORE_THRP_LINUX_MULTIPLE_EVENTS /* Multiple events. */

#define EP_DATA_F_TIMER		0x0000000100000000
#define EP_DATA_F_ONESHOT	0x0000001000000000
#define EP_DATA_IS_TIMER(data)	(0 != (EP_DATA_F_TIMER & (data).u64))
#define EP_DATA_MARK_AS_TIMER(data)						\
				(data).u64 |= EP_DATA_F_TIMER
#define EP_FD_DATA(ident, event)						\
				thrp->fd_data[(ident)].ev_udata[(event)]
#define EP_EV_DATA(epev, event)							\
				EP_FD_DATA((epev).data.u32, (event))
#define EP_EV_DATA_GET(epev, event)						\
				(EP_FD_DATA((epev).data.u32, (event)) & (uintptr_t)~1)

typedef struct thrp_fd_data_s { /* thread pool per fd data */
	volatile uintptr_t	ev_udata[2]; /* Read/Write (THRP_EV_*) udata */
} thrp_fd_data_t, *thrp_fd_data_p;

#else /* Single event. */

#define EP_DATA_F_TIMER		0x00000001
#define EP_DATA_IS_TIMER(data)	(0 != (EP_DATA_F_TIMER & (data).u32))
#define EP_DATA_MARK_AS_TIMER(data)						\
				(data).u32 |= EP_DATA_F_TIMER
#define EP_EV_DATA_GET(epe)							\
			(thrp_udata_p)((uintptr_t)(epev).data.ptr & (uintptr_t)~1)

#endif


typedef struct thrpt_msg_pkt_s { /* thread message packet data. */
	size_t		magic;
	thrpt_msg_cb	msg_cb;
	void		*udata;
} thrpt_msg_pkt_t, *thrpt_msg_pkt_p;

#define THRPT_MSG_PKT_MAGIC 0xffddaa00


#define CORE_THRP_CLOCK_REALTIME	CLOCK_REALTIME
#define CORE_THRP_CLOCK_MONOTONIC	CLOCK_MONOTONIC

#endif /* Linux specific code. */




typedef struct thrp_thread_s { /* thread pool thread info */
	volatile size_t running; /* running */
	volatile size_t tick_cnt; /* For detecting hangs thread. */
	uintptr_t	io_fd;	/* io handle: kqueue (per thread) */
#ifdef BSD /* BSD specific code. */
	int		ev_nchanges; /* passed to kevent */
	struct kevent	ev_changelist[THREADP_ITEM_EV_LIST_SIZE]; /* passed to kevent */
#endif /* BSD specific code. */
	pthread_t	pt_id;	/* thread id */
	int		cpu_id;	/* cpu num or -1 if no bindings */
	size_t		thread_num; /* num in array, short internal thread id. */
#ifdef __linux__ /* Linux specific code. */
	int		queue_fd[2]; /* Linux queue specific. */
	thrp_udata_t	queue_udata;
	thrp_udata_t	pvt_udata;	/* Pool virtual thread support */
#endif	/* Linux specific code. */
	thrp_p		thrp;	/*  */
} thrp_thread_t;


typedef struct thrp_s { /* thread pool */
	thrpt_p		pvt;		/* Pool virtual thread. */
	size_t		rr_idx;
	uint32_t	flags;
	size_t		cpu_count;
	uintptr_t	fd_count;
#if (defined(__linux__) && defined(CORE_THRP_LINUX_MULTIPLE_EVENTS))
	thrp_fd_data_p	fd_data;	/* Linux specific. */
#endif
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
		    thrp_event_p ev, thrp_udata_p udata);
static int	thrpt_data_event_init(thrpt_p thrpt);
static void	thrpt_data_event_destroy(thrpt_p thrpt);
#if defined(__linux__)
static int	thrpt_msg_recv_and_process(thrpt_p thrpt);
#endif
static void	thrpt_loop(thrpt_p thrpt);

int		thrpt_data_create(thrp_p thrp, int cpu_id, size_t thread_num,
		    thrpt_p thrpt);
void		thrpt_data_destroy(thrpt_p thrpt);

static void	*thrp_thread_proc(void *data);

void		thrpt_msg_shutdown_cb(thrpt_p thrpt, void *udata);

size_t		thrpt_msg_broadcast_send__int(thrp_p thrp, thrpt_p src,
		    thrpt_msg_data_p msg_data, uint32_t flags, thrpt_msg_cb msg_cb,
		    void *udata, size_t *send_msg_cnt, size_t *error_cnt);
int		thrpt_msg_one_by_one_send_next__int(thrp_p thrp, thrpt_p src,
		    thrpt_msg_data_p msg_data);
void		thrpt_msg_sync_proxy_cb(thrpt_p thrpt, void *udata);
void		thrpt_msg_one_by_one_proxy_cb(thrpt_p thrpt, void *udata);
void		thrpt_msg_cb_done_proxy_cb(thrpt_p thrpt, void *udata);

void		thrpt_cached_time_update_cb(thrp_event_p ev, thrp_udata_p udata);



/*
 * FreeBSD specific code.
 */
#ifdef BSD /* BSD specific code. */

/* Translate thread pool flags <-> kqueue flags */
static inline u_short
thrp_flags_to_kq(uint16_t flags) {
	u_short ret = 0;

	if (0 != (THRP_F_ONESHOT & flags))
		ret |= EV_ONESHOT;
	if (0 != (THRP_F_CLEAR & flags))
		ret |= EV_CLEAR;
	if (0 != (THRP_F_DISPATCH & flags))
		ret |= EV_DISPATCH;
	return (ret);
}


static int
thrpt_data_event_init(thrpt_p thrpt) {
	struct kevent kev;

	thrpt->io_fd = kqueue();
	if ((uintptr_t)-1 == thrpt->io_fd)
		return (errno);
	/* Init threads message exchange. */
	kev.ident = thrpt->io_fd;
	kev.filter = EVFILT_USER;
	kev.flags = (EV_ADD | EV_CLEAR); /* Auto clear event. */
	kev.fflags = NOTE_FFNOP;
	kev.data = 0;
	kev.udata = NULL;
	if (-1 == kevent(thrpt->io_fd, &kev, 1, NULL, 0, NULL))
		return (errno);
	if (NULL != thrpt->thrp->pvt && thrpt != thrpt->thrp->pvt) {
		/* Add pool virtual thread to normal thread. */
		kev.ident = thrpt->thrp->pvt->io_fd;
		kev.filter = EVFILT_READ;
		kev.flags = (EV_ADD | EV_CLEAR); /* Auto clear event. */
		kev.fflags = 0;
		kev.data = 0;
		kev.udata = NULL;
		if (-1 == kevent(thrpt->io_fd, &kev, 1, NULL, 0, NULL))
			return (errno);
	}
	return (0);
}

static void
thrpt_data_event_destroy(thrpt_p thrpt __unused) {

	/* No deinittialisation needed. */
}

static int
thrpt_ev_post(int op, uint16_t event, u_short flags, const thrp_event_p ev,
    const thrp_udata_p udata) {
	struct kevent kev;

	if (THRP_CTL_LAST < op || NULL == udata || (uintptr_t)-1 == udata->ident ||
	    NULL == udata->thrpt)
		return (EINVAL);
	if (NULL != ev) {
		event = ev->event;
		flags = ev->flags;
		kev.fflags = ev->fflags;
		kev.data = ev->data;
	} else {
		kev.fflags = 0;
		kev.data = 0;
	}
	if (THRP_EV_LAST < event)
		return (EINVAL); /* Bad event. */
	kev.ident = udata->ident;
	kev.filter = thrp_event_to_kq_map[event];
	kev.flags = (thrp_op_to_flags_kq_map[op] | thrp_flags_to_kq(flags));
	kev.udata = (void*)udata;
	/* XXX: fix timer to force update. */
	if (EVFILT_TIMER == kev.filter) {
		if (EV_ENABLE & kev.flags)
			kev.flags |= EV_ADD;
		if (EV_DISABLE & kev.flags)
			kev.flags |= EV_DELETE;
	} else {
		if (udata->thrpt->thrp->fd_count <= udata->ident)
			return (EBADF); /* Bad FD. */
	}
	if (-1 == kevent(udata->thrpt->io_fd, &kev, 1, NULL, 0, NULL))
		return (errno);
	return (0);
}

int
thrpt_msg_send(thrpt_p dst, thrpt_p src, uint32_t flags, thrpt_msg_cb msg_cb,
    void *udata) {
	struct kevent kev;

	if (NULL == dst || NULL == msg_cb)
		return (EINVAL);
	if (0 != (THRP_MSG_F_SELF_DIRECT & flags)) {
		if (NULL == src)
			src = thrp_thread_get_current();
		if (src == dst) { /* Self. */
			msg_cb(dst, udata);
			return (0);
		}
	}
	if (0 == dst->running) {
		if (0 == (THRP_MSG_F_FORCE & flags))
			return (EHOSTDOWN);
		msg_cb(dst, udata);
		return (0);
	}
	kev.ident = dst->io_fd;
	kev.filter = EVFILT_USER;
	kev.flags = 0;
	kev.fflags = NOTE_TRIGGER;
	kev.data = (intptr_t)msg_cb;
	kev.udata = udata;
	if (-1 != kevent(dst->io_fd, &kev, 1, NULL, 0, NULL))
		return (0);
	/* Error. */
	if (0 != (THRP_MSG_F_FAIL_DIRECT & flags)) {
		msg_cb(dst, udata);
		return (0);
	}
	return (errno);
}

#if 0 /* XXX may be in future... */
int
thrpt_ev_q_add(thrpt_p thrpt, uint16_t event, uint16_t flags, thrp_udata_p udata) {
	/*thrpt_p thrpt;

	if (NULL == thrpt)
		return (EINVAL);
	if (THREADP_ITEM_EV_LIST_SIZE <= thrpt->ev_nchanges)
		return (-1);

	EV_SET(&thrpt->ev_changelist[thrpt->ev_nchanges], ident, filter, flags,
	    fflags, data, udata);
	thrpt->ev_nchanges ++;

	return (0);*/
	return (thrpt_ev_add(thrpt, event, flags, udata));
}

int
thrpt_ev_q_del(uint16_t event, thrp_udata_p udata) {
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
		if (i < ev_nchanges)
			memmove(&thrpt->ev_changelist[i], 
			    &thrpt->ev_changelist[(i + 1)], 
			    (sizeof(struct kevent) * (ev_nchanges - i))); // move items, except last
		memset(&thrpt->ev_changelist[(ev_nchanges + 1)], 0,
		    sizeof(struct kevent));// zeroize last
	}
	thrpt->ev_nchanges = ev_nchanges;

	return (ret);*/
	return (thrpt_ev_del(event, udata));
}

int
thrpt_ev_q_enable(int enable, uint16_t event, thrp_udata_p udata) {

	return (thrpt_ev_enable(enable, event, udata));
}

int
thrpt_ev_q_enable_ex(int enable, uint16_t event, uint16_t flags, u_int fflags,
    intptr_t data, thrp_udata_p udata) {

	return (thrpt_ev_enable_ex(enable, event, flags, fflags, data, udata));
}

int
thrpt_ev_q_flush(thrpt_p thrpt) {

	if (NULL == thrpt)
		return (EINVAL);
	if (0 == thrpt->ev_nchanges)
		return (0);
	if (-1 == kevent(thrpt->io_fd, thrpt->ev_changelist, thrpt->ev_nchanges,
	    NULL, 0, NULL))
		return (errno);
	return (0);
}
#endif

static void
thrpt_loop(thrpt_p thrpt) {
	thrpt_p pvt;
	int new_ev_cnt;
	struct kevent kev;
	thrp_event_t ev;
	thrp_udata_p udata;
	struct timespec ke_timeout;

	pvt = thrpt->thrp->pvt;
	thrpt->ev_nchanges = 0;
	memset(&ke_timeout, 0, sizeof(ke_timeout));

	/* Main loop. */
	while (0 != thrpt->running) {
		//if (0 != thrpt->ev_nchanges)
		//	LOGD_EV("kevent 0 != thrpt->ev_nchanges");
		thrpt->tick_cnt ++; /* Tic-toc */
		new_ev_cnt = kevent(thrpt->io_fd, thrpt->ev_changelist, 
		    thrpt->ev_nchanges, &kev, 1, NULL /* infinite wait. */);
		if (0 != thrpt->ev_nchanges) {
			memset(thrpt->ev_changelist, 0,
			    (sizeof(struct kevent) * thrpt->ev_nchanges));
			thrpt->ev_nchanges = 0;
		}
		if (0 == new_ev_cnt) { /* Timeout */
			LOGD_EV("kevent thrpt 1: new_ev_cnt = 0");
			continue;
		}
		if (0 > new_ev_cnt) { /* Error / Exit */
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

			new_ev_cnt = kevent(pvt->io_fd, NULL, 0, &kev, 1, &ke_timeout);
			if (1 != new_ev_cnt) /* Timeout or error. */
				continue;
		}
		if (EVFILT_USER == kev.filter) { /* Thread message process. */
			if (0 == kev.data)
				continue;
			if (thrpt->io_fd == kev.ident)	
				((thrpt_msg_cb)kev.data)(thrpt, kev.udata);
			if (pvt->io_fd == kev.ident)	
				((thrpt_msg_cb)kev.data)(pvt, kev.udata);
			continue;
		}
		if (NULL == kev.udata) {
			LOG_EV_FMT("kevent with invalid user data, ident = %zu", kev.ident);
			continue;
		}
		udata = (thrp_udata_p)kev.udata;
		if (udata->ident != kev.ident) {
			LOG_EV_FMT("kevent with invalid ident, kq_ident = %zu, thr_ident = %zu",
			    kev.ident, udata->ident);
			continue;
		}
		if (udata->thrpt != thrpt && udata->thrpt != pvt) {
			LOG_EV_FMT("kevent with invalid thrpt, thrpt = %zu, thr_thrpt = %zu",
			    thrpt, udata->thrpt);
			//continue;
		}
		if (NULL == udata->cb_func) {
			LOG_EV_FMT("kevent with invalid user cb_func, ident = %zu", kev.ident);
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
			continue;
		}
		ev.flags = 0;
		if (EV_EOF & kev.flags) {
			ev.flags |= THRP_F_EOF;
			if (kev.fflags) /* For socket: closed, and error present. */
				ev.flags |= THRP_F_ERROR;
		}
		ev.fflags = kev.fflags;
		ev.data = kev.data;

#if 0 /* extra debug */
		if (kev.ident > 11 && kev.ident < 1000) {
			char  tmplog[1024];
			size_t tmplog_size = 0;

			tmplog_size += snprintf((tmplog + tmplog_size), (sizeof(tmplog) - tmplog_size),
				"ident = %zu, ", kev.ident);
			switch (kev.filter) {
			case EVFILT_READ:
				tmplog_size += snprintf((tmplog + tmplog_size), (sizeof(tmplog) - tmplog_size),
					"READ");
				break;
			case EVFILT_WRITE:
				tmplog_size += snprintf((tmplog + tmplog_size), (sizeof(tmplog) - tmplog_size),
					"WRITE");
				break;
			case EVFILT_TIMER:
				tmplog_size += snprintf((tmplog + tmplog_size), (sizeof(tmplog) - tmplog_size),
					"TIMER");
				break;
			}
			tmplog_size += snprintf((tmplog + tmplog_size), (sizeof(tmplog) - tmplog_size),
				", data = %zu, flags:", kev.data);
	
			if (0 != (EV_EOF & kev.flags))
				tmplog_size += snprintf((tmplog + tmplog_size), (sizeof(tmplog) - tmplog_size),
					" EOF");
			LOG_EV(tmplog);
		}
#endif	
		udata->cb_func(&ev, udata);
	} /* End Main loop. */
	return;
}
#endif /* BSD specific code. */


#ifdef __linux__ /* Linux specific code. */
/* Translate thread pool flags <-> epoll flags */
static inline uint16_t
thrp_flags_from_ep(uint32_t event) {
	uint16_t ret = 0;
	
	if (0 != (EPOLL_HUP & event))
		ret |= THRP_F_EOF;
	if (0 != (EPOLLERR & event))
		ret |= THRP_F_ERROR;
	return (ret);
}

#define thrp_flags_to_ep(flags)							\
	((flags & (THRP_F_ONESHOT | THRP_F_DISPATCH)) ? EPOLLONESHOT : 0)


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
	}
	return (errno);
}

static int
thrpt_data_event_init(thrpt_p thrpt) {
	int error;

	thrpt->io_fd = epoll_create(thrpt->thrp->fd_count);
	if ((uintptr_t)-1 == thrpt->io_fd)
		return (errno);
	/* Init threads message exchange. */
	if (-1 == pipe2(thrpt->queue_fd, O_NONBLOCK))
		return (errno);
	thrpt->queue_udata.cb_func = NULL;
	thrpt->queue_udata.ident = thrpt->queue_fd[0];
	thrpt->queue_udata.thrpt = thrpt;
	error = thrpt_ev_post(THRP_CTL_ADD, THRP_EV_READ, 0, NULL, &thrpt->queue_udata);
	if (0 != error)
		return (error);
	if (NULL != thrpt->thrp->pvt && thrpt != thrpt->thrp->pvt) {
		/* Add pool virtual thread to normal thread. */
		thrpt->pvt_udata.cb_func = NULL;
		thrpt->pvt_udata.ident = thrpt->thrp->pvt->io_fd;
		thrpt->pvt_udata.thrpt = thrpt;
		error = thrpt_ev_post(THRP_CTL_ADD, THRP_EV_READ, 0, NULL, &thrpt->pvt_udata);
		if (0 != error)
			return (error);
	}
	return (0);
}

static void
thrpt_data_event_destroy(thrpt_p thrpt) {

	if (NULL == thrpt)
		return;
	close(thrpt->queue_fd[0]);
	close(thrpt->queue_fd[1]);
}

static int
thrpt_ev_post(int op, uint16_t event, uint16_t flags, thrp_event_p ev,
    thrp_udata_p udata) {
	int error = 0;
	struct epoll_event epev;

	if (THRP_CTL_LAST < op || NULL == udata || (uintptr_t)-1 == udata->ident ||
	    NULL == udata->thrpt)
		return (EINVAL);
	if (NULL != ev) {
		event = ev->event;
		flags = ev->flags;
	}
	if (THRP_EV_LAST < event)
		return (EINVAL); /* Bad event. */
	
	epev.events = (EPOLLHUP | EPOLLERR);
#ifdef CORE_THRP_LINUX_MULTIPLE_EVENTS
	epev.data.u64 = 0;
#else /* Single event. */
	epev.data.ptr = (void*)udata;
#endif
	if (THRP_EV_TIMER == event) { /* Special handle for timer. */
		struct itimerspec new_tmr;

		if (THRP_CTL_DEL == op) { /* Delete timer. */
			if (0 == udata->tpdata)
				return (0);
err_out_timer:
#ifdef CORE_THRP_LINUX_MULTIPLE_EVENTS
			EP_FD_DATA(udata->tpdata, THRP_EV_READ) = NULL;
#endif
			close(udata->tpdata); /* no need to epoll_ctl(EPOLL_CTL_DEL) */
			udata->tpdata = 0;
			return (error);
		}
		if (THRP_CTL_DISABLE == op) {
			if (0 == udata->tpdata)
				return (0);
			memset(&new_tmr, 0, sizeof(new_tmr));
			if (-1 == timerfd_settime(udata->tpdata, 0, &new_tmr, NULL))
				return (errno);
			return (0);
		}
		/* THRP_CTL_ADD, THRP_CTL_ENABLE */
		if (NULL == ev)
			return (EINVAL);
		if (0 == udata->tpdata) { /* Create timer, if needed. */
			udata->tpdata = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
			if ((uintptr_t)-1 == udata->tpdata) {
				udata->tpdata = 0;
				return (errno);
			}
			/* Adding to epoll. */
			epev.events |= EPOLLIN;
			EP_DATA_MARK_AS_TIMER(epev.data);
#ifdef CORE_THRP_LINUX_MULTIPLE_EVENTS
			epev.data.u32 = udata->tpdata;
			EP_FD_DATA(udata->tpdata, THRP_EV_READ) = udata;
#endif
			if (0 != epoll_ctl(udata->thrpt->io_fd, EPOLL_CTL_ADD,
			    udata->tpdata, &epev)) {
				error = errno;
				goto err_out_timer;
			}
		}
		new_tmr.it_value.tv_sec = (ev->data / 1000);
		new_tmr.it_value.tv_nsec = ((ev->data % 1000) * 1000000);
		if (0 != ((THRP_F_ONESHOT | THRP_F_DISPATCH) & flags)) { /* Onetime. */
			memset(&new_tmr.it_interval, 0, sizeof(struct timespec));
		} else {/* Periodic. */
			new_tmr.it_interval = new_tmr.it_value;
			//memcpy(&new_tmr.it_interval, &new_tmr.it_value,
			//    sizeof(struct timespec));
		}
		if (-1 == timerfd_settime(udata->tpdata, 0, &new_tmr, NULL)) {
			error = errno;
			goto err_out_timer;
		}
		return (0);
	}

	/* Read/Write events. */
	if (udata->thrpt->thrp->fd_count <= udata->ident)
		return (EBADF); /* Bad FD. */
#ifdef CORE_THRP_LINUX_MULTIPLE_EVENTS
	if (THRP_CTL_DEL == op) { // XXX remove event only if it last event!
		if (NULL == EP_FD_DATA(udata->ident, event))
			return (0); /* Allready deleted. */
		EP_FD_DATA(udata->ident, event) = NULL;
		if (NULL == EP_FD_DATA(udata->ident, THRP_EV_OTHER(event))) {
			/* Delete last event. */
			epoll_ctl(udata->thrpt->io_fd, EPOLL_CTL_DEL, udata->ident, &epev);
			return (0);
		}
		/* Modify, to remove only one event. */
	} else { /* Add/mod event. */
		// XXX keep previous events in mask
		EP_FD_DATA(udata->ident, event) = udata;
		if (flags & (THRP_F_ONESHOT | THRP_F_DISPATCH))
			EP_FD_DATA(udata->ident, event) |= 1;
	}

	/* Set events. */
	if (NULL != EP_FD_DATA(udata->ident, THRP_EV_READ))
		epev.events |= EPOLL_IN;
	if (NULL != EP_FD_DATA(udata->ident, THRP_EV_WRITE))
		epev.events |= EPOLLOUT;

	/* Set flags: oneshot only if one event. */
	if ((1 & EP_FD_DATA(udata->ident, THRP_EV_READ)) ||
	    (1 & EP_FD_DATA(udata->ident, THRP_EV_WRITE))) {
		if (EPOLL_INOUT != (epev.events & EPOLL_INOUT)) {
			epev.events |= EPOLLONESHOT;
			epev.data.u64 |= EP_DATA_F_ONESHOT;
		} else { /* Set flags for handlet to simulate oneshot. */
			
		}
	}
	epev.data.u32 = udata->ident;

	if (THRP_CTL_ADD == op) { /* Try to add event to epoll. */
		if (0 == epoll_ctl(udata->thrpt->io_fd, EPOLL_CTL_ADD, udata->ident, &epev))
			return (0);
		error = errno;
		if (EEXIST != error)
			goto err_out;
		if (0 == epoll_ctl(udata->thrpt->io_fd, EPOLL_CTL_MOD, udata->ident, &epev))
			return (0);
	} else { /* Try to modify existing. */
		if (0 == epoll_ctl(udata->thrpt->io_fd, EPOLL_CTL_MOD, udata->ident, &epev))
			return (0);
		error = errno;
		if (ENOENT != error)
			goto err_out;
		if (0 == epoll_ctl(udata->thrpt->io_fd, EPOLL_CTL_ADD, udata->ident, &epev))
			return (0);
	}
	/* Error... */
	error = errno;
err_out:
	EP_FD_DATA(udata->ident, event) = NULL;
	return (error);
#else /* Single event. */
	//op = thrp_op_to_op_ep_map[op];
	if (THRP_CTL_DEL == op || THRP_CTL_DISABLE == op) {
		epoll_ctl(udata->thrpt->io_fd, EPOLL_CTL_DEL, udata->ident, &epev);
		return (0);
	}
	udata->tpdata = event; /* Remember original event. */
	epev.events |= (thrp_event_to_ep_map[event] | thrp_flags_to_ep(flags));
	if (0 == epoll_ctl(udata->thrpt->io_fd, EPOLL_CTL_ADD, udata->ident, &epev))
		return (0);
	/* Try fix. */
	LOG_EV("epoll_ctl(EPOLL_CTL_ADD) FAIL!!!");
	error = errno;
	if (EEXIST != error)
		return (error);
	if (0 != epoll_ctl(udata->thrpt->io_fd, EPOLL_CTL_MOD, udata->ident, &epev))
		return (errno);
	return (0);
#endif
}

int
thrpt_msg_send(thrpt_p dst, thrpt_p src, uint32_t flags, thrpt_msg_cb msg_cb,
    void *udata) {
	thrpt_msg_pkt_t msg;

	if (NULL == dst || NULL == msg_cb)
		return (EINVAL);
	if (0 != (THRP_MSG_F_SELF_DIRECT & flags)) {
		if (NULL == src)
			src = thrp_thread_get_current();
		if (src == dst) { /* Self. */
			msg_cb(dst, udata);
			return (0);
		}
	}
	if (0 == dst->running) {
		if (0 == (THRP_MSG_F_FORCE & flags))
			return (EHOSTDOWN);
		msg_cb(dst, udata);
		return (0);
	}
	msg.magic = THRPT_MSG_PKT_MAGIC;
	msg.msg_cb = msg_cb;
	msg.udata = udata;
	if (sizeof(msg) == write(dst->queue_fd[1], &msg, sizeof(msg)))
		return (0);
	/* Error. */
	if (0 != (THRP_MSG_F_FAIL_DIRECT & flags)) {
		msg_cb(dst, udata);
		return (0);
	}
	return (errno);
}

static int
thrpt_msg_recv_and_process(thrpt_p thrpt) {
	ssize_t rd, i;
	thrpt_msg_pkt_t msg[1024];

	for (;;) {
		rd = read(thrpt->queue_fd[0], &msg, sizeof(msg));
		//if (0 >= rd)
		//	return (rd);
		if (-1 == rd)
			return (errno);
		if (0 == rd)
			return (0);
		if (0 != (rd % sizeof(thrpt_msg_pkt_t)))
			LOG_EV("thrpt_msg_pkt_t damaged");
		rd /= sizeof(thrpt_msg_pkt_t);
		for (i = 0; i < rd; i ++) { /* Process loop. */
			if (THRPT_MSG_PKT_MAGIC != msg[i].magic) { /* XXX: Add recovery here! */
				LOG_EV("thrpt_msg_pkt_t damaged");
				continue;
			}
			if (NULL == msg[i].msg_cb)
				continue;
			msg[i].msg_cb(thrpt, msg[i].udata);
		}
		if (SIZEOF(msg) > (size_t)rd) /* All data read. */
			return (0);
	}
	return (0);
}

static void
thrpt_loop(thrpt_p thrpt) {
	thrpt_p pvt;
	thrp_p thrp;
	int new_ev_cnt, itm;
	struct epoll_event epev;
	thrp_event_t ev;
	thrp_udata_p udata;
	uint64_t tmr_data;
	socklen_t optlen;

	thrp = thrpt->thrp;
	pvt = thrp->pvt;
	/* Main loop. */
	while (0 != thrpt->running) {
		thrpt->tick_cnt ++; /* Tic-toc */
		new_ev_cnt = epoll_wait(thrpt->io_fd, &epev, 1, 1000);
		if (0 == new_ev_cnt) /* Timeout */
			continue;
		if (-1 == new_ev_cnt) { /* Error / Exit */
			LOG_ERR(errno, "epoll_wait()");
			break;
		}
#ifdef CORE_THRP_LINUX_MULTIPLE_EVENTS
		if (0 == (EPOLL_INOUT & epev.events)) {
			LOG_EV_FMT("epoll event with NO EPOLLIN | EPOLLOUT, epev.events = %"PRIu32,
			    epev.events);
			if (0 != ((EPOLLRDHUP | EPOLLPRI) & epev.events)
#ifdef CORE_THRP_LINUX_MULTIPLE_EVENTS
			    && NULL != EP_EV_DATA_GET(epev, THRP_EV_READ)
#endif
			) {
				epev.events |= EPOLLIN;
				LOG_EV("... looks like EPOLLIN");
			} else { /* Possible error happen, report to bouth handlers.*/
				epev.events |= EPOLL_INOUT;
			}
		}
		if (thrp->fd_count <= epev.data.u32) {
			LOG_EV_FMT("epoll event with invalid ident, epev.data.u32 = %"PRIu32,
			    epev.data.u32);
			continue;
		}

		/* Translate ep event to thread poll event. */
		if (EP_DATA_IS_TIMER(epev.data)) { /* Timer */
			udata = EP_EV_DATA_GET(epev, THRP_EV_READ);
			tmr_data = 0;
			itm = read(udata->tpdata, &tmr_data, sizeof(tmr_data));
			if (NULL == udata || NULL == udata->cb_func ||
			    epev.data.u32 != udata->tpdata) {
				LOGD_EV_FMT("remove timer with no callback: epev.data.u32 = %"PRIu32,
				    epev.data.u32);
				EP_EV_DATA(epev, THRP_EV_READ) = NULL;
				close(epev.data.u32);
				continue;
			}
			ev.event = THRP_EV_TIMER;
			ev.flags = 0;
			ev.fflags = 0;
			ev.data = (intptr_t)tmr_data;
			udata->cb_func(&ev, udata);
			continue;
		}
		ev.flags = thrp_flags_from_ep(epev.events);
		ev.fflags = ((EPOLL_HUP & epev.events) ? errno : 0);
		ev.data = INTPTR_MAX; /* Transfer as many as you can. */
		if (0 != (EPOLLERR & epev.events)) {
			ev.data = errno;
			optlen = sizeof(int);
			if (0 == getsockopt(epev.data.u32, SOL_SOCKET, SO_ERROR,
			    &itm, &optlen))
				ev.data = itm;
			if (0 == ev.data)
				ev.data = EINVAL;
		}

		if (0 != (EPOLLIN & epev.events) &&
		    NULL != (udata = EP_EV_DATA_GET(epev, THRP_EV_READ)) &&
		    NULL != udata->cb_func) {
			if (udata->ident != epev.data.u32)
				LOG_EV_FMT("epoll R event id not equal user ident, "
				    "epev.data.u32 = %"PRIu32", ident = %zu",
				    epev.data.u32, udata->ident);
			ev.event = THRP_EV_READ;
			/* Remove oneshot/dispatch event. */
			if (0 == (EP_DATA_F_ONESHOT | epev.data.u64) &&
			    0 != (1 & EP_EV_DATA(epev, THRP_EV_READ)))
				thrpt_ev_del(THRP_EV_READ, udata);
			udata->cb_func(&ev, udata);
		}
		if (0 != (EPOLLOUT & epev.events) &&
		    NULL != (udata = EP_EV_DATA_GET(epev, THRP_EV_WRITE)) &&
		    NULL != udata->cb_func) {
			if (udata->ident != epev.data.u32)
				LOG_EV_FMT("epoll W event id not equal user ident, "
				    "epev.data.u32 = %"PRIu32", ident = %zu",
				    epev.data.u32, udata->ident);
			/* Remove oneshot/dispatch event. */
			if (0 == (EP_DATA_F_ONESHOT | epev.data.u64) &&
			    0 != (1 & EP_EV_DATA(epev, THRP_EV_WRITE)))
				thrpt_ev_del(THRP_EV_WRITE, udata);
			ev.event = THRP_EV_WRITE;
			udata->cb_func(&ev, udata);
		}
#else /* Single event. */
		if (NULL == epev.data.ptr) {
			LOG_EV_FMT("epoll event with invalid user data, epev.data.ptr = %"PRIu64,
			    epev.data.u64);
			continue;
		}

		udata = EP_EV_DATA_GET(epev);
		if (NULL == udata->cb_func) {
			if (pvt->io_fd == udata->ident) { /* Pool virtual thread */
				new_ev_cnt = epoll_wait(pvt->io_fd, &epev, 1, 0);
				if (1 != new_ev_cnt || NULL == epev.data.ptr) /* Timeout or error. */
					continue;
				udata = EP_EV_DATA_GET(epev);
				if ((uintptr_t)pvt->queue_fd[0] == udata->ident) { /* Thread message process. */
					thrpt_msg_recv_and_process(pvt);
					continue;
				}
			} else if ((uintptr_t)thrpt->queue_fd[0] == udata->ident) { /* Thread message process. */
				thrpt_msg_recv_and_process(thrpt);
				continue;
			} else {
				LOG_EV_FMT("epoll event with invalid user cb_func, "
				    "epev.data.ptr = %"PRIu64,
				    epev.data.u64);
				continue;
			}
		}
		/* Translate ep event to thread poll event. */
		if (EP_DATA_IS_TIMER(epev.data)) { /* Timer */
			tmr_data = 0;
			itm = read(udata->tpdata, &tmr_data, sizeof(tmr_data));
			ev.event = THRP_EV_TIMER;
			ev.flags = 0;
			ev.fflags = 0;
			ev.data = (intptr_t)tmr_data;
			udata->cb_func(&ev, udata);
			continue;
		}
		ev.event = udata->tpdata;
		ev.flags = 0;
		ev.fflags = 0;
		if (0 != (EPOLL_HUP & epev.events))
			ev.flags |= THRP_F_EOF;
		if (0 != (EPOLLERR & epev.events)) {
			ev.flags |= THRP_F_ERROR;
			/* Try to find error code. */
			ev.fflags = errno;
			optlen = sizeof(int);
			if (0 == getsockopt(udata->ident, SOL_SOCKET, SO_ERROR,
			    &itm, &optlen))
				ev.fflags = itm;
			if (0 == ev.fflags)
				ev.fflags = EINVAL;
		}
		ev.data = INTPTR_MAX; /* Transfer as many as you can. */

		udata->cb_func(&ev, udata);
#endif
	} /* End Main loop. */
	return;
}
#endif /* Linux specific code. */



/*
 * Shared code.
 */


int
thrp_init(void) {

	if (0 != thrp_tls_key_thrpt_error) /* Try to reinit TLS. */
		thrp_tls_key_thrpt_error = pthread_key_create(&thrp_tls_key_thrpt, NULL);
	return (thrp_tls_key_thrpt_error);
}

int
thrp_create(uint32_t flags, size_t threads_max, uintptr_t tick_time, thrp_p *pthrp) {
	size_t i, cpu_count, cur_cpu;
	int error, fd_max_count;
	thrp_p thrp;

	error = thrp_init();
	if (0 != error) {
		LOGD_ERR(error, "thrp_init()");
		return (error);
	}

	if (NULL == pthrp)
		return (EINVAL);
	cpu_count = sysconf(_SC_NPROCESSORS_CONF);
	if (0 == threads_max)
		threads_max = cpu_count;
	thrp = (thrp_p)zalloc((sizeof(thrp_t) + ((threads_max + 1) * sizeof(thrp_thread_t))));
	if (NULL == thrp)
		return (ENOMEM);
	fd_max_count = getdtablesize();
#if (defined(__linux__) && defined(CORE_THRP_LINUX_MULTIPLE_EVENTS))
	thrp->fd_data = zalloc((sizeof(thrp_fd_data_t) * fd_max_count));
	if (NULL == thrp->fd_data) {
		free(thrp);
		return (ENOMEM);
	}
#endif
	thrp->flags = flags;
	thrp->cpu_count = cpu_count;
	thrp->threads_max = threads_max;
	thrp->fd_count = fd_max_count;
	thrp->pvt = &thrp->threads[threads_max];
	error = thrpt_data_create(thrp, -1, ~0, &thrp->threads[threads_max]);
	if (0 != error) {
		LOGD_ERR(error, "thrpt_data_create() - pvt");
		goto err_out;
	}
	for (i = 0, cur_cpu = 0; i < threads_max; i ++, cur_cpu ++) {
		if (0 != (flags & THRP_C_F_BIND2CPU)) {
			if (cur_cpu >= cpu_count)
				cur_cpu = 0;
		} else {
			cur_cpu = -1;
		}
		error = thrpt_data_create(thrp, cur_cpu, i, &thrp->threads[i]);
		if (0 != error) {
			LOGD_ERR(error, "thrpt_data_create() - threads");
			goto err_out;
		}
	}
	
	if (0 != (flags & THRP_C_F_CACHE_TIME_SYSC)) {
		thrp->thrp_timer.cb_func = thrpt_cached_time_update_cb;
		thrp->thrp_timer.ident = (uintptr_t)&thrp->tp_time_cached;
		error = thrpt_ev_add_ex(&thrp->threads[0], THRP_EV_TIMER, 0, 0,
		    tick_time, &thrp->thrp_timer);
		if (0 != error) {
			LOGD_ERR(error, "thrpt_ev_add_ex(threads[0], THRP_EV_TIMER, tick_time)");
			goto err_out;
		}
		/* Update time. */
		thrpt_cached_time_update_cb(NULL, &thrp->thrp_timer);
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
	if (0 != (THRP_C_F_CACHE_TIME_SYSC & thrp->flags))
		thrpt_ev_del(THRP_EV_TIMER, &thrp->thrp_timer);
	/* Shutdown threads. */
	for (i = 0; i < thrp->threads_max; i ++) {
		if (0 == thrp->threads[i].running)
			continue;
		thrpt_msg_send(&thrp->threads[i], NULL, THRP_MSG_F_SELF_DIRECT,
		    thrpt_msg_shutdown_cb, NULL);
		thrp->threads[i].running = 0;
	}
}
void
thrpt_msg_shutdown_cb(thrpt_p thrpt, void *udata __unused) {

	thrpt->running = 0;
}

void
thrp_shutdown_wait(thrp_p thrp) {

	if (NULL == thrp)
		return;
	/* Wait all threads before return. */
	while (0 != thrp->threads_cnt)
		usleep(100000); /* 1 sec = 1000000 microseconds */
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
#if (defined(__linux__) && defined(CORE_THRP_LINUX_MULTIPLE_EVENTS))
	free(thrp->fd_data);
#endif
	memfilld(thrp, sizeof(thrp_t));
	free(thrp);
}


int
thrp_threads_create(thrp_p thrp, int skeep_first) {
	size_t i;
	thrpt_p thrpt;

	if (NULL == thrp)
		return (EINVAL);
	if (0 != skeep_first)
		thrp->threads_cnt ++;
	for (i = ((0 != skeep_first) ? 1 : 0); i < thrp->threads_max; i ++) {
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

	if (NULL == thrpt) {
		LOG_ERR(EINVAL, "invalid data");
		return (NULL);
	}
	pthread_setspecific(thrp_tls_key_thrpt, (const void*)thrpt);

	thrpt->running ++;
	LOG_INFO_FMT("Thread %"PRIu32" started...", thrpt->thread_num);

	sigemptyset(&sig_set);
	sigaddset(&sig_set, SIGPIPE);
	if (0 != pthread_sigmask(SIG_BLOCK, &sig_set, NULL))
		LOG_ERR(errno, "can't block the SIGPIPE signal");
	if (0 != (THRP_C_F_BIND2CPU & thrpt->thrp->flags)) {
		if (0 == bind_thread_to_cpu(thrpt->cpu_id))
			LOG_INFO_FMT("Bind thread %"PRIu32" to CPU %d",
			    thrpt->thread_num, thrpt->cpu_id);
	}
	thrpt_loop(thrpt);

	thrpt->pt_id = 0;
	thrpt->thrp->threads_cnt --;
	pthread_setspecific(thrp_tls_key_thrpt, NULL);
	LOG_INFO_FMT("Thread %"PRIu32" exited...", thrpt->thread_num);

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

	if (NULL == thrp)
		return (0);
	return (thrp->threads_cnt);
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
	if (thrp->threads_cnt <= thread_num)
		thread_num = (thrp->threads_cnt - 1);
	return (&thrp->threads[thread_num]);
}

thrpt_p
thrp_thread_get_rr(thrp_p thrp) {

	if (NULL == thrp)
		return (NULL);
	thrp->rr_idx ++;
	if (thrp->threads_cnt <= thrp->rr_idx)
		thrp->rr_idx = 0;
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


int
thrpt_data_create(thrp_p thrp, int cpu_id, size_t thread_num, thrpt_p thrpt) {
	int error;

	if (NULL == thrp || NULL == thrpt)
		return (EINVAL);
	memset(thrpt, 0, sizeof(thrp_thread_t));
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
	close(thrpt->io_fd);
	memset(thrpt, 0, sizeof(thrp_thread_t));
}


static inline size_t
thrpt_msg_active_thr_count_dec(thrpt_msg_data_p msg_data, thrpt_p src, size_t dec) {
	size_t tm;

	/* Additional data handling. */
	MTX_LOCK(&msg_data->lock);
	msg_data->active_thr_count -= dec;
	tm = msg_data->active_thr_count;
	MTX_UNLOCK(&msg_data->lock);

	if (0 != tm || NULL == msg_data->done_cb)
		return (tm);
	/* There is other alive threads. */
	/* This was last thread, so we need do call back. */
	thrpt_msg_send(msg_data->thrpt, src,
	    (THRP_MSG_F_FAIL_DIRECT | THRP_MSG_F_SELF_DIRECT),
	    thrpt_msg_cb_done_proxy_cb, msg_data);
	return (tm);
}

size_t
thrpt_msg_broadcast_send__int(thrp_p thrp, thrpt_p src, thrpt_msg_data_p msg_data,
    uint32_t flags, thrpt_msg_cb msg_cb, void *udata,
    size_t *send_msg_cnt, size_t *error_cnt) {
	size_t i, err_cnt = 0;
	thrpt_p thrpt;

	if (NULL != msg_data &&
	    NULL != src && 0 != (THRP_BMSG_F_SELF_SKEEP & flags)) {
		msg_data->active_thr_count --;
	}
	(*send_msg_cnt) = 0;
	(*error_cnt) = 0;
	for (i = 0; i < thrp->threads_max; i ++) { /* Send message loop. */
		thrpt = &thrp->threads[i];
		if (thrpt == src && /* Self. */
		    0 != (THRP_BMSG_F_SELF_SKEEP & flags)) {
			/* No need to "active_thr_count --" here:
			 * SELF_SKEEP allready done,
			 * msg_cb = thrpt_msg_sync_proxy_cb and handle count for
			 * thrpt_msg_bsend_ex(THRP_BMSG_F_SYNC) and
			 * thrpt_msg_cbsend() w/o THRP_CBMSG_F_ONE_BY_ONE. */
			continue;
		}
		(*send_msg_cnt) ++;
		if (0 == thrpt_msg_send(thrpt, src, flags, msg_cb, udata))
			continue;
		/* Error on send. Allso here EHOSTDOWN from not running threads. */
		(*send_msg_cnt) --;
		(*error_cnt) ++;
		err_cnt ++;
	}
	/* Do not forget for "unlock" and free + done cb:
	 * if err_cnt = 0 then msg_data may not exist!
	 * if (0 != err_cnt && NULL != msg_data)
	 *	thrpt_msg_active_thr_count_dec(msg_data, thrpt, err_cnt);
	 */
	return (err_cnt);
}
int
thrpt_msg_one_by_one_send_next__int(thrp_p thrp, thrpt_p src,
    thrpt_msg_data_p msg_data) {
	thrpt_p thrpt;

	if (msg_data->cur_thr_idx >= thrp->threads_max)
		return (EINVAL);
	for (; msg_data->cur_thr_idx < thrp->threads_max; msg_data->cur_thr_idx ++) {
		thrpt = &thrp->threads[msg_data->cur_thr_idx];
		if (thrpt == msg_data->thrpt) /* Self. */
			continue;
		msg_data->send_msg_cnt ++;
		if (0 == thrpt_msg_send(thrpt, src, msg_data->flags,
		    thrpt_msg_one_by_one_proxy_cb, msg_data))
			return (0);
		/* Error on send. Allso here EHOSTDOWN from not running threads. */
		msg_data->send_msg_cnt --;
		msg_data->error_cnt ++;
	}
	return (ESPIPE);
}

int
thrpt_msg_bsend_ex(thrp_p thrp, thrpt_p src, uint32_t flags, thrpt_msg_cb msg_cb,
    void *udata, size_t *send_msg_cnt, size_t *error_cnt) {
	int error = 0;
	volatile size_t tm_cnt;
	thrpt_msg_data_p msg_data = NULL;
	thrpt_msg_data_t msg_data_s;

	msg_data_s.send_msg_cnt = 0;
	msg_data_s.error_cnt = 0;
	if (NULL == thrp || NULL == msg_cb ||
	    (1 == thrp->threads_max && 0 != (THRP_BMSG_F_SELF_SKEEP & flags))) {
		error = EINVAL;
		goto err_out;
	}
	if (NULL == src)
		src = thrp_thread_get_current();
	if (0 != (THRP_BMSG_F_SYNC & flags)) {
		/* Setup proxy cb. */
		msg_data = &msg_data_s;
		msg_data->msg_cb = msg_cb;
		msg_data->udata = udata;
		MTX_INIT(&msg_data->lock);
		msg_data->active_thr_count = thrp->threads_max;
		msg_data->cur_thr_idx = 0;
		msg_data->flags = flags;
		//msg_data->send_msg_cnt = 0;
		//msg_data->error_cnt = 0;
		msg_data->thrpt = NULL;
		msg_data->done_cb = NULL;
		msg_cb = thrpt_msg_sync_proxy_cb;
		udata = msg_data;
	}
	
	tm_cnt = thrpt_msg_broadcast_send__int(thrp, src, msg_data, flags,
	    msg_cb, udata, (size_t*)&msg_data_s.send_msg_cnt,
	    (size_t*)&msg_data_s.error_cnt);

	if (NULL != msg_data) { /* THRP_BMSG_F_SYNC: Wait for all. */
		/* Update active threads count and store to tm_cnt. */
		tm_cnt = thrpt_msg_active_thr_count_dec(msg_data, src, tm_cnt);
		while (0 != tm_cnt) {
			if (0 == (THRP_BMSG_F_SYNC_USLEEP & flags)) {
				pthread_yield();
			} else {
				usleep(100000); /* 1 sec = 1000000 microseconds */
			}
			MTX_LOCK(&msg_data->lock);
			tm_cnt = msg_data->active_thr_count;
			MTX_UNLOCK(&msg_data->lock);
		}
		MTX_DESTROY(&msg_data->lock);
	}
	if (0 == msg_data_s.send_msg_cnt)
		error = ESPIPE;
err_out:
	if (NULL != send_msg_cnt)
		(*send_msg_cnt) = msg_data_s.send_msg_cnt;
	if (NULL != error_cnt)
		(*error_cnt) = msg_data_s.error_cnt;
	return (error);
}

int
thrpt_msg_cbsend(thrp_p thrp, thrpt_p src, uint32_t flags, thrpt_msg_cb msg_cb,
    void *udata, thrpt_msg_done_cb done_cb) {
	size_t tm_cnt, send_msg_cnt;
	thrpt_msg_data_p msg_data;

	if (NULL == thrp || NULL == msg_cb || NULL == done_cb ||
	    0 != ((THRP_BMSG_F_SYNC | THRP_BMSG_F_SYNC_USLEEP) & flags))
		return (EINVAL);
	msg_data = malloc(sizeof(thrpt_msg_data_t));
	if (NULL == msg_data)
		return (ENOMEM);
	if (NULL == src)
		src = thrp_thread_get_current();
	msg_data->msg_cb = msg_cb;
	msg_data->udata = udata;
	msg_data->active_thr_count = thrp->threads_max;
	msg_data->cur_thr_idx = 0;
	msg_data->flags = flags;
	msg_data->send_msg_cnt = 0;
	msg_data->error_cnt = 0;
	msg_data->thrpt = src;
	msg_data->done_cb = done_cb;

	if (0 != (THRP_CBMSG_F_ONE_BY_ONE & flags)) {
		if (THRP_MSG_F_SELF_DIRECT ==
		    ((THRP_BMSG_F_SELF_SKEEP | THRP_MSG_F_SELF_DIRECT) & flags)) {
			msg_data->send_msg_cnt ++;
			msg_cb(src, udata);
		}
		if (0 == thrpt_msg_one_by_one_send_next__int(thrp, src, msg_data))
			return (0); /* OK, sheduled. */
		if (THRP_MSG_F_SELF_DIRECT ==
		    ((THRP_BMSG_F_SELF_SKEEP | THRP_MSG_F_SELF_DIRECT) & flags)) {
			done_cb(src, msg_data->send_msg_cnt, msg_data->error_cnt,
			    udata);
			return (0);
		}			
		return (ESPIPE);
	}
	/* Like SYNC but with cb. */
	MTX_INIT(&msg_data->lock);

	tm_cnt = thrpt_msg_broadcast_send__int(thrp, src, msg_data, flags,
	    thrpt_msg_sync_proxy_cb, msg_data, (size_t*)&msg_data->send_msg_cnt,
	    (size_t*)&msg_data->error_cnt);
	if (0 == tm_cnt)
		return (0); /* OK, sheduled. */
	/* Errors. Update active threads count and store to tm_cnt. */
	send_msg_cnt = msg_data->send_msg_cnt; /* Remember before release. */
	tm_cnt = thrpt_msg_active_thr_count_dec(msg_data, src, tm_cnt);
	if (0 == send_msg_cnt)
		return (ESPIPE);
	return (0);
}

void
thrpt_msg_sync_proxy_cb(thrpt_p thrpt, void *udata) {
	thrpt_msg_data_p msg_data = udata;

	msg_data->msg_cb(thrpt, msg_data->udata);
	thrpt_msg_active_thr_count_dec(msg_data, thrpt, 1);
}
void
thrpt_msg_one_by_one_proxy_cb(thrpt_p thrpt, void *udata) {
	thrpt_msg_data_p msg_data = udata;
	
	msg_data->msg_cb(thrpt, msg_data->udata);
	/* Send to next thread. */
	msg_data->cur_thr_idx ++;
	if (0 == thrpt_msg_one_by_one_send_next__int(thrpt->thrp, thrpt, msg_data))
		return;
	/* All except caller thread done / error. */
	if (0 == ((THRP_BMSG_F_SELF_SKEEP | THRP_MSG_F_SELF_DIRECT) & msg_data->flags) &&
	    msg_data->thrpt != thrpt) { /* Try shedule caller thread. */
		msg_data->cur_thr_idx = thrpt->thrp->threads_max;
		msg_data->send_msg_cnt ++;
		if (0 == thrpt_msg_send(msg_data->thrpt, thrpt, msg_data->flags,
		    thrpt_msg_one_by_one_proxy_cb, msg_data))
			return;
		/* Error on send. Allso here EHOSTDOWN from not running threads. */
		msg_data->send_msg_cnt --;
		msg_data->error_cnt ++;
	}
	/* Error / Done. */
	thrpt_msg_send(msg_data->thrpt, thrpt,
	    (THRP_MSG_F_FAIL_DIRECT | THRP_MSG_F_SELF_DIRECT),
	    thrpt_msg_cb_done_proxy_cb, msg_data);
}
void
thrpt_msg_cb_done_proxy_cb(thrpt_p thrpt, void *udata) {
	thrpt_msg_data_p msg_data = udata;

	msg_data->done_cb(thrpt, msg_data->send_msg_cnt, msg_data->error_cnt,
	    msg_data->udata);
	if (0 == (THRP_CBMSG_F_ONE_BY_ONE & msg_data->flags))
		MTX_DESTROY(&msg_data->lock);
	free(msg_data);
}


int
thrpt_ev_add(thrpt_p thrpt, uint16_t event, uint16_t flags, thrp_udata_p udata) {

	if (NULL == udata || NULL == udata->cb_func)
		return (EINVAL);
	udata->thrpt = thrpt;
	return (thrpt_ev_post(THRP_CTL_ADD, event, flags, NULL, udata));
}

int
thrpt_ev_add_ex(thrpt_p thrpt, uint16_t event, uint16_t flags, u_int fflags,
    intptr_t data, thrp_udata_p udata) {
	thrp_event_t ev;

	ev.event = event;
	ev.flags = flags;
	ev.fflags = fflags;
	ev.data = data;
	return (thrpt_ev_add2(thrpt, &ev, udata));
}

int
thrpt_ev_add2(thrpt_p thrpt, thrp_event_p ev, thrp_udata_p udata) {

	if (NULL == ev || NULL == udata || NULL == udata->cb_func)
		return (EINVAL);
	udata->thrpt = thrpt;
	return (thrpt_ev_post(THRP_CTL_ADD, THRP_EV_NONE, 0, ev, udata));
}

int
thrpt_ev_del(uint16_t event, thrp_udata_p udata) {

	//thrpt_ev_q_del(event, udata);
	return (thrpt_ev_post(THRP_CTL_DEL, event, 0, NULL, udata));
}

int
thrpt_ev_enable(int enable, uint16_t event, thrp_udata_p udata) {

	return (thrpt_ev_post(((enable) ? THRP_CTL_ENABLE : THRP_CTL_DISABLE),
	    event, 0, NULL, udata));
}

int
thrpt_ev_enable_ex(int enable, uint16_t event, uint16_t flags, u_int fflags,
    intptr_t data, thrp_udata_p udata) {
	thrp_event_t ev;

	ev.event = event;
	ev.flags = flags;
	ev.fflags = fflags;
	ev.data = data;

	return (thrpt_ev_post(((enable) ? THRP_CTL_ENABLE : THRP_CTL_DISABLE),
	    THRP_EV_NONE, 0, &ev, udata));
}


void
thrpt_cached_time_update_cb(thrp_event_p ev __unused, thrp_udata_p udata) {
	struct timespec *tp;

	tp = (struct timespec*)udata->ident;
	clock_gettime(CORE_THRP_CLOCK_MONOTONIC, &tp[0]);
	clock_gettime(CORE_THRP_CLOCK_REALTIME, &tp[1]);
}

int
thrpt_gettimev(thrpt_p thrpt, int real_time, struct timespec *tp) {

	if (NULL == tp)
		return (EINVAL);
	if (NULL == thrpt ||
	    0 == (THRP_C_F_CACHE_TIME_SYSC & thrpt->thrp->flags)) { /* No caching. */
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
