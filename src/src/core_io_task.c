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
#include <sys/socket.h>
#endif /* Linux specific code. */

#include <sys/types.h>
#include <sys/uio.h> /* readv, preadv, writev, pwritev */
#include <unistd.h> /* close, write, sysconf */
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <errno.h>

#include "macro_helpers.h"
#include "mem_helpers.h"
#include "core_io_net.h"
#ifdef DEBUG
#	include "core_log.h"
#endif
#include "core_io_task.h"


typedef struct io_task_s {
	thrp_udata_t	thrp_data; /*  */
	thrp_udata_t	thrp_timer; /* Per task timer: ident=pointer to io_task_t. */
	uint16_t	event;	/* Need for cancel io on timeout. */
	uint16_t	event_flags; /* Need for work with timer. */
	uint32_t	flags;	/* read/write / send/recv / recvfrom/sendto */
	uint64_t	timeout;/* IO timeout, 0 = disable. */
	off_t		offset;	/* Read/write offset for io_task_rw_handler() / try_no for connect_ex(). */
	io_buf_p	buf;	/* Buffer to read/write / send/recv / io_task_conn_prms_p for connect_ex(). */
	size_t		tot_transfered_size; /* Total transfered size between calls of cb func / addrs_cur for connect_ex(). */
	struct timespec	start_time; /* Task start time. Used in connect_ex for time_limit work. */
	io_task_cb	cb_func;/* Called after check return IO_TASK_DONE. */
	void		*udata;	/* Passed as arg to check and done funcs. */
	thrpt_p		thrpt;	/* Need for free and enable function */
} io_task_t;



#define TIMESPEC_TO_MS(__ts)						\
    ((((uint64_t)(__ts)->tv_sec) * 1000) + (((uint64_t)(__ts)->tv_nsec) / 1000000))


static void	io_task_handler(int type, thrp_event_p ev,
		    thrp_udata_p thrp_udata, int *cb_code_ret);
#define IO_TASK_H_TYPE_RW	1
#define IO_TASK_H_TYPE_SR	2

static int	io_task_connect_ex_start(io_task_p iotask, int do_connect);


int
io_task_create(thrpt_p thrpt, uintptr_t ident, thrpt_cb thrp_cb_func,
    uint32_t flags, void *udata, io_task_p *iotask_ret) {
	io_task_p iotask;

	if (NULL == thrpt || NULL == thrp_cb_func || NULL == iotask_ret)
		return (EINVAL);
	iotask = zalloc(sizeof(io_task_t));
	if (NULL == iotask)
		return (ENOMEM);
	iotask->thrp_data.cb_func = thrp_cb_func;
	iotask->thrp_data.ident = ident;
	iotask->thrp_timer.cb_func = thrp_cb_func;
	iotask->thrp_timer.ident = (uintptr_t)iotask;
	//iotask->event = event;
	//iotask->event_flags = event_flags;
	iotask->flags = flags;
	//iotask->timeout = timeout;
	//iotask->buf = buf;
	//iotask->tot_transfered_size = 0;
	//iotask->cb_func = cb_func;
	iotask->udata = udata;
	iotask->thrpt = thrpt;

	(*iotask_ret) = iotask;

	return (0);
}

int
io_task_create_start(thrpt_p thrpt, uintptr_t ident, thrpt_cb thrp_cb_func,
    uint32_t flags, uint16_t event, uint16_t event_flags,
    uint64_t timeout, off_t offset, io_buf_p buf, io_task_cb cb_func,
    void *udata, io_task_p *iotask_ret) {
	io_task_p iotask;
	int error;

	if (NULL == iotask_ret)
		return (EINVAL);
	error = io_task_create(thrpt, ident, thrp_cb_func, flags, udata,
	    &iotask);
	if (0 != error)
		return (error);
	error = io_task_start(iotask, event, event_flags, timeout,
	    offset, buf, cb_func);
	if (0 != error) {
		io_task_destroy(iotask);
		iotask = NULL;
	}
	(*iotask_ret) = iotask;
	return (error);
}

void
io_task_destroy(io_task_p iotask) {

	if (NULL == iotask)
		return;
	io_task_stop(iotask);
	if ((uintptr_t)-1 != iotask->thrp_data.ident &&
	    0 != (IO_TASK_F_CLOSE_ON_DESTROY & iotask->flags)) {
		close((int)iotask->thrp_data.ident);
	}
	mem_filld(iotask, sizeof(io_task_t));
	free(iotask);
}


thrpt_p
io_task_thrpt_get(io_task_p iotask) {
	
	if (NULL == iotask)
		return (NULL);
	return (iotask->thrpt);
}

void
io_task_thrpt_set(io_task_p iotask, thrpt_p thrpt) {
	
	if (NULL == iotask && NULL != thrpt)
		return;
	iotask->thrpt = thrpt;
}


uintptr_t
io_task_ident_get(io_task_p iotask) {

	if (NULL == iotask)
		return ((uintptr_t)-1);
	return (iotask->thrp_data.ident);
}

void
io_task_ident_set(io_task_p iotask, uintptr_t ident) {

	if (NULL == iotask)
		return;
	iotask->thrp_data.ident = ident;
}

void
io_task_ident_close(io_task_p iotask) {

	if (NULL == iotask)
		return;
	io_task_stop(iotask);
	if ((uintptr_t)-1 != iotask->thrp_data.ident) {
		close((int)iotask->thrp_data.ident);
		iotask->thrp_data.ident = (uintptr_t)-1;
	}
}


thrpt_cb
io_task_thrp_cb_func_get(io_task_p iotask) {

	if (NULL == iotask)
		return (NULL);
	return (iotask->thrp_data.cb_func);
}

void
io_task_thrp_cb_func_set(io_task_p iotask, thrpt_cb cb_func) {

	if (NULL == iotask || NULL == cb_func)
		return;
	iotask->thrp_data.cb_func = cb_func;
	iotask->thrp_timer.cb_func = cb_func;
}


io_task_cb
io_task_cb_func_get(io_task_p iotask) {

	if (NULL == iotask)
		return (NULL);
	return (iotask->cb_func);
}

void
io_task_cb_func_set(io_task_p iotask, io_task_cb cb_func) {

	if (NULL == iotask || NULL == cb_func)
		return;
	iotask->cb_func = cb_func;
}


void *
io_task_udata_get(io_task_p iotask) {

	if (NULL == iotask)
		return (NULL);
	return (iotask->udata);
}

void
io_task_udata_set(io_task_p iotask, void *udata) {

	if (NULL == iotask)
		return;
	iotask->udata = udata;
}


void
io_task_flags_set(io_task_p iotask, uint32_t flags) {

	if (NULL == iotask)
		return;
	iotask->flags = flags;
}

uint32_t
io_task_flags_add(io_task_p iotask, uint32_t flags) {

	if (NULL == iotask)
		return (0);
	iotask->flags |= flags;
	return (iotask->flags);
}

uint32_t
io_task_flags_del(io_task_p iotask, uint32_t flags) {

	if (NULL == iotask)
		return (0);
	iotask->flags &= ~flags;
	return (iotask->flags);
}

uint32_t
io_task_flags_get(io_task_p iotask) {

	if (NULL == iotask)
		return (0);
	return (iotask->flags);
}


off_t
io_task_offset_get(io_task_p iotask) {

	if (NULL == iotask)
		return (0);
	return (iotask->offset);
}

void
io_task_offset_set(io_task_p iotask, off_t offset) {

	if (NULL == iotask)
		return;
	iotask->offset = offset;
}


uint64_t
io_task_timeout_get(io_task_p iotask) {

	if (NULL == iotask)
		return (0);
	return (iotask->timeout);
}

void
io_task_timeout_set(io_task_p iotask, uint64_t timeout) {

	if (NULL == iotask)
		return;
	iotask->timeout = timeout;
}


io_buf_p
io_task_buf_get(io_task_p iotask) {

	if (NULL == iotask)
		return (NULL);
	return (iotask->buf);
}

void
io_task_buf_set(io_task_p iotask, io_buf_p buf) {

	if (NULL == iotask)
		return;
	iotask->buf = buf;
}

int
io_task_start_ex(int shedule_first_io, io_task_p iotask, uint16_t event,
    uint16_t event_flags, uint64_t timeout, off_t offset, io_buf_p buf,
    io_task_cb cb_func) {
	int type, cb_ret;
	thrp_event_t ev;

	if (NULL == iotask || NULL == cb_func)
		return (EINVAL);
	//iotask->thrp_data.cb_func = io_task_handler;
	//iotask->thrp_data.ident = ident;
	iotask->event = event;
	iotask->event_flags = event_flags;
	//iotask->flags = flags;
	iotask->timeout = timeout;
	iotask->offset = offset;
	iotask->buf = buf;
	iotask->tot_transfered_size = 0;
	iotask->cb_func = cb_func;
	//iotask->udata = udata;
	//iotask->thrpt = thrpt;
	if (0 != shedule_first_io ||
	    NULL == buf) /* buf may point not to io_buf_p.  */
		goto shedule_io;
	if (io_task_sr_handler == iotask->thrp_data.cb_func) {
		type = IO_TASK_H_TYPE_SR;
	} else if (io_task_rw_handler == iotask->thrp_data.cb_func) {
		type = IO_TASK_H_TYPE_RW;
	} else { /* Notify handler does not support skip first IO. */
		goto shedule_io;
	}
	/* Now we shure that buf point to io_buf_p, do additional checks. */
	if (0 == IO_BUF_TR_SIZE_GET(buf))
		goto shedule_io;
	/* Validate buf. */
	if ((buf->offset + IO_BUF_TR_SIZE_GET(buf)) > buf->size)
		return (EINVAL);
	ev.event = event;
	ev.flags = 0;
	ev.fflags = 0;
	ev.data = (uint64_t)IO_BUF_TR_SIZE_GET(buf);

	io_task_handler(type, &ev, &iotask->thrp_data, &cb_ret);
	if (IO_TASK_CB_CONTINUE != cb_ret)
		return (0);
shedule_io:
	/* Handler func may change task! */
	return (io_task_restart(iotask));
}

int
io_task_start(io_task_p iotask, uint16_t event, uint16_t event_flags,
    uint64_t timeout, off_t offset, io_buf_p buf, io_task_cb cb_func) {

	return (io_task_start_ex(1, iotask, event, event_flags, timeout,
	    offset, buf, cb_func));
}

int
io_task_restart(io_task_p iotask) {
	int error;

	if (NULL == iotask || NULL == iotask->cb_func)
		return (EINVAL);
	if (0 != iotask->timeout) { /* Set io timeout timer */
		error = thrpt_ev_add_ex(iotask->thrpt, THRP_EV_TIMER,
		    THRP_F_DISPATCH, 0, iotask->timeout,
		    &iotask->thrp_timer);
		if (0 != error)
			return (error);
	}
	error = thrpt_ev_add(iotask->thrpt, iotask->event,
	    iotask->event_flags, &iotask->thrp_data);
	if (0 != error)	{ /* Error, remove timer. */
		debugd_break();
		thrpt_ev_del(THRP_EV_TIMER, &iotask->thrp_data);
	}
	return (error);
}

void
io_task_stop(io_task_p iotask) {

	if (NULL == iotask)
		return;
	thrpt_ev_del(iotask->event, &iotask->thrp_data);
	if (0 != iotask->timeout) {
		thrpt_ev_del(THRP_EV_TIMER, &iotask->thrp_timer);
	}
}


int
io_task_enable(io_task_p iotask, int enable) {
	int error;

	if (NULL == iotask)
		return (EINVAL);
	if (0 != iotask->timeout) {
		error = thrpt_ev_enable_ex(enable, THRP_EV_TIMER,
		    THRP_F_DISPATCH, 0, iotask->timeout,
		    &iotask->thrp_timer);
		if (0 != error)
			return (error);
	}
	error = thrpt_ev_enable(enable, iotask->event, &iotask->thrp_data);
	if (0 != error) {
		debugd_break();
		thrpt_ev_enable(0, THRP_EV_TIMER, &iotask->thrp_data);
	}
	return (error);
}


static inline int
io_task_handler_pre_int(thrp_event_p ev, thrp_udata_p thrp_udata,
    io_task_p *iotask, uint32_t *eof, size_t *data2transfer_size) {

	(*eof) = ((0 != (THRP_F_EOF & ev->flags)) ? IO_TASK_IOF_F_SYS : 0);
	/* Disable other events. */
	if (THRP_EV_TIMER == ev->event) { /* Timeout! Disable io operation. */
		(*iotask) = (io_task_p)thrp_udata->ident;
		if (0 != (THRP_F_ONESHOT & (*iotask)->event_flags)) {
			io_task_stop((*iotask));
		} else {
			thrpt_ev_enable(0, (*iotask)->event,
			    &(*iotask)->thrp_data);
		}
		(*data2transfer_size) = 0;
		return (ETIMEDOUT);
	}
	(*iotask) = (io_task_p)thrp_udata;
	if (0 != (*iotask)->timeout) { /* Disable/remove timer. */
		if (0 != (THRP_F_ONESHOT & (*iotask)->event_flags)) {
			thrpt_ev_del(THRP_EV_TIMER, &(*iotask)->thrp_timer);
		} else {
			thrpt_ev_enable(0, THRP_EV_TIMER,
			    &(*iotask)->thrp_timer);
		}
	}
	(*data2transfer_size) = (size_t)ev->data;
	if (0 != (THRP_F_ERROR & ev->flags)) /* Some error. */
		return (((int)ev->fflags));
	return (0);
}

static inline void
io_task_handler_post_int(thrp_event_p ev, io_task_p iotask, int cb_ret) {

	if (IO_TASK_CB_CONTINUE != cb_ret)
		return;
	/* io_task_enable() */
	if (0 != iotask->timeout) {
		thrpt_ev_q_enable_ex(1, THRP_EV_TIMER, THRP_F_DISPATCH,
		    0, iotask->timeout, &iotask->thrp_timer);
	}
	if (0 != (iotask->event_flags & THRP_F_DISPATCH) ||
	    THRP_EV_TIMER == ev->event) {
		thrpt_ev_q_enable(1, iotask->event, &iotask->thrp_data);
	}
}


static void
io_task_handler(int type, thrp_event_p ev, thrp_udata_p thrp_udata,
    int *cb_code_ret) {
	io_task_p iotask;
	uintptr_t ident;
	ssize_t ios;
	size_t data2transfer_size, transfered_size = 0;
	int error, cb_ret;
	uint32_t eof;

	debugd_break_if(NULL == ev);
	debugd_break_if(NULL == thrp_udata);

	if (NULL != cb_code_ret) { /* Direct IO call. Skip many checks. */
		error = 0;
		eof = 0;
		iotask = (io_task_p)thrp_udata;
		data2transfer_size = (size_t)ev->data;
	} else {
		error = io_task_handler_pre_int(ev, thrp_udata, &iotask,
		    &eof, &data2transfer_size);
		/* Ignory error if we can transfer data. */
		if (0 == data2transfer_size ||
		    NULL == iotask->buf ||
		    0 == IO_BUF_TR_SIZE_GET(iotask->buf))
			goto call_cb; /* transfered_size = 0 */
		/* Transfer as much as we can. */
		data2transfer_size = min(data2transfer_size,
		    IO_BUF_TR_SIZE_GET(iotask->buf));
	}
	/* IO operations. */
	ident = iotask->thrp_data.ident;
	switch (ev->event) {
	case THRP_EV_READ:
		/* Do IO: read / recv / recvfrom. */
		while (transfered_size < data2transfer_size) { /* transfer loop. */
			if (IO_TASK_H_TYPE_RW == type) {
				ios = pread((int)ident,
				    IO_BUF_OFFSET_GET(iotask->buf),
				    IO_BUF_TR_SIZE_GET(iotask->buf),
				    iotask->offset);
			} else { /* IO_TASK_H_TYPE_SR */
				ios = recv((int)ident,
				    IO_BUF_OFFSET_GET(iotask->buf),
				    IO_BUF_TR_SIZE_GET(iotask->buf),
				    MSG_DONTWAIT);
			}
			/*LOGD_EV_FMT("ev->data = %zu, ios = %zu, "
			    "transfered_size = %zu, eof = %i, err = %i",
			    ev->data, ios, transfered_size, eof, errno);//*/
			if (-1 == ios) /* Error. */
				goto err_out;
			if (0 == ios) { /* All data read. */
				/* Set EOF ONLY if no data read and it is direct call
				 * from io_task_start_ex() or other int func, 
				 * - not from thread pool.
				 * Thread pool set EOF by self and dont need help.
				 */
				 /* Set EOF allways: eof may happen after thread pool
				  * call this callback and before pread/recv done. */
				if (/*NULL != cb_code_ret &&*/
				    0 != IO_BUF_TR_SIZE_GET(iotask->buf)) {
					eof |= IO_TASK_IOF_F_BUF;
				}
				goto call_cb;
			}
			transfered_size += (size_t)ios;
			iotask->offset += (size_t)ios;
			IO_BUF_USED_INC(iotask->buf, (size_t)ios);
			IO_BUF_OFFSET_INC(iotask->buf, (size_t)ios);
			IO_BUF_TR_SIZE_DEC(iotask->buf, (size_t)ios);
			if (0 == IO_BUF_TR_SIZE_GET(iotask->buf) || /* All data read. */
			    0 != (IO_TASK_F_CB_AFTER_EVERY_READ & iotask->flags))
				goto call_cb;
		} /* end while() */
		/* Continue read/recv. */
		/* Linux: never get here: data2transfer_size = UINT64_MAX, so
		 * we go to err_out with errno = EAGAIN */
		iotask->tot_transfered_size += transfered_size; /* Save transfered_size. */
		cb_ret = IO_TASK_CB_CONTINUE;
		goto call_cb_handle;
	case THRP_EV_WRITE:
		/* Do IO: pwrite / send. */
		while (transfered_size < data2transfer_size) { /* transfer loop. */
			if (IO_TASK_H_TYPE_RW == type) {
				ios = pwrite((int)ident,
				    IO_BUF_OFFSET_GET(iotask->buf),
				    IO_BUF_TR_SIZE_GET(iotask->buf),
				    iotask->offset);
			} else { /* IO_TASK_H_TYPE_SR */
				ios = send((int)ident,
				    IO_BUF_OFFSET_GET(iotask->buf),
				    IO_BUF_TR_SIZE_GET(iotask->buf),
				    (MSG_DONTWAIT | MSG_NOSIGNAL));
			}
			if (-1 == ios) /* Error. */
				goto err_out;
			if (0 == ios) /* All data written. */
				goto call_cb;
			transfered_size += (size_t)ios;
			iotask->offset += (size_t)ios;
			IO_BUF_OFFSET_INC(iotask->buf, (size_t)ios);
			IO_BUF_TR_SIZE_DEC(iotask->buf, (size_t)ios);
			if (0 == IO_BUF_TR_SIZE_GET(iotask->buf)) /* All data written. */
				goto call_cb;
		} /* end while() */
		/* Continue write/send at next event. */
		/* Linux: never get here: data2transfer_size = UINT64_MAX, so
		 * we go to err_out with errno = EAGAIN */
		iotask->tot_transfered_size += transfered_size; /* Save transfered_size. */
		cb_ret = IO_TASK_CB_CONTINUE;
		goto call_cb_handle;
	default: /* Unknown filter. */
		debugd_break();
		error = ENOSYS;
		goto call_cb;
	}

err_out: /* Error. */
	error = errno;
	if (0 == error) {
		error = EINVAL;
	}
	error = IO_NET_ERR_FILTER(error);
	if (0 == error) {
		iotask->tot_transfered_size += transfered_size; /* Save transfered_size. */
		cb_ret = IO_TASK_CB_CONTINUE;
		goto call_cb_handle;
	}

call_cb:
	transfered_size += iotask->tot_transfered_size;
	iotask->tot_transfered_size = 0;
	cb_ret = iotask->cb_func(iotask, error, iotask->buf, eof,
	    transfered_size, iotask->udata);

call_cb_handle:
	if (NULL != cb_code_ret) { /* Extrenal handle cb code. */
		(*cb_code_ret) = cb_ret;
		return;
	}
	io_task_handler_post_int(ev, iotask, cb_ret);
}

void
io_task_rw_handler(thrp_event_p ev, thrp_udata_p thrp_udata) {

	io_task_handler(IO_TASK_H_TYPE_RW, ev, thrp_udata, NULL);
}

void
io_task_sr_handler(thrp_event_p ev, thrp_udata_p thrp_udata) {

	io_task_handler(IO_TASK_H_TYPE_SR, ev, thrp_udata, NULL);
}

void
io_task_notify_handler(thrp_event_p ev, thrp_udata_p thrp_udata) {
	io_task_p iotask;
	size_t data2transfer_size;
	int error, cb_ret;
	uint32_t eof;

	debugd_break_if(NULL == ev);
	debugd_break_if(NULL == thrp_udata);

	error = io_task_handler_pre_int(ev, thrp_udata, &iotask, &eof,
	    &data2transfer_size);
	cb_ret = ((io_task_notify_cb)iotask->cb_func)(iotask, error,
	    eof, data2transfer_size, iotask->udata);
	io_task_handler_post_int(ev, iotask, cb_ret);
}

void
io_task_pkt_rcvr_handler(thrp_event_p ev, thrp_udata_p thrp_udata) {
	io_task_p iotask;
	uintptr_t ident;
	ssize_t ios;
	size_t data2transfer_size, transfered_size = 0;
	int error, cb_ret;
	uint32_t eof;
	socklen_t addrlen;
	struct sockaddr_storage ssaddr;

	debugd_break_if(NULL == ev);
	debugd_break_if(NULL == thrp_udata);

	error = io_task_handler_pre_int(ev, thrp_udata, &iotask, &eof,
	    &data2transfer_size);
	if (THRP_EV_WRITE == ev->event) {
		debugd_break();
		error = EINVAL;
	}
	if (0 != error) { /* Report about error. */
call_cb:
		cb_ret = ((io_task_pkt_rcvr_cb)iotask->cb_func)(iotask,
		    error, NULL, iotask->buf, 0, iotask->udata);
		if (IO_TASK_CB_CONTINUE != cb_ret)
			return;
		if (0 == data2transfer_size)
			goto call_cb_handle;
		/* Try to receive data. */
	}

	cb_ret = IO_TASK_CB_CONTINUE;
	ident = iotask->thrp_data.ident;
	while (transfered_size < data2transfer_size) { /* recv loop. */
		addrlen = sizeof(ssaddr);
		ios = recvfrom((int)ident, IO_BUF_OFFSET_GET(iotask->buf),
		    IO_BUF_TR_SIZE_GET(iotask->buf), MSG_DONTWAIT,
		    (struct sockaddr*)&ssaddr, &addrlen);
		if (-1 == ios) { /* Error. */
			error = errno;
			if (0 == error) {
				error = EINVAL;
			}
			error = IO_NET_ERR_FILTER(error);
			if (0 == error) { /* No more data. */
				cb_ret = IO_TASK_CB_CONTINUE;
				goto call_cb_handle;
			}
			goto call_cb; /* Report about error. */
		}
		if (0 == ios)
			break;
		transfered_size += (size_t)ios;
		IO_BUF_USED_INC(iotask->buf, ios);
		IO_BUF_OFFSET_INC(iotask->buf, ios);
		IO_BUF_TR_SIZE_DEC(iotask->buf, ios);

		cb_ret = ((io_task_pkt_rcvr_cb)iotask->cb_func)(iotask,
		    /*error*/ 0, &ssaddr, iotask->buf, (size_t)ios,
		    iotask->udata);
		if (IO_TASK_CB_CONTINUE != cb_ret)
			return;
	} /* end recv while */

call_cb_handle:
	io_task_handler_post_int(ev, iotask, cb_ret);
}

void
io_task_accept_handler(thrp_event_p ev, thrp_udata_p thrp_udata) {
	io_task_p iotask;
	uintptr_t skt;
	int error, cb_ret;
	uint32_t eof = 0;
	size_t i, data2transfer_size;
	socklen_t addrlen;
	struct sockaddr_storage ssaddr;

	debugd_break_if(NULL == ev);
	debugd_break_if(NULL == thrp_udata);

	error = io_task_handler_pre_int(ev, thrp_udata, &iotask, &eof,
	    &data2transfer_size);
	if (THRP_EV_WRITE == ev->event) {
		debugd_break();
		error = EINVAL;
	}
	if (0 != error) { /* Report about error. */
call_cb:
		cb_ret = ((io_task_accept_cb)iotask->cb_func)(iotask,
		    error, (uintptr_t)-1, NULL, iotask->udata);
		goto call_cb_handle;
	}

	cb_ret = IO_TASK_CB_CONTINUE;
	for (i = 0; i < data2transfer_size; i ++) { /* Accept all connections! */
		addrlen = sizeof(ssaddr);
		error = io_net_accept(iotask->thrp_data.ident,
		    &ssaddr, &addrlen, SO_F_NONBLOCK, &skt);
		if (0 != error) { /* Error. */
			error = IO_NET_ERR_FILTER(error);
			if (0 == error) { /* No more new connections. */
				cb_ret = IO_TASK_CB_CONTINUE;
				goto call_cb_handle;
			}
			goto call_cb; /* Report about error. */
		}
		cb_ret = ((io_task_accept_cb)iotask->cb_func)(iotask,
		    /*error*/ 0, skt, &ssaddr, iotask->udata);
		if (IO_TASK_CB_CONTINUE != cb_ret)
			return;
	}

call_cb_handle:
	io_task_handler_post_int(ev, iotask, cb_ret);
}

void
io_task_connect_handler(thrp_event_p ev, thrp_udata_p thrp_udata) {
	io_task_p iotask;
	int error;

	debugd_break_if(NULL == ev);
	debugd_break_if(NULL == thrp_udata);

	if (THRP_EV_TIMER == ev->event) { /* Timeout! */
		iotask = (io_task_p)thrp_udata->ident;
		error = ETIMEDOUT;
	} else {
		debugd_break_if(THRP_EV_WRITE != ev->event);
		iotask = (io_task_p)thrp_udata;
		error = ((THRP_F_ERROR & ev->flags) ? ((int)ev->fflags) : 0); /* Some error? */
	}
	io_task_stop(iotask); /* Call it on write and timeout. */
	((io_task_connect_cb)iotask->cb_func)(iotask, error, iotask->udata);
}


int
io_task_cb_check(io_buf_p buf, uint32_t eof, size_t transfered_size) {

	/* All data transfered! */
	if (NULL != buf &&
	    0 == IO_BUF_TR_SIZE_GET(buf))
		return (IO_TASK_CB_NONE);
	/* Connection closed / end of file. */
	if (0 != eof)
		return (IO_TASK_CB_EOF);
	/* Error may contain error code, or not, let done func handle this. */
	if ((size_t)-1 == transfered_size)
		return (IO_TASK_CB_ERROR);
	/* No free spase in recv buf / EOF */
	if (0 == transfered_size)
		return (IO_TASK_CB_ERROR);

	/* Handle data:
	 * here we can check received data, and decide receive more or process
	 * received in done func but this is generic receiver untill buf full or
	 * connection closed, so continue receive.
	 */
	/* Need transfer more data. */
	return (IO_TASK_CB_CONTINUE);
}


int
io_task_notify_create(thrpt_p thrpt, uintptr_t ident, uint32_t flags,
    uint16_t event, uint64_t timeout, io_task_notify_cb cb_func,
    void *udata, io_task_p *iotask_ret) {
	int error;

	flags &= IO_TASK_F_CLOSE_ON_DESTROY; /* Filter out flags. */
	error = io_task_create_start(thrpt, ident, io_task_notify_handler,
	    flags, event, 0/*THRP_F_DISPATCH*/, timeout, 0, NULL,
	    (io_task_cb)cb_func, udata, iotask_ret);
	return (error);
}

int
io_task_pkt_rcvr_create(thrpt_p thrpt, uintptr_t ident, uint32_t flags,
    uint64_t timeout, io_buf_p buf, io_task_pkt_rcvr_cb cb_func,
    void *udata, io_task_p *iotask_ret) {
	int error;

	flags &= IO_TASK_F_CLOSE_ON_DESTROY; /* Filter out flags. */
	flags |= IO_TASK_F_CB_AFTER_EVERY_READ; /* Add flags. */
	error = io_task_create_start(thrpt, ident, io_task_pkt_rcvr_handler,
	    flags, THRP_EV_READ, 0/*THRP_F_DISPATCH*/, timeout, 0, buf,
	    (io_task_cb)cb_func, udata, iotask_ret);
	return (error);
}

int
io_task_create_accept(thrpt_p thrpt, uintptr_t ident, uint32_t flags,
    uint64_t timeout, io_task_accept_cb cb_func, void *udata,
    io_task_p *iotask_ret) {
	int error;

	flags &= IO_TASK_F_CLOSE_ON_DESTROY; /* Filter out flags. */
	error = io_task_create_start(thrpt, ident, io_task_accept_handler,
	    flags, THRP_EV_READ, 0, timeout, 0, NULL,
	    (io_task_cb)cb_func, udata, iotask_ret);
	return (error);
}

int
io_task_create_connect(thrpt_p thrpt, uintptr_t ident, uint32_t flags,
    uint64_t timeout, io_task_connect_cb cb_func, void *udata,
    io_task_p *iotask_ret) {
	int error;

	flags &= IO_TASK_F_CLOSE_ON_DESTROY; /* Filter out flags. */
	error = io_task_create_start(thrpt, ident, io_task_connect_handler,
	    flags, THRP_EV_WRITE, THRP_F_ONESHOT, timeout, 0, NULL,
	    (io_task_cb)cb_func, udata, iotask_ret);
	return (error);
}

int
io_task_create_connect_send(thrpt_p thrpt, uintptr_t ident,
    uint32_t flags, uint64_t timeout, io_buf_p buf, io_task_cb cb_func,
    void *udata, io_task_p *iotask_ret) {
	int error;

	flags &= IO_TASK_F_CLOSE_ON_DESTROY; /* Filter out flags. */
	error = io_task_create_start(thrpt, ident, io_task_sr_handler,
	    flags, THRP_EV_WRITE, 0, timeout, 0, buf, cb_func, udata,
	    iotask_ret);
	return (error);
}






void
io_task_connect_ex_handler(thrp_event_p ev, thrp_udata_p thrp_udata) {
	int error, cb_ret;
	io_task_p iotask;

	debugd_break_if(NULL == ev);
	debugd_break_if(NULL == thrp_udata);

	if (THRP_EV_TIMER == ev->event) { /* Timeout / retry delay! */
		iotask = (io_task_p)thrp_udata->ident;
		if ((uintptr_t)-1 == iotask->thrp_data.ident) { /* Retry delay. */
			// XXX io_task_stop()?
			error = 0;
			goto connect_ex_start;
		}
		error = ETIMEDOUT; /* Timeout */
	} else {
		debugd_break_if(THRP_EV_WRITE != ev->event);
		iotask = (io_task_p)thrp_udata;
		error = ((THRP_F_ERROR & ev->flags) ? ((int)ev->fflags) : 0); /* Some error? */
	}
	io_task_stop(iotask);

	if (0 == error) { /* Connected: last report. */
		((io_task_connect_ex_cb)iotask->cb_func)(iotask, error,
		    (io_task_conn_prms_p)iotask->buf,
		    iotask->tot_transfered_size, iotask->udata);
		return; /* Done with this task. */
	}
	/* Error, retry. */
	close((int)iotask->thrp_data.ident);
	iotask->thrp_data.ident = (uintptr_t)-1;
	for (;;) {
		/* Report about fail to connect. */
		if (-1 == error || /* Can not continue, always report! */
		    0 != (IO_TASK_F_CB_AFTER_EVERY_READ & iotask->flags)) {
			cb_ret = ((io_task_connect_ex_cb)iotask->cb_func)(iotask,
			    error, (io_task_conn_prms_p)iotask->buf,
			    iotask->tot_transfered_size, iotask->udata);
			if (-1 == error ||
			    IO_TASK_CB_CONTINUE != cb_ret)
				return; /* Can not continue... */
		}
		if (0 == ((io_task_conn_prms_p)iotask->buf)->max_tries || /* Force: IO_TASK_CONNECT_F_ROUND_ROBIN */
		    0 != (((io_task_conn_prms_p)iotask->buf)->flags & IO_TASK_CONNECT_F_ROUND_ROBIN)) {
			iotask->tot_transfered_size ++; /* Move to next addr. */
		} else {
			iotask->offset ++; /* One more try connect to addr. */
		}
connect_ex_start:
		error = io_task_connect_ex_start(iotask, (0 == error));
		if (0 == error)
			return; /* Connect retry sheduled. */
		/* Fail / no more time/retries, report to cb. */
	}
}

static int
io_task_connect_ex_start(io_task_p iotask, int do_connect) {
	int error;
	uint64_t time_limit_ms = 0, time_run_ms;
	struct timespec	time_now;
	io_task_conn_prms_p conn_prms;

	if (NULL == iotask)
		return (EINVAL);
	conn_prms = (io_task_conn_prms_p)iotask->buf;
	if (0 != do_connect)
		goto try_connect;
	/* Check connect time limit / do initial delay. */
	if (0 == iotask->offset &&
	    0 == iotask->tot_transfered_size) { /* First connect attempt. */
		if (0 != (conn_prms->flags & IO_TASK_CONNECT_F_INITIAL_DELAY) &&
		    0 != conn_prms->retry_delay)
			goto shedule_delay_timer;
	} else {
		if (0 != conn_prms->time_limit.tv_sec ||
		    0 != conn_prms->time_limit.tv_nsec) { /* time limit checks. */
			thrpt_gettimev(iotask->thrpt, 0, &time_now);
			time_run_ms = (TIMESPEC_TO_MS(&time_now) -
			    TIMESPEC_TO_MS(&iotask->start_time)); /* Task run time. */
			time_limit_ms = TIMESPEC_TO_MS(&conn_prms->time_limit);
			if (time_limit_ms <= time_run_ms)
				return (-1); /* No more tries. */
			time_limit_ms -= time_run_ms; /* Time to end task. */
		}

		/* Check addr index and retry limit. */
		if (0 == conn_prms->max_tries || /* Force: IO_TASK_CONNECT_F_ROUND_ROBIN */
		    0 != (conn_prms->flags & IO_TASK_CONNECT_F_ROUND_ROBIN)) {
			if (iotask->tot_transfered_size >= conn_prms->addrs_count) {
				iotask->tot_transfered_size = 0;
				iotask->offset ++;
				if (0 != conn_prms->max_tries &&
				    (uint64_t)iotask->offset >= conn_prms->max_tries)
					return (-1); /* No more rounds/tries. */
				/* Delay between rounds. */
				if (0 != conn_prms->retry_delay)
					goto shedule_delay_timer;
			}
		} else {
			if ((uint64_t)iotask->offset >= conn_prms->max_tries) {
				iotask->tot_transfered_size ++;
				iotask->offset = 0;
				if (iotask->tot_transfered_size >= conn_prms->addrs_count)
					return (-1); /* No more tries. */
			}
			/* Delay before next connect attempt. */
			if (0 != conn_prms->retry_delay)
				goto shedule_delay_timer;
		}
	}

try_connect:
	/* Create socket, try to connect, start IO task with created socket. */
	error = io_net_connect(&conn_prms->addrs[iotask->tot_transfered_size],
	    conn_prms->type, conn_prms->protocol,
	    SO_F_NONBLOCK, &iotask->thrp_data.ident);
	if (0 != error) { /* Cant create socket. */
		iotask->thrp_data.ident = (uintptr_t)-1;
		return (error);
	}
	error = io_task_start(iotask, THRP_EV_WRITE,
	    THRP_F_ONESHOT, iotask->timeout, iotask->offset,
	    iotask->buf, iotask->cb_func);
	if (0 != error) {
		close((int)iotask->thrp_data.ident);
		iotask->thrp_data.ident = (uintptr_t)-1;
	}
	return (error);

shedule_delay_timer:
	/* Shedule delay timer. */
	if (0 != time_limit_ms &&
	    conn_prms->retry_delay >= time_limit_ms)
		return (-1); /* No more tries. */
	error = thrpt_ev_add_ex(iotask->thrpt, THRP_EV_TIMER,
	    THRP_F_DISPATCH, 0, conn_prms->retry_delay,
	    &iotask->thrp_timer);
	return (error);
}

int
io_task_create_connect_ex(thrpt_p thrpt, uint32_t flags,
    uint64_t timeout, io_task_conn_prms_p conn_prms,
    io_task_connect_ex_cb cb_func, void *udata, io_task_p *iotask_ret) {
	int error;
	uint64_t time_limit_ms = 0;
	io_task_p iotask;

	if (NULL == conn_prms || NULL == iotask_ret)
		return (EINVAL);
	if (0 != (conn_prms->flags & IO_TASK_CONNECT_F_INITIAL_DELAY) &&
	    0 == conn_prms->retry_delay)
		return (EINVAL);
	if (0 != conn_prms->time_limit.tv_sec ||
	    0 != conn_prms->time_limit.tv_nsec) {
		time_limit_ms = TIMESPEC_TO_MS(&conn_prms->time_limit);
		if (0 == timeout ||
		    timeout >= time_limit_ms)
			return (EINVAL);
		if (conn_prms->retry_delay >= time_limit_ms)
			return (EINVAL);
	}
	flags &= (IO_TASK_F_CLOSE_ON_DESTROY | IO_TASK_F_CB_AFTER_EVERY_READ); /* Filter out flags. */
	error = io_task_create(thrpt, (uintptr_t)-1,
	    io_task_connect_ex_handler, flags, udata, &iotask);
	if (0 != error)
		return (error);
	/* Set internal task values. */
	iotask->timeout = timeout;
	//iotask->offset = 0; /* try_no */
	iotask->buf = (io_buf_p)conn_prms;
	//iotask->tot_transfered_size = 0; /* addrs_cur */
	iotask->cb_func = (io_task_cb)cb_func;
	if (0 != time_limit_ms) {
		thrpt_gettimev(thrpt, 0, &iotask->start_time);
	}

	/* Try to shedule IO for connect. */
	for (;;) {
		error = io_task_connect_ex_start(iotask, 0);
		if (0 == error ||
		    -1 == error)
			break; /* OK / Error - can not continue. */
		if (0 == conn_prms->max_tries || /* Force: IO_TASK_CONNECT_F_ROUND_ROBIN */
		    0 != (conn_prms->flags & IO_TASK_CONNECT_F_ROUND_ROBIN)) {
			iotask->tot_transfered_size ++; /* Move to next addr. */
		} else {
			iotask->offset ++; /* One more try connect to addr. */
		}
	}
	if (0 != error) {
		io_task_destroy(iotask);
		iotask = NULL;
	}
	(*iotask_ret) = iotask;
	return (error);
}

