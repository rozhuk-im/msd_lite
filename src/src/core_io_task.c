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
#include <sys/socket.h>
#endif /* Linux specific code. */

#include <sys/types.h>
#include <sys/uio.h> /* readv, preadv, writev, pwritev */
#include <unistd.h> /* close, write, sysconf */
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <errno.h>

#include "core_macro.h"
#include "core_net_helpers.h"
#ifdef DEBUG
#include "core_log.h"
#endif
#include "core_io_task.h"


typedef struct io_task_s {
	thrp_udata_t	thrp_data; /*  */
	thrp_udata_t	thrp_timer; /* Per task timer: ident=pointer to io_task_t. */
	uint16_t	event;	/* Need for cancel io on timeout. */
	uint16_t	event_flags; /* Need for work with timer. */
	uint32_t	flags;	/* read/write / send/recv / recvfrom/sendto */
	uintptr_t	timeout;/* IO timeout, 0 = disable. */
	off_t		offset; /* Read/write offset for io_task_rw_handler(). */
	io_buf_p	buf;	/* Buffer to read/write / send/recv. */
	size_t		tot_transfered_size; /* Total transfered size between calls of cb func. */
	io_task_cb	cb_func;/* Called after check return IO_TASK_DONE. */
	void		*udata;	/* Passed as arg to check and done funcs. */
	thrpt_p		thrpt;	/* Need for free and enable function */
} io_task_t;



static void	io_task_handler(int type, thrp_event_p ev, thrp_udata_p udata,
		    int *cb_code_ret);
#define IO_TASK_H_TYPE_RW	1
#define IO_TASK_H_TYPE_SR	2


int
io_task_create(thrpt_p thrpt, uintptr_t ident, thrpt_cb thrp_cb_func, uint32_t flags,
    void *arg, io_task_p *iotask_ret) {
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
	iotask->udata = arg;
	iotask->thrpt = thrpt;
	
	(*iotask_ret) = iotask;

	return (0);
}

int
io_task_create_start(thrpt_p thrpt, uintptr_t ident, thrpt_cb thrp_cb_func,
    uint32_t flags, uint16_t event, uint16_t event_flags, uintptr_t timeout,
    off_t offset, io_buf_p buf, io_task_cb cb_func, void *arg, io_task_p *iotask_ret) {
	io_task_p iotask;
	int error;

	error = io_task_create(thrpt, ident, thrp_cb_func, flags, arg, &iotask);
	if (0 != error)
		return (error);
	error = io_task_start(iotask, event, event_flags, timeout, offset, buf, cb_func);
	if (0 != error) {
		io_task_destroy(iotask);
	} else {
		(*iotask_ret) = iotask;
	}
	return (error);
}

void
io_task_destroy(io_task_p iotask) {

	if (NULL == iotask)
		return;
	io_task_stop(iotask);
	if ((uintptr_t)-1 != iotask->thrp_data.ident &&
	    0 != (IO_TASK_F_CLOSE_ON_DESTROY & iotask->flags)) {
		close(iotask->thrp_data.ident);
	}
	memfilld(iotask, sizeof(io_task_t));
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
	
	if (NULL == iotask)
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

	if (NULL == iotask || (uintptr_t)-1 == iotask->thrp_data.ident)
		return;
	close(iotask->thrp_data.ident);
	iotask->thrp_data.ident = -1;
	if (0 != iotask->timeout)
		thrpt_ev_del(THRP_EV_TIMER, &iotask->thrp_timer);
}

void
io_task_thrp_cb_func_set(io_task_p iotask, thrpt_cb cb_func) {

	if (NULL == iotask || NULL == cb_func)
		return;
	iotask->thrp_data.cb_func = cb_func;
	iotask->thrp_timer.cb_func = cb_func;
}

void
io_task_cb_func_set(io_task_p iotask, io_task_cb cb_func) {

	if (NULL == iotask || NULL == cb_func)
		return;
	iotask->cb_func = cb_func;
}

void *
io_task_arg_get(io_task_p iotask) {

	if (NULL == iotask)
		return (NULL);
	return (iotask->udata);
}

void
io_task_arg_set(io_task_p iotask, void *arg) {

	if (NULL == iotask)
		return;
	iotask->udata = arg;
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
io_task_start_ex(int sfio, io_task_p iotask, uint16_t event, uint16_t event_flags,
    uintptr_t timeout, off_t offset, io_buf_p buf, io_task_cb cb_func) {
	int type, cb_ret;
	thrp_event_t ev;

	if (NULL == iotask || NULL == cb_func)
		return (EINVAL);
	if (NULL != buf) { /* Validate. */
		if ((buf->offset + IO_BUF_TR_SIZE_GET(buf)) > buf->size)
			return (EINVAL);
	}
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
	//iotask->udata = arg;
	//iotask->thrpt = thrpt;
	if (0 != sfio || NULL == buf || 0 == IO_BUF_TR_SIZE_GET(buf))
		goto shedule_io;
	if (io_task_sr_handler == iotask->thrp_data.cb_func)
		type = IO_TASK_H_TYPE_SR;
	else if (io_task_rw_handler == iotask->thrp_data.cb_func)
		type = IO_TASK_H_TYPE_RW;
	else /* Unsupported notify handler. */
		goto shedule_io;
	ev.event = event;
	ev.flags = 0;
	ev.fflags = 0;
	ev.data = IO_BUF_TR_SIZE_GET(buf);

	io_task_handler(type, &ev, &iotask->thrp_data, &cb_ret);
	if (IO_TASK_CB_CONTINUE != cb_ret)
		return (0);
shedule_io:
	/* Handler func may change task! */
	return (io_task_restart(iotask));
}

int
io_task_start(io_task_p iotask, uint16_t event, uint16_t event_flags,
    uintptr_t timeout, off_t offset, io_buf_p buf, io_task_cb cb_func) {

	return (io_task_start_ex(1, iotask, event, event_flags, timeout, offset, buf,
	    cb_func));
}

int
io_task_restart(io_task_p iotask) {
	int error;

	if (NULL == iotask || NULL == iotask->cb_func)
		return (EINVAL);
	if (0 != iotask->timeout) { /* Set io timeout timer */
		error = thrpt_ev_add_ex(iotask->thrpt, THRP_EV_TIMER, THRP_F_DISPATCH,
		    0, iotask->timeout, &iotask->thrp_timer);
		if (0 != error)
			return (error);
	}
	error = thrpt_ev_add(iotask->thrpt, iotask->event, iotask->event_flags,
	    &iotask->thrp_data);
	if (0 != error)	/* Error, remove timer. */
		thrpt_ev_del(THRP_EV_TIMER, &iotask->thrp_data);
	return (error);
}

void
io_task_stop(io_task_p iotask) {

	if (NULL == iotask)
		return;
	thrpt_ev_del(iotask->event, &iotask->thrp_data);
	if (0 != iotask->timeout)
		thrpt_ev_del(THRP_EV_TIMER, &iotask->thrp_timer);
}


int
io_task_enable(io_task_p iotask, int enable) {
	int error;

	if (NULL == iotask)
		return (EINVAL);
	if (0 != iotask->timeout) {
		error = thrpt_ev_enable_ex(enable, THRP_EV_TIMER, THRP_F_DISPATCH,
		    0, iotask->timeout, &iotask->thrp_timer);
		if (0 != error)
			return (error);
	}
	error = thrpt_ev_enable(enable, iotask->event, &iotask->thrp_data);
	if (0 != error)
		thrpt_ev_enable(0, THRP_EV_TIMER, &iotask->thrp_data);
	return (error);
}


static inline int
io_task_handler_pre_int(thrp_event_p ev, thrp_udata_p udata,
    io_task_p *iotask, int *eof, size_t *data2transfer_size) {

	(*eof) = ((0 != (THRP_F_EOF & ev->flags)) ? IO_TASK_IOF_F_SYS : 0);
	/* Disable other events. */
	if (THRP_EV_TIMER == ev->event) { /* Timeout! Disable io operation. */
		(*iotask) = (io_task_p)udata->ident;
		if (THRP_F_ONESHOT & (*iotask)->event_flags) {
			io_task_stop((*iotask));
		} else {
			thrpt_ev_enable(0, (*iotask)->event, &(*iotask)->thrp_data);
		}
		(*data2transfer_size) = 0;
		return (ETIMEDOUT);
	}
	(*iotask) = (io_task_p)udata;
	if (0 != (*iotask)->timeout) { /* Disable/remove timer.  */
		if (THRP_F_ONESHOT & (*iotask)->event_flags) {
			thrpt_ev_del(THRP_EV_TIMER, &(*iotask)->thrp_timer);
		} else {
			thrpt_ev_enable(0, THRP_EV_TIMER, &(*iotask)->thrp_timer);
		}
	}
	(*data2transfer_size) = ev->data;
	if (THRP_F_ERROR & ev->flags) /* Some error. */
		return (ev->fflags);
	return (0);
}

static inline void
io_task_handler_post_int(thrp_event_p ev, io_task_p iotask, int cb_ret) {

	if (IO_TASK_CB_CONTINUE != cb_ret)
		return;
	/* io_task_enable() */
	if (0 != iotask->timeout)
		thrpt_ev_q_enable_ex(1, THRP_EV_TIMER, THRP_F_DISPATCH, 0,
		    iotask->timeout, &iotask->thrp_timer);
	if (0 != (iotask->event_flags & THRP_F_DISPATCH) ||
	    THRP_EV_TIMER == ev->event)
		thrpt_ev_q_enable(1, iotask->event, &iotask->thrp_data);
}


static void
io_task_handler(int type, thrp_event_p ev, thrp_udata_p udata, int *cb_code_ret) {
	io_task_p iotask;
	uintptr_t ident;
	ssize_t ios;
	size_t data2transfer_size, transfered_size = 0;
	int error, cb_ret, eof;

	if (NULL != cb_code_ret) { /* Direct IO call. Skeep many checks. */
		error = 0;
		eof = 0;
		iotask = (io_task_p)udata;
		data2transfer_size = ev->data;
	} else {
		error = io_task_handler_pre_int(ev, udata, &iotask, &eof,
		    &data2transfer_size);
		/* Ignory error if we can transfer data. */
		if (/*0 != error ||*/ 0 == data2transfer_size || NULL == iotask->buf ||
		    0 == IO_BUF_TR_SIZE_GET(iotask->buf))
			goto call_cb; /* transfered_size = 0 */
		/* Transfer as much as we can. */
		data2transfer_size = min(data2transfer_size, IO_BUF_TR_SIZE_GET(iotask->buf));
	}
	/* IO operations. */
	ident = iotask->thrp_data.ident;
	switch (ev->event) {
	case THRP_EV_READ:
		/* Do IO: read / recv / recvfrom. */
		while (transfered_size < data2transfer_size) { /* transfer loop. */
			if (IO_TASK_H_TYPE_RW == type) {
				ios = pread(ident, IO_BUF_OFFSET_GET(iotask->buf),
				    IO_BUF_TR_SIZE_GET(iotask->buf), iotask->offset);
			} else { /* IO_TASK_H_TYPE_SR */
				ios = recv(ident, IO_BUF_OFFSET_GET(iotask->buf),
				    IO_BUF_TR_SIZE_GET(iotask->buf), MSG_DONTWAIT);
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
				    0 != IO_BUF_TR_SIZE_GET(iotask->buf))
					eof |= IO_TASK_IOF_F_BUF;
				goto call_cb;
			}
			transfered_size += ios;
			iotask->offset += ios;
			IO_BUF_USED_INC(iotask->buf, ios);
			IO_BUF_OFFSET_INC(iotask->buf, ios);
			IO_BUF_TR_SIZE_DEC(iotask->buf, ios);
			if (0 == IO_BUF_TR_SIZE_GET(iotask->buf) || /* All data read. */
			    0 != (IO_TASK_F_CB_AFTER_EVERY_READ & iotask->flags))
				goto call_cb;
		} /* end while() */
		/* Continue read/recv. */
		/* Linux: never get here: data2transfer_size = INTPTR_MAX, so
		 * we go to err_out with errno = EAGAIN */
		iotask->tot_transfered_size += transfered_size; /* Save transfered_size. */
		cb_ret = IO_TASK_CB_CONTINUE;
		goto call_cb_handle;
		break;
	case THRP_EV_WRITE:
		/* Do IO: pwrite / send. */
		while (transfered_size < data2transfer_size) { /* transfer loop. */
			if (IO_TASK_H_TYPE_RW == type) {
				ios = pwrite(ident, IO_BUF_OFFSET_GET(iotask->buf),
				    IO_BUF_TR_SIZE_GET(iotask->buf), iotask->offset);
			} else { /* IO_TASK_H_TYPE_SR */
				ios = send(ident, IO_BUF_OFFSET_GET(iotask->buf),
				    IO_BUF_TR_SIZE_GET(iotask->buf),
				    (MSG_DONTWAIT | MSG_NOSIGNAL));
			}
			if (-1 == ios) /* Error. */
				goto err_out;
			if (0 == ios) /* All data written. */
				goto call_cb;
			transfered_size += ios;
			iotask->offset += ios;
			IO_BUF_OFFSET_INC(iotask->buf, ios);
			IO_BUF_TR_SIZE_DEC(iotask->buf, ios);
			if (0 == IO_BUF_TR_SIZE_GET(iotask->buf)) /* All data written. */
				goto call_cb;
		} /* end while() */
		/* Continue write/send at next event. */
		/* Linux: never get here: data2transfer_size = INTPTR_MAX, so
		 * we go to err_out with errno = EAGAIN */
		iotask->tot_transfered_size += transfered_size; /* Save transfered_size. */
		cb_ret = IO_TASK_CB_CONTINUE;
		goto call_cb_handle;
		break;
	default: /* Unknown filter. */
		error = ENOSYS;
		goto call_cb;
		break;
	}

err_out: /* Error. */
	error = errno;
	if (0 == error)
		error = EINVAL;
	error = NET_IO_ERR_FILTER(error);
	if (0 == error) {
		iotask->tot_transfered_size += transfered_size; /* Save transfered_size. */
		cb_ret = IO_TASK_CB_CONTINUE;
		goto call_cb_handle;
	}

call_cb:
	transfered_size += iotask->tot_transfered_size;
	iotask->tot_transfered_size = 0;
	cb_ret = iotask->cb_func(iotask, error, iotask->buf, eof, transfered_size,
	    iotask->udata);

call_cb_handle:
	if (NULL != cb_code_ret) { /* Extrenal handle cb code. */
		(*cb_code_ret) = cb_ret;
		return;
	}
	io_task_handler_post_int(ev, iotask, cb_ret);
}

void
io_task_rw_handler(thrp_event_p ev, thrp_udata_p udata) {

	io_task_handler(IO_TASK_H_TYPE_RW, ev, udata, NULL);
}

void
io_task_sr_handler(thrp_event_p ev, thrp_udata_p udata) {

	io_task_handler(IO_TASK_H_TYPE_SR, ev, udata, NULL);
}

void
io_task_notify_handler(thrp_event_p ev, thrp_udata_p udata) {
	io_task_p iotask;
	size_t data2transfer_size;
	int error, cb_ret, eof;

	error = io_task_handler_pre_int(ev, udata, &iotask, &eof, &data2transfer_size);
	cb_ret = ((io_task_notify_cb)iotask->cb_func)(iotask, error, eof,
	    data2transfer_size, iotask->udata);
	io_task_handler_post_int(ev, iotask, cb_ret);
}

void
io_task_pkt_rcvr_handler(thrp_event_p ev, thrp_udata_p udata) {
	io_task_p iotask;
	uintptr_t ident;
	ssize_t ios;
	size_t data2transfer_size, transfered_size = 0;
	int error, cb_ret;
	socklen_t addrlen;
	struct sockaddr_storage ssaddr;

	error = io_task_handler_pre_int(ev, udata, &iotask, &cb_ret, &data2transfer_size);
	if (THRP_EV_READ != ev->event)
		error = EINVAL;
	if (0 != error) { /* Report about error. */
call_cb:
		cb_ret = ((io_task_pkt_rcvr_cb)iotask->cb_func)(iotask, error,
		    NULL, iotask->buf, 0, iotask->udata);
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
		ios = recvfrom(ident, IO_BUF_OFFSET_GET(iotask->buf),
		    IO_BUF_TR_SIZE_GET(iotask->buf), MSG_DONTWAIT,
		    (struct sockaddr*)&ssaddr, &addrlen);
		if (-1 == ios) { /* Error. */
			error = errno;
			if (0 == error)
				error = EINVAL;
			error = NET_IO_ERR_FILTER(error);
			if (0 == error) { /* No more data. */
				cb_ret = IO_TASK_CB_CONTINUE;
				goto call_cb_handle;
			}
			goto call_cb; /* Report about error. */
		}
		if (0 == ios)
			break;
		transfered_size += ios;
		IO_BUF_USED_INC(iotask->buf, ios);
		IO_BUF_OFFSET_INC(iotask->buf, ios);
		IO_BUF_TR_SIZE_DEC(iotask->buf, ios);

		cb_ret = ((io_task_pkt_rcvr_cb)iotask->cb_func)(iotask, /*error*/ 0,
		    &ssaddr, iotask->buf, (size_t)ios, iotask->udata);
		if (IO_TASK_CB_CONTINUE != cb_ret)
			return;
	} /* end recv while */

call_cb_handle:
	io_task_handler_post_int(ev, iotask, cb_ret);
}

void
io_task_connect_handler(thrp_event_p ev, thrp_udata_p udata) {
	io_task_p iotask;
	int error;

	if (THRP_EV_TIMER == ev->event) { /* Timeout! */
		iotask = (io_task_p)udata->ident;
		error = ETIMEDOUT;
	} else {
		iotask = (io_task_p)udata;
		error = ((THRP_F_ERROR & ev->flags) ? ev->data : 0); /* Some error? */
	}
	//if (THRP_EV_WRITE != ev->event) // XXX
	io_task_stop(iotask); /* Call it on write and timeout. */
	((io_task_connect_cb)iotask->cb_func)(iotask, error, iotask->udata);
}

void
io_task_accept_handler(thrp_event_p ev, thrp_udata_p udata) {
	io_task_p iotask;
	uintptr_t skt;
	int error, cb_ret;
	size_t i, data2transfer_size;
	socklen_t addrlen;
	struct sockaddr_storage ssaddr;

	error = io_task_handler_pre_int(ev, udata, &iotask, &cb_ret, &data2transfer_size);
	if (THRP_EV_READ != ev->event)
		error = EINVAL;
	if (0 != error) { /* Report about error. */
call_cb:
		cb_ret = ((io_task_accept_cb)iotask->cb_func)(iotask, error, -1,
		    NULL, iotask->udata);
		goto call_cb_handle;
	}

	cb_ret = IO_TASK_CB_CONTINUE;
	for (i = 0; i < data2transfer_size; i ++) { /* Accept all connections! */
		addrlen = sizeof(ssaddr);
#ifdef SOCK_NONBLOCK /* Linux */
		/*
		 * On Linux, the new socket returned by accept() does not
		 * inherit file status flags such as O_NONBLOCK and O_ASYNC
		 * from the listening socket.
		 */
		skt = accept4(iotask->thrp_data.ident, (struct sockaddr*)&ssaddr,
		    &addrlen, SOCK_NONBLOCK);
#else /* Standart / BSD */
		skt = accept(iotask->thrp_data.ident, (struct sockaddr*)&ssaddr,
		     &addrlen);
#endif
		if ((uintptr_t)-1 == skt) { /* Error. */
			error = errno;
			if (0 == error)
				error = EINVAL;
			error = NET_IO_ERR_FILTER(error);
			if (0 == error) { /* No more new connections. */
				cb_ret = IO_TASK_CB_CONTINUE;
				goto call_cb_handle;
			}
			goto call_cb; /* Report about error. */
		}
#ifdef SO_NOSIGPIPE
		cb_ret = 1;
		setsockopt(skt, SOL_SOCKET, SO_NOSIGPIPE, &cb_ret, sizeof(int));
#endif
		cb_ret = ((io_task_accept_cb)iotask->cb_func)(iotask, /*error*/ 0,
		    skt, &ssaddr, iotask->udata);
		if (IO_TASK_CB_CONTINUE != cb_ret)
			return;
	}

call_cb_handle:
	io_task_handler_post_int(ev, iotask, cb_ret);
}


int
io_task_cb_check(io_buf_p buf, int eof, size_t transfered_size) {

	/* All data transfered! */
	if (NULL != buf && 0 == IO_BUF_TR_SIZE_GET(buf))
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
io_task_notify_create(thrpt_p thrpt, uintptr_t ident, uint32_t flags, uint16_t event,
    uintptr_t timeout, io_task_notify_cb cb_func, void *arg,
    io_task_p *iotask_ret) {
	int error;

	flags &= IO_TASK_F_CLOSE_ON_DESTROY; /* Filter out flags. */
	error = io_task_create_start(thrpt, ident, io_task_notify_handler, flags,
	    event, 0/*THRP_F_DISPATCH*/, timeout, 0, NULL, (io_task_cb)cb_func, arg,
	    iotask_ret);
	return (error);
}

int
io_task_pkt_rcvr_create(thrpt_p thrpt, uintptr_t ident, uint32_t flags,
    uintptr_t timeout, io_buf_p buf, io_task_pkt_rcvr_cb cb_func, void *arg,
    io_task_p *iotask_ret) {
	int error;

	flags &= IO_TASK_F_CLOSE_ON_DESTROY; /* Filter out flags. */
	flags |= IO_TASK_F_CB_AFTER_EVERY_READ; /* Add flags. */
	error = io_task_create_start(thrpt, ident, io_task_pkt_rcvr_handler, flags,
	    THRP_EV_READ, 0/*THRP_F_DISPATCH*/, timeout, 0, buf, (io_task_cb)cb_func,
	    arg, iotask_ret);
	return (error);
}

int
io_task_create_accept(thrpt_p thrpt, uintptr_t ident, uint32_t flags, uintptr_t timeout,
    io_task_accept_cb cb_func, void *arg, io_task_p *iotask_ret) {
	int error;

	flags &= IO_TASK_F_CLOSE_ON_DESTROY; /* Filter out flags. */
	error = io_task_create_start(thrpt, ident, io_task_accept_handler, flags,
	    THRP_EV_READ, 0, timeout, 0, NULL, (io_task_cb)cb_func, arg, iotask_ret);
	return (error);
}

int
io_task_create_connect(thrpt_p thrpt, uintptr_t ident, uint32_t flags, uintptr_t timeout,
    io_task_connect_cb cb_func, void *arg, io_task_p *iotask_ret) {
	int error;

	flags &= IO_TASK_F_CLOSE_ON_DESTROY; /* Filter out flags. */
	error = io_task_create_start(thrpt, ident, io_task_connect_handler, flags,
	    THRP_EV_WRITE, THRP_F_ONESHOT, timeout, 0, NULL,
	    (io_task_cb)cb_func, arg, iotask_ret);
	return (error);
}

int
io_task_create_connect_send(thrpt_p thrpt, uintptr_t ident, uint32_t flags,
    uintptr_t timeout,io_buf_p buf, io_task_cb cb_func, void *arg,
    io_task_p *iotask_ret) {
	int error;

	flags &= IO_TASK_F_CLOSE_ON_DESTROY; /* Filter out flags. */
	error = io_task_create_start(thrpt, ident, io_task_sr_handler, flags,
	    THRP_EV_WRITE, 0, timeout, 0, buf, cb_func, arg, iotask_ret);
	return (error);
}
