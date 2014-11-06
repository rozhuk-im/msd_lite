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


 
#ifndef __CORE_IO_BASE_H__
#define __CORE_IO_BASE_H__


#include <sys/param.h>

#ifdef __linux__ /* Linux specific code. */
#define _GNU_SOURCE /* See feature_test_macros(7) */
#define __USE_GNU 1
#endif /* Linux specific code. */

#include <sys/types.h>
#include <sys/socket.h>

#include "core_thrp.h"
#include "core_io_buf.h"



typedef struct io_task_s *io_task_p;
/* io_task flags: */
#define IO_TASK_F_CLOSE_ON_DESTROY	(1 << 0) /* Call close(ident) in io_task_destroy() */
#define IO_TASK_F_CB_AFTER_EVERY_READ	(1 << 1) /* Call cb_func after each read/recv. 
					* Allways set for IO_TASK_TYPE_SOCK_DGRAM with
					* IO_TASK_F_CB_TYPE_DEFAULT
					*/

/* Replace 'io_buf_p' for send_file(). */
/* TODO: write 
 * - io_task_sendfile_handler();
 * - io_task_create_sendfile();
 * - io_task_sendfile_cb().
 */
typedef struct io_task_sf_s { /* send_file */
	/*int fd; - send data from io_task.ident */
	/*off_t offset; - io_task.offset  */
	int s; /* Socket to send data. */
	size_t nbytes; /* Number of bytes to send. */
#ifdef BSD /* BSD specific code. */
	struct sf_hdtr hdtr; /* XXX: use writev/sendmsg in linux? */
	off_t sbytes;
	int flags;
#endif /* BSD specific code. */
} io_task_sf_t, *io_task_sf_p;


/* Internal thrpt_cb thrp.data.cb funtions handlers: */

void	io_task_rw_handler(thrp_event_p ev, thrp_udata_p udata);
/* read() / write() from/to buf. */
/* cb func type: io_task_cb */

void	io_task_sr_handler(thrp_event_p ev, thrp_udata_p udata);
/* send() / recv() from/to buf. */
/* cb func type: io_task_cb */

void	io_task_notify_handler(thrp_event_p ev, thrp_udata_p udata);
/* Only notify cb function about IO ready for descriptor. */
/* cb func type: io_task_notify_cb */

void	io_task_pkt_rcvr_handler(thrp_event_p ev, thrp_udata_p udata);
/* recvfrom() to buf. */
/* cb func type: io_task_pkt_rcvr_cb */

void	io_task_connect_handler(thrp_event_p ev, thrp_udata_p udata);
/* Call io_task_stop() and notify cb function then descriptor ready to write. */
/* cb func type: io_task_connect_cb */

void	io_task_accept_handler(thrp_event_p ev, thrp_udata_p udata);
/* Notify cb function on new connection received, pass new socket and perr addr. */
/* cb func type: io_task_accept_cb */


/* Call back functions return codes: */
#define IO_TASK_CB_ERROR	-1 /* error, call done func with error code */
#define IO_TASK_CB_NONE		0 /* Do nothink / All done, call done func, error = 0. */
#define IO_TASK_CB_EOF		1 /* end of file / conn close / half closed: other side call shutdown(, SHUT_WR) */
#define IO_TASK_CB_CONTINUE	2 /* recv/read / send/write - reshedule task
				* eg call io_task_enable().
				* should not retun if THRP_F_ONESHOT event_flags is set
				*/
/* Return IO_TASK_CB_CONTINUE to continue recv/rechedule io. 
 * All other return codes stop callback untill io_task_enable(1) is called
 * if THRP_F_DISPATCH flag was set.
 * THRP_F_DISPATCH = auto disable task before callback. ie manual mode.
 * If event flag THRP_F_DISPATCH not set in io_task_start(event_flags) then you must
 * call io_task_stop() / io_task_enable(0) / io_task_ident_close() / io_task_destroy()
 * before return code other than IO_TASK_CB_CONTINUE.
 */


#define IO_TASK_IOF_F_SYS	(1 << 0) /* System return EOF. */
#define IO_TASK_IOF_F_BUF	(1 << 1) /* All data in task buf transfered. Only for read/recv. */

/* Call back function types. */
typedef int (*io_task_cb)(io_task_p iotask, int error, io_buf_p buf, int eof,
    size_t transfered_size, void *arg);
/* Transfer data to/from buf and then call back. */

typedef int (*io_task_pkt_rcvr_cb)(io_task_p iotask, int error,
    struct sockaddr_storage *addr, io_buf_p buf, size_t transfered_size, void *arg);
/* Designed for receive datagramms. If IO_TASK_F_CB_AFTER_EVERY_READ not set
 * then packets data will store in singe buffer, and thet call cb function
 * with peer addr from last received packet. */

typedef int (*io_task_notify_cb)(io_task_p iotask, int error, int eof,
    size_t data2transfer_size, void *arg);
/* Notify call back function: ident ready for data transfer. */

typedef int (*io_task_connect_cb)(io_task_p iotask, int error, void *arg);
/* Callback then connection to remonte host established.
 * Handler call io_task_stop() before io_task_connect_cb call.
 * Use in case you need connect and receive data.
 * For connect and send use io_task_sr_handler() + io_task_cb() for write. */
/* IO_TASK_CB_CONTINUE return code - ignored. */

typedef int (*io_task_accept_cb)(io_task_p iotask, int error, uintptr_t skt_new,
    struct sockaddr_storage *addr, void *arg);
/* Callback then new connection received. */



/* Create io task and set some data. */
int	io_task_create(thrpt_p thrpt, uintptr_t ident, thrpt_cb thrp_cb_func,
	    uint32_t flags, void *arg, io_task_p *iotask_ret);
/* thrpt - Thread pool thread pointer
 * ident - socket/file descriptor
 * thrp_cb_func - io_task_XXX_handler(...) - internal io task handler function
 * flags - io task flags: IO_TASK_F_*
 * arg - associated user data, passed to cb_func()
 * iotask_ret - pointer to return created iotask.
 */
/* io_task_create() + io_task_start() */
int	io_task_create_start(thrpt_p thrpt, uintptr_t ident, thrpt_cb thrp_cb_func,
	    uint32_t flags, uint16_t event, uint16_t event_flags, uintptr_t timeout,
	    off_t offset, io_buf_p buf, io_task_cb cb_func, void *arg,
	    io_task_p *iotask_ret);
/* Call io_task_stop(); optional: close(ident). */
void	io_task_destroy(io_task_p iotask);


/* Set some vars in io_task_s and shedule io for 'ident'. */
int	io_task_start_ex(int sfio, io_task_p iotask, uint16_t event,
	    uint16_t event_flags, uintptr_t timeout, off_t offset, io_buf_p buf,
	    io_task_cb cb_func);
int	io_task_start(io_task_p iotask, uint16_t event, uint16_t event_flags,
	    uintptr_t timeout, off_t offset, io_buf_p buf, io_task_cb cb_func);
/*
 * sfio - shedule first io, set 0 if you want do first recv/send/read/write without
 *  sheduling via kqueue/epoll.
 *  Need to receive data after accept() + accept_filter callback: we know that data
 *  allready received, but not shure that all data/full request.
 * iotask - point to io task.
 * event - THRP_EV_*.
 * event_flags - THRP_F_*, see thrpt_ev_add()
 * timeout - time out for io in ms (1 second = 1000 ms).
 * buf - pointer to io_buf for read/write
 *  buf->offset + buf->transfer_size <= buf->size
 *  If buf is null then io_task_cb() called every time.
 * cb_func - call back function: io_task_cb, io_task_XXX_cb, see 'Call back function types'.
 */

int	io_task_restart(io_task_p iotask);
/* Same as io_task_start(), but without any params, can be used after io_task_stop(). */

/* Remove shedule io for 'ident'. */
void	io_task_stop(io_task_p iotask);

/* Enable/disable io for 'ident'. */
int	io_task_enable(io_task_p iotask, int enable);


/* Set/get some vars in io_task_s. */
/* Call io_task_stop() before set!!!  */
thrpt_p	io_task_thrpt_get(io_task_p iotask);
void	io_task_thrpt_set(io_task_p iotask, thrpt_p thrpt);

uintptr_t io_task_ident_get(io_task_p iotask);
void	io_task_ident_set(io_task_p iotask, uintptr_t ident);
/* Call io_task_stop() before! */

void	io_task_ident_close(io_task_p iotask);
/* io_task_stop(); close(ident); ident = -1 */

void	io_task_thrp_cb_func_set(io_task_p iotask, thrpt_cb cb_func);
/* Set io_task_XXX_handler(...) - internal io task handler function. */

void	io_task_cb_func_set(io_task_p iotask, io_task_cb cb_func);

void	*io_task_arg_get(io_task_p iotask);
void	io_task_arg_set(io_task_p iotask, void *arg);

/* Task flag IO_TASK_F_* manipulation. */
void	io_task_flags_set(io_task_p iotask, uint32_t flags);
uint32_t io_task_flags_add(io_task_p iotask, uint32_t flags);
uint32_t io_task_flags_del(io_task_p iotask, uint32_t flags);
uint32_t io_task_flags_get(io_task_p iotask);

off_t	io_task_offset_get(io_task_p iotask);
void	io_task_offset_set(io_task_p iotask, off_t offset);

io_buf_p io_task_buf_get(io_task_p iotask);
void	io_task_buf_set(io_task_p iotask, io_buf_p buf);


// Generic (defailt build-in) check functions for recv and send
// will receive until connection open and some free space in buf
int	io_task_cb_check(io_buf_p buf, int eof, size_t transfered_size);


/* Creates notifier for read/write ready. */
int	io_task_notify_create(thrpt_p thrpt, uintptr_t ident, uint32_t flags,
	    uint16_t event, uintptr_t timeout, io_task_notify_cb cb_func, void *arg,
	    io_task_p *iotask_ret);
/* Creates packet receiver. */
int	io_task_pkt_rcvr_create(thrpt_p thrpt, uintptr_t ident, uint32_t flags,
	    uintptr_t timeout, io_buf_p buf, io_task_pkt_rcvr_cb cb_func, void *arg,
	    io_task_p *iotask_ret);
/* Valid flags: IO_TASK_F_CB_AFTER_EVERY_READ */
/* Call io_task_destroy() then no needed. */


int	io_task_create_accept(thrpt_p thrpt, uintptr_t ident, uint32_t flags,
	    uintptr_t timeout, io_task_accept_cb cb_func, void *arg,
	    io_task_p *iotask_ret);
/* Valid flags: IO_TASK_F_CLOSE_ON_DESTROY */



int	io_task_create_connect(thrpt_p thrpt, uintptr_t ident, uint32_t flags,
	    uintptr_t timeout, io_task_connect_cb cb_func, void *arg,
	    io_task_p *iotask_ret);

int	io_task_create_connect_send(thrpt_p thrpt, uintptr_t ident, uint32_t flags,
	    uintptr_t timeout, io_buf_p buf, io_task_cb cb_func, void *arg,
	    io_task_p *iotask_ret);
/* timeout - for connect, then for send (write) data. */




#endif // __CORE_IO_BASE_H__
