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


 
#ifndef __CORE_THREAD_POOL_MSG_H__
#define __CORE_THREAD_POOL_MSG_H__

#include <sys/param.h>

#ifdef __linux__ /* Linux specific code. */
#	define _GNU_SOURCE /* See feature_test_macros(7) */
#	define __USE_GNU 1
#endif /* Linux specific code. */

#include <sys/types.h>
#include <inttypes.h>
#include <time.h>


typedef struct thread_pool_thread_msg_queue_s	*thrpt_msg_queue_p;	/* Thread pool thread message queue. */


thrpt_msg_queue_p thrpt_msg_queue_create(thrpt_p thrpt);
void		thrpt_msg_queue_destroy(thrpt_msg_queue_p msg_queue);


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
#define thrpt_msg_bsend(__thrp, __src, __flags, __msg_cb, __udata)	\
	    thrpt_msg_bsend_ex(__thrp, __src, __flags, __msg_cb, __udata, NULL, NULL)
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
#define THRP_MSG_F_SELF_DIRECT	(((uint32_t)1) <<  0) /* Directly call cb func for calling thread. */
#define THRP_MSG_F_FORCE	(((uint32_t)1) <<  1) /* If thread mark as not running - directly call cb func.
					   * WARNING! if thread not running - thrpt will be ignored. */
#define THRP_MSG_F_FAIL_DIRECT	(((uint32_t)1) <<  2) /* Directly call cb func if fail to send. */
#define THRP_MSG_F__ALL__	(THRP_MSG_F_SELF_DIRECT | THRP_MSG_F_FORCE | THRP_MSG_F_FAIL_DIRECT)
/* Broadcast flags. */
#define THRP_BMSG_F_SELF_SKIP	(((uint32_t)1) <<  8) /* Do not send mesg to caller thread. */
#define THRP_BMSG_F_SYNC	(((uint32_t)1) <<  9) /* Wait before all thread process message before return.
						       * WARNING! This deadlock, frizes possible. */
#define THRP_BMSG_F_SYNC_USLEEP	(((uint32_t)1) << 10) /* Wait before all thread process message before return. */
#define THRP_BMSG_F__ALL__	(THRP_BMSG_F_SELF_SKIP | THRP_BMSG_F_SYNC | THRP_BMSG_F_SYNC_USLEEP)
/* Broadcast with result cb. */
#define THRP_CBMSG_F_SELF_SKIP	THRP_BMSG_F_SELF_SKIP
#define THRP_CBMSG_F_ONE_BY_ONE	(((uint32_t)1) << 16) /* Send message to next thread after current thread process message. */
#define THRP_CBMSG__ALL__	(THRP_CBMSG_F_SELF_SKIP | THRP_CBMSG_F_ONE_BY_ONE)


#endif /* __CORE_THREAD_POOL_MSG_H__ */
