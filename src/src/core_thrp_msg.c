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

#include <sys/fcntl.h> /* open, fcntl */
#include <inttypes.h>
#include <stdlib.h> /* malloc, exit */
#include <unistd.h> /* close, write, sysconf */
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <errno.h>
#include <pthread.h>

#include "macro_helpers.h"
#include "mem_helpers.h"
#include "core_log.h"
#include "core_thrp.h"
#include "core_thrp_msg.h"



typedef struct thread_pool_thread_msg_queue_s { /* thread pool thread info */
	thrp_udata_t	udata;
	int		fd[2]; /* Queue specific. */
} thrpt_msg_queue_t;


typedef struct thrpt_msg_pkt_s { /* thread message packet data. */
	size_t		magic;
	thrpt_msg_cb	msg_cb;
	void		*udata;
	size_t		chk_sum;
} thrpt_msg_pkt_t, *thrpt_msg_pkt_p;

#define THRPT_MSG_PKT_MAGIC	0xffddaa00
#define THRPT_MSG_COUNT_TO_READ	1024 /* Read messages count at one read() call. */

#define THRPT_MSG_PKT_CHK_SUM_SET(msg_pkt)				\
    (msg_pkt)->chk_sum = (((size_t)(msg_pkt)->msg_cb) ^ ((size_t)(msg_pkt)->udata))
#define THRPT_MSG_PKT_IS_VALID(msg_pkt)					\
    (THRPT_MSG_PKT_MAGIC == (msg_pkt)->magic &&				\
     (((size_t)(msg_pkt)->msg_cb) ^ ((size_t)(msg_pkt)->udata)) == (msg_pkt)->chk_sum)


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


size_t	thrpt_msg_broadcast_send__int(thrp_p thrp, thrpt_p src,
	    thrpt_msg_data_p msg_data, uint32_t flags, thrpt_msg_cb msg_cb,
	    void *udata, volatile size_t *send_msg_cnt,
	    volatile size_t *error_cnt);
int	thrpt_msg_one_by_one_send_next__int(thrp_p thrp, thrpt_p src,
	    thrpt_msg_data_p msg_data);



static void
thrpt_msg_recv_and_process(thrp_event_p ev, thrp_udata_p thrp_udata) {
	ssize_t rd;
	size_t magic = THRPT_MSG_PKT_MAGIC, i, cnt, readed;
	thrpt_msg_pkt_t msg[THRPT_MSG_COUNT_TO_READ], tmsg;
	uint8_t *ptm, *pend;

	debugd_break_if(NULL == ev);
	debugd_break_if(THRP_EV_READ != ev->event);
	debugd_break_if(NULL == thrp_udata);
	debugd_break_if((uintptr_t)((thrpt_msg_queue_p)thrp_udata)->fd[0] != thrp_udata->ident);

	for (;;) {
		rd = read((int)thrp_udata->ident, &msg, sizeof(msg));
		if (((ssize_t)sizeof(thrpt_msg_pkt_t)) > rd)
			return; /* -1, 0, < sizeof(thrpt_msg_pkt_t) */
		readed = (size_t)rd;
		cnt = (readed / sizeof(thrpt_msg_pkt_t));
		for (i = 0; i < cnt; i ++) { /* Process loop. */
			if (0 == THRPT_MSG_PKT_IS_VALID(&msg[i])) { /* Try recover. */
				LOG_EV("thrpt_msg_pkt_t damaged!!!");
				debugd_break();
				ptm = ((uint8_t*)&msg[i]);
				pend = (((uint8_t*)&msg) + readed);
				for (;;) {
					ptm = mem_find_ptr(ptm, &msg, readed,
					    &magic, sizeof(size_t));
					if (NULL == ptm)
						return; /* No more messages. */
					i = (size_t)(pend - ptm); /* Unprocessed messages size. */
					if (sizeof(thrpt_msg_pkt_t) > i)
						return; /* Founded to small, no more messages. */
					memcpy(&tmsg, ptm, sizeof(thrpt_msg_pkt_t)); /* Avoid allign missmatch. */
					if (0 == THRPT_MSG_PKT_IS_VALID(&tmsg)) { /* Bad msg, try find next. */
						ptm += sizeof(size_t);
						continue;
					}
					/* Looks OK, fix and restart. */
					readed = i;
					cnt = (readed / sizeof(thrpt_msg_pkt_t));
					i = 0;
					memmove(&msg, ptm, readed);
					break;
				}
			}
			if (NULL == msg[i].msg_cb)
				continue;
			msg[i].msg_cb(thrp_udata->thrpt, msg[i].udata);
		}
		if (sizeof(msg) > readed) /* All data read. */
			return; /* OK. */
	}
}


static void
thrpt_msg_cb_done_proxy_cb(thrpt_p thrpt, void *udata) {
	thrpt_msg_data_p msg_data = udata;

	msg_data->done_cb(thrpt, msg_data->send_msg_cnt,
	    msg_data->error_cnt, msg_data->udata);
	if (0 == (THRP_CBMSG_F_ONE_BY_ONE & msg_data->flags)) {
		MTX_DESTROY(&msg_data->lock);
	}
	free(msg_data);
}

static inline size_t
thrpt_msg_active_thr_count_dec(thrpt_msg_data_p msg_data, thrpt_p src,
    size_t dec) {
	size_t tm;

	/* Additional data handling. */
	MTX_LOCK(&msg_data->lock);
	msg_data->active_thr_count -= dec;
	tm = msg_data->active_thr_count;
	MTX_UNLOCK(&msg_data->lock);

	if (0 != tm ||
	    NULL == msg_data->done_cb)
		return (tm); /* There is other alive threads. */
	/* This was last thread, so we need do call back done handler. */
	thrpt_msg_send(msg_data->thrpt, src,
	    (THRP_MSG_F_FAIL_DIRECT | THRP_MSG_F_SELF_DIRECT),
	    thrpt_msg_cb_done_proxy_cb, msg_data);
	return (tm);
}

static void
thrpt_msg_sync_proxy_cb(thrpt_p thrpt, void *udata) {
	thrpt_msg_data_p msg_data = udata;

	msg_data->msg_cb(thrpt, msg_data->udata);
	thrpt_msg_active_thr_count_dec(msg_data, thrpt, 1);
}

static void
thrpt_msg_one_by_one_proxy_cb(thrpt_p thrpt, void *udata) {
	thrpt_msg_data_p msg_data = udata;

	msg_data->msg_cb(thrpt, msg_data->udata);
	/* Send to next thread. */
	msg_data->cur_thr_idx ++;
	if (0 == thrpt_msg_one_by_one_send_next__int(thrpt_get_thrp(thrpt), thrpt, msg_data))
		return;
	/* All except caller thread done / error. */
	if (0 == ((THRP_BMSG_F_SELF_SKIP | THRP_MSG_F_SELF_DIRECT) & msg_data->flags) &&
	    msg_data->thrpt != thrpt) { /* Try shedule caller thread. */
		msg_data->cur_thr_idx = thrp_thread_count_max_get(thrpt_get_thrp(thrpt));
		msg_data->send_msg_cnt ++;
		if (0 == thrpt_msg_send(msg_data->thrpt, thrpt,
		    msg_data->flags, thrpt_msg_one_by_one_proxy_cb,
		    msg_data))
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



thrpt_msg_queue_p
thrpt_msg_queue_create(thrpt_p thrpt) { /* Init threads message exchange. */
	int error;
	thrpt_msg_queue_p msg_queue;

	msg_queue = zalloc(sizeof(thrpt_msg_queue_t));
	if (NULL == msg_queue)
		return (NULL);
	if (-1 == pipe2(msg_queue->fd, O_NONBLOCK))
		goto err_out;
	msg_queue->udata.cb_func = thrpt_msg_recv_and_process;
	msg_queue->udata.ident = (uintptr_t)msg_queue->fd[0];
	error = thrpt_ev_add(thrpt, THRP_EV_READ, 0, &msg_queue->udata);
	if (0 == error)
		return (msg_queue);
err_out:
	free(msg_queue);
	return (NULL);
}

void
thrpt_msg_queue_destroy(thrpt_msg_queue_p msg_queue) {

	if (NULL == msg_queue)
		return;
	close(msg_queue->fd[0]);
	close(msg_queue->fd[1]);
}

	
int
thrpt_msg_send(thrpt_p dst, thrpt_p src, uint32_t flags,
    thrpt_msg_cb msg_cb, void *udata) {
	thrpt_msg_pkt_t msg;
	thrpt_msg_queue_p msg_queue;

	if (NULL == dst || NULL == msg_cb)
		return (EINVAL);
	msg_queue = thrpt_get_msg_queue(dst);
	if (NULL == msg_queue)
		return (EINVAL);
	if (0 != (THRP_MSG_F_SELF_DIRECT & flags)) {
		if (NULL == src) {
			src = thrp_thread_get_current();
		}
		if (src == dst) { /* Self. */
			msg_cb(dst, udata);
			return (0);
		}
	}
	if (0 == thrpt_is_running(dst)) {
		if (0 == (THRP_MSG_F_FORCE & flags))
			return (EHOSTDOWN);
		msg_cb(dst, udata);
		return (0);
	}

	msg.magic = THRPT_MSG_PKT_MAGIC;
	msg.msg_cb = msg_cb;
	msg.udata = udata;
	THRPT_MSG_PKT_CHK_SUM_SET(&msg);
	if (sizeof(msg) == write(msg_queue->fd[1], &msg, sizeof(msg)))
		return (0);
	/* Error. */
	debugd_break();
	if (0 != (THRP_MSG_F_FAIL_DIRECT & flags)) {
		msg_cb(dst, udata);
		return (0);
	}
	return (errno);
}


size_t
thrpt_msg_broadcast_send__int(thrp_p thrp, thrpt_p src,
    thrpt_msg_data_p msg_data, uint32_t flags,
    thrpt_msg_cb msg_cb, void *udata,
    volatile size_t *send_msg_cnt, volatile size_t *error_cnt) {
	size_t i, threads_max, err_cnt = 0;
	thrpt_p thrpt;

	if (NULL != msg_data &&
	    NULL != src &&
	    0 != (THRP_BMSG_F_SELF_SKIP & flags)) {
		msg_data->active_thr_count --;
	}
	(*send_msg_cnt) = 0;
	(*error_cnt) = 0;
	threads_max = thrp_thread_count_max_get(thrp);
	for (i = 0; i < threads_max; i ++) { /* Send message loop. */
		thrpt = thrp_thread_get(thrp, i);
		if (thrpt == src && /* Self. */
		    0 != (THRP_BMSG_F_SELF_SKIP & flags)) {
			/* No need to "active_thr_count --" here:
			 * SELF_SKIP allready done,
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
thrpt_msg_bsend_ex(thrp_p thrp, thrpt_p src, uint32_t flags,
    thrpt_msg_cb msg_cb, void *udata,
    size_t *send_msg_cnt, size_t *error_cnt) {
	int error = 0;
	volatile size_t tm_cnt;
	size_t threads_max;
	thrpt_msg_data_p msg_data = NULL;
	thrpt_msg_data_t msg_data_s;
	struct timespec rqtp;

	msg_data_s.send_msg_cnt = 0;
	msg_data_s.error_cnt = 0;
	threads_max = thrp_thread_count_max_get(thrp);
	if (NULL == thrp || NULL == msg_cb) {
		error = EINVAL;
		goto err_out;
	}
	if (NULL == src) {
		src = thrp_thread_get_current();
	}
	/* 1 thread specific. */
	if (1 == threads_max &&
	    NULL != src) { /* Only if thread send broadcast to self. */
		if (0 != (THRP_BMSG_F_SELF_SKIP & flags))
			goto err_out; /* Nothink to do. */
		if (0 == (THRP_BMSG_F_SYNC & flags)) {
			error = thrpt_msg_send(thrp_thread_get(thrp, 0), src, flags, msg_cb, udata);
			if (0 == error) {
				msg_data_s.send_msg_cnt ++;
			}
		} else { /* Cant async call from self. */
			msg_cb(src, udata);
		}
		goto err_out; /* Sended / error on send. */
	}
	/* Multithread. */
	if (0 != (THRP_BMSG_F_SYNC & flags)) {
		/* Setup proxy cb. */
		msg_data = &msg_data_s;
		msg_data->msg_cb = msg_cb;
		msg_data->udata = udata;
		MTX_INIT(&msg_data->lock);
		msg_data->active_thr_count = threads_max;
		msg_data->cur_thr_idx = 0;
		msg_data->flags = flags;
		//msg_data->send_msg_cnt = 0;
		//msg_data->error_cnt = 0;
		msg_data->thrpt = NULL;
		msg_data->done_cb = NULL;
		msg_cb = thrpt_msg_sync_proxy_cb;
		udata = msg_data;
	}

	tm_cnt = thrpt_msg_broadcast_send__int(thrp, src, msg_data,
	    flags, msg_cb, udata, &msg_data_s.send_msg_cnt,
	    &msg_data_s.error_cnt);

	if (NULL != msg_data) { /* THRP_BMSG_F_SYNC: Wait for all. */
		/* Update active threads count and store to tm_cnt. */
		rqtp.tv_sec = 0;
		rqtp.tv_nsec = 10000000; /* 1 sec = 1000000000 nanoseconds */
		tm_cnt = thrpt_msg_active_thr_count_dec(msg_data, src, tm_cnt);
		while (0 != tm_cnt) {
			if (0 == (THRP_BMSG_F_SYNC_USLEEP & flags)) {
				pthread_yield();
			} else {
				nanosleep(&rqtp, NULL);
			}
			MTX_LOCK(&msg_data->lock);
			tm_cnt = msg_data->active_thr_count;
			MTX_UNLOCK(&msg_data->lock);
		}
		MTX_DESTROY(&msg_data->lock);
	}
	if (0 == msg_data_s.send_msg_cnt) {
		error = ESPIPE;
	}
err_out:
	if (NULL != send_msg_cnt) {
		(*send_msg_cnt) = msg_data_s.send_msg_cnt;
	}
	if (NULL != error_cnt) {
		(*error_cnt) = msg_data_s.error_cnt;
	}
	return (error);
}


int
thrpt_msg_one_by_one_send_next__int(thrp_p thrp, thrpt_p src,
    thrpt_msg_data_p msg_data) {
	thrpt_p thrpt;
	size_t threads_max;

	threads_max = thrp_thread_count_max_get(thrp);
	if (msg_data->cur_thr_idx >= threads_max)
		return (EINVAL);
	for (; msg_data->cur_thr_idx < threads_max; msg_data->cur_thr_idx ++) {
		thrpt = thrp_thread_get(thrp, msg_data->cur_thr_idx);
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
thrpt_msg_cbsend(thrp_p thrp, thrpt_p src, uint32_t flags,
    thrpt_msg_cb msg_cb, void *udata, thrpt_msg_done_cb done_cb) {
	size_t tm_cnt, send_msg_cnt, threads_max;
	thrpt_msg_data_p msg_data;


	if (NULL == thrp || NULL == msg_cb || NULL == done_cb ||
	    0 != ((THRP_BMSG_F_SYNC | THRP_BMSG_F_SYNC_USLEEP) & flags))
		return (EINVAL);
	if (NULL == src) {
		src = thrp_thread_get_current();
	}
	if (NULL == src) /* Cant do final callback. */
		return (EINVAL);
	threads_max = thrp_thread_count_max_get(thrp);
	/* 1 thread specific. */
	if (1 == threads_max &&
	    NULL != src) { /* Only if thread send broadcast to self. */
		if (0 != (THRP_BMSG_F_SELF_SKIP & flags)) {
			done_cb(src, 0, 0, udata); /* Nothink to do. */
		} else { /* Cant async call from self. */
			msg_cb(src, udata);
			done_cb(src, 1, 0, udata);
		}
		return (0); /* Sended / error on send. */
	}
	msg_data = malloc(sizeof(thrpt_msg_data_t));
	if (NULL == msg_data)
		return (ENOMEM);
	msg_data->msg_cb = msg_cb;
	msg_data->udata = udata;
	msg_data->active_thr_count = threads_max;
	msg_data->cur_thr_idx = 0;
	msg_data->flags = flags;
	msg_data->send_msg_cnt = 0;
	msg_data->error_cnt = 0;
	msg_data->thrpt = src;
	msg_data->done_cb = done_cb;

	if (0 != (THRP_CBMSG_F_ONE_BY_ONE & flags)) {
		if (THRP_MSG_F_SELF_DIRECT == ((THRP_BMSG_F_SELF_SKIP | THRP_MSG_F_SELF_DIRECT) & flags)) {
			msg_data->send_msg_cnt ++;
			msg_cb(src, udata);
		}
		if (0 == thrpt_msg_one_by_one_send_next__int(thrp, src, msg_data))
			return (0); /* OK, sheduled. */
		if (THRP_MSG_F_SELF_DIRECT == ((THRP_BMSG_F_SELF_SKIP | THRP_MSG_F_SELF_DIRECT) & flags)) {
			done_cb(src, msg_data->send_msg_cnt,
			    msg_data->error_cnt, udata);
			return (0);
		}
		return (ESPIPE);
	}
	/* Like SYNC but with cb. */
	MTX_INIT(&msg_data->lock);

	tm_cnt = thrpt_msg_broadcast_send__int(thrp, src, msg_data, flags,
	    thrpt_msg_sync_proxy_cb, msg_data, &msg_data->send_msg_cnt,
	    &msg_data->error_cnt);
	if (0 == tm_cnt)
		return (0); /* OK, sheduled. */
	/* Errors. Update active threads count and store to tm_cnt. */
	send_msg_cnt = msg_data->send_msg_cnt; /* Remember before release. */
	tm_cnt = thrpt_msg_active_thr_count_dec(msg_data, src, tm_cnt);
	if (0 == send_msg_cnt)
		return (ESPIPE);
	return (0);
}

