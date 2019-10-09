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


#ifndef __CORE_LOG_H__
#define __CORE_LOG_H__

#include <sys/types.h>
#include <inttypes.h>



void	log_write_fd(uintptr_t fd, const char *data, size_t data_size);
void	log_write_err_fd(uintptr_t fd, const char *fname, int line, int error,
	    const char *descr);
void	log_write_err_fmt_fd(uintptr_t fd, const char *fname, int line, int error,
	    const char *fmt, ...);
void	log_write_ev_fd(uintptr_t fd, const char *fname, int line, const char *descr);
void	log_write_ev_fmt_fd(uintptr_t fd, const char *fname, int line, const char *fmt, ...);

#define LOG_ERR_FD(fd, error, descr)					\
	    log_write_err_fd(fd, __FUNCTION__, __LINE__, error, descr)
#define LOG_EV_FD(fd, descr)						\
	    log_write_ev_fd(fd, __FUNCTION__, __LINE__, descr)
#define LOG_INFO_FD(fd, descr)						\
	    log_write_ev_fd(fd, NULL, 0, descr)
#define LOG_ERR_FMT_FD(fd, error, fmt, args...)				\
	    log_write_err_fmt_fd(fd, __FUNCTION__, __LINE__, error, fmt, ##args)
#define LOG_EV_FMT_FD(fd, fmt, args...)					\
	    log_write_ev_fmt_fd(fd, __FUNCTION__, __LINE__, fmt, ##args)
#define LOG_INFO_FMT_FD(fd, fmt, args...)				\
	    log_write_ev_fmt_fd(fd, NULL, 0, fmt, ##args)

/* Write to app default log fd. */
extern uintptr_t core_log_fd;

#define log_write(data, data_size)					\
    log_write_fd(core_log_fd, data, data_size)
#define log_write_err(fname, line, error, descr)			\
    log_write_err_fd(core_log_fd, fname, line, error, descr)
#define log_write_err_fmt(fname, line, error, fmt, args...)		\
    log_write_err_fmt_fd(core_log_fd, fname, line, error, fmt, ##args)
#define log_write_ev(fname, line, descr)				\
    log_write_ev_fd(core_log_fd, fname, line, descr)
#define log_write_ev_fmt(fname, line, fmt, args...)			\
    log_write_ev_fmt_fd(core_log_fd, fname, line, fmt, ##args);


#define LOG_IS_ENABLED()	((uintptr_t)-1 != core_log_fd)

#define LOG_ERR(error, descr)						\
	    log_write_err(__FUNCTION__, __LINE__, error, descr)
#define LOG_EV(descr)							\
	    log_write_ev(__FUNCTION__, __LINE__, descr)
#define LOG_INFO(descr)							\
	    log_write_ev(NULL, 0, descr)
#define LOG_ERR_FMT(error, fmt, args...)				\
	    log_write_err_fmt(__FUNCTION__, __LINE__, error, fmt, ##args)
#define LOG_EV_FMT(fmt, args...)					\
	    log_write_ev_fmt(__FUNCTION__, __LINE__, fmt, ##args)
#define LOG_INFO_FMT(fmt, args...)					\
	    log_write_ev_fmt(NULL, 0, fmt, ##args)


#ifdef DEBUG
#	define LOGD_IS_ENABLED	LOG_IS_ENABLED
#	define LOGD_ERR		LOG_ERR
#	define LOGD_EV		LOG_EV
#	define LOGD_INFO	LOG_INFO
#	define LOGD_ERR_FMT	LOG_ERR_FMT
#	define LOGD_EV_FMT	LOG_EV_FMT
#	define LOGD_INFO_FMT	LOG_INFO_FMT
#else
#	define LOGD_IS_ENABLED()	0
#	define LOGD_ERR(error, descr)
#	define LOGD_EV(descr)
#	define LOGD_INFO(descr)
#	define LOGD_ERR_FMT(error, fmt, args...)
#	define LOGD_EV_FMT(fmt, args...)
#	define LOGD_INFO_FMT(fmt, args...)
#endif




#endif /* __CORE_LOG_H__ */
