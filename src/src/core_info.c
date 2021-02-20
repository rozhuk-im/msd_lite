/*-
 * Copyright (c) 2013 - 2014 Rozhuk Ivan <rozhuk.im@gmail.com>
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
#include <sys/time.h> /* For getrusage. */
#include <sys/resource.h>
#include <sys/sysctl.h>

#include <inttypes.h>
#include <stdlib.h> /* malloc, exit */
#include <stdio.h> /* snprintf, fprintf */
#include <unistd.h> /* close, write, sysconf */
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <time.h>
#include <errno.h>

#include "mem_find.h"

#include "core_helpers.h"
#include "core_info.h"



int
sysctl_str_to_buf(int *mib, u_int mib_cnt, const char *descr, size_t descr_size,
    uint8_t *buf, size_t buf_size, size_t *buf_size_ret) {
	size_t tm;

	if (descr_size >= buf_size)
		return (EINVAL);
	tm = (buf_size - descr_size);
	if (0 != sysctl(mib, mib_cnt, (buf + descr_size), &tm, NULL, 0)) {
#ifdef BSD /* BSD specific code. */
		return (errno);
#endif /* BSD specific code. */
#ifdef __linux__ /* Linux specific code. */
		/* If sysctl not implemented or fail try read from: /proc/sys */
		int error;
		const char *l1, *l2;
		char path[1024];
		size_t path_size;

		if (2 != mib_cnt)
			return (EINVAL);
		switch (mib[0]) {
		case CTL_KERN:
			l1 = "kernel";
			break;
		default:
			return (EINVAL);
		}

		switch (mib[1]) {
		case KERN_OSTYPE:
			l2 = "ostype";
			break;
		case KERN_OSRELEASE:
			l2 = "osrelease";
			break;
		case KERN_NODENAME:
			l2 = "hostname";
			break;
		case KERN_DOMAINNAME:
			l2 = "domainname";
			break;
		case KERN_VERSION:
			l2 = "version";
			break;
		default:
			return (EINVAL);
		}

		path_size = snprintf(path, sizeof(path), "/proc/sys/%s/%s", l1, l2);
		error = read_file_buf(path, path_size, (buf + descr_size), tm, &tm);
		if (0 != error)
			return (error);
#endif /* Linux specific code. */
	}
	memcpy(buf, descr, descr_size);
	/* Remove CR, LF, TAB, SP, NUL from end */
	tm += descr_size;
	while (descr_size < tm && (
	    '\r' == buf[(tm - 1)] ||
	    '\n' == buf[(tm - 1)] ||
	    '\t' == buf[(tm - 1)] ||
	    ' ' == buf[(tm - 1)] ||
	    0 == buf[(tm - 1)]))
		tm --;
	if (NULL != buf_size_ret)
		(*buf_size_ret) = tm;
	return (0);
}


int
core_info_get_os_ver(const char *separator, size_t separator_size,
    char *buf, size_t buf_size, size_t *buf_size_ret) {
	int error, mib[4];
	size_t buf_used = 0, tm;

	/* 'OS[sp]version' */
	mib[0] = CTL_KERN;

	mib[1] = KERN_OSTYPE;
	error = sysctl_str_to_buf(mib, 2, NULL, 0, (uint8_t*)(buf + buf_used),
	    (buf_size - buf_used), &tm);
	if (0 != error)
		return (error);
	buf_used += tm;

	mib[1] = KERN_OSRELEASE;
	error = sysctl_str_to_buf(mib, 2, separator, separator_size,
	    (uint8_t*)(buf + buf_used), (buf_size - buf_used), &tm);
	if (0 != error)
		return (error);
	buf_used += tm;

	if (NULL != buf_size_ret)
		(*buf_size_ret) = buf_used;
	return (0);
}


int
core_info_sysinfo(uint8_t *buf, size_t buf_size, size_t *buf_size_ret) {
	size_t tm, buf_used = 0;
	int mib[4];
#ifdef BSD /* BSD specific code. */
	size_t itm;
#endif /* BSD specific code. */
#ifdef __linux__ /* Linux specific code. */
	uint64_t tm64;
	uint8_t fbuf[1024], *model = NULL, *cl_rate = NULL, *ptm;
	size_t fbuf_size;
#endif /* Linux specific code. */

	/* Kernel */
	buf_used += snprintf((char*)(buf + buf_used), (buf_size - buf_used),
	    "System info");
	mib[0] = CTL_KERN;

	mib[1] = KERN_OSTYPE;
	if (0 == sysctl_str_to_buf(mib, 2, "\r\nOS: ", 6,
	    (buf + buf_used), (buf_size - buf_used), &tm))
		buf_used += tm;

	mib[1] = KERN_OSRELEASE;
	if (0 == sysctl_str_to_buf(mib, 2, " ", 1,
	    (buf + buf_used), (buf_size - buf_used), &tm))
		buf_used += tm;

#ifdef KERN_HOSTNAME 
	mib[1] = KERN_HOSTNAME;
#else
	mib[1] = KERN_NODENAME; /* linux */
#endif
	if (0 == sysctl_str_to_buf(mib, 2, "\r\nHostname: ", 12,
	    (buf + buf_used), (buf_size - buf_used), &tm))
		buf_used += tm;

#ifdef KERN_NISDOMAINNAME
	mib[1] = KERN_NISDOMAINNAME;
#else
	mib[1] = KERN_DOMAINNAME; /* linux */
#endif
	if (0 == sysctl_str_to_buf(mib, 2, ".", 1,
	    (buf + buf_used), (buf_size - buf_used), &tm))
		buf_used += tm;

	mib[1] = KERN_VERSION;
	if (0 == sysctl_str_to_buf(mib, 2, "\r\nVersion: ", 11,
	    (buf + buf_used), (buf_size - buf_used), &tm))
		buf_used += tm;

	buf_used += snprintf((char*)(buf + buf_used), (buf_size - buf_used),
	    "\r\n"
#ifndef BSD
	    "\r\n"
#endif
	    "Hardware");

	/* Hardware */
#ifdef BSD /* BSD specific code. */
	mib[0] = CTL_HW;
	mib[1] = HW_MACHINE;
	if (0 == sysctl_str_to_buf(mib, 2, "\r\nMachine: ", 11,
	    (buf + buf_used), (buf_size - buf_used), &tm))
		buf_used += tm;

	mib[1] = HW_MACHINE_ARCH;
	if (0 == sysctl_str_to_buf(mib, 2, "\r\nArch: ", 8,
	    (buf + buf_used), (buf_size - buf_used), &tm))
		buf_used += tm;

	mib[1] = HW_MODEL;
	if (0 == sysctl_str_to_buf(mib, 2, "\r\nModel: ", 9,
	    (buf + buf_used), (buf_size - buf_used), &tm))
		buf_used += tm;

	itm = 0;
	tm = sizeof(itm);
	if (0 == sysctlbyname("hw.clockrate", &itm, &tm, NULL, 0))
		buf_used += snprintf((char*)(buf + buf_used), (buf_size - buf_used),
		    "\r\nClockrate: %zu mHz", itm);

	mib[1] = HW_NCPU;
	itm = 0;
	tm = sizeof(itm);
	if (0 == sysctl(mib, 2, &itm, &tm, NULL, 0))
		buf_used += snprintf((char*)(buf + buf_used), (buf_size - buf_used),
		    "\r\nCPU count: %zu", itm);

	mib[1] = HW_PHYSMEM;
	itm = 0;
	tm = sizeof(itm);
	if (0 == sysctl(mib, 2, &itm, &tm, NULL, 0))
		buf_used += snprintf((char*)(buf + buf_used), (buf_size - buf_used),
		    "\r\nPhys mem: %zu mb", (itm / (1024 * 1024)));
#endif /* BSD specific code. */
#ifdef __linux__ /* Linux specific code. */
	if (0 == read_file_buf("/proc/cpuinfo", 13, fbuf, sizeof(fbuf), &fbuf_size)) {
		model = mem_find(0, fbuf, fbuf_size, "model name	:", 12);
		if (NULL != model) {
			model += 13;
			ptm = mem_find((model - fbuf), fbuf, fbuf_size, "\n", 1);
			if (NULL != ptm)
				(*ptm) = 0;
		} else {
			model = (uint8_t*)"";
		}
		cl_rate = mem_find(0, fbuf, fbuf_size, "cpu MHz		:", 10);
		if (NULL != cl_rate) {
			cl_rate += 11;
			ptm = mem_find((cl_rate - fbuf), fbuf, fbuf_size, "\n", 1);
			if (NULL != ptm)
				(*ptm) = 0;
		} else {
			cl_rate = (uint8_t*)"";
		}
	}
	tm64 = sysconf(_SC_PHYS_PAGES);
	tm64 *= sysconf(_SC_PAGE_SIZE);
	tm64 /= (1024 * 1024);
	buf_used += snprintf((char*)(buf + buf_used), (buf_size - buf_used),
	    "\r\n"
	    "Model: %s\r\n"
	    "Clockrate: %s\r\n"
	    "CPU count: %li\r\n"
	    "Phys mem: %"PRIu64" mb",
	    model,
	    cl_rate,
	    sysconf(_SC_NPROCESSORS_CONF),
	    tm64);
#endif /* Linux specific code. */
	buf_used += snprintf((char*)(buf + buf_used), (buf_size - buf_used), "\r\n\r\n");
	if (NULL != buf_size_ret)
		(*buf_size_ret) = buf_used;

	return (0);
}


int
core_info_limits(uint8_t *buf, size_t buf_size, size_t *buf_size_ret) {
	size_t i, buf_used = 0;
	struct rlimit rlp;
	int resource[] = {
		RLIMIT_NOFILE,
		RLIMIT_AS,
		RLIMIT_MEMLOCK,
		RLIMIT_DATA,
		RLIMIT_RSS,
		RLIMIT_STACK,
		RLIMIT_CPU,
		RLIMIT_FSIZE,
		RLIMIT_CORE,
		RLIMIT_NPROC,
#ifdef RLIMIT_SBSIZE
		RLIMIT_SBSIZE,
		RLIMIT_SWAP,
		RLIMIT_NPTS,
#endif
		-1
	};
	const char *res_descr[] = {
		"Max open files",
		"Virtual memory max map",
		"mlock max size",
		"Data segment max size",
		"Resident set max size",
		"Stack segment max size",
		"CPU time max",
		"File size max",
		"Core file max size",
		"Processes max count",
		"Socket buffer max size",
		"Swap space max size",
		"Pseudo-terminals max count"
	};

	buf_used += snprintf((char*)(buf + buf_used), (buf_size - buf_used),
	    "Limits\r\n"
	    "CPU count: %li\r\n"
	    "IOV maximum: %li\r\n",
	    sysconf(_SC_NPROCESSORS_ONLN),
	    sysconf(_SC_IOV_MAX));
	for (i = 0; -1 != resource[i]; i ++) {
		if (0 != getrlimit(resource[i], &rlp))
			continue;
		buf_used += snprintf((char*)(buf + buf_used), (buf_size - buf_used),
		    "%s: ", res_descr[i]);
		if (RLIM_INFINITY == rlp.rlim_cur)
			buf_used += snprintf((char*)(buf + buf_used), (buf_size - buf_used),
			    "infinity / ");
		else
			buf_used += snprintf((char*)(buf + buf_used), (buf_size - buf_used),
			    "%zu / ", rlp.rlim_cur);
		if (RLIM_INFINITY == rlp.rlim_max)
			buf_used += snprintf((char*)(buf + buf_used), (buf_size - buf_used),
			    "infinity\r\n");
		else
			buf_used += snprintf((char*)(buf + buf_used), (buf_size - buf_used),
			    "%zu\r\n", rlp.rlim_max);
	}
	if (NULL != buf_size_ret)
		(*buf_size_ret) = buf_used;

	return (0);
}



int
core_info_sysres(core_info_sysres_p sysres, uint8_t *buf, size_t buf_size,
    size_t *buf_size_ret) {
	size_t tm = 0;
	struct timespec tp;
	struct rusage rusage;
	uint64_t tpd, utime, stime;

	if (NULL == sysres)
		return (EINVAL);
	if (0 != getrusage(RUSAGE_SELF, &rusage) ||
	    0 != clock_gettime(CLOCK_MONOTONIC, &tp))
		return (errno);
	if (NULL == buf || 0 == buf_size) /* Only init/update internal data. */
		goto upd_int_data;
	tpd = (1000000000 * ((uint64_t)tp.tv_sec - (uint64_t)sysres->upd_time.tv_sec));
	tpd += ((uint64_t)tp.tv_nsec - (uint64_t)sysres->upd_time.tv_nsec);
	if (0 == tpd) /* Prevent division by zero. */
		tpd ++;
	utime = (1000000000 * ((uint64_t)rusage.ru_utime.tv_sec - (uint64_t)sysres->ru_utime.tv_sec));
	utime += ((uint64_t)rusage.ru_utime.tv_usec - (uint64_t)sysres->ru_utime.tv_usec);
	utime = ((utime * 10000) / tpd);
	stime = (1000000000 * ((uint64_t)rusage.ru_stime.tv_sec - (uint64_t)sysres->ru_stime.tv_sec));
	stime += ((uint64_t)rusage.ru_stime.tv_usec - (uint64_t)sysres->ru_stime.tv_usec);
	stime = ((stime * 10000) / tpd);
	tpd = (utime + stime);
	tm = snprintf((char*)buf, buf_size,
	    "Res usage\r\n"
	    "CPU usage system: %"PRIu64",%02"PRIu64"%%\r\n"
	    "CPU usage user: %"PRIu64",%02"PRIu64"%%\r\n"
	    "CPU usage total: %"PRIu64",%02"PRIu64"%%\r\n"
	    "Max resident set size: %li mb\r\n"
	    "Integral shared text memory size: %li\r\n"
	    "Integral unshared data size: %li\r\n"
	    "Integral unshared stack size: %li\r\n"
	    "Page reclaims: %li\r\n"
	    "Page faults: %li\r\n"
	    "Swaps: %li\r\n"
	    "Block input operations: %li\r\n"
	    "Block output operations: %li\r\n"
	    "IPC messages sent: %li\r\n"
	    "IPC messages received: %li\r\n"
	    "Signals received: %li\r\n"
	    "Voluntary context switches: %li\r\n"
	    "Involuntary context switches: %li\r\n"
	    "\r\n\r\n",
	    (stime / 100), (stime % 100),
	    (utime / 100), (utime % 100),
	    (tpd / 100), (tpd % 100),
	    (rusage.ru_maxrss / 1024), rusage.ru_ixrss,
	    rusage.ru_idrss, rusage.ru_isrss,
	    rusage.ru_minflt, rusage.ru_majflt,
	    rusage.ru_nswap, rusage.ru_inblock,
	    rusage.ru_oublock, rusage.ru_msgsnd,
	    rusage.ru_msgrcv, rusage.ru_nsignals,
	    rusage.ru_nvcsw, rusage.ru_nivcsw);

	if (tp.tv_sec >= (CORE_INFO_SYSRES_UPD_INTERVAL + sysres->upd_time.tv_sec)) {
upd_int_data: /* Update internal data. */
		memcpy(&sysres->upd_time, &tp, sizeof(tp));
		memcpy(&sysres->ru_utime, &rusage.ru_utime, sizeof(struct timeval));
		memcpy(&sysres->ru_stime, &rusage.ru_stime, sizeof(struct timeval));
	}
	if (NULL != buf_size_ret)
		(*buf_size_ret) = tm;
	return (0);
}
