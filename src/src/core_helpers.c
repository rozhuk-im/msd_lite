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
#include <sys/stat.h> // chmod, fchmod, umask
#include <sys/uio.h> /* readv, preadv, writev, pwritev */

#ifdef __linux__ /* Linux specific code. */
#	include <sched.h>
#endif /* Linux specific code. */

#include <pthread.h>

#ifdef BSD /* BSD specific code. */
#	include <pthread_np.h>
	typedef cpuset_t cpu_set_t;
#endif /* BSD specific code. */

#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h> /* open, fcntl */
#include <stdio.h>  /* snprintf, fprintf */
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strnlen, strerror... */
#include <unistd.h> /* close, write, sysconf */
#include <stdlib.h> /* malloc, exit */
#include <stdarg.h> /* va_start, va_arg */
#include <signal.h>

#include "mem_helpers.h"
#include "core_helpers.h"
#ifdef SYS_RES_XML_CONFIG
#	include <sys/resource.h>
#	ifdef BSD /* BSD specific code. */
#		include <sys/rtprio.h>
#	endif /* BSD specific code. */
#	include "StrToNum.h"
#	include "xml.h"
#endif



int
cmd_line_parse(int argc, char **argv, cmd_line_data_p data) {
	unsigned char *pCur;
	int error, i;
	char *pUID, *pGID;
	struct passwd *pwd, pwd_buf;
	char buffer[4096];
	struct group *grp, grp_buf;

	if (2 > argc || NULL == data)
		return (1);
	mem_bzero(data, sizeof(cmd_line_data_t));

	for (i = 1; i < argc; i ++) {
		pCur = (unsigned char*)argv[i];
		if (*pCur++ != '-') {
			fprintf(stderr, "invalid option: \"%s\"\n", argv[i]);
			return (0);
		}
		while (*pCur) {
			switch (*pCur++) {
			case '?':
			case 'h':
			case 'H':
				return (1);
			case 'd':
			case 'D':
				data->daemon = 1;
				break;
			case 'c':
			case 'C':
				if (*pCur) {
					data->cfg_file_name = (char*)pCur;
				} else if (argv[++ i]) {
					data->cfg_file_name = argv[i];
				} else {
					fprintf(stderr, "option \"-c\" requires config file name\n");
					return (1);
				}
				break;
			case 'f':
			case 'F':
				if (*pCur) {
					data->file_name = (char*)pCur;
				} else if (argv[++ i]) {
					data->file_name = argv[i];
				} else {
					fprintf(stderr, "option \"-f\" requires file name\n");
					return (1);
				}
				break;
			case 'p':
			case 'P':
				if (*pCur) {
					data->pid_file_name = (char*)pCur;
				} else if (argv[++ i]) {
					data->pid_file_name = argv[i];
				} else {
					fprintf(stderr, "option \"-p\" requires pid file name\n");
					return (1);
				}
				break;
			case 'u':
			case 'U':
				if (*pCur) {
					pUID = (char*)pCur;
				} else if (argv[++ i]) {
					pUID = argv[i];
				} else {
					fprintf(stderr, "option \"-u\" requires UID\n");
					return (1);
				}
				if (NULL == pUID)
					break;
				error = getpwnam_r(pUID, &pwd_buf, buffer, sizeof(buffer), &pwd);
				if (0 == error) {
					data->pw_uid = pwd->pw_uid;
				} else {
					fprintf(stderr, "option \"-u\" requires UID, UID %s not found: %i - %s\n",
					    pUID, error, strerror(error));
				}
				break;
			case 'g':
			case 'G':
				if (*pCur) {
					pGID = (char*)pCur;
				} else if (argv[++ i]) {
					pGID = argv[i];
				} else {
					fprintf(stderr, "option \"-g\" requires GID\n");
					return (1);
				}
				if (NULL == pGID)
					break;
				error = getgrnam_r(pGID, &grp_buf, buffer, sizeof(buffer), &grp);
				if (0 == error) {
					data->pw_gid = grp->gr_gid;
				} else {
					fprintf(stderr, "option \"-g\" requires GID, GID %s not found: %i - %s\n",
					    pGID, error, strerror(error));
				}
				break;
			case 'v':
			case 'V':
				data->verbose = 1;
				break;
			default:
				fprintf(stderr, "invalid option: \"%c\"\n", (*(pCur-1)));
				return (1);
			} /* switch (*pCur++) */
		} /* while (*pCur) */
	} /* for(i) */
	if (0 != data->daemon) {
		//data->verbose = 0;
		make_daemon();
	}
	return (0);
}

void
cmd_line_usage(const char *pkg_name, const char *pkg_ver) {
	fprintf(stderr, "%s %s -- (c) Rozhuk Ivan <rozhuk.im@gmail.com>\n", pkg_name, pkg_ver);
	fprintf(stderr, "   BSD licence.  Website: http://netlab.linkpc.net\n");
	fprintf(stderr, "   Build: "__DATE__" "__TIME__"\n");
	fprintf(stderr,
		"usage: [-d] [-v] [-c file]\n"
		"       [-p PID file] [-u uid|usr -g gid|grp]\n"
		" -h           usage (this screen)\n"
		" -d           become daemon\n"
		" -c file      config file\n");
	fprintf(stderr,
		" -p PID file  file name to store PID\n"
		" -u uid|user  change uid\n"
		" -g gid|group change gid\n"
		" -v           verbose\n");
}

void
signal_install(sig_t func) {

	signal(SIGINT, func);
	signal(SIGTERM, func);
	//signal(SIGKILL, func);
	signal(SIGHUP, func);
	signal(SIGUSR1, func);
	signal(SIGUSR2, func);
	signal(SIGPIPE, SIG_IGN);
}

void
make_daemon(void) {
	int error;

	switch (fork()) {
	case -1:
		error = errno;
		fprintf(stderr, "make_daemon: fork() failed: %i %s\n",
		    error, strerror(error));
		exit(error);
		/* return; */
	case 0: /* Child. */
		break;
	default: /* Parent. */
		exit(0);
	}

	/* Child... */
	setsid();
	setpgid(getpid(), 0);

	/* Close stdin, stdout, stderr. */
	close(0);
	close(1);
	close(2);
}

int
write_pid(const char *file_name) {
	int fd;
	char data[64];
	size_t data_size;

	if (NULL == file_name)
		return (EINVAL);
	fd = open(file_name, (O_WRONLY | O_CREAT | O_TRUNC), 0777);
	if (-1 == fd)
		return (errno);
	data_size = (size_t)snprintf(data, sizeof(data), "%d", getpid());
	write(fd, data, data_size);
	fchmod(fd, (S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH));
	close(fd);

	return (0);
}

int
set_user_and_group(uid_t pw_uid, gid_t pw_gid) {
	int error = 0;
	struct passwd *pwd, pwd_buf;
	char buffer[4096];

	if (0 == pw_uid || 0 == pw_gid)
		return (EINVAL);
	error = getpwuid_r(pw_uid, &pwd_buf, buffer, sizeof(buffer), &pwd);
	if (0 != error) {
		error = errno;
		fprintf(stderr, "set_user_and_group: getpwuid_r() error %i: %s\n",
		    error, strerror(error));
		return (error);
	}

	if (0 != setgid(pw_gid)) {
		error = errno;
		fprintf(stderr, "set_user_and_group: setgid() error %i: %s\n",
		    error, strerror(error));
	}
	if (0 != initgroups(pwd->pw_name, pw_gid)) {
		error = errno;
		fprintf(stderr, "set_user_and_group: initgroups() error %i: %s\n",
		    error, strerror(error));
	}
	if (0 != setgroups(1, &pwd->pw_gid)) {
		error = errno;
		fprintf(stderr, "set_user_and_group: setgroups() error %i: %s\n",
		    error, strerror(error));
	}
	if (0 != setuid(pw_uid)) {
		error = errno;
		fprintf(stderr, "set_user_and_group: setuid() error %i: %s\n",
		    error, strerror(error));
	}

	return (error);
}

int
read_file(const char *file_name, size_t file_name_size, size_t max_size,
    uint8_t **buf, size_t *buf_size) {
	int fd, error;
	ssize_t rd;
	char filename[1024];
	struct stat sb;

	if (NULL == file_name || (sizeof(filename) - 1) < file_name_size ||
	    NULL == buf || NULL == buf_size)
		return (EINVAL);
	if (0 == file_name_size) {
		file_name_size = strnlen(file_name, (sizeof(filename) - 1));
	}
	memcpy(filename, file_name, file_name_size);
	filename[file_name_size] = 0;
	/* Open file. */
	fd = open(filename, O_RDONLY);
	if (-1 == fd)
		return (errno);
	/* Get file size. */
	if (0 != fstat(fd, &sb)) {
		error = errno;
		goto err_out;
	}
	/* Check overflow. */
	(*buf_size) = (size_t)sb.st_size;
	if (0 != max_size && ((off_t)max_size) < sb.st_size) {
		error = EFBIG;
		goto err_out;
	}
	/* Allocate buf for file content. */
	(*buf) = malloc((((size_t)sb.st_size) + sizeof(void*)));
	if (NULL == (*buf)) {
		error = ENOMEM;
		goto err_out;
	}
	/* Read file content. */
	rd = read(fd, (*buf), (size_t)sb.st_size);
	close(fd);
	if (-1 == rd) {
		error = errno;
		free((*buf));
		return (error);
	}
	(*buf)[sb.st_size] = 0;
	return (0);

err_out:
	close(fd);
	return (error);
}

int
read_file_buf(const char *file_name, size_t file_name_size, uint8_t *buf,
    size_t buf_size, size_t *buf_size_ret) {
	int fd;
	size_t rd;
	char filename[1024];

	if (NULL == file_name || (sizeof(filename) - 1) < file_name_size ||
	    NULL == buf || 0 == buf_size)
		return (EINVAL);
	if (0 == file_name_size) {
		file_name_size = strnlen(file_name, (sizeof(filename) - 1));
	}
	memcpy(filename, file_name, file_name_size);
	filename[file_name_size] = 0;
	/* Open file. */
	fd = open(filename, O_RDONLY);
	if (-1 == fd)
		return (errno);
	/* Read file content. */
	rd = (size_t)read(fd, buf, buf_size);
	close(fd);
	if ((size_t)-1 == rd)
		return (errno);
	if (buf_size > rd) { /* Zeroize end. */
		buf[rd] = 0;
	}
	if (NULL != buf_size_ret) {
		(*buf_size_ret) = rd;
	}
	return (0);
}

int
get_cpu_count(void) {
	int ret;

	ret = (int)sysconf(_SC_NPROCESSORS_ONLN);
	if (-1 == ret) {
		ret = 1;
	}
	return (ret);
}


int
bind_thread_to_cpu(int cpu_id) {
	cpu_set_t cs;

	if (-1 == cpu_id)
		return (EINVAL);
	/* Bind this thread to a single cpu. */
	CPU_ZERO(&cs);
	CPU_SET(cpu_id, &cs);
	return (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cs));
}

/* Set file/socket to non blocking mode */
int
fd_set_nonblocking(uintptr_t fd, int nonblocked) {
	int opts;

	if ((uintptr_t)-1 == fd)
		return (EINVAL);
	opts = fcntl((int)fd, F_GETFL); /* Read current options. */
	if (-1 == opts)
		return (errno);
	if (0 == nonblocked) {
		if (0 == (opts & O_NONBLOCK))
			return (0); /* Allready set. */
		opts &= ~O_NONBLOCK;
	} else {
		if (0 != (opts & O_NONBLOCK))
			return (0); /* Allready set. */
		opts |= O_NONBLOCK;
	}
	if (-1 == fcntl((int)fd, F_SETFL, opts)) /* Update options. */
		return (errno);
	return (0);
}

#if defined(__FreeBSD__) && __FreeBSD__ < 10 /* __FreeBSD__ specific code. */
int
pipe2(int fildes[2], int flags) {
	int error;
	
	error = pipe(fildes);
	if (0 != error)
		return (error);
	if (0 != (O_NONBLOCK & flags)) {
		error = fd_set_nonblocking(fildes[0], 1);
		if (0 != error)
			goto err_out;
		error = fd_set_nonblocking(fildes[1], 1);
		if (0 != error)
			goto err_out;
	}
	return (0);

err_out:
	close(fildes[0]);
	close(fildes[1]);
	fildes[0] = -1;
	fildes[1] = -1;

	return (error);
}
#endif /* BSD specific code. */


/* Calc number of tab and spaces from start of buf to first non tab/space char. */
size_t
calc_sptab_count(const char *buf, size_t buf_size) {
	const char *cur, *buf_end;

	buf_end = (buf + buf_size);
	for (cur = buf; cur < buf_end && ((*cur) == ' ' || (*cur) == '\t'); cur ++)
		;
	return ((size_t)(cur - buf));
}


/* Calculate number of tab and spaces from end of buf to first non tab/space char. */
size_t
calc_sptab_count_r(const char *buf, size_t buf_size) {
	const char *cur, *buf_end;

	buf_end = (buf + (buf_size - 1));
	for (cur = buf_end; cur > buf && ((*cur) == ' ' || (*cur) == '\t'); cur --)
		;
	return ((size_t)(buf_end - cur));
}


/* Calculate number of any symbols, except tab and spaces from start of buf to 
 * first non tab/space char. */
size_t
calc_non_sptab_count(const char *buf, size_t buf_size) {
	const char *cur, *buf_end;

	buf_end = (buf + buf_size);
	for (cur = buf; cur < buf_end && ((*cur) != ' ' && (*cur) != '\t'); cur ++)
		;
	return ((size_t)(cur - buf));
}


/* Calculate number of any symbols, except tab and spaces from end of buf to
 * first non tab/space char. */
size_t
calc_non_sptab_count_r(const char *buf, size_t buf_size) {
	const char *cur, *buf_end;

	buf_end = (buf + (buf_size - 1));
	for (cur = buf_end; cur > buf && ((*cur) != ' ' && (*cur) != '\t'); cur --)
		;
	return ((size_t)(buf_end - cur));
}


/* Split buf to array of arguments, separated by SP or TAB if first char is " then
 * SP and TAB will be ignored untill next " return number of arguments. */
size_t
buf2args(char *buf, size_t buf_size, size_t max_args, char **args, size_t *args_sizes) {
	char *cur_pos, *max_pos, *ptm;
	size_t ret, cur_size, data_size, sptab_count;

	if (NULL == buf || 0 == buf_size || 0 == max_args || NULL == args)
		return (0);

	ret = 0;
	cur_pos = buf;
	cur_size = buf_size;
	max_pos = (cur_pos + cur_size);
	while (max_args > ret && max_pos > cur_pos) {
		/* Skip SP & TAB before arg value. */
		sptab_count = calc_sptab_count(cur_pos, cur_size);
		if (cur_size <= sptab_count)
			break;
		cur_size -= sptab_count;
		cur_pos += sptab_count;

		/* Calculate data size. */
		if ('"' == (*cur_pos)) {
			cur_pos ++;
			cur_size --;
			ptm = mem_chr(cur_pos, cur_size, '"');
			if (NULL != ptm) {
				data_size = (size_t)(ptm - cur_pos);
			} else {
				data_size = cur_size;
			}
		} else {
			data_size = calc_non_sptab_count(cur_pos, cur_size);
		}
		args[ret] = cur_pos;
		args_sizes[ret] = data_size;
		(*(cur_pos + data_size)) = 0;
		data_size ++;
		ret ++;

		/* Move to next arg. */
		cur_size -= data_size;
		cur_pos += data_size;
	}
	return (ret);
}


size_t
fmt_as_uptime(time_t *ut, char *buf, size_t buf_size) {
	uint64_t uptime, days, hrs, mins, secs;
	
	if (NULL == ut)
		return (0);
	uptime = (uint64_t)(*ut);

	days = (uptime / 86400);
	uptime %= 86400;
	hrs = (uptime / 3600);
	uptime %= 3600;
	mins = (uptime / 60);
	secs = (uptime % 60);

	return ((size_t)snprintf(buf, buf_size, "%"PRIu64"+%02"PRIu64":%02"PRIu64":%02"PRIu64"",
	    days, hrs, mins, secs));
}


uint8_t
data_xor8(void *dst, size_t size) {
	size_t i;
	uint8_t ret = 0, *pt = (uint8_t*)dst;

	if (NULL == dst || 0 == size)
		return (0);
	for (i = 0; i < size; i ++) {
		ret ^= pt[i];
	}
	return (ret);
}

void
memxor(void *dst, uint8_t byte, size_t size) {
	size_t i;
	uint8_t *pt = (uint8_t*)dst;

	if (NULL == dst || 0 == size)
		return;
	for (i = 0; i < size; i ++) {
		pt[i] ^= byte;
	}
}

void
memxorbuf(void *dst, size_t dsize, void *src, size_t ssize) {
	size_t i, j;
	uint8_t *pd = (uint8_t*)dst, *ps = (uint8_t*)src;

	if (NULL == dst || 0 == dsize || NULL == src || 0 == ssize)
		return;
	for (i = 0, j = 0; i < dsize; i ++, j ++) {
		if (j == ssize) {
			j = 0;
		}
		pd[i] ^= ps[j];
	}
}

/* auto_out_size: 1 = all bytes in output buffer are initialized and
 * ret_size = out buf size */
/* Convert HEX to BIN. */
int
cvt_hex2bin(const uint8_t *hex, size_t hex_size, int auto_out_size,
    uint8_t *bin, size_t bin_size, size_t *bin_size_ret) {
	const uint8_t *hex_max;
	uint8_t cur_char, *bin_max, byte = 0;
	size_t cnt;

	if (NULL == hex || 0 == hex_size || NULL == bin || 0 == bin_size)
		return (EINVAL);
	if (bin_size < (hex_size / 2))
		return (EOVERFLOW);
	hex_max = (hex + hex_size);
	bin_max = (bin + bin_size);

	for (cnt = 0; hex < hex_max; hex ++) {
		cur_char = (*hex);
		if ('0' <= cur_char && '9' >= cur_char) {
			cur_char -= '0';
		} else if ('a' <= cur_char && 'f' >= cur_char) {
			cur_char -= ('a' - 10);
		} else if ('A' <= cur_char && 'F' >= cur_char) {
			cur_char -= ('A' - 10);
		} else {
			continue;
		}
		byte = (((uint8_t)(byte << 4)) | cur_char);
		cnt ++;
		if (2 > cnt) /* Wait untill 4 + 4 bit before write a byte. */
			continue;
		if (bin == bin_max)
			return (EOVERFLOW);
		(*bin ++) = byte;
		byte = 0;
		cnt = 0;
	}
	if (0 != auto_out_size) {
		mem_bzero(bin, (size_t)(bin_max - bin));
		bin = bin_max;
	}
	if (NULL != bin_size_ret) {
		(*bin_size_ret) = (size_t)(bin_size - (size_t)(bin_max - bin));
	}
	return (0);
}
/* Convert BIN to HEX. */
int
cvt_bin2hex(const uint8_t *bin, size_t bin_size, int auto_out_size,
    uint8_t *hex, size_t hex_size, size_t *hex_size_ret) {
	static const uint8_t *hex_tbl = (const uint8_t*)"0123456789abcdef";
	const uint8_t *bin_max, *hex_max;
	uint8_t byte;
	size_t tm;

	if (NULL == bin || NULL == hex || 2 > hex_size)
		return (EINVAL);
	hex_max = (hex + hex_size);
	if (0 == bin_size) { /* is a = 0? */
		if (0 != auto_out_size) {
			tm = 2;
		} else {
			tm = (hex_size & ~((size_t)1));
		}
		mem_set(hex, tm, '0');
		hex += tm;
		goto ok_exit;
	}
	bin_max = (bin + bin_size);
	tm = (2 * bin_size);
	if (tm > hex_size) { /* Not enouth space in buf. */
		if (NULL != hex_size_ret) {
			(*hex_size_ret) = tm;
		}
		return (EOVERFLOW);
	}
	for (; bin < bin_max; bin ++) {
		byte = (*bin);
		(*hex ++) = hex_tbl[((byte >> 4) & 0x0f)];
		(*hex ++) = hex_tbl[(byte & 0x0f)];
	}
	if (0 == auto_out_size) { /* Zeroize end. */
		tm = ((hex_size - tm) & ~((size_t)1));
		mem_set(hex, tm, '0');
		hex += tm;
	}
ok_exit:
	if (hex_max > hex) { /* Zero end of string. */
		(*hex) = 0;
	}
	if (NULL != hex_size_ret) {
		(*hex_size_ret) = (size_t)(hex_size - (size_t)(hex_max - hex));
	}
	return (0);
}


int
yn_set_flag32(const uint8_t *buf, size_t buf_size, uint32_t flag_bit,
    uint32_t *flags) {

	if (NULL == flags)
		return (EINVAL);
	if (NULL == buf ||
	    0 == buf_size) {
		(*flags) &= ~flag_bit; /* Unset. */
		return (0);
	}
	switch ((*buf)) {
	case '0':
	case 'n':
	case 'N':
	case 'f':
	case 'F':
		(*flags) &= ~flag_bit; /* Unset. */
		return (0);
	case '1':
	case 'y':
	case 'Y':
	case 't':
	case 'T':
		(*flags) |= flag_bit; /* Set. */
		return (0);
	}
	return (EINVAL);
}


#ifdef SYS_RES_XML_CONFIG
void
sys_res_limits_load_xml_apply(const uint8_t *buf, size_t buf_size) {
	const uint8_t *data;
	size_t data_size;
	int64_t itm64;
	int itm;
	struct rlimit rlp;

	/* System resource limits. */
	if (NULL == buf || 0 == buf_size)
		return;
	if (0 == xml_get_val_int64_args(buf, buf_size, NULL,
	    &itm64, (const uint8_t*)"maxOpenFiles", NULL)) {
		rlp.rlim_cur = itm64;
		rlp.rlim_max = itm64;
		if (0 != setrlimit(RLIMIT_NOFILE, &rlp)) {
			fprintf(stderr, "setrlimit(RLIMIT_NOFILE) error: %i - %s\n",
			    errno, strerror(errno));
		}
	}
	if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
	    &data, &data_size,
	    (const uint8_t*)"maxCoreFileSize", NULL) &&
	    0 < data_size) {
		if (0 == mem_cmpin_cstr("unlimited", data, data_size)) {
			rlp.rlim_cur = RLIM_INFINITY;
		} else {
			rlp.rlim_cur = (UStr8ToNum64(data, data_size) * 1024); /* in kb */
		}
		rlp.rlim_max = rlp.rlim_cur;
		if (0 != setrlimit(RLIMIT_CORE, &rlp)) {
			fprintf(stderr, "setrlimit(RLIMIT_CORE) error: %i - %s\n",
			    errno, strerror(errno));
		}
	}
	if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
	    &data, &data_size,
	    (const uint8_t*)"maxMemLock", NULL) &&
	    0 < data_size) {
		if (0 == mem_cmpin_cstr("unlimited", data, data_size)) {
			rlp.rlim_cur = RLIM_INFINITY;
		} else {
			rlp.rlim_cur = (UStr8ToNum64(data, data_size) * 1024); /* in kb */
		}
		rlp.rlim_max = rlp.rlim_cur;
		if (0 != setrlimit(RLIMIT_MEMLOCK, &rlp)) {
			fprintf(stderr, "setrlimit(RLIMIT_MEMLOCK) error: %i - %s\n",
			    errno, strerror(errno));
		}
	}
	if (0 == xml_get_val_int32_args(buf, buf_size, NULL,
	    &itm, (const uint8_t*)"processPriority", NULL)) {
		if (0 != setpriority(PRIO_PROCESS, 0, itm)) {
			fprintf(stderr, "setpriority() error: %i - %s\n",
			    errno, strerror(errno));
		}
	}
	if (0 == xml_get_val_int32_args(buf, buf_size, NULL,
	    &itm, (const uint8_t*)"processPriority2", NULL)) {
#ifdef BSD /* BSD specific code. */
		struct rtprio rtp;
		rtp.type = RTP_PRIO_REALTIME;
		rtp.prio = (u_short)itm;
		if (0 != rtprio(RTP_SET, 0, &rtp)) {
			fprintf(stderr, "rtprio() error: %i - %s\n",
			    errno, strerror(errno));
		}
#endif /* BSD specific code. */
	}
}
#endif
