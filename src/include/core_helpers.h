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


#ifndef __CORE_HELPERS_H__
#define __CORE_HELPERS_H__

static void *(*volatile secure_memset_volatile)(void*, int, size_t) = memset;
#define secure_bzero(mem, size)	secure_memset_volatile(mem, 0, size)


#define mmalloc(size)	mmalloc_fd((uintptr_t)-1, size)
void	*mmalloc_fd(uintptr_t fd, size_t size);
void	mmfree(void *mem, size_t size);


typedef struct cmd_line_data_s {
	char	*cfg_file_name;
	char	*pid_file_name;
	uid_t	pw_uid;		// user uid
	gid_t	pw_gid;		// user gid
	int	daemon;
	int	verbose;
	char	*file_name;
} cmd_line_data_t, *cmd_line_data_p;


int	cmd_line_parse(int argc, char **argv, cmd_line_data_p data);
void	cmd_line_usage(const char *pkg_name, const char *pkg_ver);
void	make_daemon(void);
int	write_pid(const char *file_name);
int	set_user_and_group(uid_t pw_uid, gid_t pw_gid);
int	read_file(const char *file_name, size_t file_name_size, size_t max_size,
	    uint8_t **buf, size_t *buf_size);
int	read_file_buf(const char *file_name, size_t file_name_size, uint8_t *buf,
	    size_t buf_size, size_t *buf_size_ret);
int	get_cpu_count(void);
int	bind_thread_to_cpu(int cpu_id);
int	fd_set_nonblocking(int fd, int nonblocked);


size_t	calc_sptab_count(const char *buf, size_t buf_size);
size_t	calc_sptab_count_r(const char *buf, size_t buf_size);
size_t	calc_non_sptab_count(const char *buf, size_t buf_size);
size_t	calc_non_sptab_count_r(const char *buf, size_t buf_size);

size_t	buf2args(char *buf, size_t buf_size, size_t max_args, char **args,
	    size_t *args_sizes);

size_t	fmt_as_uptime(time_t *ut, char *buf, size_t buf_size);


uint8_t	data_xor8(void *buf, size_t size);
void	memxor(void *dst, uint8_t byte, size_t size);
void	memxorbuf(void *dst, size_t dsize, void *src, size_t ssize);

int	cvt_hex2bin(uint8_t *hex, size_t hex_size, int auto_out_size,
	    uint8_t *bin, size_t bin_size, size_t *bin_size_ret);
int	cvt_bin2hex(uint8_t *bin, size_t bin_size, int auto_hex_size,
	    uint8_t *hex, size_t hex_size, size_t *hex_size_ret);

int	yn_set_flag32(uint8_t *buf, size_t buf_size, uint32_t flag_bit,
	    uint32_t *flags);

#endif /* __CORE_HELPERS_H__ */
