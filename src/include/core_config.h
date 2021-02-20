/*-
 * Copyright (c) 2011 - 2012 Rozhuk Ivan <rozhuk.im@gmail.com>
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

 
#ifndef __CORE_CONFIG_H__
#define __CORE_CONFIG_H__


typedef struct cfg_file_s *cfg_file_p;


int	cfg_file_open(const char *file, cfg_file_p *pcfd);
void	cfg_file_close(cfg_file_p cfd);

size_t	cfg_file_lines_count(cfg_file_p cfd);
int	cfg_file_get_line(cfg_file_p cfd, size_t line, char **data, size_t *data_size);
size_t	cfg_file_calc_val_count(cfg_file_p cfd, const char *val_name,
	    size_t val_name_size, const char comment_char, const char *separator,
	    size_t separator_size, size_t line);
int	cfg_file_get_val_data(cfg_file_p cfd, const char *val_name,
	    size_t val_name_size, const char comment_char, const char *separator,
	    size_t separator_size, size_t *line, char **data_ret,
	    size_t *data_size_ret);
int	cfg_file_get_raw_data(cfg_file_p cfd, const char comment_char, size_t *line,
	    char **data_ret, size_t *data_size_ret);
int	cfg_file_get_val_int(cfg_file_p cfd, const char *val_name,
	    size_t val_name_size, const char comment_char, const char *separator,
	    size_t separator_size, size_t *line, int32_t *ival_ret);
int	cfg_file_get_val_ssize_t(cfg_file_p cfd, const char *val_name,
	    size_t val_name_size, const char comment_char, const char *separator,
	    size_t separator_size, size_t *line, ssize_t *val_ret);


#endif // __CORE_CONFIG_H__
