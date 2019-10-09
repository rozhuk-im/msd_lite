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
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>

#ifdef BSD /* BSD specific code. */
#	include <sys/uio.h> /* sendfile */
#	include <net/if_dl.h>
#endif /* BSD specific code. */

#ifdef __linux__ /* Linux specific code. */
#	include <sys/sendfile.h>
//	#include <linux/ipv6.h>
#endif /* Linux specific code. */

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <inttypes.h>
#include <unistd.h> /* close, write, sysconf */
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <stdio.h>  /* snprintf, fprintf */
#include <errno.h>

#include "macro_helpers.h"
#include "mem_helpers.h"

#include "core_helpers.h"
#include "core_net_helpers.h"
#include "core_io_net.h"
#ifdef IO_NET_XML_CONFIG
#	include "xml.h"
#	include "core_helpers.h"
#	include "core_log.h"
#endif



#ifdef IO_NET_XML_CONFIG
int
io_net_skt_opts_xml_load(const uint8_t *buf, size_t buf_size, uint32_t mask,
    skt_opts_p opts) {
	const uint8_t *data;
	size_t data_size;

	if (NULL == buf || 0 == buf_size || NULL == opts)
		return (EINVAL);
	/* Read from config. */

	/* SO_F_NONBLOCK: never read, app internal. */
	/* SO_F_HALFCLOSE_RD */
	if (0 != (SO_F_HALFCLOSE_RD & mask)) {
		if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
		    &data, &data_size,
		    (const uint8_t*)"fHalfClosedRcv", NULL)) {
			yn_set_flag32(data, data_size, SO_F_HALFCLOSE_RD, &opts->bit_vals);
			opts->mask |= SO_F_HALFCLOSE_RD;
		}
	}
	/* SO_F_HALFCLOSE_WR */
	if (0 != (SO_F_HALFCLOSE_WR & mask)) {
		if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
		    &data, &data_size,
		    (const uint8_t*)"fHalfClosedSnd", NULL)) {
			yn_set_flag32(data, data_size, SO_F_HALFCLOSE_WR, &opts->bit_vals);
			opts->mask |= SO_F_HALFCLOSE_WR;
		}
	}
	/* SO_F_BACKLOG */
	if (0 != (SO_F_BACKLOG & mask)) {
		if (0 == xml_get_val_int32_args(buf, buf_size, NULL,
		    &opts->backlog,
		    (const uint8_t*)"backlog", NULL)) {
			opts->mask |= SO_F_BACKLOG;
		}
	}
	/* SO_F_BROADCAST: never read, app internal. */
	/* SO_F_REUSEADDR */
	if (0 != (SO_F_REUSEADDR & mask)) {
		if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
		    &data, &data_size,
		    (const uint8_t*)"fReuseAddr", NULL)) {
			yn_set_flag32(data, data_size, SO_F_REUSEADDR, &opts->bit_vals);
			opts->mask |= SO_F_REUSEADDR;
		}
	}
	/* SO_F_REUSEPORT */
	if (0 != (SO_F_REUSEPORT & mask)) {
		if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
		    &data, &data_size,
		    (const uint8_t*)"fReusePort", NULL)) {
			yn_set_flag32(data, data_size, SO_F_REUSEPORT, &opts->bit_vals);
			opts->mask |= SO_F_REUSEPORT;
		}
	}
	/* SO_F_KEEPALIVE */
	if (0 != (SO_F_KEEPALIVE & mask)) {
		if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
		    &data, &data_size,
		    (const uint8_t*)"fKeepAlive", NULL)) {
			yn_set_flag32(data, data_size, SO_F_KEEPALIVE, &opts->bit_vals);
			opts->mask |= SO_F_KEEPALIVE;
		}
		if (IO_NET_SKT_OPTS_IS_FLAG_ACTIVE(opts, SO_F_KEEPALIVE)) {
			/* SO_F_TCP_KEEPIDLE */
			if (0 != (SO_F_TCP_KEEPIDLE & mask)) {
				if (0 == xml_get_val_uint32_args(buf, buf_size, NULL,
				    &opts->tcp_keep_idle,
				    (const uint8_t*)"keepAliveIDLEtime", NULL)) {
					if (0 != opts->tcp_keep_idle) {
						opts->mask |= SO_F_TCP_KEEPIDLE;
					}
				}
			}
			/* SO_F_TCP_KEEPINTVL */
			if (0 != (SO_F_TCP_KEEPINTVL & mask)) {
				if (0 == xml_get_val_uint32_args(buf, buf_size, NULL,
				    &opts->tcp_keep_intvl,
				    (const uint8_t*)"keepAliveProbesInterval", NULL)) {
					if (0 != opts->tcp_keep_intvl) {
						opts->mask |= SO_F_TCP_KEEPINTVL;
					}
				}
			}
			/* SO_F_TCP_KEEPCNT */
			if (0 != (SO_F_TCP_KEEPCNT & mask)) {
				if (0 == xml_get_val_uint32_args(buf, buf_size, NULL,
				    &opts->tcp_keep_cnt,
				    (const uint8_t*)"keepAliveNumberOfProbes", NULL)) {
					if (0 != opts->tcp_keep_cnt) {
						opts->mask |= SO_F_TCP_KEEPCNT;
					}
				}
			}
		}
	} /* SO_F_KEEPALIVE */
	/* SO_F_RCVBUF */
	if (0 != (SO_F_RCVBUF & mask)) {
		if (0 == xml_get_val_uint32_args(buf, buf_size, NULL,
		    &opts->rcv_buf,
		    (const uint8_t*)"rcvBuf", NULL)) {
			if (0 != opts->rcv_buf) {
				opts->mask |= SO_F_RCVBUF;
			}
		}
	}
	/* SO_F_RCVLOWAT */
	if (0 != (SO_F_RCVLOWAT & mask)) {
		if (0 == xml_get_val_uint32_args(buf, buf_size, NULL,
		    &opts->rcv_lowat,
		    (const uint8_t*)"rcvLoWatermark", NULL)) {
			if (0 != opts->rcv_lowat) {
				opts->mask |= SO_F_RCVLOWAT;
			}
		}
	}
	/* SO_F_RCVTIMEO */
	if (0 != (SO_F_RCVTIMEO & mask)) {
		if (0 == xml_get_val_uint64_args(buf, buf_size, NULL,
		    &opts->rcv_timeout,
		    (const uint8_t*)"rcvTimeout", NULL)) {
			opts->mask |= SO_F_RCVTIMEO;
		}
	}
	/* SO_F_SNDBUF */
	if (0 != (SO_F_SNDBUF & mask)) {
		if (0 == xml_get_val_uint32_args(buf, buf_size, NULL,
		    &opts->snd_buf,
		    (const uint8_t*)"sndBuf", NULL)) {
			if (0 != opts->snd_buf) {
				opts->mask |= SO_F_SNDBUF;
			}
		}
	}
	/* SO_F_SNDLOWAT */
	if (0 != (SO_F_SNDLOWAT & mask)) {
		if (0 == xml_get_val_uint32_args(buf, buf_size, NULL,
		    &opts->snd_lowat,
		    (const uint8_t*)"sndLoWatermark", NULL)) {
			if (0 != opts->snd_buf) {
				opts->mask |= SO_F_SNDLOWAT;
			}
		}
	}
	/* SO_F_SNDTIMEO */
	if (0 != (SO_F_SNDTIMEO & mask)) {
		if (0 == xml_get_val_uint64_args(buf, buf_size, NULL,
		    &opts->snd_timeout,
		    (const uint8_t*)"sndTimeout", NULL)) {
			opts->mask |= SO_F_SNDTIMEO;
		}
	}

	/* SO_F_ACC_FILTER */
	if (0 != (SO_F_ACC_FILTER & mask)) {
#ifdef SO_ACCEPTFILTER
		if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
		    &data, &data_size,
		    (const uint8_t*)"AcceptFilterName", NULL)) {
			if (0 != data_size &&
			    sizeof(opts->tcp_acc_filter.af_name) > data_size) {
				mem_bzero(&opts->tcp_acc_filter,
				    sizeof(struct accept_filter_arg));
				memcpy(opts->tcp_acc_filter.af_name, data, data_size);
				opts->mask |= SO_F_ACC_FILTER;
			}
		}
#elif defined(TCP_DEFER_ACCEPT)
		if (0 == xml_get_val_uint32_args(buf, buf_size, NULL,
		    &opts->tcp_acc_defer,
		    (const uint8_t*)"AcceptFilterDeferTime", NULL)) {
			if (0 != opts->tcp_acc_defer) {
				opts->mask |= SO_F_ACC_FILTER;
			}
		}
#endif
		/* accept flags */
		if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
		    &data, &data_size,
		    (const uint8_t*)"fAcceptFilter", NULL)) {
			yn_set_flag32(data, data_size, SO_F_ACC_FILTER, &opts->bit_vals);
		}
	}
	/* SO_F_TCP_NODELAY */
	if (0 != (SO_F_TCP_NODELAY & mask)) {
		if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
		    &data, &data_size,
		    (const uint8_t*)"fTCPNoDelay", NULL)) {
			yn_set_flag32(data, data_size, SO_F_TCP_NODELAY, &opts->bit_vals);
			opts->mask |= SO_F_TCP_NODELAY;
		}
	}
	/* SO_F_TCP_NOPUSH */
	if (0 != (SO_F_TCP_NOPUSH & mask)) {
		if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
		    &data, &data_size,
		    (const uint8_t*)"fTCPNoPush", NULL)) {
			yn_set_flag32(data, data_size, SO_F_TCP_NOPUSH, &opts->bit_vals);
			opts->mask |= SO_F_TCP_NOPUSH;
		}
	}
	/* SO_F_TCP_CONGESTION */
	if (0 != (SO_F_TCP_CONGESTION & mask)) {
		if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
		    &data, &data_size,
		    (const uint8_t*)"congestionControl", NULL)) {
			if (0 != data_size && TCP_CA_NAME_MAX > data_size) {
				memcpy(opts->tcp_cc, data, data_size);
				opts->tcp_cc[data_size] = 0;
				opts->tcp_cc_size = (socklen_t)data_size;
				opts->mask |= SO_F_TCP_CONGESTION;
			}
		}
	}

	return (0);
}
#endif /* IO_NET_XML_CONFIG */

void
io_net_skt_opts_init(uint32_t mask, uint32_t bit_vals, skt_opts_p opts) {

	if (NULL == opts)
		return;
	mem_bzero(opts, sizeof(skt_opts_t));
	opts->mask = (SO_F_BIT_VALS_MASK & mask);
	opts->bit_vals = bit_vals;
	opts->backlog = -1;
}

void
io_net_skt_opts_cvt(int mult, skt_opts_p opts) {
	uint32_t dtbl[4] = { 1, 1000, 1000000, 1000000000 };
	uint32_t btbl[4] = { 1, 1024, 1048576, 1073741824 };

	if (NULL == opts || 3 < mult)
		return;
	opts->rcv_buf		*= btbl[mult];
	opts->rcv_lowat		*= btbl[mult];
	opts->rcv_timeout	*= dtbl[mult];
	opts->snd_buf		*= btbl[mult];
	opts->snd_lowat		*= btbl[mult];
	opts->snd_timeout	*= dtbl[mult];
#if defined(TCP_DEFER_ACCEPT)
	//opts->tcp_acc_defer	*= dtbl[mult];
#endif
	//opts->tcp_keep_idle	*= dtbl[mult];
	//opts->tcp_keep_intvl	*= dtbl[mult];
	//opts->tcp_keep_cnt;
}

int
io_net_skt_opts_set_ex(uintptr_t skt, uint32_t mask, skt_opts_p opts,
    uint32_t *err_mask) {
	int error = 0, ival;
	uint32_t error_mask = 0;

	if ((uintptr_t)-1 == skt || NULL == opts)
		return (EINVAL);
	mask &= (opts->mask | SO_F_FAIL_ON_ERR);

	/* SO_F_NONBLOCK */
	if (0 != (SO_F_NONBLOCK & mask)) {
		error = fd_set_nonblocking(skt, (SO_F_NONBLOCK & opts->bit_vals));
		if (0 != error) {
			error_mask |= SO_F_NONBLOCK;
			if (0 != (SO_F_FAIL_ON_ERR & mask))
				goto err_out;
		}
	}
	/* SO_F_HALFCLOSE_RD */
	/* SO_F_HALFCLOSE_WR */
	if (0 != (SO_F_HALFCLOSE_RDWR & mask)) {
		switch ((SO_F_HALFCLOSE_RDWR & mask & opts->bit_vals)) {
		case SO_F_HALFCLOSE_RD:
			ival = shutdown((int)skt, SHUT_RD);
			break;
		case SO_F_HALFCLOSE_WR:
			ival = shutdown((int)skt, SHUT_WR);
			break;
		case SO_F_HALFCLOSE_RDWR:
			ival = shutdown((int)skt, SHUT_RDWR);
			break;
		default:
			ival = 0;
			break;
		}
		if (0 != ival) {
			error = errno;
			error_mask |= (SO_F_HALFCLOSE_RDWR & mask & opts->bit_vals);
			if (0 != (SO_F_FAIL_ON_ERR & mask))
				goto err_out;
		}
	}
	/* SO_F_BACKLOG - not aplly here. */
	/* SO_F_BROADCAST */
	if (0 != (SO_F_BROADCAST & mask)) {
		ival = ((SO_F_BROADCAST & opts->bit_vals) ? 1 : 0);
		if (0 != setsockopt((int)skt, SOL_SOCKET, SO_BROADCAST,
		    &ival, sizeof(ival))) {
			error = errno;
			error_mask |= SO_F_BROADCAST;
			if (0 != (SO_F_FAIL_ON_ERR & mask))
				goto err_out;
		}
	}
	/* SO_F_REUSEADDR */
	if (0 != (SO_F_REUSEADDR & mask)) {
		ival = ((SO_F_REUSEADDR & opts->bit_vals) ? 1 : 0);
		if (0 != setsockopt((int)skt, SOL_SOCKET, SO_REUSEADDR,
		    &ival, sizeof(ival))) {
			error = errno;
			error_mask |= SO_F_REUSEADDR;
			if (0 != (SO_F_FAIL_ON_ERR & mask))
				goto err_out;
		}
	}
#ifdef SO_REUSEPORT
	/* SO_F_REUSEPORT */
	if (0 != (SO_F_REUSEPORT & mask)) {
		ival = ((SO_F_REUSEPORT & opts->bit_vals) ? 1 : 0);
		if (0 != setsockopt((int)skt, SOL_SOCKET, SO_REUSEPORT,
		    &ival, sizeof(ival))) {
			error = errno;
			error_mask |= SO_F_REUSEPORT;
			if (0 != (SO_F_FAIL_ON_ERR & mask))
				goto err_out;
		}
	}
#endif
	/* SO_F_KEEPALIVE */
	if (0 != (SO_F_KEEPALIVE & mask)) {
		ival = ((SO_F_KEEPALIVE & opts->bit_vals) ? 1 : 0);
		if (0 != setsockopt((int)skt, SOL_SOCKET, SO_KEEPALIVE,
		    &ival, sizeof(ival))) {
			error = errno;
			error_mask |= SO_F_KEEPALIVE;
			if (0 != (SO_F_FAIL_ON_ERR & mask))
				goto err_out;
		}
		/* SO_F_TCP_KEEPIDLE */
		if (0 != (SO_F_TCP_KEEPIDLE & mask) &&
		    0 != opts->tcp_keep_idle) {
			if (0 != setsockopt((int)skt, IPPROTO_TCP, TCP_KEEPIDLE,
			    &opts->tcp_keep_idle, sizeof(uint32_t))) {
				error = errno;
				error_mask |= SO_F_TCP_KEEPIDLE;
				if (0 != (SO_F_FAIL_ON_ERR & mask))
					goto err_out;
			}
		}
		/* SO_F_TCP_KEEPINTVL */
		if (0 != (SO_F_TCP_KEEPINTVL & mask) &&
		    0 != opts->tcp_keep_intvl) {
			if (0 != setsockopt((int)skt, IPPROTO_TCP, TCP_KEEPINTVL,
			    &opts->tcp_keep_intvl, sizeof(uint32_t))) {
				error = errno;
				error_mask |= SO_F_TCP_KEEPINTVL;
				if (0 != (SO_F_FAIL_ON_ERR & mask))
					goto err_out;
			}
		}
		/* SO_F_TCP_KEEPCNT */
		if (0 != (SO_F_TCP_KEEPCNT & mask) &&
		    0 != opts->tcp_keep_cnt) {
			if (0 != setsockopt((int)skt, IPPROTO_TCP, TCP_KEEPCNT,
			    &opts->tcp_keep_cnt, sizeof(uint32_t))) {
				error = errno;
				error_mask |= SO_F_TCP_KEEPCNT;
				if (0 != (SO_F_FAIL_ON_ERR & mask))
					goto err_out;
			}
		}
	} /* SO_F_KEEPALIVE */
	/* SO_F_RCVBUF */
	if (0 != (SO_F_RCVBUF & mask) &&
	    0 != opts->rcv_buf) {
		if (0 != setsockopt((int)skt, SOL_SOCKET, SO_RCVBUF,
		    &opts->rcv_buf, sizeof(uint32_t))) {
			error = errno;
			error_mask |= SO_F_RCVBUF;
			if (0 != (SO_F_FAIL_ON_ERR & mask))
				goto err_out;
		}
	}
	/* SO_F_RCVLOWAT */
	if (0 != (SO_F_RCVLOWAT & mask) &&
	    0 != opts->rcv_lowat) {
		if (0 != setsockopt((int)skt, SOL_SOCKET, SO_RCVLOWAT,
		    &opts->rcv_lowat, sizeof(uint32_t))) {
			error = errno;
			error_mask |= SO_F_RCVLOWAT;
			if (0 != (SO_F_FAIL_ON_ERR & mask))
				goto err_out;
		}
	}
	/* SO_F_RCVTIMEO - no set to skt */
	/* SO_F_SNDBUF */
	if (0 != (SO_F_SNDBUF & mask) &&
	    0 != opts->snd_buf) {
		if (0 != setsockopt((int)skt, SOL_SOCKET, SO_SNDBUF,
		    &opts->snd_buf, sizeof(uint32_t))) {
			error = errno;
			error_mask |= SO_F_SNDBUF;
			if (0 != (SO_F_FAIL_ON_ERR & mask))
				goto err_out;
		}
	}
#ifdef BSD /* Linux allways fail on set SO_SNDLOWAT. */
	/* SO_F_SNDLOWAT */
	if (0 != (SO_F_SNDLOWAT & mask) &&
	    0 != opts->snd_lowat) {
		if (0 != setsockopt((int)skt, SOL_SOCKET, SO_SNDLOWAT,
		    &opts->snd_lowat, sizeof(uint32_t))) {
			error = errno;
			error_mask |= SO_F_SNDLOWAT;
			if (0 != (SO_F_FAIL_ON_ERR & mask))
				goto err_out;
		}
	}
#endif /* BSD specific code. */
	/* SO_F_SNDTIMEO - no set to skt */

	/* SO_F_ACC_FILTER */
	if (0 != (SO_F_ACC_FILTER & mask) &&
	    IO_NET_SKT_OPTS_IS_FLAG_ACTIVE(opts, SO_F_ACC_FILTER)) {
#ifdef SO_ACCEPTFILTER
		if (0 != setsockopt((int)skt, SOL_SOCKET, SO_ACCEPTFILTER,
		    &opts->tcp_acc_filter, sizeof(struct accept_filter_arg))) {
#elif defined(TCP_DEFER_ACCEPT)
		if (0 != opts->tcp_acc_defer &&
		    0 != setsockopt((int)skt, IPPROTO_TCP, TCP_DEFER_ACCEPT,
		    &opts->tcp_acc_defer, sizeof(uint32_t))) {
#else
		if (0) {
#endif
			error = errno;
			error_mask |= SO_F_ACC_FILTER;
			if (0 != (SO_F_FAIL_ON_ERR & mask))
				goto err_out;
		}
	}
	/* SO_F_TCP_NODELAY */
	if (0 != (SO_F_TCP_NODELAY & mask)) {
		ival = ((SO_F_TCP_NODELAY & opts->bit_vals) ? 1 : 0);
		if (0 != setsockopt((int)skt, IPPROTO_TCP, TCP_NODELAY,
		    &ival, sizeof(ival))) {
			error = errno;
			error_mask |= SO_F_TCP_NODELAY;
			if (0 != (SO_F_FAIL_ON_ERR & mask))
				goto err_out;
		}
	}
	/* SO_F_TCP_NOPUSH */
	if (0 != (SO_F_TCP_NOPUSH & mask)) {
		ival = ((SO_F_TCP_NOPUSH & opts->bit_vals) ? 1 : 0);
#ifdef TCP_NOPUSH
		if (0 != setsockopt((int)skt, IPPROTO_TCP, TCP_NOPUSH,
		    &ival, sizeof(ival))) {
#elif defined(TCP_CORK)
		if (0 != setsockopt((int)skt, IPPROTO_TCP, TCP_CORK,
		    &ival, sizeof(ival))) {
#else
		if (0) {
#endif
			error = errno;
			error_mask |= SO_F_TCP_NOPUSH;
			if (0 != (SO_F_FAIL_ON_ERR & mask))
				goto err_out;
		}
	}
	/* SO_F_TCP_CONGESTION */
	if (0 != (SO_F_TCP_CONGESTION & mask) &&
	    0 != opts->tcp_cc_size) {
		if (0 != setsockopt((int)skt, IPPROTO_TCP, TCP_CONGESTION,
		    &opts->tcp_cc, opts->tcp_cc_size)) {
			error = errno;
			error_mask |= SO_F_TCP_CONGESTION;
			if (0 != (SO_F_FAIL_ON_ERR & mask))
				goto err_out;
		}
	}

	return (0);

err_out:
	if (NULL != err_mask) {
		(*err_mask) = error_mask;
	}
	return (error);
}

int
io_net_skt_opts_set(uintptr_t skt, uint32_t mask, uint32_t bit_vals) {
	skt_opts_t opts;

	opts.mask = (SO_F_BIT_VALS_MASK & mask);
	opts.bit_vals = bit_vals;
	
	return (io_net_skt_opts_set_ex(skt, mask, &opts, NULL));
}


int
io_net_rcv_tune(uintptr_t skt, uint32_t buf_size, uint32_t lowat) {

	if (0 == lowat) {
		lowat ++;
	}
	if (0 != setsockopt((int)skt, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(int)))
		return (errno);
	if (0 != setsockopt((int)skt, SOL_SOCKET, SO_RCVLOWAT, &lowat, sizeof(int)))
		return (errno);
	return (0);
}

int
io_net_snd_tune(uintptr_t skt, uint32_t buf_size, uint32_t lowat) {

	if (0 == lowat) {
		lowat ++;
	}
	if (0 != setsockopt((int)skt, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(int)))
		return (errno);
#ifdef BSD /* Linux allways fail on set SO_SNDLOWAT. */
	if (0 != setsockopt((int)skt, SOL_SOCKET, SO_SNDLOWAT, &lowat, sizeof(int)))
		return (errno);
#endif /* BSD specific code. */
	return (0);
}

/* Set congestion control algorithm for socket. */
int
io_net_set_tcp_cc(uintptr_t skt, const char *cc, size_t cc_size) {

	if (NULL == cc || 0 == cc_size || TCP_CA_NAME_MAX <= cc_size)
		return (EINVAL);
	if (0 != setsockopt((int)skt, IPPROTO_TCP, TCP_CONGESTION,
	    cc, (socklen_t)cc_size))
		return (errno);
	return (0);
}

int
io_net_get_tcp_cc(uintptr_t skt, char *cc, size_t cc_size, size_t *cc_size_ret) {
	socklen_t optlen;

	if (NULL == cc || 0 == cc_size)
		return (EINVAL);
	optlen = (socklen_t)cc_size;
	if (0 != getsockopt((int)skt, IPPROTO_TCP, TCP_CONGESTION,
	    cc, &optlen))
		return (errno);
	if (NULL != cc_size_ret) {
		(*cc_size_ret) = optlen;
	}
	return (0);
}

/* Check is congestion control algorithm avaible. */
int
io_net_is_tcp_cc_avail(const char *cc, size_t cc_size) {
	uintptr_t skt;
	int res = 0;

	if (NULL == cc || 0 == cc_size || TCP_CA_NAME_MAX <= cc_size)
		return (0);

	skt = (uintptr_t)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if ((uintptr_t)-1 == skt) {
		skt = (uintptr_t)socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP); /* Re try with IPv6 socket. */
	}
	if ((uintptr_t)-1 == skt)
		return (0);
	res = (0 == setsockopt((int)skt, IPPROTO_TCP, TCP_CONGESTION,
	    cc, (socklen_t)cc_size));
	close((int)skt);
	return (res);
}

int
io_net_get_tcp_maxseg(uintptr_t skt, int *val_ret) {
	socklen_t optlen;

	if (NULL == val_ret)
		return (EINVAL);
	optlen = sizeof(int);
	if (0 != getsockopt((int)skt, IPPROTO_TCP, TCP_MAXSEG, val_ret, &optlen))
		return (errno);
	return (0);
}

int
io_net_set_tcp_nodelay(uintptr_t skt, int val) {

	if (0 != setsockopt((int)skt, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val)))
		return (errno);
	return (0);
}

int
io_net_set_tcp_nopush(uintptr_t skt, int val) {

#ifdef TCP_NOPUSH
	if (0 != setsockopt((int)skt, IPPROTO_TCP, TCP_NOPUSH, &val, sizeof(val)))
		return (errno);
#endif
#ifdef TCP_CORK
	if (0 != setsockopt((int)skt, IPPROTO_TCP, TCP_CORK, &val, sizeof(val)))
		return (errno);
#endif
	return (0);
}

int
io_net_set_accept_filter(uintptr_t skt, const char *accf, size_t accf_size) {

	if (NULL == accf || 0 == accf_size)
		return (EINVAL);
#ifdef SO_ACCEPTFILTER
	struct accept_filter_arg afa;

	accf_size = ((sizeof(afa.af_name) - 1) > accf_size) ?
	    accf_size : (sizeof(afa.af_name) - 1);
	memcpy(afa.af_name, accf, accf_size);
	afa.af_name[accf_size] = 0;
	afa.af_arg[0] = 0;
	if (0 != setsockopt((int)skt, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa)))
		return (errno);
#endif
#ifdef TCP_DEFER_ACCEPT
	int ival = (int)accf_size;
	if (0 != setsockopt((int)skt, IPPROTO_TCP, TCP_DEFER_ACCEPT, &ival, sizeof(int)))
		return (errno);
#endif
	return (0);
}



int
io_net_mc_join(uintptr_t skt, int join, uint32_t if_index,
    const struct sockaddr_storage *mc_addr) {
	struct group_req mc_group;

	if (NULL == mc_addr)
		return (EINVAL);

	/* Join/leave to multicast group. */
	mem_bzero(&mc_group, sizeof(mc_group));
	mc_group.gr_interface = if_index;
	sa_copy(mc_addr, &mc_group.gr_group);
	if (0 != setsockopt((int)skt,
	    ((AF_INET == mc_addr->ss_family) ? IPPROTO_IP : IPPROTO_IPV6),
	    ((0 != join) ? MCAST_JOIN_GROUP : MCAST_LEAVE_GROUP),
	    &mc_group, sizeof(mc_group)))
		return (errno);
	return (0);
}

int
io_net_mc_join_ifname(uintptr_t skt, int join, const char *ifname,
    size_t ifname_size, const struct sockaddr_storage *mc_addr) {
	struct ifreq ifr;

	if (NULL == ifname || 0 == ifname_size || IFNAMSIZ < ifname_size)
		return (EINVAL);
	/* if_nametoindex(ifname), but faster - we already have a socket. */
	mem_bzero(&ifr, sizeof(ifr));
	memcpy(ifr.ifr_name, ifname, ifname_size);
	ifr.ifr_name[ifname_size] = 0;
	if (-1 == ioctl((int)skt, SIOCGIFINDEX, &ifr))
		return (errno); /* Cant get if index */
	return (io_net_mc_join(skt, join, (uint32_t)ifr.ifr_ifindex, mc_addr));
}

int
io_net_enable_recv_ifindex(uintptr_t skt, int enable) {
	socklen_t addrlen;
	struct sockaddr_storage ssaddr;

	/* First, we detect socket address family: ipv4 or ipv6. */
	ssaddr.ss_family = 0;
	addrlen = sizeof(ssaddr);
	if (0 != getsockname((int)skt, (struct sockaddr*)&ssaddr, &addrlen))
		return (errno);
	switch (ssaddr.ss_family) {
	case AF_INET:
		if (
#ifdef IP_RECVIF /* FreeBSD */
		    0 != setsockopt((int)skt, IPPROTO_IP, IP_RECVIF, &enable, sizeof(int))
#endif
#if (defined(IP_RECVIF) && defined(IP_PKTINFO))
		    &&
#endif
#ifdef IP_PKTINFO /* Linux/win */
		    0 != setsockopt((int)skt, IPPROTO_IP, IP_PKTINFO, &enable, sizeof(int))
#endif
		)
			return (errno);
		break;
	case AF_INET6:
		if (
#ifdef IPV6_RECVPKTINFO /* Not exist in old versions. */
		    0 != setsockopt((int)skt, IPPROTO_IPV6, IPV6_RECVPKTINFO, &enable, sizeof(int))
#else /* old adv. API */
		    0 != setsockopt((int)skt, IPPROTO_IPV6, IPV6_PKTINFO, &enable, sizeof(int))
#endif
#ifdef IPV6_2292PKTINFO /* "backup", avail in linux. */
		    && 0 != setsockopt((int)skt, IPPROTO_IPV6, IPV6_2292PKTINFO, &enable, sizeof(int))
#endif
		)
			return (errno);
		break;
	default:
		return (EAFNOSUPPORT);
	}
	return (0);
}



int
io_net_socket(int domain, int type, int protocol, uint32_t flags,
    uintptr_t *skt_ret) {
	uintptr_t skt;
	int error, on = 1;

	if (NULL == skt_ret)
		return (EINVAL);
	/* Create blocked/nonblocked socket. */
#ifndef SOCK_NONBLOCK /* Standart / BSD */
	skt = (uintptr_t)socket(domain, type, protocol);
	if ((uintptr_t)-1 == skt)
		return (errno);
	if (0 != (SO_F_NONBLOCK & flags)) {
		error = fd_set_nonblocking(skt, 1);
		if (0 != error)
			goto err_out;
	}
#else /* Linux / FreeBSD10+ */
	if (0 != (SO_F_NONBLOCK & flags)) {
		type |= SOCK_NONBLOCK;
	} else {
		type &= ~SOCK_NONBLOCK;
	}
	skt = (uintptr_t)socket(domain, type, protocol);
	if ((uintptr_t)-1 == skt)
		return (errno);
#endif
	/* Tune socket. */
	if (0 != (SO_F_BROADCAST & flags)) {
		if (0 != setsockopt((int)skt, SOL_SOCKET, SO_BROADCAST,
		    &on, sizeof(int))) {
			error = errno;
			goto err_out;
		}
	}
#ifdef SO_NOSIGPIPE
	setsockopt((int)skt, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(int));
#endif
	if (AF_INET6 == domain) { /* Disable IPv4 via IPv6 socket. */
		setsockopt((int)skt, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(int));
	}

	(*skt_ret) = skt;
	return (0);
	
err_out:
	/* Error. */
	close((int)skt);
	return (error);
}

int
io_net_accept(uintptr_t skt, struct sockaddr_storage *addr, socklen_t *addrlen,
    uint32_t flags, uintptr_t *skt_ret) {
	uintptr_t s;

	if (NULL == skt_ret)
		return (EINVAL);

#ifndef SOCK_NONBLOCK /* Standart / BSD */
	s = accept((int)skt, (struct sockaddr*)addr, addrlen);
	if ((uintptr_t)-1 == s)
		return (errno);
	int error = fd_set_nonblocking(s, (0 != (SO_F_NONBLOCK & flags)));
	if (0 != error) {
		close((int)s);
		return (error);
	}
#else /* Linux / FreeBSD 10 + */
	/*
	 * On Linux, the new socket returned by accept() does not
	 * inherit file status flags such as O_NONBLOCK and O_ASYNC
	 * from the listening socket.
	 */
	s = (uintptr_t)accept4((int)skt, (struct sockaddr*)addr, addrlen,
	    (0 != (SO_F_NONBLOCK & flags)) ? SOCK_NONBLOCK : 0);
	if ((uintptr_t)-1 == s)
		return (errno);
#endif
#ifdef SO_NOSIGPIPE
	int on = 1;
	setsockopt((int)s, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(int));
#endif
	(*skt_ret) = s;
	return (0);
}

int
io_net_bind(const struct sockaddr_storage *addr, int type, int protocol,
    uint32_t flags, uintptr_t *skt_ret) {
	uintptr_t skt = (uintptr_t)-1;
	int error, on = 1;

	if (NULL == addr || NULL == skt_ret)
		return (EINVAL);
		
	error = io_net_socket(addr->ss_family, type, protocol, flags, &skt);
	if (0 != error)
		return (error);
	
	/* Make reusable: we can fail here, but bind() may success. */
	if (0 != (SO_F_REUSEADDR & flags)) {
		setsockopt((int)skt, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));
	}
#ifdef SO_REUSEPORT
	if (0 != (SO_F_REUSEPORT & flags)) {
		setsockopt((int)skt, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(int));
	}
#endif
	if (-1 == bind((int)skt, (const struct sockaddr*)addr, sa_type2size(addr))) { /* Error. */
		error = errno;
		close((int)skt);
		return (error);
	}

	(*skt_ret) = skt;
	return (0);
}

int
io_net_bind_ap(int family, void *addr, uint16_t port,
    int type, int protocol, uint32_t flags, uintptr_t *skt_ret) {
	struct sockaddr_storage sa;

	switch (family) {
	case AF_INET:
		sain4_init(&sa);
		if (NULL != addr) {
			sain4_a_set(&sa, addr);
		}
		sain4_p_set(&sa, port);
		break;
	case AF_INET6:
		sain6_init(&sa);
		if (NULL != addr) {
			sain6_a_set(&sa, addr);
		}
		sain6_p_set(&sa, port);
		break;
	default:
		return (EINVAL);
	}

	return (io_net_bind(&sa, type, protocol, flags, skt_ret));
}

ssize_t
io_net_recvfrom(uintptr_t skt, void *buf, size_t buf_size, int flags,
    struct sockaddr_storage *from, uint32_t *if_index) {
	ssize_t transfered_size;
	struct msghdr mhdr;
	struct iovec rcviov[4];
	struct cmsghdr *cm;
	uint8_t rcvcmsgbuf[1024 +
#if defined(IP_RECVIF) /* FreeBSD */
		CMSG_SPACE(sizeof(struct sockaddr_dl))
#endif
#if defined(IP_PKTINFO) /* Linux/win */
		CMSG_SPACE(sizeof(struct in_pktinfo))
#endif
#if (defined(IP_RECVIF) || defined(IP_PKTINFO))
		+
#endif
		CMSG_SPACE(sizeof(struct in6_pktinfo))
		];

	/* Initialize msghdr for receiving packets. */
	//mem_bzero(&rcvcmsgbuf, sizeof(struct cmsghdr));
	rcviov[0].iov_base = buf;
	rcviov[0].iov_len = buf_size;
	mhdr.msg_name = from; /* dst addr. */
	mhdr.msg_namelen = ((NULL == from) ? 0 : sizeof(struct sockaddr_storage));
	mhdr.msg_iov = rcviov;
	mhdr.msg_iovlen = 1;
	mhdr.msg_control = rcvcmsgbuf;
	mhdr.msg_controllen = sizeof(rcvcmsgbuf);
	mhdr.msg_flags = 0;

	transfered_size = recvmsg((int)skt, &mhdr, flags);
	if (-1 == transfered_size || NULL == if_index)
		return (transfered_size);
	(*if_index) = 0;
	/* Handle additional IP packet data. */
	for (cm = CMSG_FIRSTHDR(&mhdr); NULL != cm; cm = CMSG_NXTHDR(&mhdr, cm)) {
#ifdef IP_RECVIF /* FreeBSD */
		if (IPPROTO_IP == cm->cmsg_level &&
		    IP_RECVIF == cm->cmsg_type &&
		    CMSG_LEN(sizeof(struct sockaddr_dl)) <= cm->cmsg_len) {
			MEMCPY_STRUCT_FIELD(if_index, CMSG_DATA(cm),
			    struct sockaddr_dl, sdl_index);
			break;
		}
#endif
#ifdef IP_PKTINFO /* Linux/win */
		if (IPPROTO_IP == cm->cmsg_level &&
		    IP_PKTINFO == cm->cmsg_type &&
		    CMSG_LEN(sizeof(struct in_pktinfo)) <= cm->cmsg_len) {
			MEMCPY_STRUCT_FIELD(if_index, CMSG_DATA(cm),
			    struct in_pktinfo, ipi_ifindex);
			break;
		}
#endif
		if (IPPROTO_IPV6 == cm->cmsg_level && (
#ifdef IPV6_2292PKTINFO
		    IPV6_2292PKTINFO == cm->cmsg_type ||
#endif
		    IPV6_PKTINFO == cm->cmsg_type) &&
		    CMSG_LEN(sizeof(struct in6_pktinfo)) <= cm->cmsg_len) {
			MEMCPY_STRUCT_FIELD(if_index, CMSG_DATA(cm),
			    struct in6_pktinfo, ipi6_ifindex);
			break;
		}
	}
	return (transfered_size);
}


int
io_net_sendfile(uintptr_t fd, uintptr_t skt, off_t offset, size_t size, int flags,
    off_t *transfered_size) {
	int error = 0;

	/* This is for Linux behavour: zero size - do nothing.
	 * Under Linux save 1 syscall. */
	if (0 == size)
		goto err_out;

#ifdef BSD /* BSD specific code. */
	if (0 == sendfile((int)fd, (int)skt, offset, size, NULL, transfered_size, flags))
		return (0); /* OK. */
	/* Error, but some data possible transfered. */
	/* transfered_size - is set by sendfile() */
	return (errno);
#endif /* BSD specific code. */
#ifdef __linux__ /* Linux specific code. */
	ssize_t ios = sendfile((int)skt, (int)fd, &offset, size);
	if (-1 != ios) { /* OK. */
		if (NULL != transfered_size) {
			(*transfered_size) = (off_t)ios;
		}
		return (0);
	}
	/* Error. */
	error = errno;
#endif /* Linux specific code. */

err_out:
	if (NULL != transfered_size) {
		(*transfered_size) = 0;
	}
	return (error);
}


int
io_net_listen(uintptr_t skt, int backlog) {

	if (-1 == listen((int)skt, backlog))
		return (errno);
	return (0);
}

int
io_net_connect(const struct sockaddr_storage *addr, int type, int protocol,
    uint32_t flags, uintptr_t *skt_ret) {
	uintptr_t skt;
	int error;

	if (NULL == addr || NULL == skt_ret)
		return (EINVAL);

	error = io_net_socket(addr->ss_family, type, protocol, flags, &skt);
	if (0 != error)
		return (error);
	if (-1 == connect((int)skt, (const struct sockaddr*)addr, sa_type2size(addr))) {
		error = errno;
		if (EINPROGRESS != error && EINTR != error) { /* Error. */
			close((int)skt);
			return (error);
		}
	}

	(*skt_ret) = skt;
	return (0);
}

int
io_net_is_connect_error(int error) {

	switch (error) {
#ifdef BSD /* BSD specific code. */
	case EADDRNOTAVAIL:
	case ECONNRESET:
	case EHOSTUNREACH:
#endif /* BSD specific code. */
	case EADDRINUSE:
	case ETIMEDOUT:
	case ENETUNREACH:
	case EALREADY:
	case ECONNREFUSED:
	case EISCONN:
		return (1);
	}
	return (0);
}


/*
 * Very simple resolver
 * work slow, block thread, has no cache
 * ai_family: PF_UNSPEC, AF_INET, AF_INET6
 */
int
io_net_sync_resolv(const char *hname, uint16_t port, int ai_family,
    struct sockaddr_storage *addrs, size_t addrs_count, size_t *addrs_count_ret) {
	int error;
	size_t i;
	struct addrinfo hints, *res, *res0;
	char servname[8];

	if (NULL == hname)
		return (EINVAL);
	mem_bzero(&hints, sizeof(hints));
	hints.ai_family = ai_family;
	hints.ai_flags = AI_NUMERICSERV;
	snprintf(servname, sizeof(servname), "%hu", port);
	error = getaddrinfo(hname, servname, &hints, &res0);
	if (0 != error)  /* NOTREACHED */
		return (error);
	for (i = 0, res = res0; NULL != res && i < addrs_count; res = res->ai_next, i ++) {
		if (AF_INET != res->ai_family &&
		    AF_INET6 != res->ai_family)
			continue;
		sa_copy(res->ai_addr, &addrs[i]);
	}
	freeaddrinfo(res0);
	if (NULL != addrs_count_ret) {
		(*addrs_count_ret) = i;
	}
	return (0);
}

int
io_net_sync_resolv_connect(const char *hname, uint16_t port,
    int domain, int type, int protocol, uintptr_t *skt_ret) {
	int error = 0;
	uintptr_t skt = (uintptr_t)-1;
	struct addrinfo hints, *res, *res0;
	char servname[8];

	if (NULL == hname || NULL == skt_ret)
		return (EINVAL);
	mem_bzero(&hints, sizeof(hints));
	hints.ai_family = domain;
	hints.ai_flags = AI_NUMERICSERV;
	hints.ai_socktype = type;
	hints.ai_protocol = protocol;
	snprintf(servname, sizeof(servname), "%hu", port);
	error = getaddrinfo(hname, servname, &hints, &res0);
	if (0 != error)  /* NOTREACHED */
		return (error);
	for (res = res0; NULL != res; res = res->ai_next) {
		error = io_net_socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol, 0, &skt);
		if (0 != error)
			continue;
		if (connect((int)skt, res->ai_addr, res->ai_addrlen) < 0) {
			error = errno;
			close((int)skt);
			skt = (uintptr_t)-1;
			continue;
		}
		break;  /* okay we got one */
	}
	freeaddrinfo(res0);
	if ((uintptr_t)-1 == skt)
		return (error);
	(*skt_ret) = skt;
	return (0);
}

