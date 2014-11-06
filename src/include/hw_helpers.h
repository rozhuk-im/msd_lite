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


#ifndef __HW_HELPERS_H__
#define __HW_HELPERS_H__


#include <sys/param.h>

#ifdef __linux__ /* Linux specific code. */
#define _GNU_SOURCE /* See feature_test_macros(7) */
#define __USE_GNU 1
#endif /* Linux specific code. */

#include <sys/types.h>
#include <sys/ioctl.h>

#include <inttypes.h>
#include <cpuid.h>


#ifdef BSD /* BSD specific code. */
#include <sys/disk.h>
#include <sys/mount.h>
#endif /* BSD specific code. */

#ifdef __linux__ /* Linux specific code. */
#include <stdio.h>
#include <string.h>
#include <mntent.h>
#include <linux/hdreg.h>
#endif /* Linux specific code. */
#define DISK_IDENT_STR_SIZE 20
#define CPU_BRAND_STR_SIZE 48



static inline void
native_cpuid(uint32_t index, uint32_t *eax, uint32_t *ebx, uint32_t *ecx,
    uint32_t *edx) {

#if 1
	__asm__ __volatile__(
		"cpuid			\n\t"
		: "=a"((*eax)), "=b"((*ebx)), "=c"((*ecx)), "=d"((*edx))
		: "0"(index)
	);
#else
	__cpuid(index, (*eax), (*ebx), (*ecx), (*edx));
#endif
}

/* buf - must pont to mem, size 48 or more. */
static inline int
get_cpu_brand_str(char *buf) {
	uint32_t regs[12];

	if (NULL == buf)
		return (EINVAL);
	/* Get Highest Extended Function Supported */
	native_cpuid(0x80000000, &regs[0], &regs[1], &regs[2], &regs[3]);
	if (0x80000004 > regs[0]) {
		buf[0] = 0;
		return (ENODEV);
	}
	/* Processor Brand String */
	native_cpuid(0x80000002, &regs[0], &regs[1], &regs[2], &regs[3]);
	native_cpuid(0x80000003, &regs[4], &regs[5], &regs[6], &regs[7]);
	native_cpuid(0x80000004, &regs[8], &regs[9], &regs[10], &regs[11]);
	memcpy(buf, regs, sizeof(regs));
	return (0);
}

/* Return device name mounted to / */
static inline int
get_root_drive_dev_str(char *buf) {
	int error;

	if (NULL == buf)
		return (EINVAL);
	buf[0] = 0;
#ifdef BSD /* BSD specific code. */
	struct statfs sfs;

	error = statfs("/", &sfs);
	if (0 == error) {
		memcpy(buf, sfs.f_mntfromname, sizeof(sfs.f_mntfromname));
		buf[sizeof(sfs.f_mntfromname)] = 0;
	}
#endif /* BSD specific code. */
#ifdef __linux__ /* Linux specific code. */
	FILE *mtab;
	struct mntent *mnt;

	mtab = setmntent("/etc/mtab", "r");// _PATH_MNTTAB
	if (NULL == mtab)
		return (errno);
	error = ENOENT;
	while (NULL != (mnt = getmntent(mtab))) {
		if (0 != memcmp(mnt->mnt_dir, "/", 2))
			continue;
		strcpy(buf, mnt->mnt_fsname);
		error = 0;
		break;
	}
	endmntent(mtab);
#endif /* Linux specific code. */
	return (error);
}

/* Device serial, buf must point to mem size 20 = DISK_IDENT_STR_SIZE or more. */
static inline int
get_drive_id(const char *dirve, char *buf) {
	int fd, error;
	
	if (NULL == dirve || NULL == buf)
		return (EINVAL);
	buf[0] = 0;
	fd = open(dirve, O_RDONLY);
	if (0 > fd)
		return (errno);
#ifdef DIOCGIDENT /* BSD */
	char tmbuf[DISK_IDENT_SIZE];
	error = ioctl(fd, DIOCGIDENT, tmbuf); // DIOCGDESCR
	if (0 == error) {
		memcpy(buf, tmbuf, DISK_IDENT_STR_SIZE);
		buf[DISK_IDENT_STR_SIZE] = 0;
	}
#endif
#ifdef HDIO_GET_IDENTITY /* Linux */
	struct hd_driveid hd;
	error = ioctl(fd, HDIO_GET_IDENTITY, &hd);
	if (0 == error) {
		memcpy(buf, hd.serial_no, DISK_IDENT_STR_SIZE);
		buf[DISK_IDENT_STR_SIZE] = 0;
	}
#endif
	close(fd);
	return (error);
}




#if 0
#include </usr/src/sys/cam/scsi/scsi_all.h>
#include </usr/src/sys/cam/scsi/scsi_sg.h>
#define SG_INFO_OK_MASK 0x1
#define SG_INFO_OK 0x0

static inline int
scsi_get_serial(int fd, void *buf, size_t buf_len) {
	// we shall retrieve page 0x80 as per http://en.wikipedia.org/wiki/SCSI_Inquiry_Command
	uint8_t inq_cmd[6] = {INQUIRY, 1, 0x80, 0, buf_len, 0};
	uint8_t sense[32];
	struct sg_io_hdr io_hdr;
	    int result;

	memset(&io_hdr, 0, sizeof(io_hdr));
	io_hdr.interface_id = 'S';
	io_hdr.cmdp = inq_cmd;
	io_hdr.cmd_len = sizeof(inq_cmd);
	io_hdr.dxferp = buf;
	io_hdr.dxfer_len = buf_len;
	io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
	io_hdr.sbp = sense;
	io_hdr.mx_sb_len = sizeof(sense);
	io_hdr.timeout = 5000;

	result = ioctl(fd, SG_IO, &io_hdr);
	if (result < 0)
		return result;

	if ((io_hdr.info & SG_INFO_OK_MASK) != SG_INFO_OK)
		return 1;
	return 0;
}
#endif

#if 0
#include <cam/cam.h>
#include <cam/scsi/scsi_all.h>
#include <cam/cam_ccb.h>
#include <cam/scsi/scsi_pass.h>


void	cam_xxxx_strvis(u_int8_t *dst, const u_int8_t *src, size_t srclen, size_t dstlen);
static struct cam_device *cam_xxxxx_open_device(const char *path, int flags);

void
cam_xxxx_strvis(u_int8_t *dst, const u_int8_t *src, size_t srclen, size_t dstlen) {

	/* Trim leading/trailing spaces, nulls. */
	while (srclen > 0 && src[0] == ' ')
		src++, srclen--;
	while (srclen > 0
	    && (src[srclen-1] == ' ' || src[srclen-1] == '\0'))
		srclen--;

	while (srclen > 0 && dstlen > 1) {
		u_int8_t *cur_pos = dst;

		if (*src < 0x20 || *src >= 0x80) {
			/* SCSI-II Specifies that these should never occur. */
			/* non-printable character */
			if (dstlen > 4) {
				*cur_pos++ = '\\';
				*cur_pos++ = ((*src & 0300) >> 6) + '0';
				*cur_pos++ = ((*src & 0070) >> 3) + '0';
				*cur_pos++ = ((*src & 0007) >> 0) + '0';
			} else {
				*cur_pos++ = '?';
			}
		} else {
			/* normal character */
			*cur_pos++ = *src;
		}
		src++;
		srclen--;
		dstlen -= cur_pos - dst;
		dst = cur_pos;
	}
	*dst = '\0';
}


/*
 * Open a given device.  The path argument isn't strictly necessary, but it
 * is copied into the cam_device structure as a convenience to the user.
 */
static struct cam_device *
cam_xxxxx_open_device(const char *path, int flags) {
	union ccb ccb;
	int fd = -1;
	char vendor[255], product[255], revision[255], fw[255];
	struct sep_identify_data *sid;

	if ((fd = open(path, flags)) < 0) {
		printf("open(path, flags) FAIL, errno=%d, %s\n", errno, strerror(errno));
		goto crod_bailout;
	}
	memset(&ccb, 0, sizeof(ccb));

	/*
	 * Unlike the transport layer version of the GETPASSTHRU ioctl,
	 * we don't have to set any fields.
	 */
	//ccb.ccb_h.func_code = XPT_GDEVLIST;
	
	/*
	 * We're only doing this to get some information on the device in
	 * question.  Otherwise, we'd have to pass in yet another
	 * parameter: the passthrough driver unit number.
	 */
	/*if (ioctl(fd, CAMGETPASSTHRU, &ccb) == -1) {
		printf("ioctl(fd, CAMGETPASSTHRU, &ccb) FAIL, errno=%d, %s\n", errno, strerror(errno));
		goto crod_bailout;
	}//*/
	/*
	 * If the ioctl returned the right status, but we got an error back
	 * in the ccb, that means that the kernel found the device the user
	 * passed in, but was unable to find the passthrough device for
	 * the device the user gave us.
	 */
	/*if (ccb.cgdl.status == CAM_GDEVLIST_ERROR) {
		printf("passthrough device does not exist!\n");
		goto crod_bailout;
	}//*/
	/*ccb.ccb_h.func_code = XPT_PATH_INQ;
	if (ioctl(fd, CAMIOCOMMAND, &ccb) == -1) {
		printf("ioctl(fd, CAMIOCOMMAND, &ccb) Path Inquiry CCB failed, errno=%d, %s\n", errno, strerror(errno));
		goto crod_bailout;
	}//*/


	/*
	 * It doesn't really matter what is in the payload for a getdev
	 * CCB, the kernel doesn't look at it.
	 */
	ccb.ccb_h.func_code = XPT_GDEV_TYPE;
	if (ioctl(fd, CAMIOCOMMAND, &ccb) == -1) {
		printf("ioctl(fd, CAMIOCOMMAND, &ccb) FAIL, errno=%d, %s\n", errno, strerror(errno));
		goto crod_bailout;
	}//*/

	switch (ccb.cgd.protocol) {
	case PROTO_UNKNOWN:
		printf("PROTO_UNKNOWN\n");
		break;
	case PROTO_UNSPECIFIED:
		printf("PROTO_UNSPECIFIED\n");
		break;
	case PROTO_SCSI:
		printf("PROTO_SCSI Small Computer System Interface\n");
		//scsi_print_inquiry(&ccb.cgd.inq_data);
		cam_xxxx_strvis((u_int8_t*)vendor, (u_int8_t*)&ccb.cgd.inq_data.vendor,
		   sizeof(ccb.cgd.inq_data.vendor),
		   sizeof(vendor));
		cam_xxxx_strvis((u_int8_t*)product, (u_int8_t*)&ccb.cgd.inq_data.product,
		   sizeof(ccb.cgd.inq_data.product),
		   sizeof(product));
		cam_xxxx_strvis((u_int8_t*)revision, (u_int8_t*)&ccb.cgd.inq_data.revision,
		   sizeof(ccb.cgd.inq_data.revision),
		   sizeof(revision));
		printf("vendor %s\n", vendor);
		printf("product %s\n", product);
		printf("revision %s\n", revision);
		break;
	case PROTO_ATA:
		printf("PROTO_ATA AT Attachment\n");
		break;
	case PROTO_ATAPI:
		printf("PROTO_ATAPI AT Attachment Packetized Interface\n");
		break;
	case PROTO_SATAPM:
		printf("PROTO_SATAPM SATA Port Multiplier\n");
		break;
	case PROTO_SEMB:
		printf("PROTO_SEMB Small Computer System Interface\n");
		sid = (struct sep_identify_data *)&ccb.cgd.ident_data;
		cam_xxxx_strvis((u_int8_t*)vendor, (u_int8_t*)sid->vendor_id,
		    sizeof(sid->vendor_id),
		    sizeof(vendor));
		cam_xxxx_strvis((u_int8_t*)product, (u_int8_t*)sid->product_id,
		    sizeof(sid->product_id),
		    sizeof(product));
		cam_xxxx_strvis((u_int8_t*)revision, (u_int8_t*)sid->product_rev,
		    sizeof(sid->product_rev),
		    sizeof(revision));
		cam_xxxx_strvis((u_int8_t*)fw, (u_int8_t*)sid->firmware_rev,
		    sizeof(sid->firmware_rev),
		    sizeof(fw));
		printf("vendor %s\n", vendor);
		printf("product %s\n", product);
		printf("revision %s\n", revision);
		printf("fw %s\n", fw);
		break;
	}
	switch (ccb.cgd.protocol) {
	case PROTO_ATA:
	case PROTO_ATAPI:
	case PROTO_SATAPM:
		cam_xxxx_strvis((u_int8_t*)product, (u_int8_t*)&ccb.cgd.ident_data.model,
		   sizeof(ccb.cgd.ident_data.model),
		   sizeof(product));
		cam_xxxx_strvis((u_int8_t*)revision, (u_int8_t*)&ccb.cgd.ident_data.revision,
		   sizeof(ccb.cgd.ident_data.revision),
		   sizeof(revision));
		printf("product %s\n", product);
		printf("revision %s\n", revision);
		cam_xxxx_strvis((u_int8_t*)fw, (u_int8_t*)&ccb.cgd.ident_data.serial,
		   sizeof(ccb.cgd.ident_data.serial),
		   sizeof(fw));
		printf("serial %s\n", fw);
	}
	printf("serial_num %s\n", (char*)&ccb.cgd.serial_num);

crod_bailout:

	if (fd >= 0)
		close(fd);

	return (NULL);
}
#endif


#if 0
{
	const char *drive = "/dev/ada0";
	int fd;
	char scsi_serial[256];

	fd = open(drive, (O_RDONLY | O_NONBLOCK));
	if (0 > fd)
		return (errno);
	memset(scsi_serial, 0, sizeof(scsi_serial));
	error = scsi_get_serial(fd, scsi_serial, (sizeof(scsi_serial) - 1));
	// scsi_serial[3] is the length of the serial number
	// scsi_serial[4] is serial number (raw, NOT null terminated)
	if (error < 0) {
		printf("FAIL, rc=%d, errno=%d, %s\n", error, errno, strerror(errno));
	} else if (error == 1) {
		printf("FAIL, rc=%d, drive doesn't report serial number\n", error);
	} else {
		if (!scsi_serial[3]) {
			printf("Failed to retrieve serial for %s\n", drive);
			return -1;
		}
		printf("Serial Number: %.*s\n",
		    (size_t)scsi_serial[3], (char *) & scsi_serial[4]);
	}
	close(fd);

	cam_xxxxx_open_device("/dev/pass0", O_RDWR);

}
#endif




#endif /* __HW_HELPERS_H__ */
