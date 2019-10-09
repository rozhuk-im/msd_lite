/*-
 * Copyright (c) 2013 - 2016 Rozhuk Ivan <rozhuk.im@gmail.com>
 * All rights reserved.
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

#include <stdlib.h> /* malloc, exit */
#include <unistd.h> /* close, write, sysconf */
#include <fcntl.h> // open
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <stdio.h> /* for snprintf, fprintf */
#include <time.h>
#include <errno.h>
#include <dirent.h> // opendir, readdir

#include "mem_helpers.h"
#include "StrToNum.h"
#include "HTTP.h"
#include "xml.h"

#include "macro_helpers.h"
#include "core_io_buf.h"
#include "core_log.h"
#include "core_upnp_base.h"
#include "core_upnp.h"
#include "core_upnp_svc_cntnt_dir.h"



int		upnp_browse(uint8_t *req_data, size_t req_data_size, io_buf_p buf,
		    uint32_t *num_ret, uint32_t *tot_mach, uint32_t *upd_id);


int
upnp_svc_cntnt_dir_ctrl_cb(upnp_device_p dev __unused, upnp_service_p svc __unused,
    http_srv_cli_p cli, int action,
    uint8_t *req_data, size_t req_data_size) {
	char *ptm;
	size_t tm = 0;
	io_buf_p buf;
	uint32_t num_ret = 0, tot_mach = 0, upd_id = 0;

	switch (action) {
	case CNTNT_DIR_ACTION_GetSearchCapabilities: /* GetSearchCapabilities */
		IO_BUF_PRINTF(cli->buf,
		    "			<SearchCaps></SearchCaps>\n");
		return (200);
		break;
	case CNTNT_DIR_ACTION_GetSortCapabilities: /* GetSortCapabilities */
		IO_BUF_PRINTF(cli->buf,
		    "			<SortCaps>dc:title</SortCaps>\n");
		return (200);
		break;
	//case 2: /* GetSortExtensionCapabilities */
	//case 3: /* GetFeatureList */
	case CNTNT_DIR_ACTION_GetSystemUpdateID: /* GetSystemUpdateID */
		IO_BUF_PRINTF(cli->buf,
		    "			<Id>%"PRIu32"</Id>\n",
		    6);
		return (200);
		break;
	//case 5: /* GetServiceResetToken */
	case CNTNT_DIR_ACTION_Browse: /* Browse */
	case CNTNT_DIR_ACTION_Search: /* Search */
		cli->buf = io_buf_realloc(cli->buf, (4 * 1024 * 1024));
		buf = io_buf_alloc((4 * 1024 * 1024));
		IO_BUF_PRINTF(cli->buf,
		    "			<Result>");
		/* Encapsulated xml. */
		IO_BUF_PRINTF(buf,
		    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		    "<DIDL-Lite\n"
		    " xmlns:dc=\"http://purl.org/dc/elements/1.1/\"\n"
		    " xmlns=\"urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/\"\n"
		    " xmlns:upnp=\"urn:schemas-upnp-org:metadata-1-0/upnp/\"\n"
		    " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n"
		    " xsi:schemaLocation=\"\n"
		    "	urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/ http://www.upnp.org/schemas/av/didl-lite.xsd\n"
		    "	urn:schemas-upnp-org:metadata-1-0/upnp/ http://www.upnp.org/schemas/av/upnp.xsd\">\n");
#if 0
		// ...
		IO_BUF_PRINTF(buf,
		    "	<item id=\"1\" parentID=\"-1\" restricted=\"0\">\n"
		    "		<dc:title>Ace of Base - Adventures in Paradise</dc:title>\n"
		    "		<dc:creator>Ace of Base</dc:creator>\n"
		    "		<upnp:class>object.item.audioItem.musicTrack</upnp:class>\n"
		    "		<res protocolInfo=\"http-get:*:audio/mpeg:*\" size=\"70000\">http://172.16.0.254/DataStore/Music/Music/Ace of Base/Ace of Base - Adventures in Paradise.mp3</res>\n"
		    "	</item>\n");
		IO_BUF_PRINTF(buf,
		    "	<item id=\"2\" parentID=\"-1\" restricted=\"0\">\n"
		    "		<dc:title>Playlist of John and Mary's music</dc:title>\n"
		    "		<dc:creator>John Jones</dc:creator>\n"
		    "		<upnp:class>object.item.playlistItem</upnp:class>\n"
		    "		<res protocolInfo=\"http-get:*:audio/m3u:*\">http://172.16.0.254:80/download/Samsung_TV/Playlists/iptv_mc_ttk.m3u</res>\n"
		    "	</item>\n");
		IO_BUF_PRINTF(buf,
		    "	<item id=\"3\" parentID=\"-1\" restricted=\"0\">\n"
		    "		<dc:title>Playlist of John and Mary's music</dc:title>\n"
		    "		<dc:creator>John Jones</dc:creator>\n"
		    "		<upnp:class>object.item.playlistItem</upnp:class>\n"
		    "		<res protocolInfo=\"http-get:*:video/m3u:*\">http://172.16.0.254:80/download/Samsung_TV/Playlists/iptv_mc_ttk.m3u</res>\n"
		    "	</item>\n");
		IO_BUF_PRINTF(buf,
		    "	<item id=\"4\" parentID=\"-1\" restricted=\"0\">\n"
		    "		<dc:title>RED</dc:title>\n"
		    "		<dc:creator>Rozhuk Ivan</dc:creator>\n"
		    "		<upnp:class>object.item.videoItem</upnp:class>\n"
		    "		<res protocolInfo=\"http-get:*:video/x-mkv:*\">http://172.16.0.254/DataStore/Video/Films/!Ivan/Red.2010.BD.Remux.1080p.h264.2xRus.Eng.Commentary.mkv</res>\n"
		    "	</item>\n");
		IO_BUF_PRINTF(buf,
		    "	<item id=\"5\" parentID=\"-1\" restricted=\"0\">\n"
		    "		<dc:title>IPTV</dc:title>\n"
		    "		<dc:creator>Rozhuk Ivan</dc:creator>\n"
		    "		<upnp:class>object.item.videoItem</upnp:class>\n"
		    "		<res protocolInfo=\"http-get:*:video/mpeg:*\">http://172.16.0.254:7088/udp/239.0.1.3:1234</res>\n"
		    "	</item>\n");
		IO_BUF_PRINTF(buf,
		    "	<item id=\"6\" parentID=\"-1\" restricted=\"0\">\n"
		    "		<dc:title>IPTV - udp</dc:title>\n"
		    "		<dc:creator>Rozhuk Ivan</dc:creator>\n"
		    "		<upnp:class>object.item.videoItem.videoBroadcast</upnp:class>\n"
		    "		<upnp:icon>http://172.16.0.254:80/download/tmp/image/karusel.png</upnp:icon>\n"
		    "		<res protocolInfo=\"http-get:*:video/mpeg:*\">udp://@239.0.1.3:1234</res>\n"
		    "	</item>\n");
#endif
		upnp_browse(req_data, req_data_size, buf, &num_ret, &tot_mach, &upd_id);
		IO_BUF_PRINTF(buf,
		    "</DIDL-Lite>\n");
	
		/*fprintf(stderr, buf->data);//*/
		xml_encode(buf->data, buf->used, IO_BUF_FREE_GET(cli->buf),
		    IO_BUF_FREE_SIZE(cli->buf), &tm);
		io_buf_free(buf);
		IO_BUF_INC_USED(cli->buf, tm);
		/* End of encapsulated xml. */
		IO_BUF_PRINTF(cli->buf,
		    "</Result>\n"
		    "			<NumberReturned>%"PRIu32"</NumberReturned>\n"
		    "			<TotalMatches>%"PRIu32"</TotalMatches>\n"
		    "			<UpdateID>%"PRIu32"</UpdateID>\n",
		    num_ret, tot_mach, upd_id);
		return (200);
		break;
	//case 8: /* CreateObject */
	//case 9: /* DestroyObject */
	//case 10: /* UpdateObject */
	//case 11: /* MoveObject */
	//case 12: /* ImportResource */
	//case 13: /* ExportResource */
	//case 14: /* DeleteResource */
	//case 15: /* StopTransferResource */
	//case 16: /* GetTransferProgress */
	//case 17: /* CreateReference */
	//case 18: /* FreeFormQuery */
	//case 19: /* GetFreeFormQueryCapabilities */
	case CNTNT_DIR_ACTION_X_GetFeatureList: /* X_GetFeatureList - samsung */
		ptm =
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		"<Features xmlns=\"urn:schemas-upnp-org:av:avs\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"urn:schemas-upnp-org:av:avs http://www.upnp.org/schemas/av/avs.xsd\">\n"
		"	<Feature name=\"samsung.com_BASICVIEW\" version=\"1\">\n"
		"		<container id=\"I\" type=\"object.item.imageItem\"/>\n"
		"		<container id=\"A\" type=\"object.item.audioItem\"/>\n"
		"		<container id=\"V\" type=\"object.item.videoItem\"/>\n"
		"		<container id=\"P\" type=\"object.item.playlistItem\"/>\n"
		"	</Feature>\n"
		"</Features>\n";
		xml_encode((uint8_t*)ptm, strlen(ptm),
		    IO_BUF_FREE_GET(cli->buf),
		    IO_BUF_FREE_SIZE(cli->buf), &tm);
		IO_BUF_INC_USED(cli->buf, tm);
		return (200);
		break;
	}

	return (602);
}




int
upnp_browse(uint8_t *req_data, size_t req_data_size, io_buf_p buf,
    uint32_t *num_ret, uint32_t *tot_mach, uint32_t *upd_id) {
	int root_fd, fd;
	DIR *d;
	struct dirent *de;
	char *path, path_buf[4096] = {0}, url[4096], *val;
	size_t path_size = 0, val_size = 0;
	uint32_t num_r = 0, t_mach = 0;

	path = &path_buf[1];
	//req_data[req_data_size] = 0;
	LOG_EV_FMT("req_data: %zu: %s", req_data_size, req_data);
	root_fd = open("/usr/data/", O_RDONLY);
	snprintf(url, sizeof(url), "http://172.16.0.254/DataStore/");
#if 0
	if (0 == xml_get_val_ns_args(req_data, req_data_size, NULL,
	    NULL, NULL, NULL, NULL, &val, &val_size,
	    (const uint8_t*)"ObjectID", NULL)){// &&
	    //0 != mem_cmpn_cstr("0", val, val_size)) {
		memcpy(path, val, val_size);
		path_size = val_size;
		path[path_size] = 0;
		LOG_EV_FMT("ObjectID: %s", path);
	}
#endif
	if (0 == xml_get_val_args(req_data, req_data_size, NULL,
	    NULL, NULL, (uint8_t **)&val, &val_size,
	    (const uint8_t*)"ObjectID", NULL) &&
	    0 != mem_cmpn_cstr("0", val, val_size)) {
		path_buf[0] = '.';
		memcpy(path, val, val_size);
		path_size = val_size;
		path[path_size] = 0;
		LOG_EV_FMT("ObjectID: %s", path_buf);
		fd = openat(root_fd, path_buf, O_RDONLY);
		if (-1 == fd)
			LOG_ERR(errno, "openat");
	} else {
		fd = dup(root_fd);
		LOG_EV_FMT("Browse: %s", path);
	}

	//d = opendir(path);
	d = fdopendir(fd);
	if (NULL == d)
		return 1;

	while (NULL != (de = readdir(d))) {
		if (0 == mem_cmpn_cstr(".", de->d_name, _D_EXACT_NAMLEN(de)) ||
		    0 == mem_cmpn_cstr("..", de->d_name, _D_EXACT_NAMLEN(de)))
			continue;
		switch (de->d_type) {
		case DT_DIR:
		case DT_LNK:
			IO_BUF_PRINTF(buf,
			    "	<container id=\"%s/%s\" parentID=\"%s\" restricted=\"0\">\n"
			    "		<dc:title>%s</dc:title>\n"
			    "		<upnp:class>object.container.storageFolder</upnp:class>\n"
			    "	</container>\n",
			    path, de->d_name, ((0 == path_size) ? "0" : path),
			    de->d_name);
			num_r ++;
			break;
		default:
			IO_BUF_PRINTF(buf,
			    "	<item id=\"%s/%s\" parentID=\"%s\" restricted=\"0\">\n"
			    "		<dc:title>%s</dc:title>\n"
			//    "		<dc:creator>Rozhuk Ivan</dc:creator>\n"
			    "		<upnp:class>object.item.videoItem</upnp:class>\n"
			    "		<res protocolInfo=\"http-get:*:video/mpeg:*\">%s%s/%s</res>\n"
			    "	</item>\n",
			    path, de->d_name, path,
			    de->d_name,
			    url, path, de->d_name);
			num_r ++;
			break;
		}
	}
	closedir(d);
	close(root_fd);
	
	t_mach = num_r;
	(*num_ret) = num_r;
	(*tot_mach) = t_mach;
	(*upd_id) = 1;//time(NULL);
	
	return (0);
}








