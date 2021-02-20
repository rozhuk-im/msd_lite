AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS = msd_lite
msd_lite_SOURCES = msd_lite.c msd_lite_stat_text.c stream_sys.c src/core_http_srv.c src/xml.c src/HTTP.c src/core_r_buf.c src/core_thrp.c src/core_io_task.c src/core_io_net.c src/core_log.c src/core_helpers.c src/core_net_helpers.c src/core_info.c 

AM_LDFLAGS	= ${LDFLAGS} ${OSLIBS}
#AM_CFLAGS	= -I $(srcdir)/include/ -pipe -O0 -g -DDEBUG -DHTTP_SRV_XML_CONFIG -Wall -W -Wcast-align -Wchar-subscripts -Wformat -Winline -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -Wpointer-arith -Wwrite-strings -Wcast-align -Wsign-compare -Wformat-security -fstack-protector -fomit-frame-pointer -fPIE 
AM_CFLAGS	= -I $(srcdir)/include/ -pipe -O2 -DNDEBUG -DHTTP_SRV_XML_CONFIG -fstack-protector -fomit-frame-pointer -fPIE -ffast-math
#AM_CFLAGS	= -I $(srcdir)/include/ -pipe -O3 -DNDEBUG -DHTTP_SRV_XML_CONFIG -fstack-protector -fomit-frame-pointer -fPIE -funroll-loops
#AM_CFLAGS	= -I $(srcdir)/include/ -pipe -Os -DNDEBUG -DHTTP_SRV_XML_CONFIG


