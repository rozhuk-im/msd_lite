# Process this file with autoconf to produce a configure script.


AC_INIT([msd_lite], [1.07], [rozhuk.im@gmail.com], [msd_lite], [http://www.netlab.linkpc.net/])
AC_CONFIG_SRCDIR([src/msd_lite.c])
AC_CONFIG_HEADER([src/config.h])
AM_INIT_AUTOMAKE

AC_PREFIX_DEFAULT([/usr/local])


AC_PROG_INSTALL
CFLAGS=""
AC_PROG_CC
AM_PROG_CC_C_O

AC_LANG_C

AC_CHECK_LIB(pthread, pthread_create,,AC_MSG_ERROR(requires pthread))
AC_CHECK_FUNCS([clock_gettime],,
               [AC_CHECK_LIB(rt, clock_gettime,,AC_MSG_ERROR(requires rt))])


AC_OUTPUT([Makefile] [src/Makefile])
