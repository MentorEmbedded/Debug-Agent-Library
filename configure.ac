dnl Autoconf configure script for AGENT.NAME.
dnl
dnl Copyright (C) 2012 Free Software Foundation, Inc.
dnl
dnl This file is part of AGENT.NAME.
dnl
dnl This library is free software; you can redistribute it and/or
dnl modify it under the terms of the GNU Lesser General Public
dnl License version 2.1 as published by the Free Software Foundation.
dnl
dnl This library is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl Lesser General Public License for more details.
dnl
dnl You should have received a copy of the GNU Lesser General Public
dnl License along with this library; if not, write to the Free Software
dnl Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA


AC_PREREQ(2.59)
AC_INIT([libdagent], [0.1], [])

AC_CONFIG_AUX_DIR([config])

AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE([foreign])

AC_GNU_SOURCE

AC_PROG_CC
AC_PROG_LIBTOOL

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES([Makefile])

# Check the target.
target_amd64=
target_i386=

case $target_cpu in
     x86_64)
	target_amd64="yes";;
     i*86)
	target_i386="yes";;
esac

AM_CONDITIONAL(BUILD_ON_X86, test x$target_i386 = xyes)

AM_CONDITIONAL(BUILD_ON_AMD64, test x$target_amd64 = xyes)

# Check whether libust is installed.

ustinc=""
ustlib=""

AC_ARG_WITH(ust,
	    AC_HELP_STRING([--with-ust],
                           [the path to installed UST]),
            UST_CFLAGS=" -I${withval}/include"
            UST_LDFLAGS=" -L${withval}/lib")

if test "x$with_ust" != "xno"; then
   saved_CFLAGS="$CFLAGS"
   CFLAGS="$CFLAGS $UST_CFLAGS"
   AC_MSG_CHECKING([for ust])
   AC_TRY_COMPILE([
    #define CONFIG_UST_GDB_INTEGRATION
    #include <ust/ust.h>
      ],[],
  [AC_MSG_RESULT([yes]); AC_DEFINE(BUILD_UST, 1, [Define if UST is available]) AM_CONDITIONAL(BUILD_UST, true)],
  [AC_MSG_RESULT([no]); AM_CONDITIONAL(BUILD_UST, false) UST_CFLAGS= ; UST_LDFLAGS= ; ])
  CFLAGS="$saved_CFLAGS"
else
  AM_CONDITIONAL(BUILD_UST, false)
fi

# Flags needed for UST
##AC_SUBST(ustlib)
AC_SUBST(UST_CFLAGS)
AC_SUBST(UST_LDFLAGS)

AC_SUBST(LIBS)

AC_PROG_INSTALL

AC_OUTPUT
