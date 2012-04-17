## Copyright (C) 2012 Free Software Foundation, Inc.
##
## This file is part of AGENT.NAME.
##
## This library is free software; you can redistribute it and/or
## modify it under the terms of the GNU Lesser General Public
## License version 2.1 as published by the Free Software Foundation.
##
## This library is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## Lesser General Public License for more details.
##
## You should have received a copy of the GNU Lesser General Public
## License along with this library; if not, write to the Free Software
## Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA

COMMON_FILES = agent.c comm.c command.c thread.c \
	tracepoint.c agent-expr.c log.c

if BUILD_ON_X86
COMMON_FILES += i386-linux-backend.c
endif

if BUILD_ON_AMD64
COMMON_FILES += x86-64-linux-backend.c
endif

if BUILD_UST
COMMON_FILES += ust.c
AM_LDFLAGS = -ldl
endif

ACLOCAL_AMFLAGS = -I config

AM_CFLAGS = -Wall -Werror -fno-strict-aliasing

lib_LTLIBRARIES = libdagent.la

libdagent_la_SOURCES = $(COMMON_FILES)
libdagent_la_SOURCES += gdb.c
libdagent_la_LIBADD = -lpthread

if BUILD_UST
libdagent_la_LIBADD += -ldl
endif

libdagent_la_LDFLAGS = -Wl,--no-undefined

