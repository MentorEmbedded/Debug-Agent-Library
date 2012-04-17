/* Copyright (C) 2012 Mentor Graphics.

   This file is part of dagent, the Debugging Agent.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License version 2.1 as published by the Free Software Foundation.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
*/

#ifndef LOG_H
#define LOG_H 1

#include <stdlib.h>
#include <stdarg.h>

typedef enum agent_message_t
{
  AGENT_MESSAGE_INFORM,  /* Information messages */
  AGENT_MESSAGE_VERBOSE, /* Verbose messages */
  AGENT_MESSAGE_HWM,
} agent_message_t;

/* Verbosity levels */
typedef enum agent_verbosity_t
{
  AGENT_VERBOSITY_QUIET = 0,
  AGENT_VERBOSITY_NORMAL = 1u << AGENT_MESSAGE_INFORM,
  AGENT_VERBOSITY_NOISY = AGENT_VERBOSITY_NORMAL | (1u << AGENT_MESSAGE_VERBOSE),
  AGENT_VERBOSITY_DEBUG = (1u << AGENT_MESSAGE_HWM) - 1u,
} gdb_verbosity_t;

/* Issue a fatal error message, and exit.  */

extern void __attribute__ ((noreturn)) __attribute__ ((format (printf, 1, 2)))
  agent_fatal (const char *format, ...);

/*  Message formatting flags.  */
typedef enum agent_message_format_t
{
  AGENT_MESSAGE_END = 1 << 0,  /* Last in a sequence */
  AGENT_MESSAGE_CONT = 1 << 1, /* Continuation of a sequence */
} agent_message_format_t;

/* Issue a message of particular type. */
extern void __attribute__ ((format (printf, 3, 4)))
  agent_message (int type, int m, const char *fmt, ...);

extern unsigned AGENT_verbosity;

/* Indicate whether a message of type F should be emitted.  */
#define gdb_message_p(F) (AGENT_verbosity & (1u << (F)))

/* Issue a debug message.  */
#if !NDEBUG
#define gdb_debug(F, FMT, args...) \
   	(gdb_message_p (F) \
	 ? agent_message ((F), AGENT_MESSAGE_END, (FMT), ##args) \
 	: (void)0)
#else
/* Disable debug messages at compile time.  */
static __inline__ void __attribute__ ((always_inline))
gdb_debug (char const *fmt __attribute__((unused)), ...)
{
  /* Modern GDB is smart enough to inline such empty variadic
     functions.  We need to use a function call to avoid irrelevent
     unused variable warnings.  */
}
#define gdb_debug(F, FMT, args...) \
   	((void)(F), gdb_debug ((FMT), ##args))
#endif

/* Issue a verbose message. */
#define gdb_verbose(FMT, args...) \
	(gdb_message_p (AGENT_MESSAGE_VERBOSE) \
	 ? agent_message (AGENT_MESSAGE_VERBOSE, AGENT_MESSAGE_END, (FMT), ##args) \
 	: (void)0)

/* Issue a normal message.  */
#define gdb_inform(FMT, args...) \
	(gdb_message_p (AGENT_MESSAGE_INFORM) \
	 ? agent_message (AGENT_MESSAGE_INFORM, AGENT_MESSAGE_END, (FMT), ##args) \
 	: (void)0)

#endif /* LOG_H */
