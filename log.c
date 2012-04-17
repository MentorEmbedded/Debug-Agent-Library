/* Logging utilities of agent.

   Copyright (C) 2012 Mentor Graphics.

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

#include <stdarg.h>
#include <stdio.h>

#include "log.h"

static int
AGENT_veprintf (const char *fmt, va_list ap)
{
  return vfprintf (stderr, fmt, ap);
}

static int
AGENT_eflush (void)
{
  return fflush (stderr);
}

static int
AGENT_eprintf (const char *fmt, ...)
{
  va_list ap;
  int result;
  va_start (ap, fmt);
  result = AGENT_veprintf (fmt, ap);
  va_end (ap);
  return result;
}

/* Name of agent.  */
const char *agent_program_name = "dagent";

/* Issue a message.  */

void __attribute__ ((format (printf, 3, 4)))
agent_message (int type, int flags, const char *fmt, ...)
{
  va_list va;

  if (!(flags & AGENT_MESSAGE_CONT))
    AGENT_eprintf ("%s: debug:", agent_program_name);

  va_start (va, fmt);
  AGENT_veprintf (fmt, va);
  va_end (va);
  
  if (flags & AGENT_MESSAGE_END)
    {
      AGENT_eprintf ("\n");
      AGENT_eflush ();
    }
}

void __attribute__((noreturn)) __attribute__ ((format (printf, 1, 2)))
agent_fatal (const char *fmt, ...)
{
  exit (1);
}


unsigned AGENT_verbosity = AGENT_VERBOSITY_NORMAL;
