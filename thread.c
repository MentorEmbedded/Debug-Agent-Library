/* Threads related stuff in agent.

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

#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include "thread.h"
#include "backend.h"

/* Thread related operations.  */

/* The list of threads known to the agent.  */

static agent_thread_info_t *agent_threads = NULL;

static agent_thread_info_t *last_gdb_stub_thread = NULL;

/* FIXME: these operations on agent_threads are not thread-safe.  */

/* Have pthread_t PTH_ID added to the list of threads being
   debugged.  Return the info for new thread.  */

agent_thread_info_t *
agent_thread_info_add (pthread_t pth_id)
{
  agent_thread_info_t *tinfo;

  /* Don't create thread info a second time.  */
  tinfo = agent_thread_info_find_from_pthread (pth_id);
  if (tinfo)
    return tinfo;

  tinfo = (agent_thread_info_t *)
    calloc (1, sizeof (agent_thread_info_t));
  tinfo->pthread = pthread_self ();

  tinfo->regblock = (char *) malloc (agent_backend->global_gbufsize);
  tinfo->next = NULL;

  if (!last_gdb_stub_thread)
    last_gdb_stub_thread = tinfo;
  else
    last_gdb_stub_thread->next = tinfo;

  last_gdb_stub_thread = tinfo;

  return tinfo;
}

/* Given a Posix thread id PTH_ID, return the stub's thread info for it.  */

agent_thread_info_t *
agent_thread_info_find_from_pthread (pthread_t pth_id)
{
  agent_thread_info_t *tinfo;

  for (tinfo = agent_threads; tinfo; tinfo = tinfo->next)
    if (pth_id == tinfo->pthread)
      return tinfo;

  return NULL;
}

