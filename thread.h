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

#include <pthread.h>

#ifndef AGENT_THREAD_H
#define AGENT_THREAD_H 1

/* This struct is a collection of the agent's information about
   each thread.  */

typedef struct agent_thread_info_t
{
  /* The Posix thread id.  */
  pthread_t pthread;

  /* The block of saved registers.  The size of this must match the
     amount of register data that GDB expects.  The contents are only
     defined while the thread is stopped.  */
  char *regblock;

  /* Link to the next thread in the list.  */
  struct agent_thread_info_t *next;

} agent_thread_info_t;

agent_thread_info_t *agent_thread_info_find_from_pthread (pthread_t pt);

agent_thread_info_t *agent_thread_info_add (pthread_t pth_id);

#endif
