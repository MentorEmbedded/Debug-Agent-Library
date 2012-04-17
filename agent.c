/* Top level stuff for dagent, the Debugging Agent.

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

#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stddef.h>

#include "agent.h"
#include "tracepoint.h"
#include "thread.h"
#include "backend.h"
#include "config.h"
#include "log.h"

/* Global variable of agent configuration.  */
struct agent_config *agent_config;

void
agent_config_set (struct agent_config *config)
{
  agent_config = config;
}

int
agent_config_capa_get (struct agent_config *agent_config,
		       enum AGENT_CAPA_TYPE type)
{
  return agent_config->capas[type];
}

/* Helper of agent to read and write memory.  */

/* Read memory from address ADDR of length LEGNTH to BUF.  *NBYTES is the
   actual number of bytes read.  Return 0 on success, otherwise return
   non-zero.  */
int
agent_read_mem (gdb_addr_t addr, gdb_size_t length,
		unsigned char *buf, size_t *nbytes)
{
  memcpy ((void *) buf, (void *) (ptrdiff_t) addr, length);
  *nbytes = length;
  return 0;
}

/* Write memory from BUF to address ADDR of length LENGTH.  Return 0 if
   success, otherwise return non-zero.  */
int
agent_write_mem (gdb_addr_t addr, gdb_size_t length,
		 const unsigned char *buf)
{
  int err;

  if (!agent_config_capa_get (agent_config, AGENT_CAPA_WRITE_MEM))
    {
      gdb_verbose ("Memory writing not permitted");
      return 1;
    }

  err = mprotect ((void *) (ptrdiff_t) (addr & 0xfffff000UL),
		  (length + 4095) & 0xfffff000UL,
		  PROT_READ|PROT_WRITE|PROT_EXEC);
  if (err)
    return 1;

  memcpy ((void *) (ptrdiff_t) addr, (void *) buf, length);

  return 0;
}

/* Return the system's pagesize.  The value returned by the system is
   memoized.  */
int
agent_get_pagesize (void)
{
  static int pagesize = 0;

  /* This should be safe as long as only the debug thread calls this,
     which is true currently.  */
  if (pagesize == 0)
    {
      pagesize = sysconf (_SC_PAGE_SIZE);
      if (pagesize == -1)
	agent_fatal ("sysconf");
    }

  return pagesize;
}

#if defined BUILD_UST
void initialize_ust (void);
#endif
void initialize_helper_thread (void);

struct backend *agent_backend;

/* Initialization of the whole agent.  */
static void __attribute__ ((constructor))
initialize_agent (void)
{
  /* AGENT_verbosity = AGENT_VERBOSITY_NOISY; */

  agent_backend = initialize_backend ();

  /* Initialize tracepoints module.  */
  initialize_tracepoint ();

  extern struct agent_config agent_config_gdb;
  agent_config_set (&agent_config_gdb);

  agent_config->init ();

  initialize_helper_thread ();

#if defined BUILD_UST
  initialize_ust ();
#endif

}

int GDB_AGENT_SYM(ust_loaded) = 0;

/* The last two bits represent the capability of installing fast tracepoint
   and install static tracepoint respectively.  */

int GDB_AGENT_SYM(capability) = 0x1 | 0x2;

