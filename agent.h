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

#ifndef AGENT_H
#define AGENT_H

#include "defs.h"

/* Different capabilities of agent.  We can add more capabilities when
   required.  */
enum AGENT_CAPA_TYPE {AGENT_CAPA_WRITE_MEM, /* Write memory */
		      AGENT_CAPA_FAST_TRACE, /* Install fast tracepoint */
		      AGENT_CAPA_LAST};

struct agent_config
{
  /* Each slot presents one capability of agent.  */
  int capas[AGENT_CAPA_LAST];

  /* Initialization routine.  */
  void (* init) (void);
};

#define GDB_AGENT_SYM(SYM) gdb_agent_##SYM

int agent_read_mem (gdb_addr_t addr, gdb_size_t length,
		    unsigned char *buf, size_t *nbytes);

int agent_get_pagesize (void);

int agent_config_capa_get (struct agent_config *agent_config,
			   enum AGENT_CAPA_TYPE type);

#endif

