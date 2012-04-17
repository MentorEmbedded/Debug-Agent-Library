/* Interaction with GDB or GDBserver.

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

#include <sys/mman.h>
#include <string.h>
#include <malloc.h>

#include "log.h"
#include "agent.h"
#include "tracepoint.h"
#include "backend.h"

extern unsigned char *GDB_AGENT_SYM(trace_buffer_hi);
extern unsigned char *GDB_AGENT_SYM(trace_buffer_lo);

/* Place a breakpoints on these three functions.  */
void
GDB_AGENT_SYM(stop_tracing) (void)
{
}

void
GDB_AGENT_SYM(flush_trace_buffer)(void)
{
}

void
GDB_AGENT_SYM(about_to_request_buffer_space) ()
{}

/* Two gdbserver-read-only variables.  They are used by gdbserver to track
   the jump pad buffers.  */
char *GDB_AGENT_SYM(gdb_jump_pad_buffer);
char *GDB_AGENT_SYM(gdb_jump_pad_buffer_end);

/********************** trace buffer control ***************************/

#define GDB_FLUSH_COUNT_MASK        0xfffffff0
#define GDB_FLUSH_COUNT_MASK_PREV   0x7ff00000
#define GDB_FLUSH_COUNT_MASK_CURR   0x0007ff00

struct trace_buffer_control
{
  unsigned char *start;

  unsigned char *free;

  unsigned char *end_free;

  /* unsigned char *wrap; */
};


unsigned int GDB_AGENT_SYM(trace_buffer_ctrl_curr);
struct trace_buffer_control GDB_AGENT_SYM(trace_buffer_ctrl)[3];

unsigned int GDB_AGENT_SYM(traceframe_write_count);
unsigned int GDB_AGENT_SYM(traceframe_read_count);

#if defined(__GNUC__)
#  define memory_barrier() asm volatile ("" : : : "memory")
#else
#  define memory_barrier() do {} while (0)
#endif

#define cmpxchg(mem, oldval, newval) \
  __sync_val_compare_and_swap (mem, oldval, newval)

/* Carve out a piece of the trace buffer.  AMT is the ammount to allocate.
   Return NULL in case of failure.  */
unsigned char *
gdb_trace_buffer_alloc (size_t amt)
{
  unsigned char *rslt;
  struct trace_buffer_control *tbctrl;
  unsigned int curr;
  unsigned int prev, prev_filtered;
  unsigned int commit_count;
  unsigned int commit;
  unsigned int readout;

  gdb_verbose ("Want to allocate %d+%u bytes in trace buffer",
	       (int) amt, (unsigned) sizeof (traceframe_t));

  /* Account for the EOB marker.  */
  amt += sizeof (traceframe_t);

 again:
  memory_barrier ();

  /* Read the current token and extract the index to try to write to,
     storing it in CURR.  */
  prev = GDB_AGENT_SYM(trace_buffer_ctrl_curr);
  prev_filtered = prev & ~GDB_FLUSH_COUNT_MASK;
  curr = prev_filtered + 1;
  if (curr > 2)
    curr = 0;

  GDB_AGENT_SYM(about_to_request_buffer_space) ();

  GDB_AGENT_SYM(trace_buffer_ctrl)[curr]
    = GDB_AGENT_SYM(trace_buffer_ctrl)[prev_filtered];
  gdb_verbose ("trying curr=%u", curr);

  tbctrl = &GDB_AGENT_SYM(trace_buffer_ctrl)[curr];

  while (1)
    {
      if (tbctrl->end_free < tbctrl->free)
	{
	  if (tbctrl->free + amt <= GDB_AGENT_SYM(trace_buffer_hi))
	    break;
	  else
	    {
	      gdb_verbose ("Upper part too small, setting wraparound");
	      /* tbctrl->wrap = tbctrl->free; */
	      tbctrl->free = GDB_AGENT_SYM(trace_buffer_lo);
	    }
	}

      /* The normal case.  */
      if (tbctrl->free + amt <= tbctrl->end_free)
	break;

      GDB_AGENT_SYM(flush_trace_buffer)();
      memory_barrier ();
      if (GDB_AGENT_SYM(tracing))
	{
	  gdb_verbose ("gdbserver flushed buffer, retrying");
	  goto again;
	}

      /* GDBserver cancelled the tracing.  Bail out as well.  */
      return NULL;
    }

  /* If we get here, we know we can provide the asked-for space.  */

  rslt = tbctrl->free;

  tbctrl->free += (amt - sizeof (traceframe_t));

  /* Or not.  If GDBserver changed the trace buffer behind our back,
     we get to restart a new allocation attempt.  */

  /* Build the tentative token.  */
  commit_count = (((prev & GDB_FLUSH_COUNT_MASK_CURR) + 0x100)
		  & GDB_FLUSH_COUNT_MASK_CURR);
  commit = (((prev & GDB_FLUSH_COUNT_MASK_CURR) << 12)
	    | commit_count
	    | curr);

  /* Try to commit it.  */
  readout = cmpxchg (&GDB_AGENT_SYM(trace_buffer_ctrl_curr), prev, commit);
  if (readout != prev)
    {
      gdb_verbose ("GDBserver has touched the trace buffer, restarting."
		   " (prev=%08x, commit=%08x, readout=%08x)",
		   prev, commit, readout);
      goto again;
    }

  GDB_AGENT_SYM(about_to_request_buffer_space) ();

  /* Check if the change has been effective, even if GDBserver stopped
     us at the breakpoint.  */

  {
    unsigned int refetch;

    memory_barrier ();

    refetch = GDB_AGENT_SYM(trace_buffer_ctrl_curr);

    if (refetch == commit
	|| ((refetch & GDB_FLUSH_COUNT_MASK_PREV) >> 12) == commit_count)
	gdb_verbose ("Change is effective: (prev=%08x, commit=%08x, "
		     "readout=%08x, refetch=%08x)",
		     prev, commit, readout, refetch);
    else
      {
	gdb_verbose ("GDBserver has touched the trace buffer, not effective."
		     " (prev=%08x, commit=%08x, readout=%08x, refetch=%08x)",
		     prev, commit, readout, refetch);
	goto again;
      }
  }

  ((traceframe_t *) tbctrl->free)->tpnum = 0;
  ((traceframe_t *) tbctrl->free)->data_size = 0;

  return rslt;
}


void
traceframe_finish (traceframe_t *tframe)
{
  GDB_AGENT_SYM(traceframe_write_count)++;
  GDB_AGENT_SYM(traceframes_created)++;
}

uint64_t
GDB_AGENT_SYM(get_raw_reg) (unsigned char *raw_regs, int regnum)
{
  return agent_backend->reg.get_raw_reg (raw_regs, regnum);
}

uint64_t
GDB_AGENT_SYM(get_trace_state_variable_value) (int num)
{
  return 0;
}

void
GDB_AGENT_SYM(set_trace_state_variable_value) (int num, uint64_t val)
{
  /* FIXME: Not implemented.  */
}

typedef struct collecting_t
{
  uintptr_t tpoint;
  uintptr_t thread_area;
} collecting_t;


static collecting_t *GDB_AGENT_SYM(collecting) __attribute__((used));

char *GDB_AGENT_SYM(gdb_trampoline_buffer);
char *GDB_AGENT_SYM(gdb_trampoline_buffer_end);
char *GDB_AGENT_SYM(gdb_trampoline_buffer_error);

char *GDB_AGENT_SYM(gdb_tp_heap_buffer) __attribute__((used));

void
initialize_gdb_config (void)
{
  int pagesize = agent_get_pagesize ();

  GDB_AGENT_SYM(gdb_jump_pad_buffer) = memalign (pagesize, pagesize * 20);
  GDB_AGENT_SYM(gdb_jump_pad_buffer_end)
    = GDB_AGENT_SYM(gdb_jump_pad_buffer) + pagesize * 20;

  if (mprotect (GDB_AGENT_SYM(gdb_jump_pad_buffer), pagesize * 20,
		PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    {
      gdb_inform ("Unable to set up jump pad buffer!");
    }

  GDB_AGENT_SYM(gdb_trampoline_buffer) = 0;
  GDB_AGENT_SYM(gdb_trampoline_buffer_end) = 0;

  GDB_AGENT_SYM(gdb_trampoline_buffer_error) = malloc (100);

  strcpy (GDB_AGENT_SYM(gdb_trampoline_buffer_error), "No errors reported");

  GDB_AGENT_SYM(gdb_tp_heap_buffer) = malloc (5 * 1024 * 1024);
}

struct agent_config agent_config_gdb = {
  {1, 1}, initialize_gdb_config,
};
