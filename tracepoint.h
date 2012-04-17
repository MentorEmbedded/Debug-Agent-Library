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

#ifndef TRACEPOINT_H
#define TRACEPOINT_H 1

#include "agent.h"
#include "thread.h"
#include "agent-expr.h"

struct tracerun_t;
struct traceframe_t;
struct tracepoint_t;

/* Base action.  Concrete actions inherit this.  */

typedef struct tracepoint_action_t
{
  char type;
} tracepoint_action_t;

/* An 'M' (collect memory) action.  */
struct collect_memory_action
{
  tracepoint_action_t base;

  uint64_t addr;
  uint64_t len;
  int basereg;
};

/* An 'R' (collect registers) action.  */

struct collect_registers_action
{
  tracepoint_action_t base;
};

/* An 'X' (evaluate expression) action.  */

struct eval_expr_action
{
  tracepoint_action_t base;

  agent_expr_t *expr;
};

typedef struct trace_state_variable_t
{
  /* This number identifies the variable uniquely.  Numbers are always
     assigned by GDB, and are presumed unique during the course of a
     trace experiment.  */
  int number;

  /* The variable's initial value.  We don't use it in the target,
     just return it back to the host upon request.  */
  int64_t initial_value;

  /* The variable's value, a 64-bit signed integer always.  */
  int64_t value;

  /* Pointer to a getter function, app can use to supply computed values.  */
  int64_t (*getter) (agent_thread_info_t *tinfo);

  /* The name of the variable as used on the host.  Target doesn't use
     it, but we want to be able to report it back upon reconnection
     and such.  */
  char *name;

  /* Link to the next variable.  */
  struct trace_state_variable_t *next;

} trace_state_variable_t;

enum tracepoint_type
{
  trap_tracepoint,

  fast_tracepoint,

  static_tracepoint
};

/* The definition of a tracepoint.  */

/* Tracepoints may have multiple locations, each at a different
   address.  This can occur with optimizations, template
   instantiation, etc.  Since the locations may be in different
   scopes, the conditions and actions may be different for each
   location.  Our target version of tracepoints is more like GDB's
   notion of "breakpoint locations", but we have almost nothing that
   is not per-location, so we bother having two kinds of objects.  The
   key consequence is that numbers are not unique, and that it takes
   both number and address to identify a tracepoint uniquely.  */

typedef struct tracepoint_t {

  /* The number of the tracepoint, as specified by GDB.  Several
     tracepoint objects here may share a number.  */
  uint32_t number;

  /* The breakpoint address.  */
  gdb_addr_t addr;

  /* The tracepoint point type, such as fast tracepoint, and etc.  */
  enum tracepoint_type type;

  /* True if the tracepoint is currently enabled.  */
  int8_t enabled;

  /* The number of single steps that will be performed after each
     tracepoint hit.  */
  uint64_t step_count;

  /* The number of times the tracepoint may be hit before it will
     terminate the entire tracing run.  */
  uint64_t pass_count;

  /* Pointer to the agent expression that is the point's or
     breakpoint's conditional, or NULL if the tracepoint is
     unconditional.  */
  agent_expr_t *cond;

  /* The list of actions to take when the tracepoint triggers.  */
  uint32_t numactions;
  tracepoint_action_t **actions;

  /* Count of the times we've hit this tracepoint during the run.  Note
     that while-stepping steps are not counted as "hits".  */
  uint64_t hit_count;

  /* Cached sum of the sizes of traceframes created by this point.  */
  uint64_t traceframe_usage;

  gdb_addr_t compiled_cond;

  /* Pointer to next in linked-list.  */
  struct tracepoint_t *next;

  /*******************************************************************/
  /* The number of bytes displaced by the tracepoints. It may subsume
     multiple instructions, for multi-byte fast tracepoints.  */
  uint32_t orig_size;

  /* The address range of the piece of the trampoline buffer that was
     assigned to this fast tracepoint.  (trampoline_end is actually one
     byte past the end).  If trampoline_end is zero, then this fast
     tracepoint does not use a trampoline.  */
  gdb_addr_t trampoline;
  gdb_addr_t trampoline_end;
} tracepoint_t;

/* The results of tracing go into a fixed-size space known as the
   "trace buffer".  Because usage follows a limited number of
   patterns, we manage it ourselves rather than with malloc. Basic
   rules are that we create only one traceframe at a time, each is
   variable in size, they are never moved once created, and we only
   discard if we are doing a circular buffer, and then only the oldest
   ones.  Each traceframe includes its own size, so we don't need to
   link them together, and the traceframe number is relative to the
   first one, so we don't need to record numbers.  A traceframe also
   records the number of the tracepoint that created it.  The data
   itself is a series of blocks, each introduced by a single character
   and with a defined format.  Each type of block has enough
   type/length info to allow scanners to jump quickly from one block
   to the next without reading each byte in the block.

   Trace buffer management would be simple - advance a free pointer
   from beginning to end, then stop - were it not for the circular
   buffer option, which is a useful way to prevent a trace run from
   stopping prematurely because the buffer filled up.  In the circular
   case, the location of the first traceframe (trace_buffer_start)
   moves as old traceframes are discarded.  Also, since we grow
   traceframes incrementally as actions are performed, we wrap around
   to the beginning of the trace buffer.  This is per-block, so each
   block within a traceframe remains contiguous.  Things get messy
   when the wrapped-around traceframe is the one being discarded; the
   free space ends up in two parts at opposite ends of the buffer.

   The data collected at a tracepoint hit.  This object should be as
   small as possible, since there may be a great many of them.  We do
   not need to keep a frame number, because they are all sequential
   and there are no deletions; so the Nth frame in the buffer is
   always frame number N.  */

typedef struct traceframe_t
{

  /* Number of the tracepoint that collected this traceframe.  A value
     of 0 indicates the current end of the trace buffer.  We make this
     a 16-bit field because it's never going to happen that GDB's
     numbering of tracepoints reaches 32,000.  */
  int tpnum : 16;

  /* The size of the data in this traceframe.  We limit this to 32 bits,
     even on a 64-bit target, because it's just implausible that one is
     validly going to collect 4 gigabytes of data at a single tracepoint
     hit.  */
  unsigned int data_size : 32;

  /* The base of the trace data, which is contiguous from this point.  */
  unsigned char data[0];

} __attribute__ ((__packed__)) traceframe_t;


void initialize_tracepoint (void);

void trace_state_variable_set_value (int num, int64_t val);

unsigned char* traceframe_add_block (traceframe_t *tframe,
				     int amt);
void tracepoint_compile_condition (tracepoint_t *tpoint,
				   gdb_addr_t *jump_entry);

int64_t trace_state_variable_get_value (agent_thread_info_t *tinfo, int num);

extern tracepoint_t * GDB_AGENT_SYM(stopping_tracepoint);
extern tracepoint_t * GDB_AGENT_SYM(error_tracepoint);
extern tracepoint_t * GDB_AGENT_SYM(tracepoints);
extern int GDB_AGENT_SYM(tracing);
extern unsigned int GDB_AGENT_SYM(traceframes_created);
extern int GDB_AGENT_SYM(trace_buffer_is_full);
extern enum eval_result_type GDB_AGENT_SYM(expr_eval_result);

void GDB_AGENT_SYM(stop_tracing) (void);

int claim_trampoline_space (size_t used, gdb_addr_t *trampoline);


int tracepoint_condition_is_true (tracepoint_t *tpoint,
				  agent_thread_info_t *tinfo,
				  unsigned char *raw_regs);

void tracepoint_collect_data (agent_thread_info_t *tinfo,
			      tracepoint_t *tpoint,
			      unsigned char *raw_regs);
#endif

