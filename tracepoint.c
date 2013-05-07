/* Tracepoint implementation in agent.
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

#include <assert.h>
#include <sys/mman.h>
#include <pthread.h>
#include <malloc.h>
#include <string.h>

#include "tracepoint.h"
#include "agent.h"
#include "backend.h"
#include "config.h"
#include "log.h"

/* Pointer to the block of memory that traceframes all go into.  */

unsigned char *GDB_AGENT_SYM(trace_buffer_lo);

/* Pointer to the end of the trace buffer, more precisely to the byte after
   the end of the buffer.  */

unsigned char *GDB_AGENT_SYM(trace_buffer_hi);

int GDB_AGENT_SYM(trace_buffer_is_full);

enum eval_result_type GDB_AGENT_SYM(expr_eval_result);

tracepoint_t * GDB_AGENT_SYM(stopping_tracepoint);

tracepoint_t * GDB_AGENT_SYM(error_tracepoint);

tracepoint_t * GDB_AGENT_SYM(tracepoints);

void GDB_AGENT_SYM(gdb_collect) (tracepoint_t *tpoint,
				 unsigned char *raw_regs);

int GDB_AGENT_SYM(tracing);

trace_state_variable_t *GDB_AGENT_SYM(trace_state_variables);

unsigned int GDB_AGENT_SYM(traceframes_created);

/* Linked list of all builtin trace state variables.  */

trace_state_variable_t *trace_state_variables;


/* Empty out an already-existing trace buffer.  */
void
agent_trace_buffer_clear ()
{
  GDB_AGENT_SYM(traceframes_created) = 0;
}

/* Trace buffer management.  */

static void
agent_trace_buffer_init (char *buf, int bufsize)
{
  GDB_AGENT_SYM(trace_buffer_lo) = (unsigned char *) buf;
  GDB_AGENT_SYM(trace_buffer_hi) = GDB_AGENT_SYM(trace_buffer_lo) + bufsize;

  agent_trace_buffer_clear ();
}

static  unsigned char fjump[20];

/* Install tracepoint TPOINT in agent.  GDB_JUMP_PAD_HEAD is the jump pad
   head.  BUF is the command buffer.  Some information we want to return
   to GDB or GDBserver is copied into BUF.  Return 0 if successful, return
   non-zero otherwise.  */

static int
tracepoint_install (tracepoint_t *tpoint, gdb_addr_t gdb_jump_pad_head,
		    char *buf)
{
  tracepoint_t **tp_next;

  gdb_verbose ("tracepoint_install:");

  /* Insert TPOINT into tracepoint list.  */
  for (tp_next = &GDB_AGENT_SYM(tracepoints);
       (*tp_next) != NULL && (*tp_next)->addr <= tpoint->addr;
       tp_next = &(*tp_next)->next)
    ;
  tpoint->next = *tp_next;
  *tp_next = tpoint;

 if (tpoint->type == fast_tracepoint
     || tpoint->type == static_tracepoint)
    {
      tracepoint_t *tp;

      /* Compile condition.  */
      if (tpoint->cond != NULL)
	{
	  gdb_addr_t jump_entry, jentry;

	  jentry = jump_entry = (gdb_addr_t) (ptrdiff_t) gdb_jump_pad_head;

	  gdb_verbose ("tracepoint_install: compile condition\n");
	  tracepoint_compile_condition (tpoint, &jump_entry);

	  /* Pad to 8-byte alignment.  */
	  jentry = ((jentry + 7) & ~0x7);

	  gdb_jump_pad_head += (jentry - jump_entry);
	}

      /* Find existing tracepoint has the same address and type with TPOINT.  */
      for (tp = GDB_AGENT_SYM(tracepoints); tp != NULL; tp = tp->next)
	{
	  if (tp->addr == tpoint->addr
	      && tp->type == tpoint->type
	      && tp->number != tpoint->number)
	    break;
	}

      if (tpoint->type == fast_tracepoint)
	{
	  int err = 0;
	  gdb_addr_t jentry, jump_entry;
	  size_t fjump_size = 0;

	  if (tp == NULL)
	    {
	      unsigned char *orig_copy;
	      gdb_addr_t trampoline = 0;
	      size_t trampoline_size = 0;
	      size_t nbytes;

	      gdb_verbose ("tracepoint_install: install new tp");

	      /* First, copy off the instruction we are
		 overwriting.  */
	      orig_copy = (unsigned char *) malloc (tpoint->orig_size);
	      err = agent_read_mem (tpoint->addr, tpoint->orig_size,
				    orig_copy, &nbytes);

	      jentry = jump_entry =  (gdb_addr_t) (ptrdiff_t) gdb_jump_pad_head;
	      gdb_verbose ("tracepoint_install: install_jump jentry %x",
			   (unsigned int) jentry);

	      err = INSTALL_FAST_TRACEPOINT_JUMP_PAD
		((gdb_addr_t) (ptrdiff_t) tpoint, tpoint->addr,
		 (gdb_addr_t) (ptrdiff_t) GDB_AGENT_SYM(gdb_collect),
		 orig_copy, tpoint->orig_size, &jentry, fjump, &fjump_size,
		 &trampoline, &trampoline_size, buf);

	      if (err)
		return err;

	      /* Pad to 8-byte alignment.  */
	      jentry = ((jentry + 7) & ~0x7);
	      gdb_jump_pad_head += (jentry - jump_entry);

	      gdb_verbose ("tracepoint_install: install_jump jentry %x fjump_size %d",
			   (unsigned int) jentry, (unsigned int) fjump_size);

	      /* Copy GDB_JUMP_PAD_HEAD back to BUF, as well its length.  */
	      memcpy (buf, &gdb_jump_pad_head, 8);
	      * ((uint32_t *) &buf[8]) = (uint32_t) fjump_size;

	      memcpy (&buf[12], fjump, fjump_size);
	    }
	  else
	    {
	      gdb_verbose ("tracepoint_install: clone new tp");

	      tpoint->trampoline = tp->trampoline;
	      tpoint->trampoline_end = tp->trampoline_end;

	      /* Copy the value of GDB_JUMP_PAD_HEAD and its length to command
		 buffer  */
	      memcpy (buf, &gdb_jump_pad_head, 8);
	      memset (&buf[8], 0, 4);
	    }
	}
      else
	{
	  assert (0);
	}
    }

 gdb_verbose ("tracepoint_install: done");
 return 0;
}

static struct agent_expr_t *
agent_cmdbuf_read_agent_expr (char **cmd_buf)
{
  char *p = *cmd_buf;
  int i = *(int *) p;
  struct agent_expr_t *aexpr = NULL;

  if (i == 0)
    p += 4;
  else
    {
      struct agent_expr_t *aexpr = malloc (sizeof (struct agent_expr_t));

      aexpr->length = i;
      p += 4;
      aexpr->bytes = malloc (i);
      memcpy (aexpr->bytes, p, i);
      p += i;
    }

  *cmd_buf = p;
  return aexpr;
}

static tracepoint_action_t *
agent_cmdbuf_read_tp_action (char **cmd_buf)
{
  tracepoint_action_t *action = NULL;
  char *p = *cmd_buf;

  gdb_verbose ("agent_cmdbuf_read_tp_action: type %c", p[0]);
  switch (*p++)
    {
    case 'M':
      {
	struct collect_memory_action *maction =
	  malloc (sizeof (struct collect_memory_action));

	maction->base.type = 'M';
	memcpy ((void *) &maction->addr, p, 8);
	p += 8;
	memcpy ((void *) &maction->len, p, 8);
	p += 8;
	memcpy ((void *) &maction->basereg, p, 4);
	p += 4;

	action = (tracepoint_action_t *) maction;
      }
      break;
    case 'R':
      {
	struct collect_registers_action *raction =
	  malloc (sizeof (struct collect_registers_action));

	raction->base.type = 'R';
	 action = (struct tracepoint_action_t *) raction;
      }
      break;
    case 'X':
      {
	struct eval_expr_action *eaction;

	eaction = malloc (sizeof (struct eval_expr_action));
	eaction->base.type = 'X';
	eaction->expr = agent_cmdbuf_read_agent_expr (&p);
	action = (struct tracepoint_action_t *) eaction;
      }
      break;
    default:
      gdb_inform ("Unknow tracepoint action\n");
    }

  *cmd_buf = p;
  return action;
}

extern struct agent_config *agent_config;

#define COPY_FROM_BUF(TPOINT,BUF,FIELD,LENGTH)	\
  memcpy ((void *) &TPOINT->FIELD, BUF, LENGTH); \
  BUF += LENGTH;

/* Command handler for tracepoint.  CMD_BUF is the command buffer.  All
   information of tracepoint is extracted from CMD_BUF.  Return 0 if success
   otherwise return 1.  */

int
trace_command_protocol (char *cmd_buf)
{
  char *p;
  tracepoint_t *tpoint;
  int i, ret;
  gdb_addr_t gdb_jump_pad_head = 0;

  tpoint = (tracepoint_t *) malloc (sizeof (tracepoint_t));
  memset (tpoint, 0, sizeof (tracepoint_t));
  tpoint->actions = NULL;
  tpoint->next = NULL;
  tpoint->cond = NULL;

  p = cmd_buf + 10;

  COPY_FROM_BUF(tpoint, p, number, 4);
  COPY_FROM_BUF(tpoint, p, addr, 8);
  COPY_FROM_BUF(tpoint, p, type, 4);

  if (tpoint->type == fast_tracepoint
      && !agent_config_capa_get (agent_config, AGENT_CAPA_FAST_TRACE))
    {
      gdb_verbose ("Fast tracepoint not permitted");
      return 1;
    }
  COPY_FROM_BUF(tpoint, p, enabled, 1);
  COPY_FROM_BUF(tpoint, p, step_count, 8);
  COPY_FROM_BUF(tpoint, p, pass_count, 8);
  COPY_FROM_BUF(tpoint, p, numactions, 4);
  COPY_FROM_BUF(tpoint, p, hit_count, 8);
  COPY_FROM_BUF(tpoint, p, traceframe_usage, 8);
  COPY_FROM_BUF(tpoint, p, compiled_cond, 8);
  COPY_FROM_BUF (tpoint, p, orig_size, 4);

  tpoint->cond = agent_cmdbuf_read_agent_expr (&p);

  gdb_verbose ("trace_command_protocol: tp %d addr 0x%x cond %p orig_size %d numaction %d\n",
	       tpoint->number, (unsigned int) tpoint->addr,
	       tpoint->cond, (unsigned int) tpoint->orig_size,
	       tpoint->numactions);

  if (tpoint->numactions > 0)
    tpoint->actions = malloc (sizeof (*tpoint->actions) * tpoint->numactions);

  for (i = 0; i < tpoint->numactions; i++)
    tpoint->actions[i] = agent_cmdbuf_read_tp_action (&p);

  if (tpoint->type == fast_tracepoint)
    {
      memcpy ((void *) &gdb_jump_pad_head, p, 8);
      p += 8;

      gdb_verbose ("trace_command_protocol: gdb_jump_pad_head 0x%x",
		   (unsigned int) gdb_jump_pad_head);
    }

  /* Write the address of TPOINT to CMD_BUF.  */
  memcpy (&cmd_buf[2], &tpoint, 8);

  gdb_verbose ("trace_command_protocol: ");
  ret = tracepoint_install (tpoint, gdb_jump_pad_head, &cmd_buf[10]);

  if (ret)
    memmove (cmd_buf, &cmd_buf[10], strlen (&cmd_buf[10]));
  else
    memcpy (cmd_buf, "OK", 2);

  return ret;
}
/********************* trace state variable **********************************/

/* Find a trace state variable with the given number NUM.  */

static trace_state_variable_t *
trace_state_variable_get (int num)
{
  trace_state_variable_t *tsv;

  /* Search for an existing variable.  */
  for (tsv = trace_state_variables; tsv; tsv = tsv->next)
    if (tsv->number == num)
      return tsv;

  for (tsv = GDB_AGENT_SYM(trace_state_variables); tsv; tsv = tsv->next)
    if (tsv->number == num)
      return tsv;

  return NULL;
}

static int64_t
trace_state_variable_get_value_pself (int num)
{
  trace_state_variable_t *tsv;

  tsv = trace_state_variable_get (num);

  if (!tsv)
    {
      gdb_verbose ("No trace state variable %d, skipping value get", num);
      return 0;
    }

  /* Call a getter function if we have one.  While it's tempting to
     set up something to only call the getter once per tracepoint hit,
     it could run afoul of thread races. Better to let the getter
     handle it directly, if necessary to worry about it.  */
  if (tsv->getter)
    tsv->value = (tsv->getter) (NULL);

  return tsv->value;
}

/* Get the current value of the given TSV.  NUM is the number of trace state
   variable.  Variable's value is returned.  */

int64_t
trace_state_variable_get_value (agent_thread_info_t *tinfo, int num)
{
  trace_state_variable_t *tsv;

  tsv = trace_state_variable_get (num);

  if (!tsv)
    {
      gdb_verbose ("No trace state variable %d, skipping value get", num);
      return 0;
    }

  /* Call a getter function if we have one.  While it's tempting to
     set up something to only call the getter once per tracepoint hit,
     it could run afoul of thread races. Better to let the getter
     handle it directly, if necessary to worry about it.  */
  if (tsv->getter)
    tsv->value = (tsv->getter) (tinfo);

  return tsv->value;
}

/* Set the current value of the given trace state variable whose number is,
   NUM, to VAL.  */
void
trace_state_variable_set_value (int num, int64_t val)
{
  trace_state_variable_t *tsv;

  tsv = trace_state_variable_get (num);

  if (!tsv)
    {
      gdb_verbose ("No trace state variable %d, skipping value set", num);
      return;
    }

  tsv->value = val;
}


/****************************************************************************/

/* Add a raw traceframe for the given tracepoint TPOINT, and return this raw
   traceframe.  */
unsigned char* gdb_trace_buffer_alloc (size_t amt);

static traceframe_t *
traceframe_add (tracepoint_t *tpoint)
{
  traceframe_t *tframe;

  tframe = (traceframe_t *) gdb_trace_buffer_alloc (sizeof (traceframe_t));

  if (tframe == NULL)
    return NULL;

  tframe->tpnum = tpoint->number;
  tframe->data_size = 0;

  /* ++current_tracerun->traceframe_count; */
  ++GDB_AGENT_SYM(traceframes_created);

  return tframe;
}

/* Add a block of desired block size AMT to the traceframe TFRAME currently
   being worked on.  */
unsigned char *
traceframe_add_block (traceframe_t *tframe, int amt)
{
  unsigned char *block;

  if (!tframe)
    return NULL;

  block = gdb_trace_buffer_alloc (amt);

  if (!block)
    return NULL;

  tframe->data_size += amt;

  return block;
}

struct trampoline_block
{
  gdb_addr_t begin, end;
  struct trampoline_block *next;
};

/* A linked-list of blocks of free space in the trampoline buffer.  */

static struct trampoline_block *free_trampoline_blocks = NULL;

gdb_addr_t trampoline_buffer = 0;
gdb_addr_t trampoline_buffer_end = 0;

gdb_addr_t
get_trampoline_buffer (void)
{
  return trampoline_buffer;
}

gdb_addr_t
get_trampoline_buffer_end (void)
{
  return trampoline_buffer_end;
}

/* Reserve USED bytes from the trampoline buffer and return the address of the
   start of the reserved space in TRAMPOLINE.  Returns non-zero if the space
   is successfully claimed.  */

int
claim_trampoline_space (size_t used, gdb_addr_t *trampoline)
{
  struct trampoline_block *prev_block, *block;

  /* Check that there is a trampoline buffer available.  */
  if (!get_trampoline_buffer_end ())
    return 0;

  for (prev_block = NULL, block = free_trampoline_blocks;
       block;
       prev_block = block, block = block->next)
    {
      /* Start claiming space from the top of the first suitably sized free
	 block.  If the trampoline space is located at the bottom of the
	 virtual address space, this reduces the possibility that corruption
	 will occur if a null pointer is used to write to memory.  */
      if (block->end - block->begin >= used)
	{
	  block->end -= used;
	  *trampoline = block->end;

	  /* Remove block if empty.  */
	  if (block->begin == block->end)
	    {
	      /* Maintain linked list.  */
	      if (block == free_trampoline_blocks)
		free_trampoline_blocks = block->next;
	      else
		{
		  assert (prev_block);
		  prev_block->next = block->next;
		}

	      free (block);
	    }

	  gdb_verbose ("claim_trampoline_space reserves 0x%x bytes",
		       (unsigned int) used);

	  return 1;
	}
    }

  /* Failed to find space for trampoline.  */
  return 0;
}

static int
should_stop_tracing (void)
{
  return (GDB_AGENT_SYM(stopping_tracepoint)
	  || GDB_AGENT_SYM(trace_buffer_is_full)
	  || GDB_AGENT_SYM(expr_eval_result) != expr_eval_no_error);
}

/* Record that an error occurred during expression evaluation for tracepoint
   TPOINT.   */

static void
tracepoint_record_error (tracepoint_t *tpoint, const char *which,
			 enum eval_result_type rtype)
{
  gdb_verbose ("Tracepoint %d at 0x%" PRIx64
	       " %s eval reports error %d",
	       tpoint->number, tpoint->addr, which, rtype);

  /* Only record the first error we get.  */
  if (GDB_AGENT_SYM(expr_eval_result) != expr_eval_no_error)
    return;

  GDB_AGENT_SYM(expr_eval_result) = rtype;
  GDB_AGENT_SYM(error_tracepoint) = tpoint;
}


/* Test if the tracepoint POINT's condition is true.  Return 1 if condition
   is true, else 0.  */

int
tracepoint_condition_is_true (tracepoint_t *tpoint,
			      agent_thread_info_t *tinfo,
			      unsigned char *raw_regs)
{
  uint64_t value = 0;
  enum eval_result_type err;

  if (tpoint->compiled_cond)
    err = ((condfn) (ptrdiff_t) (tpoint->compiled_cond)) (raw_regs, &value);
  else
    err = agent_expr_eval (tinfo, raw_regs, NULL, tpoint->cond, &value);

  /* (It would be useful to have a testing mode that would run both
     interpreted and compiled versions, warn about any
     discrepancies) */
  if (err != expr_eval_no_error)
    {
      tracepoint_record_error (tpoint, "condition", err);
      /* The error case must return false.  */
      return 0;
    }

  gdb_verbose ("Tracepoint %d at 0x%" PRIx64
	       " condition evals to %" PRIx64,
	       tpoint->number, tpoint->addr, value);
  return (value ? 1 : 0);
}

/* Perform a tracepoint TPOINT's action TACTION at its hit.  */

static void
tracepoint_do_action (agent_thread_info_t *tinfo,
		      tracepoint_t *tpoint,
		      traceframe_t *tframe,
		      tracepoint_action_t *taction)
{
  int merr;
  enum eval_result_type err;

  gdb_verbose ("Tracepoint %d at 0x%" PRIx64 " about to do action",
	       tpoint->number, tpoint->addr);

  switch (taction->type)
    {
    case 'M':
      {
	struct collect_memory_action *maction;

	maction = (struct collect_memory_action *) taction;

	gdb_verbose ("Want to collect %" PRIu64 " bytes at 0x%"
		     PRIx64" (basereg %d)",
		     maction->len, maction->addr, maction->basereg);
	/* (should use basereg) */
	merr = agent_mem_read (tframe,
			       (gdb_addr_t) maction->addr, maction->len);
	if (merr)
	  {
	    gdb_verbose ("Memory read error %d while collecting", merr);
	    /* We don't get back useful info indicating exactly what
	       happened, so just record it as a generic memory read
	       failure.  */
	    tracepoint_record_error (tpoint, "action expression",
				     expr_eval_mem_read_error);
	    return;
	  }
	break;
      }
    case 'R':
      {
	unsigned char *regspace;

	gdb_verbose ("Want to collect registers");

	/* Collect all registers for now.  */
	regspace = traceframe_add_block (tframe,
					 1 + agent_backend->global_gbufsize);
	if (regspace == NULL)
	  {
	    gdb_verbose ("Trace buffer reg block alloc of %d failed, assuming full",
			 1 + agent_backend->global_gbufsize);
	    GDB_AGENT_SYM(trace_buffer_is_full) = 1;
	    break;
	  }
	/* Identify a register block.  */
	*regspace = 'R';

	memcpy ((void *) (regspace + 1), (void *) tinfo->regblock,
		agent_backend->global_gbufsize);
      }
      break;
    case 'X':
      {
	struct eval_expr_action *eaction;

	eaction = (struct eval_expr_action *) taction;

	if (eaction->expr == NULL)
	  return;

	gdb_verbose ("Want to evaluate expression");

	err = agent_expr_eval (tinfo, NULL, tframe, eaction->expr, NULL);

	if (err != expr_eval_no_error)
	  {
	    tracepoint_record_error (tpoint, "action expression", err);
	    return;
	  }
      }
      break;
    case 'L':
      {
#if defined BUILD_UST
	gdb_inform ("Not implemented yet to collect ust data");
#else
	gdb_verbose ("Warning: static tracepoints are not supported");
#endif
	break;
      }
    default:
      gdb_verbose ("unknown trace action '%c', ignoring", taction->type);
      break;
    }
}

extern void traceframe_finish (traceframe_t *tframe);

/* Create a trace frame for the hit of the given tracepoint TPOINT in the
   given thread TINFO.  */
void
tracepoint_collect_data (agent_thread_info_t *tinfo,
			 tracepoint_t *tpoint,
			 unsigned char *raw_regs)
{
  traceframe_t *tframe;
  int acti;

  /* If we're coming in from a fast tracepoint, set up thread
     info and registers.  */
  if (!tinfo)
    tinfo = agent_thread_info_find_from_pthread (pthread_self ());
  if (raw_regs)
    agent_backend->fast_tracepoint.get_fast_tracepoint_regs (tinfo, raw_regs);

  /* Only count it as a hit when we actually collect data.  */
  tpoint->hit_count++;

  /* If we've exceeded a defined pass count, record the event for
     later, and finish the collection for this hit.  This test is
     only for nonstepping tracepoints, stepping tracepoints test
     at the end of their while-stepping loop.  */
  if (tpoint->pass_count > 0
      && tpoint->hit_count >= tpoint->pass_count
      && tpoint->step_count == 0
      && GDB_AGENT_SYM(stopping_tracepoint) == NULL)
    GDB_AGENT_SYM(stopping_tracepoint) = tpoint;

  gdb_verbose ("Making new traceframe for tracepoint %d at 0x%"
	       PRIx64 ", hit %" PRIu64,
	       (int)tpoint->number, tpoint->addr, tpoint->hit_count);

  tframe = traceframe_add (tpoint);

  if (tframe)
    {
      for (acti = 0; acti < tpoint->numactions; ++acti)
	tracepoint_do_action (tinfo, tpoint, tframe,
			      tpoint->actions[acti]);

      tpoint->traceframe_usage += sizeof (traceframe_t) + tframe->data_size;
      traceframe_finish (tframe);
    }

  if (tframe == NULL)
    GDB_AGENT_SYM(trace_buffer_is_full) = 1;
}

/* This routine is designed to be called from the jump pads of fast
   tracepoint TPOINT and RAW_REGS is a pointer to the saved register block.   */
void
GDB_AGENT_SYM(gdb_collect) (tracepoint_t *tpoint, unsigned char *raw_regs)
{
  tracepoint_t *tp;

  /* Don't do anything until the trace run is completely set up.  */
  if (!GDB_AGENT_SYM(tracing))
    return;

  for (tp = tpoint;
       tp != NULL && tp->addr == tpoint->addr; tp = tp->next)
    {
      if (!tp->enabled)
	continue;

      /* Note that we don't test for disabled tracepoints, because they
	 are never installed in the first place.  This will need to change
	 if we allow enable/disable during a run.  */

      /* Test the condition if present, and collect if true.  */
      if (!tp->cond
	  || tracepoint_condition_is_true (tp, NULL, raw_regs))
	{
	  pthread_t self = pthread_self ();
	  agent_thread_info_t *thread
	    = agent_thread_info_find_from_pthread (pthread_self ());

	  /*
	  if (tp->itset)
	    {

	      if (!itset_contains_thread (tp->base.itset, thread))
		continue;
	    }
	  */
	  if (thread == NULL)
	    thread = agent_thread_info_add (self);

	  tracepoint_collect_data (thread, tp, raw_regs);

	  /* Note that this will cause original insns to be written back to
	     where we jumped from, but that's OK because we're jumping back to
	     the next whole instruction.  This will go badly if instruction
	     restoration is not atomic though.  */
	  if (should_stop_tracing ())
	    GDB_AGENT_SYM(stop_tracing) ();
	}
      else
	{
	  /* If there was a condition and it evaluated to false, the only
	     way we would stop tracing is if there was an error during
	     condition expression evaluation.  */
	  if (GDB_AGENT_SYM(expr_eval_result) != expr_eval_no_error)
	    GDB_AGENT_SYM(stop_tracing) ();
	}
    }
}

extern gdb_addr_t current_insn_ptr;

void
tracepoint_compile_condition (tracepoint_t *tpoint, gdb_addr_t *jump_entry)
{
  gdb_addr_t entry_point = *jump_entry;
  enum eval_result_type err;

  gdb_verbose ("Starting condition compilation for tracepoint %d",
	       tpoint->number);

  /* Initialize the global pointer to the code being built.  */
  current_insn_ptr = *jump_entry;

  emit_prologue ();

  err = agent_expr_compile_bytecodes (tpoint->cond,
				      trace_state_variable_get_value_pself,
				      trace_state_variable_set_value);

  if (err == expr_eval_no_error)
    {
      emit_epilogue ();

      /* Record the beginning of the compiled code.  */
      tpoint->compiled_cond = entry_point;

      gdb_verbose ("Condition compilation for tracepoint %d complete",
		   tpoint->number);
    }
  else
    {
      /* Leave the unfinished code in situ, but don't point to it.  */

      tpoint->compiled_cond = 0;

      gdb_verbose ("Condition compilation for tracepoint %d failed, error code %d",
		   tpoint->number, err);
    }

  /* Update the code pointer passed in.  Note that we do this even if
     the compile fails, so that we can look at the partial results
     instead of letting them be overwritten.  */
  *jump_entry = current_insn_ptr;

  /* Leave a gap, to aid dump decipherment.  */
  *jump_entry += 16;
}

/* Initialize tracepoint module of agent.  */

void
initialize_tracepoint (void)
{
  const int sizeOfBuffer = 5 * 1024 * 1024;
  char *tracebuffer = malloc (sizeOfBuffer);

  GDB_AGENT_SYM(expr_eval_result) = expr_eval_no_error;

  agent_trace_buffer_init (tracebuffer, sizeOfBuffer);
}

