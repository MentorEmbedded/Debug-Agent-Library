/* Agent Expression.

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

#include <stddef.h>
#include <string.h>

#include "agent.h"
#include "log.h"
#include "tracepoint.h"
#include "backend.h"

static int agent_mem_read_to (unsigned char *to,
			      gdb_addr_t from, gdb_size_t len);

static int
is_goto_target (agent_expr_t *aexpr, int pc)
{
  /* FIXME scan for goto's to the given pc */
  return 0;
}

/* Append instructions, basically a memcpy and increment.  Note that
   this can only be safely used to build code in space that is owned
   by the agent, since it is doing direct copies.  */
void
append_insns (gdb_addr_t *to, size_t len, unsigned char *buf)
{
  memcpy ((void *) (ptrdiff_t) *to, (void *) buf, len);
  *to += len;
}

/* Bytecode compilation.  */

/* A global variable that points to the current instruction during bytecode
   compilation.  */
gdb_addr_t current_insn_ptr;

/* A flag that whether an error is emitted during bytecode compilation.  */
int emit_error;

void
add_insns (unsigned char *start, int len)
{
  gdb_addr_t buildaddr = current_insn_ptr;

  gdb_verbose ("Adding %d bytes of insn at 0x%x", len,
	       (unsigned int) buildaddr);

  append_insns (&buildaddr, len, start);
  current_insn_ptr = buildaddr;
}


const char *gdb_agent_op_names [gdb_agent_op_last] =
  {
    "?undef?",
    "float",
    "add",
    "sub",
    "mul",
    "div_signed",
    "div_unsigned",
    "rem_signed",
    "rem_unsigned",
    "lsh",
    "rsh_signed",
    "rsh_unsigned",
    "trace",
    "trace_quick",
    "log_not",
    "bit_and",
    "bit_or",
    "bit_xor",
    "bit_not",
    "equal",
    "less_signed",
    "less_unsigned",
    "ext",
    "ref8",
    "ref16",
    "ref32",
    "ref64",
    "ref_float",
    "ref_double",
    "ref_long_double",
    "l_to_d",
    "d_to_l",
    "if_goto",
    "goto",
    "const8",
    "const16",
    "const32",
    "const64",
    "reg",
    "end",
    "dup",
    "pop",
    "zero_ext",
    "swap",
    "getv",
    "setv",
    "tracev",
    "tracenz"
    "trace16",
  };

/* Given an agent expression AEXPR, turn it into native code.  */

enum eval_result_type
agent_expr_compile_bytecodes (agent_expr_t *aexpr,
			      int64_t (*get_tsv_value_pself) (int num),
			      void (*set_tsv_value) (int num, int64_t val))
{
  int pc = 0;
  int done = 0;
  unsigned char op, next_op;
  int arg;
  /* This is only used to build 64-bit value for constants.  */
  uint64_t top;
  struct bytecode_address *aentry, *aentry2;

#define UNHANDLED \
  gdb_verbose ("Cannot compile op 0x%x", op);  \
  return expr_eval_unhandled_opcode;

  if (aexpr->length == 0)
    {
      gdb_verbose ("empty agent expression");
      return expr_eval_empty_expression;
    }

  bytecode_address_table = NULL;

  while (!done)
    {
      op = aexpr->bytes[pc];

      gdb_verbose ("About to compile op 0x%x, pc=%d", op, pc);

      /* Record the compiled-code address of the bytecode, for use by
	 jump instructions.  */
      aentry = (struct bytecode_address *) malloc (sizeof (struct bytecode_address));
      aentry->pc = pc;
      aentry->address = (unsigned char *) (ptrdiff_t) current_insn_ptr;
      aentry->goto_pc = -1;
      aentry->from_offset = aentry->from_size = 0;
      aentry->next = bytecode_address_table;
      bytecode_address_table = aentry;

      ++pc;

      emit_error = 0;

      switch (op)
	{
	case gdb_agent_op_add:
	  emit_add ();
	  break;

	case gdb_agent_op_sub:
	  emit_sub ();
	  break;

	case gdb_agent_op_mul:
	  emit_mul ();
	  break;

	case gdb_agent_op_div_signed:
	  UNHANDLED;
	  break;

	case gdb_agent_op_div_unsigned:
	  UNHANDLED;
	  break;

	case gdb_agent_op_rem_signed:
	  UNHANDLED;
	  break;

	case gdb_agent_op_rem_unsigned:
	  UNHANDLED;
	  break;

	case gdb_agent_op_lsh:
	  emit_lsh ();
	  break;

	case gdb_agent_op_rsh_signed:
	  emit_rsh_signed ();
	  break;

	case gdb_agent_op_rsh_unsigned:
	  emit_rsh_unsigned ();
	  break;

	case gdb_agent_op_trace:
	  UNHANDLED;
	  break;

	case gdb_agent_op_trace_quick:
	  UNHANDLED;
	  break;

	case gdb_agent_op_log_not:
	  emit_log_not ();
	  break;

	case gdb_agent_op_bit_and:
	  emit_bit_and ();
	  break;

	case gdb_agent_op_bit_or:
	  emit_bit_or ();
	  break;

	case gdb_agent_op_bit_xor:
	  emit_bit_xor ();
	  break;

	case gdb_agent_op_bit_not:
	  emit_bit_not ();
	  break;

	case gdb_agent_op_equal:
	  next_op = aexpr->bytes[pc];
	  if (next_op == gdb_agent_op_if_goto
	      && !is_goto_target (aexpr, pc))
	    {
	      gdb_verbose ("Combining equal & if_goto");
	      pc += 1;
	      aentry->pc = pc;
	      arg = aexpr->bytes[pc++];
	      arg = (arg << 8) + aexpr->bytes[pc++];
	      aentry->goto_pc = arg;
	      emit_eq_goto (&(aentry->from_offset), &(aentry->from_size));
	    }
	  else if (next_op == gdb_agent_op_log_not
		   && (aexpr->bytes[pc+1] == gdb_agent_op_if_goto)
		   && !is_goto_target (aexpr, pc+1))
	    {
	      gdb_verbose ("Combining equal & log_not & if_goto");
	      pc += 2;
	      aentry->pc = pc;
	      arg = aexpr->bytes[pc++];
	      arg = (arg << 8) + aexpr->bytes[pc++];
	      aentry->goto_pc = arg;
	      emit_ne_goto (&(aentry->from_offset), &(aentry->from_size));
	    }
	  else
	    emit_equal ();
	  break;

	case gdb_agent_op_less_signed:
	  next_op = aexpr->bytes[pc];
	  if (next_op == gdb_agent_op_if_goto
	      && !is_goto_target (aexpr, pc))
	    {
	      gdb_verbose ("Combining less_signed & if_goto");
	      pc += 1;
	      aentry->pc = pc;
	      arg = aexpr->bytes[pc++];
	      arg = (arg << 8) + aexpr->bytes[pc++];
	      aentry->goto_pc = arg;
	      emit_lt_goto (&(aentry->from_offset), &(aentry->from_size));
	    }
	  else if (next_op == gdb_agent_op_log_not
		   && !is_goto_target (aexpr, pc)
		   && (aexpr->bytes[pc+1] == gdb_agent_op_if_goto)
		   && !is_goto_target (aexpr, pc+1))
	    {
	      gdb_verbose ("Combining less_signed & log_not & if_goto");
	      pc += 2;
	      aentry->pc = pc;
	      arg = aexpr->bytes[pc++];
	      arg = (arg << 8) + aexpr->bytes[pc++];
	      aentry->goto_pc = arg;
	      emit_ge_goto (&(aentry->from_offset), &(aentry->from_size));
	    }
	  else
	    emit_less_signed ();
	  break;

	case gdb_agent_op_less_unsigned:
	  emit_less_unsigned ();
	  break;

	case gdb_agent_op_ext:
	  arg = aexpr->bytes[pc++];
	  if (arg < (int) (sizeof (int64_t) * 8))
	    emit_ext (arg);
	  break;

	case gdb_agent_op_ref8:
	  emit_ref (1, agent_mem_read_to);
	  break;

	case gdb_agent_op_ref16:
	  emit_ref (2, agent_mem_read_to);
	  break;

	case gdb_agent_op_ref32:
	  emit_ref (4, agent_mem_read_to);
	  break;

	case gdb_agent_op_ref64:
	  emit_ref (8, agent_mem_read_to);
	  break;

	case gdb_agent_op_if_goto:
	  arg = aexpr->bytes[pc++];
	  arg = (arg << 8) + aexpr->bytes[pc++];
	  aentry->goto_pc = arg;
	  emit_if_goto (&(aentry->from_offset), &(aentry->from_size));
	  break;

	case gdb_agent_op_goto:
	  arg = aexpr->bytes[pc++];
	  arg = (arg << 8) + aexpr->bytes[pc++];
	  aentry->goto_pc = arg;
	  emit_goto (&(aentry->from_offset), &(aentry->from_size));
	  break;

	case gdb_agent_op_const8:
	  emit_stack_flush ();
	  top = aexpr->bytes[pc++];
	  emit_const (top);
	  break;

	case gdb_agent_op_const16:
	  emit_stack_flush ();
	  top = aexpr->bytes[pc++];
	  top = (top << 8) + aexpr->bytes[pc++];
	  emit_const (top);
	  break;

	case gdb_agent_op_const32:
	  emit_stack_flush ();
	  top = aexpr->bytes[pc++];
	  top = (top << 8) + aexpr->bytes[pc++];
	  top = (top << 8) + aexpr->bytes[pc++];
	  top = (top << 8) + aexpr->bytes[pc++];
	  emit_const (top);
	  break;

	case gdb_agent_op_const64:
	  emit_stack_flush ();
	  top = aexpr->bytes[pc++];
	  top = (top << 8) + aexpr->bytes[pc++];
	  top = (top << 8) + aexpr->bytes[pc++];
	  top = (top << 8) + aexpr->bytes[pc++];
	  top = (top << 8) + aexpr->bytes[pc++];
	  top = (top << 8) + aexpr->bytes[pc++];
	  top = (top << 8) + aexpr->bytes[pc++];
	  top = (top << 8) + aexpr->bytes[pc++];
	  emit_const (top);
	  break;

	case gdb_agent_op_reg:
	  emit_stack_flush ();
	  arg = aexpr->bytes[pc++];
	  arg = (arg << 8) + aexpr->bytes[pc++];
	  emit_reg (arg);
	  break;

	case gdb_agent_op_end:
	  gdb_verbose ("At end of expression");

	  /* Assume there is one stack element left, and that it is
	     cached in "top" where emit_epilogue can get to it.  */
	  emit_stack_adjust (1);

	  done = 1;
	  break;

	case gdb_agent_op_dup:
	  /* In our design, dup is equivalent to stack flushing.  */
	  emit_stack_flush ();
	  break;

	case gdb_agent_op_pop:
	  emit_pop ();
	  break;

	case gdb_agent_op_zero_ext:
	  arg = aexpr->bytes[pc++];
	  if (arg < (int) (sizeof (int64_t) * 8))
	    emit_zero_ext (arg);
	  break;

	case gdb_agent_op_swap:
	  next_op = aexpr->bytes[pc];
	  /* Detect greater-than comparison sequences.  */
	  if (next_op == gdb_agent_op_less_signed
	      && !is_goto_target (aexpr, pc)
	      && (aexpr->bytes[pc+1] == gdb_agent_op_if_goto)
	      && !is_goto_target (aexpr, pc+1))
	    {
	      gdb_verbose ("Combining swap & less_signed & if_goto");
	      pc += 2;
	      aentry->pc = pc;
	      arg = aexpr->bytes[pc++];
	      arg = (arg << 8) + aexpr->bytes[pc++];
	      aentry->goto_pc = arg;
	      emit_gt_goto (&(aentry->from_offset), &(aentry->from_size));
	    }
	  else if (next_op == gdb_agent_op_less_signed
		   && !is_goto_target (aexpr, pc)
		   && (aexpr->bytes[pc+1] == gdb_agent_op_log_not)
		   && !is_goto_target (aexpr, pc+1)
		   && (aexpr->bytes[pc+2] == gdb_agent_op_if_goto)
		   && !is_goto_target (aexpr, pc+2))
	    {
	      gdb_verbose ("Combining swap & less_signed & log_not & if_goto");
	      pc += 3;
	      aentry->pc = pc;
	      arg = aexpr->bytes[pc++];
	      arg = (arg << 8) + aexpr->bytes[pc++];
	      aentry->goto_pc = arg;
	      emit_le_goto (&(aentry->from_offset), &(aentry->from_size));
	    }
	  else
	    emit_swap ();
	  break;

	case gdb_agent_op_getv:
	  emit_stack_flush ();
	  arg = aexpr->bytes[pc++];
	  arg = (arg << 8) + aexpr->bytes[pc++];
	  emit_int_call_1 (get_tsv_value_pself, arg);
	  break;

	case gdb_agent_op_setv:
	  arg = aexpr->bytes[pc++];
	  arg = (arg << 8) + aexpr->bytes[pc++];
	  emit_void_call_2 (set_tsv_value, arg);
	  break;

	case gdb_agent_op_tracev:
	  UNHANDLED;
	  break;

	  /* GDB never (currently) generates any of these ops.  */
	case gdb_agent_op_float:
	case gdb_agent_op_ref_float:
	case gdb_agent_op_ref_double:
	case gdb_agent_op_ref_long_double:
	case gdb_agent_op_l_to_d:
	case gdb_agent_op_d_to_l:
	case gdb_agent_op_trace16:
	  UNHANDLED;
	  break;

	default:
	  gdb_verbose ("Agent expression op 0x%x not recognized", op);
	  /* Don't struggle on, things will just get worse.  */
	  return expr_eval_unrecognized_opcode;
	}
      
      /* This catches errors that occur in target-specific code
	 emission.  */
      if (emit_error)
	{
	  gdb_verbose ("Error %d while emitting code for %s",
		       emit_error, gdb_agent_op_names[op]);
	  return expr_eval_unhandled_opcode;
	}

      gdb_verbose ("Op %s compiled", gdb_agent_op_names[op]);
    }

  /* Now fill in real addresses as goto destinations.  */
  for (aentry = bytecode_address_table; aentry; aentry = aentry->next)
    {
      int written = 0;

      if (aentry->goto_pc < 0)
	continue;

      /* Find the location that we are going to, and call back into
	 target-specific code to write the actual address or
	 displacement.  */
      for (aentry2 = bytecode_address_table; aentry2; aentry2 = aentry2->next)
	{
	  if (aentry2->pc == aentry->goto_pc)
	    {
	      gdb_verbose ("Want to jump from 0x%lx to 0x%lx",
			   (unsigned long) aentry->address,
			   (unsigned long) aentry2->address);
	      write_goto_address (aentry->address + aentry->from_offset,
				  aentry2->address, aentry->from_size);
	      written = 1;
	      break;
	    }
	}

      /* Error out if we didn't find a destination.  */
      if (!written)
	{
	  gdb_verbose ("Destination of goto %d not found",
		       aentry->goto_pc);
	  return expr_eval_invalid_goto;
	}
    }

  return expr_eval_no_error;
}

/* Record the value of a trace state variable, whose number is N, from
   traceframe TFRAME.  Return 0 if success, otherwise return non-zero.  */

static int
agent_tsv_read (traceframe_t *tframe, int n)
{
  int amt = 1 + sizeof (n) + sizeof (int64_t);
  unsigned char *vspace;
  int64_t val;

  vspace = traceframe_add_block (tframe, amt);
  if (vspace == NULL)
    {
      gdb_verbose ("Trace buffer tsv block alloc of %d failed, assuming full",
		   amt);
       GDB_AGENT_SYM(trace_buffer_is_full) = 1;
      /* Don't say fullness is an error.  */
      return 0;
    }
  /* Identify block as a variable.  */
  *vspace = 'V';
  /* Record variable's number and value.  */
  memcpy ((void *) (vspace + 1), (void *) &n, sizeof (n));
  val = trace_state_variable_get_value (NULL, n);
  memcpy ((void *) (vspace + 1 + sizeof (n)), (void *) &val, sizeof (val));
  gdb_verbose ("Variable %d recorded", n);
  return 0;
}

/* Do memory copies for bytecodes from address FROM to buffer TO.  LEN is the
   length to copy.  */
static int
agent_mem_read_to (unsigned char *to,
		   gdb_addr_t from, gdb_size_t len)
{

  int err;
  size_t nbytes;
  err = agent_read_mem (from, len, to, &nbytes);
  /* If the basic read succeeded, but it didn't return all the bytes
     we asked for, things are going to go downhill in a hurry; flag it
     as an error.  */
  if (err == 0 && nbytes < len)
    err = 1;

  return err;

}

/* Do the recording of memory blocks in traceframe TFRAME for actions and
   bytecodes.  Copy from address FROM of length LEN.  Return 0 if success,
   otherwise return non-zero.   */
int
agent_mem_read (traceframe_t *tframe,
		gdb_addr_t from, gdb_size_t len)
{
  unsigned char *mspace;
  size_t nbytes;
  gdb_size_t remaining = len;
  unsigned short blocklen;
  int amt, err;

  /* To save a bit of space, block lengths are 16-bit, so break large
     requests into multiple blocks.  */
  while (remaining > 0)
    {
      blocklen = (remaining > 65535 ? 65535 : remaining);
      amt = 1 + sizeof (from) + sizeof (blocklen) + blocklen;
      mspace = traceframe_add_block (tframe, amt);
      if (mspace == NULL)
	{
	  gdb_verbose ("Trace buffer mem block alloc of %d failed, assuming full",
		       amt);
	   GDB_AGENT_SYM(trace_buffer_is_full) = 1;
	  /* Don't say fullness is an error.  */
	  return 0;
	}
      /* Identify block as a memory block.  */
      *mspace = 'M';
      ++mspace;
      /* Record address and size.  */
      memcpy ((void *) mspace, (void *) &from, sizeof (from));
      mspace += sizeof (from);
      memcpy ((void *) mspace, (void *) &blocklen, sizeof (blocklen));
      mspace += sizeof (blocklen);
      /* Record the memory block proper, using API.  */
      err = agent_read_mem (from, blocklen, mspace, &nbytes);
      if (err)
	{
	  gdb_verbose ("Memory read error %d while recording", err);
	  /* Note that despite us returning suddenly, the traceframe
	     block is correctly formed, although its contents may be
	     random junk.  */
	  return 2;
	}
      gdb_verbose ("%d bytes recorded", (unsigned)nbytes);
      remaining -= blocklen;
      from += blocklen;
    }
  return 0;
}

/* Do the recording of strings to traceframe TFRAME for actions and bytecodes.
   Copy from address FROM of length LEN.  Return 0 if success, otherwise, return
   non-zero.  */
static int
agent_mem_read_string (traceframe_t *tframe,
		       gdb_addr_t from, gdb_size_t len)
{
  unsigned char *buf, *mspace;
  size_t nbytes;
  gdb_size_t remaining = len;
  unsigned short blocklen, i;
  int amt, err;

  /* To save a bit of space, block lengths are 16-bit, so break large
     requests into multiple blocks.  Bordering on overkill for strings,
     but it could happen that someone specifies a large max length.  */
  while (remaining > 0)
    {
      blocklen = (remaining > 65535 ? 65535 : remaining);
      /* We want working space to accumulate nonzero bytes, since
	 traceframes must have a predecided size (otherwise it gets
	 harder to wrap correctly for the circular case, etc).  */
      buf = (unsigned char *) malloc (blocklen + 1);
      for (i = 0; i < blocklen; ++i)
	{
	  /* Get a single byte, using API.  This is not ideal, but
	     with larger blocks we would have to be careful about
	     out-of-bounds reads.  */
	  err = agent_read_mem (from + i, 1, buf + i, &nbytes);
	  if (err)
	    {
	      gdb_verbose ("Memory read error %d while recording", err);
	      free (buf);
	      return 2;
	    }

	  if (buf[i] == '\0')
	    {
	      blocklen = i + 1;
	      /* Make sure outer loop stops now too.  */
	      remaining = blocklen;
	      break;
	    }
	}
      amt = 1 + sizeof (from) + sizeof (blocklen) + blocklen;
      mspace = traceframe_add_block (tframe, amt);
      if (mspace == NULL)
	{
	  gdb_verbose ("Trace buffer mem block alloc of %d failed, assuming full",
		       amt);
	   GDB_AGENT_SYM(trace_buffer_is_full) = 1;
	  free (buf);
	  /* Don't say fullness is an error.  */
	  return 0;
	}
      /* Identify block as a memory block.  */
      *mspace = 'M';
      ++mspace;
      /* Record address and size.  */
      memcpy ((void *) mspace, (void *) &from, sizeof (from));
      mspace += sizeof (from);
      memcpy ((void *) mspace, (void *) &blocklen, sizeof (blocklen));
      mspace += sizeof (blocklen);
      /* Copy the string contents.  */
      memcpy ((void *) mspace, (void *) buf, blocklen);
      remaining -= blocklen;
      from += blocklen;
      free (buf);
    }
  return 0;
}

/* The agent expression evaluator, as specified by the GDB docs. Evaluate
   agent expression AEXPR for thread TINFO.  RAW_REGS points to block of
   registers.  TFRAME is a traceframe to get any trace data.  Evaluation
   result value is put in RSLT.  It returns 0 if everything went OK, and
   a nonzero error code otherwise.  */
enum eval_result_type
agent_expr_eval (agent_thread_info_t *tinfo,
		 unsigned char *raw_regs,
		 traceframe_t *tframe,
		 agent_expr_t *aexpr,
		 uint64_t *rslt)
{
  int pc = 0;
#define STACK_MAX 100
  uint64_t stack[STACK_MAX] = {(uint64_t) 0};
  uint64_t top;
  int sp = 0;
  unsigned char op;
  int arg, err;

  /* This union is a convenient way to convert representations.  */
  union
  {
    union
    {
      unsigned char bytes[1];
      uint8_t val;
    } u8;
    union
    {
      unsigned char bytes[2];
      uint16_t val;
    } u16;
    union
    {
      unsigned char bytes[4];
      uint32_t val;
    } u32;
    union
    {
      unsigned char bytes[8];
      uint64_t val;
    } u64;
  } cnv;

  if (aexpr->length == 0)
    {
      gdb_verbose ("empty agent expression");
      return expr_eval_empty_expression;
    }

  /* Cache the stack top in its own variable. Much of the time we can
     operate on this variable, rather than dinking with the stack. It
     needs to be copied to the stack when sp changes.  */
  top = stack[sp];

  while (1)
    {
      op = aexpr->bytes[pc++];

      gdb_verbose ("About to interpret byte 0x%x", op);

      switch (op)
	{
	case gdb_agent_op_add:
	  top += stack[--sp];
	  break;

	case gdb_agent_op_sub:
	  top = stack[--sp] - top;
	  break;

	case gdb_agent_op_mul:
	  top *= stack[--sp];
	  break;

	case gdb_agent_op_div_signed:
	  if (top == 0)
	    {
	      gdb_verbose ("Attempted to divide by zero");
	      return expr_eval_divide_by_zero;
	    }
	  top = ((int64_t) stack[--sp]) / ((int64_t) top);
	  break;

	case gdb_agent_op_div_unsigned:
	  if (top == 0)
	    {
	      gdb_verbose ("Attempted to divide by zero");
	      return expr_eval_divide_by_zero;
	    }
	  top = stack[--sp] / top;
	  break;

	case gdb_agent_op_rem_signed:
	  if (top == 0)
	    {
	      gdb_verbose ("Attempted to divide by zero");
	      return expr_eval_divide_by_zero;
	    }
	  top = ((int64_t) stack[--sp]) % ((int64_t) top);
	  break;

	case gdb_agent_op_rem_unsigned:
	  if (top == 0)
	    {
	      gdb_verbose ("Attempted to divide by zero");
	      return expr_eval_divide_by_zero;
	    }
	  top = stack[--sp] % top;
	  break;

	case gdb_agent_op_lsh:
	  top = stack[--sp] << top;
	  break;

	case gdb_agent_op_rsh_signed:
	  top = ((int64_t) stack[--sp]) >> top;
	  break;

	case gdb_agent_op_rsh_unsigned:
	  top = stack[--sp] >> top;
	  break;

	case gdb_agent_op_trace:
	  err = agent_mem_read (tframe,
				(gdb_addr_t) stack[--sp], (gdb_size_t) top);
	  if (err)
	    {
	      gdb_verbose ("Memory read error %d", err);
	      return expr_eval_mem_read_error;
	    }
	  if (--sp >= 0)
	    top = stack[sp];
	  break;

	case gdb_agent_op_trace_quick:
	  arg = aexpr->bytes[pc++];
	  err = agent_mem_read (tframe,
				(gdb_addr_t) top, (gdb_size_t) arg);
	  if (err)
	    {
	      gdb_verbose ("Memory read error %d", err);
	      return expr_eval_mem_read_error;
	    }
	  break;

	case gdb_agent_op_tracenz:
	  err = agent_mem_read_string (tframe,
				       (gdb_addr_t) stack[--sp],
				       (gdb_size_t) top);
	  if (err)
	    {
	      gdb_verbose ("Memory read error %d", err);
	      return expr_eval_mem_read_error;
	    }
	  if (--sp >= 0)
	    top = stack[sp];
	  break;

	case gdb_agent_op_log_not:
	  top = !top;
	  break;

	case gdb_agent_op_bit_and:
	  top &= stack[--sp];
	  break;

	case gdb_agent_op_bit_or:
	  top |= stack[--sp];
	  break;

	case gdb_agent_op_bit_xor:
	  top ^= stack[--sp];
	  break;

	case gdb_agent_op_bit_not:
	  top = ~top;
	  break;

	case gdb_agent_op_equal:
	  top = (stack[--sp] == top);
	  break;

	case gdb_agent_op_less_signed:
	  top = (((int64_t) stack[--sp]) < ((int64_t) top));
	  break;

	case gdb_agent_op_less_unsigned:
	  top = (stack[--sp] < top);
	  break;

	case gdb_agent_op_ext:
	  arg = aexpr->bytes[pc++];
	  if (arg < (int) (sizeof (int64_t) * 8))
	    {
	      int64_t mask = 1 << (arg - 1);
	      top &= ((int64_t) 1 << arg) - 1;
	      top = (top ^ mask) - mask;
	    }
	  break;

	case gdb_agent_op_ref8:
	  err = agent_mem_read_to (cnv.u8.bytes, (gdb_addr_t) top, 1);
	  if (err)
	    {
	      gdb_verbose ("Memory read error %d", err);
	      return expr_eval_mem_read_error;
	    }
	  top = cnv.u8.val;
	  break;

	case gdb_agent_op_ref16:
	  err = agent_mem_read_to (cnv.u16.bytes, (gdb_addr_t) top, 2);
	  if (err)
	    {
	      gdb_verbose ("Memory read error %d", err);
	      return expr_eval_mem_read_error;
	    }
	  asm volatile ("# marker3");
	  top = cnv.u16.val;
	  break;

	case gdb_agent_op_ref32:
	  err = agent_mem_read_to (cnv.u32.bytes, (gdb_addr_t) top, 4);
	  if (err)
	    {
	      gdb_verbose ("Memory read error %d", err);
	      return expr_eval_mem_read_error;
	    }
	  top = cnv.u32.val;
	  break;

	case gdb_agent_op_ref64:
	  err = agent_mem_read_to (cnv.u64.bytes, (gdb_addr_t) top, 8);
	  if (err)
	    {
	      gdb_verbose ("Memory read error %d", err);
	      return expr_eval_mem_read_error;
	    }
	  top = cnv.u64.val;
	  break;

	case gdb_agent_op_if_goto:
	  if (top)
	    pc = (aexpr->bytes[pc] << 8) + (aexpr->bytes[pc + 1]);
	  else
	    pc += 2;
	  if (--sp >= 0)
	    top = stack[sp];
	  break;

	case gdb_agent_op_goto:
	  pc = (aexpr->bytes[pc] << 8) + (aexpr->bytes[pc + 1]);
	  break;

	case gdb_agent_op_const8:
	  /* Flush the cached stack top.  */
	  stack[sp++] = top;
	  top = aexpr->bytes[pc++];
	  break;

	case gdb_agent_op_const16:
	  /* Flush the cached stack top.  */
	  stack[sp++] = top;
	  top = aexpr->bytes[pc++];
	  top = (top << 8) + aexpr->bytes[pc++];
	  break;

	case gdb_agent_op_const32:
	  /* Flush the cached stack top.  */
	  stack[sp++] = top;
	  top = aexpr->bytes[pc++];
	  top = (top << 8) + aexpr->bytes[pc++];
	  top = (top << 8) + aexpr->bytes[pc++];
	  top = (top << 8) + aexpr->bytes[pc++];
	  break;

	case gdb_agent_op_const64:
	  /* Flush the cached stack top.  */
	  stack[sp++] = top;
	  top = aexpr->bytes[pc++];
	  top = (top << 8) + aexpr->bytes[pc++];
	  top = (top << 8) + aexpr->bytes[pc++];
	  top = (top << 8) + aexpr->bytes[pc++];
	  top = (top << 8) + aexpr->bytes[pc++];
	  top = (top << 8) + aexpr->bytes[pc++];
	  top = (top << 8) + aexpr->bytes[pc++];
	  top = (top << 8) + aexpr->bytes[pc++];
	  break;

	case gdb_agent_op_reg:
	  /* Flush the cached stack top.  */
	  stack[sp++] = top;
	  arg = aexpr->bytes[pc++];
	  arg = (arg << 8) + aexpr->bytes[pc++];
	  if (tinfo)
	    top = agent_backend->reg.get_reg (tinfo, arg);
	  else if (raw_regs)
	    top = agent_backend->reg.get_raw_reg (raw_regs, arg);
	  else
	    {
	      gdb_verbose ("No registers available");
	      return expr_eval_no_registers;
	    }
	  break;

	case gdb_agent_op_end:
	  gdb_verbose ("At end of expression, sp=%d, stack top cache=0x%"
		       PRIx64, sp, top);
	  if (rslt)
	    {
	      if (sp <= 0)
		{
		  /* This should be an error */
		  gdb_verbose ("Stack is empty, nothing to return");
		  return expr_eval_empty_stack;
		}
	      *rslt = top;
	    }
	  return expr_eval_no_error;

	case gdb_agent_op_dup:
	  stack[sp++] = top;
	  break;

	case gdb_agent_op_pop:
	  if (--sp >= 0)
	    top = stack[sp];
	  break;

	case gdb_agent_op_zero_ext:
	  arg = aexpr->bytes[pc++];
	  if (arg < (int) (sizeof (int64_t) * 8))
	    top &= ((int64_t) 1 << arg) - 1;
	  break;

	case gdb_agent_op_swap:
	  /* Interchange top two stack elements, making sure top gets
	     copied back onto stack.  */
	  /* FIXME error if sp==0 */
	  stack[sp] = top;
	  top = stack[sp - 1];
	  stack[sp - 1] = stack[sp];
	  break;

	case gdb_agent_op_getv:
	  stack[sp++] = top;
	  arg = aexpr->bytes[pc++];
	  arg = (arg << 8) + aexpr->bytes[pc++];
	  top = trace_state_variable_get_value (tinfo, arg);
	  break;

	case gdb_agent_op_setv:
	  arg = aexpr->bytes[pc++];
	  arg = (arg << 8) + aexpr->bytes[pc++];
	  trace_state_variable_set_value (arg, top);
	  break;

	case gdb_agent_op_tracev:
	  arg = aexpr->bytes[pc++];
	  arg = (arg << 8) + aexpr->bytes[pc++];
	  agent_tsv_read (tframe, arg);
	  break;

	  /* GDB never (currently) generates any of these ops.  */
	case gdb_agent_op_float:
	case gdb_agent_op_ref_float:
	case gdb_agent_op_ref_double:
	case gdb_agent_op_ref_long_double:
	case gdb_agent_op_l_to_d:
	case gdb_agent_op_d_to_l:
	case gdb_agent_op_trace16:
	  gdb_verbose ("Agent expression op 0x%x valid, but not handled", op);
	  /* If ever GDB generates any of these, we don't have the
	     option of ignoring.  */
	  return expr_eval_unhandled_opcode;

	default:
	  gdb_verbose ("Agent expression op 0x%x not recognized", op);
	  /* Don't struggle on, things will just get worse.  */
	  return expr_eval_unrecognized_opcode;
	}

      /* Check for stack badness.  */
      if (sp >= (STACK_MAX - 1))
	{
	  gdb_verbose ("Expression stack overflow");
	  return expr_eval_stack_overflow;
	}

      if (sp < 0)
	{
	  gdb_verbose ("Expression stack underflow");
	  return expr_eval_stack_underflow;
	}

      gdb_verbose ("Op %s -> sp=%d, top=0x%" PRIx64,
		   gdb_agent_op_names[op], sp, top);
    }
}

