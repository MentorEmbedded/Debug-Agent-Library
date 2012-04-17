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

#ifndef AGENT_EXPR_H
#define AGENT_EXPR_H 1

#include <stdint.h>
#include "thread.h"

typedef struct agent_expr_t
{

  int length;

  unsigned char *bytes;

} agent_expr_t;

struct bytecode_address
{
  int pc;
  unsigned char *address;
  int goto_pc;
  /* Offset and size of field to be modified in the goto block */
  int from_offset, from_size;
  struct bytecode_address *next;
} *bytecode_address_table;

/* Enumeration of the different kinds of things that can happen during
   agent expression evaluation.  */

enum eval_result_type
  {
    expr_eval_no_error,
    expr_eval_empty_expression,
    expr_eval_empty_stack,
    expr_eval_stack_overflow,
    expr_eval_stack_underflow,
    expr_eval_unhandled_opcode,
    expr_eval_unrecognized_opcode,
    expr_eval_divide_by_zero,
    expr_eval_no_registers,
    expr_eval_invalid_goto,
    expr_eval_mem_read_error = 10
  };

typedef enum eval_result_type (*condfn) (unsigned char *, uint64_t *);

/* This enum must exactly match what is documented in
   gdb/doc/agentexpr.texi, including all the numerical values.  */

enum gdb_agent_op
  {
    gdb_agent_op_float = 0x01,
    gdb_agent_op_add = 0x02,
    gdb_agent_op_sub = 0x03,
    gdb_agent_op_mul = 0x04,
    gdb_agent_op_div_signed = 0x05,
    gdb_agent_op_div_unsigned = 0x06,
    gdb_agent_op_rem_signed = 0x07,
    gdb_agent_op_rem_unsigned = 0x08,
    gdb_agent_op_lsh = 0x09,
    gdb_agent_op_rsh_signed = 0x0a,
    gdb_agent_op_rsh_unsigned = 0x0b,
    gdb_agent_op_trace = 0x0c,
    gdb_agent_op_trace_quick = 0x0d,
    gdb_agent_op_log_not = 0x0e,
    gdb_agent_op_bit_and = 0x0f,
    gdb_agent_op_bit_or = 0x10,
    gdb_agent_op_bit_xor = 0x11,
    gdb_agent_op_bit_not = 0x12,
    gdb_agent_op_equal = 0x13,
    gdb_agent_op_less_signed = 0x14,
    gdb_agent_op_less_unsigned = 0x15,
    gdb_agent_op_ext = 0x16,
    gdb_agent_op_ref8 = 0x17,
    gdb_agent_op_ref16 = 0x18,
    gdb_agent_op_ref32 = 0x19,
    gdb_agent_op_ref64 = 0x1a,
    gdb_agent_op_ref_float = 0x1b,
    gdb_agent_op_ref_double = 0x1c,
    gdb_agent_op_ref_long_double = 0x1d,
    gdb_agent_op_l_to_d = 0x1e,
    gdb_agent_op_d_to_l = 0x1f,
    gdb_agent_op_if_goto = 0x20,
    gdb_agent_op_goto = 0x21,
    gdb_agent_op_const8 = 0x22,
    gdb_agent_op_const16 = 0x23,
    gdb_agent_op_const32 = 0x24,
    gdb_agent_op_const64 = 0x25,
    gdb_agent_op_reg = 0x26,
    gdb_agent_op_end = 0x27,
    gdb_agent_op_dup = 0x28,
    gdb_agent_op_pop = 0x29,
    gdb_agent_op_zero_ext = 0x2a,
    gdb_agent_op_swap = 0x2b,
    gdb_agent_op_getv = 0x2c,
    gdb_agent_op_setv = 0x2d,
    gdb_agent_op_tracev = 0x2e,
    gdb_agent_op_tracenz = 0x2f,
    gdb_agent_op_trace16 = 0x30,
    gdb_agent_op_last
  };

struct traceframe_t;

int agent_mem_read (struct traceframe_t *tframe,
		    gdb_addr_t from,  gdb_size_t len);

enum eval_result_type agent_expr_eval (agent_thread_info_t *tinfo,
				       unsigned char *raw_regs,
				       struct traceframe_t *tframe,
				       agent_expr_t *aexpr,
				       uint64_t *rslt);

enum eval_result_type agent_expr_compile_bytecodes (agent_expr_t *aexpr,
						    int64_t (*get_tsv_value_pself) (int num),
						    void (*set_tsv_value) (int num, int64_t val));

void add_insns (unsigned char *start, int len);
void append_insns (gdb_addr_t *to, size_t len, unsigned char *buf);

extern int emit_error;
extern gdb_addr_t current_insn_ptr;

#endif
