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

#include <stdint.h>
#include <ucontext.h>

#include "thread.h"
#include "defs.h"

#include "config.h"

struct bytecode_compiler_emit_backend
{
  void (*emit_prologue) (void);
  void (*emit_epilogue) (void);
  void (*emit_add) (void);
  void (*emit_sub) (void);
  void (*emit_mul) (void);
  void (*emit_lsh) (void);
  void (*emit_rsh_signed) (void);
  void (*emit_rsh_unsigned) (void);
  void (*emit_ext) (int arg);
  void (*emit_log_not) (void);
  void (*emit_bit_and) (void);
  void (*emit_bit_or) (void);
  void (*emit_bit_xor) (void);
  void (*emit_bit_not) (void);
  void (*emit_equal) (void);
  void (*emit_less_signed) (void);
  void (*emit_less_unsigned) (void);
  void (*emit_ref) (int size,
		    int (*agent_mem_read_to) (unsigned char *,
					      gdb_addr_t from, gdb_size_t));
  void (*emit_if_goto) (int *offset_p, int *size_p);
  void (*emit_goto) (int *offset_p, int *size_p);

  void (*write_goto_address) (unsigned char *from, unsigned char *to, int size);

  void (*emit_const) (int64_t num);

  void (*emit_call) (void *fn);

  void (*emit_reg) (int reg);
  void (*emit_pop) (void);
  void (*emit_stack_flush) (void);
  void (*emit_zero_ext) (int arg);
  void (*emit_swap) (void);
  void (*emit_stack_adjust) (int n);

  void (*emit_int_call_1) (int64_t (*fn) (int), int arg1);
  void (*emit_void_call_2) (void (*fn) (int, int64_t), int arg1);

  void (*emit_eq_goto) (int *offset_p, int *size_p);
  void (*emit_ne_goto) (int *offset_p, int *size_p);
  void (*emit_lt_goto) (int *offset_p, int *size_p);
  void (*emit_le_goto) (int *offset_p, int *size_p);
  void (*emit_gt_goto) (int *offset_p, int *size_p);
  void (*emit_ge_goto) (int *offset_p, int *size_p);
};

struct fast_tracepoint_backend
{
  /* Determine needs trampoline buffer or not.   */
  int need_tramploline_buffer_p;

  /* Move a block of saved registers REGS (typically located on the stack)
     into a thread TINFO's register block.  */
  void (*get_fast_tracepoint_regs) (agent_thread_info_t *tinfo,
				    unsigned char *regs);

  int (*install_fast_tracepoint_jump_pad) (gdb_addr_t tpoint, gdb_addr_t tpaddr,
					   gdb_addr_t collector,
					   unsigned char *orig_bytes,
					   size_t orig_size,
					   gdb_addr_t *jump_entry,
					   unsigned char *jjumppad_insn,
					   size_t *jjumppad_insn_size,
					   gdb_addr_t *trampoline,
					   size_t *trampoline_size,
					   char *err);
};

#if defined BUILD_UST
/* "struct registers" is the UST object type holding the registers at
   the time of the static tracepoint marker call.  */

#define ST_COLLECT_REG(REG)			\
  {						\
    offsetof (struct registers, REG),		\
    sizeof (((struct registers *) NULL)->REG)	\
  }

struct ust_register_map
{
  int offset;
  int size;
};

struct static_tracepoint_backend
{
  struct ust_register_map *collect_regmap;
  int collect_reg_num;
  int pc_reg_num;
};
#endif

struct register_backend
{
  uint64_t (*get_reg) (agent_thread_info_t *tinfo, int regnum);
  void (*set_reg) (agent_thread_info_t *tinfo, int regnum, uint64_t val);
  uint64_t (*get_raw_reg) (unsigned char *raw_regs, int regnum);
};

struct backend
{
  struct register_backend reg;

  struct fast_tracepoint_backend fast_tracepoint;

#if defined BUILD_UST
  struct static_tracepoint_backend static_tracepoint;
#endif

  struct bytecode_compiler_emit_backend byte_code_compler;

  int global_gbufsize;
};

extern struct backend *agent_backend;

#define INSTALL_FAST_TRACEPOINT_JUMP_PAD \
  agent_backend->fast_tracepoint.install_fast_tracepoint_jump_pad

uint64_t (*get_reg) (agent_thread_info_t *tinfo, int regnum);

struct backend* initialize_backend (void);

#define emit_prologue() \
agent_backend->byte_code_compler.emit_prologue()
#define emit_epilogue() \
  agent_backend->byte_code_compler.emit_epilogue()
#define emit_add() \
  agent_backend->byte_code_compler.emit_add()
#define emit_sub() \
  agent_backend->byte_code_compler.emit_sub()
#define emit_mul() \
  agent_backend->byte_code_compler.emit_mul()
#define emit_lsh() \
  agent_backend->byte_code_compler.emit_lsh()
#define emit_rsh_signed() \
  agent_backend->byte_code_compler.emit_rsh_signed()
#define emit_rsh_unsigned() \
  agent_backend->byte_code_compler.emit_rsh_unsigned()
#define emit_log_not() \
  agent_backend->byte_code_compler.emit_log_not()
#define emit_bit_and() \
  agent_backend->byte_code_compler.emit_bit_and()
#define emit_bit_or() \
  agent_backend->byte_code_compler.emit_bit_or()
#define emit_bit_xor() \
  agent_backend->byte_code_compler.emit_bit_xor()
#define emit_bit_not() \
  agent_backend->byte_code_compler.emit_bit_not()
#define emit_equal() \
  agent_backend->byte_code_compler.emit_equal()
#define emit_less_signed() \
  agent_backend->byte_code_compler.emit_less_signed()
#define emit_less_unsigned() \
  agent_backend->byte_code_compler.emit_less_unsigned()
#define emit_ext(ARG) \
  agent_backend->byte_code_compler.emit_ext(ARG)
#define emit_ref(ARG1, ARG2) \
  agent_backend->byte_code_compler.emit_ref(ARG1, ARG2)
#define emit_if_goto(ARG1, ARG2) \
  agent_backend->byte_code_compler.emit_if_goto(ARG1, ARG2)
#define emit_goto(ARG1, ARG2) \
  agent_backend->byte_code_compler.emit_goto(ARG1, ARG2);
#define emit_const(ARG1) \
  agent_backend->byte_code_compler.emit_const(ARG1)
#define emit_reg(ARG1) \
  agent_backend->byte_code_compler.emit_reg(ARG1)
#define emit_pop() \
  agent_backend->byte_code_compler.emit_pop()
#define emit_zero_ext(ARG) \
  agent_backend->byte_code_compler.emit_zero_ext(ARG)
#define emit_swap() \
  agent_backend->byte_code_compler.emit_swap()
#define emit_stack_flush() \
  agent_backend->byte_code_compler.emit_stack_flush()
#define emit_stack_adjust(ARG) \
  agent_backend->byte_code_compler.emit_stack_adjust(ARG)
#define emit_int_call_1(ARG1, ARG2) \
  agent_backend->byte_code_compler.emit_int_call_1(ARG1, ARG2)
#define emit_void_call_2(ARG1, ARG2) \
  agent_backend->byte_code_compler.emit_void_call_2(ARG1, ARG2)
#define write_goto_address(X,Y,Z) \
  agent_backend->byte_code_compler.write_goto_address (X, Y, Z)
#define emit_eq_goto(ARG1, ARG2) \
  agent_backend->byte_code_compler.emit_eq_goto(ARG1, ARG2)
#define emit_ne_goto(ARG1, ARG2) \
  agent_backend->byte_code_compler.emit_ne_goto(ARG1, ARG2)
#define emit_lt_goto(ARG1, ARG2) \
  agent_backend->byte_code_compler.emit_lt_goto(ARG1, ARG2)
#define emit_le_goto(ARG1, ARG2) \
  agent_backend->byte_code_compler.emit_le_goto(ARG1, ARG2)
#define emit_gt_goto(ARG1, ARG2) \
  agent_backend->byte_code_compler.emit_gt_goto(ARG1, ARG2)
#define emit_ge_goto(ARG1, ARG2) \
  agent_backend->byte_code_compler.emit_ge_goto(ARG1, ARG2)
