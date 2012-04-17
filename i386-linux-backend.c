/* Agent backend bits specific to i386 Linux.

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

#include <string.h>
#include <stddef.h>
#include <sys/mman.h>

#include "agent.h"
#include "agent-expr.h"
#include "backend.h"
#include "tracepoint.h"
#include "log.h"

#include "config.h"
#if defined BUILD_UST
#include <ust/processor.h>
#endif

static void i386_emit_call (void *fn);

#define GBUFSIZE 312

/* Collect segment registers.  */
#define COLLECT_SEG_REGS 1


static const unsigned char jump_insn[] = { 0xe9, 0, 0, 0, 0 };
static const unsigned char small_jump_insn[] = { 0x66, 0xe9, 0, 0 };

#define MAX_INSN_LENGTH 16

/* This enum lists registers in the order that GDB expects to see
   them, and so should be sync'ed with i386-tdep.c .  */

enum gdb_reg_num
{
  GDB_REG_invalid = -1,
  GDB_REG_EAX,
  GDB_REG_ECX,
  GDB_REG_EDX,
  GDB_REG_EBX,
  GDB_REG_ESP,
  GDB_REG_EBP,
  GDB_REG_ESI,
  GDB_REG_EDI,
  GDB_REG_EIP,
  GDB_REG_EFLAGS,
  GDB_REG_CS,
  GDB_REG_SS,
  GDB_REG_DS,
  GDB_REG_ES,
  GDB_REG_FS,
  GDB_REG_GS,
  GDB_REG_ST0,
  dummy
};

/* Table mapping signal context positions to GDB's numbering of
   registers.  The ordering comes from <sys/ucontext.h> .  */

static const enum gdb_reg_num
signal_reg_to_gdb_reg_map[] =
  {
  GDB_REG_GS,
  GDB_REG_FS,
  GDB_REG_ES,
  GDB_REG_DS,

  GDB_REG_EDI,
  GDB_REG_ESI,
  GDB_REG_EBP,
  GDB_REG_ESP,

  GDB_REG_EBX,
  GDB_REG_EDX,
  GDB_REG_ECX,
  GDB_REG_EAX,

  GDB_REG_invalid,
  GDB_REG_invalid,
  GDB_REG_EIP,
  GDB_REG_CS,

  GDB_REG_EFLAGS,
  GDB_REG_invalid,
  GDB_REG_SS
  };

/* Get the value of the given register REGNUM in the given thread TINFO.
   Simplify life by returning a 64-bit value with high half all 0s.  */
static uint64_t
i386_get_reg (agent_thread_info_t *tinfo, int regnum)
{
  return ((unsigned int *) (tinfo->regblock))[regnum];
}

static void
i386_set_reg (agent_thread_info_t *tinfo, int regnum, uint64_t val)
{
  ((unsigned int *) (tinfo->regblock))[regnum] = val;
}

#define ADDR_PREFIX 0x67
#define DATA_PREFIX 0x66
#define LOCK_PREFIX 0xf0
#define CS_PREFIX 0x2e
#define DS_PREFIX 0x3e
#define ES_PREFIX 0x26
#define FS_PREFIX 0x64
#define GS_PREFIX 0x65
#define SS_PREFIX 0x36
#define REPE_PREFIX 0xf3
#define REPNE_PREFIX 0xf2

/* Given a pointer to bytes of an instruction INSN, advance it past the
   various prefixes that are possible.  END is the address at which to stop
   scanning, just in case.  Return the pointer to base instruction, or NULL
   if error.  */
static unsigned char *
skip_insn_prefixes (unsigned char *insn, unsigned char *end)
{
  for (; insn < end; ++insn)
    {
      switch (*insn)
	{
	case ADDR_PREFIX:
	case DATA_PREFIX:
	case LOCK_PREFIX:
	case CS_PREFIX:
	case DS_PREFIX:
	case ES_PREFIX:
	case FS_PREFIX:
	case GS_PREFIX:
	case SS_PREFIX:
	case REPE_PREFIX:
	case REPNE_PREFIX:
	  break;
	default:
	  return insn;
	}
    }
  /* Something is very wrong if we get here.  */
  return NULL;
}


/* Unlike displaced stepping, for fast tracepoints we want to alter
   the replaced instructions, because we won't have a post-single-step
   stop in which to fix up registers or memory.

   Fortunately we don't have to worry about adjusting every imaginable
   instruction. For instance, small-displacement jumps aren't an issue,
   because they are too short to be a fast tracepoint site anyway.

   TO is the address in scratch space to modify.  OLDLOD is the original
   location of instruction INSN.  NBYTES is the number of bytes.
 */
static void
adjust_jump_pad_insns (gdb_addr_t *to, gdb_addr_t oldloc,
		       size_t nbytes, unsigned char *insn)
{
  int offset = 0, rel32, newrel;
  unsigned char *insn0 = insn;

  /* Get past the prefixes.  */
  insn = skip_insn_prefixes (insn, insn + MAX_INSN_LENGTH);

  /* Adjust calls with 32-bit relative addresses as push/jump, with
     the address pushed being the location where the original call in
     the user program would return to.  */
  if (insn[0] == 0xe8)
    {
      unsigned char buf[5];
      unsigned int ret_addr;

      /* Where "ret" in the original code will return to.  */
      ret_addr = oldloc + nbytes;
      buf[0] = 0x68; /* pushq $... */
      memcpy (&buf[1], &ret_addr, 4);
      /* Push the push.  */
      append_insns (to, 5, buf);

      /* Convert the relative call to a relative jump.  */
      insn[0] = 0xe9;

      /* Adjust the destination offset.  */
      rel32 = *((int *) (insn + 1));
      newrel = (oldloc - *to) + rel32;
      *((int *) (insn + 1)) = newrel;

      /* Write the adjusted jump into its displaced location.  */
      append_insns (to, nbytes, insn0);
      return;
    }

  /* Adjust jumps with 32-bit relative addresses.  Calls are already
     handled above.  */
  if (insn[0] == 0xe9)
    offset = 1;
  /* Adjust conditional jumps.  */
  else if (insn[0] == 0x0f && (insn[1] & 0xf0) == 0x80)
    offset = 2;

  if (offset)
    {
      rel32 = *((int *) (insn + offset));
      newrel = (oldloc - *to) + rel32;
      *((int *) (insn + offset)) = newrel;
      gdb_verbose ("Adjusted insn rel32=0x%x at 0x%llx to rel32=0x%x at 0x%llx",
		   rel32, oldloc, newrel, *to);
    }

  /* Write the adjusted instructions into their displaced
     location.  */
  append_insns (to, nbytes, insn0);
}

/* Build a jump pad for tracepoint TPOINT installed at TPADDR that saves
   registers and calls a collection function COLLECTOR.  Writes a jump
   instruction to the jump pad to JJUMPAD_INSN and JJUMPPAD_INSN_SIZE
   is the size of the jump instruction.  The caller is responsible to write
   it in at the tracepoint address.  ORIG_BYTES is the bytes of the instruction
   being replaced, and ORIG_SIZE is the length of instruction.  The base address
   of the jump pad is JUMP_ENTRY.  TRAMPOLINE is the address of trampoline
   used in jumping to jump pad, and TRAMPOLINE_SIZE is the size of the
   trampoline.  Return 0 if successful.  */
static int
i386_install_fast_tracepoint_jump_pad (gdb_addr_t tpoint, gdb_addr_t tpaddr,
				       gdb_addr_t collector,
				       unsigned char *orig_bytes,
				       size_t orig_size,
				       gdb_addr_t *jump_entry,
				       unsigned char *jjumppad_insn,
				       size_t *jjumppad_insn_size,
				       gdb_addr_t *trampoline,
				       size_t *trampoline_size,
				       char *err)
{
  unsigned char buf[16], adjust[16];
  int i, offset;
  gdb_addr_t buildaddr = *jump_entry;

  /* Build the jump pad.  */

  /* First, do tracepoint data collection.  Save registers.  For the PC,
     we fake it by saving the address of the tracepoint.  */
  i = 0;
  buf[i++] = 0x60; /* pushad */
  buf[i++] = 0x68; /* push tpaddr aka $pc */
  *((int *)(buf + i)) = (int) tpaddr;
  i += 4;
  append_insns (&buildaddr, i, buf);
  /* These registers are expensive to save, handle them separately.  */
  i = 0;

  buf[i++] = 0x9c; /* pushf */
  /* Full-blown state saving would include segment registers, but it
     costs some time and is unlikely to matter in a Linux tracepoint
     context.  */
#ifdef COLLECT_SEG_REGS
  buf[i++] = 0x1e; /* push %ds */
  buf[i++] = 0x06; /* push %es */
  buf[i++] = 0x0f; /* push %fs */
  buf[i++] = 0xa0;
  buf[i++] = 0x0f; /* push %gs */
  buf[i++] = 0xa8;
  buf[i++] = 0x16; /* push %ss */
  buf[i++] = 0x0e; /* push %cs */
#endif
  append_insns (&buildaddr, i, buf);

  /* Set up arguments to the gdb_collect call.  */
  buf[0] = 0x89; /* mov %esp,-0x4(%esp) */
  buf[1] = 0x64;
  buf[2] = 0x24;
  buf[3] = 0xfc;
  append_insns (&buildaddr, 4, buf);
  buf[0] = 0x83; /* sub $0x8,%esp */
  buf[1] = 0xec;
  buf[2] = 0x08;
  append_insns (&buildaddr, 3, buf);
  buf[0] = 0xc7; /* movl <addr>,(%esp) */
  buf[1] = 0x04;
  buf[2] = 0x24;
  memcpy ((void *) (buf + 3), (void *) &tpoint, 4);
  append_insns (&buildaddr, 7, buf);
  buf[0] = 0xe8; /* call <reladdr> */
  offset = collector - (buildaddr + sizeof (jump_insn));
  memcpy ((void *) (buf + 1), (void *) &offset, 4);
  append_insns (&buildaddr, 5, buf);
  /* Clean up after the call.  */
  buf[0] = 0x83; /* add $0x8,%esp */
  buf[1] = 0xc4;
  buf[2] = 0x08;
  append_insns (&buildaddr, 3, buf);

  /* These registers are expensive to save/restore, handle separately.  */
  i = 0;
  /* Skip restoration of segment registers.  */
#ifdef COLLECT_SEG_REGS
  buf[i++] = 0x83; /* add $0x4,%esp (no pop of %cs, assume unchanged) */
  buf[i++] = 0xc4;
  buf[i++] = 0x04;
  buf[i++] = 0x17; /* pop %ss */
  buf[i++] = 0x0f; /* pop %gs */
  buf[i++] = 0xa9;
  buf[i++] = 0x0f; /* pop %fs */
  buf[i++] = 0xa1;
  buf[i++] = 0x07; /* pop %es */
  buf[i++] = 0x1f; /* pop %ds */
#endif
#if 1
  buf[i++] = 0x9d; /* popf */
#else
  /* Need to check details of flag bits before we can use this.  */
  buf[i++] = 0x58; /* pop %eax */
  buf[i++] = 0x9e; /* sahf */
#endif
  append_insns (&buildaddr, i, buf);
  i = 0;
  buf[i++] = 0x83; /* add $0x4,%esp (pop of tpaddr aka $pc) */
  buf[i++] = 0xc4;
  buf[i++] = 0x04;
  buf[i++] = 0x61; /* popad */
  append_insns (&buildaddr, i, buf);
  /* Now, adjust the original instruction to execute in the jump
     pad.  */
  memcpy (adjust, orig_bytes, orig_size);
  adjust_jump_pad_insns (&buildaddr, tpaddr, orig_size, adjust);

  /* Write the jump back to the program.  */
  offset = (tpaddr + orig_size) - (buildaddr + sizeof (jump_insn));
  memcpy ((void *) buf, jump_insn, sizeof (jump_insn));
  memcpy ((void *) (buf + 1), (void *) &offset, 4);
  append_insns (&buildaddr, sizeof (jump_insn), buf);

  /* The jump pad is now built.  Construct a jump that will go from
     the tracepoint site to this pad, but return the instruction, so
     that our caller can install it, which helps when threads are
     running.  This relies on the agent's atomic write support.  */
  if (orig_size == 4)
    {
      /* Create a trampoline.  */
      *trampoline_size = sizeof (jump_insn);

      if (!claim_trampoline_space (*trampoline_size, trampoline))
	{
	  /* No trampoline space available.  */
	  /* FIXME: How to report this error.  */
	  return 1;
	}

      offset = *jump_entry - (*trampoline + *trampoline_size);
      memcpy (buf, jump_insn, *trampoline_size);
      memcpy (buf + 1, &offset, 4);
      memcpy ((void *) (uint32_t) *trampoline, buf, *trampoline_size);

      /* Use a 16-bit relative jump instruction to jump to the trampoline.  */
      offset = (*trampoline - (tpaddr + sizeof (small_jump_insn))) & 0xffff;
      memcpy (buf, small_jump_insn, sizeof (small_jump_insn));
      memcpy (buf + 2, &offset, 2);
      memcpy (jjumppad_insn, buf, sizeof (small_jump_insn));
      *jjumppad_insn_size = 4;
    }
  else
    {
      offset = *jump_entry - (tpaddr + sizeof (jump_insn));
      memcpy ((void *) buf, jump_insn, sizeof (jump_insn));
      memcpy ((void *) (buf + 1), (void *) &offset, 4);
      memcpy (jjumppad_insn, buf, sizeof (jump_insn));
      *jjumppad_insn_size = 5;
    }

  /* Return the end address of our pad.  */
  *jump_entry = buildaddr;

  return 0;
}

/* Given a block of registers RAW_REGS as saved by the jump pad, return the
   given (GDB-number) register REGNUM.  If segment registers were not saved,
   return 0 for their values.  (This is not ideal, but erroring out
   can result in cascading problems for higher levels that ask for all
   registers.)  */
static uint64_t
i386_get_raw_reg (unsigned char *raw_regs, int regnum)
{
  int ix, rslt = 0;
  int gdb_reg_to_raw_reg_map[] =
    {
      9, /* GDB_REG_EAX */
      8, /* GDB_REG_ECX */
      7, /* GDB_REG_EDX */
      6, /* GDB_REG_EBX */
      5, /* GDB_REG_ESP */
      4, /* GDB_REG_EBP */
      3, /* GDB_REG_ESI */
      2, /* GDB_REG_EDI */
      1, /* GDB_REG_EIP */
      0, /* GDB_REG_EFLAGS */
      -6, /* GDB_REG_CS */
      -5, /* GDB_REG_SS */
      -1, /* GDB_REG_DS */
      -2, /* GDB_REG_ES */
      -3, /* GDB_REG_FS */
      -4, /* GDB_REG_GS */
    };

  if (!(GDB_REG_EAX <= regnum && regnum <= GDB_REG_GS))
    /* this should maybe be allowed to return an error code */
    agent_fatal ("bad register number");

  ix = gdb_reg_to_raw_reg_map[regnum];

#ifdef COLLECT_SEG_REGS
  /* Make this adjustment if the jump pad is saving segment registers.  */
  ix += 6;
#endif

  if (ix >= 0)
    rslt = ((int *) raw_regs)[ix];

#if 0
  gdb_verbose ("get_raw_reg (0x%x, %d) returns 0x%x",
	       (int) raw_regs, regnum, rslt);
#endif

  return rslt;
}

/* Move a block of saved registers REGS (typically located on the stack)
   into a thread TINFO's register block.  */
static void
get_fast_tracepoint_regs (agent_thread_info_t *tinfo, unsigned char *regs)
{
  int i;

  memset ((void *) (tinfo->regblock), 0, GBUFSIZE);

  for (i = 0; i < 16; ++i)
    ((int *) (tinfo->regblock))[i] = (int) i386_get_raw_reg (regs, i);
}

#if defined BUILD_UST
static struct ust_register_map i386_st_collect_regmap[] =
  {
    ST_COLLECT_REG(eax),
    ST_COLLECT_REG(ecx),
    ST_COLLECT_REG(edx),
    ST_COLLECT_REG(ebx),
    ST_COLLECT_REG(esp),
    ST_COLLECT_REG(ebp),
    ST_COLLECT_REG(esi),
    ST_COLLECT_REG(edi),
    {-1, 0},
    ST_COLLECT_REG(eflags),
    ST_COLLECT_REG(cs),
    ST_COLLECT_REG(ss),
  };

#endif

/* A function used to trick optimizers.  */

int
always_true ()
{
  return 1;
}


/* Our general strategy for emitting code is to avoid specifying raw
   bytes whenever possible, and instead copy a block of inline asm
   that is embedded in the function.  This is a little messy, because
   we need to keep the compiler from discarding what looks like dead
   code, plus suppress various warnings.  */

#define EMIT_ASM(NAME,INSNS) \
  { extern unsigned char start_ ## NAME, end_ ## NAME;	\
  add_insns (&start_ ## NAME, &end_ ## NAME - &start_ ## NAME); \
  if (always_true ()) \
    goto skipover ## NAME; \
  __asm__ ("start_" #NAME ":\n\t" INSNS "\n\tend_" #NAME ":\n\t"); \
 skipover ## NAME: \
  ; }

static void
i386_emit_prologue (void)
{
  EMIT_ASM (prologue,
	    "push %ebp\n\t"
	    "mov %esp,%ebp");
  /* At this point, the raw regs base address is at 8(%ebp), and the
     value pointer is at 12(%ebp).  */
}

static void
i386_emit_epilogue (void)
{
  EMIT_ASM (epilogue,
	    "mov 12(%ebp),%ecx\n\t"
	    "mov %eax,(%ecx)\n\t"
	    "mov %ebx,0x4(%ecx)\n\t"
	    "xor %eax,%eax\n\t"
	    "leave\n\t"
	    "ret");
}

static void
i386_emit_add (void)
{
  EMIT_ASM (add,
	    "add (%esp),%eax\n\t"
	    "adc 0x4(%esp),%ebx\n\t"
	    "lea 0x8(%esp),%esp");
}

static void
i386_emit_sub (void)
{
  EMIT_ASM (sub,
	    "subl %eax,(%esp)\n\t"
	    "sbbl %ebx,4(%esp)\n\t"
	    "pop %eax\n\t"
	    "pop %ebx\n\t");
}

static void
i386_emit_mul (void)
{
  emit_error = 1;
}

static void
i386_emit_lsh (void)
{
  emit_error = 1;
}

static void
i386_emit_rsh_signed (void)
{
  emit_error = 1;
}

static void
i386_emit_rsh_unsigned (void)
{
  emit_error = 1;
}

static void
i386_emit_ext (int arg)
{
  switch (arg)
    {
    case 8:
      EMIT_ASM (ext_8,
		"cbtw\n\t"
		"cwtl\n\t"
		"movl %eax,%ebx\n\t"
		"sarl $31,%ebx");
      break;
    case 16:
      EMIT_ASM (ext_16,
		"cwtl\n\t"
		"movl %eax,%ebx\n\t"
		"sarl $31,%ebx");
      break;
    case 32:
      EMIT_ASM (ext_32,
		"movl %eax,%ebx\n\t"
		"sarl $31,%ebx");
      break;
    default:
      emit_error = 1;
    }
}

static void
i386_emit_log_not (void)
{
  EMIT_ASM (log_not,
	    "or %ebx,%eax\n\t"
	    "test %eax,%eax\n\t"
	    "sete %cl\n\t"
	    "xor %ebx,%ebx\n\t"
	    "movzbl %cl,%eax");
}

static void
i386_emit_bit_and (void)
{
  EMIT_ASM (and,
	    "and (%esp),%eax\n\t"
	    "and 0x4(%esp),%ebx\n\t"
	    "lea 0x8(%esp),%esp");
}

static void
i386_emit_bit_or (void)
{
  EMIT_ASM (or,
	    "or (%esp),%eax\n\t"
	    "or 0x4(%esp),%ebx\n\t"
	    "lea 0x8(%esp),%esp");
}

static void
i386_emit_bit_xor (void)
{
  EMIT_ASM (xor,
	    "xor (%esp),%eax\n\t"
	    "xor 0x4(%esp),%ebx\n\t"
	    "lea 0x8(%esp),%esp");
}

static void
i386_emit_bit_not (void)
{
  EMIT_ASM (bit_not,
	    "xor $0xffffffff,%eax\n\t"
	    "xor $0xffffffff,%ebx\n\t");
}

static void
i386_emit_equal (void)
{
  EMIT_ASM (equal,
	    "cmpl %ebx,4(%esp)\n\t"
	    "jne .Lequal_false\n\t"
	    "cmpl %eax,(%esp)\n\t"
	    "je .Lequal_true\n\t"
	    ".Lequal_false:\n\t"
	    "xor %eax,%eax\n\t"
	    "jmp .Lequal_end\n\t"
	    ".Lequal_true:\n\t"
	    "mov $1,%eax\n\t"
	    ".Lequal_end:\n\t"
	    "xor %ebx,%ebx\n\t"
	    "lea 0x8(%esp),%esp");
}

static void
i386_emit_less_signed (void)
{
  EMIT_ASM (less_signed,
	    "cmpl %ebx,4(%esp)\n\t"
	    "jl .Lless_signed_true\n\t"
	    "jne .Lless_signed_false\n\t"
	    "cmpl %eax,(%esp)\n\t"
	    "jl .Lless_signed_true\n\t"
	    ".Lless_signed_false:\n\t"
	    "xor %eax,%eax\n\t"
	    "jmp .Lless_signed_end\n\t"
	    ".Lless_signed_true:\n\t"
	    "mov $1,%eax\n\t"
	    ".Lless_signed_end:\n\t"
	    "xor %ebx,%ebx\n\t"
	    "lea 0x8(%esp),%esp");
}

static void
i386_emit_less_unsigned (void)
{
  EMIT_ASM (less_unsigned,
	    "cmpl %ebx,4(%esp)\n\t"
	    "jb .Lless_unsigned_true\n\t"
	    "jne .Lless_unsigned_false\n\t"
	    "cmpl %eax,(%esp)\n\t"
	    "jb .Lless_unsigned_true\n\t"
	    ".Lless_unsigned_false:\n\t"
	    "xor %eax,%eax\n\t"
	    "jmp .Lless_unsigned_end\n\t"
	    ".Lless_unsigned_true:\n\t"
	    "mov $1,%eax\n\t"
	    ".Lless_unsigned_end:\n\t"
	    "xor %ebx,%ebx\n\t"
	    "lea 0x8(%esp),%esp");
}

static void
i386_emit_ref (int size, int (*agent_mem_read_to) (unsigned char *,
					      gdb_addr_t from, gdb_size_t))
{
#ifndef SPEED_CHECK
  unsigned char buf[16];
  int i;
  gdb_addr_t buildaddr;

  /* In the normal case, we need to set up a call to memory read API.  */
  EMIT_ASM (ref_a,
	    "sub $0x1c,%esp\n\t"
	    "mov %eax,0x4(%esp)\n\t"
	    "movl $0,0x8(%esp)");
  buildaddr = current_insn_ptr;
  i = 0;
  buf[i++] = 0xb8; /* mov $<n>,%eax */
  *((int *) (&buf[i])) = size;
  i += 4;
  append_insns (&buildaddr, i, buf);
  current_insn_ptr = buildaddr;
  EMIT_ASM (ref_b,
	    /* The length is expected to be 8 bytes.  */
	    "mov %eax,0xc(%esp)\n\t"
	    "movl $0,0x10(%esp)\n\t"
	    /* Destination is an extra bit of stack space we reserved.  */
	    "lea 0x10(%esp),%eax\n\t"
	    "mov %eax,(%esp)");
  i386_emit_call ((void *) agent_mem_read_to);
  EMIT_ASM (ref_c,
	    /* Check the return result for error reports.  */
	    "test %eax,%eax\n\t"
	    "jz .Lref_ok\n\t"
	    /* An error; clean up and return.  */
	    /* This should be the value of expr_eval_mem_read_error. */
	    "movl $10,%eax\n\t"
	    /* Return a zero in &value.  */
	    "mov 0xc(%ebp),%ecx\n\t"
	    "movl $0,(%ecx)\n\t"
	    "movl $0,0x4(%ecx)\n\t"
	    "leave\n\t"
	    "ret\n\t"
	    ".Lref_ok:\n\t"
	    /* Make the address of the result be on the bytecode stack top.  */
	    "lea 0x10(%esp),%eax");
#endif /* SPEED_CHECK */
  switch (size)
    {
    case 1:
      EMIT_ASM (ref1,
		"movb (%eax),%al");
      break;
    case 2:
      EMIT_ASM (ref2,
		"movw (%eax),%ax");
      break;
    case 4:
      EMIT_ASM (ref4,
		"movl (%eax),%eax");
      break;
    case 8:
      EMIT_ASM (ref8,
		"movl 4(%eax),%ebx\n\t"
		"movl (%eax),%eax");
      break;
    }
#ifndef SPEED_CHECK
  EMIT_ASM (ref_d,
	    "lea 0x1c(%esp),%esp");
#endif /* SPEED_CHECK */
}

static void
i386_emit_if_goto (int *offset_p, int *size_p)
{
  EMIT_ASM (if_goto,
	    "mov %eax,%ecx\n\t"
	    "or %ebx,%ecx\n\t"
	    "pop %eax\n\t"
	    "pop %ebx\n\t"
	    /* jnz, but don't trust the assembler to choose the right jump */
	    ".byte 0x0f, 0x85, 0x0, 0x0, 0x0, 0x0");

  if (offset_p)
    *offset_p = 8; /* be sure that this matches the sequence above */
  if (size_p)
    *size_p = 4;
}

static void
i386_emit_goto (int *offset_p, int *size_p)
{
  EMIT_ASM (goto,
	    /* jmp, but don't trust the assembler to choose the right jump */
	    ".byte 0xe9, 0x0, 0x0, 0x0, 0x0");
  if (offset_p)
    *offset_p = 1;
  if (size_p)
    *size_p = 4;
}

static void
i386_write_goto_address (unsigned char *from, unsigned char *to, int size)
{
  int diff = (to - (from + size));

  /* We're only doing 4-byte sizes at the moment.  */
  if (size != 4)
    {
      emit_error = 1;
      return;
    }

  *((int *) from) = diff;
}

static void
i386_emit_const (int64_t num)
{
  unsigned char buf[16];
  int i, lo, hi;
  gdb_addr_t buildaddr = current_insn_ptr;

  lo = (num & 0xffffffff);
  if (lo)
    {
      i = 0;
      buf[i++] = 0xb8; /* mov $<n>,%eax */
      *((int *) (&buf[i])) = (num & 0xffffffff);
      i += 4;
      append_insns (&buildaddr, i, buf);
      current_insn_ptr = buildaddr;
    }
  else
    {
      EMIT_ASM (const_a,
		"xor %eax,%eax");
    }

  hi = ((num >> 32) & 0xffffffff);
  if (hi)
    {
      i = 0;
      buf[i++] = 0xbb; /* mov $<n>,%ebx */
      *((int *) (&buf[i])) = hi;
      i += 4;
      append_insns (&buildaddr, i, buf);
      current_insn_ptr = buildaddr;
    }
  else
    {
      EMIT_ASM (const_b,
		"xor %ebx,%ebx");
    }
}

static void
i386_emit_call (void *fn)
{
  unsigned char buf[16];
  int i, offset;
  gdb_addr_t buildaddr;

  buildaddr = current_insn_ptr;
  i = 0;
  buf[i++] = 0xe8; /* call <reladdr> */
  offset = ((int) fn) - (buildaddr + 5);
  memcpy ((void *) (buf + 1), (void *) &offset, 4);
  append_insns (&buildaddr, 5, buf);
  current_insn_ptr = buildaddr;
}

static void
i386_emit_reg (int reg)
{
  unsigned char buf[16];
  int i;
  gdb_addr_t buildaddr;

  EMIT_ASM (reg_a,
	    "sub $0x8,%esp");
  buildaddr = current_insn_ptr;
  i = 0;
  buf[i++] = 0xb8; /* mov $<n>,%eax */
  *((int *) (&buf[i])) = reg;
  i += 4;
  append_insns (&buildaddr, i, buf);
  current_insn_ptr = buildaddr;
  EMIT_ASM (reg_b,
	    "mov %eax,4(%esp)\n\t"
	    "mov 8(%ebp),%eax\n\t"
	    "mov %eax,(%esp)");
  i386_emit_call ((void *) i386_get_raw_reg);
  EMIT_ASM (reg_c,
	    "xor %ebx,%ebx\n\t"
	    "lea 0x8(%esp),%esp");
}

static void
i386_emit_pop (void)
{
  EMIT_ASM (pop,
	    "pop %eax\n\t"
	    "pop %ebx");
}

static void
i386_emit_stack_flush (void)
{
  EMIT_ASM (stack_flush,
	    "push %ebx\n\t"
	    "push %eax");
}

static void
i386_emit_zero_ext (int arg)
{
  switch (arg)
    {
    case 8:
      EMIT_ASM (zero_ext_8,
		"and $0xff,%eax\n\t"
		"xor %ebx,%ebx");
      break;
    case 16:
      EMIT_ASM (zero_ext_16,
		"and $0xffff,%eax\n\t"
		"xor %ebx,%ebx");
      break;
    case 32:
      EMIT_ASM (zero_ext_32,
		"xor %ebx,%ebx");
      break;
    default:
      emit_error = 1;
    }
}

static void
i386_emit_swap (void)
{
  EMIT_ASM (swap,
	    "mov %eax,%ecx\n\t"
	    "mov %ebx,%edx\n\t"
	    "pop %eax\n\t"
	    "pop %ebx\n\t"
	    "push %edx\n\t"
	    "push %ecx");
}

static void
i386_emit_stack_adjust (int n)
{
  unsigned char buf[16];
  int i;
  gdb_addr_t buildaddr = current_insn_ptr;

  i = 0;
  buf[i++] = 0x8d; /* lea $<n>(%esp),%esp */
  buf[i++] = 0x64;
  buf[i++] = 0x24;
  buf[i++] = n * 8;
  append_insns (&buildaddr, i, buf);
  current_insn_ptr = buildaddr;
}

/* Emit code for a generic function that takes one fixed integer
 * argument and returns a 64-bit int (for instance, tsv getter).
 *
 */
static void
i386_emit_int_call_1 (int64_t (*fn) (int), int arg1)
{
  unsigned char buf[16];
  int i;
  gdb_addr_t buildaddr;

  EMIT_ASM (int_call_1_a,
	    /* Reserve a bit of stack space.  */
	    "sub $0x8,%esp");
  /* Put the one argument on the stack.  */
  buildaddr = current_insn_ptr;
  i = 0;
  buf[i++] = 0xc7;  /* movl $<arg1>,(%esp) */
  buf[i++] = 0x04;
  buf[i++] = 0x24;
  *((int *) (&buf[i])) = arg1;
  i += 4;
  append_insns (&buildaddr, i, buf);
  current_insn_ptr = buildaddr;
  i386_emit_call ((void *) fn);
  EMIT_ASM (int_call_1_c,
	    "mov %edx,%ebx\n\t"
	    "lea 0x8(%esp),%esp");
}

/* Emit code for a generic function that takes one fixed integer
 * argument and a 64-bit int from the top of the stack, and returns
 * nothing (for instance, tsv setter).
 *
 */
static void
i386_emit_void_call_2 (void (*fn) (int, int64_t), int arg1)
{
  unsigned char buf[16];
  int i;
  gdb_addr_t buildaddr;

  EMIT_ASM (void_call_2_a,
	    /* Preserve %eax only; we don't have to worry about %ebx.  */
	    "push %eax\n\t"
	    /* Reserve a bit of stack space for arguments.  */
	    "sub $0x10,%esp\n\t"
	    /* Copy "top" to the second argument position.  (Note that
	       we can't assume function won't scribble on its
	       arguments, so don't try to restore from this.)  */
	    "mov %eax,4(%esp)\n\t"
	    "mov %ebx,8(%esp)");
  /* Put the first argument on the stack.  */
  buildaddr = current_insn_ptr;
  i = 0;
  buf[i++] = 0xc7;  /* movl $<arg1>,(%esp) */
  buf[i++] = 0x04;
  buf[i++] = 0x24;
  *((int *) (&buf[i])) = arg1;
  i += 4;
  append_insns (&buildaddr, i, buf);
  current_insn_ptr = buildaddr;
  i386_emit_call ((void *) fn);
  EMIT_ASM (void_call_2_b,
	    "lea 0x10(%esp),%esp\n\t"
	    /* Restore original stack top.  */
	    "pop %eax");
}

static void
i386_emit_eq_goto (int *offset_p, int *size_p)
{
  EMIT_ASM (eq,
	    /* Check low half first, more likely to be decider  */
	    "cmpl %eax,(%esp)\n\t"
	    "jne .Leq_fallthru\n\t"
	    "cmpl %ebx,4(%esp)\n\t"
	    "jne .Leq_fallthru\n\t"
	    "lea 0x8(%esp),%esp\n\t"
	    "pop %eax\n\t"
	    "pop %ebx\n\t"
	    /* jmp, but don't trust the assembler to choose the right jump */
	    ".byte 0xe9, 0x0, 0x0, 0x0, 0x0\n\t"
	    ".Leq_fallthru:\n\t"
	    "lea 0x8(%esp),%esp\n\t"
	    "pop %eax\n\t"
	    "pop %ebx");

  if (offset_p)
    *offset_p = 18;
  if (size_p)
    *size_p = 4;
}

static void
i386_emit_ne_goto (int *offset_p, int *size_p)
{
  EMIT_ASM (ne,
	    /* Check low half first, more likely to be decider  */
	    "cmpl %eax,(%esp)\n\t"
	    "jne .Lne_jump\n\t"
	    "cmpl %ebx,4(%esp)\n\t"
	    "je .Lne_fallthru\n\t"
	    ".Lne_jump:\n\t"
	    "lea 0x8(%esp),%esp\n\t"
	    "pop %eax\n\t"
	    "pop %ebx\n\t"
	    /* jmp, but don't trust the assembler to choose the right jump */
	    ".byte 0xe9, 0x0, 0x0, 0x0, 0x0\n\t"
	    ".Lne_fallthru:\n\t"
	    "lea 0x8(%esp),%esp\n\t"
	    "pop %eax\n\t"
	    "pop %ebx");

  if (offset_p)
    *offset_p = 18;
  if (size_p)
    *size_p = 4;
}

static void
i386_emit_lt_goto (int *offset_p, int *size_p)
{
  EMIT_ASM (lt,
	    "cmpl %ebx,4(%esp)\n\t"
	    "jl .Llt_jump\n\t"
	    "jne .Llt_fallthru\n\t"
	    "cmpl %eax,(%esp)\n\t"
	    "jnl .Llt_fallthru\n\t"
	    ".Llt_jump:\n\t"
	    "lea 0x8(%esp),%esp\n\t"
	    "pop %eax\n\t"
	    "pop %ebx\n\t"
	    /* jmp, but don't trust the assembler to choose the right jump */
	    ".byte 0xe9, 0x0, 0x0, 0x0, 0x0\n\t"
	    ".Llt_fallthru:\n\t"
	    "lea 0x8(%esp),%esp\n\t"
	    "pop %eax\n\t"
	    "pop %ebx");

  if (offset_p)
    *offset_p = 20;
  if (size_p)
    *size_p = 4;
}

static void
i386_emit_le_goto (int *offset_p, int *size_p)
{
  EMIT_ASM (le,
	    "cmpl %ebx,4(%esp)\n\t"
	    "jle .Lle_jump\n\t"
	    "jne .Lle_fallthru\n\t"
	    "cmpl %eax,(%esp)\n\t"
	    "jnle .Lle_fallthru\n\t"
	    ".Lle_jump:\n\t"
	    "lea 0x8(%esp),%esp\n\t"
	    "pop %eax\n\t"
	    "pop %ebx\n\t"
	    /* jmp, but don't trust the assembler to choose the right jump */
	    ".byte 0xe9, 0x0, 0x0, 0x0, 0x0\n\t"
	    ".Lle_fallthru:\n\t"
	    "lea 0x8(%esp),%esp\n\t"
	    "pop %eax\n\t"
	    "pop %ebx");

  if (offset_p)
    *offset_p = 20;
  if (size_p)
    *size_p = 4;
}

static void
i386_emit_gt_goto (int *offset_p, int *size_p)
{
  EMIT_ASM (gt,
	    "cmpl %ebx,4(%esp)\n\t"
	    "jg .Lgt_jump\n\t"
	    "jne .Lgt_fallthru\n\t"
	    "cmpl %eax,(%esp)\n\t"
	    "jng .Lgt_fallthru\n\t"
	    ".Lgt_jump:\n\t"
	    "lea 0x8(%esp),%esp\n\t"
	    "pop %eax\n\t"
	    "pop %ebx\n\t"
	    /* jmp, but don't trust the assembler to choose the right jump */
	    ".byte 0xe9, 0x0, 0x0, 0x0, 0x0\n\t"
	    ".Lgt_fallthru:\n\t"
	    "lea 0x8(%esp),%esp\n\t"
	    "pop %eax\n\t"
	    "pop %ebx");

  if (offset_p)
    *offset_p = 20;
  if (size_p)
    *size_p = 4;
}

static void
i386_emit_ge_goto (int *offset_p, int *size_p)
{
  EMIT_ASM (ge,
	    "cmpl %ebx,4(%esp)\n\t"
	    "jge .Lge_jump\n\t"
	    "jne .Lge_fallthru\n\t"
	    "cmpl %eax,(%esp)\n\t"
	    "jnge .Lge_fallthru\n\t"
	    ".Lge_jump:\n\t"
	    "lea 0x8(%esp),%esp\n\t"
	    "pop %eax\n\t"
	    "pop %ebx\n\t"
	    /* jmp, but don't trust the assembler to choose the right jump */
	    ".byte 0xe9, 0x0, 0x0, 0x0, 0x0\n\t"
	    ".Lge_fallthru:\n\t"
	    "lea 0x8(%esp),%esp\n\t"
	    "pop %eax\n\t"
	    "pop %ebx");

  if (offset_p)
    *offset_p = 20;
  if (size_p)
    *size_p = 4;
}

struct backend i386_backend =
{
  { /* register_backend */
    i386_get_reg,
    i386_set_reg,
    i386_get_raw_reg,
  },
  { /* fast_tracepoint_backend */
    1, get_fast_tracepoint_regs,
    i386_install_fast_tracepoint_jump_pad,
  },
#if defined BUILD_UST
  {
    /* static_tracepoint_backend */
    i386_st_collect_regmap,
    sizeof (i386_st_collect_regmap) / sizeof (i386_st_collect_regmap[0]),
    8,
  },
#endif
  { /* bytecode_compiler_emit_backend */
    i386_emit_prologue, i386_emit_epilogue, i386_emit_add, i386_emit_sub,
    i386_emit_mul, i386_emit_lsh, i386_emit_rsh_signed, i386_emit_rsh_unsigned,
    i386_emit_ext, i386_emit_log_not, i386_emit_bit_and,
    i386_emit_bit_or, i386_emit_bit_xor, i386_emit_bit_not, i386_emit_equal,
    i386_emit_less_signed, i386_emit_less_unsigned, i386_emit_ref,
    i386_emit_if_goto, i386_emit_goto, i386_write_goto_address, i386_emit_const,
    i386_emit_call, i386_emit_reg, i386_emit_pop, i386_emit_stack_flush,
    i386_emit_zero_ext, i386_emit_swap, i386_emit_stack_adjust,
    i386_emit_int_call_1, i386_emit_void_call_2, i386_emit_eq_goto,
    i386_emit_ne_goto, i386_emit_lt_goto, i386_emit_le_goto, i386_emit_gt_goto,
    i386_emit_ge_goto,
  },
  GBUFSIZE,
};

struct backend*
initialize_backend (void)
{
  return &i386_backend;
}
