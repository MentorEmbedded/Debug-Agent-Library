/* Agent backend bits specific to x86-64 Linux.

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
#include <stdio.h>

#include "backend.h"
#include "agent.h"
#include "agent-expr.h"
#include "tracepoint.h"
#include "log.h"

extern int agent_mem_read_to (unsigned char *to,
			      gdb_addr_t from, gdb_size_t len);
static void x86_64_emit_call (void *fn);

#define JUMP_SIZE 5

static const unsigned char jump_insn[] = { 0xe9, 0, 0, 0, 0 };

#define MAX_INSN_LENGTH 16

/* This enum lists registers in the order that GDB expects to see
   them, and so should be sync'ed with amd64-tdep.c .  */

enum gdb_reg_num
{
  GDB_REG_invalid = -1,
  GDB_REG_RAX,
  GDB_REG_RBX,
  GDB_REG_RCX,
  GDB_REG_RDX,
  GDB_REG_RSI,
  GDB_REG_RDI,
  GDB_REG_RBP,
  GDB_REG_RSP,
  GDB_REG_R8,
  GDB_REG_R9,
  GDB_REG_R10,
  GDB_REG_R11,
  GDB_REG_R12,
  GDB_REG_R13,
  GDB_REG_R14,
  GDB_REG_R15,
  GDB_REG_RIP,
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

/* Table mapping signal context positions to GDB's numbering of registers.  The
   ordering comes from <sys/ucontext.h> .  */

static const enum gdb_reg_num
signal_reg_to_gdb_reg_map[] =
  {
  GDB_REG_R8,
  GDB_REG_R9,
  GDB_REG_R10,
  GDB_REG_R11,

  GDB_REG_R12,
  GDB_REG_R13,
  GDB_REG_R14,
  GDB_REG_R15,

  GDB_REG_RDI,
  GDB_REG_RSI,
  GDB_REG_RBP,
  GDB_REG_RBX,

  GDB_REG_RDX,
  GDB_REG_RAX,
  GDB_REG_RCX,
  GDB_REG_RSP,

  GDB_REG_RIP,
  GDB_REG_EFLAGS
  };

#define GBUFSIZE 544

static uint64_t
x86_64_get_reg (agent_thread_info_t *tinfo, int regnum)
{
  return ((unsigned int *) (tinfo->regblock))[regnum];
}

static void
x86_64_set_reg (agent_thread_info_t *tinfo, int regnum, uint64_t val)
{
  ((unsigned int *) (tinfo->regblock))[regnum] = val;
}



/* References below are from: "AMD64 Architecture programmer’s Manual
   Volume 3: General-Purpose and System Instructions" (rev 3.17).  */

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

/* From Appendix A - Opcode and Operand Encodings, Tables A-1, A-2,
   A-3 and A-4.  */

/* The use this macros instead of hard-coding a 0 is just to help
   revisiting the tables in the architecture manual.  */

/* Invalid opcode.  */
#define X 0

/* Invalid opcode in 64-bit.  */
#define x 0

/* A Null Prefix in 64-bit mode.  */
#define N 0

/* REX prefix in 64-bit mode.  */
#define R 0

/* Reserved.  */
#define r 0

static const char one_byte_op_has_ModRM[256] =
  {
    /*         0  1  2  3  4  5  6  7   8  9  a  b  c  d  e  f */
    /*         -----------------------  ---------------------- */
    /* 0x00 */ 1, 1, 1, 1, 0, 0, x, x,  1, 1, 1, 1, 0, 0, x, x,
    /* 0x10 */ 1, 1, 1, 1, 0, 0, x, x,  1, 1, 1, 1, 0, 0, x, x,
    /* 0x20 */ 1, 1, 1, 1, 0, 0, N, x,  1, 1, 1, 1, 0, 0, N, x,
    /* 0x30 */ 1, 1, 1, 1, 0, 0, N, x,  1, 1, 1, 1, 0, 0, N, x,
    /* 0x40 */ R, R, R, R, R, R, R, R,  R, R, R, R, R, R, R, R,
    /* 0x50 */ 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x60 */ x, x, 1, 1, 0, 0, 0, 0,  0, 1, 0, 1, 0, 0, 0, 0,
    /* 0x70 */ 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x80 */ 1, 1, 1, 1, 1, 1, 1, 1,  1, 1, 1, 1, 1, 1, 1, 1,
    /* 0x90 */ 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xa0 */ 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xb0 */ 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xc0 */ 1, 1, 0, 0, 1, 1, 1, 1,  0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xd0 */ 1, 1, 1, 1, 0, 0, 0, 0,  1, 1, 1, 1, 1, 1, 1, 1,
    /* 0xe0 */ 0, 0, 0, x, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xf0 */ 0, 0, 0, 0, 0, 0, 1, 1,  0, 0, 0, 0, 0, 0, 1, 1
};

static char two_byte_op_has_ModRM[256] =
  {
    /*         0  1  2  3  4  5  6  7   8  9  a  b  c  d  e  f */
    /*         -----------------------  ---------------------- */
    /* 0x00 */ 1, 1, 1, 1, X, 0, 0, 0,  0, 0, X, 0, X, 1, 0, 1,
    /* 0x10 */ 1, 1, 1, 1, 1, 1, 1, 1,  1, 1, 1, 1, 1, 1, 1, 1,
    /* 0x20 */ 1, 1, 1, 1, X, X, X, X,  1, 1, 1, 1, 1, 1, 1, 1,
    /* 0x30 */ 0, 0, 0, 0, 0, 0, X, X,  X, X, X, X, X, X, X, X,
    /* 0x40 */ 1, 1, 1, 1, 1, 1, 1, 1,  1, 1, 1, 1, 1, 1, 1, 1,
    /* 0x50 */ 1, 1, 1, 1, 1, 1, 1, 1,  1, 1, 1, 1, 1, 1, 1, 1,
    /* 0x60 */ 1, 1, 1, 1, 1, 1, 1, 1,  1, 1, 1, 1, X, X, 1, 1,
    /* 0x70 */ 1, 1, 1, 1, 1, 1, 1, 0,  X, X, X, X, X, X, 1, 1,
    /* 0x80 */ 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x90 */ 1, 1, 1, 1, 1, 1, 1, 1,  1, 1, 1, 1, 1, 1, 1, 1,
    /* 0xa0 */ 0, 0, 0, 1, 1, 1, X, X,  0, 0, 0, 1, 1, 1, 1, 1,
    /* 0xb0 */ 1, 1, 1, 1, 1, 1, 1, 1,  r, 1, 1, 1, 1, 1, 1, 1,
    /* 0xc0 */ 1, 1, 1, 1, 1, 1, 1, 1,  0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xd0 */ X, 1, 1, 1, 1, 1, X, 1,  1, 1, 1, 1, 1, 1, 1, 1,
    /* 0xe0 */ 1, 1, 1, 1, 1, 1, X, 1,  1, 1, 1, 1, 1, 1, 1, 1,
    /* 0xf0 */ X, 1, 1, 1, 1, 1, 1, 1,  1, 1, 1, 1, 1, 1, 1, X
  };

#undef x
#undef X
#undef N
#undef R
#undef r

/* Parse instruction at INSN, and if it uses RIP-relative addressing,
   return the offset into INSN where the displacement to be adjusted
   is found.  */

static int
rip_relative_offset (unsigned char *insn)
{
  unsigned char *p;
  unsigned char *modrm = NULL;

  p = insn;

  /* Skip AMD64 register extensions / REX instruction prefix.  The
     value of a REX prefix is in the range 40h through 4Fh, depending
     on the particular combination of AMD64 register extensions
     desired.  */
  if ((*p & 0xf0) == 0x40)
    ++p;

  /* Follows the opcode.  It can be 1 or 2 bytes long.  All two-byte
     opcodes have 0x0f as their first byte.  */
  if (*p != 0x0f)
    {
      if (one_byte_op_has_ModRM[*p])
	{
	  ++p;
	  modrm = p;
	}
    }
  else
    {
      ++p;
      if (two_byte_op_has_ModRM[*p])
	{
	  ++p;
	  modrm = insn;
	}
    }

    /* When RIP-relative addressing is in use, ModRM.mod == 0, and
       ModRM.rm = 0b101.  */
  if (modrm != NULL && (*modrm & 0xc7) == 0x05)
    {
      /* The displacement is found right after the ModRM byte.  */
      ++p;
      return p - insn;
    }

  return 0;
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

  offset = rip_relative_offset (insn);
  if (!offset)
    {
      /* Adjust jumps with 32-bit relative addresses.  Calls are
	 already handled above.  */
      if (insn[0] == 0xe9)
	offset = 1;
      /* Adjust conditional jumps.  */
      else if (insn[0] == 0x0f && (insn[1] & 0xf0) == 0x80)
	offset = 2;
    }

  if (offset)
    {
      rel32 = *((int *) (insn + offset));
      newrel = (oldloc - *to) + rel32;
      *((int *) (insn + offset)) = newrel;
      gdb_verbose ("Adjusted insn rel32=0x%x at 0x%" PRIx64
		   " to rel32=0x%x at 0x%" PRIx64,
		   rel32, oldloc, newrel, *to);
    }

  /* Write the adjusted instructions into their displaced
     location, being sure to copy any prefixes too!  */
  append_insns (to, nbytes, insn0);
}

  /* Trampolines are not used on x86-64.  */

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
x86_64_install_fast_tracepoint_jump_pad (gdb_addr_t tpoint, gdb_addr_t tpaddr,
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
  unsigned char buf[100], adjust[100];
  int i, offset;
  int64_t offset64;
  gdb_addr_t buildaddr = *jump_entry;

  /* Build the jump pad.  */

  /* First, do tracepoint data collection.  Save registers.  */
  i = 0;
  /* Need to ensure stack pointer saved first.  */
  buf[i++] = 0x54; /* push %rsp */
  buf[i++] = 0x55; /* push %rbp */
  buf[i++] = 0x57; /* push %rdi */
  buf[i++] = 0x56; /* push %rsi */
  buf[i++] = 0x52; /* push %rdx */
  buf[i++] = 0x51; /* push %rcx */
  buf[i++] = 0x53; /* push %rbx */
  buf[i++] = 0x50; /* push %rax */
  buf[i++] = 0x41; buf[i++] = 0x57; /* push %r15 */
  buf[i++] = 0x41; buf[i++] = 0x56; /* push %r14 */
  buf[i++] = 0x41; buf[i++] = 0x55; /* push %r13 */
  buf[i++] = 0x41; buf[i++] = 0x54; /* push %r12 */
  buf[i++] = 0x41; buf[i++] = 0x53; /* push %r11 */
  buf[i++] = 0x41; buf[i++] = 0x52; /* push %r10 */
  buf[i++] = 0x41; buf[i++] = 0x51; /* push %r9 */
  buf[i++] = 0x41; buf[i++] = 0x50; /* push %r8 */
  buf[i++] = 0x9c; /* pushfq */
  buf[i++] = 0x48; /* movl <addr>,%rdi */
  buf[i++] = 0xbf;
  *((unsigned long *)(buf + i)) = (unsigned long) tpaddr;
  i += sizeof (unsigned long);
  buf[i++] = 0x57; /* push %rdi */
  append_insns (&buildaddr, i, buf);
  /* Set up the gdb_collect call.  */
  /* At this point, the stack pointer is the base of our saved
     register block.  */
  i = 0;
  buf[i++] = 0x48; /* mov %rsp,%rsi */
  buf[i++] = 0x89;
  buf[i++] = 0xe6;
  /* tpoint address may be 64-bit wide.  */
  buf[i++] = 0x48; /* movl <addr>,%rdi */
  buf[i++] = 0xbf;
  memcpy ((void *) (buf + i), (void *) &tpoint, 8);
  i += 8;
  append_insns (&buildaddr, i, buf);

  i = 0; /* mov $collector, %rax */
  buf[i++] = 0x48;
  buf[i++] = 0xb8;
  memcpy (buf + i, &collector, 8);
  i += 8;
  append_insns (&buildaddr, i, buf);

  i = 0; /* callq *%rax */
  buf[i++] = 0xff;
  buf[i++] = 0xd0;
  append_insns (&buildaddr, i, buf);

  i = 0;
  buf[i++] = 0x48; /* add $0x8,%rsp */
  buf[i++] = 0x83;
  buf[i++] = 0xc4;
  buf[i++] = 0x08;
  buf[i++] = 0x9d; /* popfq */
  buf[i++] = 0x41; buf[i++] = 0x58; /* pop %r8 */
  buf[i++] = 0x41; buf[i++] = 0x59; /* pop %r9 */
  buf[i++] = 0x41; buf[i++] = 0x5a; /* pop %r10 */
  buf[i++] = 0x41; buf[i++] = 0x5b; /* pop %r11 */
  buf[i++] = 0x41; buf[i++] = 0x5c; /* pop %r12 */
  buf[i++] = 0x41; buf[i++] = 0x5d; /* pop %r13 */
  buf[i++] = 0x41; buf[i++] = 0x5e; /* pop %r14 */
  buf[i++] = 0x41; buf[i++] = 0x5f; /* pop %r15 */
  buf[i++] = 0x58; /* pop %rax */
  buf[i++] = 0x5b; /* pop %rbx */
  buf[i++] = 0x59; /* pop %rcx */
  buf[i++] = 0x5a; /* pop %rdx */
  buf[i++] = 0x5e; /* pop %rsi */
  buf[i++] = 0x5f; /* pop %rdi */
  buf[i++] = 0x5d; /* pop %rbp */
  buf[i++] = 0x5c; /* pop %rsp */
  append_insns (&buildaddr, i, buf);

  /* Now, adjust the original instruction to execute in the jump
     pad.  */
  memcpy (adjust, orig_bytes, orig_size);
  adjust_jump_pad_insns (&buildaddr, tpaddr, orig_size, adjust);

  /* Finally, write the jump back to the program.  */
  offset64 = (tpaddr + orig_size) - (buildaddr + JUMP_SIZE);
  if (offset64 < - (((int64_t) 1) << 32)
      || (((int64_t) 1) << 32) <= offset64)
    {
      gdb_verbose ("Error: cannot handle jump back's wanted offset of 0x%"
		   PRIx64 ", >32 bits", offset64);
      sprintf (err, "E.Jump back from jump pad too far from tracepoint "
               "(offset 0x%" PRIx64 " > int32).%c", offset64, 0);
      return -1;
    }
  offset = (int) offset64;
  memcpy ((void *) buf, jump_insn, JUMP_SIZE);
  memcpy ((void *) (buf + 1), (void *) &offset, 4);
  append_insns (&buildaddr, JUMP_SIZE, buf);

  /* The jump pad is now built.  Wire in a jump to our jump pad.  This
     is always done last (by our caller actually), so that we can
     install fast tracepoints with threads running.  This relies on
     the agent's atomic write support.  */
  offset64 = *jump_entry - (tpaddr + JUMP_SIZE);
  if (offset64 < - (((int64_t) 1) << 32)
      || (((int64_t) 1) << 32) <= offset64)
    {
      gdb_verbose ("Error: Cannot handle jump's wanted offset of 0x%"
		   PRIx64 ", >32 bits", offset64);
      sprintf (err,
               "E.Jump pad too far from tracepoint "
               "(offset 0x%" PRIx64 " > int32).", offset64);
      return -1;
    }
  offset = (int) offset64;
  memcpy ((void *) buf, jump_insn, JUMP_SIZE);
  memcpy ((void *) (buf + 1), (void *) &offset, 4);
  memcpy (jjumppad_insn, buf, JUMP_SIZE);
  *jjumppad_insn_size = 5;

  /* Return the end address of our pad.  */
  *jump_entry = buildaddr;

  return 0;
}

/* Given a block of registers as saved by the jump pad, return the
 * given (GDB-number) register.
 *
 * \pin raw_regs        Pointer to a register block
 * \pin regnum          GDB register number
 * \return              Register's value, as a 64-bit number
 */
static uint64_t
x86_64_get_raw_reg (unsigned char *raw_regs, int regnum)
{
  int pos = -1;

  if (regnum == GDB_REG_RIP)
    pos = 0;
  else if (regnum == GDB_REG_EFLAGS)
    pos = 1;
  else if (GDB_REG_R8 <= regnum && regnum <= GDB_REG_R15)
    pos = (regnum - GDB_REG_R8) + 2;
  else if (GDB_REG_RAX <= regnum && regnum <= GDB_REG_RSP)
    pos = (regnum - GDB_REG_RAX) + 10;
  else
    /* this should maybe be allowed to return an error code */
    agent_fatal ("bad register number");

  return ((uint64_t *) raw_regs)[pos];
}

/* Move a block of saved registers (typically located on the stack) REGS
   into a thread TFINO's register block.  */

static void
get_fast_tracepoint_regs (agent_thread_info_t *tinfo, unsigned char *regs)
{
  int i;

  /* (It might be faster to maintain a bitmap and only work with registers
     of actual interest.) */
  memset ((void *) (tinfo->regblock), 0, GBUFSIZE);

  /* Copy over only the registers actually saved by the jump pad.  */
  for (i = 0; i < 18; ++i)
    ((long *) (tinfo->regblock))[i] = (long) x86_64_get_raw_reg (regs, i);
}

#if defined BUILD_UST
static struct ust_register_map x86_64_st_collect_regmap[] =
  {
    ST_COLLECT_REG(rax),
    ST_COLLECT_REG(rbx),
    ST_COLLECT_REG(rcx),
    ST_COLLECT_REG(rdx),
    ST_COLLECT_REG(rsi),
    ST_COLLECT_REG(rdi),
    ST_COLLECT_REG(rbp),
    ST_COLLECT_REG(rsp),
    ST_COLLECT_REG(r8),
    ST_COLLECT_REG(r9),
    ST_COLLECT_REG(r10),
    ST_COLLECT_REG(r11),
    ST_COLLECT_REG(r12),
    ST_COLLECT_REG(r13),
    ST_COLLECT_REG(r14),
    ST_COLLECT_REG(r15),
    { -1, 0 },
    ST_COLLECT_REG(rflags),
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
x86_64_emit_prologue (void)
{
  EMIT_ASM (prologue,
	    "pushq %rbp\n\t"
	    "movq %rsp,%rbp\n\t"
	    "sub $0x20,%rsp\n\t"
	    "movq %rdi,-8(%rbp)\n\t"
	    "movq %rsi,-16(%rbp)");
}


static void
x86_64_emit_epilogue (void)
{
  EMIT_ASM (epilogue,
	    "movq -16(%rbp),%rdi\n\t"
	    "movq %rax,(%rdi)\n\t"
	    "xor %rax,%rax\n\t"
	    "leave\n\t"
	    "ret");
}

static void
x86_64_emit_add (void)
{
  EMIT_ASM (add,
	    "add (%rsp),%rax\n\t"
	    "lea 0x8(%rsp),%rsp");
}

static void
x86_64_emit_sub (void)
{
  EMIT_ASM (sub,
	    "sub %rax,(%rsp)\n\t"
	    "pop %rax");
}

static void
x86_64_emit_mul (void)
{
  emit_error = 1;
}

static void
x86_64_emit_lsh (void)
{
  emit_error = 1;
}

static void
x86_64_emit_rsh_signed (void)
{
  emit_error = 1;
}

static void
x86_64_emit_rsh_unsigned (void)
{
  emit_error = 1;
}

static void
x86_64_emit_ext (int arg)
{
  switch (arg)
    {
    case 8:
      EMIT_ASM (ext_8,
		"cbtw\n\t"
		"cwtl\n\t"
		"cltq");
      break;
    case 16:
      EMIT_ASM (ext_16,
		"cwtl\n\t"
		"cltq");
      break;
    case 32:
      EMIT_ASM (ext_32,
		"cltq");
      break;
    default:
      emit_error = 1;
    }
}

static void
x86_64_emit_log_not (void)
{
  EMIT_ASM (log_not,
	    "test %rax,%rax\n\t"
	    "sete %cl\n\t"
	    "movzbq %cl,%rax");
}

static void
x86_64_emit_bit_and (void)
{
  EMIT_ASM (and,
	    "and (%rsp),%rax\n\t"
	    "lea 0x8(%rsp),%rsp");
}

static void
x86_64_emit_bit_or (void)
{
  EMIT_ASM (or,
	    "or (%rsp),%rax\n\t"
	    "lea 0x8(%rsp),%rsp");
}

static void
x86_64_emit_bit_xor (void)
{
  EMIT_ASM (xor,
	    "xor (%rsp),%rax\n\t"
	    "lea 0x8(%rsp),%rsp");
}

static void
x86_64_emit_bit_not (void)
{
  EMIT_ASM (bit_not,
	    "xorq $0xffffffffffffffff,%rax");
}

static void
x86_64_emit_equal (void)
{
  EMIT_ASM (equal,
	    "cmp %rax,(%rsp)\n\t"
	    "je .Lequal_true\n\t"
	    "xor %rax,%rax\n\t"
	    "jmp .Lequal_end\n\t"
	    ".Lequal_true:\n\t"
	    "mov $0x1,%rax\n\t"
	    ".Lequal_end:\n\t"
	    "lea 0x8(%rsp),%rsp");
}

static void
x86_64_emit_less_signed (void)
{
  EMIT_ASM (less_signed,
	    "cmp %rax,(%rsp)\n\t"
	    "jl .Lless_signed_true\n\t"
	    "xor %rax,%rax\n\t"
	    "jmp .Lless_signed_end\n\t"
	    ".Lless_signed_true:\n\t"
	    "mov $1,%rax\n\t"
	    ".Lless_signed_end:\n\t"
	    "lea 0x8(%rsp),%rsp");
}

static void
x86_64_emit_less_unsigned (void)
{
  EMIT_ASM (less_unsigned,
	    "cmp %rax,(%rsp)\n\t"
	    "jb .Lless_unsigned_true\n\t"
	    "xor %rax,%rax\n\t"
	    "jmp .Lless_unsigned_end\n\t"
	    ".Lless_unsigned_true:\n\t"
	    "mov $1,%rax\n\t"
	    ".Lless_unsigned_end:\n\t"
	    "lea 0x8(%rsp),%rsp");
}

static void
x86_64_emit_ref (int size, int (*agent_mem_read_to) (unsigned char *,
					      gdb_addr_t from, gdb_size_t))
{
#ifndef SPEED_CHECK
  unsigned char buf[16];
  int i;
  gdb_addr_t buildaddr;

  /* In the normal case, we need to set up a call to memory read API.  */
  EMIT_ASM (ref_a,
	    "sub $0x8,%rsp\n\t"
	    /* (need to do caller saves?) */
	    "mov %rsp,%rdi\n\t"
	    "mov %rax,%rsi");
  buildaddr = current_insn_ptr;
  i = 0;
  buf[i++] = 0x48; /* mov $<n>,%rdx */
  buf[i++] = 0xc7;
  buf[i++] = 0xc2;
  *((int *) (&buf[i])) = size;
  i += 4;
  append_insns (&buildaddr, i, buf);
  current_insn_ptr = buildaddr;
  x86_64_emit_call (agent_mem_read_to);
  EMIT_ASM (ref_b,
	    /* Check the return result for error reports.  */
	    "test %rax,%rax\n\t"
	    "jz .Lref_ok\n\t"
	    /* An error; clean up and return.  */
	    /* Return a zero in &value.  */
	    "movq -16(%rbp),%rdi\n\t"
	    "movq $0,(%rdi)\n\t"
	    /* This should be the value of expr_eval_mem_read_error. */
	    "movq $10,%rax\n\t"
	    "leave\n\t"
	    "ret\n\t"
	    ".Lref_ok:\n\t"
	    /* Make the address of the result be on the bytecode stack top.  */
	    "mov %rsp,%rax");
#endif /* SPEED_CHECK */
  switch (size)
    {
    case 1:
      EMIT_ASM (ref1,
		"movb (%rax),%al");
      break;
    case 2:
      EMIT_ASM (ref2,
		"movw (%rax),%ax");
      break;
    case 4:
      EMIT_ASM (ref4,
		"movl (%rax),%eax");
      break;
    case 8:
      EMIT_ASM (ref8,
		"movq (%rax),%rax");
      break;
    }
#ifndef SPEED_CHECK
  EMIT_ASM (ref_c,
	    "lea 0x8(%rsp),%rsp");
#endif /* SPEED_CHECK */
}

static void
x86_64_emit_if_goto (int *offset_p, int *size_p)
{
  EMIT_ASM (if_goto,
	    "mov %rax,%rcx\n\t"
	    "pop %rax\n\t"
	    "cmp $0,%rcx\n\t"
	    ".byte 0x0f, 0x85, 0x0, 0x0, 0x0, 0x0");
  if (offset_p)
    *offset_p = 10;
  if (size_p)
    *size_p = 4;
}

static void
x86_64_emit_goto (int *offset_p, int *size_p)
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
x86_64_write_goto_address (unsigned char *from, unsigned char *to, int size)
{
  int diff = (to - (from + size));

  if (size != 4)
    {
      emit_error = 1;
      return;
    }

  *((int *) from) = diff;
}

static void
x86_64_emit_const (int64_t num)
{
  unsigned char buf[16];
  int i;
  gdb_addr_t buildaddr = current_insn_ptr;

  if (num)
    {
      i = 0;
      buf[i++] = 0x48;  buf[i++] = 0xb8; /* mov $<n>,%rax */
      *((int64_t *) (&buf[i])) = num;
      i += 8;
      append_insns (&buildaddr, i, buf);
      current_insn_ptr = buildaddr;
    }
  else
    {
      EMIT_ASM (const,
		"xor %rax,%rax");
    }
}

static void
x86_64_emit_call (void *fn)
{
  unsigned char buf[16];
  int i, offset;
  gdb_addr_t buildaddr;

  buildaddr = current_insn_ptr;
  i = 0;
  buf[i++] = 0xe8; /* call <reladdr> */
  offset = ((unsigned long) fn) - (buildaddr + i + 4);
  memcpy ((void *) (buf + i), (void *) &offset, 4);
  i += 4;
  append_insns (&buildaddr, i, buf);
  current_insn_ptr = buildaddr;
}

static void
x86_64_emit_reg (int reg)
{
  unsigned char buf[16];
  int i;
  gdb_addr_t buildaddr;

  /* Don't assume raw_regs is still in %rdi.  */
  EMIT_ASM (reg,
	    "movq -8(%rbp),%rdi");
  buildaddr = current_insn_ptr;
  i = 0;
  buf[i++] = 0xbe; /* mov $<n>,%esi */
  *((int *) (&buf[i])) = reg;
  i += 4;
  append_insns (&buildaddr, i, buf);
  current_insn_ptr = buildaddr;
  x86_64_emit_call (x86_64_get_raw_reg);
}

static void
x86_64_emit_pop (void)
{
  EMIT_ASM (pop,
	    "pop %rax");
}

static void
x86_64_emit_stack_flush (void)
{
  EMIT_ASM (stack_flush,
	    "push %rax");
}

static void
x86_64_emit_zero_ext (int arg)
{
  switch (arg)
    {
    case 8:
      EMIT_ASM (zero_ext_8,
		"and $0xff,%rax");
      break;
    case 16:
      EMIT_ASM (zero_ext_16,
		"and $0xffff,%rax");
      break;
    case 32:
      EMIT_ASM (zero_ext_32,
		"mov $0xffffffff,%rcx\n\t"
		"and %rcx,%rax");
      break;
    default:
      emit_error = 1;
    }
}

static void
x86_64_emit_swap (void)
{
  EMIT_ASM (swap,
	    "mov %rax,%rcx\n\t"
	    "pop %rax\n\t"
	    "push %rcx");
}

static void
x86_64_emit_stack_adjust (int n)
{
  unsigned char buf[16];
  int i;
  gdb_addr_t buildaddr = current_insn_ptr;

  i = 0;
  buf[i++] = 0x48; /* lea $<n>(%rsp),%rsp */
  buf[i++] = 0x8d;
  buf[i++] = 0x64;
  buf[i++] = 0x24;
  /* This only handles adjustments up to 16, but we don't expect any more.  */
  buf[i++] = n * 8;
  append_insns (&buildaddr, i, buf);
  current_insn_ptr = buildaddr;
}

static void
x86_64_emit_int_call_1 (int64_t(*fn)(int), int arg1)
{
  unsigned char buf[16];
  int i;
  gdb_addr_t buildaddr;

  buildaddr = current_insn_ptr;
  i = 0;
  buf[i++] = 0xbf; /* movl $<n>,%edi */
  *((int *) (&buf[i])) = arg1;
  i += 4;
  append_insns (&buildaddr, i, buf);
  current_insn_ptr = buildaddr;
  x86_64_emit_call (fn);
}

static void
x86_64_emit_void_call_2 (void(*fn)(int,int64_t), int arg1)
{
  unsigned char buf[16];
  int i;
  gdb_addr_t buildaddr;

  buildaddr = current_insn_ptr;
  i = 0;
  buf[i++] = 0xbf; /* movl $<n>,%edi */
  *((int *) (&buf[i])) = arg1;
  i += 4;
  append_insns (&buildaddr, i, buf);
  current_insn_ptr = buildaddr;
  EMIT_ASM (void_call_2_a,
	    /* Save away a copy of the stack top.  */
	    "push %rax\n\t"
	    /* Also pass top as the second argument.  */
	    "mov %rax,%rsi");
  x86_64_emit_call (fn);
  EMIT_ASM (void_call_2_b,
	    /* Restore the stack top, %rax may have been trashed.  */
	    "pop %rax");
}

static void
x86_64_emit_eq_goto (int *offset_p, int *size_p)
{
  EMIT_ASM (eq,
	    "cmp %rax,(%rsp)\n\t"
	    "jne .Leq_fallthru\n\t"
	    "lea 0x8(%rsp),%rsp\n\t"
	    "pop %rax\n\t"
	    /* jmp, but don't trust the assembler to choose the right jump */
	    ".byte 0xe9, 0x0, 0x0, 0x0, 0x0\n\t"
	    ".Leq_fallthru:\n\t"
	    "lea 0x8(%rsp),%rsp\n\t"
	    "pop %rax")

  if (offset_p)
    *offset_p = 13;
  if (size_p)
    *size_p = 4;
}

static void
x86_64_emit_ne_goto (int *offset_p, int *size_p)
{
  EMIT_ASM (ne,
	    "cmp %rax,(%rsp)\n\t"
	    "je .Lne_fallthru\n\t"
	    "lea 0x8(%rsp),%rsp\n\t"
	    "pop %rax\n\t"
	    /* jmp, but don't trust the assembler to choose the right jump */
	    ".byte 0xe9, 0x0, 0x0, 0x0, 0x0\n\t"
	    ".Lne_fallthru:\n\t"
	    "lea 0x8(%rsp),%rsp\n\t"
	    "pop %rax");

  if (offset_p)
    *offset_p = 13;
  if (size_p)
    *size_p = 4;
}

static void
x86_64_emit_lt_goto (int *offset_p, int *size_p)
{
  EMIT_ASM (lt,
	    "cmp %rax,(%rsp)\n\t"
	    "jnl .Llt_fallthru\n\t"
	    "lea 0x8(%rsp),%rsp\n\t"
	    "pop %rax\n\t"
	    /* jmp, but don't trust the assembler to choose the right jump */
	    ".byte 0xe9, 0x0, 0x0, 0x0, 0x0\n\t"
	    ".Llt_fallthru:\n\t"
	    "lea 0x8(%rsp),%rsp\n\t"
	    "pop %rax");

  if (offset_p)
    *offset_p = 13;
  if (size_p)
    *size_p = 4;
}

static void
x86_64_emit_le_goto (int *offset_p, int *size_p)
{
  EMIT_ASM (le,
	    "cmp %rax,(%rsp)\n\t"
	    "jnle .Lle_fallthru\n\t"
	    "lea 0x8(%rsp),%rsp\n\t"
	    "pop %rax\n\t"
	    /* jmp, but don't trust the assembler to choose the right jump */
	    ".byte 0xe9, 0x0, 0x0, 0x0, 0x0\n\t"
	    ".Lle_fallthru:\n\t"
	    "lea 0x8(%rsp),%rsp\n\t"
	    "pop %rax");

  if (offset_p)
    *offset_p = 13;
  if (size_p)
    *size_p = 4;
}

static void
x86_64_emit_gt_goto (int *offset_p, int *size_p)
{
  EMIT_ASM (gt,
	    "cmp %rax,(%rsp)\n\t"
	    "jng .Lgt_fallthru\n\t"
	    "lea 0x8(%rsp),%rsp\n\t"
	    "pop %rax\n\t"
	    /* jmp, but don't trust the assembler to choose the right jump */
	    ".byte 0xe9, 0x0, 0x0, 0x0, 0x0\n\t"
	    ".Lgt_fallthru:\n\t"
	    "lea 0x8(%rsp),%rsp\n\t"
	    "pop %rax");

  if (offset_p)
    *offset_p = 13;
  if (size_p)
    *size_p = 4;
}

static void
x86_64_emit_ge_goto (int *offset_p, int *size_p)
{
  EMIT_ASM (ge,
	    "cmp %rax,(%rsp)\n\t"
	    "jnge .Lge_fallthru\n\t"
	    ".Lge_jump:\n\t"
	    "lea 0x8(%rsp),%rsp\n\t"
	    "pop %rax\n\t"
	    /* jmp, but don't trust the assembler to choose the right jump */
	    ".byte 0xe9, 0x0, 0x0, 0x0, 0x0\n\t"
	    ".Lge_fallthru:\n\t"
	    "lea 0x8(%rsp),%rsp\n\t"
	    "pop %rax");

  if (offset_p)
    *offset_p = 13;
  if (size_p)
    *size_p = 4;
}

struct backend x86_64_backend =
{
  { /* register_backend */
    x86_64_get_reg,
    x86_64_set_reg,
    x86_64_get_raw_reg,
  },
  { /* fast_tracepoint_backend */
    0, get_fast_tracepoint_regs,
    x86_64_install_fast_tracepoint_jump_pad,
  },
#if defined BUILD_UST
  {
    /* static_tracepoint_backend */
    x86_64_st_collect_regmap,
    sizeof (x86_64_st_collect_regmap) / sizeof (x86_64_st_collect_regmap[0]),
    16,
  }
#endif
  { /* bytecode_compiler_emit_backend */
    x86_64_emit_prologue, x86_64_emit_epilogue, x86_64_emit_add,
    x86_64_emit_sub, x86_64_emit_mul, x86_64_emit_lsh, x86_64_emit_rsh_signed,
    x86_64_emit_rsh_unsigned, x86_64_emit_ext, x86_64_emit_log_not,
    x86_64_emit_bit_and, x86_64_emit_bit_or, x86_64_emit_bit_xor,
    x86_64_emit_bit_not, x86_64_emit_equal, x86_64_emit_less_signed,
    x86_64_emit_less_unsigned, x86_64_emit_ref, x86_64_emit_if_goto,
    x86_64_emit_goto, x86_64_write_goto_address, x86_64_emit_const,
    x86_64_emit_call, x86_64_emit_reg, x86_64_emit_pop, x86_64_emit_stack_flush,
    x86_64_emit_zero_ext, x86_64_emit_swap, x86_64_emit_stack_adjust,
    x86_64_emit_int_call_1, x86_64_emit_void_call_2, x86_64_emit_eq_goto,
    x86_64_emit_ne_goto, x86_64_emit_lt_goto, x86_64_emit_le_goto,
    x86_64_emit_gt_goto, x86_64_emit_ge_goto,
  },
  GBUFSIZE,
};

struct backend*
initialize_backend (void)
{
  return &x86_64_backend;
}
