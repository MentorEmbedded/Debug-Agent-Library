/* Agent module for User Space Tracer.

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
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <ust/ust.h>

#include "log.h"
#include "tracepoint.h"
#include "backend.h"

extern int  GDB_AGENT_SYM(ust_loaded);
extern char GDB_AGENT_SYM(cmd_buf)[];

static struct
{
  int (*serialize_to_text) (char *outbuf, int bufsize,
			    const char *fmt, va_list ap);

  int (*ltt_probe_register) (struct ltt_available_probe *pdata);
  int (*ltt_probe_unregister) (struct ltt_available_probe *pdata);

  int (*ltt_marker_connect) (const char *channel, const char *mname,
			     const char *pname);
  int (*ltt_marker_disconnect) (const char *channel, const char *mname,
				const char *pname);

  void (*marker_iter_start) (struct marker_iter *iter);
  void (*marker_iter_next) (struct marker_iter *iter);
  void (*marker_iter_stop) (struct marker_iter *iter);
  void (*marker_iter_reset) (struct marker_iter *iter);
} ust_ops;


#define __USE_GNU 1
#include <dlfcn.h>
#define RESOLVE_UST_SYMBOL(SYM)				\
  do								\
    {								\
      if (ust_ops.SYM == NULL)					\
	ust_ops.SYM = (typeof (&SYM)) dlsym (RTLD_DEFAULT, #SYM);	\
      if (ust_ops.SYM == NULL)					\
	return 0;						\
    } while (0)

#define UST_FUNCTION(SYM) ust_ops.SYM

/* Marker iterator for FSTM/SSTM.  */
static struct marker_iter iter_for_command;

static int
tohex (int nib)
{
  if (nib < 10)
    return '0' + nib;
  else
    return 'a' + nib - 10;
}


static void
convert_int_to_ascii (const unsigned char *from, char *to, int n)
{
  int nib;
  int ch;
  while (n--)
    {
      ch = *from++;
      nib = ((ch & 0xf0) >> 4) & 0x0f;
      *to++ = tohex (nib);
      nib = ch & 0x0f;
      *to++ = tohex (nib);
    }
  *to++ = 0;
}

/* Return an hexstr version of the STR C string.  */

static char *
cstr_to_hexstr (const char *str)
{
  int len = strlen (str);
  char *hexstr = malloc (len * 2 + 1);
  convert_int_to_ascii ((const unsigned char *) str, hexstr, len);
  return hexstr;
}

static void
response_ust_marker (char *packet, struct marker_iter *iter)
{
  char *strid, *format, *tmp;
  const struct marker *st = iter->marker;

  if (st == NULL)
    return;

  tmp = (char *) malloc (strlen (st->channel) + 1 +
			 strlen (st->name) + 1);
  sprintf (tmp, "%s/%s", st->channel, st->name);

  strid = cstr_to_hexstr (tmp);
  free (tmp);

  format = cstr_to_hexstr (st->format);

  sprintf (packet, "m%lx:%s:%s",
	   (unsigned long) st->location,
	   strid,
	   format);

  free (strid);
  free (format);
}


static int
ishex (int ch, int *val)
{
  if ((ch >= 'a') && (ch <= 'f'))
    {
      *val = ch - 'a' + 10;
      return 1;
    }
  if ((ch >= 'A') && (ch <= 'F'))
    {
      *val = ch - 'A' + 10;
      return 1;
    }
  if ((ch >= '0') && (ch <= '9'))
    {
      *val = ch - '0';
      return 1;
    }
  return 0;
}

char *
unpack_varlen_hex (char *buff,	/* packet to parse */
		   unsigned long long *result)
{
  int nibble;
  unsigned long long retval = 0;

  while (ishex (*buff, &nibble))
    {
      buff++;
      retval = retval << 4;
      retval |= nibble & 0x0f;
    }
  *result = retval;
  return buff;
}

int
cmd_qtstmat (char *packet)
{
  char *p = packet;
  unsigned long long address;
  struct marker_iter iter;
  struct marker *m;

  p += sizeof ("qTSTMat:") - 1;

  p = unpack_varlen_hex (p, &address);

  UST_FUNCTION(marker_iter_reset) (&iter);

  for (UST_FUNCTION(marker_iter_start) (&iter), m = iter.marker;
       m != NULL;
       UST_FUNCTION(marker_iter_next) (&iter), m = iter.marker)
    if ((uintptr_t ) m->location == address)
      {
	response_ust_marker (packet, &iter);
	return 0;
      }

  strcpy (packet, "l");
  return -1;
}

/* Return the first static tracepoint, and initialize the state
   machine that will iterate through all the static tracepoints.  */

int
cmd_qtfstm (char *packet)
{
  gdb_verbose ("Returning first trace state variable definition");

  UST_FUNCTION(marker_iter_reset) (&iter_for_command);
  UST_FUNCTION(marker_iter_start) (&iter_for_command);

  if (iter_for_command.marker)
    response_ust_marker (packet, &iter_for_command);
  else
    strcpy (packet, "l");

  return 0;
}

/* Return additional trace state variable definitions. */

int
cmd_qtsstm (char *packet)
{
  gdb_verbose ("Returning static tracepoint");

  UST_FUNCTION(marker_iter_next) (&iter_for_command);

  if (iter_for_command.marker)
    response_ust_marker (packet, &iter_for_command);
  else
    strcpy (packet, "l");

  return 0;
}

int
cmd_probe_marker_at(char *packet)
{
  char *p = packet;
  gdb_addr_t address;
  struct marker_iter iter;
  struct marker *m;

  p += sizeof ("probe_marker_at:") - 1;

  p = unpack_varlen_hex (p, &address);

  UST_FUNCTION(marker_iter_reset) (&iter);
  UST_FUNCTION(marker_iter_start) (&iter);
  for (m = iter.marker; m != NULL;
       UST_FUNCTION(marker_iter_next) (&iter), m = iter.marker)
    if ((uintptr_t ) m->location == address)
      {
	int result;

	gdb_verbose ("found marker for address.  "
		     "ltt_marker_connect (marker = %s/%s)",
		     m->channel, m->name);

	result = UST_FUNCTION(ltt_marker_connect) (m->channel, m->name,
						   "gdb");
	if (result && result != -EEXIST)
	  gdb_verbose ("ltt_marker_connect (marker = %s/%s, errno = %d)",
		       m->channel, m->name, -result);

	if (result < 0)
	  {
	    sprintf (packet, "E.could not connect UST marker: channel=%s, name=%s",
		     m->channel, m->name);
	    return -1;
	  }

	strcpy (packet, "OK");
	return 0;
      }

  sprintf (packet, "E.no UST marker found at 0x%x", (unsigned int) address);
  return -1;
}

int
cmd_unprobe_marker_at (char *packet)
{
  char *p = packet;
  gdb_addr_t address;
  struct marker_iter iter;

  p += sizeof ("unprobe_marker_at:") - 1;

  p = unpack_varlen_hex (p, &address);

  UST_FUNCTION(marker_iter_reset) (&iter);
  UST_FUNCTION(marker_iter_start) (&iter);
  for (; iter.marker != NULL; UST_FUNCTION(marker_iter_next) (&iter))
    if ((uintptr_t ) iter.marker->location == address)
      {
	int result;

	result = UST_FUNCTION(ltt_marker_disconnect) (iter.marker->channel,
						      iter.marker->name, "gdb");
	if (result < 0)
	  {
	    gdb_inform ("could not disable marker %s/%s",
			iter.marker->channel, iter.marker->name);
	    return -1;
	  }
	break;
      }

  return 0;
}

extern int serialize_to_text (char *outbuf, int bufsize,
			      const char *fmt, va_list ap);

static int
resolve_ust_symbol ()
{
  RESOLVE_UST_SYMBOL (serialize_to_text);

  RESOLVE_UST_SYMBOL (ltt_probe_register);
  RESOLVE_UST_SYMBOL (ltt_probe_unregister);

  RESOLVE_UST_SYMBOL (ltt_marker_connect);
  RESOLVE_UST_SYMBOL (ltt_marker_disconnect);

  RESOLVE_UST_SYMBOL (marker_iter_start);
  RESOLVE_UST_SYMBOL (marker_iter_next);
  RESOLVE_UST_SYMBOL (marker_iter_stop);
  RESOLVE_UST_SYMBOL (marker_iter_reset);

  return 1;
}

#include<ust/marker.h>

static struct tracepoint_t *
static_tracepoint_find (const struct marker *mdata)
{
  struct tracepoint_t *tpoint;

  for (tpoint = GDB_AGENT_SYM(tracepoints); tpoint; tpoint = tpoint->next)
    {
      if (tpoint->type != static_tracepoint)
	continue;

      if (tpoint->addr == (uintptr_t) mdata->location)
	return tpoint;
    }

  return NULL;
}

/* Extract registers' contents from REGS and PC, and store them into TINFO.  */

static void
static_tracepoint_supply_registers (agent_thread_info_t *tinfo,
				    struct registers *regs,
				    gdb_addr_t pc)
{
  int i;

  memset ((void *) (tinfo->regblock), 0, agent_backend->global_gbufsize);

  for (i = 0; i < agent_backend->static_tracepoint.collect_reg_num; i++)
    {
      int size = agent_backend->static_tracepoint.collect_regmap[i].size;
      int offset = agent_backend->static_tracepoint.collect_regmap[i].offset;

      if (agent_backend->static_tracepoint.pc_reg_num == i)
	((unsigned int *) (tinfo->regblock))[i] = pc;
      else if (offset != -1)
	{
	  switch (size)
	    {
	    case 4:
	      ((unsigned int *) (tinfo->regblock))[i]
		= * (unsigned int *) ((unsigned char *) regs + offset);
	      break;
	    case 2:
	      {
		unsigned long reg
		  = * (short *) (((unsigned char *) regs) + offset);

		reg &= 0xffff;
		((unsigned int *) (tinfo->regblock))[i] = reg;
	      }
	      break;
	    default:
	      agent_fatal ( "unhandled register size: %d", size);
	      break;
	    }
	}
    }
}

static void
agent_probe (const struct marker *mdata, void *probe_private,
	     struct registers *regs, void *call_private,
	     const char *fmt, va_list *args)
{
  struct tracepoint_t *tpoint;

  if (!GDB_AGENT_SYM(tracing))
    {
      gdb_verbose ("agent_probe: not tracing\n");
      return;
    }

  tpoint = static_tracepoint_find (mdata);
  if (tpoint == NULL)
    {
      gdb_verbose ("agent_probe: marker not known: "
		   "loc:0x%p, ch:\"%s\",n:\"%s\",f:\"%s\"",
		   mdata->location, mdata->channel,
		   mdata->name, mdata->format);
      return;
    }

  if (!tpoint->enabled)
    {
      gdb_verbose ("agent_probe: tracepoint disabled");
      return;
    }

  if (tpoint->cond == NULL
      || tracepoint_condition_is_true (tpoint, NULL, NULL))
    {
      pthread_t self = pthread_self ();
      agent_thread_info_t *thread
	= agent_thread_info_find_from_pthread (pthread_self ());

      if (thread == NULL)
	thread = agent_thread_info_add (self);

      static_tracepoint_supply_registers (thread, regs, tpoint->addr);

      tracepoint_collect_data (thread, tpoint, NULL);

      if (GDB_AGENT_SYM(stopping_tracepoint)
	  || GDB_AGENT_SYM(trace_buffer_is_full)
	  || GDB_AGENT_SYM(expr_eval_result) != expr_eval_no_error)
	GDB_AGENT_SYM(stop_tracing) ();
    }
  else
    {
      if (GDB_AGENT_SYM(expr_eval_result) != expr_eval_no_error)
	GDB_AGENT_SYM(stop_tracing) ();
    }
}


/* The probe to register with lttng/ust.  */
static struct ltt_available_probe gdb_ust_probe =
  {
    "gdb",
    NULL,
    agent_probe,
  };

void
initialize_ust (void)
{
  if (!resolve_ust_symbol ())
    return;

  GDB_AGENT_SYM(ust_loaded) = 1;

  UST_FUNCTION(ltt_probe_register) (&gdb_ust_probe);

}
