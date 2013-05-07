/* Commands that agent receives from gdb or gdbserver.

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
#include <stdint.h>

#include "config.h"
#include "log.h"
#include "agent.h"


/* Agent can receive commands from gdb or gdbserver through command buffer.
   Command is composed of a KEY and a corresponding FUNCTION.  */
struct command
{
  /* A key to match this command instance from command buffer.  */
  char *key;
  /* Execute this FUN when KEY matches.  */
  int (*fun) (char *cmd_buf);
};

int
break_command (char *cmd_buf)
{
/*
  int number;
  uint64_t address;

  number = *((int *) &cmd_buf[8]);
  address = *((uint64_t *) &cmd_buf[12]);
*/
  return 0;
}

int trace_command_protocol (char *cmd_buf);
#if defined BUILD_UST
int cmd_qtfstm (char *cmd_buf);
int cmd_qtsstm (char *cmd_buf);
int cmd_qtstmat (char *cmd_buf);
int cmd_probe_marker_at (char *cmd_buf);
int cmd_unprobe_marker_at (char *cmd_buf);
#endif

/* Array of agent supported commands.  */
struct command commands[] =
  {
#if defined BUILD_UST
    {"qTfSTM", cmd_qtfstm},
    {"qTsSTM", cmd_qtsstm},
    {"qTSTMat:", cmd_qtstmat},
    {"unprobe_marker_at:", cmd_unprobe_marker_at},
    {"probe_marker_at:", cmd_probe_marker_at},
#endif
    {"break ", break_command},
    {"FastTrace:", trace_command_protocol},
  };

/* Parse CMD_BUF, and call corresponding function if it is found.  */
void
command_parse (char *cmd_buf)
{
  int i;

  gdb_verbose ("parse command");
  for (i = 0; i < sizeof (commands) / sizeof (struct command); i++)
    {
      if (strncmp (commands[i].key, cmd_buf, strlen (commands[i].key)) == 0)
	{
	  gdb_verbose ("parse command: match %s", commands[i].key);
	  commands[i].fun (cmd_buf);
	  return;
	}
    }

  strcpy (cmd_buf, "");
}
