/* Communication module.

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

#include <sys/socket.h>
#include <linux/un.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>

#include "log.h"
#include "agent.h"

#define SOCK_DIR P_tmpdir

int GDB_AGENT_SYM(helper_thread_id) = 0;

/* Command buffer */
char GDB_AGENT_SYM(cmd_buf)[1024];

/* Initialize named socket for NAME.  Return valid file descriptor if
   success, otherwise return -1.  */
static int
init_named_socket (const char *name)
{
  int result, fd;
  struct sockaddr_un addr;

  result = fd = socket (PF_UNIX, SOCK_STREAM, 0);
  if (result == -1)
    {
      gdb_inform ("socket creation failed: %s", strerror (errno));
      return -1;
    }

  addr.sun_family = AF_UNIX;

  strncpy (addr.sun_path, name, UNIX_PATH_MAX);
  addr.sun_path[UNIX_PATH_MAX - 1] = '\0';

  result = access (name, F_OK);
  if (result == 0)
    {
      /* File exists.  */
      result = unlink (name);
      if (result == -1)
	{
	  gdb_inform ("unlink failed: %s", strerror (errno));
	  close (fd);
	  return -1;
	}
      gdb_inform ("socket %s already exists; overwriting", name);
    }

  result = bind (fd, (struct sockaddr *) &addr, sizeof (addr));
  if (result == -1)
    {
      gdb_inform ("bind failed: %s", strerror (errno));
      close (fd);
      return -1;
    }

  result = listen (fd, 1);
  if (result == -1)
    {
      gdb_inform ("listen: %s", strerror (errno));
      close (fd);
      return -1;
    }
  printf ("listen on socket %s\n", name);
  return fd;
}

/* Initialize agent communication socket.  Return valid file descriptor if
   success, otherwise return -1.  */

static int
agent_comm_socket_init (void)
{
  int result, fd;
  char name[UNIX_PATH_MAX];

  result = snprintf (name, UNIX_PATH_MAX, "%s/gdb_ust%d", P_tmpdir, getpid ());
  if (result >= UNIX_PATH_MAX)
    {
      gdb_verbose ("string overflow allocating socket name");
      return -1;
    }

  fd = init_named_socket (name);
  if (fd < 0)
    gdb_inform ("Error initializing named socket (%s) for communication with the "
		 "agent helper thread. Check that directory exists and that it "
		 "is writable.", name);

  return fd;
}

void command_parse (char *cmd_buf);

/* Entry of helper thread.  */

static void *
agent_helper_thread (void *arg)
{
  int listen_fd;

  /* It is an endless loop here.  In each time, agent is waiting for commands
     from clients.  Agent will run corresponding command, write result back
     command buffer and write one byte to synchronization socket.  */
  while (1)
    {
      listen_fd = agent_comm_socket_init ();

      if (GDB_AGENT_SYM(helper_thread_id) == 0)
	GDB_AGENT_SYM(helper_thread_id) = syscall (SYS_gettid);

      if (listen_fd == -1)
	{
	  gdb_inform ("could not create sync socket\n");
	  break;
	}

      while (1)
	{
	  socklen_t tmp;
	  struct sockaddr_un sockaddr;
	  int fd;
	  char buf[1];
	  int ret;

	  tmp = sizeof (sockaddr);
	  gdb_verbose (" calling accept");
	  do
	    {
	      fd = accept (listen_fd, (struct sockaddr *) &sockaddr, &tmp);
	    }
	  while (fd == -512 || (fd == -1 && errno == EINTR));

	  if (fd < 0)
	    {
	      gdb_inform (" Accept returned %d, error: %s\n",
			   fd, strerror (errno));
	      break;
	    }
	  gdb_verbose (" calling read");
	  do
	    {
	      ret = read (fd, buf, 1);
	    } while (ret == -1 && errno == EINTR);

	  if (ret == -1)
	    {
	      gdb_inform (" reading socket (fd=%d) failed with %s",
			  fd, strerror (errno));
	      close (fd);
	      break;
	    }

	  if (GDB_AGENT_SYM(cmd_buf)[0])
	    command_parse (GDB_AGENT_SYM(cmd_buf));

	  if (write (fd, buf, 1))
	    ;

	  gdb_verbose (" write one byte to sync socket");
	  close (fd);
	  gdb_verbose (" close sync socket");
	}
    }

  return NULL;
}

/* Initialize helper thread to communicate with client.  */

void
initialize_helper_thread (void)
{
  int res;
  pthread_t thread;
  sigset_t new_mask;
  sigset_t orig_mask;

  /* We want the helper thread to be as transparent as possible, so
     have it inherit an all-signals-blocked mask.  */

  sigfillset (&new_mask);
  res = pthread_sigmask (SIG_SETMASK, &new_mask, &orig_mask);
  if (res)
    agent_fatal ("pthread_sigmask failed: %s", strerror (res));

  res = pthread_create (&thread, NULL, agent_helper_thread,
			NULL);

  res = pthread_sigmask (SIG_SETMASK, &orig_mask, NULL);
  if (res)
    agent_fatal ("pthread_sigmask (2) failed: %s", strerror (res));

  while (GDB_AGENT_SYM(helper_thread_id) == 0)
    usleep (1);
}
