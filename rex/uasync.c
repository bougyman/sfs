/* Micro async library */

/* $Id: uasync.c,v 1.2 2002/05/17 16:05:25 fubob Exp $ */

/*
 *
 * Copyright (C) 2002 David Mazieres (dm@uun.org)
 * Copyright (C) 2002 Kevin Fu (fubob@mit.edu)   
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>

#include <sys/time.h>
#include <sys/types.h>

#include "uasync.h"

/* Callback to make when a file descriptor is ready */
struct cb {
  void (*cb_fn) (void *);     /* Function to call */
  void *cb_arg;               /* Argument to pass function */
};
static struct cb rcb[FD_MAX], wcb[FD_MAX];  /* Per fd callbacks */
static fd_set rfds, wfds;                   /* Bitmap of cb's in use */

void
cb_add (int fd, int write, void (*fn)(void *), void *arg)
{
  struct cb *c;

  assert (fd >= 0 && fd < FD_MAX);
  c = &(write ? wcb : rcb)[fd];
  c->cb_fn = fn;
  c->cb_arg = arg;
  FD_SET (fd, write ? &wfds : &rfds);
}

void
cb_free (int fd, int write)
{
  assert (fd >= 0 && fd < FD_MAX);
  FD_CLR (fd, write ? &wfds : &rfds);
}

void
cb_check (void)
{
  fd_set trfds, twfds;
  int i, n;

  /* Call select.  Since the fd_sets are both input and output
   * arguments, we must copy rfds and wfds. */
  trfds = rfds;
  twfds = wfds;
  n = select (FD_MAX, &trfds, &twfds, NULL, NULL);
  if (n < 0)
    fatal ("select: %s\n", strerror (errno));

  /* Loop through and make callbacks for all ready file descriptors */
  for (i = 0; n && i < FD_MAX; i++) {
    if (FD_ISSET (i, &trfds)) {
      n--;
      /* Because any one of the callbacks we make might in turn call
       * cb_free on a higher numbered file descriptor, we want to make
       * sure each callback is wanted before we make it.  Hence check
       * rfds. */
      if (FD_ISSET (i, &rfds))
        rcb[i].cb_fn (rcb[i].cb_arg);
    }
    if (FD_ISSET (i, &twfds)) {
      n--;
      if (FD_ISSET (i, &wfds))
        wcb[i].cb_fn (wcb[i].cb_arg);
    }
  }
}

void
make_async (int s)
{
  int n;

  /* Make file file descriptor nonblocking. */
  if ((n = fcntl (s, F_GETFL)) < 0
      || fcntl (s, F_SETFL, n | O_NONBLOCK) < 0)
    fatal ("O_NONBLOCK: %s\n", strerror (errno));

  /* You can pretty much ignore the rest of this function... */

  /* Many asynchronous programming errors occur only when slow peers
   * trigger short writes.  To simulate this during testing, we set
   * the buffer size on the socket to 4 bytes.  This will ensure that
   * each read and write operation works on at most 4 bytes--a good
   * stress test. */
#if defined (SO_RCVBUF) && defined (SO_SNDBUF)
  /* Make sure this really is a stream socket (like TCP).  Code using
   * datagram sockets will simply fail miserably if it can never
   * transmit a packet larger than 4 bytes. */
  {
    int sn = sizeof (n);
    if (getsockopt (s, SOL_SOCKET, SO_TYPE, (char *)&n, &sn) < 0
        || n != SOCK_STREAM)
      return;
  }

#if SMALL_LIMITS
  n = 4;
#else
  n = 0x11000; /* 64K + header */
#endif /* SMALL_LIMITS */

  if (setsockopt (s, SOL_SOCKET, SO_RCVBUF, (char *)&n, sizeof (n)) < 0)
    perror ("SO_RCVBUF:");

  if (setsockopt (s, SOL_SOCKET, SO_SNDBUF, (char *)&n, sizeof (n)) < 0)
    perror ("SO_SNDBUF:");
#endif /* SO_RCVBUF && SO_SNDBUF */

  /* Enable keepalives to make sockets time out if servers go away. */
  n = 1;
  if (setsockopt (s, SOL_SOCKET, SO_KEEPALIVE, (void *) &n, sizeof (n)) < 0)
    fatal ("SO_KEEPALIVE: %s\n", strerror (errno));
}

void *
xrealloc (void *p, size_t size)
{
  p = realloc (p, size);
  if (size && !p)
    fatal ("out of memory\n");
  return p;
}

void
fatal (const char *msg, ...)
{
  va_list ap;

  fprintf (stderr, "fatal: ");
  va_start (ap, msg);
  vfprintf (stderr, msg, ap);
  va_end (ap);
  exit (1);
}
