/* $Id: relay.c,v 1.1 2004/07/01 05:46:39 dm Exp $ */

/*
 *
 * Copyright (C) 2004 David Mazieres (dm@uun.org)
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

#include "sysconf.h"
#include "uasync.h"

static int nstreams;

enum { bufsize = 0x10000 };

typedef struct stream_t {
  char eof;
  int rfd;
  int wfd;
  int buf_start;
  int buf_len;
  char *buf;
} stream_t;

static void stream_input (void *_st);
static void stream_output (void *_st);
static void stream_sched (stream_t *st);

stream_t *
stream_alloc (int rfd, int wfd)
{
  stream_t *st = xmalloc (sizeof (*st));
  bzero (st, sizeof (*st));
  st->buf = xmalloc (bufsize);
  st->rfd = rfd;
  st->wfd = wfd;
  make_async (rfd);
  make_async (wfd);
  nstreams++;
  stream_sched (st);
  return st;
}

static void
stream_free (stream_t *st)
{
  cb_free (st->rfd, 0);
  cb_free (st->wfd, 1);
  xfree (st->buf);
  xfree (st);
  nstreams--;
}

static void
stream_sched (stream_t *st)
{
  if (st->buf_len) {
    cb_free (st->rfd, 0);
    cb_add (st->wfd, 1, stream_output, st);
  }
  else if (st->eof) {
    shutdown (st->wfd, SHUT_WR);
    stream_free (st);
  }
  else {
    cb_add (st->rfd, 0, stream_input, st);
    cb_free (st->wfd, 1);
  }
}

static void
stream_input (void *_st)
{
  stream_t *st = _st;
  st->buf_start = 0;
  st->buf_len = read (st->rfd, st->buf, bufsize);
  if (st->buf_len <= 0)
    st->eof = 1;
  stream_sched (st);
}

static void
stream_output (void *_st)
{
  stream_t *st = _st;
  int n = write (st->wfd, st->buf + st->buf_start, st->buf_len);
  if (n <= 0)
    stream_free (st);
  else {
    st->buf_start += n;
    st->buf_len -= n;
    stream_sched (st);
  }
}

void
relay (int fd)
{
  stream_alloc (0, fd);
  stream_alloc (fd, 1);
  while (nstreams)
    cb_check ();
}
