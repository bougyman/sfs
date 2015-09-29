/* $Id: connect.c,v 1.4 2002/05/16 04:19:45 fubob Exp $ */

/*
 *
 * Copyright (C) 2002 David Mazieres (dm@uun.org)
 * Copyright (C) 2002 Michael Kaminsky (kaminsky@lcs.mit.edu)
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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/un.h>
#include <sys/time.h>
#include <assert.h>
/* #include <stdlib.h> */

#include "connect.h"
#include "uasync.h"

struct cuff_state cuff;

extern char *optarg;
extern int optind;
/* extern int h_errno; */

char *progname;


void usage (void) __attribute__ ((noreturn));
void
usage (void)
{
  fprintf (stderr, "usage: %s [ host:port | unixsock ]\n", progname);
  exit (1);
}

void fperror (char *) __attribute__ ((noreturn));
void
fperror (char *msg)
{
  perror (msg);
  exit (1);
}

int
mksaddr (struct sockaddr_in *saddr, char *name)
{
  char hname[1 + strlen (name)];
  int port;
  struct hostent *hp;

  if (sscanf (name, "%[^:]:%d", hname, &port) != 2)
    return (-1);
  saddr->sin_family = AF_INET;
  saddr->sin_port = htons (port);
  if (! (hp = gethostbyname (hname))) {
    if (inet_aton (hname, &saddr->sin_addr))
      return (0);
    herror (hname);
    return (-1);
  }
  saddr->sin_addr = *(struct in_addr *)hp->h_addr;
  return (0);
}

int
condest_net (char *dest)
{
  struct sockaddr_in saddr;
  int fd;

  if ((fd = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    fperror ("socket");
  bzero (&saddr, sizeof (saddr));
  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = htonl (INADDR_ANY);
  saddr.sin_port = htons (0);
  if (bind (fd, (struct sockaddr *) &saddr, sizeof (saddr)) < 0)
    fperror ("bind (dfd)");
  if (mksaddr (&saddr, dest) < 0)
    exit (1);
  if (connect (fd, (struct sockaddr *) &saddr, sizeof (saddr)) < 0) {
    fprintf (stderr, "connect (%s): ", dest);
    perror (NULL);
    exit (1);
  }
  make_async (fd);
  return (fd);
}

int
condest_unix (char *dest)
{
  struct sockaddr_un saddr;
  int fd;

  if ((fd = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
    fperror ("socket");
  bzero (&saddr, sizeof (saddr));
  saddr.sun_family = AF_UNIX;
  strcpy (saddr.sun_path, dest);
  if (connect (fd, (struct sockaddr *) &saddr, sizeof (saddr)) < 0) {
    fprintf (stderr, "connect (%s): ", dest);
    perror (NULL);
    exit (1);
  }
  make_async (fd);
  return (fd);
}


int
is_connection_up (int fd)
{
  struct sockaddr_in dummy;
  int dummy_len = sizeof(dummy);
  int ret;

  ret = getpeername(fd,
		    (struct sockaddr *)&dummy, &dummy_len);

  return (ret == 0);
}

#define ARESET(a,b) (((a) & (b)) == (b))

void
do_cleanup (struct cuff_state *cuff)
{
  /* If we can't write to anybody, we might as well shut the 
     whole thing down.
  */

  if (ARESET(cuff->state, (SERVER_DONTWRITE | CLIENT_DONTWRITE)))
    cuff->state |= SERVER_DONTREAD | CLIENT_DONTREAD;

  if (cuff->client_fd != -1 && 
      ARESET(cuff->state, (CLIENT_DONTREAD | CLIENT_DONTWRITE))) {
    close(cuff->client_fd);
    cb_free(cuff->client_fd, 0);
    cb_free(cuff->client_fd, 1);
    
    cuff->client_fd = -1;
  }
  
  if (cuff->server_fd != -1 &&
      ARESET(cuff->state, (SERVER_DONTREAD | SERVER_DONTWRITE))) {
    close (cuff->server_fd);
    cb_free(cuff->server_fd, 0);
    cb_free(cuff->server_fd, 1);
    cuff->server_fd = -1;
  }
  
  if (cuff->client_fd == -1 &&
      cuff->server_fd == -1) {
    /* We are done.  Exit. */
    exit (0);
  }
}

void 
client_read (void *arg)
{
  struct cuff_state *cuff = (struct cuff_state *)arg;
  int ret;

  assert (cuff->server_buf_bytes == 0);
  assert (cuff->client_fd != -1);
	
  ret = read (cuff->client_fd,
	      cuff->server_buf,
	      BUFSIZE);

  if (ret <= 0) {
    if (ret == 0)
      fprintf (stderr, "Read client done...\n");
    else
      perror ("read");
    
    cuff->state |= (CLIENT_DONTREAD | SERVER_DONTWRITE);
    
    shutdown (cuff->server_fd, 1);
    cb_free (cuff->client_fd, 0);
    
    do_cleanup (cuff);
    return;
  } else {
    cuff->server_buf_bytes = ret;
    cuff->server_buf_off = 0;
    cb_free (cuff->client_fd, 0);
    assert (cuff->server_fd != -1);
    cb_add (cuff->server_fd, 1, server_write, arg);
  }
}


void 
server_read (void *arg)
{
  struct cuff_state *cuff = (struct cuff_state *)arg;
  int ret;

  assert (cuff->client_buf_bytes == 0);
  assert (cuff->server_fd != -1);
  
  ret = read (cuff->server_fd,
	      cuff->client_buf,
	      BUFSIZE);

  if (ret <= 0) {
    if (ret == 0)
      fprintf (stderr, "Read server done...\n");
    else
      perror ("read");
    
    cuff->state |= (SERVER_DONTREAD | CLIENT_DONTWRITE);
    cb_free (cuff->server_fd, 0);
    
    shutdown (cuff->client_fd, 1);
    
    do_cleanup (cuff);
    return;
  } else {
    cuff->client_buf_bytes = ret;
    cuff->client_buf_off = 0;
    cb_free (cuff->server_fd, 0);
    assert (cuff->client_fd != -1);
    cb_add (cuff->client_fd, 1, client_write, arg);
  }
}

void
client_write (void *arg)
{
  struct cuff_state *cuff = (struct cuff_state *)arg;
  int ret;
  
  if (cuff->client_buf_bytes == 0) {
    cb_free (cuff->client_fd, 1);
    
    assert (cuff->server_fd != -1);
    cb_add (cuff->server_fd, 0,
	    server_read, arg);
    
    return;
  }
  
  assert (cuff->client_fd != -1);
  
  ret = write (cuff->client_fd, 
	       &cuff->client_buf[cuff->client_buf_off],
	       cuff->client_buf_bytes);

  if (ret <= 0) {
    if (ret == 0)
      fprintf (stderr, "Write returned 0. Confused..\n");
    else if (errno == EAGAIN)
      return;
    
    cuff->state |= FULL_CLOSE; 
    do_cleanup (cuff);
    return;
  } else {
    cuff->client_buf_bytes -= ret;
    if (cuff->client_buf_bytes > 0)
      cuff->client_buf_off += ret;
  }
}

void
server_write (void *arg)
{
  struct cuff_state *cuff = (struct cuff_state *)arg;
  int ret;
  
  if (cuff->server_buf_bytes == 0) {
    cb_free (cuff->server_fd, 1);
    
    assert (cuff->client_fd != -1);

    cb_add (cuff->client_fd, 0,
	    client_read, arg);
    return;
  }
  
  assert (cuff->server_fd != -1);
  
  ret = write (cuff->server_fd, 
	       &cuff->server_buf[cuff->server_buf_off],
	       cuff->server_buf_bytes);

  if (ret <= 0) {
    if (ret == 0)
      fprintf (stderr, "Write returned 0. Confused..\n");
    else if (errno == EAGAIN)
      return;
    
    cuff->state |= FULL_CLOSE;
    do_cleanup (cuff);
    return;
  } else {
    cuff->server_buf_bytes -= ret;
    if (cuff->server_buf_bytes > 0)
      cuff->server_buf_off += ret;
  }
}

int
main (int argc, char **argv)
{
  int fd;

  if ((progname = strrchr (argv[0], '/')))
    progname++;
  else
    progname = argv[0];

  if (argc != 2)
    usage ();

  if (strchr (argv[1], ':'))
    fd = condest_net (argv[1]);
  else
    fd = condest_unix (argv[1]);

  memset (&cuff, 0, sizeof (cuff));
  signal (SIGPIPE, SIG_IGN);

  make_async (0);
  cuff.client_fd = 0;
  cuff.server_fd = fd;
  cuff.state = 1;

  cb_add (cuff.server_fd, 1, server_write, &cuff);
  cb_add (cuff.client_fd, 1, client_write, &cuff);

  while (1) {
    cb_check();
  }

  return 0;
}

