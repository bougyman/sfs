/* $Id: listen.c,v 1.13 2004/07/27 01:09:13 dm Exp $ */

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
#include "rwfd.h"
#include "uasync.h"

#define XDIR "/tmp/.X11-unix"

char *progname;
char *path2unlink;
int opt_insecure;		/* -U */
int opt_oneshot;		/* -1 */

static void usage () __attribute__ ((noreturn));
static void
usage ()
{
  fprintf (stderr, "usage: %s [-1] [-U] {-x | -u path | tcpportnum}\n",
	   progname);
  exit (-1);
}

static void
termsig (int sig)
{
  if (path2unlink)
    unlink (path2unlink);
  exit (1);
}

void
tcp_nodelay (int s)
{
#if defined (TCP_NODELAY) || defined (IPTOS_LOWDELAY)
  int n = 1;
#endif /* TCP_NODELAY || IPTOS_LOWDELAY */
#ifdef TCP_NODELAY
  if (setsockopt (s, IPPROTO_TCP, TCP_NODELAY, (char *) &n, sizeof (n)) < 0)
    warn ("TCP_NODELAY: %m\n");
#endif /* TCP_NODELAY */
#ifdef IPTOS_LOWDELAY
  setsockopt (s, IPPROTO_IP, IP_TOS, (char *) &n, sizeof (n));
#endif /* IPTOS_LOWDELAY */

#if defined (SO_RCVBUF) && defined (SO_SNDBUF)
  int n = 0x11000;

  if (setsockopt (s, SOL_SOCKET, SO_RCVBUF, (char *) &n, sizeof (n)) < 0)
    perror ("SO_RCVBUF:");

  if (setsockopt (s, SOL_SOCKET, SO_SNDBUF, (char *) &n, sizeof (n)) < 0)
    perror ("SO_SNDBUF:");
#endif /* SO_RCVBUF && SO_SNDBUF */
}

int
do_oneshot (int s)
{
  relay (s);
  return 0;
}

int
bind_unix (char *path)
{
  struct sockaddr_un sun;
  if (strlen (path) + 1 > sizeof (sun.sun_path)) {
    errno = E2BIG;
    return -1;
  }

  bzero (&sun, sizeof (sun));
  sun.sun_family = AF_UNIX;
  strcpy (sun.sun_path, path);
  umask (opt_insecure ? 0111 : 0177);
  for (;;) {
    int s = socket (AF_UNIX, SOCK_STREAM, 0);
    if (s < 0)
      return -1;
    if (!bind (s, (struct sockaddr *) &sun, sizeof (sun))) {
      if (!(path2unlink = strdup (path))) {
	unlink (path);
	fprintf (stderr, "out of memory\n");
	exit (1);
      }
      return s;
    }
    if (errno != EADDRINUSE) {
      close (s);
      return -1;
    }

    /* Don't unlink if someone is still listening */
    if (!connect (s, (struct sockaddr *) &sun, sizeof (sun))) {
      close (s);
      errno = EADDRINUSE;
      return -1;
    }
    close (s);
    unlink (path);
  }
}

int
bind_x (void)
{
  int i, s;
  char xpath[sizeof (XDIR) + 12];
  struct stat sb;

  if (stat (XDIR, &sb)) {
    if (errno != ENOENT || mkdir (XDIR, 0777) || chmod (XDIR, 01777)) {
      fprintf (stderr, "%s: %s: %s\n", progname, XDIR, strerror (errno));
      exit (1);
    }
  }
  else if (sb.st_uid && sb.st_uid != getuid ()) {
    /* If someone else can write the directory, that person can also
     * move our socket out of the way, accept a connection from one of
     * our clients, and learn the magic cookie.  So best not to rely
     * entirely cookies for security... */
    opt_insecure = 0;
  }

  for (i = 1; i < 100; i++) {
    sprintf (xpath, "%s/X%d", XDIR, i);
    if ((s = bind_unix (xpath)) >= 0) {
      printf (":%d\n", i);	/* so client can setenv DISPLAY */
      fflush (stdout);
      return s;
    }
  }

  fprintf (stderr, "no X displays available\n");
  exit (1);
}

int
bind_tcp (char *addrstr, char *portstr)
{
  int port;
  struct hostent *hp;
  struct sockaddr_in sin;
  int s;
  int n = 1;

  port = atoi (portstr);
  if (port <= 0 || port >= 0x10000)
    usage ();

  bzero (&sin, sizeof (sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons (port);

  if (!inet_aton (addrstr, &sin.sin_addr)) {
    if (!(hp = gethostbyname (addrstr))) {
      fprintf (stderr, "%s: no such host\n", addrstr);
      exit (1);
    }
    sin.sin_addr = *(struct in_addr *) hp->h_addr;
  }
  if (sin.sin_addr.s_addr != htonl (INADDR_LOOPBACK))
    opt_insecure = 1;

  if ((s = socket (AF_INET, SOCK_STREAM, 0)) < 0) {
    fprintf (stderr, "%s: TCP socket: %s\n", progname, strerror (errno));
    exit (1);
  }
  if (setsockopt (s, SOL_SOCKET, SO_REUSEADDR, &n, sizeof (n))) {
    fprintf (stderr, "%s: SO_REUSEADDR: %s\n", progname, strerror (errno));
    exit (1);
  }
  if (bind (s, (struct sockaddr *) &sin, sizeof (sin))) {
    fprintf (stderr, "%s: %s port %d: %s\n", progname,
	     addrstr, port, strerror (errno));
    exit (1);
  }

  return s;
}

int
check_tcp (int s, const struct sockaddr *_addr, socklen_t len)
{
  struct sockaddr_in *sinp = (struct sockaddr_in *) _addr;
  tcp_nodelay (s);
  fprintf (stderr, "%s: accepting TCP connection from %s:%d\n", progname,
	   inet_ntoa (sinp->sin_addr), ntohs (sinp->sin_port));
  if (!opt_insecure) {
#if HAVE_BSD_REUSEADDR
    struct sockaddr_in sin;
    socklen_t sinlen = sizeof (sin);
    int n = 1;
    int s2;
    bzero (&sin, sizeof (&sin));
    sin.sin_family = AF_INET;
    if (getpeername (s, (struct sockaddr *) &sin, &sinlen)
	|| sin.sin_family != AF_INET || sinlen != sizeof (sin))
      return 0;
    if (ntohs (sin.sin_port) < IPPORT_RESERVED)
      return 1;

    /* On newer BSD OSes, you can't re-bind a port bound by a
     * different user ID, so we use this as a kind of cheap sanity
     * check. */
    if ((s2 = socket (AF_INET, SOCK_STREAM, 0)) < 0) {
      fprintf (stderr, "%s: TCP socket: %s\n", progname, strerror (errno));
      return 0;
    }
    sin.sin_addr.s_addr = htonl (INADDR_ANY);
    if (setsockopt (s2, SOL_SOCKET, SO_REUSEADDR, &n, sizeof (n))) {
      fprintf (stderr, "%s: SO_REUSEADDR: %s\n", progname, strerror (errno));
      close (s2);
      return 0;

    }
    if (bind (s2, (struct sockaddr *) &sin, sizeof (sin))) {
      fprintf (stderr,
	       "%s: rejecting TCP connection possibly from other user\n",
	       progname);
      close (s2);
      return 0;
    }
    close (s2);
#endif /* HAVE_BSD_REUSEADDR */
  }
  return 1;
}

int
check_unix (int s, const struct sockaddr *_addr, socklen_t len)
{
  fprintf (stderr, "%s: accepting connection\n", progname);
  if (!opt_insecure) {
#ifdef HAVE_GETPEEREID
    uid_t uid;
    gid_t gid;
    if (getpeereid (s, &uid, &gid) < 0) {
      fprintf (stderr, "%s: getpeereid: %s\n", progname, strerror (errno));
      return 0;
    }
    else if (uid && uid != getuid ()) {
      fprintf (stderr, "%s: rejecting connection from UID %d\n",
	       progname, uid);
      return 0;
    }
#endif /* HAVE_GETPEEREID */
  }
  return 1;
}


int
accept_loop (int lfd,
	     int (*check_fn) (int, const struct sockaddr *, socklen_t))
{
  static fd_set rfds;
  FD_ZERO (&rfds);

  for (;;) {
    FD_SET (0, &rfds);
    FD_SET (lfd, &rfds);
    if (select (lfd + 1, &rfds, NULL, NULL, NULL) < 0) {
      fprintf (stderr, "%s: select: %s\n", progname, strerror (errno));
      return -1;
    }
    if (FD_ISSET (0, &rfds))
      return 0;
    if (FD_ISSET (lfd, &rfds)) {
      union sock_union {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_un sun;
      } s_un;
      socklen_t len = sizeof (s_un);
      int s;

      bzero (&s_un, sizeof (s_un));
      s = accept (lfd, &s_un.sa, &len);
      if (s < 0) {
	fprintf (stderr, "%s: accept: %s\n", progname, strerror (errno));
	return -1;
      }
      if (check_fn (s, &s_un.sa, len)) {
	if (opt_oneshot) {
	  close (lfd);
	  return do_oneshot (s);
	}
	if (writefd (0, "", 1, s) < 0) {
	  fprintf (stderr, "%s: failed to send accepted fd\n", progname);
	  return -1;
	}
      }
      close (s);
    }
  }
}

int
main (int argc, char **argv)
{
  int ch;
  char *opt_unixpath = NULL;	/* -u */
  int opt_x = 0;		/* -x */
  int (*check_fn) (int, const struct sockaddr *, socklen_t) = check_unix;
  int listen_sock = -1;
  int err;

  if ((progname = strrchr (argv[0], '/')))
    progname++;
  else
    progname = argv[0];

  while ((ch = getopt (argc, argv, "Uu:x1")) != -1)
    switch (ch) {
    case 'U':
      opt_insecure = 1;
      break;
    case 'u':
      opt_unixpath = optarg;
      break;
    case 'x':
      opt_x = 1;
      break;
    case '1':
      opt_oneshot = 1;
      break;
    default:
      usage ();
    }

  signal (SIGINT, termsig);
  signal (SIGTERM, termsig);

  if (opt_x) {
    if (opt_unixpath || optind != argc)
      usage ();
    opt_insecure = 1;		/* Since we have cookies */
    listen_sock = bind_x ();
  }
  else if (opt_unixpath) {
    if (optind != argc)
      usage ();
    if ((listen_sock = bind_unix (opt_unixpath)) < 0) {
      fprintf (stderr, "%s: %s: %s\n", progname, opt_unixpath,
	       strerror (errno));
      exit (1);
    }
  }
  else {
    if (optind + 1 == argc)
      listen_sock = bind_tcp ("127.0.0.1", argv[optind]);
    else if (optind + 2 == argc)
      listen_sock = bind_tcp (argv[optind], argv[optind + 1]);
    else
      usage ();
    check_fn = check_tcp;
  }

  if (listen (listen_sock, opt_oneshot ? 0 : 5) < 0) {
    err = 1;
    fprintf (stderr, "%s: listen: %s\n", progname, strerror (errno));

  }
  else
    err = accept_loop (listen_sock, check_fn);
  if (path2unlink)
    unlink (path2unlink);
  exit (err ? 1 : 0);
}
