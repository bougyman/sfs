/* $Id: nfsfd.C,v 1.11 2004/05/22 17:12:57 dm Exp $ */

/*
 *
 * Copyright (C) 1998 David Mazieres (dm@uun.org)
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


#include "nfsmnt.h"

/* This is kind of gross, but we don't want the global destructor
 * running on fdtab, as it might happen before all the nfsfd's are
 * freed. */
typedef ihash2<const int, const sockaddr_in, nfsfd,
  &nfsfd::sotype, &nfsfd::sin, &nfsfd::hlink> fdtab_t;
static fdtab_t &fdtab = *New fdtab_t;

nfsfd::nfsfd (int f, int type, const sockaddr_in *sinp)
  : fd (f), sotype (type), sin (*sinp), server (NULL)
{
  fdtab.insert (this);
}

nfsfd::~nfsfd ()
{
  fdtab.remove (this);
  if (server)
    delete server;
  if (!server)
    close (fd);
}

ptr<nfsfd>
nfsfd::lookup (int f)
{
  if (f < 0)
    return NULL;

  socklen_t len;

  int type = 0;
  len = sizeof (type);
  if (getsockopt (f, SOL_SOCKET, SO_TYPE, (char *) &type, &len) < 0) {
    warn ("NFS server socket: %m\n");
    return NULL;
  }
  if (type != SOCK_DGRAM && type != SOCK_STREAM) {
    warn ("attempt to NFS-mount unknown socket type %d\n", type);
    return NULL;
  }

  sockaddr_in sin;
  len = sizeof (sin);
  bzero (&sin, sizeof (sin));
  if (getpeername (f, (sockaddr *) &sin, &len) >= 0) {
    warn ("attempt to NFS-mount connected socket\n");
    return NULL;
  }
  len = sizeof (sin);
  bzero (&sin, sizeof (sin));
  if (errno != ENOTCONN || getsockname (f, (sockaddr *) &sin, &len) < 0) {
    warn ("NFS server socket: %m\n");
    return NULL;
  }
  if (sin.sin_family != AF_INET) {
    warn ("attempt to NFS-mount non-INET socket\n");
    return NULL;
  }
  if (sin.sin_port == htons (0)) {
    warn ("attempt to NFS-mount unbound socket\n");
    return NULL;
  }
  if (sin.sin_addr.s_addr == htonl (INADDR_ANY))
    sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

#ifdef SO_ACCEPTCONN
  if (type == SOCK_STREAM) {
    int listening = 0;
    len = sizeof (listening);
    if (getsockopt (f, SOL_SOCKET, SO_ACCEPTCONN,
		    (char *) &listening, &len) < 0) {
      warn ("NFS server socket (SO_ACCEPTCONN): %m\n");
      return NULL;
    }
    else if (!listening) {
      warn ("attempt to NFS-mount non-listening stream socket\n");
      return NULL;
    }
  }
#endif /* SO_ACCEPTCONN */

  if (nfsfd *nf = fdtab (type, sin)) {
    close (f);
    return mkref (nf);
  }
  return New refcounted<nfsfd> (f, type, &sin);
}

void
nfsfd::traverse (callback<void, nfsfd *>::ref cb)
{
  fdtab.traverse (cb);
}

ptr<aclnt>
nfsfd::mkclnt (int nfsvers)
{
  const rpc_program *rpp;
  switch (nfsvers) {
  case 2:
    rpp = &nfs_program_2;
    break;
  case 3:
    rpp = &nfs_program_3;
    break;
  default:
    panic ("nfsfd::mkclnt: bad nfs version %d\n", nfsvers);
    break;
  }

#if 0
  if (sotype == SOCK_DGRAM)
    return aclnt::alloc (udpxprt, *rpp, (sockaddr *) &sin);
  int fd = socket (AF_INET, SOCK_STREAM, 0);
#else
  int fd = socket (AF_INET, sotype, 0);
#endif
  if (fd < 0) {
    warn ("socket: %m\n");
    return NULL;
  }
  make_async (fd);
  if (connect (fd, (sockaddr *) &sin, sizeof (sin)) < 0
      && errno != EINPROGRESS) {
    warn ("connect: %m\n");
    close (fd);
    return NULL;
  }
  if (sotype == SOCK_DGRAM)
    return aclnt::alloc (axprt_dgram::alloc (fd), *rpp);
  else
    return aclnt::alloc (axprt_stream::alloc (fd), *rpp);
}
