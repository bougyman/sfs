// -*-c++-*-
/* $Id: tcpproxy.C,v 1.3 2004/06/03 20:09:58 dm Exp $ */

/*
 *
 * Copyright (C) 2002 David Mazieres (dm@uun.org)
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



#include "sfssd.h"

proxy::proxy (int fd1, int fd2)
{
  con[0].fd = fd1;
  con[1].fd = fd2;
  for (int i = 0; i < 2; i++) {
    make_async (con[i].fd);
    tcp_nodelay (con[i].fd);
    setcb (i);
  }
}

void
proxy::setcb (int i)
{
  /* If we have data or an EOF to transmit, schedule a write callback. */
  if (con[i].wbuf.resid () || con[!i].eof && !con[i].closed) {
    fdcb (con[i].fd, selwrite, wrap (this, &proxy::wcb, i));
    if (!con[i].tmo)
      con[i].tmo = delaycb (120, wrap (this, &proxy::timeout, i));
  }

  /* If buffer falls beneath low-water mark, schedule a read callback. */
  if (!con[!i].eof && con[i].wbuf.resid () <= lowat)
    fdcb (con[!i].fd, selread, wrap (this, &proxy::rcb, !i));
}

void
proxy::rcb (int i)
{
  if (con[!i].wbuf.resid () >= hiwat) {
    fdcb (con[i].fd, selread, NULL);
    return;
  }
  int n = con[!i].wbuf.input (con[i].fd);
  if (n == 0 || n < 0 && errno != EAGAIN) {
    if (n < 0)
      warn << "read: " << strerror (errno) << "\n";
    con[i].eof = true;
    fdcb (con[i].fd, selread, NULL);
  }
  setcb (!i);
}

void
proxy::wcb (int i)
{
  size_t bufsize = con[i].wbuf.resid ();
  if (bufsize && con[i].wbuf.output (con[i].fd) < 0 && errno != EAGAIN) {
    warn << "write-" << (i ? "client" : "server")
	 << ": " << strerror (errno) << "\n";
    delete this;
    return;
  }
  if (con[i].wbuf.resid () < bufsize && con[i].tmo) {
    timecb_remove (con[i].tmo);
    con[i].tmo = NULL;
  }
  if (!con[i].wbuf.resid ()) {
    fdcb (con[i].fd, selwrite, NULL);
    if (con[!i].eof && !con[i].closed) {
      if (con[!i].closed) {
	delete this;
	return;
      }
      con[i].closed = true;
      shutdown (con[i].fd, 1);
    }
  }
  setcb (i);
}

void
proxy::timeout (int i)
{
  con[i].tmo = NULL;
  delete this;
}

proxy::~proxy ()
{
  list<proxy, &proxy::llink>::remove (this);
  for (int i = 0; i < 2; i++) {
    fdcb (con[i].fd, selread, NULL);
    fdcb (con[i].fd, selwrite, NULL);
    close (con[i].fd);
    timecb_remove (con[i].tmo);
  }
}

sfssrv_proxy::sfssrv_proxy (str h, u_int16_t p)
  : host (h), port (p ? p : sfs_defport),
    destroyed (New refcounted<bool> (false))
{
}


sfssrv_proxy::~sfssrv_proxy ()
{
  *destroyed = true;
  while (proxies.first)
    delete proxies.first;
}

void
sfssrv_proxy::mkproxy (ref<bool> dest, int cfd, str data, svccb *sbp, int sfd)
{
  if (*dest) {
    sbp->replyref (sfs_connectres (SFS_TEMPERR));
    close (cfd);
    close (sfd);
    return;
  }
  if (sfd < 0) {
    warn << host << ":" << port << ": " << strerror (errno) << "\n";
    sbp->replyref (sfs_connectres (SFS_TEMPERR));
    close (cfd);
    return;
  }
  sbp->ignore ();
  proxy *pp = New proxy (cfd, sfd);
  proxies.insert_head (pp);
  suio_print (&pp->con[1].wbuf, data);
  pp->setcb (1);
}

void
sfssrv_proxy::clone (ref<axprt_clone> xc, svccb *sbp)
{
  int cfd;
  str data;
  xc->extract (&cfd, &data);
  tcpconnect (host, port, wrap (this, &sfssrv_proxy::mkproxy,
				destroyed, cfd, data, sbp));
}

str
sfssrv_proxy::name ()
{
  return strbuf ("TCP proxy to %s:%d", host.cstr (), port);
}
