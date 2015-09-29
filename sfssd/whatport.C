/* $Id: whatport.C,v 1.1 2003/10/12 05:22:41 dm Exp $ */

/*
 *
 * Copyright (C) 2003 David Mazieres (dm@uun.org)
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
#include "dns.h"

struct wpstate {
  typedef callback<void, const vec<u_int16_t> *>::ref cb_t;
  cb_t cb;
  str srvname;
  bhash<in_addr> addrs;
  ptr<srvlist> srvl;
  u_int rqpending;
  bool anyerr;
  bool tmperr;

  wpstate (str sn, cb_t c);
  void gotsrv (ptr<srvlist> sl, int err);
  void gota (int n, ptr<hostent> h, int err);
  void reply ();
};

wpstate::wpstate (str sn, wpstate::cb_t c)
  : cb (c), srvname (sn), anyerr (false), tmperr (false)
{
  vec<in_addr> a;
  if (!myipaddrs (&a))
    fatal ("could not find my IP address (%m)\n");
  for (in_addr *ap = a.base (); ap < a.lim (); ap++)
    addrs.insert (*ap);
  dns_srvbyname (srvname, "tcp", "sfs", wrap (this, &wpstate::gotsrv));
}

void
wpstate::gotsrv (ptr<srvlist> sl, int err)
{
  if (!sl) {
    if (dns_tmperr (err)) {
      tmperr = true;
      warn << srvname << ": " << dns_strerror (err) << "\n";
    }
    reply ();
    return;
  }

  srvl = sl;
  rqpending = srvl->s_nsrv;
  for (u_int i = 0; i < srvl->s_nsrv; i++) {
    srvrec &sr = srvl->s_srvs[i];
    if (!sr.port)
      gota (i, NULL, ARERR_NXREC);
    else
      dns_hostbyname (sr.name, wrap (this, &wpstate::gota, i), false, false);
  }
}

void
wpstate::gota (int n, ptr<hostent> h, int err)
{
  srvrec &sr = srvl->s_srvs[n];
  if (!h) {
    sr.port = 0;
    if (!anyerr) {
      anyerr = true;
      warn << "in resolving DNS SRV records for " << srvname << ":\n";
    }
    warn << sr.name << ": " << dns_strerror (err) << "\n";
    if (dns_tmperr (err))
      tmperr = true;
  }
  else {
    char **hp;
    for (hp = h->h_addr_list; *hp && !addrs[*(in_addr *) *hp]; hp++)
      ;
    if (!*hp)
      sr.port = 0;
  }

  if (!--rqpending)
    reply ();
}

void
wpstate::reply ()
{
  bhash<u_int16_t> seen;
  vec<u_int16_t> ports;

  if (srvl)
    for (u_int i = 0; i < srvl->s_nsrv; i++) {
      u_int16_t port = srvl->s_srvs[i].port;
      if (port && seen.insert (port))
	ports.push_back (port);
    }
  if (ports.empty ()) {
    if (tmperr || srvl)
      warn ("assuming default port %d\n", SFS_PORT);
    ports.push_back (SFS_PORT);
  }

  (*cb) (&ports);
  delete this;
}

void
whatport (str hostname, callback<void, const vec<u_int16_t> *>::ref cb)
{
  vNew wpstate (hostname, cb);
}
