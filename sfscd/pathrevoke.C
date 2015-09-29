/* $Id: pathrevoke.C,v 1.6 2002/08/23 19:58:16 max Exp $ */

/*
 *
 * Copyright (C) 1999 David Mazieres (dm@uun.org)
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

#include "sfscd.h"

static ihash<sfs_hash, revocation,
  &revocation::hostid, &revocation::hlink> revtab;

revocation::revocation (sfs_pathrevoke_w *w) : prw (w)
{
  bool ok = w->si->mkhostid (&hostid);
  assert (ok);
  srvinfo::revoke (w->si->mkpath_client ()); 

  if (prw->rev.msg.redirect) {
    setres (w->rsi->mkpath_client ());
  } else
    setres (":REVOKED:");

  revtab.insert (this);
}

void
revocation::update (sfs_pathrevoke_w *w)
{
  if (!prw->rev.msg.redirect || !w->check ())
    return;
  if (w->rev.msg.redirect && 
      w->rev.msg.redirect->serial < prw->rev.msg.redirect->serial)
    return;

  delete prw;
  prw = w;

  if (w->rev.msg.redirect)
    setres (w->rsi->mkpath_client ());
  else
    setres (":REVOKED:");
}

revocation::~revocation ()
{
  delete prw;
  revtab.remove (this);
}

ptr<revocation>
revocation::alloc (const sfs_pathrevoke &c)
{
  sfs_hash hostid;
  sfs_pathrevoke_w *w = New sfs_pathrevoke_w (c);
  if (!w->check (&hostid)) {
    delete w;
    return NULL;
  } 

  if (revocation *r = revtab[hostid]) {
    r->update (w);
    return mkref (r);
  }
  else {
    srvinfo::revoke (w->si->mkpath_client ());
    return New refcounted<revocation> (w);
  }
}

ptr<revocation>
revocation::lookup (const str &path)
{
  sfs_hash hostid;
  if (!sfs_parsepath (path, NULL, &hostid))
    return NULL;
  revocation *r = revtab[hostid];
  if (r)
    return mkref (r);
  return NULL;
}
