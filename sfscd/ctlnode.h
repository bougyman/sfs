// -*-c++-*-
/* $Id: ctlnode.h,v 1.1 2002/09/26 19:10:30 dm Exp $ */

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

#ifndef _CTLNODE_H_
#define _CTLNODE_H_ 1

#include "afsnode.h"
#include "qhash.h"

typedef rpc_bytes<NFS3_FHSIZE> fhbytes;

class ctlnode;

class msgnode : public afsnode {
  const inum_t fhextra;
  ctlnode *const ctl;

  char *buf;
  u_int size;
  u_int maxsize;

  timespec closetime;
  bool dirty;

  bool setsize (u_int s);
  void touch ();
  void destroy ();

public:
  tailq_entry<msgnode> tlink;

  static void tmosched (bool expired = false);

  msgnode (ctlnode *c, const fhbytes &fh);
  ~msgnode ();
  void mkfattr3 (fattr3 *f, sfs_aid a);
  void nfs_setattr (svccb *sbp);
  void nfs_read (svccb *sbp);
  void nfs_write (svccb *sbp);
};

class ctlnode : public afsreg {
  friend class msgnode;

  sfs_aid aid;
  mutable inum_t lastino;

  void closecb (svccb *sbp, int err);
  msgnode *getmsgnode (svccb *sbp);

public:
  const str name;
  qhash<const inum_t, ref<msgnode> > ntab;

  void mkfh (nfs_fh *);
  void mkfattr3 (fattr3 *f, sfs_aid a);
  void nfs_setattr (svccb *sbp) { getmsgnode (sbp)->nfs_setattr (sbp); }
  void nfs_write (svccb *sbp) { getmsgnode (sbp)->nfs_write (sbp); }
  void nfs_read (svccb *sbp);
  void nfs3_access (svccb *sbp);

  virtual bool isfilecomplete (bool timeout, const char *buf, u_int size)
    { return timeout; }
  virtual void doclose (str new_contents, cbi errcb)
    { setcontents (new_contents); (*errcb) (0); }

  ctlnode (sfs_aid aid, str name);
};

struct testnode : ctlnode {
  bool isfilecomplete (bool timeout, const char *buf, u_int size) {
    return timeout
      || (size > 2 && !memcmp (buf + size - 3, "\n.\n", 3))
      || (size == 2 && !memcmp (buf + size - 2, ".\n", 2));
  }
  void doclose (str new_contents, cbi cb) {
    if (new_contents.len () >= 3) {
      if (!strcmp (new_contents.cstr () + new_contents.len () - 3, "\n.\n"))
	new_contents = substr (new_contents, 0, new_contents.len () - 2);
    }
    else if (new_contents == ".\n")
      new_contents = "";
    warn << name << ": new contents:\n" << new_contents << "\n";
    ctlnode::doclose (new_contents, cb);
  }
  testnode (sfs_aid aid, str name) : ctlnode (aid, name) {}
};

#endif /* !_CTLNODE_H_ */
