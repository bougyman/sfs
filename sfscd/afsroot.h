// -*-c++-*-
/* $Id: afsroot.h,v 1.24 2002/09/19 04:15:19 dm Exp $ */

/*
 *
 * Copyright (C) 1998-2000 David Mazieres (dm@uun.org)
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

ref<afsdir> userdir (sfs_aid aid);
ref<afsdir> userdir (const svccb *);

class mntfs;
class delaypt : public afsnode {
  const str name;
  ref<afslink> wlink;
  ptr<mntfs> mdir;
  ptr<afslink> mlink;

  bool resok;
  bool mdirok;
  bool finalized;
  str delaypath;
  sfs_aid lastaid;

  void delthis () { delete this; }
  bool trydel ();
  void getmntfs (ref<mntfs>);

protected:
  delaypt ();
  PRIVDEST ~delaypt ();
  void bumpctime () { ctime.seconds++; }
  void mkfattr3 (fattr3 *, sfs_aid aid);
  void finalize ();

public:
  static ref<delaypt> alloc () { return New refcounted<delaypt>; }
  void nfs_getattr (svccb *sbp);
  void nfs_readlink (svccb *sbp);
  void nfs3_readlink (svccb *);
  void setres (str);
  void setres (nfsstat err);
  bool resset () { return resok; }
};

struct ctdir : public afsdir {
  sfs_aid lastaid;

  ctdir (afsdir *p) : afsdir (p), lastaid (0)
    { ctime.seconds = ctime.nseconds = 0; }
  void bumpctime () { ctime.seconds++; }
  void mkfattr3 (fattr3 *, sfs_aid aid);
};

class afsroot : public afsdir {
protected:
  sfs_aid lastaid;

  afsroot () : afsdir (NULL) {}
  virtual ~afsroot () {}

public:
  void bumpmtime () { mtime.seconds++; }
  virtual void nfs_lookup (svccb *, str name);

  virtual bool entryok (afsdirentry *, sfs_aid aid);
  virtual afsdirentry *firstentry (sfs_aid aid);
  virtual afsdirentry *nextentry (afsdirentry *, sfs_aid aid);

  virtual void mkfattr3 (fattr3 *, sfs_aid aid);
  virtual void nfs3_access (svccb *sbp);
  virtual void nfs_remove (svccb *sbp);
  virtual void nfs_rmdir (svccb *sbp) { nfs_remove (sbp); }
  virtual void nfs_mkdir (svccb *sbp);
  virtual void nfs_symlink (svccb *sbp);

  static ptr<afsroot> alloc () { return New refcounted<afsroot>; }
};

struct usrinfo;
struct srvinfo;
const size_t maxulinks = 256;

class afsusrdir : public afsdir {
  afsroot *const root;
  size_t nentries;
  str path;

  void lookup_cb (str name, ref<delaypt> dpt,
		  ref<sfsagent_lookup_res> resp, clnt_stat err);

protected:
  sfs_aid aid;
  bool chkaid (svccb *sbp);
  ptr<aclnt> agentc ();

public:
  bhash<str> negcache;

  afsusrdir (afsroot *r, sfs_aid a, afsdir *p, str pn)
    : afsdir (p), root (r), nentries (0), path (pn), aid (a) {}
  ~afsusrdir () { bumpmtime (); }

  virtual void bumpmtime ();
  virtual afsnode *lookup (const str &name, sfs_aid rqaid);
  virtual void mkfh (nfs_fh *fhp);
  virtual void mkfattr3 (fattr3 *, sfs_aid rqaid);
  virtual void nfs3_access (svccb *sbp);
  virtual void nfs_remove (svccb *sbp);
  virtual void nfs_mkdir (svccb *sbp);
  virtual void nfs_symlink (svccb *sbp);

  bool link (afsnode *node, const str &name)
    { if (!afsdir::link (node, name)) return false; nentries++; return true; }
  bool unlink (const str &name)
    { if (!afsdir::unlink (name)) return false; nentries--; return true; }

  bool mkulink (const str &path, const str &name);
  void clrulink (const str &name);
  void clrnegcache () { negcache.clear (); bumpmtime (); }

  virtual ptr<afsdir> mkdir (const str &name);
  ptr<afsdir> mkctdir (const str &name);

  static ref<afsusrdir> alloc (afsroot *r, sfs_aid aid,
			       afsdir *p = NULL, str pn = NULL)
    { return New refcounted<afsusrdir> (r, aid, p ? p : r, pn); }
};

class afsusrroot : public afsusrdir {
  typedef afsusrdir super;

  struct setupstate {
    str name;
    ptr<delaypt> dpt;
    bool revdone;
    sfsagent_revoked_res revres;

    setupstate (const str &n, const ref<delaypt> &d)
      : name (n), dpt (d), revdone (false) {}
  };


  void finish (ref<setupstate> ss, int err);
  void revcb (ref<setupstate> ss, clnt_stat err);

public:
  afsusrroot (afsroot *r, sfs_aid a, afsdir *p, str pn)
    : afsusrdir (r, a, p, pn) {}

  virtual afsnode *lookup (const str &name, sfs_aid rqaid);
  void nfs_lookup (svccb *sbp, str name);

  static ref<afsusrroot> alloc (afsroot *r, sfs_aid aid,
				afsdir *p = NULL, str pn = NULL);
};

class afsaidfile : public afsreg {
  sfs_aid owner;
protected:
  afsaidfile (sfs_aid aid, const str &c) : afsreg (c), owner (aid) {}
public:
  virtual void nfs_getattr (svccb *);
  virtual void nfs3_access (svccb *);
  static ref<afsaidfile> alloc (sfs_aid aid, const str &contents = "")
    { return New refcounted<afsaidfile> (aid, contents); }
};

class afsrootfile : public afsreg {
protected:
  afsrootfile (const str &c) : afsreg (c) {}
public:
  virtual void mkfattr3 (fattr3 *, sfs_aid aid);
  virtual void nfs3_access (svccb *);
  static ref<afsrootfile> alloc (const str &contents = "")
    { return New refcounted<afsrootfile> (contents); }
};

bool nameok (const str &name);
