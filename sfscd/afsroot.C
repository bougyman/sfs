/* $Id: afsroot.C,v 1.42 2004/09/19 22:02:28 dm Exp $ */

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


#include "sfscd.h"

/*
 * ctdir directories are used for self-certifying pathname mount
 * points.  There is some subtlety to getting mount points to behave
 * properly, because users only see a self-certifying pathname once
 * they have referenced it--even if other users are already using that
 * self-certifying pathname.
 *
 * The danger here is that user A might execute:
 *
 *    cd /sfs/@host,hostid
 *
 * User A would then see @host,hostid in listings of /sfs.  However,
 * suppose user B subsequently runs:
 *
 *    cd /sfs/@host,hostid
 *
 * The kernel might then get the name @host,hostid out of the name
 * cache, and not actually issue an NFS LOOKUP RPC on behalf of user
 * B.  That means we won't add @host,hostid to B's afsusrroot
 * directory, and consequently B won't see @host,hostid in /sfs (and
 * pwd may not work).
 *
 * The standard trick we use is to increment the ctime by one second
 * every time a different user looks at the attributes of the
 * @host,hostid directory.  (These are the attributes of the
 * mountpoint, as opposed to the underlying file system, so users
 * can't actually see this particular ctime, but the kernel uses is
 * for cache consistency.)  If the ctime has incremented by a whole
 * second (because some Unixes are broken and don't check the
 * nanoseconds), then the file may have been renamed so the kernel
 * will not use the name cache.
 *
 * But that's still not quite good enough, because a user may start an
 * agent after cding to a self-certifying pathname.  So we remember
 * not the last aid, but the last aid if the user was running an
 * agent.  (Still not quite perfect, but probably good enough.  If
 * this causes problems, though, then we will have to bump the ctime
 * on every lookup--even back-to-back ones by the same user.)
 */
void
ctdir::mkfattr3 (fattr3 *f, sfs_aid aid)
{
  if (!sfs_specaid (aid) && !usrtab[aid])
    aid = sfsaid_nobody;
  if (aid != lastaid) {
    lastaid = aid;
    bumpctime ();
  }
  afsnode::mkfattr3 (f, aid);
}

void
afsroot::nfs_lookup (svccb *sbp, str name)
{
  if (afsnode *e = lookup (name, sbp2aid (sbp)))
    lookup_reply (sbp, e);
  else
    userdir (sbp)->nfs_lookup (sbp, name);
}

bool
afsroot::entryok (afsdirentry *de, sfs_aid aid)
{
  afsdir *d = userdir (aid);
  if (d && d->entryok (de, aid))
    return true;
  return afsdir::entryok (de, aid);
}

afsdirentry *
afsroot::firstentry (sfs_aid aid)
{
  afsdir *d = userdir (aid);
  afsdirentry *de = afsdir::firstentry (aid);
  if (!d || !d->lookup (de->name, aid))
    return de;
  return nextentry (de, aid);
}

afsdirentry *
afsroot::nextentry (afsdirentry *de, sfs_aid aid)
{
  afsdir *d = userdir (aid);
  if (de->dir == this) {
    for (de = afsdir::nextentry (de, aid); de;
	 de = afsdir::nextentry (de, aid))
      if (!d || !d->lookup (de->name, aid))
	return de;
  }
  else {
    assert (de);
  }

  if (!d)
    return NULL;
  if (!de)
    return d->firstentry (aid);
  else
    return d->nextentry (de, aid);
}

void
afsroot::mkfattr3 (fattr3 *f, sfs_aid aid)
{
  /* BSD needs the seconds (not just milliseconds/nanoseconds) of the
   * mtime to change on every lookup/getattr in order to defeat the
   * name cache. */
  if (aid != lastaid) {
    lastaid = aid;
    bumpmtime ();
  }
  afsdir::mkfattr3 (f, aid);
  if (afsdir *d = userdir (aid)) {
    if (d != afs_naroot)
      f->mode |= 0222;
    f->nlink += d->getnlinks () - 2;
  }
}

void
afsroot::nfs3_access (svccb *sbp)
{
  const sfs_aid aid = sbp2aid (sbp);
  if (usrinfo *u = usrtab[aid])
    u->root->nfs3_access (sbp);
  else {
    access3res res (NFS3_OK);
    mkpoattr (res.resok->obj_attributes, aid);
    res.resok->access = (ACCESS3_READ | ACCESS3_LOOKUP | ACCESS3_EXECUTE
			 | ACCESS3_DELETE);
    res.resok->access &= sbp->Xtmpl getarg<access3args> ()->access;
    sbp->reply (&res);
  }
}
 bool
nameok (const str &name)
{
  static rxx namerx ("[a-zA-Z0-9\\-]+(\\.[a-zA-Z0-9\\-]+)*");
  return name.len () < NFS_MAXNAMLEN && namerx.match (name);
}

void
afsroot::nfs_remove (svccb *sbp)
{
  str name = sbp->vers () == 2
    ? str (sbp->Xtmpl getarg<diropargs> ()->name)
    : str (sbp->Xtmpl getarg<diropargs3> ()->name);

  if (srvinfo *si = srvinfo::lookup (name)) {
    si->unmount (0);
    nfs_error (sbp, nfsstat (EINPROGRESS));
  }
  else if (afsdir *d = userdir (sbp))
    d->nfs_remove (sbp);
  else
    nfs_error (sbp, NFSERR_ACCES);
}

void
afsroot::nfs_symlink (svccb *sbp)
{
  str name = sbp->vers () == 2
    ? str (sbp->Xtmpl getarg<symlinkargs> ()->from.name)
    : str (sbp->Xtmpl getarg<symlink3args> ()->where.name);

  if (entries[name])
    nfs_error (sbp, NFSERR_EXIST);
  else if (usrinfo *u = usrtab[sbp2aid (sbp)])
    u->root->nfs_symlink (sbp);
  else
    nfs_error (sbp, NFSERR_ACCES);
}

void
afsroot::nfs_mkdir (svccb *sbp)
{
  str name = sbp->vers () == 2
    ? str (sbp->Xtmpl getarg<createargs> ()->where.name)
    : str (sbp->Xtmpl getarg<mkdir3args> ()->where.name);

  if (entries[name])
    nfs_error (sbp, nfsstat (NFSERR_EXIST));
  else if (usrinfo *u = usrtab[sbp2aid (sbp)])
    u->root->nfs_mkdir (sbp);
  else
    nfs_error (sbp, nfsstat (NFSERR_ACCES));
}

bool
afsusrdir::chkaid (svccb *sbp)
{
  const sfs_aid rqaid = sbp2aid (sbp);
  if (rqaid != aid) {
    nfs_error (sbp, NFSERR_STALE);
    return false;
  }
  return true;
}

ptr<aclnt>
afsusrdir::agentc ()
{
  if (!terminating)
    if (usrinfo *u = usrtab[aid])
      return u->ch;
  return NULL;
}

void
afsusrdir::bumpmtime ()
{
  if (root == parent)
    root->bumpmtime ();
  afsdir::bumpmtime ();
}

afsnode *
afsusrdir::lookup (const str &name, sfs_aid rqaid)
{
  if (afsnode *n = afsdir::lookup (name, aid))
    return n;
  ptr<aclnt> ch;
  if (negcache[name] || !nameok (name) || !(ch = agentc ()))
    return NULL;

  ref<delaypt> dpt = delaypt::alloc ();
  link (dpt, name);
  sfs_filename lname = path ? str (path << "/" << name) : name;
  ref<sfsagent_lookup_res> resp = New refcounted<sfsagent_lookup_res>;
  ch->timedcall (agent_timeout, AGENTCB_LOOKUP, &lname, resp,
		    wrap (mkref (this), &afsusrdir::lookup_cb,
			  name, dpt, resp));
  return dpt;
}

void
afsusrdir::lookup_cb (str name, ref<delaypt> dpt,
		      ref<sfsagent_lookup_res> resp, clnt_stat err)
{
  unlink (name);
  if (err || resp->type == LOOKUP_NOOP ||
      (resp->type == LOOKUP_MAKELINK && !resp->path->len ())) {
    mkulink (NULL, name);
    dpt->setres (NFSERR_NOENT);
  }
  else if (resp->type == LOOKUP_MAKELINK) {
    mkulink (*resp->path, name);
    if (path && (*resp->path)[0] != '/')
      dpt->setres (path << "/" << *resp->path);
    else
      dpt->setres (*resp->path);
  } else if (resp->type == LOOKUP_MAKEDIR) {
    clrulink (name);
    mkdir (name);
    dpt->setres (name);
  }
}

void
afsusrdir::mkfh (nfs_fh *fhp)
{
  if (root == parent)		// For lookup ("..")
    root->mkfh (fhp);
  else
    afsdir::mkfh (fhp);
}

void
afsusrdir::mkfattr3 (fattr3 *f, sfs_aid rqaid)
{
  if (root == parent)
    root->mkfattr3 (f, rqaid);
  else {
    afsdir::mkfattr3 (f, rqaid);
    f->mode = 0755;
    f->uid = aid;
    f->gid = aid >> 32;
    f->gid = f->gid ? f->gid - 1 + sfs_resvgid_start : sfs_gid;
  }
}

void
afsusrdir::nfs3_access (svccb *sbp)
{
  if (!chkaid (sbp))
    return;

  access3res res (NFS3_OK);
  mkpoattr (res.resok->obj_attributes, sbp2aid (sbp));
  res.resok->access = ACCESS3_READ | ACCESS3_LOOKUP | ACCESS3_EXECUTE
    | ACCESS3_DELETE | ACCESS3_EXTEND | ACCESS3_MODIFY;
  res.resok->access &= sbp->Xtmpl getarg<access3args> ()->access;
  sbp->reply (&res);
}

void
afsusrdir::nfs_remove (svccb *sbp)
{
  if (!chkaid (sbp))
    return;

  str name = sbp->vers () == 2 ?
    str (sbp->Xtmpl getarg<diropargs> ()->name)
    : str (sbp->Xtmpl getarg<diropargs3> ()->name);
  if (!entries[name])
    nfs_error (sbp, NFSERR_NOENT);
  else if (!nameok (name) && !sfs_parsepath (name))
    nfs_error (sbp, NFSERR_ACCES);
  else {
    clrulink (name);
    if (sbp->vers () == 2)
      sbp->replyref (NFS_OK);
    else
      sbp->replyref (wccstat3 (NFS3_OK));
  }
}

void
afsusrdir::nfs_mkdir (svccb *sbp)
{
  str name = sbp->vers () == 2 ?
    str (sbp->Xtmpl getarg<createargs> ()->where.name)
    : str (sbp->Xtmpl getarg<mkdir3args> ()->where.name);

  if (entries[name]) {
    nfs_error (sbp, NFSERR_EXIST);
    return;
  }
  if (!nameok (name)) {
    nfs_error (sbp, nfsstat (NFSERR_ACCES));
    return;
  }

  clrulink (name);
  ptr<afsnode> e = mkdir (name);
  dirop_reply (sbp, e);
}

void
afsusrdir::nfs_symlink (svccb *sbp)
{
  if (!chkaid (sbp))		// XXX - redundant (handled by afsroot)
    return;
  str name, contents;
  if (sbp->vers () == 2) {
    symlinkargs *argp = sbp->Xtmpl getarg<symlinkargs> ();
    name = argp->from.name;
    contents = argp->to;
  }
  else {
    symlink3args *argp = sbp->Xtmpl getarg<symlink3args> ();
    name = argp->where.name;
    contents = argp->symlink.symlink_data;
  }

  afsnode *e = afsdir::lookup (name, aid);
  if (e && e->type != NF3LNK)
    nfs_error (sbp, NFSERR_EXIST);
  if (mkulink (contents, name))
    dirop_reply (sbp, afsdir::lookup (name, aid));
  else
    nfs_error (sbp, NFSERR_ACCES);
}

bool
afsusrdir::mkulink (const str &path, const str &name)
{
  if (!nameok (name))
    return false;
  unlink (name);
  if (path && path.len ()) {
    negcache.remove (name);
    if (nentries < maxulinks)
      symlink (path, name);
    else {
      // XXX - what to do?
      warn ("afsusrdir: maxulinks exceeded\n");
      return false;
    }
  }
  else {
    if (negcache.size () >= maxulinks)
      // XXX - this is kind of low-tech
      negcache.clear ();
    negcache.insert (name);
  }
  return true;
}

void
afsusrdir::clrulink (const str &name)
{
  negcache.remove (name);
  unlink (name);
  bumpmtime ();
}

ptr<afsdir>
afsusrdir::mkdir (const str &name)
{
  ref<afsdir> d (alloc (root, aid, this,
			path ? str (path << "/" << name) : name));
  if (!link (d, name))
    return NULL;
  addlink ();
  return d;
}

ptr<afsdir>
afsusrdir::mkctdir (const str &name)
{
  ref<afsdir> d = New refcounted<ctdir> (this);
  if (!link (d, name))
    return NULL;
  addlink ();
  return d;
}

afsnode *
afsusrroot::lookup (const str &name, sfs_aid rqaid)
{
  if (ptr<afsnode> r = revocation::lookup (name)) {
    afsnode *e = afsdir::lookup (name, rqaid);
    if (e != r) {
      if (e)
	unlink (name);
      link (r, name);
    }
    return r;
  }
  return super::lookup (name, rqaid);
}

void
afsusrroot::nfs_lookup (svccb *sbp, str name)
{
  afsnode *e = lookup (name, aid);
  if (e) {
    if (int err = srvinfo::geterr (name))
      nfs_error (sbp, err);
    else
      lookup_reply (sbp, e);
    return;
  }
  else if ((!sfs_parsepath (name)
	    && (!namedprotrx.match (name) /*|| !nptab[namedprotrx[1]]*/))
	   || terminating) {
    nfs_error (sbp, ENOENT);
    return;
  }

  ref<delaypt> dpt = delaypt::alloc ();
  ref<setupstate> ss = New refcounted<setupstate> (name, dpt);
  link (dpt, name);

  if (ptr<aclnt> ch = agentc ())
    ch->timedcall (agent_timeout, AGENTCB_REVOKED, &name, &ss->revres,
		   wrap (mkref (this), &afsusrroot::revcb, ss));
  else {
    ss->revdone = true;
    finish (ss, NFS_OK);
  }

  lookup_reply (sbp, afsdir::lookup (name, aid));
}

void
afsusrroot::revcb (ref<setupstate> ss, clnt_stat err)
{
  static ptr<afslink> revokedlink;
  if (!revokedlink)
    revokedlink = afslink::alloc (":REVOKED:");

  ss->revdone = true;
  if (err == RPC_PROCUNAVAIL)
    err = RPC_SUCCESS;
  if (err) {
    finish (ss, NFSERR_IO);
    return;
  }

  switch (ss->revres.type) {
  case REVOCATION_NONE:
    finish (ss, NFS_OK);
    break;
  default:
    /* case REVOCATION_BLOCK: */
    unlink (ss->name);
    link (revokedlink, ss->name);
    finish (ss, NFSERR_NOENT);
    break;
  case REVOCATION_CERT:
    unlink (ss->name);
    if (ptr<afsnode> e = revocation::alloc (*ss->revres.cert))
      link (e, ss->name);
    else
      link (revokedlink, ss->name);
    finish (ss, NFSERR_NOENT);
    break;
  }
}

static void
afsdir_unlink (ref<afsdir> d, str name)
{
  d->unlink (name);
}
void
afsusrroot::finish (ref<setupstate> ss, int err)
{
  if (!ss->dpt)
    return;
  if (!err)
    err = srvinfo::geterr (ss->name);
  if (err) {
    ss->dpt->setres (nfsstat (err));
    ss->dpt = NULL;
    delaycb (15, wrap (afsdir_unlink, mkref (this), ss->name));
    return;
  }
  if (!ss->revdone)
    return;

  afsnode *e = lookup (ss->name, NULL);
  if (!e || e == ss->dpt)
    e = afs_sfsroot->lookup (ss->name, NULL);

  if (e) {
    str name = ss->name;
    unlink (name);
    link (e, name);
#if FIX_MNTPOINT
    if (opt_fix_mntpoint) {
      if (str res = e->readlink ())
	ss->dpt->setres (res);
      else {
	warn << "afsusrroot::finish: shouldn't get here (please report bug)\n";
	ss->dpt->setres (strbuf ("%s/%s", sfsroot, ss->name.cstr ()));
	ss->dpt->setres (strbuf ("%s/" MPDOT "%s/r", sfsroot,
				 ss->name.cstr ()));
      }
    }
    else
#endif /* FIX_MNTPOINT */
      ss->dpt->setres (strbuf ("%s/%s", sfsroot, ss->name.cstr ()));
  }
  else
    srvinfo::alloc (ss->name, wrap (mkref (this), &afsusrroot::finish, ss));
}

ref<afsdir> ctldiralloc (afsdir *p, sfs_aid aid);
ref<afsusrroot>
afsusrroot::alloc  (afsroot *r, sfs_aid aid, afsdir *p, str pn)
{
  ref<afsusrroot> root (New refcounted<afsusrroot> (r, aid, p ? p : r, pn));
  if (aid != sfsaid_nobody) {
    root->link (afsaidfile::alloc (aid, strbuf () << aid << "\n"), ".aid");
    //root->link (ctldiralloc (root, aid), ".ctl");
  }
  return root;
}

void
afsaidfile::nfs_getattr (svccb *sbp)
{
  const sfs_aid aid = sbp2aid (sbp);
  if (aid != owner)
    nfs_error (sbp, NFSERR_STALE);
  else
    afsnode::nfs_getattr (sbp);
}

void
afsaidfile::nfs3_access (svccb *sbp)
{
  const sfs_aid aid = sbp2aid (sbp);
  if (aid != owner)
    nfs_error (sbp, NFSERR_STALE);
  else
    afsnode::nfs3_access (sbp);
}

void
afsrootfile::mkfattr3 (fattr3 *f, sfs_aid aid)
{
  afsreg::mkfattr3 (f, aid);
  f->mode = 0400;
  f->uid = 0;
}

void
afsrootfile::nfs3_access (svccb *sbp)
{
  access3res res (NFS3_OK);
  mkpoattr (res.resok->obj_attributes, sbp2aid (sbp));
  const authunix_parms *aup = sbp->getaup ();
  if (!aup || aup->aup_uid)
    res.resok->access = 0;
  else
    res.resok->access = (ACCESS3_READ
			 & sbp->Xtmpl getarg<access3args> ()->access);
  sbp->reply (&res);
}

