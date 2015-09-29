/* $Id: authdb.C,v 1.69 2004/06/17 21:10:23 dm Exp $ */

/*
 *
 * Copyright (C) 2001-2003 David Mazieres (dm@uun.org)
 * Copyright (C) 2003 Michael Kaminsky (kaminsky@lcs.mit.edu)
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

#include "authdb.h"
#include "qhash.h"
#include "rxx.h"
#include <grp.h>

bool
rpc_traverse (XDR *xdrs, dbrec_rev &obj)
{
  return rpc_traverse (xdrs, implicit_cast<sfsauth_dbrec &> (obj));
#if 0
  if (!rpc_traverse (xdrs, implicit_cast<sfsauth_dbrec &> (obj)))
    return false;
  if (rpc_traverse (xdrs, obj.dbrev))
    return true;
  if (xdrs->x_op != XDR_DECODE)
    return false;
  obj.dbrev = 0;
  return true;
#endif
}

str
aekey (const sfsauth_dbrec &ae)
{
  switch (ae.type) {
  case SFSAUTH_USER:
    return strbuf () << "USER:" << ae.userinfo->name;
  case SFSAUTH_GROUP:
    return strbuf () << "GROUP:" << ae.groupinfo->name;
  case SFSAUTH_CACHEENTRY:
    return strbuf () << "CACHE:" << ae.cacheentry->key;
  default:
    {
      static rxx knrx ("^[^:]*:[^:]*");
      str astr = authdbrec2str (&ae);
      if (!astr)
	return NULL;
      if (!knrx.search (astr))
	panic << "missing colon: " << astr << "\n";
      return knrx[0];
    }
  }
}

void
aesanitize (sfsauth_dbrec *aep, int level)
{
  switch (aep->type) {
  case SFSAUTH_USER:
    aep->userinfo->pwauth = "";
    if (aep->userinfo->srvprivkey.type != SFSAUTH_KEYHALF_NONE)
      aep->userinfo->srvprivkey.set_type (SFSAUTH_KEYHALF_FLAG);
    if (level < AE_USER)
      aep->userinfo->privkey.setsize (0);
    break;
  default:
    break;
  }
}


#define SEARCH(compare)				\
  reset ();					\
  while (next ())				\
    if (compare)				\
      return true;				\
  return false;

#define COUNT(compare)				\
  unsigned int i = 0;				\
  reset ();					\
  while (next ())				\
    if (compare)				\
      i++;					\
  return i;

bool 
authcursor::validate ()
{
  bool pe = false, ret = true, flag = true;
  reset ();
  while (flag) {
    flag = next (&pe);
    if (pe)
      ret = false;
  }
  return ret;
}

bool
authcursor::find_user_name (str name)
{
  SEARCH (ae.type == SFSAUTH_USER && ae.userinfo->name == name);
}

bool
authcursor::find_user_pubkey (const sfspub &pk)
{
  SEARCH (ae.type == SFSAUTH_USER && 
	  (pk == ae.userinfo->pubkey || pk == ae.userinfo->srvprivkey));
}

bool
authcursor::find_user_uid (u_int32_t id)
{
  SEARCH (ae.type == SFSAUTH_USER && ae.userinfo->id == id);
}

bool
authcursor::find_group_name (str name)
{
  SEARCH (ae.type == SFSAUTH_GROUP && ae.groupinfo->name == name);
}

bool
authcursor::find_group_gid (u_int32_t id)
{
  SEARCH (ae.type == SFSAUTH_GROUP && ae.groupinfo->id == id);
}

bool
authcursor::find_cache_key (str key)
{
  SEARCH (ae.type == SFSAUTH_CACHEENTRY && ae.cacheentry->key == key);
}

bool
authcursor::find_rev (u_int64_t dbrev)
{
  if (dbrev)
    return false;
  reset ();
  return next_rev ();
}

void
authcursor::find_groups_member (vec<str> *groups, str member)
{
  for (reset (); next ();)
    if (ae.type == SFSAUTH_GROUP)
      for (sfs_groupmember *gmp = ae.groupinfo->members.base ();
	   gmp < ae.groupinfo->members.lim (); gmp++)
	if (*gmp == member) {
	  groups->push_back (ae.groupinfo->name);
	  break;
	}
}

void
authcursor::find_gids_user (vec<u_int32_t> *gids, str user)
{
  user = strbuf () << "u=" << user;
  for (reset (); next ();)
    if (ae.type == SFSAUTH_GROUP)
      for (sfs_groupmember *gmp = ae.groupinfo->members.base ();
	   gmp < ae.groupinfo->members.lim (); gmp++)
	if (*gmp == user) {
	  gids->push_back (ae.groupinfo->id);
	  break;
	}
}

u_int
authcursor::count_group_prefix (str pref)
{
  COUNT (ae.type == SFSAUTH_GROUP
	 && !strncmp (ae.groupinfo->name, pref, pref.len ()));
}


u_int32_t
authcursor::alloc_gid (u_int32_t min, u_int32_t max)
{
  u_int32_t gid = min;
  while (find_group_gid (gid))
    if (++gid > max)
      return badid;
  return gid;
}

struct authcursor_etc_group : public authcursor {
  static authcursor_etc_group *lastcursor;

  int min_getgrent;	     // to avoid loops if duplicates in /etc/group

  authcursor_etc_group () : min_getgrent (0) {}
  ~authcursor_etc_group () 
  { if (lastcursor == this) lastcursor = NULL; endgrent (); }

  bool setae (struct group *gr);
  void reset () { ae.set_type (SFSAUTH_ERROR); }
  bool next (bool *pep = NULL);

  bool find_user_name (str name) { return false; }
  bool find_user_pubkey (const sfspub &pk) { return false; }
  bool find_user_uid (u_int32_t uid) { return false; }

  bool find_group_name (str name)
    { min_getgrent = 0; return setae (getgrnam (name)); }
  bool find_group_gid (u_int32_t gid)
    { min_getgrent = 0; return setae (getgrgid (gid)); }
};

authcursor_etc_group *authcursor_etc_group::lastcursor;

bool
authcursor_etc_group::setae (struct group *gr)
{
  lastcursor = this;
  if (!gr) {
    ae.set_type (SFSAUTH_ERROR);
    return false;
  }
  ae.set_type (SFSAUTH_GROUP);
  ae.groupinfo->name = gr->gr_name;
  ae.groupinfo->id = gr->gr_gid;
  ae.groupinfo->vers = 0;
  ae.groupinfo->owners.setsize (0);
  // ae.groupinfo->refresh = 3600;
  // ae.groupinfo->timeout = 604800;
  ae.groupinfo->audit = "";

  int i;
  for (i = 0; gr->gr_mem[i]; i++)
    ;
  ae.groupinfo->members.setsize (i);
  while (i-- > 0)
    ae.groupinfo->members[i] = add_member_type (gr->gr_mem[i], "u");
  return true;
}

bool
authcursor_etc_group::next (bool *pep)
{
  if (ae.type != SFSAUTH_GROUP) {
    min_getgrent = 0;
    setgrent ();
  }
  else if (lastcursor != this) {
    //struct group *gp;
    setgrent ();
    for (int i = 0; i < min_getgrent; i++)
      getgrent ();
#if 0
    do {
      gp = getgrent ();
      //warn << ae.groupinfo->name << " =? " << gp->gr_name << "\n";
      if (!gp) {
	if (pep)
	  *pep = true;
	return false;
      }
    } while (ae.groupinfo->name != gp->gr_name);
#endif
  }
  min_getgrent++;
  return setae (getgrent ());
}

ptr<authcursor>
authdb_etc_group::open (u_int flags, mode_t perm, ptr<audblock>)
{
  if (flags & AUDB_WRITE)
    return NULL;
  return New refcounted<authcursor_etc_group> ();
}

authcursor_file_append::~authcursor_file_append ()
{
  str tmppath = path << ".tmp";
  if (wfd >= 0) {
    close (wfd);
    if (lf->ok ())
      unlink (tmppath);
  }
}

ptr<authcursor_file_append>
authcursor_file_append::alloc (str path, mode_t perm, ref<audblock> lf)
{
  str tmppath = path << ".tmp";
  int fd = open (tmppath, O_CREAT|O_WRONLY|O_TRUNC, perm);
  if (fd < 0) {
    warn << tmppath << ": " << strerror (errno) << "\n";
    return NULL;
  }
  return New refcounted<authcursor_file_append> (lf, path, fd);
}

bool
authcursor_file_append::update ()
{
  if (wfd < 0)
    return false;
  str astr = authdbrec2str (&ae);
  if (!astr)
    return false;
  str k = aekey (ae);
  if (keys[k]) {
    warn << "duplicate: " << astr << "\n";
    return false;
  }
  keys.insert (k);
  suio_print (&buf, astr);
  buf.print ("\n", 1);
  if (buf.resid () >= 8192)
    buf.output (wfd);
  return true;
}

bool
authcursor_file_append::commit (size_t tot)
{
  if (wfd < 0)
    return false;
  if (buf.resid () && buf.output (wfd) <= 0
      || fsync (wfd) < 0) {
    warn ("authcursor_file_append::commit: %s: %m\n", path.cstr ());
    return false;
  }
  assert (!buf.resid ());
  close (wfd);
  wfd = -1;
  str tmppath = path << ".tmp";
  if (lf->ok ()) {
    if (rename (tmppath, path) < 0) {
      warn ("authcursor_file_append::commit: %s: rename: %m\n",
	    tmppath.cstr ());
      unlink (tmppath);
      return false;
    }
    if (tot)
      warnx (" done \n");
    return true;
  }
  else {
    warn ("authcursor_file_append::commit: %s: lost the lock\n",
	  path.cstr ());
    unlink (tmppath);
    return false;
  }
}

authcursor_file::authcursor_file (str p, mode_t pm, ptr<audblock> l, int f)
    : path (p), lf (l), perm (pm), linemax (0x20000),
      fd (f), lineno (1), error (false)
{
  if (fd < 0)
    reset ();
}

authcursor_file::~authcursor_file ()
{
  close (fd);
}

void
authcursor_file::reset ()
{
  if (fd >= 0)
    close (fd);
  fd = open (path, O_RDONLY);
  if (fd < 0) {
    if (errno != ENOENT)
      warn ("%s: %m\n", path.cstr ());
  }
  else 
    lseek (fd, 0, SEEK_SET);
  buf.clear ();
  lineno = 1;
}

bool
authcursor_file::next (bool *pep)
{
  if (fd < 0)
    return false;
  bool flush = false;
  str line;
  for (;;) {
    while (!(line = suio_getline (&buf))) {
      if (linemax && buf.resid () > linemax) {
	buf.clear ();
	flush = true;
	continue;
      }
      int n = buf.input (fd);
      if (n > 0)
	continue;
      if (n < 0)
	warn << path << ": " << strerror (errno) << "\n";
      else if (buf.resid ()) {
	warn << path << ": " << lineno << ": incomplete last line\n";
	if (pep) *pep = true;
      }
      return false;
    }
    lineno++;
    if (flush) {
      warn << path << ": " << lineno-1 << ": line too long\n";
      if (pep) *pep = true;
    }
    else if (!str2authdbrec (&ae, line)) {
      warn << path << ": " << lineno-1 << ": syntax error\n";
      if (pep) *pep = true;
    } else
      return true;
  }
}

bool
authcursor_file::update ()
{
  if (error)
    return false;
  if (!lf) {
    error = true;
    return false;
  }
  ptr<authcursor_file_append> c
    = authcursor_file_append::alloc (path, perm, lf);
  if (!c) {
    error = true;
    return false;
  }
  dbrec_rev dbr = ae;
  str k = aekey (dbr);
  if (!k) {
    error = true;
    return false;
  }
  bool found = false;
  bool empty = true;
  for (reset (); next (&error);) {
    empty = false;
    str kk = aekey (ae);
    if (k == kk) {
      c->ae = dbr;
      found = true;
    } else
      c->ae = ae;
    if (!c->update ()) {
      error = true;
      return false;
    }
  }
  if (error)
    return false;
  if (!found) {
    c->ae = dbr;
    if (!c->update ()) {
      error = true;
      return false;
    }
  }
  if (!c->commit ()) {
    error = true;
    warn << path << ": " << strerror (errno) << "\n";
    return false;
  }
  return true;
}

ptr<audblock>
authdb_file::lock (bool wait)
{
  if (ptr<lockfile> l = lockfile::alloc (path << ".lock", wait))
    return New refcounted<audblock_file> (l);
  return NULL;
}

ptr<authcursor>
authdb_file::open (u_int flags, mode_t perm, ptr<audblock> lf)
{
  const bool writable = flags & AUDB_WRITE;
  const bool create = flags & AUDB_CREATE;
  const bool trunc = flags & AUDB_TRUNC;
  const bool wait = flags & AUDB_WAIT;
  //const bool norecov = flags & AUDB_NORECOV;

  if (writable && !lf && !(lf = lock (wait)))
    return NULL;
  if (access (path, 0) < 0 && errno == ENOENT) {
    if (!create)
      return NULL;
    if (writable) {
      int fd = ::open (path, O_CREAT|O_WRONLY, perm);
      close (fd);
    }
    else
      return New refcounted<authcursor_null> ();
  }
  if (writable && trunc)
    return authcursor_file_append::alloc (path, perm, lf);
  else
    return New refcounted<authcursor_file> (path, perm, lf);
}
