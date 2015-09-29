// -*-c++-*-
/* $Id: authdb_db.h,v 1.27 2004/09/19 22:02:27 dm Exp $ */

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

#ifdef SLEEPYCAT

#include "db.h"

#if DB_VERSION_MAJOR < 4
#undef SLEEPYCAT
#elif DB_VERSION_MAJOR == 4 && DB_VERSION_MINOR < 1
#undef SLEEPYCAT
#endif /* DB >= 4.0 < 4.1 */

#endif /* SLEEPYCAT */

#ifdef SLEEPYCAT

struct db_t : DBT {
private:
  db_t (const db_t &);
  db_t operator= (const db_t &);
  void zero () { bzero (implicit_cast<DBT *> (this), sizeof (DBT)); }

public:
  db_t () { zero (); }
  db_t (const str &s) { zero (); putstr (s); }
  db_t &operator= (const str &s) { putstr (s); return *this; }
  template<class T> explicit db_t (const T &t) {
    zero ();
    if (!putxdr (t))
      panic ("failed to marshal %s\n", rpc_type2str<T>::type ());
  }
  template<class T> db_t &operator= (const T &t) {
    if (!putxdr (t))
      panic ("failed to marshal %s\n", rpc_type2str<T>::type ());
    return *this;
  }
  ~db_t () { alloc (0); }

  void alloc (size_t nsize) {
    if (!(flags & DB_DBT_REALLOC))
      data = NULL;
    if (nsize) {
      data = xrealloc (data, nsize);
      flags |= DB_DBT_REALLOC;
    }
    else if (data) {
      xfree (data);
      data = NULL;
      flags &= ~DB_DBT_REALLOC;
    }
    size = nsize;
  }

  template<class T> bool putxdr (const T &t) {
    xdrsuio x (XDR_ENCODE);
    XDR *xp = &x;
    if (!rpc_traverse (xp, const_cast<T &> (t)))
      return false;
    alloc (size = x.uio ()->resid ());
    x.uio ()->copyout (data);
    return true;
  }
  template<class T> bool getxdr (T *tp) const {
    xdrmem x (static_cast<char *> (data), size);
    XDR *xp = &x;
    return rpc_traverse (xp, *tp);
  }

  // N.B.:  Strings have trailing nul byte in database!
  void setstr (const str &s) {
    alloc (0);
    data = const_cast<char *> (s.cstr ());
    size = s.len () + 1;
  }
  void putstr (const str &s) {
    alloc (s.len () + 1);
    memcpy (data, s.cstr (), s.len () + 1);
  }
  str getstr () const {
    const char *buf = static_cast<char *> (data);
    u_int32_t len = size;
    if (len && !buf[len-1])
      len--;
    return str (buf, len);
  }
};

inline bool
operator== (const db_t &a, const db_t &b)
{
  return a.size == b.size && !memcmp (a.data, b.data, a.size);
}

inline bool
operator!= (const db_t &a, const db_t &b)
{
  return a.size != b.size || memcmp (a.data, b.data, a.size);
}

inline int
cmp (const db_t &a, const db_t &b)
{
  if (int r = memcmp (a.data, b.data, min (a.size, b.size)))
    return r;
  if (a.size < b.size)
    return -1;
  return a.size != b.size;
}

/* XXX - GCC BUG: explicit constructors busted in 2.95.3, so need this */
inline bool
operator!= (const hash_t &a, const hash_t &b)
{
  return static_cast<u_int> (a) != static_cast<u_int> (b);
}


struct dbenv_t : public virtual refcount {
  DB_ENV *e;
  const str dbenvdir;
  ihash_entry<dbenv_t> hlink;
  bool txn;
  bool error;

protected:
  mode_t dbmode;
  int recovlockfd;
  bool opened;

  int fbstate;
  int fbpct;
  time_t fbstart;
  time_t fblast;

  dbenv_t (str p);
  ~dbenv_t ();

  bool mkdir ();
  bool recovlock (int flags = LOCK_SH);
  bool open (int flags);
  void close ();
  static void seterr (DB_ENV *ee, int errval);
  static void feedbk (DB_ENV *ee, int opcode, int pct);

public:
  static str mkdbpath (str path, str dbenvdir);
  str mkdbpath (str path) { return mkdbpath (path, dbenvdir); }
  static ptr<dbenv_t> alloc (str path, u_int32_t flags);
};

struct dbset {
  const str path;
  mode_t perm;
  u_int32_t flags;

  str dbenvdir;
  ptr<dbenv_t> dbenv;

  DB *dbrec;			// All records, indexed by TYPE:name
  DB *pkmap;			// Pubkey -> USER:name
  DB *u2gmap;			// all user->group pairs from GROUP: records
  DB *uidmap;			// numeric UID -> USER:name
  DB *gidmap;			// numerig GID -> GROUP:name
  DB *delta;			// dbrev -> key

  virtual str envdir () { return NULL; }
  virtual str dbfile (const char *subdb) { return path; }
  virtual str dbname (const char *subdb) { return subdb; }

protected:
  struct okvec_t { str path; int fd; };
  vec<okvec_t> okvec;

  bool envinit (u_int32_t envflags);
  bool doopen (DB_TXN *tid);

public:
  dbset (const char *p);
  virtual ~dbset ();
  bool mktxn (DB_TXN **out, u_int32_t fl = 0, DB_TXN *parent = NULL);
  virtual bool open (int perm, u_int32_t flags, u_int32_t envflags = 0);
  void close ();
  virtual bool truncate (DB_TXN *tid);
  virtual bool sync ();
  virtual bool ok ();
};

struct dbset_txn : dbset {
  dbset_txn (const char *p) : dbset (p) {}
  //virtual str envdir () { return strbuf () << sfsdir << "/dbenv"; }
};

struct dbset_dir : dbset {
  dbset_dir (const char *p) : dbset (p) {}
  virtual str envdir () { return path; }
  virtual str dbfile (const char *subdb) {
    if (flags & DB_AUTO_COMMIT)
      return strbuf ("%s.db", subdb);
    return strbuf () << path
		     << ((path.len () && path[path.len () - 1] != '/')
			 ? "/" : "")
		     << subdb << ".db";
  }
  virtual str dbname (const char *subdb) { return NULL; }
};

struct dbset_mem : dbset {
  dbset_mem () : dbset ("(tempDB)") {}
  virtual str envdir () { return NULL; }
  virtual str dbfile (const char *subdb) { return NULL; }
  virtual str dbname (const char *subdb) { return NULL; }
  bool open (int perm, u_int32_t flags, u_int32_t envflags);
  bool truncate (DB_TXN *tid) { return true; }
  bool sync () { return true; }
  bool ok () { return true; }
};


class authcursor_db : public authcursor {
protected:
  ref<dbset> dbs;
  ptr<audblock> lf;
  u_int txncnt;
  bool error;
  bool trunc;
  bool async;

  DB_TXN *tid;
  DBC *dbc;

  bool getkey (dbrec_rev *res, str aek);
  // Lookup by primary key:
  bool getprikey (const char *type, str k)
    { init (); return getkey (&ae, strbuf ("%s:", type) << k); }
  // Lookup in secondary index:
  bool getseckey (DB *map, const db_t &k, bool exact = true);
  template<class T> bool getseckey (DB *map, const T &k, bool exact = true) {
    db_t kk (k);
    return getseckey (map, kk, exact);
  }

  u_int64_t update_rev (str aek, u_int64_t oldrev);
  bool update_key (str aek, dbrec_rev *val);
  bool update_map (DB *map, db_t *okey, db_t *nkey, str aek,
		   const char *mapname);
  bool update_members (DB *map, sfs_groupmembers *oms, sfs_groupmembers *nms,
		       str aek, const char *mapname);
  bool update_user ();
  bool update_group ();
  bool update_cacheentry ();
  bool findid (u_int32_t *res, DBC *c, u_int32_t min, u_int32_t max);

  bool flushtxn ();
  virtual bool init (bool write = false);
  virtual bool complete ();
  void abort ();

public:
  authcursor_db (ref<dbset> dbs, ptr<audblock> lf,
		 bool trunc = false, bool async = false);
  ~authcursor_db ();

  void reset ();
  bool next (bool *pep = NULL);
  bool next_rev () { return next (); }
  bool update ();
  bool commit (size_t = 0);

  virtual bool remove (str aek); // internal use only
  bool revinfo (sfsauth_revinfo *rip);

  bool find_user_name (str name) { return getprikey ("USER", name); }
  bool find_user_pubkey (const sfspub &pk);
  bool find_user_uid (u_int32_t uid);
  bool find_group_name (str name) { return getprikey ("GROUP", name); }
  bool find_group_gid (u_int32_t gid);
  bool find_cache_key (str key) { return getprikey ("CACHE", key); }
  bool find_rev (u_int64_t dbrev);

  void find_groups_member (vec<str> *groups, str member);
  void find_gids_user (vec<u_int32_t> *gids, str user);
  u_int count_group_prefix (str pref);
  u_int32_t alloc_gid (u_int32_t min, u_int32_t max);
};

class authcursor_db_trunc : public authcursor_db {
protected:
  ref<dbset> target;
  bool retargeted;
  authcursor_db_trunc (ref<dbset> dbs, ref<audblock> lf, ref<dbset> target);
  ~authcursor_db_trunc ();
public:
  bool update ();
  bool commit (size_t tot);
  static ptr<authcursor_db_trunc> alloc (ref<dbset> targetdbs, ref<audblock>);
};

class authcursor_db_rename : public authcursor_db {
protected:
  str target;
  bool renamed;

  authcursor_db_rename (ref<dbset> dbs, ref<audblock> lf, str target);
  ~authcursor_db_rename ();
  void clean ();
  bool rename ();
public:
  bool commit (size_t tot);
  static ptr<authcursor_db_trunc> alloc (ref<dbset> targetdbs, ref<audblock>);
};

str abspath (const char *p);

class authdb_db : public authdb {
protected:
  ptr<dbset> dbs;
  ptr<lockfile> lf;
public:
  virtual ~authdb_db () {}
  virtual str lockpath () { return NULL; }
  virtual ptr<dbset> getdbs (bool tmpname = false) = 0;
  ptr<authcursor> open (u_int flags, mode_t perm, ptr<audblock> lf);
  ptr<audblock> lock (bool wait);
  bool revinfo (sfsauth_revinfo *rip);
};

class authdb_txn : public authdb_db {
  str path;
public:
  authdb_txn (str p) { path = p; }
  str lockpath ();
  ptr<dbset> getdbs (bool tmpname = false);
};

class authdb_dir : public authdb_db {
  str path;
public:
  authdb_dir (str p) { path = p; }
  str lockpath () { return path << "/lock"; }
  ptr<dbset> getdbs (bool tmpname = false);
};

#endif /* SLEEPYCAT */
