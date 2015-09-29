// -*-c++-*-
/* $Id: authdb.h,v 1.50 2004/06/17 21:10:23 dm Exp $ */

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

#ifndef _SFSAUTHD_AUTHDB_H_
#define _SFSAUTHD_AUTHDB_H_ 1

#include "sfscrypt.h"
#include "amisc.h"
#include "authdb_types.h"
#include "qhash.h"

const u_int32_t badid = (u_int32_t) -1;

struct authdb;

struct audblock {
  virtual bool ok () { return true; }
  virtual ~audblock () {}
};

struct audblock_file : public audblock {
  const ref<lockfile> lf;
  audblock_file (ref<lockfile> l) : lf (l) {}
  ~audblock_file () { lf->release (); }
  bool ok () { return lf->ok (); }
};

struct dbrec_rev : public sfsauth_dbrec {
  u_int64_t dbrev;
  explicit dbrec_rev (sfsauth_dbtype t = SFSAUTH_ERROR)
    : sfsauth_dbrec (t), dbrev (0) {}
  dbrec_rev &operator= (const sfsauth_dbrec &dbr)
    { *implicit_cast<sfsauth_dbrec *> (this) = dbr; return *this; }
};
bool rpc_traverse (XDR *xdrs, dbrec_rev &obj);

struct authcursor {
  dbrec_rev ae;
  ptr<sfspub> pubkey;

  authcursor () {}
  virtual ~authcursor () {}
  virtual void reset () = 0;
  virtual bool next (bool *pep = NULL) = 0;
  virtual bool next_rev () { return next (); }
  virtual bool validate ();
  virtual bool update () { return false; }
  virtual bool commit (size_t tot = 0) { return true; }

  virtual bool find_user_name (str name);
  virtual bool find_user_pubkey (const sfspub &pk);
  virtual bool find_user_uid (u_int32_t uid);
  virtual bool find_group_name (str name);
  virtual bool find_group_gid (u_int32_t gid);
  virtual bool find_cache_key (str key);
  virtual bool find_rev (u_int64_t dbrev);

  // N.B. result vectors are not cleared--values are appended
  virtual void find_groups_member (vec<str> *groups, str member);
  virtual void find_gids_user (vec<u_int32_t> *gids, str user);
  virtual u_int count_group_prefix (str pref);
  virtual u_int32_t alloc_gid (u_int32_t min, u_int32_t max);
};

struct authcursor_null : authcursor {
  void reset () {}
  bool next (bool *pep) { return false; }
};

struct authcursor_file : public authcursor {
  const str path;
  ptr<audblock> lf;
  mode_t perm;
  size_t linemax;
  int fd;
  suio buf;
  int lineno;
  bool error;

  authcursor_file (str p, mode_t pm, ptr<audblock> l, int fd = -1);
  ~authcursor_file ();
  void reset ();
  bool next (bool *pep = NULL);
  bool update ();
  bool commit (size_t = 0) { return !error; }
};

class authcursor_file_append : public authcursor {
  const ref<audblock> lf;
  const str path;
  int wfd;
  suio buf;
  bhash<str> keys;

protected:
  authcursor_file_append (const ref<audblock> l, str p, int wfd)
    : lf (l), path (p), wfd (wfd) { assert (wfd >= 0); }
  ~authcursor_file_append ();

public:
  void reset () { close (wfd); wfd = -1; }
  bool next (bool *pep = NULL) { return false; }
  bool update ();
  bool commit (size_t = 0);
  static ptr<authcursor_file_append> alloc (str path, mode_t perm,
					    ref<audblock> lf);
};

struct authdb {
  enum {
    AUDB_WRITE = 0x1,	      // Open for writing (must set for other flags)
    AUDB_CREATE = 0x2,	      // Create file if it doesn't exist
    AUDB_TRUNC = 0x4,	      // Truncate database to zero length
    AUDB_WAIT = 0x8,	      // Wait for dababase if locked
    AUDB_NORECOV = 0x10,      // Don't protect DB against crashes
    AUDB_RUNRECOV = 0x20,     // Attempt to recover corrupted database
    AUDB_ASYNC = 0x40,	      // Updates maybe delayed, maybe reverted
  };

  virtual ~authdb () {}
  virtual ptr<authcursor> open (u_int flags, mode_t perm = 0600,
				ptr<audblock> lf = NULL) = 0;
  virtual ptr<audblock> lock (bool wait) { return NULL; }
  virtual bool revinfo (sfsauth_revinfo *rip)
    { rpc_clear (*rip); return true; }
};

struct authdb_etc_group : public authdb {
  ptr<authcursor> open (u_int flags, mode_t perm, ptr<audblock> lf);
};

class authdb_file : public authdb {
  bool locked;
  str path;
public:
  authdb_file (str path) : locked (false), path (path) {}
  ptr<authcursor> open (u_int flags, mode_t perm, ptr<audblock> lf);
  ptr<audblock> lock (bool wait);
};

ptr<authdb> authdb_db_alloc (str path);
ptr<authdb> authdb_alloc (str path, str finalpath = NULL);

str authdbrec2str (const sfsauth_dbrec *dbr);
bool str2authdbrec (sfsauth_dbrec *dbr, str s);
str single_char_sub (const str &in, const char find, const str &repl);

str aekey (const sfsauth_dbrec &ae);
// level arguments for aesanitize
enum {
  AE_QUERY = 1,			// Unauthenticated remote query
  AE_PUBFILE = 2,		// Info for sfs_users.pub file
  AE_USER = 3,		        // Info returned to SRP-authenticated user
};
void aesanitize (sfsauth_dbrec *aep, int level);

inline bool
isuser (const str s)
{
  return s.len () >= 2 && s[0] == 'u' && s[1] == '=';
}

inline bool
isgroup (const str s)
{
  return s.len () >= 2 && s[0] == 'g' && s[1] == '=';
}

inline bool
ispkhash (const str s)
{
  return s.len () >= 2 && s[0] == 'p' && s[1] == '=';
}

inline bool
isremote (const str s)
{
  // XXX: check for proper format: user@hostname,HOSTID
  return strchr (s, '@') && strchr (s, ',');
}

inline str
add_member_type (const str s, const str t)
{
  return strbuf () << t << "=" << s;
}

inline str
rem_member_type (const str s)
{
  return substr (s, 2);
}

#endif /* !_SFSAUTHD_AUTHDB_H_ */
