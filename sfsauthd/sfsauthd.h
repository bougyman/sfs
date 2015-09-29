// -*-c++-*-
/* $Id: sfsauthd.h,v 1.53 2004/05/19 18:02:49 dm Exp $ */

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

#ifndef _SFSAUTHD_SFSAUTHD_H
#define _SFSAUTHD_SFSAUTHD_H

#include "sfscrypt.h"
#include "sfsserv.h"
#include "sfsauth_prot.h"
#include "authdb.h"
#include "srp.h"
#include "parseopt.h"

struct dbfile;
struct authclnt;

typedef callback<void, sfsauth2_loginres *, sfs_authtype,
		 const sfsauth_dbrec *>::ref logincb_t;

class sprivk_tab_t {
public:
  sprivk_tab_t () : nentries (0) {}

  struct sprivk_t {
    sprivk_t () : refs (1), valid (true) {}
    int refs;
    bool valid;
  };

  bool is_valid (const str &hv);
  bool invalidate (const str &hv);
  void bind (const str &hv);
  void release (const str &hv, sprivk_t *s = NULL);

private:
  u_int nentries;
  qhash<str, sprivk_t> keys;
};

class authpending {
public:
  authclnt *const ac;
  const sfs_hash authid;
  const u_int64_t seqno;
  sfs_authtype atype;
  timecb_t *tmo;
  ihash_entry<authpending> hlink;

  authpending (authclnt *ac, const sfsauth2_loginarg *largp);
  virtual ~authpending ();
  void refresh () {
    timecb_remove (tmo);
    tmo = delaycb (300, wrap (this, &authpending::timeout));
  }
  void timeout () { tmo = NULL; delete this; }
  virtual void next (const sfs_autharg2 *argp, logincb_t cb) = 0;
};

class authpending_srp : public authpending {
  srp_server srp;
  dbfile *srp_dbp;
  ptr<authcursor> srp_ac;

public:
  authpending_srp (authclnt *ac, const sfsauth2_loginarg *argp)
    : authpending (ac, argp) {}
  void init (const sfs_autharg2 *argp, logincb_t cb);
  void next (const sfs_autharg2 *argp, logincb_t cb);
};

class authpending_helper : public authpending {
  ptr<asrv> srv;
  pid_t pid;
  logincb_t::ptr cb;
  str user;
  vec<str> pwds;
  svccb *getpassreq;

  void reap (int);
  void dispatch (svccb *sbp);

public:
  ptr<authcursor> ah_ac;

  authpending_helper (authclnt *ac, const sfsauth2_loginarg *argp)
    : authpending (ac, argp), pid (-1), getpassreq (NULL) {}
  ~authpending_helper ();
  
  void init (const sfs_autharg2 *argp, logincb_t cb);
  void next (const sfs_autharg2 *argp, logincb_t cb);
};

class authclnt : public sfsserv {
  rpc_ptr<u_int32_t> uid;
  const ref<asrv> authsrv;

  struct urec_t {
    urec_t (u_int32_t a, sfs_authtype t, const sfsauth_dbrec &dbr);
    ~urec_t ();

    u_int32_t authno;
    sfs_authtype authtype;
    sfsauth_keyhalf kh;
    sfs_idname uname;
    
    list_entry<urec_t> link;
    ihash_entry<urec_t> hlink;
  };

  void urecfree (urec_t *u);

  ihash<u_int32_t, authclnt::urec_t, &authclnt::urec_t::authno, 
	&authclnt::urec_t::hlink> utab;
  list<authclnt::urec_t, &authclnt::urec_t::link> ulist;

protected:
  ptr<aclnt> getauthclnt () { panic ("authclnt::getauthclnt called\n"); }
  ptr<sfspriv> doconnect (const sfs_connectarg *, sfs_servinfo *);
  void setuser_groups (sfsauth2_loginres *resp, const sfsauth_dbrec *ae,
                       const dbfile *dbp, ptr<sfspub> vrfy);
  static void findgroups_unix (vec<u_int32_t> *groups, str name);
  static void findgroups_symbolic (vec<str> *groups, str name,
                                   const u_int32_t *gidp, str pkhash);
  void dispatch (svccb *sbp);
  static void dispatch_2 (svccb *sbp, sfsauth2_loginres *resp,
			  sfs_authtype atype, const sfsauth_dbrec *dbrp)
    { sbp->reply (resp); }

  static bool authreq_validate (sfsauth2_loginres *resp,
				const sfsauth2_loginarg *lap,
				const sfs_authreq2 &areq,
				bool nocred_okay = false);

  str update_srv_keyhalf (const sfsauth_keyhalf &deltakh,
			  sfsauth_keyhalf &newkh,
			  const sfsauth_keyhalf &oldkh, 
			  bool oldsig, urec_t *ur);

  str siglogline (const sfsauth2_sign_arg &arg, const str &uname);
  bool is_authenticated (svccb *sbp);

public:
  ihash<const sfs_hash, authpending, &authpending::authid,
	&authpending::hlink> aptab;
  vec<sfsauth_dbrec> dbrtab;

  authclnt (ref<axprt_crypt> x, const authunix_parms *aup = NULL);
  ~authclnt ();
  u_int32_t client_release () {
    if (!cd)
      return SFS_RELEASE;
    else if (cd->ci.civers < 5)
      return cd->ci.civers;
    return cd->ci.ci5->release;
  }

  void sfs_login (svccb *sbp);
  void sfs_login_2 (svccb *sbp, sfsauth2_loginres *resp,
		    sfs_authtype atype, const sfsauth_dbrec *dbrp);
  void utab_insert (u_int32_t authno, sfs_authtype t, const sfsauth_dbrec &d);
  void sfs_logout (svccb *sbp);
  
  void sfsauth_login (const sfsauth2_loginarg *lap,
		      logincb_t cb, bool self = false);
  void sfsauth_login_2 (str source, logincb_t cb,
			sfsauth2_loginres *resp, sfs_authtype atype,
			const sfsauth_dbrec *dbrp);
  void login_sigauth (sfsauth2_loginres *resp,
		      const sfsauth2_loginarg *lap, const sfs_autharg2 *aap,
		      sfsauth_dbrec *dbp = NULL);
  void login_sigauth (const sfsauth2_loginarg *lap, const sfs_autharg2 *aap,
		      bool self, logincb_t cb);
  void login_srp (const sfsauth2_loginarg *lap, const sfs_autharg2 *aap,
		  bool self, logincb_t cb);
  void login_unixpw (const sfsauth2_loginarg *lap, const sfs_autharg2 *aap,
		     bool self, logincb_t cb);
  void login_unixpw_2 (ref<authcursor> ac, str user, str pwd,
		     bool self, logincb_t cb);
  static bool setuser (sfsauth2_loginres *resp, const sfsauth_dbrec &ae,
		       const dbfile *dbp);

  virtual void sfsauth_query (svccb *sbp);
  void query_user (svccb *sbp);
  void query_group (svccb *sbp);
  void query_certinfo (svccb *sbp);
  void query_srpparms (svccb *sbp);
  void query_expandedgroup (svccb *sbp);
  void query_changelog (svccb *sbp);

  virtual void sfsauth_update (svccb *sbp);
  virtual void sfsauth_sign (svccb *sbp);
};

struct idmap {
  virtual u_int32_t map (u_int32_t id) = 0;
  virtual u_int32_t unmap (u_int32_t id) = 0;
};
struct idmap_id : public idmap {
  u_int32_t map (u_int32_t id) { return id; }
  u_int32_t unmap (u_int32_t id) { return id; }
};
struct idmap_const : public idmap {
  const u_int32_t id;
  idmap_const (u_int32_t id) : id (id) {}
  u_int32_t map (u_int32_t) { return id; }
  u_int32_t unmap (u_int32_t) { return badid; }
};
struct idmap_range : public idmap {
  const u_int32_t id_min;
  const u_int32_t id_max;
  const u_int32_t id_offset;

  idmap_range (u_int32_t imin, u_int32_t imax, u_int32_t ioff)
    : id_min (imin), id_max (imax), id_offset (ioff) {
    assert (id_max >= id_min);
    assert (!id_max || !id_offset || id_max - 1 + id_offset > id_max);
  }
  u_int32_t map (u_int32_t id) {
    if (id < id_min || id >= id_max)
      return badid;
    return (id + id_offset);
  }
  u_int32_t unmap (u_int32_t mid) {
    if (mid < id_offset || mid >= id_offset + id_max)
      return badid;
    return mid - id_offset;
  }
};

class xfer : public virtual refcount {
  pid_t pid;

  void stop (int) { pid = -1; }
public:
  const str src;
  const str dst;

  xfer (str s, str d) : pid (-1), src (s), dst (d) {}
  void start ();
};

struct dbfile {
  ptr<authdb> db;
  int dbflags;
  str prefix;
  ptr<idmap> uidmap;
  ptr<idmap> gidmap;
  ptr<idmap_range> grprange;
  vec<str> pubfiles;
  u_int default_refresh;
  u_int default_timeout;
  int default_groupquota;
  bool allow_update;
  bool allow_unix_pwd;
  bool allow_admin;
  bool allow_userdir_shell;
  bool allow_create;
  bool hide_users;
  cbv::ptr refresh;
  dbfile ()
    : dbflags (0), default_refresh (3600),
      default_timeout (604800), default_groupquota (-1),
      allow_update (false), allow_unix_pwd (false),
      allow_admin (false), allow_userdir_shell (false),
      allow_create (false), hide_users (false) {}
  void mkpub ();
  str strip_prefix (str name);
};

#define USERDIR_HOMEDIR "/sfs/HOMEDIR";
#define USERDIR_SHELL   "/sfs/SHELL";

extern ptr<sfspriv> myprivkey;
extern sfs_servinfo myservinfo;
extern ptr<sfs_servinfo_w> siw;
extern sfs_hash myhostid;
extern vec<dbfile> dbfiles;
extern str sfsauthrealm;
extern vec<sfsauth_certpath> sfsauthcertpaths;
extern str logfile;
extern str srpparms;
extern str sfsauthcachedir;
extern str sfsauthdbcache;
extern int logfd;
extern str auth_helper;

bool siglog (const str &line);
str  siglog_startup_msg ();
void siglogv ();

bool get_user_cursor (dbfile **dbp, ptr<authcursor> *acp,
		      sfsauth_dbrec *dbrp, const sfsauth_dbkey &k,
    		      bool writable = false);
bool get_group_cursor (dbfile **dbp, ptr<authcursor> *acp,
                       sfsauth_dbrec *dbrp, const sfsauth_dbkey &k,
                       bool writable = false, bool create = false);

extern const str refresh_eq;
extern const str timeout_eq;

inline bool
extract_u_int (u_int32_t *value, const str &comma_name_equals, const str &s)
{
  const char *p;
  if (memcmp (s, comma_name_equals.cstr () + 1, comma_name_equals.len () - 1))
    p = s + comma_name_equals.len () - 1;
  else if (!(p = strstr (s, comma_name_equals)))
    return false;

  char *e;
  *value = strtoi64 (p + comma_name_equals.len () - 1, &e);
  return e != p && (*e == '\0' || *e == ',');
}

inline u_int32_t
extract_u_int_default (const str &comma_name_equals,
		       const str &s, u_int32_t def)
{
  u_int32_t ret;
  return extract_u_int (&ret, comma_name_equals, s) ? ret : def;
}

#endif /* _SFSAUTHD_SFSAUTHD_H */
