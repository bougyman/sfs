// -*-c++-*-
/* $Id: agent.h,v 1.33 2004/09/19 22:02:19 dm Exp $ */

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

#include "arpc.h"
#include "sfsmisc.h"
#include "sfsauth_prot.h"
#include "crypt.h"
#include "sfsagent.h"
#include "rxx.h"
#include "qhash.h"
#include "sfscrypt.h"

class rxfilter {
  rrxx filter;
  rrxx exclude;
public:
  rxfilter () {}
  rxfilter (const str &f, const str &e);
  bool check (const str &n);
};

extern vec<sfsagent_certprog> certprogs;
extern vec<rxfilter> certfilters;
extern vec<sfsagent_revokeprog> revokeprogs;
extern vec<rxfilter> revokefilters;
extern qhash<str, str> srpnames;
extern bhash<sfs_hash> norevoke;
extern sfsagent_confprog confprog;
extern sfsagent_srpcacheprog srpcacheprog;

void runprog (const sfsagent_cmd &av, str target, cbs cb);
void sfslookup (str name, callback<void, sfsagent_lookup_type, str>::ref cb, 
		u_int certno = 0, str res = NULL);
void revcheck (str name, callback<void, const sfsagent_revoked_res *>::ref cb);
void store_srp_cache (sfsagent_srpname_pair *pair);
void load_srp_cache (cbv cb);


struct authmgr;
struct authmeth : virtual public sfs_authorizer {
  list_entry<authmeth> link;
  str name;
  sfs_time expire;
  ref<bool> destroyed;
  sfs_hash authid_cache;
  authmgr *amgr;

  authmeth () 
    : destroyed (New refcounted<bool> (false)), amgr(NULL) {}
  authmeth (authmgr *a) 
    : destroyed (New refcounted<bool> (false)), amgr(a) {}
  virtual ~authmeth () { *destroyed = true; }

  virtual void authwarn (const sfsagent_authinit_arg *aa);
  virtual bool kcmp (const sfspub &k) { return false; }
  virtual bool pcmp (const int p) { return false; }
  virtual str get_desc () const = 0 ;

  virtual void to_str (strbuf &b) { b << name; }

  bool register_sess (const sfs_authinfo &ai, const sfs_seqno &seqno,
		      sfs_hash &hsh, bool storeit = true);

};

struct key : public authmeth, public sfskey_authorizer {
  key () {}
  key (authmgr *a) {}

  bool ntries_ok (int) { return true; }
  bool kcmp (const sfspub &kk)
    { if (!k) return false; return *k == kk; }
  void to_str (strbuf &b) { 
    strbuf kb;
    if (k) k->export_pubkey (kb);
    b << name << " (key: " << kb << ")";
  }
  str get_desc () const { return k->get_desc (); }
};

struct extauth_server {
  virtual void eof () {}
  virtual ~extauth_server () {} 
};

struct extauth : public authmeth {
  int pid;
  ref<axprt> x;
  ptr<aclnt> ac;
  bool eof;
  extauth_server *eas;

  extauth (ref<axprt> xx, authmgr *a, extauth_server *eas);
  ~extauth () ;

  void authinit (const sfsagent_authinit_arg *aa,
		 sfsagent_auth_res *res, cbv cb);
  void authmore (const sfsagent_authmore_arg *aa,
		 sfsagent_auth_res *res, cbv cb);
  void eofcb (authmgr *a);
  bool pcmp (const int p) { return p == pid; }
  void eacb (sfsagent_auth_res *, cbv, ref<bool>, clnt_stat);
  void to_str (strbuf &b) { b << name << " (pid: " << pid << ")" ; }
  str get_desc () const { strbuf b; b << "pid: " << pid; return b;}
};

struct authsess {
  authmeth *am;
  sfs_time expire;
  u_int id;
  tailq_entry<authsess> link;
  ihash_entry<authsess> hlink;

  authsess::authsess (authmeth *a, u_int i);

  void to_str (strbuf &b) 
  {  
    b.fmt ("ASID: 0x%x  KEY: ", id);
    if (am) { am->to_str (b); } 
    else { b << "(null)"; }
  }
};

struct auth_sess_mgr {
  timecb_t *exp_tmo;
  authmgr *amgr;
  ihash<u_int, authsess, &authsess::id, &authsess::hlink> sh;
  tailq<authsess, &authsess::link> sq;
  int num;

  auth_sess_mgr () : exp_tmo (NULL), num (0) {}

  void timeout (bool cb = false);
  void remove (authsess *as);
  void touch (authsess *as);
  void insert (authmeth *am, u_int id);
  bool register_sess (const sfs_authinfo &ai, const sfs_seqno &seqno,
		      authmeth *m, sfs_hash &hsh, bool storeit = true);
  u_int compute_asid (const sfs_authinfo &, const sfs_seqno &,
		      sfs_hash &);
  authmeth *retrieve (const sfs_authinfo &, const sfs_seqno &,
		      sfs_hash &);
  bool exists (const authmeth *p); 
  
};

struct authmgr : virtual public sfs_authorizer {
  timecb_t *exp_tmo;
  sfs_time exp_time;
  auth_sess_mgr asmgr;
  list<authmeth, &authmeth::link> authmeths;

  authmgr () 
    : exp_tmo (NULL), exp_time (0) { asmgr.amgr = this; }
  
  void timeout (bool cb = false);
  authmeth *klookup (const sfspub &s);
  authmeth *plookup (const int p);
  authmeth *clookup (const str &c);
  bool exists (const authmeth *p);
  authmeth *lookup_by_index (const u_int n);

  // Warning: in next 2 funcs can't delete argp's before cb is called
  void authinit (const sfsagent_authinit_arg *argp,
		 sfsagent_auth_res *resp, cbv cb);
  void authmore (const sfsagent_authmore_arg *argp,
		 sfsagent_auth_res *resp, cbv cb);

  static void authdone_cb (svccb *s)
    { s->reply (s->Xtmpl getres<sfsagent_auth_res> ()); }
  pid_t confirm (authmeth *k, const sfsagent_authinit_arg *aa, cbi cb);
  void confirmed (authmeth *k, const sfsagent_authinit_arg *aa,
		  sfsagent_auth_res *resp, cbv cb, int stat);

  void remove (authmeth *am) { authmeths.remove (am); }
  void insert (authmeth *am) { authmeths.insert_head (am) ; }
  void remove_all ();
  void fill_keylist (sfs_keylist *kl) ;
};

struct sfsagent : public extauth_server {
  str name;
  ref<axprt> x;
  ptr<aclnt> ac;
  ptr<asrv> as;
  ptr<asrv> cs;
  list_entry<sfsagent> link;
  vec<callback<void>::ptr> failcbs;

  sfsagent (int fd);
  sfsagent (ref<axprt> x);
  ~sfsagent ();

  void agentdisp (svccb *sbp);
  void ctldisp (svccb *sbp);
  void dispatch (svccb *sbp);
  void keyinitcb (svccb *sbp, key *nk, str err);
  void rexres (svccb *sbp, ptr<sfsagent_rex_res> res,
               callback<void>::ptr failcb);

  void setname (str name);
  void eof () { delete this; }
};

extern authmgr gmgr;
extern list<sfsagent, &sfsagent::link> agents;
extern str agent_id;

void agentmsg (u_int32_t proc, const void *arg = NULL);

/* agentrex.C */
typedef callback<void, ptr<sfsagent_rex_res>, cbv::ptr>::ref cb_rex;
void rex_connect (str dest, str path, str frompath,
    		  bool forwardagent, bool agentconnect, bool resumable,
                  cb_rex::ref cb);
void rex_keepalive (str path, svccb *sbp);
void list_rexsess (svccb *sbp);
bool kill_rexsess (str schost);
