/* $Id: authclnt.C,v 1.124 2004/09/19 22:02:26 dm Exp $ */

/*
 *
 * Copyright (C) 2002-2004 David Mazieres (dm@uun.org)
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

#include "sfscrypt.h"
#include "sfsschnorr.h"
#include "sfsauthd.h"
#include "rxx.h"
#include "parseopt.h"
#include "sfskeymisc.h"
#include "authgrps.h"
#include "auth_helper_prot.h"

#if HAVE_GETSPNAM
#include <shadow.h>
#endif /* HAVE_GETSPNAM */

extern "C" char *crypt (const char *, const char *);
sprivk_tab_t sprivk_tab;

const str refresh_eq (",refresh=");
const str timeout_eq (",timeout=");

static str
unixpriv (const char *p)
{
  static const str unixeq ("unix=");
  static const str cunixeq (strbuf () << "," << unixeq);
  if (strncasecmp (p, unixeq, unixeq.len ())) {
    p = strstr (p, cunixeq);
    if (!p)
      return NULL;
    p++;
  }
  p += unixeq.len ();

  str val;
  if (char *e = strchr (p, ','))
    val = str (p, e - p);
  else
    val = p;
  if (val.len () == 0 || val.len () > 31)
    return NULL;
  for (u_int i = 0; i < val.len (); i++)
    if (!isalnum (val[i]) && val[i] != '_' && val[i] != '.' && val[i] != '-')
      return NULL;
  return val;
}

static str
hash_sprivk (const sfs_2schnorr_priv_xdr &k)
{
  sfs_hash h;
  if (!sha1_hashxdr (&h, k))
    return NULL;
  return str (h.base (), h.size ());
}

inline str
mkname (const dbfile *dbp, str name)
{
  str r;
  if (dbp->prefix)
    r = dbp->prefix << "/" << name;
  else
    r = name;
  return name;
}

static void
badauth (logincb_t cb, sfs_authtype atype, str msg, const sfsauth_dbrec *dbrp)
{
  static str badlogin ("bad login");
  sfsauth2_loginres res (SFSLOGIN_BAD);
  *res.errmsg = msg ? msg : badlogin;
  (*cb) (&res, atype, dbrp);
}
static void
badauth (logincb_t cb, sfs_authtype atype, str msg, str user)
{
  if (user && user.len ()) {
    sfsauth_dbrec ae (SFSAUTH_USER);
    rpc_wipe (*ae.userinfo);
    ae.userinfo->name = user;
    ae.userinfo->id = badid;
    ae.userinfo->gid = badid;
    badauth (cb, atype, msg, &ae);
  }
  else
    badauth (cb, atype, msg, (sfsauth_dbrec *) NULL);
}
static void
badauth (logincb_t cb, sfs_authtype atype, str msg, ref<sfspub> pub)
{
  sfsauth_dbrec ae (SFSAUTH_USER);
  rpc_wipe (*ae.userinfo);
  ae.userinfo->id = badid;
  ae.userinfo->gid = badid;
  if (pub->export_pubkey (&ae.userinfo->pubkey))
    badauth (cb, atype, msg, &ae);
  else
    badauth (cb, atype, msg, NULL);
}

bool
sprivk_tab_t::is_valid (const str &hv)
{
  assert (hv);
  bool ret;
  sprivk_t *s = keys[hv];
  if (!s)
    ret = false;
  else 
    ret = s->valid;
  return ret;
}

bool
sprivk_tab_t::invalidate (const str &hv)
{
  assert (hv);
  sprivk_t *s = keys[hv];
  if (!s)
    return false;
  s->valid = false;
  release (hv, s);
  return true;
}

void
sprivk_tab_t::bind (const str &hv)
{
  
  assert (hv);
  sprivk_t *s = keys[hv];
  if (s)
    s->refs++;
  else {
    nentries ++;
    keys.insert (hv);
  }
}

void
sprivk_tab_t::release (const str &hv, sprivk_t *s)
{
  assert (hv);
  if (!s)
    s = keys[hv];
  if (s && --s->refs == 0) {
    nentries --;
    keys.remove (hv);
  }
}

authpending::authpending (authclnt *a, const sfsauth2_loginarg *largp)
    : ac (a), authid (largp->authid), seqno (largp->arg.seqno), tmo (NULL)
{
  if (!bytes2xdr (atype, largp->arg.certificate))
    panic ("authpending::authpending: could not decode type\n");
  ac->aptab.insert (this);
  refresh ();
}

authpending::~authpending ()
{
  timecb_remove (tmo);
  ac->aptab.remove (this);
}

void
authpending_srp::init (const sfs_autharg2 *aap, logincb_t cb)
{
  sfsauth_dbkey kname (SFSAUTH_DBKEY_NAME);
  *kname.name = aap->srpauth->req.user;
  if (!get_user_cursor (&srp_dbp, &srp_ac, NULL, kname)) {
    /* Note we are divulging what accounts exist and don't.  To avoid
     * doing so, we'd have to synthesize new but constant SRP
     * parameters and run part way through the protocol.
     */
    badauth (cb, atype, "bad user", *kname.name);
    delete this;
    return;
  }

  sfsauth2_loginres res (SFSLOGIN_MORE);
  switch (srp.init (res.resmore.addr (), &aap->srpauth->msg,
		    authid, srp_ac->ae.userinfo->name,
		    srp_ac->ae.userinfo->pwauth,
		    /* XXX - The following is for backwards compatibility,
		     * but could allow "two-for-one" guessing by active
		     * adversaries.  Should be phased out eventually. */
		    ac->client_release () < 8 ? 3 : 6)) {
  case SRP_NEXT:
    (*cb) (&res, SFS_SRPAUTH, NULL);
    break;
  default:
    badauth (cb, atype, "no password established", srp.user);
    delete this;
    break;
  }
}

void
authpending_srp::next (const sfs_autharg2 *aap, logincb_t cb)
{
  sfsauth2_loginres res;

  srpmsg msg;
  switch (srp.next (&msg, &aap->srpauth->msg)) {
  case SRP_NEXT:
    res.set_status (SFSLOGIN_MORE);
    swap (*res.resmore, msg);
    (*cb) (&res, atype, NULL);
    break;
  case SRP_LAST:
    if (ac->setuser (&res, srp_ac->ae, srp_dbp))
      swap (res.resok->resmore, msg);
    (*cb) (&res, atype, &srp_ac->ae); 
    delete this;
    return;
  default:
    badauth (cb, atype, "incorrect password", &srp_ac->ae);
    delete this;
    return;
  }
}

authpending_helper::~authpending_helper ()
{
  srv = NULL;
  if (getpassreq)
    getpassreq->reject (SYSTEM_ERR);
  if (pid > 0) {
    chldcb (pid, NULL);
    kill (pid, SIGKILL);
  }
  if (cb)
    badauth (cb, atype, "canceled or timed out", user);
}

void
authpending_helper::init (const sfs_autharg2 *aap, logincb_t c)
{
  vec<str> av;
  av.push_back (auth_helper);
  av.push_back ("-r");
  av.push_back (PACKAGE);
  if (aap->pwauth->req.user.len ()) {
    /* Problem is, a user might accidentally type his/her password
     * instead of a username.  So perhaps it's best not to have
     * usernames showing up in ps.  */
    user = aap->pwauth->req.user;
    pwds.push_back (user);
    if (aap->pwauth->password.len ())
      pwds.push_back (aap->pwauth->password);
  }

  ptr<axprt_unix> x (axprt_unix_aspawnv (av[0], av));
  if (!x) {
    badauth (c, atype, "could not spawn auth helper program", user);
    delete this;
    return;
  }
  pid = axprt_unix_spawn_pid;
  chldcb (pid, wrap (this, &authpending_helper::reap));
  x->allow_recvfd = false;

  cb = c;
  srv = asrv::alloc (x, authhelp_prog_1,
		     wrap (this, &authpending_helper::dispatch));
}

void
authpending_helper::next (const sfs_autharg2 *aap, logincb_t c)
{
  str2wstr (aap->pwauth->password);
  if (cb || !pwds.empty () || !getpassreq) {
    badauth (c, atype, "multiple concurrent login RPCs for same seqno", user);
    delete this;
    return;
  }
  cb = c;
  if (!user)
    user = aap->pwauth->password;
  authhelp_getpass_res res;
  res.response = aap->pwauth->password;
  svccb *sbp = getpassreq;
  getpassreq = NULL;
  sbp->reply (&res);
}

void
authpending_helper::reap (int)
{
  pid = -1;
}

void
authpending_helper::dispatch (svccb *sbp)
{
  if (!sbp) {
    badauth (cb, atype, NULL, user);
    cb = NULL;
    delete this;
    return;
  }

  switch (sbp->proc ()) {
  case AUTHHELPPROG_NULL:
    sbp->reply (NULL);
    break;
  case AUTHHELPPROG_GETPASS:
    if (getpassreq) {
      warn ("received concurrent RPCs from auth helper\n");
      delete this;
    }
    else if (!pwds.empty ()) {
      authhelp_getpass_res res;
      res.response = pwds.pop_front ();
      sbp->reply (&res);
    }
    else if (cb) {
      getpassreq = sbp;
      authhelp_getpass_arg *argp
	= sbp->Xtmpl getarg<authhelp_getpass_arg> ();
      if (!argp->echo && !strncasecmp (argp->prompt, "password:", 9))
	argp->prompt = strbuf () << "Unix " << argp->prompt;
      sfsauth2_loginres res (SFSLOGIN_MORE);
      xdr2bytes (*res.resmore, *argp);
      logincb_t c (cb);
      cb = NULL;
      (*c) (&res, atype, NULL);
    }
    else
      panic ("authpending_helper no cb and no getpassreq\n");
    break;
  case AUTHHELPPROG_SUCCEED:
    {
      str unixuser (sbp->Xtmpl getarg<authhelp_succeed_arg> ()->user);
      authclnt *ac_local (ac);
      ptr<authcursor> ah_ac_local (ah_ac);
      logincb_t::ptr c (cb);
      cb = NULL;
      delete this;
      sbp->reply (NULL);
      if (c)
	ac_local->login_unixpw_2 (ah_ac_local, unixuser, NULL, false, c);
      break;
    }
  default:
    sbp->reject (PROC_UNAVAIL);
    break;
  }
}

bool
authclnt::is_authenticated (svccb *sbp)
{
  const sfsauth_cred *cp = NULL;
  const urec_t *ur = NULL;

  return (sbp->getaui () < credtab.size ()
      && (cp = &credtab[sbp->getaui ()]) 
      && cp->type == SFS_UNIXCRED 
      && (ur = utab[sbp->getaui ()])
      && ur->authtype != SFS_NOAUTH);
}

void
authclnt::urecfree (urec_t *u)
{
  utab.remove (u);
  ulist.remove (u);
  delete u;
}

authclnt::urec_t::~urec_t ()
{
  if (kh.type == SFSAUTH_KEYHALF_PRIV) 
    for (u_int i = 0; i < kh.priv->size (); i++) 
      sprivk_tab.release (hash_sprivk ((*kh.priv) [i]));
}

authclnt::urec_t::urec_t (u_int32_t a, sfs_authtype t, 
			  const sfsauth_dbrec &dbr)
  : authno (a), authtype (t)
{
  if (dbr.type == SFSAUTH_USER) {
    uname = dbr.userinfo->name;
    kh = dbr.userinfo->srvprivkey;
    if (kh.type == SFSAUTH_KEYHALF_PRIV)
      for (u_int i = 0; i < kh.priv->size (); i++)
	sprivk_tab.bind (hash_sprivk ((*kh.priv) [i]));
  }
}

authclnt::authclnt (ref<axprt_crypt> x, const authunix_parms *aup)
  : sfsserv (x),
    authsrv (asrv::alloc (x, sfsauth_prog_2,
			  wrap (this, &authclnt::dispatch)))
{
  if (aup) {
    uid.alloc ();
    *uid = aup->aup_uid;
    if (!client_name || !client_name.len ()) {
      if (!*uid)
	client_name = "LOCAL";
      else
	client_name = strbuf ("LOCAL(uid=%d)", *uid);
    }
  }
}

authclnt::~authclnt ()
{
  ulist.traverse (wrap (this, &authclnt::urecfree));
  aptab.deleteall ();
}

ptr<sfspriv>
authclnt::doconnect (const sfs_connectarg *ci,
		     sfs_servinfo *si)
{
  *si = myservinfo;
  return myprivkey;
}

struct passwd *
unix_user (str user, str pwd, str *errp)
{
  struct passwd *pw = getpwnam (user);
  if (!pw) {
    if (errp)
      *errp = "Invalid login";
    return NULL;
  }

  time_t now = time (NULL);
  bool expired = false;
#if HAVE_GETSPNAM
  struct spwd *spe = getspnam (user);
  if (spe && spe->sp_expire > 0
      && spe->sp_expire <= (now / (24 * 60 * 60)))
    expired = true;
#elif defined (HAVE_PASSWD_PW_EXPIRE)
  if (pw->pw_expire > 0 && pw->pw_expire <= now)
    expired = true;
#endif /* HAVE_PASSWD_PW_EXPIRE */
  if (expired) {
    if (errp)
      *errp = "Login expired";
    return NULL;
  }

  if (!pwd)
    return pw;
#if HAVE_GETSPNAM
  if (spe) {
    if (!strcmp (spe->sp_pwdp, crypt (pwd, spe->sp_pwdp)))
      return pw;
  }
  else
#endif /* HAVE_GETSPNAM */
    if (!strcmp (pw->pw_passwd, crypt (pwd, pw->pw_passwd)))
      return pw;

  if (errp)
    *errp = "Invalid password";
  /* Yes, some people believe you should just say invalid login here,
   * but I don't think the additional security through obscurity of
   * login names is worth the potential confusion to users. */
  return NULL;
}


bool
authclnt::setuser (sfsauth2_loginres *resp, const sfsauth_dbrec &ae,
		   const dbfile *dbp)
{
  assert (ae.type == SFSAUTH_USER);

  resp->set_status (SFSLOGIN_OK);
  resp->resok->creds.setsize (1);
  resp->resok->creds[0].set_type (SFS_UNIXCRED);

  str name = mkname (dbp, ae.userinfo->name);

  bool require_unix = false;
  str unixname;
  if (dbp->allow_unix_pwd) {
    if ((unixname = unixpriv (ae.userinfo->privs)))
      require_unix = true;
    else // For compatibility before unix= priv
      unixname = ae.userinfo->name;
  }
      
  if (unixname) {
    str err;
    if (struct passwd *pw = unix_user (unixname, NULL, &err)) {
      resp->resok->creds[0].unixcred->username = unixname;
      resp->resok->creds[0].unixcred->homedir = pw->pw_dir;
      resp->resok->creds[0].unixcred->shell = pw->pw_shell;
      resp->resok->creds[0].unixcred->uid = pw->pw_uid;
      resp->resok->creds[0].unixcred->gid = pw->pw_gid;
    }
    else if (require_unix) {
      resp->set_status (SFSLOGIN_BAD);
      *resp->errmsg = err;
      return false;
    }
    else
      unixname = NULL;
  }

  if (!unixname) {
    resp->resok->creds[0].unixcred->username = name;
    resp->resok->creds[0].unixcred->homedir = "/dev/null";
    resp->resok->creds[0].unixcred->shell = "/dev/null";
    resp->resok->creds[0].unixcred->uid = dbp->uidmap->map (ae.userinfo->id);
    resp->resok->creds[0].unixcred->gid = dbp->gidmap->map (ae.userinfo->gid);
  }

  if (resp->resok->creds[0].unixcred->uid == badid) {
    resp->set_status (SFSLOGIN_BAD);
    *resp->errmsg = "uid out of range";
    return false;
  }

  vec<u_int32_t> groups;
  findgroups_unix (&groups, unixname ? unixname : name);
  resp->resok->creds[0].unixcred->groups.setsize (groups.size ());
  memcpy (resp->resok->creds[0].unixcred->groups.base (),
	  groups.base (), groups.size () * sizeof (groups[0]));
  return true;
}

void
setuser_pkhash (sfsauth2_loginres *resp, ptr<sfspub> vrfy)
{
  str h;
  if (!(h = vrfy->get_pubkey_hash ())) {
    warn << "Error in sha1_hashxdr of user's public key\n";
    return;
  }

  vec<sfsauth_cred> v;
  size_t n = resp->resok->creds.size ();

  for (size_t i = 0; i < n; i++)
    v.push_back (resp->resok->creds[i]);

  v.push_back ();
  v[n].set_type (SFS_PKCRED);
  *v[n].pkhash = armor32 (h);

  resp->resok->creds.setsize (n + 1);
  for (size_t i = 0; i < n + 1; i++)
    resp->resok->creds[i] = v[i];
}

void
authclnt::setuser_groups (sfsauth2_loginres *resp, const sfsauth_dbrec *ae,
                          const dbfile *dbp, ptr<sfspub> vrfy)
{
  vec<str> groups;
  str h = vrfy->get_pubkey_hash ();
  if (h)
    h = armor32 (h);
  if (dbp && ae)
    findgroups_symbolic (&groups, mkname (dbp, ae->userinfo->name),
                         &ae->userinfo->gid, h);
  else
    findgroups_symbolic (&groups, NULL, NULL, h);

  if (!groups.size ())
    return;

  vec<sfsauth_cred> v;
  size_t n = resp->resok->creds.size ();
  for (size_t i = 0; i < n; i++)
    v.push_back (resp->resok->creds[i]);

  v.push_back ();
  v[n].set_type (SFS_GROUPSCRED);
  v[n].groups->setsize (groups.size ());
  for (unsigned int i = 0; i < groups.size (); i++)
    (*v[n].groups)[i] = groups[i];

  resp->resok->creds.setsize (n + 1);
  for (size_t i = 0; i < n + 1; i++)
    resp->resok->creds[i] = v[i];
}

void
authclnt::findgroups_unix (vec<u_int32_t> *groups, str name)
{
  groups->clear ();
  bhash<u_int32_t> seen;
  for (dbfile *dbp = dbfiles.base (); dbp < dbfiles.lim (); dbp++) {
    str suffix = dbp->strip_prefix (name);
    if (!suffix)
      continue;

    if (ptr<authcursor> ac = dbp->db->open (dbp->dbflags)) {
      vec<u_int32_t> gv;
      ac->find_gids_user (&gv, suffix);
      while (!gv.empty ()) {
	u_int32_t gid = dbp->gidmap->map (gv.pop_front ());
	if (gid != badid && seen.insert (gid))
	  groups->push_back (gid);
      }
    }
  }
}

void
authclnt::findgroups_symbolic (vec<str> *groups, str name,
                               const u_int32_t *gidp, str pkhash)
{
  groups->clear ();
  if (!global_dbcache)  // symbolic groups are disabled
    return;

  if (name)
    groups->push_back (add_member_type (name, "u"));
  if (pkhash)
    groups->push_back (add_member_type (pkhash, "p"));
  global_dbcache->find_groups (groups);
}

void
authclnt::dispatch (svccb *sbp)
{
  if (!sbp) {
    delete this;
    return;
  }
  switch (sbp->proc ()) {
  case SFSAUTH2_NULL:
    sbp->reply (NULL);
    break;
  case SFSAUTH2_LOGIN:
    sfsauth_login (sbp->Xtmpl getarg<sfsauth2_loginarg> (),
		   wrap (&authclnt::dispatch_2, sbp));
    break;
  case SFSAUTH2_QUERY:
    sfsauth_query (sbp);
    break;
  case SFSAUTH2_UPDATE:
    sfsauth_update (sbp);
    break;
  case SFSAUTH2_SIGN:
    sfsauth_sign (sbp);
    break;
  default:
    sbp->reject (PROC_UNAVAIL);
    break;
  }
}

void
authclnt::sfsauth_sign (svccb *sbp)
{
  sfsauth2_sign_arg *arg = sbp->Xtmpl getarg<sfsauth2_sign_arg> ();
  sfsauth2_sign_res res (true);
  u_int32_t authno = sbp->getaui ();
  sfsauth_dbrec db;
  bool restricted_sign = false;
  urec_t *ur = NULL;
  sfsauth_keyhalf *kh = NULL;
  sfs_idname uname;

  if (authno && (ur = utab[authno])) {
    kh = &ur->kh;
    uname = ur->uname;
  }

  if (!kh && arg->req.type == SFS_SIGNED_AUTHREQ
      && arg->req.authreq->type == SFS_SIGNED_AUTHREQ_NOCRED
      && arg->authinfo.service == SFS_AUTHSERV
      && authid == arg->req.authreq->authid) {
    sfsauth_dbkey key (SFSAUTH_DBKEY_NAME);
    if ((*key.name = arg->user) && get_user_cursor (NULL, NULL, &db, key)) {
      kh = &db.userinfo->srvprivkey;
      uname = db.userinfo->name;
      restricted_sign = true;
    }
  } 

  if (!kh || kh->type != SFSAUTH_KEYHALF_PRIV) {
    res.set_ok (false);
    *res.errmsg = "No valid server private keyhalf for user";
    sbp->replyref (res);
    return;
  }
  if (arg->presig.type != SFS_2SCHNORR) {
    res.set_ok (false);
    *res.errmsg = "Can only answer 2-Schnorr requests";
    sbp->replyref (res);
    return;
  }
  res.sig->set_type (SFS_SCHNORR);
  int i = sfs_schnorr_pub::find (*kh, arg->pubkeyhash);
  if (i < 0) {
    res.set_ok (false);
    *res.errmsg = "No matching keyhalf found on server.";
    sbp->replyref (res);
    return;
  }
  const sfs_2schnorr_priv_xdr &spriv = (*kh->priv)[i];
  if (ur && !sprivk_tab.is_valid (hash_sprivk (spriv))) {
    res.set_ok (false);
    *res.errmsg = "Server keyhalf is no longer valid.";
    sbp->replyref (res);
    return;
  }

  ref<schnorr_srv_priv> srv_key = New refcounted<schnorr_srv_priv> 
    (spriv.p, spriv.q, spriv.g, spriv.y, spriv.x);

  str msg = sigreq2str (arg->req);
  if (!msg) {
    res.set_ok (false);
    *res.errmsg = "Cannot marshal signature request";
    sbp->replyref (res);
    return ;
  }

  sfs_hash aid_tmp;
  if (arg->req.type != SFS_NULL && 
      (!sha1_hashxdr (aid_tmp.base (), arg->authinfo) || 
      !sigreq_authid_cmp (arg->req, aid_tmp))) {
    res.set_ok (false);
    *res.errmsg = "Incorrect authid in request";
    sbp->replyref (res);
    return ;
  }

  if (!siglog (siglogline (*arg, uname))) {
    res.set_ok (false);
    *res.errmsg = "Refusing to sign: could not log signature";
    sbp->replyref (res);
    return;
  }
    
  srv_key->endorse_signature (&res.sig->schnorr->r, &res.sig->schnorr->s, 
			      msg, arg->presig.schnorr->r);
  sbp->replyref (res);
}

str
authclnt::siglogline (const sfsauth2_sign_arg &arg, const str &uname)
{
  str req = xdr2str (arg);
  if (!req) return NULL;
  req = armor64 (req);
  str tm = single_char_sub (timestr (), ':', ".");
  strbuf line;
  line << "SIGN:" << uname << ":" << client_name << ":" << tm << ":" 
       << req << "\n";
  return line;
}

bool
siglog (const str &line)
{
  if (!line) return false;
  int n = write (logfd, line.cstr (), line.len ());
  if (n < int (line.len ())) 
    return false;
  return true;
}

str 
siglog_startup_msg ()
{
  strbuf msg;
  str tm = single_char_sub (timestr (), ':', ".");
  msg << "sfsauthd restarted: " << tm << "\n";
  return msg;
}

void
siglogv ()
{
  if (!siglog (siglog_startup_msg ()))
    fatal << "Cannot generate startup message for signature log\n";
}

inline str
group_prefix (str s, str prefix)
{
  if (s.len () <= prefix.len () || s[prefix.len ()] != '.'
      || memcmp (s.cstr (), prefix.cstr (), prefix.len ()))
    return NULL;
  return substr (s, prefix.len () + 1);
}

void
authclnt::sfsauth_update (svccb *sbp)
{
  const sfsauth_cred *cp = NULL;
  urec_t *ur = NULL;
  if (sbp->getaui () >= credtab.size ()
      || !(cp = &credtab[sbp->getaui ()]) 
      || cp->type != SFS_UNIXCRED 
      || !(ur = utab[sbp->getaui ()])
      || ur->authtype == SFS_NOAUTH) {
    sbp->reject (AUTH_REJECTEDCRED);
    return;
  }

  sfsauth2_update_res res (false);
  sfsauth_dbkey kname (SFSAUTH_DBKEY_NAME);
  *kname.name = cp->unixcred->username;
  bool oldsig = false;

  sfsauth_dbrec cdbr;
  dbfile *cdbp;
  if (!get_user_cursor (&cdbp, NULL, &cdbr, kname)
      || cp->unixcred->username != cdbr.userinfo->name) {
    *res.errmsg = "could not load credential db record";
    sbp->replyref (res);
    return;
  }

  if (cp->unixcred->uid != cdbr.userinfo->id) {
    *res.errmsg = "invalid uid";
    warn << cp->unixcred->username << " authenticated with uid "
	 << cp->unixcred->uid << " while DB record has uid "
	 << cdbr.userinfo->id << "\n";
    warn << "could user " << cp->unixcred->username << " have"
	 << " wrong UID in sfs_users file?\n";
    sbp->replyref (res);
    return;
  }

  sfsauth2_update_arg *argp = sbp->Xtmpl getarg<sfsauth2_update_arg> ();
  if (argp->req.type != SFS_UPDATEREQ
      || (argp->req.rec.type != SFSAUTH_USER
	  && argp->req.rec.type != SFSAUTH_GROUP)) {
    *res.errmsg = "invalid request";
    sbp->replyref (res);
    return;
  }
  u_int32_t opts = argp->req.opts;
  if (argp->req.authid != authid) {
    *res.errmsg = "invalid authid";
    sbp->replyref (res);
    return ;
  }

  static rxx adminrx ("(\\A|,)admin(\\Z|,)");
  bool admin = cdbp->allow_admin && adminrx.search (cdbr.userinfo->privs);
  str reqxdr = xdr2str (argp->req);
  if (argp->newsig) {
    str e;
    if (!sfscrypt.verify (argp->req.rec.userinfo->pubkey, *(argp->newsig), 
			  reqxdr, &e)) {
      *res.errmsg = str (strbuf ("new signature: " << e));
      sbp->replyref (res);
      return;
    }
  }
  else if (!(opts & SFSUP_KPPK) && !admin) {
    *res.errmsg = "Missing signature with new public key.";
    sbp->replyref (res);
    return;
  }

  if (argp->authsig) {
    str e;
    if (!sfscrypt.verify (cdbr.userinfo->pubkey, *(argp->authsig), 
			  reqxdr, &e)) {
      *res.errmsg = str (strbuf ("old signature: " << e));
      sbp->replyref (res);
      return;
    } else 
      oldsig = true;
  }
  else if (!cdbp->allow_unix_pwd || ur->authtype != SFS_UNIXPWAUTH) {
    *res.errmsg = "digital signature required";
    sbp->replyref (res);
    return;
  }
  else
    admin = false;

  dbfile *udbp;
  ptr<authcursor> uac;
  sfsauth_dbrec udbr;
  if (argp->req.rec.type == SFSAUTH_USER) {
    *kname.name = argp->req.rec.userinfo->name;
    if (!get_user_cursor (&udbp, &uac, &udbr, kname, true)) {
      *res.errmsg = "could not find or update user's record";
      sbp->replyref (res);
      return;
    }
    if (!admin && (udbr.userinfo->name != cdbr.userinfo->name
		   || udbr.userinfo->id != cdbr.userinfo->id)) {
      /* XXX - ignoring owner field for now */
      *res.errmsg = "access denied";
      sbp->replyref (res);
      return;
    }
    if (argp->req.rec.userinfo->vers < 1) {
      *res.errmsg = "version number of record must be greater than 0";
      sbp->replyref (res);
      return;
    }
    if (argp->req.rec.userinfo->vers != udbr.userinfo->vers + 1) {
      *res.errmsg = "version mismatch";
      sbp->replyref (res);
      return;
    }
    uac->ae.userinfo->vers = argp->req.rec.userinfo->vers;
    if (!(opts & SFSUP_KPPK))
      uac->ae.userinfo->pubkey = argp->req.rec.userinfo->pubkey;
    if (!(opts & SFSUP_KPSRP))
      uac->ae.userinfo->pwauth = argp->req.rec.userinfo->pwauth;
    if (!(opts & SFSUP_KPESK))
      uac->ae.userinfo->privkey = argp->req.rec.userinfo->privkey;

    str err = update_srv_keyhalf (argp->req.rec.userinfo->srvprivkey,
				  uac->ae.userinfo->srvprivkey, 
				  udbr.userinfo->srvprivkey, true, ur);
    if (err) {
      *res.errmsg = err;
      sbp->replyref (res);
      return;
    }

    strbuf sb;
    sb << "Last modified " << timestr () << " by " ;
    if (uid && !*uid)
      sb << "*superuser*";
    else
      sb << cp->unixcred->username;
    sb << "@" << client_name;
    uac->ae.userinfo->audit = sb;

    if (admin) {
      u_int32_t gid = argp->req.rec.userinfo->gid;
      if (udbp->gidmap && gid != udbp->gidmap->map (uac->ae.userinfo->gid)) {
	gid = udbp->gidmap->unmap (gid);
	if (gid == badid
	    || udbp->gidmap->map (gid) != argp->req.rec.userinfo->gid) {
	  *res.errmsg = "bad gid";
	  sbp->replyref (res);
	  return;
	}
      }
      uac->ae.userinfo->gid = gid;
      uac->ae.userinfo->privs = argp->req.rec.userinfo->privs;
    }

    if (!uac->update ()) {
      *res.errmsg = "database refused update";
      sbp->replyref (res);
      return;
    }
    res.set_ok (true);
    udbp->mkpub ();
  }
  else {
    *kname.name = argp->req.rec.groupinfo->name;
    bool create = argp->req.rec.groupinfo->id == 0 && argp->req.rec.groupinfo->vers == 1;
    bool exists = get_group_cursor (&udbp, &uac, &udbr, kname, true, create);

    if (exists && create && udbr.groupinfo->id > udbp->grprange->id_max) {
      *res.errmsg = strbuf () << "all group IDs in the allowed range ("
	                      << udbp->grprange->id_min << "-"
	                      << udbp->grprange->id_max << ") are in use";
      sbp->replyref (res);
      return;
    }

    if (!exists) {
      if (!create) {
	*res.errmsg = "perhaps record is read-only "
	              "or database doesn't accept group updates";
	sbp->replyref (res);
	return;
      }
      else {
	*res.errmsg = "no writable databases that accept group updates";
	sbp->replyref (res);
	return;
      }
    }
    if (create && udbr.groupinfo->vers != 0) {
      *res.errmsg = strbuf () << "group `" << udbr.groupinfo->name
	                      << "'already exists";
      sbp->replyref (res);
      return;
    }

    if (!admin) {
      if (create) {
	str gname;
	if (!(gname = group_prefix (udbr.groupinfo->name, cdbr.userinfo->name))
	    || gname.len () < 1) {
	  *res.errmsg = strbuf () << "group name must be of the form `"
	                          << cdbr.userinfo->name << ".groupname'";
	  sbp->replyref (res);
	  return;
	}
	static rxx groupquotarx ("(\\A|,)groupquota=([0-9]+)(\\Z|,)");
	if (groupquotarx.search (cdbr.userinfo->privs)
            || udbp->default_groupquota >= 0) {
	  u_int32_t max_groups;
	  u_int32_t cur_groups;
	  
          if (groupquotarx.success ())
            convertint (groupquotarx[2], &max_groups);
          else
            max_groups = udbp->default_groupquota;

	  // XXX - open could fail
	  ptr<authcursor> gac = udbp->db->open (udbp->dbflags);
	  cur_groups = gac->count_group_prefix (strbuf ()
						<< cdbr.userinfo->name << ".");
	  if (cur_groups + 1 > max_groups) {
	    *res.errmsg = strbuf () << "group quota exceeded (current="
	                            << cur_groups << "/quota=" << max_groups << ")";
	    sbp->replyref (res);
	    return;
	  }
	}
      }
      else {
	ptr<sfspub> pk = sfscrypt.alloc (cdbr.userinfo->pubkey);
	str h = armor32 (pk->get_pubkey_hash ());
	sfs_groupmembers list;
	unsigned int n = udbr.groupinfo->owners.size ();
	for (unsigned int i = 0; i < n; i++)
	  list.push_back (udbr.groupinfo->owners[i]);
	
	if (!group_prefix (udbr.groupinfo->name, cdbr.userinfo->name)
	    && !is_a_member (cdbr.userinfo->name, h, list)) {
	  *res.errmsg = "access denied";
	  sbp->replyref (res);
	  return;
	}
      }
    }
    if (argp->req.rec.groupinfo->vers < 1) {
      *res.errmsg = "version number of record must be greater than 0";
      sbp->replyref (res);
      return;
    }
    if (argp->req.rec.groupinfo->vers != udbr.groupinfo->vers + 1) {
      *res.errmsg = "version mismatch";
      sbp->replyref (res);
      return;
    }
    uac->ae.groupinfo->vers = argp->req.rec.groupinfo->vers;

    strbuf sb;
    sb << "Last modified " << timestr () << " by " ;
    if (uid && !*uid)
      sb << "*superuser*";
    else
      sb << cp->unixcred->username;
    sb << "@" << client_name;
    uac->ae.groupinfo->audit = sb;

    // XXX: checking to make sure that the owners/groups are well-formed happens in update
    process_group_updates (udbr.groupinfo->owners, argp->req.rec.groupinfo->owners);
    process_group_updates (udbr.groupinfo->members, argp->req.rec.groupinfo->members);
    uac->ae.groupinfo->owners = udbr.groupinfo->owners;
    uac->ae.groupinfo->members = udbr.groupinfo->members;

    bool chlogok = write_group_changelog (argp->req.rec.groupinfo->name,
					  argp->req.rec.groupinfo->vers,
					  argp->req.rec.groupinfo->members,
					  sb);
    if (!chlogok) {
      *res.errmsg = "could not write changelog; database unmodified";
      sbp->replyref (res);
      return;
    }

    if (!uac->update ()) {
      // XXX: remove changelog entry
      *res.errmsg = "database refused update; see SFS documentation for correct syntax";
      sbp->replyref (res);
      return;
    }
    res.set_ok (true);
    udbp->mkpub ();
    uac->find_group_name (udbr.groupinfo->name);
    if (global_dbcache)
      update_dbcache (uac);
  }

  sbp->replyref (res);
}

/* XXX - this is needed for backwards compatibility with SFS 0.7,
 * because there was an extra hyper in the protocol we needed to get
 * rid of (but old clients still expect the hyper). */
static BOOL
xdr_dbrec_plus_hyper (XDR *xdrs, void *dbrec)
{
  if (!xdr_sfsauth_dbrec (xdrs, dbrec))
    return FALSE;
  if (xdrs->x_op == XDR_ENCODE && !xdr_puthyper (xdrs, 0))
    return FALSE;
  return TRUE;
}

void
authclnt::query_user (svccb *sbp)
{
  sfsauth2_query_arg *arg = sbp->Xtmpl getarg<sfsauth2_query_arg> ();
  ptr<authcursor> ac;
  sfsauth2_query_res res;

  if (!get_user_cursor (NULL, &ac, &res, arg->key)) {
    if (res.type != SFSAUTH_ERROR) {
      res.set_type (SFSAUTH_ERROR);
      *res.errmsg = "bad user";
    }
  }
  else if (sbp->getaui () < credtab.size ()) {
    const sfsauth_cred &c = credtab[sbp->getaui ()];
    const urec_t *ur = utab[sbp->getaui ()];
    if (ur && c.type == SFS_UNIXCRED
	&& c.unixcred->username == res.userinfo->name
	&& c.unixcred->uid == res.userinfo->id
	&& ur->authtype == SFS_SRPAUTH) {
      aesanitize (&res, AE_USER);
      res.userinfo->privkey = ac->ae.userinfo->privkey;
    }
    else if (c.type == SFS_UNIXCRED)
      aesanitize (&res, AE_PUBFILE);
    else
      aesanitize (&res, AE_QUERY);
  }
  else
    aesanitize (&res, AE_QUERY);
  
  sbp->reply (&res, xdr_dbrec_plus_hyper);
}

void
authclnt::query_srpparms (svccb *sbp)
{
  sfsauth2_query_res res (SFSAUTH_SRPPARMS);
  if (!srpparms) {
    res.set_type (SFSAUTH_ERROR);
    *res.errmsg = "No SRP information available";
  }
  else
    res.srpparms->parms = srpparms;
  sbp->replyref (res);
}

void
authclnt::query_certinfo (svccb *sbp)
{
  sfsauth2_query_res res (SFSAUTH_CERTINFO);
  if (sfsauthrealm.len () > 0) {
    res.certinfo->name = sfsauthrealm;
    res.certinfo->info.set_status (SFSAUTH_CERT_REALM);
    res.certinfo->info.certpaths->set (sfsauthcertpaths.base (), 
				       sfsauthcertpaths.size ());
  }
  else {
    res.certinfo->name = myservinfo.cr7->host.hostname;
    res.certinfo->info.set_status (SFSAUTH_CERT_SELF);
  }
  sbp->replyref (res);
  return ;

}

void
authclnt::query_group (svccb *sbp)
{
  sfsauth2_query_arg *arg = sbp->Xtmpl getarg<sfsauth2_query_arg> ();
  sfsauth2_query_res res;
  dbfile *dbp;
  sfsauth_dbkey key = arg->key;
  unsigned int start = 0;
  bool more = false;

  if (arg->key.type == SFSAUTH_DBKEY_NAMEVERS) {
    key.set_type (SFSAUTH_DBKEY_NAME);
    *key.name = arg->key.namevers->name;
    start = arg->key.namevers->vers;
  }

  if (get_group_cursor (&dbp, NULL, &res, key)) {
    // Send back chunks of 250 members that can fit in an RPC
    while (start && res.groupinfo->owners.size () > 0) {
      res.groupinfo->owners.pop_front ();
      start--;
    }
    while (start && res.groupinfo->members.size () > 0) {
      res.groupinfo->members.pop_front ();
      start--;
    }
    while (res.groupinfo->members.size () + res.groupinfo->owners.size ()
	   > 250) {
      if (res.groupinfo->members.size () > 0)
	res.groupinfo->members.pop_back ();
      else
	res.groupinfo->owners.pop_back ();
      more = true;
    }
    if (more)
      res.groupinfo->members.push_back ("...");

    if (dbp->hide_users && !is_authenticated (sbp)) {
      obfuscate_group (res.groupinfo->members);
      obfuscate_group (res.groupinfo->owners);
    }
  }
  sbp->replyref (res);
}

void
authclnt::query_expandedgroup (svccb *sbp)
{
  sfsauth2_query_arg *arg = sbp->Xtmpl getarg<sfsauth2_query_arg> ();
  sfsauth2_query_res res;
  dbfile *dbp;
  sfsauth_dbkey key = arg->key;
  unsigned int start = 0;
  bool more = false;

  // This query is disabled if the authentication cache is off because the
  // results could be misleading.  Specifically, the "members" list will
  // always be empty because it is generated from the (non-existent) cache.
  if (!global_dbcache) {
    res.set_type (SFSAUTH_ERROR);
    *res.errmsg = strbuf ("Expanded queries are disabled because this "
                          "server's authentication cache is disabled.");
    sbp->replyref (res);
    return;
  }

  if (arg->key.type == SFSAUTH_DBKEY_NAMEVERS) {
    key.set_type (SFSAUTH_DBKEY_NAME);
    *key.name = arg->key.namevers->name;
    start = arg->key.namevers->vers;
  }

  if (get_group_cursor (&dbp, NULL, &res, key)) {
    sfs_groupmembers list;
    sfs_groupmembers closure;

    list.push_back (add_member_type (res.groupinfo->name, "g"));
    transitive_closure (list, closure);
    res.groupinfo->members = closure;

    closure.clear ();
    transitive_closure (res.groupinfo->owners, closure);
    res.groupinfo->owners = closure;

    // Send back chunks of 250 members that can fit in an RPC
    while (start && res.groupinfo->owners.size () > 0) {
      res.groupinfo->owners.pop_front ();
      start--;
    }
    while (start && res.groupinfo->members.size () > 0) {
      res.groupinfo->members.pop_front ();
      start--;
    }
    while (res.groupinfo->members.size () + res.groupinfo->owners.size () > 250) {
      if (res.groupinfo->members.size () > 0)
	res.groupinfo->members.pop_back ();
      else
	res.groupinfo->owners.pop_back ();
      more = true;
    }
    if (more)
      res.groupinfo->members.push_back ("...");

    if (dbp->hide_users && !is_authenticated (sbp)) {
      obfuscate_group (res.groupinfo->members);
      obfuscate_group (res.groupinfo->owners);
    }
  }
  sbp->replyref (res);
}

void
authclnt::query_changelog (svccb *sbp)
{
  sfsauth2_query_arg *arg = sbp->Xtmpl getarg<sfsauth2_query_arg> ();
  sfsauth2_query_res res;
  dbfile *dbp;

  if (arg->key.type != SFSAUTH_DBKEY_NAMEVERS || arg->type != SFSAUTH_LOGENTRY) {
    res.set_type (SFSAUTH_ERROR);
    *res.errmsg = strbuf ("unsupported DB (%d) or key type (%d)",
	                  arg->type, arg->key.type);
    sbp->replyref (res);
    return;
  }

  sfs_namevers *nv = arg->key.namevers;
  sfsauth_dbkey key (SFSAUTH_DBKEY_NAME);
  *key.name = nv->name;

  if (get_group_cursor (&dbp, NULL, &res, key)) {
    sfs_groupmembers updates;
    unsigned int latest;

    if (nv->vers
	&& (latest = read_group_changelog (nv->name, nv->vers, updates))) {
      bool more = res.groupinfo->vers > latest;
      // sfs_time refresh = res.groupinfo->refresh;
      // sfs_time timeout = res.groupinfo->timeout;
      sfs_time refresh = extract_u_int_default (refresh_eq,
						res.groupinfo->properties,
						dbp->default_refresh);
      sfs_time timeout = extract_u_int_default (timeout_eq,
						res.groupinfo->properties,
						dbp->default_timeout);

      if (dbp->hide_users && !is_authenticated (sbp))
	obfuscate_group (updates, true);

      res.set_type (SFSAUTH_LOGENTRY);
      res.logentry->vers = latest;
      res.logentry->members = updates;
      res.logentry->more = more;
      res.logentry->refresh = refresh;
      res.logentry->timeout = timeout;
      res.logentry->audit = strbuf () << "Changes for group `" << nv->name
	                    << "' from version " << nv->vers << " to " << latest;
    }
    else {
      // if read_group_changelog fails, we return the full group record
      query_group (sbp);
      return;
    }
  }
  sbp->replyref (res);
}

void
authclnt::sfsauth_query (svccb *sbp)
{
  sfsauth2_query_arg *arg = sbp->Xtmpl getarg<sfsauth2_query_arg> ();
  switch (arg->type) {
  case SFSAUTH_USER:
    query_user (sbp);
    break;
  case SFSAUTH_GROUP:
    query_group (sbp);
    break;
  case SFSAUTH_CERTINFO:
    query_certinfo (sbp);
    break;
  case SFSAUTH_SRPPARMS:
    query_srpparms (sbp);
    break;
  case SFSAUTH_EXPANDEDGROUP:
    query_expandedgroup (sbp);
    break;
  case SFSAUTH_LOGENTRY:
    query_changelog (sbp);
    break;
  default:
    sfsauth2_query_res res;
    res.set_type (SFSAUTH_ERROR);
    *res.errmsg = strbuf ("unsupported query type %d", arg->type);
    sbp->replyref (res);
    break;
  }
}

void
authclnt::sfs_login (svccb *sbp)
{
  if (!authid_valid) {
    sbp->replyref (sfs_loginres (SFSLOGIN_ALLBAD));
    return;
  }
  sfsauth2_loginarg la;
  la.arg = *sbp->Xtmpl getarg<sfs_loginarg> ();
  la.authid = authid;
  la.source = client_name << "!" << progname;

  sfsauth_login (&la, wrap (this, &authclnt::sfs_login_2, sbp), true);
}

void
authclnt::sfs_login_2 (svccb *sbp, sfsauth2_loginres *resp,
		       sfs_authtype atype, const sfsauth_dbrec *dbrp)
{
  sfs_loginarg *lap = sbp->Xtmpl getarg<sfs_loginarg> ();
  sfsauth2_loginres &lr = *resp;

  sfs_loginres res (lr.status);
  switch (lr.status) {
  case SFSLOGIN_OK:
    if (!seqstate.check (lap->seqno) || lr.resok->creds.size () < 1)
      res.set_status (SFSLOGIN_BAD);
    else {
      u_int32_t authno;
      authno = authalloc (lr.resok->creds.base (), 
			  lr.resok->creds.size ());
      if (!authno) {
	warn << "ran out of authnos (or bad cred type)\n";
	res.set_status (SFSLOGIN_BAD);
      }
      else {
	utab_insert (authno, atype, *dbrp);
	res.resok->authno = authno;
	res.resok->resmore = resp->resok->resmore;
	res.resok->hello = resp->resok->hello;
      }
    }
    break;
  case SFSLOGIN_MORE:
    *res.resmore = *lr.resmore;
    break;
  default:
    break;
  }

  sbp->replyref (res);
}

void
authclnt::utab_insert (u_int32_t authno, sfs_authtype at,
		       const sfsauth_dbrec &dbr)
{
  urec_t *u = utab[authno];
  if (u) 
    urecfree (u);
  urec_t *ur = New urec_t (authno, at, dbr);
  utab.insert (ur);
  ulist.insert_head (ur);
}

void
authclnt::sfs_logout (svccb *sbp)
{
  u_int32_t authno = *sbp->Xtmpl getarg<u_int32_t> ();
  urec_t *u = utab[authno];
  if (u) 
    urecfree (u);
  sfsserv::sfs_logout (sbp);
}

inline bool
sourceok (str source)
{
  for (u_int i = 0; i < source.len (); i++)
    if (source[i] < 0x20 || source[i] >= 0x7f)
      return false;
  return true;
}

// XXX - this function doesn't make sense for multi-round authentication
inline str
arg2user (const sfs_autharg2 &aa)
{
  str user;
  switch (aa.type) {
  case SFS_AUTHREQ2:
    user = aa.sigauth->req.user;
    break;
  case SFS_UNIXPWAUTH:
    user = aa.pwauth->req.user;
    break;
  case SFS_SRPAUTH:
    user = aa.srpauth->req.user;
    break;
  default:
    user = "";
    break;
  }

  for (const char *p = user; *p; p++)
    if (*p <= ' ' || *p >= 127) {
      user = "";
      break;
    }
  if (user.len ())
    return user;

  switch (aa.type) {
  case SFS_AUTHREQ:
    if (ptr<sfspub> pk = sfscrypt.alloc (aa.authreq1->usrkey))
      user = strbuf ("keyhash ") << armor32 (pk->get_pubkey_hash ());
    break;
  case SFS_AUTHREQ2:
    if (ptr<sfspub> pk = sfscrypt.alloc (aa.sigauth->key))
      user = strbuf ("keyhash ") << armor32 (pk->get_pubkey_hash ());
    break;
  default:
    break;
  }

  if (!user || !user.len ())
    user = "<unknown user>";
  return user;
}

static str
method_str (sfs_authtype atype)
{
  switch (atype) {
  case SFS_AUTHREQ:
    return "old-style public key";
  case SFS_AUTHREQ2:
    return "public key";
  case SFS_UNIXPWAUTH:
    return "unix password";
  case SFS_SRPAUTH:
    return "SRP password";
  default:
    return "unknown auth method";
  }
}

void
authclnt::sfsauth_login (const sfsauth2_loginarg *lap,
			 logincb_t cb, bool self)
{
  sfs_autharg2 aa;
  sfsauth2_loginres res (SFSLOGIN_BAD);
  if (!sourceok (lap->source)) {
    *res.errmsg = "invalid source in login request";
    (*cb) (&res, SFS_NOAUTH, NULL);
    return;
  }
  if (!bytes2xdr (aa, lap->arg.certificate)) {
    *res.errmsg = "cannot unmarshal certificate";
    (*cb) (&res, SFS_NOAUTH, NULL);
    return;
  }

  if (authpending *ap = aptab[lap->authid]) {
    if (lap->arg.seqno == ap->seqno && aa.type == ap->atype) {
      ap->next (&aa, wrap (this, &authclnt::sfsauth_login_2, lap->source, cb));
      return;
    }
    warn << "canceling incomplete " << method_str (ap->atype)
	 << " login from " << lap->source << "\n";
    delete ap;
  }

  switch (aa.type) {
  case SFS_AUTHREQ:
  case SFS_AUTHREQ2:
    login_sigauth (lap, &aa, self, wrap (this, &authclnt::sfsauth_login_2,
					 lap->source, cb));
    return;
  case SFS_UNIXPWAUTH:
    login_unixpw (lap, &aa, self, wrap (this, &authclnt::sfsauth_login_2,
					lap->source, cb));
    return;
  case SFS_SRPAUTH:
    if (self || (uid && !*uid)) {
      login_srp (lap, &aa, self, wrap (this, &authclnt::sfsauth_login_2,
				       lap->source, cb));
      return;
    }
    else
      *res.errmsg = "SRP authentication of client to third party not allowed";
    break;
  case SFS_NOAUTH:
    *res.errmsg = "no authentication";
    (*cb) (&res, aa.type, NULL);
    return;
  default:
    *res.errmsg = strbuf ("unknown login type %d", aa.type);
    break;
  }

  sfsauth_login_2 (lap->source, cb, &res, aa.type, NULL);
}

void
authclnt::sfsauth_login_2 (str source, logincb_t cb,
			   sfsauth2_loginres *resp, sfs_authtype atype,
			   const sfsauth_dbrec *dbrp)
{
  str method = method_str (atype);
  if (resp->status == SFSLOGIN_OK && !resp->resok->creds.size ())
    resp->set_status (SFSLOGIN_BAD);
  if (resp->status == SFSLOGIN_OK) {
    if (resp->resok->creds[0].type == SFS_UNIXCRED)
      warn << "accepted user " << resp->resok->creds[0].unixcred->username
	   << " from " << source
	   << " using " << method << "\n";
    else if (resp->resok->creds[0].type == SFS_PKCRED)
      warn << "accepted pubkey " << *resp->resok->creds[0].pkhash
	   << " from " << source
	   << " using " << method << "\n";
  }
  else if (resp->status == SFSLOGIN_BAD) {
    str msg;
    if (resp->errmsg->len ())
      msg = strbuf () << " (" << *resp->errmsg << ")";
    else
      msg = "";

    str foruser = "";
    if (dbrp && dbrp->type == SFSAUTH_USER) {
      if (dbrp->userinfo->name.len ())
	foruser = strbuf () << " for " << dbrp->userinfo->name;
      else if (ptr<sfspub> pk = sfscrypt.alloc (dbrp->userinfo->pubkey))
	foruser = strbuf () << " for keyhash "
			    << armor32 (pk->get_pubkey_hash ());
    }

    warn << "BAD login" << foruser << " from " << source
	 << " using " << method << msg << "\n";
  }
  (*cb) (resp, atype, dbrp);
}

bool
authclnt::authreq_validate (sfsauth2_loginres *resp,
			    const sfsauth2_loginarg *lap,
			    const sfs_authreq2 &areq, bool nocred)
{
  if (areq.type != SFS_SIGNED_AUTHREQ
      && (!nocred || areq.type == SFS_SIGNED_AUTHREQ_NOCRED)) {
    resp->set_status (SFSLOGIN_BAD);
    *resp->errmsg = "malformed authentication request (bad type)";
    return false;
  }
  if (areq.authid != lap->authid) {
    resp->set_status (SFSLOGIN_BAD);
    *resp->errmsg = "bad authid in authentication request";
    return false;
  }
  if (areq.seqno != lap->arg.seqno) {
    resp->set_status (SFSLOGIN_BAD);
    *resp->errmsg = "sequence number mismatch in authentication request";
    return false;
  }
  return true;
}

void
authclnt::login_sigauth (const sfsauth2_loginarg *lap, const sfs_autharg2 *aap,
			 bool self, logincb_t cb)
{
  sfsauth2_loginres res (SFSLOGIN_BAD);
  ptr<sfspub> vrfy;
  sfs_msgtype mtype;
  str logname;

  if (aap->type == SFS_AUTHREQ) {
    const sfs_pubkey &kp = aap->authreq1->usrkey;
    if (!(vrfy = sfscrypt.alloc (kp, SFS_VERIFY))) {
      badauth (cb, aap->type, "cannot load public Rabin key", NULL);
      return;
    }
    sfs_signed_authreq authreq;
    str msg;
    if (!vrfy->verify_r (aap->authreq1->signed_req, sizeof (authreq), msg)
	|| !str2xdr (authreq, msg)
	|| (authreq.type != SFS_SIGNED_AUTHREQ && 
	    authreq.type != SFS_SIGNED_AUTHREQ_NOCRED)
	|| authreq.seqno != lap->arg.seqno
	|| authreq.authid != lap->authid) {
      badauth (cb, aap->type, "bad signature", vrfy);
      return;
    }
    mtype = authreq.type;
    if (authreq.usrinfo[0]) {
      if (memchr (authreq.usrinfo.base (), 0, authreq.usrinfo.size ()))
	logname = authreq.usrinfo.base ();
      else
	logname.setbuf (authreq.usrinfo.base (), authreq.usrinfo.size ());
    }
  }
  else {
    if (aap->sigauth->req.user.len ())
      logname = aap->sigauth->req.user;
    mtype = aap->sigauth->req.type;
    str e;
    if (!(vrfy = sfscrypt.alloc (aap->sigauth->key, SFS_VERIFY))) {
      badauth (cb, aap->type, "cannot load public key", NULL);
      return; 
    }
    if (!vrfy->verify (aap->sigauth->sig,
			    xdr2str (aap->sigauth->req), &e)) {
      badauth (cb, aap->type, e, vrfy);
      return;
    }
    if (!authreq_validate (&res, lap, aap->sigauth->req, true)) {
      (*cb) (&res, aap->type, NULL);
      return;
    }
  }

  for (dbfile *dbp = dbfiles.base (); dbp < dbfiles.lim (); dbp++) {
    ptr<authcursor> ac = dbp->db->open (dbp->dbflags);
    // XXX - in long form for aiding in debugging
    if (!ac)
      continue;
    if (!ac->find_user_pubkey (*vrfy))
      continue;
    if (ac->ae.type != SFSAUTH_USER)
      continue;
    if (logname) {
      if (dbp->prefix) {
	if (logname != dbp->prefix << "/" << ac->ae.userinfo->name) 
	  continue;
      } else {
	if (logname != ac->ae.userinfo->name)
	  continue;
      }
    }

    if (!(*vrfy == ac->ae.userinfo->pubkey))
      continue;

    if (mtype == SFS_SIGNED_AUTHREQ_NOCRED) {
      res.set_status (SFSLOGIN_OK);
      res.resok->creds.setsize (1);
      res.resok->creds[0].set_type (SFS_NOCRED);
    }
    else {
      if (!setuser (&res, ac->ae, dbp))
	continue;
      setuser_pkhash (&res, vrfy);
      setuser_groups (&res, &ac->ae, dbp, vrfy);
    }
    (*cb) (&res, aap->type, &ac->ae);
    return;
  }

  if (mtype != SFS_SIGNED_AUTHREQ_NOCRED) {
    res.set_status (SFSLOGIN_OK);
    setuser_pkhash (&res, vrfy);
    setuser_groups (&res, NULL, NULL, vrfy);
    (*cb) (&res, aap->type, NULL);
  }
  else
    badauth (cb, aap->type, "signed login of type AUTHREQ_NOCRED", vrfy);
}

inline dbfile *
pwdb ()
{
  static bool initialized;
  static dbfile *unix_dbp;
  if (!initialized) {
    for (dbfile *dbp = dbfiles.base ();
	 !unix_dbp && dbp < dbfiles.lim (); dbp++)
      if (dbp->allow_unix_pwd)
	unix_dbp = dbp;
    initialized = true;
  }
  return unix_dbp;
}

void
authclnt::login_unixpw (const sfsauth2_loginarg *lap, const sfs_autharg2 *aap,
			bool self, logincb_t cb)
{
  str2wstr (aap->pwauth->password);
  sfsauth2_loginres res;
  if (!authreq_validate (&res, lap, aap->pwauth->req)) {
    (*cb) (&res, aap->type, NULL);
    return;
  }
  if (!self || !uid) {	// This is safest, but debatable
    badauth (cb, aap->type, "remote unix-style login disallowed",
	     aap->pwauth->req.user);
    return;
  }
  dbfile *dbp = pwdb ();
  if (!dbp) {
    badauth (cb, aap->type, "Unix password authentication not allowed",
	     aap->pwauth->req.user);
    return;
  }

  str pwd = aap->pwauth->password;
  if (!pwd.len () && self && uid && !*uid)
    pwd = NULL;

  ptr<authcursor> ac = dbp->db->open (dbp->dbflags);
  if (!ac) {
    badauth (cb, aap->type, "authentication database error",
	     aap->pwauth->req.user);
    return;
  }

  str unixname;
  if (ac->find_user_name (aap->pwauth->req.user)) {
    unixname = unixpriv (ac->ae.userinfo->privs);
    if (!unixname) // For compatibility before unix= priv
      unixname = aap->pwauth->req.user;
    if (unixname && unixname != aap->pwauth->req.user) {
      /*  Note:  This policy is arguable, but the idea is that if you
       *  have multiple public keys mapped to the same Unix account,
       *  you don't necessarily want different users to be able to
       *  muck with each other's keys through sfskey register, even if
       *  they are all accessing the file system with the same UID.
       */ 
      badauth (cb, aap->type,
	       strbuf ("password login to %s rejected for"
		       " mismatched unix=%s priv\n",
		       aap->pwauth->req.user.cstr (), unixname.cstr ()),
	       &ac->ae);
      return;
    }
  }
  else {
    unixname = aap->pwauth->req.user;
    ac->ae.set_type (SFSAUTH_ERROR);
  }

  if (pwd && auth_helper) {
    authpending_helper *ahp (New authpending_helper (this, lap));
    ahp->ah_ac = ac;
    ahp->init (aap, cb);
  }
  else
    login_unixpw_2 (ac, unixname, pwd, self, cb);
}

void
authclnt::login_unixpw_2 (ref<authcursor> ac, str unixname,
			  str pwd, bool self, logincb_t cb)
{
  dbfile *dbp = pwdb ();
  assert (dbp);

  str err;
  struct passwd *pe = unix_user (unixname, pwd, &err);
  if (!pe) {
    if (ac->ae.type == SFSAUTH_USER)
      badauth (cb, SFS_UNIXPWAUTH, err, &ac->ae);
    else
      badauth (cb, SFS_UNIXPWAUTH, err, unixname);
    return;
  }
  /* The following is debatable, but safer to deny than allow... */
  if (uid && *uid && *uid != pe->pw_uid) {
    badauth (cb, SFS_UNIXPWAUTH, strbuf ("user %s does not match uid %d",
					 pe->pw_name, *uid), &ac->ae);
    return;
  }

  if (ac->ae.type != SFSAUTH_USER) {
    if ((!self || !uid || *uid) && !validshell (pe->pw_shell)) {
      badauth (cb, SFS_UNIXPWAUTH, "bad shell", unixname);
      return;
    }
    ac->ae.set_type (SFSAUTH_USER);
    ac->ae.userinfo->name = pe->pw_name;
    ac->ae.userinfo->id = pe->pw_uid;
    ac->ae.userinfo->vers = 0;
    ac->ae.userinfo->gid = pe->pw_gid;
    ac->ae.userinfo->privs = strbuf ("unix=%s,refresh=%d,timeout=%d",
				     pe->pw_name, dbp->default_refresh,
				     dbp->default_timeout);
  }

  sfsauth2_loginres res;
  bool ok = setuser (&res, ac->ae, dbp);
  if (ok)
    res.resok->resmore = mkname (dbp, ac->ae.userinfo->name);
  (*cb) (&res, SFS_UNIXPWAUTH, ok ? &ac->ae : NULL);
}


void
authclnt::login_srp (const sfsauth2_loginarg *lap, const sfs_autharg2 *aap,
		   bool self, logincb_t cb)
{
  sfsauth2_loginres res;
  if (!authreq_validate (&res, lap, aap->srpauth->req)) {
    (*cb) (&res, aap->type, NULL);
    return;
  }
  if ((!uid || *uid) && lap->authid != authid) {
    // SRP auth is mutual, so only root daemons
    badauth (cb, aap->type, "third-party SRP authentication refused",
	     aap->srpauth->req.user);
    return;
  }
  (New authpending_srp (this, lap))->init (aap, cb);
}

str
authclnt::update_srv_keyhalf (const sfsauth_keyhalf &updkh,
			      sfsauth_keyhalf &newkh,
			      const sfsauth_keyhalf &oldkh,
			      bool canclear, urec_t *ur)
{
  bool hasoldkh = false;
  const sfsauth_keyhalf_type &kht = updkh.type;
  if (kht == SFSAUTH_KEYHALF_NONE)
    return NULL;

  newkh.set_type (SFSAUTH_KEYHALF_PRIV);
  u_int okeys = 0;
  if (oldkh.type == SFSAUTH_KEYHALF_PRIV)
    okeys =  oldkh.priv->size ();
  u_int nkeys;
  if (oldkh.type == SFSAUTH_KEYHALF_PRIV && okeys >= 1) {
    hasoldkh = true;
    if (kht == SFSAUTH_KEYHALF_DELTA) {
      nkeys = okeys;
      for (u_int i = 1; i < okeys; i++) 
	(*newkh.priv)[i] = (*oldkh.priv)[i];
    } else {
      nkeys = (okeys == SPRIVK_HISTORY_LEN) ? okeys : okeys + 1;
      newkh.priv->setsize (nkeys);
      for (u_int i = 1; i < nkeys; i++)
	(*newkh.priv)[i] = (*oldkh.priv)[i-1];
    }
  } else {
    nkeys = 1;
    newkh.priv->setsize (1);
  }

  if (kht == SFSAUTH_KEYHALF_DELTA) {
    if (!hasoldkh) 
      return "Cannot apply key delta: no key currently exists!";
    (*newkh.priv)[0] = (*oldkh.priv)[0];
    (*newkh.priv)[0].x += *updkh.delta;
    (*newkh.priv)[0].x %= (*newkh.priv)[0].q;
    sprivk_tab.invalidate (hash_sprivk ((*oldkh.priv)[0]));
    sprivk_tab.bind (hash_sprivk ((*newkh.priv)[0]));
  } else if (kht == SFSAUTH_KEYHALF_PRIV) {
    if (!canclear)
      return "Can only explicitly set server keyhalf on register or signed "
	     "update.";
    if (nkeys == okeys) 
      sprivk_tab.invalidate (hash_sprivk ((*oldkh.priv)[okeys - 1]));
    (*newkh.priv)[0] = (*updkh.priv)[0];
    sprivk_tab.bind (hash_sprivk ((*newkh.priv)[0]));
  }
  ur->kh = newkh;
  
  return NULL;
}

bool
get_user_cursor (dbfile **dbpp, ptr<authcursor> *acp,
		 sfsauth_dbrec *dbrp, const sfsauth_dbkey &key,
		 bool writable)
{
  if (key.type != SFSAUTH_DBKEY_NAME && key.type != SFSAUTH_DBKEY_ID
      && key.type != SFSAUTH_DBKEY_PUBKEY) {
    if (dbrp) {
      dbrp->set_type (SFSAUTH_ERROR);
      *dbrp->errmsg = strbuf ("unsupported key type %d", key.type);
    }
    return false;
  }
  ptr<sfspub> pk;
  for (dbfile *dbp = dbfiles.base (); dbp < dbfiles.lim (); dbp++) {
    if (writable && !dbp->allow_update)
      continue;
    u_int flags = dbp->dbflags;
    if (writable)
      flags |= authdb::AUDB_WRITE;
    ptr<authcursor> ac = dbp->db->open (flags);
    if (!ac)
      continue;
    switch (key.type) {
    case SFSAUTH_DBKEY_NAME:
      {
	struct passwd *pw;
	str name = dbp->strip_prefix (*key.name);
	if (!name)
	  continue;
	else if (ac->find_user_name (name))
	  break;
	else if (dbp->allow_unix_pwd && (pw = getpwnam (name))) {
	  sfsauth_dbrec rec (SFSAUTH_USER);
	  rec.userinfo->name = *key.name;
	  rec.userinfo->id = pw->pw_uid;
	  rec.userinfo->vers = 0;
	  rec.userinfo->gid = pw->pw_gid;
	  rec.userinfo->privs = strbuf ("unix=%s,refresh=%d,timeout=%d",
					pw->pw_name, dbp->default_refresh,
					dbp->default_timeout);
	  ac->ae = rec;
	  break;
	} else 
	  continue;
      }
    case SFSAUTH_DBKEY_ID:
      {
	u_int32_t id = dbp->uidmap ? dbp->uidmap->unmap (*key.id) : *key.id;
	if (id == badid || !ac->find_user_uid (id)) {
	  struct passwd *pw;
	  if (dbp->allow_unix_pwd && (pw = getpwuid (*key.id))) {
	    sfsauth_dbrec rec (SFSAUTH_USER);
	    rec.userinfo->name = pw->pw_name;
	    rec.userinfo->id = pw->pw_uid;
	    rec.userinfo->vers = 0;
	    rec.userinfo->gid = pw->pw_gid;
	    rec.userinfo->privs = strbuf ("unix=%s,refresh=%d,timeout=%d",
					  pw->pw_name, dbp->default_refresh,
					  dbp->default_timeout);
	    ac->ae = rec;
	    break;
	  }
	  continue;
	}
	break;
      }
    case SFSAUTH_DBKEY_PUBKEY:
      if (!pk) {
	if (!(pk = sfscrypt.alloc (*key.key))) {
	  warn << "Cannot import user public key.\n";
          if (dbrp) {
            dbrp->set_type (SFSAUTH_ERROR);
            *dbrp->errmsg = "cannot import user public key";
          }
	  return false;
	}
      }
      if (!(ac->find_user_pubkey (*pk) && *pk == ac->ae.userinfo->pubkey))
	continue;
      break;
    default:
      panic ("unreachable\n");
    }
    if (dbp->allow_unix_pwd)
      if (str u = unixpriv (ac->ae.userinfo->privs))
	if (struct passwd *pw = getpwnam (u)) {
	  if (ac->ae.userinfo->id != pw->pw_uid) {
	    warn << "overriding uid " << ac->ae.userinfo->id << " with "
		 << pw->pw_uid << " for unix privs " << u << "\n";
	    ac->ae.userinfo->id = pw->pw_uid;
	  }
	  if (ac->ae.userinfo->gid != pw->pw_gid) {
	    warn << "overriding gid " << ac->ae.userinfo->gid << " with "
		 << pw->pw_gid << " for unix privs " << u << "\n";
	    ac->ae.userinfo->gid = pw->pw_gid;
	  }
	}
    if (dbpp)
      *dbpp = dbp;
    if (acp)
      *acp = ac;
    if (dbrp) {
      *dbrp = ac->ae;
      aesanitize (dbrp, AE_QUERY);
      if (dbp->prefix)
	dbrp->userinfo->name = dbp->prefix << "/" << dbrp->userinfo->name;
      if (dbp->uidmap)
	dbrp->userinfo->id = dbp->uidmap->map (dbrp->userinfo->id);
      if (dbrp->userinfo->id == badid)
	continue;
      if (dbp->gidmap)
	dbrp->userinfo->gid = dbp->gidmap->map (dbrp->userinfo->gid);
    }
    return true;
  }
  if (dbrp) {
    dbrp->set_type (SFSAUTH_ERROR);
    *dbrp->errmsg = "user not found";
  }
  return false;
}

bool
get_group_cursor (dbfile **dbpp, ptr<authcursor> *acp,
                  sfsauth_dbrec *dbrp, const sfsauth_dbkey &key,
                  bool writable, bool create)
{
  if (key.type != SFSAUTH_DBKEY_NAME && key.type != SFSAUTH_DBKEY_ID) {
    if (dbrp) {
      dbrp->set_type (SFSAUTH_ERROR);
      *dbrp->errmsg = strbuf ("unsupported key type %d", key.type);
    }
    return false;
  }
  for (dbfile *dbp = dbfiles.base (); dbp < dbfiles.lim (); dbp++) {
    if (writable && (!dbp->allow_update || !dbp->grprange))
      continue;
    u_int flags = dbp->dbflags;
    if (writable)
      flags |= authdb::AUDB_WRITE;
    ptr<authcursor> ac = dbp->db->open (flags);
    if (!ac)
      continue;
    switch (key.type) {
    case SFSAUTH_DBKEY_NAME:
      {
	str name = dbp->strip_prefix (*key.name);
	if (!name)
	  continue;
	else if (ac->find_group_name (name))
	  break;
	else if (create) {
	  u_int32_t gid = ac->alloc_gid (dbp->grprange->id_min,
	                                 dbp->grprange->id_max);
	  sfsauth_dbrec rec (SFSAUTH_GROUP);
	  rec.groupinfo->name = *key.name;
	  rec.groupinfo->id = gid;
	  rec.groupinfo->vers = 0;
	  //rec.groupinfo->refresh = dbp->default_refresh;
	  //rec.groupinfo->timeout = dbp->default_timeout;
	  ac->ae = rec;
	  break;
	} else 
	  continue;
      }
    case SFSAUTH_DBKEY_ID:
      {
	u_int32_t id = dbp->gidmap ? dbp->gidmap->unmap (*key.id) : *key.id;
	if (id == badid || !ac->find_group_gid (id))
	  continue;
	break;
      }
    default:
      panic ("unreachable\n");
    }
    if (dbpp)
      *dbpp = dbp;
    if (acp)
      *acp = ac;
    if (dbrp) {
      *dbrp = ac->ae;
      if (dbp->prefix)
	dbrp->groupinfo->name = dbp->prefix << "/" << dbrp->groupinfo->name;
      if (dbp->gidmap)
	dbrp->groupinfo->id = dbp->gidmap->map (dbrp->groupinfo->id);
      if (dbrp->groupinfo->id == badid)
	continue;
    }
    return true;
  }
  if (dbrp) {
    dbrp->set_type (SFSAUTH_ERROR);
    *dbrp->errmsg = "group not found";  // WARNING: Do not change the text of
                                        // this string; sfsgroupmgr.C uses it

  }
  return false;
}
