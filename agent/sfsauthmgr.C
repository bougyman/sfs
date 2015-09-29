
/* $Id: sfsauthmgr.C,v 1.18 2004/06/01 21:49:21 dm Exp $ */

/*
 *
 * Copyright (C) 1998, 1999 David Mazieres (dm@uun.org)
 * Copyright (C) 1999, 2000 Michael Kaminsky (kaminsky@lcs.mit.edu)
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

#include "agent.h"
#include "sfsschnorr.h"

// XXX - change this into a configuration parameter.  for now, we'll leave
// it at 10 seconds
#define   SESS_TIMEOUT   10

sfsagent_confprog confprog;

bool 
auth_sess_mgr::exists (const authmeth *p) 
{ 
  return amgr->exists (p); 
}

void
auth_sess_mgr::remove (authsess *as)
{
  sq.remove (as);
  sh.remove (as);
  num --;
  delete as;
}

void
auth_sess_mgr::insert (authmeth *m, u_int id)
{
  authsess *as;
  if ((as = sh[id])) {
    as->am = m;
    touch (as);
  } else {
    as = New authsess (m, id);
    num++;
    sq.insert_tail (as);
    sh.insert (as);
    timeout ();
  }
}

void
auth_sess_mgr::timeout (bool cb)
{
  if (!cb && exp_tmo) 
    timecb_remove (exp_tmo);
  exp_tmo = NULL;
  sfs_time now = time (NULL);

  authsess *nas, *as;
  for (as = sq.first; as; as = nas) {
    nas = sq.next (as);
    if (as->expire && as->expire < now) {
      remove (as);
    } else {
      break;
    }
  }
  if (as) {
    exp_tmo = timecb (as->expire, wrap (this, &auth_sess_mgr::timeout, true));
  }
}

// authmethods should be able to exist without an associate authmgr,
// although the applications are very limited. 
bool
authmeth::register_sess(const sfs_authinfo &ai, const sfs_seqno &seqno,
			sfs_hash &h, bool storeit)
{
  if (!amgr) {
    void *b = h.base();
    return sha1_hashxdr (b, ai);
  } else {
    return amgr->asmgr.register_sess (ai, seqno, this, h, storeit);
  }
}
  

bool
auth_sess_mgr::register_sess (const sfs_authinfo &ai, const sfs_seqno &seqno,
			      authmeth *m, sfs_hash &hsh, bool storeit)
{
  u_int id = compute_asid (ai, seqno, hsh);
  if (!id) 
    return false;
  if (storeit)
    insert (m, id);
  return true;
}

u_int
auth_sess_mgr::compute_asid (const sfs_authinfo &ai, const sfs_seqno &seqno, 
			     sfs_hash &h)
{
  void *b = h.base();
  if (!sha1_hashxdr (b, ai)) 
    return 0;
  u_int *p = (u_int *)b;
  u_int ui = p[0];
  ui += seqno;
  return ui;
}

authmeth *
auth_sess_mgr::retrieve (const sfs_authinfo &ai, const sfs_seqno &seqno,
			 sfs_hash &h)
{
  u_int id = compute_asid (ai, seqno, h);
  if (!id)
    return NULL;
  
  authsess *as = sh[id];
  if (!as) 
    return NULL;

  // the authmeth associated might have been remove due to an EOF on the
  // socket or even an sfskey remove
  authmeth *r = as->am;
  if (!exists (r)) {
    delete as;
    return NULL;
  }
  touch (as);
  return r;
}

void
auth_sess_mgr::touch (authsess *as)
{
  as->expire = time (NULL) + SESS_TIMEOUT;
  if (num > 1) {
    sq.remove (as);
    sq.insert_tail (as);
  }
}

authsess::authsess (authmeth *m, u_int i) 
  : am (m), id (i)
{
  expire = time (NULL) + SESS_TIMEOUT;
}

void
authmgr::timeout (bool cb)
{
  if (!cb)
    timecb_remove (exp_tmo);
  exp_tmo = NULL;
  exp_time = 0;
  sfs_time now = time (NULL);
  for (authmeth *k = authmeths.first, *nk; k; k = nk) {
    nk = authmeths.next (k);
    if (k->expire && k->expire <= now) {
      authmeths.remove (k);
      delete k;
    }
    else if (k->expire && (!exp_time || k->expire < exp_time))
      exp_time = k->expire;
  }
  if (exp_time)
    exp_tmo = timecb (exp_time, wrap (this, &authmgr::timeout, true));
}

authmeth *
authmgr::klookup (const sfspub &key)
{
  authmeth *m;
  for (m = authmeths.first; m ; m = m->link.next) {
    if (m->kcmp (key))
      return m;
  }
  return NULL;
}

authmeth *
authmgr::plookup (const int p) 
{
  authmeth *k;
  for (k = authmeths.first; k ; k = k->link.next) {
    if (k->pcmp (p)) 
      return k;
  }
  return NULL;
}

authmeth *
authmgr::clookup (const str &c)
{
  authmeth *k;
  for (k = authmeths.first; k; k = k->link.next)
    if (k->name == c)
      return k;
  return NULL;
}

bool
authmgr::exists (const authmeth *p)
{
  for (authmeth *a = authmeths.first; a; a = a->link.next)
    if (a == p)
      return true;
  return false;
}

authmeth *
authmgr::lookup_by_index (const u_int na)
{
  u_int n = na;
  authmeth *k = authmeths.first;
  while (k && n--)
    k = k->link.next;
  return k;
}

void 
authmgr::remove_all ()
{
  while (authmeth *a = authmeths.first) {
    authmeths.remove (a);
    delete a;
  }
}

void 
authmgr::fill_keylist (sfs_keylist *kl) 
{
  sfs_keylist *klp = kl;

  for (authmeth *a = authmeths.first; a; a = a->link.next) {
    (*klp).alloc ();
    (*klp)->desc = a->get_desc ();
    (*klp)->expire = a->expire;
    (*klp)->name = a->name;
    klp = &(*klp)->next;
  }
}

void
extauth::eofcb (authmgr *a)
{
  eof = true;
  a->remove (this);
  delete this;
}

extauth::extauth (ref<axprt> xx, authmgr *a, extauth_server *s = NULL)
  : x (xx), eas (s)
{
  ac = aclnt::alloc (x, sfsextauth_prog_1);
  ac->seteofcb (wrap (this, &extauth::eofcb, a));
  amgr = a;
  eof = false;
}

extauth::~extauth ()
{
  if (eas) 
    eas->eof ();
}

void
authmgr::authinit (const sfsagent_authinit_arg *aa,
		   sfsagent_auth_res *resp, cbv cb)
{
  assert (resp);
  authmeth *k = lookup_by_index (aa->ntries);
  if (!k || aa->authinfo.type != SFS_AUTHINFO
      || confirm (k, aa,
		  wrap (this, &authmgr::confirmed, k, aa, resp, cb)) < 0) {
    resp->set_authenticate (false);
    (*cb) ();
  }
}

void
authmgr::authmore (const sfsagent_authmore_arg *aa,
		   sfsagent_auth_res *resp, cbv cb)
{
  sfs_hash dummy;
  /* XXX - this looks dangerous because it potentially allows one
   * client of the agent to hijack a pending authentication of a
   * different client.  While in practice the worst I can see how to
   * do is to disrupt an authentication that should succeed, it still
   * seems like a bad architecture.  The asmgr should probably be per
   * sfsagent structure, not per authmgr.  -dm */
  authmeth *k = asmgr.retrieve (aa->authinfo, aa->seqno, dummy);
  if (!k || aa->authinfo.type != SFS_AUTHINFO) {
    /* XXX - we should probably default to false in the case of
     * checkserver, but that would require a more intelligent scheme
     * for garbage-collecting authmeth structures. */ 
    resp->set_authenticate (aa->checkserver);
    (*cb) ();
    return;
  }
  k->authmore(aa, resp, cb);
}

pid_t
authmgr::confirm (authmeth *k, const sfsagent_authinit_arg *aa, cbi cb)
{
  if (confprog.empty ()) {
    (*cb) (0);
    return 0;
  }

  str keys_s = "";
  str keyname = k->name;
  str requestor = aa->requestor;
  str request = strbuf () << "@" << aa->authinfo.name  << ","
    << armor32 (str (aa->authinfo.hostid.base (),
                     aa->authinfo.hostid.size ()));
  strbuf servicebuf;
  print_sfs_service (&aa->authinfo.service, &servicebuf, 0, NULL, NULL);
  str service (servicebuf);

  for (authmeth *a = authmeths.first; a; a = a->link.next)
    keys_s = keys_s << a->name << " ";

#if 0
  str msg = strbuf ()
    << "\n*****  SFS Authentication Request  *****\n"
    << "----------------------------------------"
    << "\n\n"
    << "     KEY NAME: " << keyname
    << "\n"
    << "   OTHER KEYS: " << keys_s
    << "\n\n"
    << " REQUEST FROM: " << requestor
    << "\n"
    << "    TO ACCESS: " << request
    << "\n"
    << " WITH SERVICE: " << service
    << "\n";
  warn << msg;
#endif

#if 0
  // XXX: Should this test just be in the external program for consistency?
  char *p = strrchr (requestor, '@');
  if (p && !strcmp (p, "@LOCALHOST")) {
    warn << "automatically signing authentication request from local machine\n";
    confirmed (s, k, aa, 0);
    return 0;
  }
#endif

  vec<char *> av;
  for (u_int i = 0; i < confprog.size (); i++)
    av.push_back (const_cast<char *> (confprog[i].cstr ()));
  av.push_back (const_cast<char *> (requestor.cstr ()));
  av.push_back (const_cast<char *> (request.cstr ()));
  av.push_back (const_cast<char *> (service.cstr ()));
  av.push_back (const_cast<char *> (keyname.cstr ()));
  for (authmeth *a = authmeths.first; a; a = a->link.next)
    av.push_back (const_cast<char *> (a->name.cstr ()));
  av.push_back (NULL);

  pid_t pid = aspawn (av[0], av.base ());
  if (pid < 0)
    warn ("Error forking confirm command: %s: %m\n", av[0]);
  else
    chldcb (pid, cb);
  return pid;
}

void
authmgr::confirmed (authmeth *k, const sfsagent_authinit_arg *aa,
		    sfsagent_auth_res *resp, cbv cb, int status)
{
  if (!WIFEXITED (status))
    warn ("Confirmation process did not exit normally.\n");
  else if (WEXITSTATUS (status))
    warn ("Authentication request denied\n");
  else {
    k->authwarn (aa);
    k->authinit (aa, resp, cb);
    return;
  }
  resp->set_authenticate (false);
  (*cb) ();
}

void
extauth::authinit (const sfsagent_authinit_arg *aa,
		   sfsagent_auth_res *res, cbv cb)
{
  sfsextauth_init arg;
  arg.autharg = *aa;
  arg.name = name;

  sfs_hash dummy;
  if (!register_sess (aa->authinfo, aa->seqno, dummy, true)) {
    warn ("sfsagent::authinit: xdr failed\n");
    res->set_authenticate (false);
    (*cb) () ;
  } else {
    ac->call (SFSEXTAUTH_AUTHINIT, &arg, res, 
	      wrap (this, &extauth::eacb, res, cb, destroyed));
  }
}

void
extauth::authmore (const sfsagent_authmore_arg *aa,
		   sfsagent_auth_res *res, cbv cb)
{
  sfsextauth_more arg;
  arg.autharg = *aa;
  arg.name = name;
  ac->call (SFSEXTAUTH_AUTHMORE, &arg, res,
	    wrap (this, &extauth::eacb, res, cb, destroyed));
}

void
authmeth::authwarn (const sfsagent_authinit_arg *aa) 
{
  warn << name << "!" << aa->requestor << ": @" 
       << aa->authinfo.name  << ","
       << armor32 (str (aa->authinfo.hostid.base (),
			aa->authinfo.hostid.size ()))
       << " (" << implicit_cast<int> (aa->authinfo.service) << ")\n";
}


// call back after external agent responds
void
extauth::eacb (sfsagent_auth_res *res, cbv cb, ref<bool> dest, clnt_stat err)
{
  if (*dest || err)
    res->set_authenticate (false);
  (*cb) ();
}

