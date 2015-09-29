/* $Id: agentrex.C,v 1.71 2004/06/01 23:03:06 dbg Exp $ */

/*
 *
 * Copyright (C) 2004 David Mazieres (dm@uun.org)
 * Copyright (C) 2000 Michael Kaminsky (kaminsky@lcs.mit.edu)
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

#include "aios.h"
#include "sfsmisc.h"
#include "sfsconnect.h"
#include "list.h"
#include "agentrex.h"
#include "rexcommon.h"

ihash<str, rexsess, &rexsess::path, &rexsess::link> sesstab;

void
knockout (rexsess *rs)
{
  close (rs->sessconn->x->reclaim ());
}

void
subvert ()
{
  sesstab.traverse (wrap (knockout));
}

timecb_t *
backoff (time_t &delay, time_t initdelay, time_t maxdelay, cbv::ref cb)
{
  timecb_t *tcb = delaycb (delay, cb);
  delay = delay ? min<time_t> (delay * 2, maxdelay) : initdelay;
  return tcb;
}

rexsess::rexsess (str dest, str path, str pathfrom,
                  bool forwardagent, bool blockactive, bool resumable,
                  cb_rex::ptr firstcb)
  : clients (0), resumable_clients (0), reaper (NULL),
    afpending (false), sess (NULL), probecall (NULL),
    probetmo (NULL), destroyed (New refcounted<bool> (false)),
    agentforwarded (false),
    dest (dest), path (path), rexconnect_origin (pathfrom)
{
  if (const char *p = strchr (dest, '@'))
    destuser = str (dest.cstr (), p - dest.cstr ());
  else
    destuser = "";

  rex_seqno = 1;

  connect_init ();
  connect (true);

  if (firstcb)
    rex_request (forwardagent, blockactive, resumable, firstcb);
}

rexsess::~rexsess ()
{
  assert (!*destroyed);
  *destroyed = true;

  rpc_wipe (skeys);
  rpc_wipe (ckeys);

  if (sesstab[path])
    sesstab.remove (this);

  connect_cancel ();

  if (probecall)
    probecall->cancel ();
  if (reaper)
    timecb_remove (reaper);

  delete sess;
}

void
rexsess::connect_init ()
{
  backoffcb = NULL;
  conpending = NULL;
  rcpending = NULL;
  cbase = NULL;
  resumepending = NULL;
}

inline bool
rexsess::connecting ()
{
  return backoffcb || conpending || rcpending || cbase || resumepending;
}

void
rexsess::connect_cancel ()
{
  if (backoffcb) {
    timecb_remove (backoffcb);
    backoffcb = NULL;
  }
  if (conpending) {
    conpending->cancel ();
    conpending = NULL;
  }
  if (rcpending) {
    rcpending->cancel ();
    rcpending = NULL;
  }
  if (cbase) {
    cbase->cancel ();
    cbase = NULL;
  }
  if (resumepending) {
    resumepending->cancel ();
    resumepending = NULL;
  }
}

void
rexsess::connect (bool force)
{
  assert (!connecting ());
  retry_delay = 15;
  connect_inner (force);
}

void
rexsess::connect_inner (bool force)
{
  backoffcb = NULL;

  if (sessconn && sess)
    rcpending = sfs_reconnect (sessconn,
			       wrap (this, &rexsess::connected, force),
			       force);
  else
    conpending = sfs_connect_path (path, SFS_REX,
				   wrap (this, &rexsess::connected, force),
				   true, true, &gmgr, destuser);
}

void
rexsess::connected (bool force, ptr<sfscon> sc, str err)
{
  rcpending = NULL;
  conpending = NULL;

  if (!force && active (probetime)) {
    sc = NULL;
    alert_active ();
    sess->silence_tmo_reset ();
    sess->silence_tmo_enable ();
    return;
  }

  if (!sc) {
    alert_badconnect ();
    if (sess && sess->getresumable () && reqs.size ()) {
      // warn << path << ": failed (" << err << "); retrying\n";
      backoffcb = backoff (retry_delay, 15, 3600,
                           wrap (this, &rexsess::connect_inner, force));
    }
    else {
      warn << path << ": failed (" << err << ")\n";
      fail ();
    }
    return;
  }

  if (sc == sessconn) {
    // warn << "no need to reconnect\n";
    backoffcb = backoff (retry_delay, 15, 3600,
                         wrap (this, &rexsess::connect_inner, force));
    return;
  }

  sessconn = sc;
  sessclnt = aclnt::alloc (sc->x, rexd_prog_1);
  sfsclnt = aclnt::alloc (sc->x, sfs_program_1);

  if (sess)
    attach ();
  else {
    if (!sc->encrypting || !sc->auth)
      conpending = sfs_connect_crypt (sc,
                                      wrap (this, &rexsess::connected_crypt,
                                            force),
                                      &gmgr, destuser);
    else
      spawn ();
  }
}

void
rexsess::connected_crypt (bool force, ptr<sfscon> sc, str err)
{
  if (sc)
    connected (force, sc, err);
  else {
    warn << path << ": permission denied: " << err << "\n";
    fail ();
  }
}

void
rexsess::spawn ()
{
  assert (!sess);

  if (!sessconn->encrypting) {
    conpending = sfs_connect_crypt (sessconn,
				    wrap (this, &rexsess::connected, true),
				    &gmgr, destuser);
    return;
  }

  rnd.getbytes (ckeys.kcs_share.base (), ckeys.kcs_share.size ());
  rnd.getbytes (ckeys.ksc_share.base (), ckeys.ksc_share.size ());

  rexd_spawn_arg arg;
  arg.kmsg = ckeys;
  arg.command.setsize (1);
  arg.command[0] = "proxy";
  if (agent_id) {
    arg.command.push_back ("-i");
    arg.command.push_back (agent_id);
  }

  ref<rexd_spawn_res> resp (New refcounted<rexd_spawn_res>);
  cbase = sessclnt->call (REXD_SPAWN, &arg, resp,
			  wrap (this, &rexsess::spawned, resp),
			  sessconn->auth);
  rpc_wipe (arg.kmsg);
}

void
rexsess::spawned (ref<rexd_spawn_res> resp, clnt_stat err)
{
  cbase = NULL;

  if (err) {
    warn << "REXD_SPAWN proxy RPC FAILED (" << err << ")\n";
    fail ();
    return;
  }
  else if (resp->err != SFS_OK) {
    // XXX
    warn << "FAILED (spawn proxy err " << int (resp->err) << ")\n";
    fail ();
    return;
  }
  warnx << "spawned proxy\n";

  skeys = resp->resok->kmsg;
  rpc_wipe (*resp);

  attach ();
}

void
rexsess::attach ()
{
  rex_mkkeys (NULL, NULL, &sessid, 0, skeys, ckeys);
  sessinfo.type = SFS_SESSINFO;

  rexd_attach_arg arg;
  arg.seqno = rex_seqno++;
  arg.sessid = sessid;
  rex_mkkeys (&sessinfo.ksc, &sessinfo.kcs, &arg.newsessid,
              arg.seqno, skeys, ckeys);

  ref<rexd_attach_res> resp = New refcounted<rexd_attach_res>;
  cbase = sessclnt->call (REXD_ATTACH, &arg, resp,
			  wrap (this, &rexsess::attached, resp));
}

void
rexsess::attached (ref<rexd_attach_res> resp, clnt_stat err)
{
  cbase = NULL;
  if (err) {
    rpc_wipe (sessinfo);
    warn << path << ": rex attach: " << err << "\n";
    fail ();
    return;
  }
  else if (*resp != SFS_OK) {
    rpc_wipe (sessinfo);
    warn << path << ": rex attach:" << *resp << "\n";
    fail ();
    return;
  }
  warnx << "attached to proxy\n";

  sessconn->x = axprt_crypt::alloc (sessconn->x->reclaim ());
  sessconn->x->encrypt (sessinfo.kcs.base (), sessinfo.kcs.size (),
			sessinfo.ksc.base (), sessinfo.ksc.size ());

  if (sess) {
    if (probecall) {
      probecall->cancel ();
      probecall = NULL;
    }
    assert (!resumepending);
    resumepending = sess->resume (sessconn->x, 1,
                                  wrap (this, &rexsess::resumed));
  }
  else {
    sesstab.insert (this);

    vec<char> secretid;
    rex_mksecretid (secretid, sessinfo.ksc, sessinfo.kcs);

    sess = New rexsession (path, sessconn->x, secretid,
			   wrap (this, &rexsess::proxy_fail),
                           wrap (this, &rexsess::proxy_timeout),
                           false, resumable_clients > 0);
    bzero (secretid.base (), secretid.size ());
    sess->setresumable (resumable_clients > 0);
    alert_active ();
  }

  rpc_wipe (sessinfo);
}

void
rexsess::resumed (bool success)
{
  resumepending = NULL;
  warn << "resume " << (success ? "succeeded" : "failed") << "\n";
  if (success)
    alert_active ();
  else
    fail ();
}

void
rexsess::probe ()
{
  assert (!connecting ());

  sess->silence_tmo_disable ();
  probetime = timenow;
  probecall = sess->ping (wrap (this, &rexsess::probed));
  probetmo = delaycb (15, wrap (this, &rexsess::probetimeout));
}

void
rexsess::probed (clnt_stat err)
{
  probecall = NULL;
  if (probetmo) {
    timecb_remove (probetmo);
    probetmo = NULL;
  }

  if (err)
    proxy_fail ();
  else {
    if (resumepending)
      return;  // can't cancel the resume
    else
      connect_cancel ();

    sess->silence_tmo_reset ();
    sess->silence_tmo_enable ();
    alert_active ();
  }
}

void
rexsess::probetimeout ()
{
  probetmo = NULL;

  if (!connecting ()) {
    warn << "probe is late; possibly reconnecting\n";
    connect (false);
  }
}

static void
rexsess_client_died (rexsess *rs, ref<bool> destroyed, sfs_seqno dead_seqno,
                   bool resumable)
{
  if (!*destroyed)
    rs->client_died (dead_seqno, resumable);
}

void
rexsess::client_died (sfs_seqno dead_seqno, bool resumable)
{
  assert (clients);
  clients--;
  if (resumable) {
    assert (resumable_clients);
    resumable_clients--;
  }

  sess->setresumable (resumable_clients > 0);
  sess->proxy->call (REX_CLIENT_DIED, &dead_seqno, NULL, aclnt_cb_null);

  if (!clients)
    reaper = delaycb (1800, wrap (this, &rexsess::reaped));
}

void
rexsess::reaped ()
{
  reaper = NULL;
  delete this;
}

void
rexsess::fail ()
{
  connect_cancel ();
  alert_fail ();
  delete this;
}

bool
rexsess::proxy_fail ()
{
  warn << "connection to proxy failed\n";

  if (resumepending)
    return true;

  if (sess->getresumable ()) {
    connect_cancel ();  // cancel any non-forced connect attempt
    connect (true);
    return true;
  }
  else {
    fail ();
    return false;
  }
}

bool
rexsess::proxy_timeout ()
{
  warn << "connection to proxy unresponsive\n";
  if (sess->getresumable () && !connecting ())
    connect (false);
  return true;
}

inline bool
rexsess::active (time_t since)
{
  return sess && sess->last_heard > since;
}

static void
keepalive_reply (svccb *sbc, int error)
{
  sbc->replyref (error == 0);
}

void
rexsess::keepalive (svccb *sbc)
{
  retry_delay = 0;  // if we're trying to reconnect, try again immediately
  take_request (wrap (keepalive_reply, sbc), false, true, false);
}

void
rexsess::rex_request (bool forwardagent, bool blockactive, bool resumable,
                      cb_rex::ref cb)
{
  clients++;
  if (resumable)
    resumable_clients++;
  if (reaper) {
    timecb_remove (reaper);
    reaper = NULL;
  }

  if (!connecting ())
    sess->setresumable (resumable_clients > 0);

  retry_delay = 0;  // if we're trying to reconnect, try again immediately
  take_request (wrap (this, &rexsess::rex_reply, cb, resumable),
                forwardagent, blockactive, resumable);
}

void
rexsess::rex_reply (cb_rex::ref cb, bool resumable, int error)
{
  if (error) {
    assert (clients);
    clients--;
    if (resumable) {
      assert (resumable_clients);
      resumable_clients--;
    }
    if (sess && !connecting ())
      sess->setresumable (resumable_clients > 0);

    (*cb) (New refcounted<sfsagent_rex_res> (false), NULL);
  }
  else {
    ref<sfsagent_rex_res> res (New refcounted<sfsagent_rex_res_w> (true));
    res->resok->sessid = sessid;
    res->resok->seqno = rex_seqno++;
    rex_mkkeys (&res->resok->ksc, &res->resok->kcs, &res->resok->newsessid,
		res->resok->seqno, skeys, ckeys);
    (*cb) (res, wrap (rexsess_client_died, this, destroyed, res->resok->seqno,
                      resumable));
  }
}

void
rexsess::af_init ()
{
  afpending = true;
  vec<str> suidcommand;
  suidcommand.setsize (2);
  suidcommand[0] = "suidconnect";
  suidcommand[1] = "agent";
  sess->makechannel (New refcounted <agentchannel>
                                     (sess, suidcommand, path,
                                      wrap (this, &rexsess::af_init_done)));
}

void
rexsess::af_init_done (int err)
{
  afpending = false;
  agentforwarded = (err == 0);
  alert_forwardedagent ();
}

void
rexsess::take_request (callback<void, int>::ref cb,
                       bool forwardagent, bool blockactive, bool resumable)
{
  rexreq *req = New rexreq (cb, forwardagent, blockactive, resumable);

  if (forwardagent && !agentforwarded) {
    afreqs.push_back (req);
    if (!afpending && !connecting ())
      af_init ();
  }
  else if (connecting ()) {
    reqs.push_back (req);
  }
  else if (blockactive && !active (timenow - 15)) {
    reqs.push_back (req);
    if (!probecall)
      probe ();  // make sure our connection to proxy is viable
  }
  else
    finish (req);
}

void
rexsess::finish (rexreq *req, int error)
{
  req->cb (error);
  delete req;
}

void
rexsess::alert_forwardedagent ()
{
  int n = afreqs.size ();
  for (int i = 0; i < n; i++)
    finish (afreqs[i]);
  afreqs.clear ();
}

void
rexsess::alert_active ()
{
  int n = reqs.size ();
  for (int i = 0; i < n; i++)
    finish (reqs[i]);
  reqs.clear ();

  if (!afreqs.empty () && !agentforwarded && !afpending)
    af_init ();
}

void
rexsess::alert_badconnect ()
{
  vec<rexreq*> treqs;
  treqs.swap (reqs);
  int n = treqs.size ();
  for (int i = 0; i < n; i++)
    if (treqs[i]->blockactive)
      reqs.push_back (treqs[i]);
    else
      finish (treqs[i], 1);

  treqs.clear ();
  treqs.swap (afreqs);
  n = treqs.size ();
  for (int i = 0; i < n; i++)
    if (treqs[i]->blockactive)
      afreqs.push_back (treqs[i]);
    else
      finish (treqs[i], 1);
}

void
rexsess::alert_fail ()
{
  int n = reqs.size ();
  for (int i = 0; i < n; i++)
    finish (reqs[i], 1);
  reqs.clear ();

  n = afreqs.size ();
  for (int i = 0; i < n; i++)
    finish (afreqs[i], 1);
  afreqs.clear ();
}

void
rex_connect (str dest, str path, str pathfrom,
    	     bool forwardagent, bool blockactive, bool resumable,
             cb_rex::ref cb)
{
  if (!pathfrom)
    pathfrom = sfshostname ();
  if (rexsess *sp = sesstab[path]) {
    warn << "rexsess: hash lookup for " << path
	 << " succeeded from " << pathfrom << "\n";
    sp->rex_request (forwardagent, blockactive, resumable, cb);
  }
  else
    vNew rexsess (dest, path, pathfrom, forwardagent, blockactive, resumable,
                  cb);
}

void
rex_keepalive (str path, svccb *sbp)
{
  if (rexsess *sp = sesstab[path])
    sp->keepalive (sbp);
  else {
    warn << "no such session in keepalive request for " << path << "\n";
    sbp->replyref (false);
  }
}

static void
print_rexsess (vec<rex_sessentry> *psv, rexsess *sp)
{
  rex_sessentry se;
  se.dest = sp->dest;
  se.schost = sp->path;
  se.created_from = sp->rexconnect_origin;
  se.agentforwarded = sp->agentforwarded;
  psv->push_back (se);
}

void
list_rexsess (svccb *sbp)
{
  vec<rex_sessentry> sv;
  sesstab.traverse (wrap (print_rexsess, &sv));

  rex_sessvec rsv;
  rsv.setsize (sv.size ());
  for (size_t i = 0; i < sv.size (); i++)
    rsv[i] = sv[i];
  sbp->replyref (rsv);
}

bool
kill_rexsess (str path)
{
  vec<rex_sessentry> sv;
  sesstab.traverse (wrap (print_rexsess, &sv));

  int found = 0;
  str foundstr;

  for (size_t i = 0; i < sv.size (); i++)
    if (sv[i].schost.len () >= path.len ()
	&& !memcmp (sv[i].schost, path, path.len ())) {
      found++;
      foundstr = sv[i].schost;
    }

  if (found == 0) {
    warn ("%s does not specify a valid rex session to remove.\n", 
	  path.cstr ());
    return false;
  }
  else if (found >= 2) {
    warn ("%s does not specify a unique rex session to remove.\n"
	  "Please use a longer prefix\n", path.cstr ());
    return false;
  }
  else if (rexsess *sp = sesstab[foundstr]) {
    warn ("removing rexsession connected to %s.\n", foundstr.cstr ());
    sp->abort ();
    delete sp;
    return true;
  }

  return false; /* make GCC 3.0.4 happy with this unreachable code */
}
