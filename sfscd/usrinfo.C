/* $Id: usrinfo.C,v 1.69 2004/09/19 22:02:29 dm Exp $ */

/*
 *
 * Copyright (C) 1998 David Mazieres (dm@uun.org)
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
#include "sfsagent.h"

qhash<sfs_aid, ref<usrinfo> > &usrtab (*New qhash<sfs_aid, ref<usrinfo> >);
static ptr<afslink> revokedlink;

sfs_aid
cdaup2aid (const authunix_parms *aup)
{
  if (!aup)
    return sfsaid_nobody;
  if (root_is_nfsmounter && !aup->aup_uid)
    return sfsaid_sfs;
  return aup2aid (aup);
}

sfs_aid
sbp2aid (const svccb *sbp)
{
  if (!sbp)
    return sfsaid_nobody; 
  return cdaup2aid (sbp->getaup ());
}

static void
flushuser (sfs_aid aid, cdaemon *cdp)
{
  if (aclnt *c = cdp->c)
    c->call (SFSCDPROC_FLUSHAUTH, &aid, NULL, aclnt_cb_null);
}

struct newagent {
  const sfs_aid aid;
  ref<axprt_unix> ax;
  ref<asrv> as;

  newagent (ref<axprt_unix> x, const authunix_parms *aup)
    : aid (cdaup2aid (aup)), ax (x),
      as (asrv::alloc (ax, agent_prog_1, wrap (this, &newagent::dispatch)))
    {}
  void dispatch (svccb *);
};

static void
agent_default (svccb *sbp, sfs_aid aid)
{
  switch (sbp->proc ()) {
  case AGENT_NULL:
    sbp->reply (NULL);
    break;
  case AGENT_REVOKE:
    revocation::alloc (*sbp->Xtmpl getarg<sfs_pathrevoke> ());
    sbp->reply (NULL);
    break;
  case AGENT_RNDSEED:
    {
      sfsagent_seed seed;
      rnd.getbytes (seed.base (), seed.size ());
      sbp->reply (&seed);
      break;
    }
  case AGENT_AIDALLOC:
    {
      if (sfs_specaid (aid)) {
	sbp->replyref (sfs_badgid);
	break;
      }
      u_int32_t uid = aid & 0xffffffff;
      u_int32_t gid = sfs_resvgid_start + sfs_resvgid_count;
      while (gid-- > sfs_resvgid_start)
	if (!usrtab[sfs_mkaid (uid, gid)])
	  break;
      if (gid < sfs_resvgid_start
	  || gid > sfs_resvgid_start + sfs_resvgid_count)
	gid = (u_int32_t) sfs_badgid;
      sbp->reply (&gid);
      break;
    }
  default:
    sbp->reject (PROC_UNAVAIL);
    break;
  }
}

void
newagent::dispatch (svccb *sbp)
{
  if (!sbp) {
    delete this;
    return;
  }

  switch (sbp->proc ()) {
  case AGENT_KILLSTART:
    {
      if (aid == sfsaid_sfs || aid == sfsaid_nobody)
	sbp->replyref (EINVAL);
      ref<usrinfo> u (New refcounted<usrinfo> (aid));
      u->sh = as;
      u->ch = aclnt::alloc (ax, agentcb_prog_1);
      u->x = ax;
      usrtab.insert (u->aid, u);
      as->setcb (wrap (u.get (), &usrinfo::dispatch));
      delete this;
      sbp->replyref (0);
      break;
    }

  case AGENT_START:
    if (aid == sfsaid_sfs || aid == sfsaid_nobody)
      sbp->replyref (EINVAL);
    else if (usrtab[aid])
      sbp->replyref (EBUSY);
    else {
      ref<usrinfo> u (New refcounted<usrinfo> (aid));
      u->sh = as;
      u->ch = aclnt::alloc (ax, agentcb_prog_1);
      u->x = ax;
      usrtab.insert (u->aid, u);
      as->setcb (wrap (u.get (), &usrinfo::dispatch));
      delete this;
      sbp->replyref (0);
    }
    break;

  case AGENT_KILL:
    if (usrtab[aid]) {
      usrtab.remove (aid);
      sbp->replyref (0);
    }
    else
      sbp->replyref (ESRCH);
    break;

  case AGENT_GETAGENT:
    if (ptr<usrinfo> u = usrtab[aid]) {
      if (u->clonelock) {
	sbp->replyref (EAGAIN);
	break;
      }
      int fds[2];
      if (socketpair (AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
	sbp->replyref (errno);
	break;
      }
      u->clonelock = true;
      ax->sendfd (fds[0]);
      u->x->sendfd (fds[1]);
      u->ch->call (AGENTCB_CLONE, NULL, NULL, aclnt_cb_null);
      sbp->replyref (0);
      u->x->setwcb (wrap (ref<axprt_stream> (ax), &axprt_stream::setwcb,
			  wrap (u, &usrinfo::clonelock_clear)));
    }
    else
      sbp->replyref (ESRCH);
    break;

  default:
    agent_default (sbp, aid);
  }

}

static void
authreq_cb (svccb *sbp, ref<sfsagent_auth_res> resp, clnt_stat err)
{
  if (err)
    resp->set_authenticate (false);
  sbp->reply (resp);
}

void
usrinfo::authreq (sfscd_authreq *ar, svccb *sbp)
{
  ref<sfsagent_auth_res> resp = New refcounted<sfsagent_auth_res>;
  switch (ar->type) {
  case AGENTCB_AUTHINIT:
    ch->timedcall (agent_timeout, AGENTCB_AUTHINIT, ar->init.addr (), resp,
		   wrap (authreq_cb, sbp, resp));
    break;
  case AGENTCB_AUTHMORE:
    ch->timedcall (agent_timeout, AGENTCB_AUTHMORE, ar->more.addr (), resp,
		   wrap (authreq_cb, sbp, resp));
    break;
  default:
    warn ("usrinfo::authreq: bad type\n");
    sbp->replyref (sfsagent_auth_res (false));
    break;
  }
}

ref<afsdir>
userdir (sfs_aid aid)
{
  if (aid == sfsaid_sfs)
    return afs_sfsroot;
  if (usrinfo *u = usrtab[aid])
    return u->root;
  return afs_naroot;
}

ref<afsdir>
userdir (const svccb *sbp)
{
  if (!sbp)
    return afs_naroot;
  return userdir (sbp2aid (sbp));
}

usrinfo::usrinfo (sfs_aid a)
  : aid (a), root (afsusrroot::alloc (afs_root, aid)), clonelock (false)
{
  daemontab.traverse (wrap (flushuser, aid));
}

usrinfo::~usrinfo ()
{
  daemontab.traverse (wrap (flushuser, aid));
}

void
usrinfo::dispatch (svccb *sbp)
{
  if (!sbp) {
    x = NULL;
    sh = NULL;
    ch = NULL;
    usrtab.remove (aid);
    return;
  }

  switch (sbp->proc ()) {
  case AGENT_KILLSTART:
    root = afsusrroot::alloc (afs_root, aid);
    /* above implies root->bumpmtime (); */
    /* cascade */
  case AGENT_START:
    daemontab.traverse (wrap (flushuser, aid));
    sbp->replyref (0);
    break;
  case AGENT_KILL:
    sbp->replyref (0);
    usrtab.remove (aid);
    break;
  case AGENT_SYMLINK:
    {
      sfsagent_symlink_arg *ssa
	= sbp->Xtmpl getarg<sfsagent_symlink_arg> ();
      root->mkulink (ssa->contents, ssa->name);
      sbp->reply (NULL);
      break;
    }
  case AGENT_FLUSHNAME:
    {
      str name = *sbp->Xtmpl getarg<sfs_filename> ();
      root->clrulink (name);
      sbp->reply (NULL);
      break;
    }
  case AGENT_FLUSHNEG:
    {
      root->clrnegcache ();
      sbp->reply (NULL);
      break;
    }
  default:
    agent_default (sbp, aid);
    break;
  }
}

static void
usrinfo_accept (ptr<axprt_unix> ax, const authunix_parms *aup)
{
  if (!ax)
    fatal << "agent.sock" << ": " << strerror (errno) << "\n";
  assert (!ax->ateof ());
  vNew newagent (ax, aup);
}

void
usrinfo_init ()
{
  sfs_suidserv ("agent", wrap (usrinfo_accept));
}

static void
unlinkdir (str dirname, const sfs_aid &, ptr<usrinfo> u)
{
  if (afsnode *e = u->root->lookup (dirname, NULL))
    if (typeid (*e) != typeid (revocation))
      u->root->unlink (dirname);
}

void
flushpath (str path)
{
  if (afsnode *e = afs_naroot->lookup (path, NULL))
    if (typeid (*e) != typeid (revocation))
      afs_naroot->unlink (path);
  usrtab.traverse (wrap (unlinkdir, path));
}
