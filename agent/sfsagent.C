/* $Id: sfsagent.C,v 1.95 2004/09/19 22:02:20 dm Exp $ */

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
#include "sfskeymisc.h"
#include "agentmisc.h"

EXITFN (cleanup);

authmgr gmgr;

list<sfsagent, &sfsagent::link> agents;

vec<str> &bound_sockets (*New vec<str>);

str agent_id;
sfsagent *cdagent;

rpc_program agentcb_compat = agentcb_prog_1;

bool opt_forwarding = true;
bool opt_killstart;
bool opt_nodaemon;
str opt_keytime;
str opt_socket;

str sock_standalone;
int sock_standalone_fd;

static void start_listening ();

static bool rndok;
static void
setrnd ()
{
  random_update ();
  rndok = true;
}
inline void
checkrnd ()
{
  while (!rndok)
    acheck ();
}

static inline axprt_unix *
xprt2unix (axprt *x)
{
  // XXX - dynamic_cast is busted in egcs
  axprt_unix *ux = static_cast<axprt_unix *> (&*x);
  if (typeid (*ux) == typeid (refcounted<axprt_unix>))
    return ux;
  else
    return NULL;
}

static bool_t
xdr_authinit_compat (XDR *xdrs, void *objp)
{
  switch (xdrs->x_op) {
  case XDR_DECODE:
    {
      unsigned pos = XDR_GETPOS (xdrs);
      if (xdr_sfsagent_authinit_arg (xdrs, objp))
	return TRUE;
      if (!XDR_SETPOS (xdrs, pos)
	  || !xdr_sfsagent_authinit_arg_old (xdrs, objp))
	return FALSE;
      static_cast<sfsagent_authinit_arg *> (objp)->server_release
	= SFS_RELEASE;
      return TRUE;
    }
  default:
    return xdr_sfsagent_authinit_arg (xdrs, objp);
  }
}

sfsagent::sfsagent (int fd)
  : x (axprt_unix::alloc (fd)),
    cs (asrv::alloc (x, agentctl_prog_1, wrap (this, &sfsagent::dispatch)))
{
  agents.insert_head (this);
}

sfsagent::sfsagent (ref<axprt> xx)
  : x (xx),
    cs (asrv::alloc (x, agentctl_prog_1, wrap (this, &sfsagent::dispatch)))
{
  agents.insert_head (this);
}

sfsagent::~sfsagent ()
{
  callback<void>::ptr fcb;
  for (int ix = 0; implicit_cast <u_int32_t> (ix) < failcbs.size (); ix++)
    (*(failcbs[ix])) ();

  agents.remove (this);
  if (this == cdagent) {
    warn << "exiting\n";
    exit (0);
  }
}

void
sfsagent::dispatch (svccb *sbp)
{
  if (!sbp) {
    if (name)
      warn << "EOF from " << name << "\n";
    delete this;
    return;
  }

  if (sbp->prog () == AGENTCB_PROG && sbp->vers () == AGENTCB_VERS)
    agentdisp (sbp);
  else if (sbp->prog () == AGENTCTL_PROG && sbp->vers () == AGENTCTL_VERS)
    ctldisp (sbp);
  else
    panic ("invalid prog/vers\n");
}

template<class T> void
pushit (vec<T> *vecp, const T &obj)
{
  vecp->push_back (obj);
}

void
pushsrpname (vec<sfsagent_srpname_pair> *vecp, const str &obj1, str *obj2)
{
  sfsagent_srpname_pair sn;
  sn.srpname = obj1;
  sn.sfsname = *obj2;
  vecp->push_back (sn);
}

static void
lookupres (svccb *sbp, sfsagent_lookup_type typ, str path)
{
  sfsagent_lookup_res res (LOOKUP_NOOP);
  if (path && path.len () <= sfsagent_path::maxsize) {
    if (typ == LOOKUP_MAKELINK) {
      res.set_type (typ);
      *res.path = path;
    } else if (typ == LOOKUP_MAKEDIR) {
      res.set_type (typ);
      *res.dir = path;
    }
  }
  sbp->replyref (res);
}

static void
revokedres (svccb *sbp, const sfsagent_revoked_res *res)
{
  sbp->reply (res);
}

static void
addsrpname_res (svccb *sbp)
{
  sfsagent_srpname_pair *arg = 
    sbp->Xtmpl getarg<sfsagent_srpname_pair> ();

  if (arg->srpname && arg->srpname.len () > 0
      && arg->sfsname && arg->sfsname.len () > 0) {
    srpnames.insert (arg->srpname, arg->sfsname);
    store_srp_cache (arg);
    sbp->replyref (true);
  }
  else
    sbp->replyref (false);
}

static void
dumpsrpnames_res (svccb *sbp)
{
  vec<sfsagent_srpname_pair> resvec;
  srpnames.traverse (wrap (pushsrpname, &resvec));
  sfsagent_srpname_pairs res;
  res.set (resvec.base (), resvec.size ());
  sbp->reply (&res);
}

static void
lookupsrpname_res (svccb *sbp)
{
  sfsagent_srpname *arg = sbp->Xtmpl getarg<sfsagent_srpname> ();
  str *sfsname = srpnames[*arg];

  sfsagent_srpname_res res (false);
  if (sfsname) {
    res.set_status (true);
    *res.sfsname = *sfsname;
  }
  sbp->replyref (res);
}

void
sfsagent::rexres (svccb *sbp, ptr<sfsagent_rex_res> res,
                  callback<void>::ptr failcb)
{
  if (!res)
    sbp->replyref (sfsagent_rex_res (false));
  else {
    if (failcb)
      failcbs.push_back (failcb);
    sbp->reply (res);
  }
}

void
sfsagent::agentdisp (svccb *sbp)
{
  checkrnd ();
  switch (sbp->proc ()) {
  case AGENTCB_NULL:
    sbp->reply (NULL);
    break;
  case AGENTCB_AUTHINIT:
    if (name) {
      sfsagent_authinit_arg *aa
	= sbp->Xtmpl getarg<sfsagent_authinit_arg> ();
      if (aa->requestor) {
	str s;
	if (name == "sfscd")
	  s = "@LOCALHOST";
	else
	  s = name;
	aa->requestor = strbuf () << aa->requestor << s;
      }
    }
    gmgr.authinit (sbp->Xtmpl getarg<sfsagent_authinit_arg> (),
		   sbp->Xtmpl getres<sfsagent_auth_res> (),
		   wrap (&authmgr::authdone_cb, sbp));
    break;
  case AGENTCB_AUTHMORE:
    gmgr.authmore (sbp->Xtmpl getarg<sfsagent_authmore_arg> (),
		   sbp->Xtmpl getres<sfsagent_auth_res> (),
		   wrap (&authmgr::authdone_cb, sbp));
    break;
  case AGENTCB_LOOKUP:
    sfslookup (*sbp->Xtmpl getarg<sfs_filename> (), wrap (lookupres, sbp));
    break;
  case AGENTCB_REVOKED:
    revcheck (*sbp->Xtmpl getarg<filename3> (), wrap (revokedres, sbp));
    break;
  case AGENTCB_CLONE:
    if (axprt_unix *ux = xprt2unix (x)) {
      int fd = ux->recvfd ();
      if (fd < 0)
	warn << "failed to receive fd for AGENTCB_CLONE\n";
      else 
	vNew sfsagent (fd);
    }
    sbp->reply (NULL);
    break;
  default:
    warn ("invalid AGENTCB procno %d\n", sbp->proc ());
    sbp->reject (PROC_UNAVAIL);
  }
}

void
sfsagent::keyinitcb (svccb *sbp, key *nk, str err)
{
  if (err) {
    warn << nk->name << ": initilization failure\n" << err << "\n";
    gmgr.remove (nk);
    delete nk;
    sbp->replyref (false);
    return;
  }
  sbp->replyref (true);
}

void
sfsagent::ctldisp (svccb *sbp)
{
  switch (sbp->proc ()) {
  case AGENTCTL_NULL:
    sbp->reply (NULL);
    break;
  case AGENTCTL_ADDEXTAUTH:
    {
      sfsagent_addextauth_arg *aa = 
	sbp->Xtmpl getarg<sfsagent_addextauth_arg> ();
      extauth *ea = New extauth (x, &gmgr, this);
      ea->pid = aa->pid;
      ea->expire = aa->expire;
      ea->name = aa->name;
      
      // what if a key has the same comment?  leave it in for now
      if (authmeth *am = gmgr.plookup (aa->pid)) {
	gmgr.remove (am);
	delete am;
      }
      gmgr.insert (ea);
      gmgr.timeout ();
      
      // tells sfscd that we've just added a new key
      agentmsg (AGENT_START);
      sbp->replyref (true);
      break;
    }
  case AGENTCTL_ADDKEY:
    {
      sfs_addkey_arg *aa = sbp->Xtmpl getarg<sfs_addkey_arg> ();
      key *nk; 
      nk = New key (&gmgr);
      // XXX - key_version field is useless and should be deleted
      // nk->vers = aa->key_version;
      nk->setkey (sfscrypt.alloc (aa->privkey, SFS_SIGN));
      if (!nk) {
	warn << "Cannot parse keypair\n";
	sbp->replyref (false);
	break;
      }
      if (authmeth *k = gmgr.klookup (*nk->k)) {
	gmgr.remove (k);
	delete k;
      }
      nk->expire = aa->expire;
      nk->name = aa->name;
      gmgr.insert (nk);
      gmgr.timeout ();
      agentmsg (AGENT_START);
      nk->k->init (wrap (this, &sfsagent::keyinitcb, sbp, nk));
      break;
    }
  case AGENTCTL_REMAUTH:
    {
      sfs_remauth_arg *ra = sbp->Xtmpl getarg<sfs_remauth_arg> ();
      authmeth *a;
      bool ok = false;
      switch (ra->type) {
      case SFS_REM_PUBKEY:
	{
	  ptr<sfspub> pk = sfscrypt.alloc (*ra->pubkey);
	  if (pk && (a = gmgr.klookup (*pk))) {
	    ok = true;
	    gmgr.remove (a);
	    delete a;
	  }
	  break;
	}
      case SFS_REM_NAME:
	while ((a = gmgr.clookup(*ra->name))) {
	  ok = true;
	  gmgr.remove (a);
	  delete a;
	}
	break;
      case SFS_REM_PID:
	if ((a = gmgr.plookup (*ra->pid))) {
	  ok = true;
	  gmgr.remove (a);
	  delete a;
	}
	break;
      }
      if (ok)
	agentmsg (AGENT_START);
      sbp->replyref (ok);
      break;
    }
  case AGENTCTL_REMALLKEYS:
    {
      gmgr.remove_all();
      agentmsg (AGENT_START);
      sbp->replyref (NULL);	// XXX race-prone
      break;
    }
  case AGENTCTL_DUMPKEYS:
    {
      sfs_keylist kl;
      gmgr.fill_keylist (&kl);
      sbp->reply (&kl);
      break;
    }
  case AGENTCTL_ADDCERTPROG:
    {
      sfsagent_certprog *arg = sbp->Xtmpl getarg<sfsagent_certprog> ();
      str av0;
      if (arg->av.size () > 0 && (av0 = find_program (arg->av[0]))) {
	bool found = false;
	size_t i, n = certprogs.size ();

	arg->av[0] = av0;
	while (n--)
	  if (arg->prefix == certprogs[n].prefix
	      && arg->filter == certprogs[n].filter
	      && arg->exclude == certprogs[n].exclude) {
	    for (i = 0; i < arg->av.size (); i++)
	      if (arg->av[i] != certprogs[n].av[i])
		break;
	    if (i == arg->av.size ())
	      found = true;
	  }
	if (!found) {
	  certprogs.push_back (*arg);
	  certfilters.push_back (rxfilter (arg->filter, arg->exclude));
	  agentmsg (AGENT_FLUSHNEG);
	}
	sbp->replyref (true);
      }
      else
	sbp->replyref (false);
      break;
    }
  case AGENTCTL_CLRCERTPROG_BYREALM:
    {
      size_t n = certprogs.size ();
      sfsagent_certprog cp;
      rxfilter rxf;
      sfsauth_realm *arg = sbp->Xtmpl getarg<sfsauth_realm> ();
      bool found = false;

      while (n--) {
	cp = certprogs.pop_front ();
	rxf = certfilters.pop_front ();
	if (cp.prefix != *arg) {
	  certprogs.push_back (cp);
	  certfilters.push_back (rxf);
	}
	else
	  found = true;
      }
      agentmsg (AGENT_FLUSHNEG);
      sbp->replyref (found);
      break;
    }
  case AGENTCTL_CLRCERTPROGS:
    certprogs.clear ();
    certfilters.clear ();
    agentmsg (AGENT_KILLSTART);	// XXX
    sbp->reply (NULL);
    break;
  case AGENTCTL_DUMPCERTPROGS:
    {
      sfsagent_certprogs res;
      res.set (certprogs.base (), certprogs.size ());
      sbp->replyref (res);
      break;
    }
  case AGENTCTL_ADDREVOKEPROG:
    {
      sfsagent_revokeprog *arg = sbp->Xtmpl getarg<sfsagent_revokeprog> ();
      str av0;
      if (arg->av.size () > 0 && (av0 = find_program (arg->av[0]))) {
	arg->av[0] = av0;
	revokeprogs.push_back (*arg);
	if (arg->block)
	  revokefilters.push_back (rxfilter (arg->block->filter,
					     arg->block->exclude));
	else
	  revokefilters.push_back ();
	sbp->replyref (true);
      }
      else
	sbp->replyref (false);
      break;
    }
  case AGENTCTL_CLRREVOKEPROGS:
    revokeprogs.clear ();
    revokefilters.clear ();
    agentmsg (AGENT_KILLSTART);	// XXX
    norevoke.clear ();
    sbp->reply (NULL);
    break;
  case AGENTCTL_DUMPREVOKEPROGS:
    {
      sfsagent_revokeprogs res;
      res.set (revokeprogs.base (), revokeprogs.size ());
      sbp->replyref (res);
      break;
    }
  case AGENTCTL_SETNOREVOKE:
    {
      sfsagent_norevoke_list *arg
	= sbp->Xtmpl getarg<sfsagent_norevoke_list> ();
      for (sfs_hash *hid = arg->base (); hid < arg->lim (); hid++)
	norevoke.insert (*hid);
      sbp->reply (NULL);
      break;
    }
  case AGENTCTL_GETNOREVOKE:
    {
      vec<sfs_hash> revvec;
      norevoke.traverse (wrap (pushit<sfs_hash>, &revvec));
      sfsagent_norevoke_list res;
      res.set (revvec.base (), revvec.size ());
      sbp->reply (&res);
      break;
    }
  case AGENTCTL_SYMLINK:
    agentmsg (AGENT_SYMLINK, sbp->getvoidarg ());
    sbp->reply (NULL);
    break;
  case AGENTCTL_RESET:
    agentmsg (AGENT_KILLSTART);
    sbp->reply (NULL);
    break;
  case AGENTCTL_FORWARD:
    if (!opt_forwarding)
      sbp->replyref ((int32_t) EPERM);
    else if (name)
      sbp->replyref ((int32_t) EBUSY);
    else {
      setname (*sbp->Xtmpl getarg<sfs_hostname> ());
      sbp->replyref ((int32_t) 0);
    }
    break;
  case AGENTCTL_REX:
    {
      sfsagent_rex_arg *prca = sbp->Xtmpl getarg<sfsagent_rex_arg> ();
      if (name) {
	warn << name << ": " << prca->dest << "(rexsess)\n";
      }
      rex_connect (prca->dest, prca->schost, name,
                   prca->forwardagent, prca->blockactive, prca->resumable,
                   wrap (this, &sfsagent::rexres, sbp));
      break;
    }
  case AGENTCTL_KEEPALIVE:
    {
      sfs_hostname *schost =
        sbp->Xtmpl getarg<sfs_hostname> ();
      rex_keepalive (*schost, sbp);
      break;
    }
  case AGENTCTL_LISTSESS:
    {
      list_rexsess (sbp);
      break;
    }
  case AGENTCTL_KILLSESS:
    {
      sbp->replyref (kill_rexsess (*sbp->Xtmpl getarg<sfs_hostname> ()));
      break;
    }
  case AGENTCTL_ADDSRPNAME:
    {
      load_srp_cache (wrap (addsrpname_res, sbp));
      break;
    }
  case AGENTCTL_CLRSRPNAMES:
    {
      srpnames.clear ();
      agentmsg (AGENT_KILLSTART);	// XXX
      sbp->reply (NULL);
      break;
    }
  case AGENTCTL_DUMPSRPNAMES:
    {
      load_srp_cache (wrap (dumpsrpnames_res, sbp));
      break;
    }
  case AGENTCTL_LOOKUPSRPNAME:
    {
      load_srp_cache (wrap (lookupsrpname_res, sbp));
      break;
    }
  case AGENTCTL_CLRCONFIRMPROG:
    {
      confprog.setsize (0);
      agentmsg (AGENT_KILLSTART);	// XXX
      sbp->reply (NULL);
      break;
    }
  case AGENTCTL_ADDCONFIRMPROG:
    {
      sfsagent_confprog *arg = sbp->Xtmpl getarg<sfsagent_confprog> ();
      str av0;
      if (arg->size () > 0 && (av0 = find_program_plus_libsfs ((*arg)[0]))) {
	(*arg)[0] = av0;
        confprog.clear ();
        for (sfsagent_progarg *a = arg->base (); a < arg->lim (); a++)
          confprog.push_back (*a);
	sbp->replyref (true);
      }
      else
	sbp->replyref (false);
      agentmsg (AGENT_START);
      break;
    }
  case AGENTCTL_DUMPCONFIRMPROG:
    {
      sfsagent_confprog res;
      res.set (confprog.base (), confprog.size ());
      sbp->reply (&res);
      break;
    }
  case AGENTCTL_CLRSRPCACHEPROG:
    {
      srpcacheprog.setsize (0);
      agentmsg (AGENT_KILLSTART);	// XXX
      sbp->reply (NULL);
      break;
    }
  case AGENTCTL_ADDSRPCACHEPROG:
    {
      sfsagent_srpcacheprog *arg =
        sbp->Xtmpl getarg<sfsagent_srpcacheprog> ();
      str av0;
      if (arg->size () > 0 && (av0 = find_program_plus_libsfs ((*arg)[0]))) {
	(*arg)[0] = av0;
        srpcacheprog.clear ();
        for (sfsagent_progarg *a = arg->base (); a < arg->lim (); a++)
          srpcacheprog.push_back (*a);
	sbp->replyref (true);
      }
      else
	sbp->replyref (false);
      agentmsg (AGENT_START);
      break;
    }
  case AGENTCTL_DUMPSRPCACHEPROG:
    {
      sfsagent_srpcacheprog res;
      res.set (srpcacheprog.base (), srpcacheprog.size ());
      sbp->reply (&res);
      break;
    }
  case AGENTCTL_KILL:
    if (!name) {
      cleanup ();
      warn << "exiting\n";
      sbp->reply (NULL);
      exit (0);
    }
    else
      sbp->reject (PROC_UNAVAIL);
    break;
  default:
    warn ("invalid AGENTCTL procno %d\n", sbp->proc ());
    sbp->reject (PROC_UNAVAIL);
    break;
  }
}

void
sfsagent::setname (str n)
{
  if (!name) {
    name = n;
    ac = aclnt::alloc (x, agent_prog_1);
#if 0
    as = asrv::alloc (x, agentcb_prog_1, wrap (this, &sfsagent::dispatch));
#else
    as = asrv::alloc (x, agentcb_compat, wrap (this, &sfsagent::dispatch));
#endif
  }
}

void
agentmsg (u_int32_t proc, const void *arg)
{
  static int32_t garbage_int;
  for (sfsagent *a = agents.first; a; a = agents.next (a))
    if (a->ac)
      a->ac->call (proc, arg, &garbage_int, aclnt_cb_null);
}

static void
ctlaccept (int lfd)
{
  sockaddr_un sun;
  socklen_t sunlen = sizeof (sun);
  bzero (&sun, sizeof (sun));
  int fd = accept (lfd, (sockaddr *) &sun, &sunlen);
  if (fd < 0) {
    if (errno != EAGAIN)
      warn ("ctlaccept: %m\n");
    return;
  }
#ifdef HAVE_GETPEEREID
  uid_t uid;
  gid_t gid;
  if (getpeereid (fd, &uid, &gid) < 0) {
    warn ("getpeereid: %m\n");
    close (fd);
    return;
  }
  if (uid != (myaid () & 0xffffffff)) {
    if (uid) {
      warn ("rejecting connection by UID %u\n", unsigned (uid));
      close (fd);
      return;
    }
    warn ("accepting connection from root\n");
  }
#endif /* HAVE_GETPEEREID */
  vNew sfsagent (fd);
}

static void
cleanup ()
{
  // XXX - race-prone when dying from "sfsagent -k"
  while (!bound_sockets.empty ())
    unlink (bound_sockets.pop_front ());
}

static void
unix_listen_cb (str path, int fd, int status)
{
  if (status) {
    if (sock_standalone && sock_standalone == path)
      fatal ("cannot bind %s\n", path.cstr ());
    close (fd);
  }
  else if (listen (fd, 5) < 0) {
    if (sock_standalone && sock_standalone == path)
      fatal ("listen on %s: %m\n", path.cstr ());
    warn ("not listening on %s: listen: %m\n", path.cstr ());
    close (fd);
  }
  else {
    bound_sockets.push_back (path);
    fdcb (fd, selread, wrap (ctlaccept, fd));
  }
}

static bool
ctl_sendkill (int fd)
{
  if (fd < 0)
    return true;

  xdrsuio x;
  u_int32_t *lenp = reinterpret_cast<u_int32_t *> (XDR_INLINE (x.xdrp (), 4));
  if (!lenp)
    fatal ("failed to marshal length of kill message\n");
  if (!aclnt::marshal_call (x, NULL, AGENTCTL_PROG, AGENTCTL_VERS,
			    AGENTCTL_KILL, xdr_void, NULL))
    panic ("failed to marshal AGENTCTL_KILL call\n");
  *lenp = htonl (0x80000000 | (XDR_GETPOS (x.xdrp ()) - 4));

  while (x.uio ()->resid ()) {
    timeval tmo;
    tmo.tv_sec = 10;
    tmo.tv_usec = 0;
    if (fdwait (fd, selwrite, &tmo) <= 0)
      break;

    errno = 0;
    int n = writev (fd, x.uio ()->iov (), x.uio ()->iovcnt ());
    if (n > 0)
      x.uio ()->rembytes (n);
    else if (errno != EAGAIN)
      break;
  }

  if (!x.uio ()->resid ()) {
    timeval tmo;
    tmo.tv_sec = 10;
    tmo.tv_usec = 0;
    fdwait (fd, selread, &tmo);
  }

  close (fd);
  return !x.uio ()->resid ();
}

static void
unix_listen (str path, bool sync)
{
  if (path == "-") {
    vNew sfsagent (0);
    return;
  }

  sockaddr_un sun;
  if (path.len () >= sizeof (sun.sun_path)) {
    warn ("not listening on %s: path too long\n", path.cstr ());
    return;
  }
  int ctlfd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (ctlfd < 0) {
    warn ("not listening on %s: socket: %m\n", path.cstr ());
    return;
  }
  make_async (ctlfd);

  bzero (&sun, sizeof (sun));
  sun.sun_family = AF_UNIX;
  strcpy (sun.sun_path, path);

  pid_t pid = afork ();
  if (pid == -1) {
    warn ("not listening on %s: fork: %m\n", path.cstr ());
    close (ctlfd);
    return;
  }
  else if (!pid) {
    umask (077);
    if (bind (ctlfd, (sockaddr *) &sun, sizeof (sun)) < 0) {
      if (errno == EADDRINUSE) {
	int fd = unixsocket_connect (path);
	if (fd < 0)
	  unlink (sun.sun_path);
	else
	  ctl_sendkill (fd);
      }
      if (bind (ctlfd, (sockaddr *) &sun, sizeof (sun)) < 0) {
	warn ("not listening on %s: bind: %m\n", sun.sun_path);
	err_flush ();
	_exit (1);
      }
    }
    err_flush ();
    _exit (0);
  }

  if (sync) {
    int status = -1;
    waitpid (pid,  &status, 0);
    unix_listen_cb (path, ctlfd, status);
  }
  else
    chldcb (pid, wrap (unix_listen_cb, path, ctlfd));
}

static void
start_listening ()
{
  if (opt_socket)
    unix_listen (opt_socket, false);
}

static void
agent_daemonize (int status = 0)
{
  if (status)
    fatal ("agentrc failed\n");
  checkrnd ();
  int32_t err = EIO;
  if (opt_killstart) {
    if (sock_standalone) {
      if (sock_standalone_fd >= 0)
	ctl_sendkill (sock_standalone_fd);
      sock_standalone_fd = -1;
    }
    else if (cdagent->ac->scall (AGENT_KILLSTART, NULL, &err) || err)
      fatal ("could not start agent: %s\n", strerror (err));
  }
  if (sock_standalone)
    unix_listen (sock_standalone, true);
  if (!opt_nodaemon) {
    switch (fork ()) {
    case -1:
      fatal ("fork: %m\n");
    case 0:
      break;
    default:
      _exit (0);
    }
    if (setsid () < 0)
      fatal ("setsid: %m\n");
    if (!runinplace)
      chdir ("/");
  }
  start_listening ();
  //load_srp_cache ();
}

static void
setenvfd (int fd)
{
  str var (strbuf ("SFS_AGENTSOCK=-%d", fd));
  xputenv (var);
}

static void
startagent (bool optc, int argc, char **argv)
{
  char **arge = argv + argc;
  vec<const char *> av;

  str rc;
  if (!optc)
    rc = sfsconst_etcfile_required ("agentrc");
  else if (!argc) {
    agent_daemonize ();
    return;
  }
  else {
    if (strchr (*argv, '/'))
      rc = *argv;
    else {
      rc = find_program (*argv);
      if (!rc)
	fatal ("cannot find program %s\n", *argv);
    }
    argv++;
  }
 
  struct stat sb;
  if (!stat (rc, &sb) && S_ISREG (sb.st_mode) && !(sb.st_mode & 0111))
    av.push_back ("/bin/sh");
  av.push_back (rc);
  if (opt_keytime) {
    av.push_back ("-t");
    av.push_back (opt_keytime);
  }
  for (char *const *ap = argv; ap < arge; ap++)
    av.push_back (*ap);
  av.push_back (NULL);

  int fds[2];
  if (socketpair (AF_UNIX, SOCK_STREAM, 0, fds) < 0)
    fatal ("socketpair: %m\n");
  close_on_exec (fds[0]);

  pid_t pid = aspawn (av[0], av.base (), 0, 1, 2, wrap (setenvfd, fds[1]));
  if (pid == -1)
    fatal ("fork: %m\n");
  close (fds[1]);
  ptr<axprt_unix> x = axprt_unix::alloc (fds[0]);
  chldcb (pid, wrap (agent_daemonize));
  vNew sfsagent (x);
}

static void
set_agent_id ()
{
  sfs_aid aid = myaid ();
  uid_t uid = getuid ();
  str user = myusername ();

  if (!user)
    user = strbuf ("[%qd]", aid);
  else if (aid != uid)
    user = strbuf ("%s[%qd]", user.cstr (), aid);

  agent_id = user << "@" << sfshostname ();
}

static void
usage ()
{
  warnx << "usage: " << progname
	<< " [-S socket] [-dnkF] [-c [sfskey ...] | key-source]\n";
  exit (1);
}

int
main (int argc, char **argv)
{
  setprogname (argv[0]);
  sfsconst_init ();
  if (!runinplace) {
    /* In any case, try to avoid core dumps */
#ifdef RLIMIT_CORE
    struct rlimit rlcore;
    if (getrlimit (RLIMIT_CORE, &rlcore) >= 0) {
      rlcore.rlim_cur = 0;
      setrlimit (RLIMIT_CORE, &rlcore);
    }
#endif /* RLIMIT_CORE */
  }

  bool opt_c = false, opt_n = false;
  int ch;
  while ((ch = getopt (argc, argv, "FS:cdknt:")) != -1)
    switch (ch) {
    case 'F':
      opt_forwarding = false;
      break;
    case 'S':
      opt_socket = optarg;
      break;
    case 'c':
      opt_c = true;
      break;
    case 'd':
      opt_nodaemon = true;
      break;
    case 'k':
      opt_killstart = true;
      break;
    case 'n':
      opt_n = true;
      break;
    case 't':
      opt_keytime = optarg;
      break;
    default:
      usage ();
      break;
    }
  argc -= optind;
  argv += optind;

  set_agent_id ();
  if (!runinplace && !opt_nodaemon) {
    /* setuid makes ptrace fail on some OS's (a good thing, when we
     * hold private keys). */
    setuid (getuid ());
#ifdef RLIMIT_CORE
    /* Similarly, core dumps are a bad thing when you may have private
     * keys. */
    struct rlimit rl;
    if (!getrlimit (RLIMIT_CORE, &rl)) {
      rl.rlim_cur = 0;
      setrlimit (RLIMIT_CORE, &rl);
    }
#endif /* RLIMIT_CORE */
  }

  {
    rpcgen_table *tbl = New rpcgen_table[agentcb_compat.nproc];
    memcpy (tbl, agentcb_compat.tbl, agentcb_compat.nproc * sizeof (*tbl));
    tbl[AGENTCB_AUTHINIT].xdr_arg = xdr_authinit_compat;
    agentcb_compat.tbl = tbl;
  }

  int fd;
  if (opt_n) {
    if (!opt_socket)
      fatal ("-S <socket> option required with -n option\n");
    random_set_seedfile ("~/.sfs/random_seed");
  }
  else if ((fd = suidgetfd ("agent")) >= 0) {
    sfsagent *a = cdagent = New sfsagent (fd);
    a->setname ("sfscd");
    a->cs = NULL;

    int32_t err = EIO;
    if (!opt_killstart && (a->ac->scall (AGENT_START, NULL, &err) || err))
      fatal ("could not start agent: %s\n", strerror (err));
    sfsagent_seed seed;
    if (a->ac->scall (AGENT_RNDSEED, NULL, &seed))
      fatal ("I/O error from sfscd\n");
    rnd_input.update (seed.base (), seed.size ());
    bzero (seed.base (), seed.size ());
    random_update ();		// Unnecessary paranoia - done in checkrnd()
  }
  else {
    sock_standalone = agent_usersock (true);
    if (!sock_standalone)
      fatal ("could not create agent socket directory");
    sock_standalone_fd = unixsocket_connect (sock_standalone);
    if (sock_standalone_fd >= 0 && !opt_killstart)
      fatal << "Already running (on " << sock_standalone << ")\n";
    warn << "no sfscd; listening on " << sock_standalone << "\n";
  }

  getsysnoise (&rnd_input, wrap (setrnd));
  sigcb (SIGTERM, wrap (exit, 1));
  void subvert ();
  sigcb (SIGUSR1, wrap (subvert));
  startagent (opt_c, argc, argv);
  amain ();
}
