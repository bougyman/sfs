/* $Id: srvinfo.C,v 1.51 2003/12/15 04:54:26 dm Exp $ */

/*
 *
 * Copyright (C) 1998-2000 David Mazieres (dm@uun.org)
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
#include "parseopt.h"
#include "sfsconnect.h"

static str rootnfsinfo;
static const u_int64_t badfsid = (u_int64_t) -1;
static ihash<str, srvinfo, &srvinfo::path, &srvinfo::hlink> srvtab;
static ihash<str, srvinfo, &srvinfo::oldpath, &srvinfo::ohlink> osrvtab;

inline srvinfo *
srvlookup (const str &n)
{
  if (srvinfo *si = srvtab[n])
    return si;
  return osrvtab[n];
}

static inline str
mpof (str fs)
{
#if FIX_MNTPOINT
  if (opt_fix_mntpoint)
    return strbuf ("%s/" MPDOT, sfsroot) << fs << "/r";
  else
#endif /* FIX_MNTPOINT */
    return strbuf ("%s/", sfsroot) << fs;
}

void
update_devdb ()
{
  afs_root->unlink (".devdb");
  afs_root->link (afsreg::alloc (srvinfo::devlist ()), ".devdb");
  afs_root->unlink (".nfsdb");
  afs_root->link (afsrootfile::alloc (srvinfo::nfslist ()), ".nfsdb");
}

inline
srvinfo::srvinfo (const str &p, bool namedprot)
  : tmo (NULL), waiting (true), destroyed (false), cdmounted (false),
    visible_flag (true), devno (badfsid), error (0), cdp (NULL)
{
  if (namedprot || sfs_parsepath_v2 (p, NULL, NULL, NULL)) {
    assert (!srvtab[p]);
    path = p;
    srvtab.insert (this);
  }
  else {
    assert (!osrvtab[p]);
    oldpath = p;
    osrvtab.insert (this);
  }
}

inline
srvinfo::~srvinfo ()
{
  timecb_remove (tmo);
  if (path) {
    afs_sfsroot->unlink (path);
#if FIX_MNTPOINT
    if (opt_fix_mntpoint)
      afs_linuxbug->unlink (path);
#endif /* FIX_MNTPOINT */
    srvtab.remove (this);
  }
  if (oldpath) {
    afs_sfsroot->unlink (oldpath);
    osrvtab.remove (this);
  }

  if (cdp) {
    cdp->servers.remove (this);
    if (cdp->c) {
      nfspath3 p (path);
      cdp->c->call (SFSCDPROC_UNMOUNT, &p, NULL, aclnt_cb_null);
    }
  }
  if (waitq.empty ()) {
    if (path)
      flushpath (path);
    if (oldpath)
      flushpath (oldpath);
  }
  else
    for (size_t n = waitq.size (); n-- > 0;)
      (*waitq.pop_front ()) (error);

  update_devdb ();
}

void
srvinfo::timeout (bool start)
{
  tmo = NULL;
#if 0
  tmo = delaycb (destroyed ? 10 : 300, wrap (this, &srvinfo::timeout, false));
#else
  if (destroyed)
    tmo = delaycb (10, wrap (this, &srvinfo::timeout, false));
#endif
  if (!start)
    unmount ((destroyed ? NUOPT_FORCE : 0) | NUOPT_NLOG);
}

void
srvinfo::fail (int err)
{
  if (!error || (err && err != ENOENT))
    error = err;
  if (srvl)
    tcpconnect_srv_retry (srvl, wrap (this, &srvinfo::connected), &dnsname);
  else
    delete this;
}

int
srvinfo::geterr (const str &path)
{
  srvinfo *si = srvlookup (path);
  if (si) {
    if (si->error)
      return si->error;
    if (!si->visible_flag)
      return EWOULDBLOCK;
  }
  return 0;
}

srvinfo *
srvinfo::lookup (const str &path)
{
  srvinfo *si = srvlookup (path);
  if (si && !si->waiting)
    return si;
  return NULL;
}

static void
delcpath (str path)
{
  afs_sfsroot->unlink (path);
  flushpath (path);
}

void
srvinfo::alloc (const str &path, srvinfo::alloccb_t cb)
{
  srvinfo *si = srvlookup (path);
  if (si) {
    if (si->waiting)
      si->waitq.push_back (cb);
    else
      (*cb) (si->error);
    return;
  }

  str hname;
  sfs_hash hid;
  u_int16_t port;
  if (sfs_parsepath (path, &hname, &hid, &port)) {
    si = New srvinfo (path);
    si->waitq.push_back (cb);
    si->dnsname = NULL;
    si->port = port;

    if (const sfs_host *hp = sfs_hosttab.lookup (hname)) {
      switch (hp->sa.sa.sa_family) {
      case AF_INET:
	si->dnsname = inet_ntoa (hp->sa.sa_in.sin_addr);
	if (!port)
	  port = ntohs (hp->sa.sa_in.sin_port);
	tcpconnect (hp->sa.sa_in.sin_addr, port,
		    wrap (si, &srvinfo::connected));
	break;
      default:
	warn << hname << ": unknown protocol family "
	     << hp->sa.sa.sa_family << "\n";
	delete si;
	break;
      }
    }
    else if (port)
      tcpconnect (hname, port, wrap (si, &srvinfo::connected),
		  false, &si->dnsname);
    else
      tcpconnect_srv (hname, "sfs", SFS_PORT, wrap (si, &srvinfo::connected),
		      false, &si->srvl, &si->dnsname);
  }
  else if (namedprotrx.match (path)) {
    str prot (namedprotrx[1]);
    named_protocol *np = nptab[prot];
    if (!np) {
      warn << "unknown named protocol " << prot << "\n";
      (*cb) (EPROTONOSUPPORT);
    }
    else if (!np->cdp->c) {
      warn << "client for protocol " << prot << " is dead.\n";
      (*cb) (EAGAIN);
    }
    else {
      si = New srvinfo (path, true);
      si->cdp = np->cdp;
      si->cdp->servers.insert_head (si);
      si->waitq.push_back (cb);
      sfscd_mountarg arg;
      sfs_initci (&arg.carg, path, SFS_SFS, &sfs_extensions);
      si->cdp->c->call (SFSCDPROC_MOUNT, &arg, &si->mntres,
			wrap (si, &srvinfo::gotmntres));
    }
  }
  else
    (*cb) (ENOENT);
}

void
srvinfo::connected (int fd)
{
  if (fd < 0) {
    srvl = NULL;
    warn ("%s: %m\n", path ? path.cstr () : oldpath.cstr ());
    fail (errno);
    return;
  }
  else {
    sockaddr_in sin;
    socklen_t len = sizeof (sin);
    bzero (&sin, sizeof (sin));
    if (getpeername (fd, reinterpret_cast<sockaddr *> (&sin), &len) < 0) {
      close (fd);
      warn ("%s: %m\n", path ? path.cstr () : oldpath.cstr ());
      fail (errno);
      return;
    }
    if (badaddrs[sin.sin_addr]) {
      close (fd);
      warn ("%s: cannot connect to my own IP address\n",
	    path ? path.cstr () : oldpath.cstr ());
      fail (EDEADLK);
      return;
    }
  }

  tcp_nodelay (fd);
  ref<aclnt> c = aclnt::alloc (axprt_stream::alloc (fd), sfs_program_1);
  sfs_initci (&conarg, path ? path : oldpath, SFS_SFS, &sfs_extensions);
  sendconnect (c);
}

void
srvinfo::sendconnect (ref<aclnt> c)
{
  c->call (SFSPROC_CONNECT, &conarg, &conres,
	   wrap (this, &srvinfo::gotconres, c));
}

void
srvinfo::gotconres (ref<aclnt> c, clnt_stat err)
{
  str mypath = path ? path : oldpath;
  if (err == RPC_CANTDECODEARGS && sfs_nextci (&conarg)) {
    sendconnect (c);
    return;
  }
  if (err) {
    warn << mypath << ": " << err << "\n";
    fail (EIO);
    return;
  }
  if (conres.status) {
    warn << mypath << ": " << conres.status << "\n";
    switch (conres.status) {
    default:
    case SFS_NOSUCHHOST:
      fail (ENOENT);
      return;
    case SFS_NOTSUPP:
      fail (EPROTONOSUPPORT);
      return;
    case SFS_TEMPERR:
      fail (EAGAIN);
      return;
    case SFS_REDIRECT:
      {
	ptr<revocation> r = revocation::alloc (*conres.revoke);
	if (r) {
	  delaycb (300, wrap (r, &revocation::nop));
	  flushpath (mypath);
	  for (size_t n = waitq.size (); n-- > 0;)
	    (*waitq.pop_front ()) (0);
	}
	fail (EAGAIN);
	return;
      }
    }
  }

  ref<const sfs_servinfo_w> si = 
    sfs_servinfo_w::alloc (conres.reply->servinfo);
  int relno = si->get_relno ();
  int progno = si->get_progno ();
  int versno = si->get_versno ();
  if ((path && !si->ckpath (path))
      || (oldpath && !si->ckpath (oldpath))) {
    if (path)
      warn << path << ": server is " << si->mkpath () << "\n";
    else
      warn << oldpath << ": server is " << si->mkpath (1) << "\n";
    fail (ENOENT);
    return;
  }

  srvl = NULL;

  if (si->get_port () != port) {
    vec<alloccb_t> q;
    swap (q, waitq);
    fail (EAGAIN);
    afs_sfsroot->symlink (si->mkpath (), mypath);
    delaycb (15, wrap (delcpath, mypath));
    while (!q.empty ())
      (*q.pop_front ()) (0);
    return;
  }

  if (!path) {
    path = si->mkpath (2, port);
    flushpath (oldpath);
    afs_sfsroot->symlink (path, oldpath);
    if (srvinfo *nsi = srvtab[path]) {
      assert (!nsi->oldpath);
      nsi->oldpath = oldpath;
      osrvtab.remove (this);
      osrvtab.insert (nsi);
      path = NULL;
      oldpath = NULL;
      fail (0);
      return;
    }
    srvtab.insert (this);
  }

  cdp = release::cdlookup (relno, progno, versno);
  if (!cdp) {
    warn << path << ": no client for program " << progno << ", version "
	 << versno << " (release " << relno / 100
	 << "." << relno % 100 << ")\n";
    fail (EPROTONOSUPPORT);
    return;
  }
  cdp->servers.insert_head (this);

  if (!cdp->c) {
    warn << path << ": client for program " << progno << ", version "
	 << versno << " is dead\n";
    fail (EAGAIN);
    return;
  }
  cdp->x->sendfd (static_cast<axprt_stream *> (c->xprt ().get ())->reclaim ());
  if (!cdp->c) {
    warn << path << ": client for program " << progno << ", version "
	 << versno << " is dead\n";
    fail (EAGAIN);
    return;
  }

  sfscd_mountarg arg;
  arg.carg = conarg;
  *arg.cres.alloc () = *conres.reply;
  if (dnsname)
    arg.hostname = dnsname;
  cdp->c->call (SFSCDPROC_MOUNT, &arg, &mntres,
		wrap (this, &srvinfo::gotmntres));
}

static str
sock2str (int fd)
{
  sockaddr_in sin;
  socklen_t sinlen = sizeof (sin);
  int n;
  bzero (&sin, sizeof (&sin));
  if (getsockname (fd, (sockaddr *) &sin, &sinlen) < 0
      || sin.sin_family != AF_INET)
    return "-";

  sinlen = sizeof (n);
  if (getsockopt (fd, SOL_SOCKET, SO_TYPE, (char *) &n, &sinlen) < 0)
    return "-";
  switch (n) {
  case SOCK_STREAM:
    return strbuf ("TCP:%d", ntohs (sin.sin_port));
  case SOCK_DGRAM:
    return strbuf ("UDP:%d", ntohs (sin.sin_port));
  default:
    return "-";
  }
}

void
srvinfo::gotmntres (clnt_stat err)
{
  if (err || mntres.err) {
    fail (EIO);
    return;
  }
  cdmounted = true;
  int fd = cdp->x->recvfd ();
  if (fd < 0) {
    warn << "srvinfo::gotmntres: did not receive file descriptor\n";
    fail (EIO);
    return;
  }

  nfsinfo = strbuf ()
    << hexdump (mntres.reply->fh.base (), mntres.reply->fh.size ())
    << " "
    << sock2str (fd);

#if FIX_MNTPOINT
  if (opt_fix_mntpoint) {
    afs_linuxbug->mkdir (path)->mkdir ("r");
    afs_sfsroot->symlink (mpof (path), path);
  }
  else
#endif /* FIX_MNTPOINT */
    afs_sfsroot->mkctdir (path);
  mnt_mount (fd, /* hostname*/ path, mpof (path),
	     mntres.reply->mntflags, mntres.reply->fh,
	     wrap (this, &srvinfo::gotnfsmntres));
}

void
srvinfo::gotnfsmntres (int err, u_int64_t fsid)
{
  if (err) {
    warn << "mount (" << path << "): " << strerror (err) << "\n";
    fail (err);
    return;
  }
  devno = fsid;
  update_devdb ();
  ready ();
}

void
srvinfo::ready ()
{
  waiting = false;
  while (!waitq.empty ())
    (*waitq.pop_front ()) (error);
  if (destroyed)
    unmount (NUOPT_FORCE);
  else
    timeout ();
}

void
srvinfo::unmountcb (cbi::ptr cb, int err)
{
  if (terminating && err != EBUSY && err != EAGAIN)
    err = 0;
  if (err)
    waiting = false;
  if (cb)
    (*cb) (err);
  if (!err) {
    if (waitq.empty ())
      delete this;
    else {
      vec<alloccb_t> wq;
      str p = path;
      swap (wq, waitq);
      delete this;
      while (!wq.empty ())
	srvinfo::alloc (p, wq.pop_front ());
    }
  }
}

void
srvinfo::unmount (int flags, cbi::ptr cb)
{
#if 0
  warn << "unmounting: " << path << " (flags = "
       << strbuf ("0x%x", flags) << ")\n";
#endif
  if (!waiting) {
    waiting = true;
    mnt_umount (mpof (path), flags, wrap (this, &srvinfo::unmountcb, cb));
  }
  else if (cb)
    (*cb) (EBUSY);
}

void
srvinfo::destroy (bool stale)
{
  if (waiting && stale) {
    destroyed = true;
    mnt_umount (mpof (path), NUOPT_STALE|NUOPT_NOOP, cbi_null);
  }
  else if (!destroyed) {
    timecb_remove (tmo);
    tmo = NULL;
    destroyed = true;
    unmount (NUOPT_FORCE | (stale ? NUOPT_STALE : 0));
    timeout ();
  }
}

void
srvinfo::destroy (const str &path, cdaemon *rcdp, bool stale)
{
  srvinfo *si = srvlookup (path);
  if (si && (!rcdp || rcdp == si->cdp))
    si->destroy (stale);
}

void
srvinfo::idle (const str &path, cdaemon *rcdp)
{
  srvinfo *si = srvlookup (path);
  if (si && (!rcdp || rcdp == si->cdp))
    si->unmount (NUOPT_NLOG);
}

void
srvinfo::show (const str &path, cdaemon *rcdp, bool showit)
{
  srvinfo *si = srvlookup (path);
  if (si && (!rcdp || rcdp == si->cdp)) {
    si->visible_flag = showit;
    if (!showit && !si->waiting)
      si->unmount (NUOPT_NLOG);
  }
}

void
srvinfo::revoke (const str &path)
{
  srvinfo *si = srvlookup (path);
  if (si) {
    if (si->cdp && si->cdp->c)
      si->cdp->c->call (SFSCDPROC_CONDEMN, &si->path, NULL, aclnt_cb_null);
    si->destroy (false);
  }
}

void
srvinfo::printdev (strbuf *sb, bool donfsinfo, srvinfo *si)
{
  if (si->devno != badfsid) {
    sb->fmt ("0x%" U64F "x ", si->devno) << si->path << " " << si->cdp->name;
    if (donfsinfo && si->nfsinfo)
      (*sb) << " " << si->nfsinfo;
    (*sb) << "\n";
  }
}

str
srvinfo::devlist ()
{
  strbuf sb;
  srvtab.traverse (wrap (*srvinfo::printdev, &sb, false));
  return sb;
}

str
srvinfo::nfslist ()
{
  strbuf sb;
  if (!rootnfsinfo) {
    nfs_fh3 fh;
    afs_root->mkfh3 (&fh);
    rootnfsinfo = strbuf () << hexdump (fh.data.base (), fh.data.size ())
			    << " " << sock2str (afsfd);
  }
  sb.fmt ("0x%" U64F "x . - ", root_dev) << rootnfsinfo << "\n";
  srvtab.traverse (wrap (*srvinfo::printdev, &sb, true));
  return sb;
}
