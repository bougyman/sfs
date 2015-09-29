/* $Id: agentdir.C,v 1.15 2004/03/10 21:34:40 kaminsky Exp $ */

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

#include "agent.h"
#include "agentmisc.h"

vec<sfsagent_certprog> certprogs;
vec<rxfilter> certfilters;
vec<sfsagent_revokeprog> revokeprogs;
vec<rxfilter> revokefilters;
bhash<sfs_hash> norevoke;
sfsagent_srpcacheprog srpcacheprog;

static str
checkprefix (str name, const str &prefix)
{
  if (name.len () >= prefix.len ()
      && !memcmp (name, prefix, prefix.len ()))
    return substr (name, prefix.len (), name.len () - prefix.len ());
  return NULL;
}

void
sfslookup (str name, callback<void, sfsagent_lookup_type, str>::ref cb, 
	   u_int certno, str res)
{
  for (;; certno++) {
    if (res || certno >= certprogs.size ()) {
      if (res && res.len ()) {
	if (res[res.len () - 1] == '\n')
	  res = substr (res, 0, res.len () - 1);
	(*cb) (LOOKUP_MAKELINK, res);
      }
      else
	(*cb) (LOOKUP_NOOP, NULL);
      return;
    }
    str n = checkprefix (certprogs[certno].prefix, name);
    if (n) {
      (*cb) (LOOKUP_MAKEDIR, n);
      return;
    }
    n = checkprefix (name, certprogs[certno].prefix);
    if (n && certfilters[certno].check (n)) {
      runprog (certprogs[certno].av, n,
	       wrap (sfslookup, name, cb, certno + 1));
      return;
    }
  }
}

static void
dorevcheck (str location, ref<sfs_hash> hostid,
	    callback<void, const sfsagent_revoked_res *>::ref cb,
	    bool block, u_int revno, str res)
{
  sfsagent_revoked_res rr;
  sfs_pathrevoke_w *w = NULL;
  if (res) {
    rr.set_type (REVOCATION_CERT);
    if (str2xdr (*rr.cert, res) && (w = New sfs_pathrevoke_w (*rr.cert)) &&
	w->check () && w->si->ckhostid_client (hostid)
	&& location == rr.cert->msg.path.hostname) {
      if (w) delete w;
      (*cb) (&rr);
      return;
    }
    else if (block) {
      rr.set_type (REVOCATION_BLOCK);
      (*cb) (&rr);
      return;
    }
  }
  if (revno >= revokeprogs.size ()) {
    rr.set_type (REVOCATION_NONE);
    (*cb) (&rr);
    return;
  }
  block = revokeprogs[revno].block && revokefilters[revno].check (location);
  runprog (revokeprogs[revno].av, armor32 (hostid->base (), hostid->size ()),
	   wrap (dorevcheck, location, hostid, cb, block, revno + 1));
}

void
revcheck (str name, callback<void, const sfsagent_revoked_res *>::ref cb)
{
  str location;
  ref<sfs_hash> hostid (New refcounted<sfs_hash>);
  if (!sfs_parsepath (name, &location, hostid) || norevoke[*hostid]) {
    warn << "revocation check on bad or non-revocable path: " << name << "\n";
    sfsagent_revoked_res rr (REVOCATION_NONE);
    (*cb) (&rr);
    return;
  }
  dorevcheck (location, hostid, cb, false, 0, NULL);
}

rxfilter::rxfilter (const str &f, const str &e)
{
  if (f.len () && !filter.compile (f))
    warn << filter.geterr ();
  if (e.len () && !exclude.compile (e))
    warn << exclude.geterr ();
}

bool
rxfilter::check (const str &n)
{
  return (filter.geterr () || filter.search (n))
    && (exclude.geterr () || !exclude.search (n));
}

class agentprog {
  enum { maxres = 8192 };

  cbs cb;
  strbuf sb;
  int fd;
  pid_t pid;
  bool error;

  agentprog (cbs c) : cb (c), fd (-1), pid (-1), error (true) {}
  PRIVDEST ~agentprog ();
  void stop ();
  void input ();
  void reap (int status);
public:
  static void alloc (const sfsagent_cmd &av, str target, cbs cb);
};

agentprog::~agentprog ()
{
  input ();

  str res;
  if (!error)
    res = sb;
  stop ();
  (*cb) (res);
}

void
agentprog::stop ()
{
  if (fd >= 0) {
    fdcb (fd, selread, NULL);
    close (fd);
    fd = -1;
  }
  if (pid != -1)
    kill (pid, SIGTERM);
  error = true;
}

void
agentprog::input ()
{
  if (fd < 0)
    return;
  while (sb.tosuio ()->resid () <= maxres
	 && sb.tosuio ()->input (fd, maxres + 1 - sb.tosuio ()->resid ()) > 0)
    ;
  if (sb.tosuio ()->resid () > maxres)
    stop ();
}

void
agentprog::reap (int status)
{
  pid = -1;
  if (status)
    stop ();
  delete this;
}

static void
voidclose (int fd)
{
  close (fd);
}
void
agentprog::alloc (const sfsagent_cmd &av, str target, cbs c)
{
  agentprog *ap = New agentprog (c);

  vec<char *> argv;
  argv.setsize (av.size () + 2);
  for (u_int i = 0; i < av.size (); i++)
    argv[i] = const_cast<char *> (av[i].cstr ());
  if (target) {
    argv[av.size ()] = const_cast<char *> (target.cstr ());
    argv[av.size () + 1] = NULL;
  }
  else
    argv[av.size ()] = NULL;

  int fds[2];
  if (pipe (fds) < 0) {
    warn ("pipe: %m\n");
    delete ap;
    return;
  }
  ap->fd = fds[0];
  make_async (ap->fd);
  ap->pid = aspawn (argv[0], argv.base (), 0, fds[1], 2,
		    wrap (voidclose, fds[0]));
  close (fds[1]);
  if (ap->pid < 0) {
    warn ("fork: %m\n");
    delete ap;
    return;
  }

  ap->error = false;
  fdcb (ap->fd, selread, wrap (ap, &agentprog::input));
  chldcb (ap->pid, wrap (ap, &agentprog::reap));
}

void
runprog (const sfsagent_cmd &av, str target, cbs cb)
{
  agentprog::alloc (av, target, cb);
}

static void
load_srp_cache_cb (cbv cb, str s)
{
  if (s) {
    warn << "Loading SRP cache\n";
    //warn << s;
  }
  else {
    warn << "Could not load SRP cache\n";
    (*cb) ();
    return;
  }

  str line;
  strbuf ss = s;
  suio *sss = ss.tosuio ();

  srpnames.clear ();
  while ((line = suio_getline (sss))) {
    const char *r = line.cstr ();
    char *p = strchr (r, ' ');
    if (!p) continue;
    char *q = strchr (p + 1, ' ');
    if (q) continue;

    str srpname = substr (line, 0, p - r);
    str sfsname (p + 1);
    if (srpname.len () > 0 && sfsname.len () > 0)
      srpnames.insert (srpname, sfsname);
  }

  (*cb) ();
}

void
load_srp_cache (cbv cb)
{
  if (srpcacheprog.size () > 0)
    runprog (srpcacheprog, NULL, wrap (load_srp_cache_cb, cb));
  else
    (*cb) ();
}

static void
store_srp_cache_cb (str s)
{
  if (s)
    warn << "Storing SRP cache\n";
  else
    warn << "Could not store SRP cache\n";
}

void
store_srp_cache (sfsagent_srpname_pair *pair)
{
  str s = pair->srpname << " " << pair->sfsname;
  if (srpcacheprog.size () > 0)
    runprog (srpcacheprog, s, wrap (store_srp_cache_cb));
}
