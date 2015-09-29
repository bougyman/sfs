/* $Id: sfssd.C,v 1.53 2004/09/19 22:02:35 dm Exp $ */

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

#include "sfssd.h"
#include "parseopt.h"
#include "rxx.h"
#include <dirent.h>

str configfile;
str revocationdir;
list<sfssrv, &sfssrv::llink> services;
ihash<const vec<str>, sfssrv_exec, &sfssrv_exec::argv,
      &sfssrv_exec::link> exectab;
list<server, &server::link> serverlist;
bool hup_lock = true;

static vec<sockaddr *> listenaddrs;

static void newserv (int fd);
class listener {
  listener &operator= (const listener &);
  listener (const listener &);
public:
  const int fd;
  listener (int f) : fd (f) {
    make_async (fd);
    close_on_exec (fd);
    listen (fd, 5);
    fdcb (fd, selread, wrap (newserv, fd));
  }
  ~listener () {
    fdcb (fd, selread, NULL);
    close (fd);
  }
};
static vec<ref<listener> > listeners;

sfssrv::sfssrv ()
{
  services.insert_head (this);
}

sfssrv::~sfssrv ()
{
  services.remove (this);
}

void
sfssrv_unix::getpkt (const char *, ssize_t, const sockaddr *)
{
  /* We shouldn't receive anything, so assume this is an EOF */
  warn << "EOF from " << name () << "\n";
  x = NULL;
}

void
sfssrv_unix::setx (ptr<axprt_unix> xx)
{
  if ((x = xx))
    x->setrcb (wrap (this, &sfssrv_unix::getpkt));
}

void
sfssrv_unix::clone (ref<axprt_clone> xc, svccb *sbp)
{
  if (!x || x->ateof ()) {
    launch ();
    if (!x || x->ateof ()) {
      sbp->replyref (sfs_connectres (SFS_TEMPERR));
      return;
    }
  }
  sbp->ignore ();
  x->clone (xc);
}

void
sfssrv_sockpath::launch ()
{
  int fd = unixsocket_connect (path);
  if (fd < 0)
    warn << path << ": " << strerror (errno) << "\n";
  else
    setx (axprt_unix::alloc (fd));
}

str
sfssrv_sockpath::name ()
{
  return strbuf ("socket %s", path.cstr ());
}

void
sfssrv_exec::setprivs ()
{
  if ((uid || gid) && setgroups (0, NULL))
    fatal ("could not void grouplist: %m\n");
  if (gid && setgid (*gid))
    warn ("could not setgid (%d): %m\n", *gid);
  if (uid && setuid (*uid))
    warn ("could not setuid (%d): %m\n", *uid);
}

void
sfssrv_exec::launch ()
{
  setx (axprt_unix_aspawnv (argv[0], argv, 0,
			    wrap (this, &sfssrv_exec::setprivs)));
}

sfssrv_exec::sfssrv_exec (const vec<str> &av)
  : argv (av)
{
  assert (!argv.empty ());
  exectab.insert (this);
}

sfssrv_exec::~sfssrv_exec ()
{
  exectab.remove (this);
}

str
sfssrv_exec::name ()
{
  strbuf sb;
  sb << argv[0];
  for (u_int i = 1; i < argv.size (); i++)
    sb << " " << argv[i];
  return sb;
}

bool
extension::covered (const bhash<str> &eh)
{
  for (const str *ep = names.base (); ep < names.lim (); ep++)
    if (!eh[*ep])
      return false;
  return true;
}

bool
extension::covered (const vec<str> &ev)
{
  bhash<str> eh;
  for (const str *ep = ev.base (); ep < ev.lim (); ep++)
    eh.insert (*ep);
  return covered (eh);
}

release::release (u_int32_t r)
  : rel (r)
{
  extlist.insert_head (New extension);
}

release::~release ()
{
  extension *e, *ne;
  for (e = extlist.first; e; e = ne) {
    ne = extlist.next (e);
    delete e;
  }
}

static void
pushext (vec<str> *evp, const str &e)
{
  evp->push_back (e);
}

extension *
release::getext (const vec<str> &ev)
{
  bhash<str> eh;
  for (const str *sp = ev.base (); sp < ev.lim (); sp++)
    eh.insert (*sp);
  for (extension *e = extlist.first; e; e = extlist.next (e))
    if (eh.size () == e->names.size () && e->covered (ev))
      return e;
  extension *e = New extension;
  eh.traverse (wrap (pushext, &e->names));
  extlist.insert_head (e);
  return e;
}

server::server (const str &h, sfs_hash *hid)
  : host (h)
{
  if (hid) {
    hostid.alloc ();
    *hostid = *hid;
  }
  serverlist.insert_head (this);
}

server::~server ()
{
  serverlist.remove (this);
  reltab.deleteall ();
}

release *
server::getrel (u_int32_t r)
{
  release *rp, *ret;
  ret = rp = reltab.root ();
  while (rp) {
    if (r <= rp->rel && rp->rel <= ret->rel)
      ret = rp;
    if (r <= rp->rel)
      rp = reltab.left (rp);
    else
      rp = reltab.right (rp);
  }
  return ret;
}

bool
server::clone (ref<axprt_clone> x, svccb *sbp, const char *source,
	       u_int32_t rel, sfs_service service, const bhash<str> &eh)
{
  for (release *r = getrel (rel); r; r = reltab.next (r))
    for (extension *e = r->extlist.first; e; e = r->extlist.next (e))
      if (e->covered (eh))
	if (sfssrv **srvp = e->srvtab[service]) {
	  sfssrv *srv = *srvp;
	  warn ("accepted connection from %s for ", source)
	    << srv->name () << "\n";
	  srv->clone (x, sbp);
	  return true;
	}
  return false;
}

static bool
parse_service (vec<str> &av, extension *e, str errpref)
{
  u_int32_t snum;
  str usage = strbuf ()
    << errpref << ": usage: Service num prog [arg ...]\n"
    << errpref << ":        Service num -u path\n"
    << errpref << ":        Service num -t server [port]\n";
  if (av.size () < 3 || !convertint (av[1], &snum)) {
    warn << usage;
    return false;
  }
  if (!e) {
    warn << errpref
	 << ": Service must follow Release or Extensions\n";
    return false;
  }
  if (e->srvtab[snum]) {
    warn << errpref
	 << ": Service " << snum << " already defined\n";
    return false;
  }
  av.pop_front ();
  av.pop_front ();

  if (av[0][0] != '-') {
    av[0] = fix_exec_path (av[0]);
    sfssrv *ss = exectab[av];
    if (!ss)
      ss = New sfssrv_exec (av);
    e->srvtab.insert (snum, ss);
    return true;
  }
  else if (av[0] == "-u" && av.size () == 2) {
    sfssrv *ss = New sfssrv_sockpath (av[1]);
    e->srvtab.insert (snum, ss);
    return true;
  }
  else if (av[0] == "-t" && av.size () >= 2 && av.size () <= 3) {
    u_int16_t port = 0;
    if (av.size () == 2 || convertint (av[2], &port)) {
      sfssrv *ss = New sfssrv_proxy (av[1], port);
      e->srvtab.insert (snum, ss);
      return true;
    }
  }
  warn << usage;
  return false;
}


static rxx versrx ("^(\\d+)(-(\\d+))?$");
static void
parseconfig ()
{
  str cf = configfile;
  parseargs pa (cf);
  bool errors = false;

  str hostname;
  rpc_ptr<sfs_hash> hostid;
  server *s = NULL;
  release *r = NULL;
  extension *e = NULL;
  char *c;

  int line;
  vec<str> av;
  while (pa.getline (&av, &line)) {
    if (!strcasecmp (av[0], "BindAddr")) {
      in_addr addr;
      u_int16_t port = 0;
      if (av.size () < 2 || av.size () > 3
	  || !inet_aton (av[1], &addr)
	  || (av.size () == 3 && !convertint (av[2], &port))) {
	warn << cf << ":" << line
	     << ": usage: BindAddr addr [port]\n";
	errors = true;
	continue;
      }
      if (!port)
	port = sfs_defport ? sfs_defport : SFS_PORT;
      sockaddr_in *sinp
	= static_cast<sockaddr_in *> (xmalloc (sizeof (*sinp)));
      bzero (sinp, sizeof (*sinp));
      sinp->sin_family = AF_INET;
      sinp->sin_port = htons (port);
      sinp->sin_addr = addr;
#ifdef HAVE_SA_LEN
      sinp->sin_len = sizeof (*sinp);
#endif /* HAVE_SA_LEN */
      listenaddrs.push_back (reinterpret_cast<sockaddr *> (sinp));
    }
    else if (!strcasecmp (av[0], "Server")) {
      if (av.size () != 2) {
	  warn << cf << ":" << line
	       << ": usage: Server {hostname|*}[:hostid]\n";
	  errors = true;
	  continue;
      }
      if (strchr (av[1], ':') || 
	  ((c = strchr (av[1], '@')) && strchr (c, ','))) {
	hostid.alloc ();
	if (!sfs_parsepath (av[1], &hostname, hostid)) {
	  warn << cf << ":" << line << ": bad hostname/hostid\n";
	  errors = true;
	  continue;
	}
      }
      else {
	hostid.clear ();
	if (av[1] == "*")
	  hostname = sfshostname ();
	else
	  hostname = av[1];
      }

      for (s = serverlist.first; s; s = serverlist.next (s))
	if (hostname == s->host
	    && ((hostid && s->hostid && *hostid == *s->hostid)
		|| (!hostid && !s->hostid)))
	  break;
      if (!s)
	s = New server (hostname, hostid);
      r = NULL;
      e = NULL;
    }
    else if (!strcasecmp (av[0], "Release")) {
      static rxx relrx ("^(\\d+)\\.(\\d\\d?)$");
      if (av.size () != 2 || (!relrx.search (av[1]) && av[1] != "*")) {
	warn << cf << ":" << line << ": usage Release { N.NN | * }\n";
	errors = true;
	r = NULL;
	continue;
      }
      if (!s) {
	warn << cf << ":" << line << ": Release must follow Server\n";
	errors = true;
	r = NULL;
	continue;
      }
      u_int32_t rel;
      if (av[1] == "*")
	rel = 0xffffffff;
      else
	rel = strtoi64 (relrx[1]) * 100 + strtoi64 (relrx[2]);
      r = s->reltab[rel];
      if (!r)
	s->reltab.insert ((r = New release (rel)));
      for (e = r->extlist.first; r->extlist.next (e); e = r->extlist.next (e))
	;
    }
    else if (!strcasecmp (av[0], "Extensions")) {
      av.pop_front ();
      e = r->getext (av);
    }
    else if (!strcasecmp (av[0], "Service")) {
      if (!parse_service (av, e, cf << ":" << line))
	errors = true;
    }
    else if (!strcasecmp (av[0], "HashCost")) {
      if (av.size () != 2 || !convertint (av[1], &sfs_hashcost)) {
	warn << cf << ":" << line << ": usage: HashCost <nbits>\n";
	errors = true;
      }
      else {
	if (sfs_hashcost > sfs_maxhashcost)
	  sfs_hashcost = sfs_maxhashcost;
	str s (strbuf ("SFS_HASHCOST=%d", sfs_hashcost));
	xputenv (s);
      }
    }
    else if (!strcasecmp (av[0], "RevocationDir")) {
      if (av.size () != 2) {
	warn << cf << ":" << line << ": usage: RevocationDir <directory>\n";
	errors = true;
      }
      else {
	revocationdir = av[1];
      }
    }
    else {
      errors = true;
      warn << cf << ":" << line << ": unknown directive '"
	   << av[0] << "'\n";
    }
  }

  if (errors)
    fatal ("parse errors in configuration file\n");
}

static void
sclone (ref<asrv> s, ref<axprt_clone> x, sockaddr_in sin, svccb *sbp)
{
  s->setcb (NULL);
  if (!sbp) {
    warn ("invalid connect from %s\n", inet_ntoa (sin.sin_addr));
    return;
  }
  if (sbp->proc () != SFSPROC_CONNECT) {
    sbp->reject (PROC_UNAVAIL);
    return;
  }

  sfs_connectarg *arg = sbp->Xtmpl getarg<sfs_connectarg> ();
  u_int32_t rel;
  sfs_service service;
  str name;
  sfs_hash hostid;
  rpc_vec<sfs_extension, RPC_INFINITY> *extensions;

  switch (arg->civers) {
  case 4:
    rel = 4;
    service = arg->ci4->service;
    name = arg->ci4->name;
    hostid = arg->ci4->hostid;
    extensions = &arg->ci4->extensions;
    break;
  case 5:
    rel = arg->ci5->release;
    service = arg->ci5->service;
    if (!sfs_parsepath (arg->ci5->sname, &name, &hostid))
      name = arg->ci5->sname;
    extensions = &arg->ci5->extensions;
    break;
  default:
    sbp->reject (GARBAGE_ARGS);
    return;
  }

  bhash<str> eh;
  for (const sfs_extension *ep = extensions->base ();
       ep < extensions->lim (); ep++)
    eh.insert (*ep);

  sfs_pathrevoke cert;
  str rawcert = file2str (revocationdir << "/" << 
			  armor32 (hostid.base (), hostid.size ()));
  if (rawcert && str2xdr (cert, rawcert)) {
    sfs_connectres res(SFS_REDIRECT);
    res.revoke->msg = cert.msg;
    res.revoke->sig = cert.sig;
    sbp->reply (&res);
    return;
  }

  const char *source = inet_ntoa (sin.sin_addr);

  server *srv;
  for (srv = serverlist.first; srv; srv = serverlist.next (srv))
    if (srv->host == name && srv->hostid && *srv->hostid == hostid)
      if (srv->clone (x, sbp, source, rel, service, eh))
	return;
      else
	break;
  for (srv = serverlist.first; srv; srv = serverlist.next (srv))
    if (srv->host == name && !srv->hostid)
      if (srv->clone (x, sbp, source, rel, service, eh))
	return;
      else
	break;
  for (srv = serverlist.first; srv; srv = serverlist.next (srv))
    if (srv->host == name)
      if (srv->clone (x, sbp, source, rel, service, eh))
	return;
  for (srv = serverlist.first; srv; srv = serverlist.next (srv))
    if (srv->clone (x, sbp, source, rel, service, eh))
      return;
  sbp->replyref (sfs_connectres (SFS_NOSUCHHOST));
}

static void
newserv (int fd)
{
  sockaddr_in sin;
  bzero (&sin, sizeof (sin));
  socklen_t sinlen = sizeof (sin);
  int nfd = accept (fd, (sockaddr *) &sin, &sinlen);
  if (nfd >= 0) {
    close_on_exec (nfd);
    tcp_nodelay (nfd);
    ref<axprt_clone> x = axprt_clone::alloc (nfd);
    ref<asrv> s = asrv::alloc (x, sfs_program_1);
    s->setcb (wrap (sclone, s, x, sin));
  }
  else if (errno != EAGAIN)
    warn ("accept: %m\n");
}

static void
dolisten ()
{
  for (sockaddr **sp = listenaddrs.base (); sp < listenaddrs.lim (); sp++) {
    sockaddr_in *sinp = reinterpret_cast<sockaddr_in *> (*sp);
    int fd = inetsocket (SOCK_STREAM, ntohs (sinp->sin_port),
			 ntohl (sinp->sin_addr.s_addr));
    if (fd < 0)
      warn ("could not bind TCP port %d: %m\n", ntohs (sinp->sin_port));
    else {
      if (sinp->sin_addr.s_addr == htonl (INADDR_ANY))
	warn ("listening on TCP port %d\n", ntohs (sinp->sin_port));
      else
	warn ("listening on %s TCP port %d\n",
	      inet_ntoa (sinp->sin_addr), ntohs (sinp->sin_port));
      listeners.push_back (New refcounted<listener> (fd));
    }
  }

  if (listeners.empty ())
    fatal ("no TCP ports to listen on\n");

  hup_lock = false;
}

static void
setaddrs (const vec<u_int16_t> *pv)
{
  for (u_int i = 0; i < pv->size (); i++) {
    sockaddr_in *sinp = New sockaddr_in;
    bzero (sinp, sizeof (*sinp));
    sinp->sin_family = AF_INET;
    sinp->sin_port = htons ((*pv)[i]);
    sinp->sin_addr.s_addr = htonl (INADDR_ANY);
    listenaddrs.push_back (reinterpret_cast<sockaddr *> (sinp));
  }

  dolisten ();
}

static void
launchservers ()
{
  for (sfssrv *nsp, *sp = services.first; sp; sp = nsp) {
    nsp = services.next (sp);
    sp->launch ();
  }

  if (listenaddrs.empty () && sfs_defport) {
    sockaddr_in *sinp = New sockaddr_in;
    bzero (sinp, sizeof (*sinp));
    sinp->sin_family = AF_INET;
    sinp->sin_port = htons (SFS_PORT);
    sinp->sin_addr.s_addr = htonl (INADDR_ANY);
    listenaddrs.push_back (reinterpret_cast<sockaddr *> (sinp));
  }

  if (listenaddrs.empty ())
    whatport (sfshostname (), wrap (setaddrs));
  else
    dolisten ();
}

static void
restart ()
{
  if (hup_lock)
    return;
  hup_lock = true;

  warn ("version %s, pid %d, restarted with SIGHUP\n", VERSION,
	int (getpid ()));
  server *s, *ns;
  for (s = serverlist.first; s; s = ns) {
    ns = serverlist.next (s);
    serverlist.remove (s);
    delete s;
  }
  for (sfssrv *nsp, *sp = services.first; sp; sp = nsp) {
    nsp = services.next (sp);
    delete sp;
  }

  for (sockaddr **sap = listenaddrs.base (); sap < listenaddrs.lim (); sap++)
    xfree (*sap);
  listenaddrs.clear ();
  listeners.clear ();

  parseconfig ();
  delaycb (0, 100000000, wrap (launchservers));
}

static void
termsig (int sig)
{
  warn ("exiting on signal %d\n", sig);
  exit (1);
}

static void
usage ()
{
  warnx << progname << ": [-d] [-S sfs_config] [-f configfile]\n";
  exit (1);
}

int
main (int argc, char **argv)
{
  bool opt_nodaemon = false;
  setprogname (argv[0]);

  int ch;
  while ((ch = getopt (argc, argv, "df:S:")) != -1)
    switch (ch) {
    case 'd':
      opt_nodaemon = true;
      break;
    case 'f':
      if (configfile)
	usage ();
      configfile = optarg;
      break;
    case 'S':
      {
	str sfsconf (strbuf ("SFS_CONFIG=%s", optarg));
	xputenv (sfsconf);
      }
    case '?':
    default:
      usage ();
    }
  argc -= optind;
  argv += optind;
  if (argc > 1)
    usage ();

  sfsconst_init ();
  if (!configfile)
    configfile = sfsconst_etcfile_required ("sfssd_config");

  parseconfig ();
  if (!revocationdir)
    revocationdir = sfsdir << "srvrevoke";
  if (!opt_nodaemon && !builddir) {
    daemonize ();
    sigcb (SIGINT, wrap (termsig, SIGINT));
    sigcb (SIGTERM, wrap (termsig, SIGTERM));
  }
  warn ("version %s, pid %d\n", VERSION, int (getpid ()));
  sigcb (SIGHUP, wrap (restart));
  launchservers ();

  amain ();
}
