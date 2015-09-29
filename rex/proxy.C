/* $Id: proxy.C,v 1.35 2004/09/19 22:02:24 dm Exp $ */

/*
 *
 * Copyright (C) 2000-2001 Eric Peterson (ericp@lcs.mit.edu)
 * Copyright (C) 2000 David Mazieres (dm@uun.org)
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

#include "proxy.h"
#include "qhash.h"
#include "axprt_crypt.h"
#include "sfsmisc.h"
#include "crypt.h"
#include "agentmisc.h"

str opt_proxyid;
str trigger_socket;
str sfs_user_dir;

static struct stat trigger_stat;

struct rexclnt {
  static u_int nclnt;

  ref<aclnt_resumable> c;
  ref<asrv_resumable> s;
  bool resumable;
  bool suspended;

  sfs_seqno seqno;
  vec<char> secretid;
  
  ihash_entry<rexclnt> tlink;

  qhash<int, ref<chanbase> > chantab;

  rexclnt (ref<axprt> x, sfs_seqno seqno);
  ~rexclnt ();

  bool fail ();
  void suspend ();
  bool resume (ref<axprt>);
      
  int chanalloc ();
  void dispatch (svccb *);
};

static ihash<sfs_seqno, rexclnt, &rexclnt::seqno, &rexclnt::tlink> clnttab;
u_int rexclnt::nclnt;
ptr<axprt_unix> rxprt;
ptr<asrv> rsrv;

rexclnt::rexclnt (ref<axprt> x, sfs_seqno seqno)
  : c (aclnt_resumable::alloc (x, rexcb_prog_1, wrap (this, &rexclnt::fail))),
    s (asrv_resumable::alloc (x, rex_prog_1, wrap (this, &rexclnt::dispatch))),
    resumable (false), suspended (false), seqno (seqno)
{
  nclnt++;
  clnttab.insert (this);
}

rexclnt::~rexclnt ()
{
  c->setfailcb (NULL);
  s->stop ();
  clnttab.remove (this);
  if (!--nclnt)
    exit (0);
}

bool
rexclnt::fail ()
{
  if (resumable) {
    suspend ();
    return true;
  }
  else {
    delete this;
    return false;
  }
}

void
rexclnt::suspend ()
{
  suspended = true;
  s->stop ();
  c->stop ();
}

bool
rexclnt::resume (ref<axprt> x)
{
  assert (resumable);
  if (s->resume (x)) {
    if (c->resume (x)) {
      suspended = false;
      return true;
    }
    else
      s->stop ();
  }
  return false;
}

int
rexclnt::chanalloc ()
{
  /*
   *  int i;
   *  for (i = 0; chantab[i]; i++)
   *    ;
   *  return i;
   *
   * kaminsky: we're not going to reuse channel numbers for now as 
   * the code was wrong before and we weren't keeping track of things
   * correctly
   */
  static u_int channel_numbers;
  return channel_numbers++;
}

void
rexclnt::dispatch (svccb *sbp)
{
  if (!sbp) {
    fail ();
    return;
  }
  switch (sbp->proc ()) {
  case REX_NULL:
    sbp->reply (NULL);
    break;
  case REX_DATA:
    {
      rex_payload *argp = sbp->Xtmpl getarg<rex_payload> ();
      if (argp->fd < 0) {
	chantab.remove (argp->channel);
	sbp->replyref (false);
      }
      else if (chanbase *c = chantab[argp->channel])
	c->data (sbp);
      else
	sbp->replyref (false);
      break;
    }
  case REX_NEWFD:
    {
      rex_newfd_arg *argp = sbp->Xtmpl getarg<rex_newfd_arg> ();
      if (argp->fd < 0) {
	chantab.remove (argp->channel);
	sbp->replyref (false);
      }
      else if (chanbase *c = chantab[argp->channel])
	c->newfd (sbp);
      else
	sbp->replyref (false);
      break;
    }
  case REX_CLOSE:
  case REX_KILL:
    {
      rex_int_arg *argp = sbp->Xtmpl getarg<rex_int_arg> ();
      if (chanbase *c = chantab[argp->channel]) {
	if (sbp->proc () == REX_KILL)
	  c->kill (sbp);
	else
	  c->close (sbp);
      }
      else
	sbp->replyref (false);
      break;
    }
  case REX_MKCHANNEL:
    {
      rex_mkchannel_arg *argp = sbp->Xtmpl getarg<rex_mkchannel_arg> ();
      ptr<chanbase> cb;

      int cn = chanalloc ();
      cb = mkchannel_prog (c, cn, argp);

      rex_mkchannel_res res (SFS_TEMPERR);
      if (cb) {
	chantab.insert (cn, cb);
	res.set_err (SFS_OK);
	res.resok->channel = cn;
      }
      sbp->reply (&res);
      break;
    }
  case REX_GETENV:
    {
      rex_getenv_arg *arg = sbp->Xtmpl getarg<rex_getenv_arg> ();
      rex_getenv_res res (false);
      if (const char *p = getenv (*arg)) {
	res.set_present (true);
	*res.value = p;
      }
      sbp->reply (&res);
      break;
    }
  case REX_SETENV:
    {
      rex_setenv_arg *arg = sbp->Xtmpl getarg<rex_setenv_arg> ();
      if (!arg->name.len ()) {
	warn ("received REX_SETENV with null name\n");
	sbp->replyref (false);
	break;
      }
      if (strchr (arg->name, '=')) {
	warn ("received REX_SETENV with '=' in name\n");
	sbp->replyref (false);
	break;
      }
      str envname = strbuf ("%s=%s", arg->name.cstr (), arg->value.cstr ());
      if (xputenv (envname)) {
	warn ("dispatch (REX_SETENV call) setenv failed for (%m)\n");
	sbp->replyref (false);
	break;
      }
      sbp->replyref (true);
      break;
    }
  case REX_UNSETENV:
    {
      rex_unsetenv_arg *arg = sbp->Xtmpl getarg<rex_unsetenv_arg> ();
      if (arg->len ())
	unsetenv (arg->cstr ());
      else
        warn ("received unsetenv on null variable name\n");
      sbp->reply (NULL);
      break;
    }
  case REX_SETRESUMABLE:
    {
      rex_setresumable_arg *arg =
        sbp->Xtmpl getarg<rex_setresumable_arg> ();
      resumable = arg->resumable;
      if (arg->resumable) {
        secretid.setsize (arg->secretid->size ());
        memcpy (secretid.base (), arg->secretid->base (), secretid.size ());
      }
      sbp->reply (NULL);
      break;
    }
  case REX_RESUME:
    {
      rex_resume_arg *arg = sbp->Xtmpl getarg<rex_resume_arg> ();
      rexclnt *rc = clnttab[arg->seqno];
      if (!rc) {
        warn ("resume (%d): no such session\n", (int) arg->seqno);
	sbp->replyref (false);
	break;
      }
      if (memcmp (arg->secretid.base (), rc->secretid.base (),
                  rc->secretid.size ()) != 0) {
        warn ("resume (%d): bad secret id\n", (int) arg->seqno);
        sbp->replyref (false);
        break;
      }
      if (!rc->resumable) {
        warn ("resume (%p): not resumable\n", this);
	sbp->replyref (false);
	break;
      }
      rc->suspend ();

      s->stop ();
      c->stop ();
      if (rc->resume (s->xprt ())) {
	sbp->replyref (true);
	delete this;
      }
      else {
        s->start ();
        c->start ();
	sbp->replyref (false);
        warn ("resume failed\n");
      }
      break;
    }
  case REX_CLIENT_DIED:
    {
      sfs_seqno *seqno = sbp->Xtmpl getarg<sfs_seqno> ();
      rexclnt *rc = clnttab[*seqno];
      if (rc)
        delete rc;
      sbp->reply (NULL);
      break;
    }
  default:
    sbp->reject (PROC_UNAVAIL);
    break;
  }
}

static void
ctldispatch (svccb *sbp)
{
  if (!sbp) {
    warn ("EOF from rexd\n");
    rxprt = NULL;
    rsrv = NULL;
    return;
  }

  switch (sbp->proc ()) {
  case REXCTL_NULL:
    sbp->reply (NULL);
    break;
  case REXCTL_CONNECT:
    {
      rexctl_connect_arg *argp = sbp->Xtmpl getarg<rexctl_connect_arg> ();
      sfs_sessinfo &si = argp->si;
      int fd = rxprt->recvfd ();
      if (fd >= 0) {
	ref<axprt_crypt> x (axprt_crypt::alloc (fd));
	x->encrypt (si.ksc.base (), si.ksc.size (),
		    si.kcs.base (), si.kcs.size ());
	vNew rexclnt (x, argp->seqno);
      }
      else
	warn ("could not receive descriptor from rexd\n");
      // XXX - more stuff needs to be bzeroed
      bzero (si.ksc.base (), si.ksc.size ());
      bzero (si.kcs.base (), si.kcs.size ());
      sbp->reply (NULL);
      break;
    }
  default:
    sbp->reject (PROC_UNAVAIL);
    break;
  }
}

EXITFN (cleanup);
static void
cleanup ()
{
  struct stat sb;
  if (trigger_socket && !lstat (trigger_socket, &sb)
      && sb.st_dev == trigger_stat.st_dev
      && sb.st_ino == trigger_stat.st_ino)
    unlink (trigger_socket);
}

static void
death_trigger (int tfd)
{
  sockaddr_un sun;
  socklen_t sunlen = sizeof (sun);
  bzero (&sun, sizeof (sun));
  sun.sun_family = AF_UNIX;
  int s = accept (tfd, (sockaddr *) &sun, &sunlen);
  if (s < 0) {
    warn ("%s (accept): %m\n", trigger_socket.cstr ());
    return;
  }
#ifdef HAVE_GETPEEREID
  uid_t u;
  gid_t g;
  if (getpeereid (s, &u, &g) < 0) {
    warn ("%s (getpeereid): %m\n", trigger_socket.cstr ());
    close (s);
    return;
  }
  if (u && u != (myaid () & 0xffffffff)) {
    warn ("rejecting connection to %s from UID %u\n",
	  trigger_socket.cstr (), unsigned (u));
    close (s);
    return;
  }
#endif /* HAVE_GETPEEREID */
  fdcb (tfd, selread, NULL);
  close (tfd);

  warn ("previous proxy becoming unresumable\n");

  rexclnt *c = clnttab.first ();
  while (c) {
    rexclnt *cnext = clnttab.next (c);
    c->resumable = false;
    if (c->suspended)
      delete c;
    c = cnext;
  }
}

static void
set_death_trigger (int cfd, str sockpath)
{
  char c;
  int tfd = -1;
  if (readfd (cfd, &c, 1, &tfd) < 1 || tfd < 0)
    fatal ("could not bind socket for proxy ID %s\n", opt_proxyid.cstr ());
  close_on_exec (tfd);
  if (lstat (sockpath, &trigger_stat) || !S_ISSOCK (trigger_stat.st_mode))
    fatal ("%s disappeared\n", trigger_socket.cstr ());
  trigger_socket = sockpath;
  if (listen (tfd, 5) < 0)
    fatal ("could not listen on trigger socket for proxy ID %s\n",
	   opt_proxyid.cstr ());
  fdcb (cfd, selread, NULL);
  close (cfd);
  fdcb (tfd, selread, wrap (death_trigger, tfd));
}

static int
get_proxyidsock (str sockpath, int receiver)
{
  umask (077);
  for (int i = 0; i < 10; i++) {
    int s = unixsocket (sockpath);
    if (s >= 0)
      return (writefd (receiver, "", 1, s) != 1);
    if (errno != EADDRINUSE) {
      warn ("%s (bind): %m\n", sockpath.cstr ());
      return 1;
    }
    s = unixsocket_connect (sockpath);
    if (s >= 0) {
      close (s);
      int backoff = 1 << i;
      timeval tv = { backoff/10, (backoff%10) * 100000 };
      select (0, NULL, NULL, NULL, &tv);
    }
    else if (errno == ECONNREFUSED)
      unlink (sockpath);
    else {
      warn ("%s (connect): %m\n", sockpath.cstr ());
      return 1;
    }
  }
  return 1;
}

static void
set_proxyid ()
{
  str sockpath = sfs_user_dir << "/proxy-" << opt_proxyid;

  int fds[2];
  if (socketpair (AF_UNIX, SOCK_STREAM, 0, fds) < 0)
    fatal ("socketpair: %m\n");

  if (!afork ()) {
    close (fds[0]);
    int err = get_proxyidsock (sockpath, fds[1]);
    err_flush ();
    _exit (err);
  }

  close (fds[1]);
  close_on_exec (fds[0]);
  fdcb (fds[0], selread, wrap (set_death_trigger, fds[0], sockpath));
}


static void
timeout ()
{
  if (!rexclnt::nclnt)
    exit (0);
}

static void usage () __attribute__ ((noreturn));
static void
usage ()
{
  warnx << "usage: " << progname << " [-i proxy_id]\n";
  exit (1);
}

int
main (int argc, char **argv)
{
  setprogname (argv[0]);
  sfsconst_init ();
  
  int ch;
  while ((ch = getopt (argc, argv, "i:")) != -1)
    switch (ch) {
    case 'i':
      if (optarg[0] == '.' || strchr (optarg, '/'))
	fatal ("invalid proxy ID %s\n", optarg);
      if (strlen (optarg) + 1 > sizeof (((sockaddr_un *) 0)->sun_path))
	fatal ("proxy ID %s too long\n", optarg);
      opt_proxyid = optarg;
      break;
    default:
      usage ();
      break;
    }
  argc -= optind;
  argv += optind;

  if (argc > 0)
    fatal << "usage: " << progname << "\n";

  if (!isunixsocket (0))
    fatal ("stdin must be a unix domain socket.\n");

  sfs_user_dir = agent_userdir (myaid () & 0xffffffff, true);
  if (sfs_user_dir) {
    str envvar (strbuf ("SFS_USER_DIR=%s", sfs_user_dir.cstr ()));
    xputenv (envvar);
  }
  {
    str envvar (strbuf ("SFS_PROXY_PID=%d", getpid ()));
    xputenv (envvar);
  }

  if (opt_proxyid && sfs_user_dir) {
    progname = progname << " (" << opt_proxyid << ")";
    set_proxyid ();
    warn ("version %s, pid %d, id %s\n", VERSION, int (getpid ()),
	  opt_proxyid.cstr ());
  }
  else
    warn ("version %s, pid %d\n", VERSION, int (getpid ()));

  rxprt = axprt_unix::alloc (0);
  rsrv = asrv::alloc (rxprt, rexctl_prog_1, wrap (ctldispatch));

  timecb (time (NULL) + 120, wrap (timeout));

  sigcb (SIGINT, wrap (exit, 1));
  sigcb (SIGTERM, wrap (exit, 1));
  amain ();
}
