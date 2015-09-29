/* $Id: rexd.C,v 1.43 2004/09/19 22:02:25 dm Exp $ */

/*
 *
 * Copyright (C) 2000-2001 Eric Peterson (ericp@lcs.mit.edu)
 * Copyright (C) 2000-2001 Michael Kaminsky (kaminsky@lcs.mit.edu)
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

#include "arpc.h"
#include "rex_prot.h"
#include "crypt.h"
#include "sfsserv.h"
#include "sfscrypt.h"
#include "fdlim.h"
#include "rexcommon.h"

#define REXSESS_DEFAULT_PATH "/usr/bin:/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin"

pid_t ptydpid = 0;
int execprotect = 1;

ptr<sfspriv> sk;
sfs_servinfo servinfo;
ptr<sfs_servinfo_w> siw;
str newaid;

static void
cleanup ()
{
  if (ptydpid > 0)
    kill (ptydpid, SIGTERM);
}

class rexsess {
  ref<bool> destroyed;
  sfs_kmsg skdat;
  sfs_kmsg ckdat;
  seqcheck seqstate;
  ptr<axprt_unix> x;
  ptr<aclnt> c;

  static void postfork (const sfsauth_cred *credp);
  void ctlconnect (ref<bool> abort, ref<rexctl_connect_arg> arg,
		   ref<axprt_stream> xs);
  void seq2sessinfo (sfs_seqno seqno, sfs_hash *sidp, sfs_sessinfo *sip);
  void eof () { delete this; }

public:
  sfs_hash sessid;
  ihash_entry<rexsess> link;

  rexsess (const sfsauth_cred *credp, const rexd_spawn_arg *argp,
	   rexd_spawn_res *resp);
  ~rexsess ();
  void attach (str client_name, svccb *sbp);
};

ihash<sfs_hash, rexsess, &rexsess::sessid, &rexsess::link> sesstab;

const bool shellspec[128] = {
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0,
  1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1,
};
inline bool
isshellspec (u_char c)
{
  return c < 128 && shellspec[c];
}
static str
shellcmd (const vec<str> &av)
{
  strbuf cmd ("exec");
  for (const str *ap = av.base (); ap < av.lim (); ap++) {
    cmd << " ";
    for (const char *p = *ap; *p; p++) {
      if (isshellspec (*p))
	cmd.tosuio ()->print ("\\", 1);
      cmd.tosuio ()->print (p, 1);
    }
  }

  return cmd;
}

static bool
shellsafe (const char *shell)
{
  if (!validshell (shell))
    return false;
  if (strstr (shell, "/nologin"))
    return false;
  if (!strcmp (shell, "/dev/null"))
    return false;
  int n = strlen (shell);
  if (n >= 4 && !strcmp (shell + n - 4, "/vsh"))
    return false;
  return true;
}

rexsess::rexsess (const sfsauth_cred *credp, const rexd_spawn_arg *argp,
		  rexd_spawn_res *resp)
  : destroyed (New refcounted<bool> (false)), seqstate (32)
{
  resp->set_err (SFS_OK);
  rnd.getbytes (resp->resok->kmsg.kcs_share.base (),
		resp->resok->kmsg.kcs_share.size ());
  rnd.getbytes (resp->resok->kmsg.ksc_share.base (),
		resp->resok->kmsg.ksc_share.size ());
  ckdat = argp->kmsg;
  skdat = resp->resok->kmsg;

  seqstate.check (0);
  rex_mkkeys (NULL, NULL, &sessid, 0, skdat, ckdat);
  sesstab.insert (this);

  vec<str> av;
  av.push_back (newaid);
  assert (credp->type == SFS_UNIXCRED);
  av.push_back (strbuf ("-U%d", credp->unixcred->uid));

  if (argp->command.size ()) {
    if (shellsafe (credp->unixcred->shell)) {
      av.push_back ("--");
      av.push_back (fix_exec_path (argp->command[0]));
      for (size_t i = 1; i < argp->command.size (); i++)
	av.push_back (argp->command[i]);
    }
    else {
      av.push_back ("-G");
      av.push_back ("--");
      av.push_back (credp->unixcred->shell);
      av.push_back ("-c");
      vec<str> rav;
      rav.push_back (fix_exec_path (argp->command[0]));
      for (size_t i = 1; i < argp->command.size (); i++)
	rav.push_back (argp->command[i]);
      av.push_back (shellcmd (rav));
    }
  }

  av.push_back (NULL);

  /* Set up environment just for exec */
  const char *evarstosave[] = {
#ifdef MAINTAINER
    "ACLNT_TRACE",
    "ASRV_TRACE",
    "CALLBACK_TRACE",
    "DMALLOC_OPTIONS",
    "SFS_ROOT",
    "SFS_RUNINPLACE",
#endif /* MAINTAINER */
    "MALLOC_OPTIONS",
    "SFS_CONFIG",
    "SFS_HASHCOST",
    "SFS_HOSTNAME",
    "SFS_PORT",
    "SFS_RELEASE",
    "TMPDIR",
    NULL
  };

  vec<str> envs;
  for (int v = 0; evarstosave[v]; v++) {
    char *val = getenv (evarstosave[v]);
    if (val)
      envs.push_back (strbuf () << evarstosave[v] << "=" << val);
  }
  envs.push_back (strbuf () << "USER=" << credp->unixcred->username);
  envs.push_back (strbuf () << "LOGNAME=" << credp->unixcred->username);
  envs.push_back (strbuf () << "HOME=" << credp->unixcred->homedir);
  envs.push_back (strbuf () << "SHELL=" << credp->unixcred->shell);
  envs.push_back (strbuf () << "PATH=" REXSESS_DEFAULT_PATH);
#ifdef MAILPATH
  envs.push_back (strbuf () << "MAIL=" MAILPATH "/"
		  << credp->unixcred->username);
#endif

  vec<char *> env;
  for (const str *s = envs.base (), *e = envs.lim (); s < e; s++)
    env.push_back (const_cast<char *> (s->cstr ()));
  env.push_back (NULL);

  x = axprt_unix_aspawnv (newaid, av, 0, wrap (&postfork, credp), env.base ());
  x->allow_recvfd = false;
  c = aclnt::alloc (x, rexctl_prog_1);
  c->seteofcb (wrap (this, &rexsess::eof));
}

rexsess::~rexsess ()
{
  *destroyed = true;
  rpc_wipe (skdat);
  rpc_wipe (ckdat);
  sesstab.remove (this);
}

void
rexsess::postfork (const sfsauth_cred *credp)
{
  if (credp->type != SFS_UNIXCRED)
    fatal ("setpriv: invalid credential type %d\n", int (credp->type));

  GETGROUPS_T groups[NGROUPS_MAX];
  size_t ngroups = min<size_t> (credp->unixcred->groups.size () + 1,
				NGROUPS_MAX);
  groups[0] = credp->unixcred->gid;
  for (size_t i = 1; i < ngroups; i++)
    groups[i] = credp->unixcred->groups[i - 1];

  /* No setuid.  This must happen in an execed process, because we are
   * too paranoid about ptrace, signals, core dumps, etc. (given how
   * many private keys we have in memory). */
  if (setgroups (ngroups, groups) < 0)
    fatal ("setgroups: %m\n");
  if (setgid (groups[0]) < 0)
    fatal ("setgid: %m\n");
  if (setsid () < 0) 
    warn ("setsid: %m\n");

  if (char *p = getenv ("FDLIM_HARD")) {
    int n = atoi (p);
    if (n > fdlim_get (1))
      fdlim_set (n, -1);
  }
  if (char *p = getenv ("FDLIM_SOFT")) {
    int n = atoi (p);
    if (n > fdlim_get (0))
      fdlim_set (n, 0);
  }
}

void
rexsess::attach (str client_name, svccb *sbp)
{
  // XXX - dynamic_cast is busted in egcs
  axprt_stream *xsp
    = static_cast<axprt_stream *> (sbp->getsrv ()->xprt ().get ());
  ref<axprt_stream> xs (mkref (xsp));

  /* XXX - Note that what we are doing here does not pipeline.  If a
   * cilent sends a REXD_ATTACH RPC followed by another RPC (before
   * getting thre reply from the REXD_ATTACH), we may end up reading
   * both RPC's and discarding the second one (because we pass the
   * file descriptor off to the child process and discard any extra
   * data we have read and buffered). */
  xhinfo::xon (xs, false);
  rexd_attach_arg *argp = sbp->Xtmpl getarg<rexd_attach_arg> ();

  sfs_hash sid;
  ref<rexctl_connect_arg> ccarg = New refcounted<rexctl_connect_arg> ();
  ccarg->seqno = argp->seqno;
  ccarg->si.type = SFS_SESSINFO;
  rex_mkkeys (&ccarg->si.ksc, &ccarg->si.kcs, &sid, argp->seqno, skdat, ckdat);

  if (sid == argp->newsessid && seqstate.check (argp->seqno)) {
    sbp->replyref (rexd_attach_res (SFS_OK));
    xs->setwcb (wrap (this, &rexsess::ctlconnect, destroyed, ccarg, xs));
  }
  else {
    bzero (ccarg->si.kcs.base (), ccarg->si.kcs.size ());
    bzero (ccarg->si.ksc.base (), ccarg->si.ksc.size ());
    warn << client_name << ": newsessid mismatch\n";
    sbp->replyref (rexd_attach_res (SFS_BADLOGIN));
  }
}

void
rexsess::ctlconnect (ref<bool> abort, ref<rexctl_connect_arg> arg,
  		     ref<axprt_stream> xs)
{
  int fd = xs->reclaim ();
  sfs_sessinfo &si = arg->si;
  if (*abort || fd < 0) {
    bzero (si.kcs.base (), si.kcs.size ());
    bzero (si.ksc.base (), si.ksc.size ());
    if (fd >= 0)
      close (fd);
    return;
  }
  x->sendfd (fd);

  // XXX - c->call may leave un-bzeroed copies of session key around
  c->call (REXCTL_CONNECT, arg, NULL, aclnt_cb_null);
  bzero (si.kcs.base (), si.kcs.size ());
  bzero (si.ksc.base (), si.ksc.size ());
}

struct rexclient : public sfsserv {
  ptr<asrv> rexs;

  rexclient (ref<axprt_crypt> x)
    : sfsserv (x),
      rexs (asrv::alloc (x, rexd_prog_1, wrap (this, &rexclient::dispatch))) {}

  ptr<sfspriv> doconnect (const sfs_connectarg *ci, sfs_servinfo *si)
  { *si = servinfo; return ::sk; }
  void dispatch (svccb *sbp);
};

void
rexclient::dispatch (svccb *sbp)
{
  if (!sbp) {
    delete this;
    return;
  }

  switch (sbp->proc ()) {
  case REXD_NULL:
    sbp->reply (NULL);
    break;
  case REXD_SPAWN:
    {
      u_int32_t authno = sbp->getaui ();
      if (authno >= credtab.size () || credtab[authno].type != SFS_UNIXCRED) {
	sbp->reject (AUTH_BADCRED);
	break;
      }
      if (!validshell (credtab[authno].unixcred->shell)) {
	warn << "rejected user " << credtab[authno].unixcred->username
	     << " with invalid shell " << credtab[authno].unixcred->shell
	     << "\n";
	sbp->reject (AUTH_BADCRED);
	break;
      }
      rexd_spawn_res res;
      vNew rexsess (&credtab[authno],
		    sbp->Xtmpl getarg<rexd_spawn_arg> (), &res);
      sbp->replyref (res);
      break;
    }
  case REXD_ATTACH:
    {
      rexd_attach_arg *argp = sbp->Xtmpl getarg<rexd_attach_arg> ();
      if (rexsess *sp = sesstab[argp->sessid]) {
	sp->attach (client_name, sbp);
	delete this;
      }
      else {
        warn << client_name << ": attach to unknown session\n";
	sbp->replyref (rexd_attach_res (SFS_BADLOGIN));
      }
      break;
    }
  default:
    sbp->reject (PROC_UNAVAIL);
    break;
  }
}

void
client_accept (ptr<axprt_crypt> x)
{
  if (!x)
    fatal ("EOF from sfssd\n");
  vNew rexclient (x);
}

static void
loadkey (const char *path)
{
  if (!path)
    path = "sfs_host_key";
  str keyfile = sfsconst_etcfile (path);
  if (!keyfile)
    fatal << path << ": " << strerror (errno) << "\n";
  str key = file2wstr (keyfile);
  if (!key)
    fatal << keyfile << ": " << strerror (errno) << "\n";
  if (!(sk = sfscrypt.alloc_priv (key, SFS_DECRYPT)))
    fatal << "could not decode " << keyfile << "\n";
}

static void
usage ()
{
  fatal << "usage: " << progname << " [-k keyfile]\n";
}

int
main (int argc, char **argv)
{
  const char *keyfile = NULL;
  setprogname (argv[0]);
  sfsconst_init ();

  servinfo.set_sivers (7);
  servinfo.cr7->host.hostname = "";
  servinfo.cr7->host.port = 0;
  servinfo.cr7->release = 7;

  int ch;
  while ((ch = getopt (argc, argv, "k:h:")) != -1)
    switch (ch) {
    case 'k':
      keyfile = optarg;
      break;
    case 'h':
      servinfo.cr7->host.hostname = optarg;
      break;
    default:
      usage ();
    }
  if (optind < argc)
    usage ();

  warn ("version %s, pid %d\n", VERSION, int (getpid ()));
  loadkey (keyfile);

  servinfo.cr7->host.type = SFS_HOSTINFO;
  if (servinfo.cr7->host.hostname == "")
    servinfo.cr7->host.hostname = sfshostname ();
  if (!sk->export_pubkey (&servinfo.cr7->host.pubkey))
    fatal ("could not get pubkey\n");
  servinfo.cr7->prog = REXD_PROG;
  servinfo.cr7->vers = REXD_VERS;
  
  siw = sfs_servinfo_w::alloc (servinfo);

  if (!runinplace)
    chdir ("/");

  warn << "serving " << siw->mkpath () << "\n";
  newaid = fix_exec_path ("newaid");
  if (!newaid)
    fatal ("could not find newaid (should be in %s)\n", execdir.cstr ());

  str ptydpath = fix_exec_path ("ptyd");
  if (!ptydpath)
    warn ("could not find ptyd (should be in %s)\n", execdir.cstr ());
  else {
    char *av[2] = { "ptyd", NULL };
    
    ptydpid = spawn (ptydpath, av);
    
    if (ptydpid < 0)
      warn << ptydpath << ": " << strerror (errno) << "\n";
    else {
      warn << "spawning " << ptydpath << "\n";
      atexit (cleanup);
    }
  }
  mode_t m = umask (0);
  mkdir ("/tmp/.X11-unix", 01777);
  umask (m);
  
  sfssd_slave (wrap (client_accept));
  amain ();
}

