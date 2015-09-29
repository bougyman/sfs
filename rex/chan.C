/* $Id: chan.C,v 1.38 2004/09/19 22:02:24 dm Exp $ */

/*
 *
 * Copyright (C) 2001 Michael Kaminsky (kaminsky@lcs.mit.edu)
 * Copyright (C) 2001 Eric Peterson (ericp@lcs.mit.edu)
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
#include "aios.h"

static bool garbage_bool;

chanbase::chanbase (u_int32_t cn, ptr<aclnt> cc, pid_t p)
  : channo (cn), c (cc), pid (p)
{
  if (pid != -1)
    chldcb (pid, wrap (this, &chanbase::reap));
}

void
chanbase::kill (svccb *sbp)
{
  assert (sbp->prog () == REX_PROG && sbp->proc () == REX_KILL);
  rex_int_arg *argp = sbp->Xtmpl getarg<rex_int_arg> ();
  assert (argp->channel == channo);
  sbp->replyref (bool (pid != -1 && ::kill (pid, argp->val) >= 0));
}

void
chanbase::reap (int status)
{
  pid = -1;
  rex_int_arg arg;
  arg.channel = channo;
  arg.val = WIFEXITED (status) ? WEXITSTATUS (status) : -WTERMSIG (status);
  c->call (REXCB_EXIT, &arg, NULL, aclnt_cb_null);
}

void
chanfd::fdinfo::seterr ()
{
  if (fd >= 0) {
    while (!fdsendq.empty ())
      ::close (fdsendq.pop_front ());
    fdcb (fd, selread, NULL);
    fdcb (fd, selwrite, NULL);
    int savedfd = fd;
    fd = -1;
    wuio.clear ();
    ::close (savedfd);
  }
  reof = weof = true;
}

void
chanfd::fdinfo::close ()
{
  //signifies that it is ok to reuse fd
  closed = true;
}

void
chanfd::fdinfo::reset ()
{
  assert (closed && fd == -1 && !rsize && !wuio.resid ());
  closed = reof = weof = false;
}

chanfd::chanfd (u_int32_t cn, ref<aclnt> cc, const vec<int> f, pid_t p)
  : chanbase (cn, cc, p), destroyed (New refcounted<bool> (false))
{
  for (size_t i = 0; i < f.size (); i++)
    newfd (f[i]);
}

chanfd::~chanfd ()
{
  *destroyed = true;
}

int
chanfd::newfd (int rfd, bool _enablercb)
{
  size_t i;
  for (i = 0; i < fdi.size (); i++)
    if (fdi[i].fd == -1 && fdi[i].closed && !fdi[i].rsize)
      break;
  if (i == fdi.size ())
    fdi.push_back ();
      
  fdi[i].reset ();
  fdi[i].fd = rfd;

  fdi[i].isunixsocket = isunixsocket (rfd);

  if (_enablercb)
    enablercb (i);

  make_async (fdi[i].fd);

  return i;
}

void
chanfd::enablercb (int fdn)
{
  fdcb (fdi[fdn].fd, selread, wrap (this, &chanfd::rcb, fdn));
}

void
chanfd::disablercb (int fdn)
{
  fdcb (fdi[fdn].fd, selread, NULL);
}
    
ssize_t
chanfd::readfd (int fdn, void *buf, size_t len, bool &fdrecv)
{
  int rfd;
  ssize_t n = ::readfd (fdi[fdn].fd, buf, len, &rfd);
  if (rfd >= 0) {
    fdrecv = true;
    close_on_exec (rfd);
    rexcb_newfd_arg arg;
    arg.channel = channo;
    arg.fd = fdn;
    arg.newfd = newfd (rfd, false);
    ref<bool> okp (New refcounted<bool> (false));
    c->call (REXCB_NEWFD, &arg, okp,
	     wrap (this, &chanfd::newfdrep, arg.newfd, okp));
  }
  return n;
}

ssize_t
chanfd::readmore (int fd, char *buf, size_t len, size_t &numbytes)
{
  ssize_t n = 0;
//   int cnt = 0;
  numbytes = 0;
  while (numbytes < len) {
    n = read (fd, buf + numbytes, len - numbytes);
    if (n <= 0)
      break;
//     cnt++;
    numbytes += n;
    break;			// XXX - added by dm for benchmark
  }

//   warn << "readmore: n = " << n << "; numbytes = " << numbytes 
//        << "; cnt = " << cnt << "\n";
  return n;
}

void
chanfd::newfdrep (int fdn, ref <bool> okp, clnt_stat cs)
{
  if (!cs && *okp)
    enablercb (fdn);
}

void
chanfd::ccb (int fdn, size_t size, ref<bool> dest, ref<bool> okp, clnt_stat)
{
  if (*dest)
    return;
  if (!*okp)
    fdi[fdn].seterr ();
  bool stalled = !fdi[fdn].reof && fdi[fdn].rsize >= hiwat;
  assert (fdi[fdn].rsize >= size);
  fdi[fdn].rsize -= size;
  
  if (stalled && fdi[fdn].rsize < hiwat)
    enablercb (fdn);
}

void
chanfd::rcb (int fdn)
{
  rex_payload data;
  data.channel = channo;
  data.fd = fdn;

  char buf[16*1024];
  bool fdrecved = false;
  size_t numbytes = 0;
  ssize_t n = fdi[fdn].isunixsocket ?
    readfd (fdn, buf, sizeof (buf), fdrecved):
    readmore (fdi[fdn].fd, buf, sizeof (buf), numbytes);

  if (fdi[fdn].isunixsocket && n >= 0)
    numbytes = n;

//   warn << "isunixsocket = " << (fdi[fdn].isunixsocket ? "YES" : "NO") 
//        << "; numbytes = " << numbytes << "\n";

  if (numbytes > 0) {
    data.data.set (buf, numbytes);
    fdi[fdn].rsize += numbytes;
    if (fdi[fdn].rsize >= hiwat)
      disablercb (fdn);
    ref<bool> okp (New refcounted<bool> (false));
    c->call (REXCB_DATA, &data, okp,
	     wrap (this, &chanfd::ccb, fdn, numbytes, destroyed, okp));
  }

  if (n < 0 && errno == EAGAIN)
    return;

  if (n <= 0) {
    if (fdrecved)
      return;
    if (n < 0)
      warn ("chanfd::rcb:read(%d), rexfd:%d: %m\n", fdi[fdn].fd, fdn);
    data.data.clear ();
    fdi[fdn].reof = true;
    disablercb (fdn);
    c->call (REXCB_DATA, &data, &garbage_bool, aclnt_cb_null);
  }
}

void
chanfd::wcb (int fdn)
{
  if (fdi[fdn].wuio.resid ()) {
    assert (fdi[fdn].wuio.iovcnt () >= 1);
    if (fdi[fdn].fdsendq.empty ()) {
      if (fdi[fdn].wuio.output (fdi[fdn].fd) < 0) {
	fdi[fdn].seterr ();
	return;
      }
    }
    else {
      int n = writevfd (fdi[fdn].fd, fdi[fdn].wuio.iov (), 1,
			fdi[fdn].fdsendq.front ());
      if (n > 0) {
	::close (fdi[fdn].fdsendq.pop_front ());
	fdi[fdn].wuio.rembytes (n);
      }
      else {
	fdi[fdn].seterr ();
	return;
      }
    }
  }

  if (fdi[fdn].wuio.resid ())
    fdcb (fdi[fdn].fd, selwrite, (wrap (this, &chanfd::wcb, fdn)));
  else if (fdi[fdn].weof && fdi[fdn].reof)
    fdi[fdn].seterr ();
  else
    fdcb (fdi[fdn].fd, selwrite, NULL);
}

void
chanfd::data (svccb *sbp)
{
  assert (sbp->prog () == REX_PROG && sbp->proc () == REX_DATA);
  rex_payload *dp = sbp->Xtmpl getarg<rex_payload> ();
  assert (dp->channel == channo);
  if (dp->fd < 0 || implicit_cast<size_t> (dp->fd) >= fdi.size ()) {
    warn ("payload fd %d out of range\n", dp->fd);
    sbp->replyref (false);
    return;
  }
  int fdn = dp->fd;
  if (fdi[fdn].weof) {
    sbp->replyref (false);
    return;
  }

  if (dp->data.size ()) {
    bool wasempty = !fdi[fdn].wuio.resid ();
    fdi[fdn].wuio.print (dp->data.base (), dp->data.size ());
    fdi[fdn].wuio.iovcb (wrap (this, &chanfd::scb, dp->fd, sbp));
    if (wasempty)
      wcb (dp->fd);
  }
  else {
    fdi[fdn].weof = true;
    fdi[fdn].wuio.iovcb (wrap (this, &chanfd::voidshut, fdn, SHUT_WR));
    sbp->replyref (true);
  }
}

void
chanfd::newfd (svccb *sbp)
{
  assert (sbp->prog () == REX_PROG && sbp->proc () == REX_NEWFD);
  rex_newfd_arg *argp = sbp->Xtmpl getarg<rex_newfd_arg> ();
  assert (argp->channel == channo);
  if (argp->fd < 0 || implicit_cast<size_t> (argp->fd) >= fdi.size ()
      || fdi[argp->fd].weof) {
    warn ("newfd invalid fd %d\n", argp->fd);
    sbp->replyref (rex_newfd_res (false));
    return;
  }

  int fds[2];
  if (socketpair (AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
    warn ("socketpair: %m\n");
    sbp->replyref (rex_newfd_res (false));
    return;
  }
  close_on_exec (fds[0]);
  close_on_exec (fds[1]);

  fdinfo *fdip = &fdi[argp->fd];
  /* Need to make sure file descriptors get sent no later than data */
  if (!fdip->fdsendq.empty ())
    fdip->wuio.breakiov ();
  fdip->fdsendq.push_back (fds[0]);

  rex_newfd_res res (true);
  *res.newfd = newfd (fds[1]);
  sbp->replyref (res);
}

void
chanfd::close (svccb *sbp)
{
  assert (sbp->prog () == REX_PROG && sbp->proc () == REX_CLOSE);
  rex_int_arg *argp = sbp->Xtmpl getarg<rex_int_arg> ();
  assert (argp->channel == channo);
  fdi[argp->val].close ();
  sbp->replyref (true);
}


static void
setfds (ptr<vec<int> > fdsp, rex_env env)
{
  const vec<int> &fds = *fdsp;

  const int firstfd = fds.size () >= 3 ? 0 : 3 - fds.size ();

  for (int i = 0; i < firstfd; i++)
    if (i != fds[0] && dup2 (fds[0], i) < 0)
      fatal ("dup2: %m\n");

  //for 1 fd case, child shares stderr with proxy so that errors go to sfssd console
  if (fds.size () == 1) {
    close (fds[0]);
  }
  else {  
    for (int i = 0; implicit_cast<size_t> (i) < fds.size (); i++)
      if (fds[i] != i + firstfd) {
	assert (fds[i] > i + firstfd); // XXX - relying on mkchannel_prog
	if (dup2 (fds[i], firstfd + i) < 0)
	  fatal ("dup2: %m\n");
	close (fds[i]);
      }
  }

  /* chdir to $HOME might not work in rexd which runs as root if the
   * user's home directory is in /sfs (because root doesn't have access
   * to the user's agent) */
  char *homedir = getenv ("HOME");
  if (homedir) {
    if (chdir (homedir) < 0)
      warn << "Could not chdir to home directory " 
	  << homedir << ": " << strerror (errno) << "\n";
  }
  for (size_t v = 0; v < env.size (); v++)
    if (env[v] && env[v][0] == '!')
      unsetenv (substr (env[v], 1));
    else
      xputenv (env[v]);
}

ptr<chanfd>
mkchannel_prog (ref<aclnt> c, u_int32_t cno, const rex_mkchannel_arg *argp)
{
  if (!argp) {
    warn ("mkchannel_prog: argp NULL\n");
    return NULL;
  }

  if (argp->nfds < 0 || argp->nfds > 3) {
    warn ("mkchannel_prog:  nfds = %d out of range\n", argp->nfds);
    return NULL;
  }

  if (!argp->av.size()) {
    warn ("mkchannel_prog: received null command\n");
    return NULL;
  }
    
  vec<int> pfds;
  ref<vec<int> > cfds (New refcounted<vec<int> >());

  for (int i = 0; i < argp->nfds; i++) {
    int socks[2];
    if (socketpair (AF_UNIX, SOCK_STREAM, 0, socks) < 0) {
      warn ("socketpair: %m\n");
      for (int j = 0; j < i; j++) {
	close (pfds[i]);
	close ((*cfds)[i]);
      }
      return NULL;
    }
    close_on_exec (socks[0]);
    pfds.push_back (socks[0]);
    cfds->push_back (socks[1]);
  }

  vec<char *> av;
  str arg;

  if (argp->av[0] == ".") {
    char *default_shell = getenv ("SHELL");
    if (default_shell)
      av.push_back (default_shell);
    else {
      warn ("SHELL not set, reverting to sh\n");
      av.push_back ("sh");
    }
    if (argp->av.size () == 1)
      av.push_back ("-i");
  }
  else
    av.push_back (const_cast<char *> (argp->av[0].cstr ()));
 
  for (u_int i = 1; i < argp->av.size (); i++)
    av.push_back (const_cast<char *> (argp->av[i].cstr ()));
  av.push_back (NULL);

  str s = find_program_plus_libsfs (av[0]);
  if (!s) {
    warn << "Could not locate program: " << av[0] << "\n";
    return NULL;
  }
//   warn << "spawning " << s << "\n";
  
  pid_t p = aspawn (s, av.base (), 0, 1, 2, wrap (setfds, cfds, argp->env));

  for (int i = 0; implicit_cast<unsigned> (i) < cfds->size (); i++)
    close ((*cfds)[i]);

  if (p <= 0) {
    warn << "aspawn of program '" << av[0] << "' failed\n";
    for (int i = 0; implicit_cast<unsigned> (i) < pfds.size (); i++)
      close (pfds[i]);
    return NULL;
  }

  return New refcounted<chanfd> (cno, c, pfds, p);
}
