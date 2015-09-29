/* $Id: ptyd.C,v 1.11 2004/09/19 22:02:24 dm Exp $ */

/*
 *
 * Copyright (C) 2001 Eric Peterson (ericp@lcs.mit.edu)
 * Copyright (C) 2001 Michael Kaminsky (kaminsky@lcs.mit.edu)
 * Copyright (C) 2000 Charles Blake (cblake@lcs.mit.edu)
 * Copyright (C) 1999, 2002 David Mazieres (dm@uun.org)
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
#include "sfsmisc.h"
#include "rex_prot.h"
#include "ptyd.h"
#include <grp.h>
#ifdef USE_TTYENT
#include <ttyent.h>
#endif /* USE_TTYENT */

static const char ttygrpname[] = "tty";
static gid_t ttygrp = (gid_t) -1;

struct ptyclient;

struct pty {
  ptyclient *const c;
  const str path;
  ihash_entry<pty> link;

  pty (ptyclient *cc, const str &p, const str &host);
  ~pty ();
};

struct ptyclient {
  ptr<axprt_unix> x;
  ptr<asrv> s;
  const uid_t uid;
  ihash<const str, pty, &pty::path, &pty::link> ptys;

  ptyclient::ptyclient (ref<axprt_unix> xx, uid_t u)
    : x (xx), s (asrv::alloc (x, ptyd_prog_1)), uid (u) {}
  ~ptyclient ();
  void dispatch (svccb *sbp);
};

#if defined PATH_SESSREG
#ifdef USE_TTYENT
static int
/* The following code is adapted from the OpenBSD source to ttyslot (3). */
myttyslot(const char *name)
{
  struct ttyent *ttyp;
  int slot;
  char *p;

  setttyent ();
  if ((p = strrchr (name, '/')))
    ++p;
  else
    p = const_cast <char *> (name);
  for (slot = 1; (ttyp = getttyent ()); ++slot)
    if (!strcmp (ttyp->ty_name, p)) {
      endttyent ();
      return slot;
    }
  endttyent ();
  return 0;
}
#endif /* USE_TTYENT */

static int 
sessreg (int add, const uid_t u, const char *tty, const char *host)
{
  struct passwd *pw;
  char *tmp;

  if (!(pw = getpwuid (u)))
    return -1;

  vec<char *> argv;
  argv.push_back ("sessreg");
  if (add)
    argv.push_back ("-a");
  else
    argv.push_back ("-d");

  argv.push_back ("-l");
  if (tty && !strncmp ("/dev/", tty, 5) && tty[5])
    tmp = const_cast<char *> (&tty[5]);
  else {
    tmp = strrchr (tty, '/');
    tmp++;
  }
  if (tmp)
    argv.push_back (tmp);
  else
    argv.push_back ("?");

  if (host) {
    argv.push_back ("-h");
    argv.push_back (const_cast<char *> (host));
  }

#ifdef USE_TTYENT
  int slot = myttyslot (tty);
  if (slot > 0) {
    str s = strbuf () << slot;
    argv.push_back ("-s");
    argv.push_back (const_cast<char *> (s.cstr ()));
  }
#endif /* USE_TTYENT */

  argv.push_back (pw->pw_name);
  argv.push_back (NULL);
  aspawn (PATH_SESSREG, argv.base ());
  return 0;
}
#else /* !PATH_SESSREG */
inline static int 
sessreg (int add, const uid_t u, const char *tty, const char *host)
{
  return 0;
}
#endif /* !PATH_SESSREG */

pty::pty (ptyclient *cc, const str &p, const str &host)
  : c (cc), path (p)
{
  sessreg (1, c->uid, path, host);
  chmod (path, 0600);
  chown (path, c->uid, ttygrp);
  c->ptys.insert (this);
}

pty::~pty ()
{
  sessreg (0, c->uid, path, 0);
  chown (path, 0, ttygrp == (gid_t) -1 ? 0 : ttygrp);
  chmod (path, 0666);
  c->ptys.remove (this);
}

static void
delete_pty (pty *p)
{
  delete p;
}

ptyclient::~ptyclient ()
{
  ptys.traverse (wrap (delete_pty));
}

void
ptyclient::dispatch (svccb *sbp)
{
  if (!sbp) {
    delete this;
    return;
  }

  switch (sbp->proc ()) {
  case PTYD_NULL:
    sbp->reply (NULL);
    break;
  case PTYD_PTY_ALLOC:
    {
      int fd;
      str path;
      pty_alloc_res res (0);
      if (pty_alloc (&fd, &path)) {
	New pty (this, path, *sbp->Xtmpl getarg<utmphost> ());
	x->sendfd (fd);
	*res.path = path;
      }
      else
	res.set_err (errno);
      sbp->reply (&res);
      break;
    }
  case PTYD_PTY_FREE:
    {
      int32_t res = 0;
      if (pty *p = ptys[*sbp->Xtmpl getarg<utmphost> ()])
	delete p;
      else
	res = ENOENT;
      sbp->reply (&res);
      break;
    }
  default:
    sbp->reject (PROC_UNAVAIL);
    break;
  }
}

static void
getcon (ptr<axprt_unix> x, const authunix_parms *aup)
{
  if (!x || x->ateof ())
    fatal ("suidserv failed\n");
  ptyclient *pcp = New ptyclient (x, aup->aup_uid);
  pcp->s->setcb (wrap (pcp, &ptyclient::dispatch));
}

int
main (int argc, char **argv)
{
  setprogname (argv[0]);

  sfsconst_init ();

  if (group *gr = getgrnam (ttygrpname))
    ttygrp = gr->gr_gid;

  sfs_suidserv ("ptyd", wrap (getcon));
  amain ();
}
