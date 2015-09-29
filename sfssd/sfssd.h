// -*-c++-*-
/* $Id: sfssd.h,v 1.12 2004/06/03 20:09:58 dm Exp $ */

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

#include "arpc.h"
#include "sfsmisc.h"
#include "list.h"
#include "qhash.h"
#include "itree.h"

struct sfssrv {
  list_entry<sfssrv> llink;
  virtual void clone (ref<axprt_clone> xc, svccb *sbp) = 0;
  virtual void launch () = 0;
  virtual str name () { return "server"; }
  sfssrv ();
  virtual ~sfssrv ();
};
extern list<sfssrv, &sfssrv::llink> services;

struct proxy {
  enum { lowat = 0, hiwat = 8192 };
  struct tcp {
    int fd;
    suio wbuf;
    bool eof;
    bool closed;
    timecb_t *tmo;
    tcp () : fd (-1), eof (false), closed (false), tmo (NULL) {}
  };
  tcp con[2];
  list_entry<proxy> llink;

  proxy (int fd1, int fd2);
  void setcb (int i);
  void rcb (int i);
  void wcb (int i);
  void timeout (int i);
  ~proxy ();
};

class sfssrv_proxy : public sfssrv {
  const str host;
  const u_int16_t port;
  const ref<bool> destroyed;
  list<proxy, &proxy::llink> proxies;
  void mkproxy (ref<bool> destroyed, int cfd, str data, svccb *sbp, int fd);

public:
  sfssrv_proxy (str h, u_int16_t p);
  ~sfssrv_proxy ();
  void launch () {}
  void clone (ref<axprt_clone> xc, svccb *sbp);
  str name ();
};

class sfssrv_unix : public sfssrv {
protected:
  ptr<axprt_unix> x;
  void getpkt (const char *, ssize_t, const sockaddr *);
  void setx (ptr<axprt_unix> xx);
public:
  void clone (ref<axprt_clone> xc, svccb *sbp);
};

struct sfssrv_sockpath : sfssrv_unix {
  const str path;
  void launch ();
  str name ();
  explicit sfssrv_sockpath (str p) : path (p) { assert (path); }
};

struct sfssrv_exec : sfssrv_unix {
  /* How to invoke this server */
  const vec<str> argv;
  rpc_ptr<int> uid;
  rpc_ptr<int> gid;

  /* Copy of the server we are running */
  ptr<axprt_unix> x;
  ihash_entry<sfssrv_exec> link;

private:
  void setprivs ();

public:
  explicit sfssrv_exec (const vec<str> &argv);
  ~sfssrv_exec ();
  void launch ();
  str name ();
};
extern ihash<const vec<str>, sfssrv_exec, &sfssrv_exec::argv,
	     &sfssrv_exec::link> exectab;

struct extension {
  vec<str> names;
  qhash<u_int32_t, sfssrv *> srvtab;
  list_entry<extension> link;
  bool covered (const bhash<str> &eh);
  bool covered (const vec<str> &ev);
};

struct release {
  const u_int32_t rel;
  list<extension, &extension::link> extlist;
  itree_entry<release> link;
  release (u_int32_t rel);
  ~release ();
  extension *getext (const vec<str> &ev);
};

struct server {
  const str host;
  rpc_ptr<sfs_hash> hostid;
  itree<const u_int32_t, release, &release::rel, &release::link> reltab;
  list_entry<server> link;

  server (const str &host, sfs_hash *hostid);
  ~server ();
  release *getrel (u_int32_t r);
  bool clone (ref<axprt_clone> x, svccb *sbp, const char *source,
	      u_int32_t rel, sfs_service service, const bhash<str> &eh);
};

extern list<server, &server::link> serverlist;

extern void whatport (str hostname,
		      callback<void, const vec<u_int16_t> *>::ref cb);
