// -*-c++-*-
/* $Id: proxy.h,v 1.14 2004/05/01 21:18:58 dbg Exp $ */

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

#include "arpc.h"
#include "rex_prot.h"

class chanbase {
protected:
  const u_int32_t channo;
  const ref<aclnt> c;

  void reap (int status);

public:
  pid_t pid;

  chanbase (u_int32_t cn, ptr<aclnt> cc, pid_t p = -1);
  virtual ~chanbase () { if (pid != -1) chldcb (pid, NULL); }
  virtual void data (svccb *sbp) { sbp->replyref (false); }
  virtual void newfd (svccb *sbp) { sbp->replyref (false); }
  virtual void close (svccb *sbp) { sbp->replyref (false); }
  virtual void kill (svccb *sbp);
};

class chanfd : public chanbase {
private:
  struct fdinfo {
  private:
    fdinfo (const fdinfo &f);
  public:
    int fd;
    bool isunixsocket;
    bool closed;
    bool reof; /* the read direction of the local fd is in eof state */
    bool weof; /* a shutdown(WR) has been queued but write direction of
                  local fd might not be in eof state yet */
    size_t rsize;
    suio wuio;
    vec<int> fdsendq;

    fdinfo () : fd (-1), closed (true), rsize (0) {}
    fdinfo (fdinfo &f) : fd (f.fd), isunixsocket (f.isunixsocket),
			 closed (f.closed), reof (f.reof), weof (f.weof),
			 rsize (f.rsize) {
      wuio.take (&f.wuio);
      f.fd = -1;
      fdsendq.swap (f.fdsendq);
    }
    ~fdinfo () { seterr (); }

    void seterr ();
    void close ();
    void reset ();
  };

  enum {hiwat = 0x10000};

  ref<bool> destroyed;
  vec<fdinfo> fdi;

  int newfd (int fd, bool enablercb = true); // unrelated to next fn
  void newfd (svccb *sbp);	// Get new fd from client
  void newfdrep (int fdn, ref <bool> okp, clnt_stat cs);
  ssize_t readfd (int fdn, void *buf, size_t len, bool &fdrecved);
  ssize_t readmore (int fdn, char *buf, size_t len, size_t &numbytes);
  void voidshut (int fdn, int how) {
    if (fdi[fdn].fd >= 0)
      shutdown (fdi[fdn].fd, how);
  }

  void ccb (int fdn, size_t size, ref<bool> dest, ref<bool> okp, clnt_stat);
  void rcb (int fdn);
  void enablercb (int fdn);
  void disablercb (int fdn);
  void scb (int fdn, svccb *sbp) { sbp->replyref (bool (fdi[fdn].fd >= 0)); }
  void wcb (int fdn);
  
public:
  chanfd (u_int32_t channo, ref<aclnt> c, const vec<int> fds, pid_t p);
  ~chanfd ();
  void close (svccb *sbp);
  void data (svccb *sbp);
};

ptr<chanfd> mkchannel_prog (ref<aclnt> c, u_int32_t cno,
			    const rex_mkchannel_arg *argp);
