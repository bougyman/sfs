/* $Id: aios.C,v 1.22 2004/07/19 06:28:39 dm Exp $ */

/*
 *
 * Copyright (C) 1998 David Mazieres (dm@uun.org)
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

#define __AIOS_IMPLEMENTATION

#include "aios.h"
#include "async.h"

bssptr<aios> ain;
bssptr<aios> aout;

void
aios::fail (int e)
{
  ref<aios> hold = mkref (this); // Don't let this be freed under us

  eof = true;
  if (e)
    err = e;

  if (fd >= 0) {
    fdcb (fd, selread, NULL);
    if (rcb)
      mkrcb (NULL);

    if (fd >= 0 && err && err != ETIMEDOUT) {
      fdcb (fd, selwrite, NULL);
      outb.tosuio ()->clear ();
    }
  }
}

void
aios::timeoutcatch ()
{
  time_t now = time (NULL);
  if (now < timeoutnext) {
    timeoutcb = timecb (timeoutnext, wrap (this, &aios::timeoutcatch));
    return;
  }
  timeoutcb = NULL;
  if (timeoutval && (rcb || outb.tosuio ()->resid ())) {
    if (debugname)
      warnx << debugname << " === Timeout\n";
    fail (ETIMEDOUT);
  }
}

void
aios::timeoutbump ()
{
  if (timeoutval && !eof) {
    timeoutnext = time (NULL) + timeoutval;
    if (!timeoutcb && (rcb || outb.tosuio ()->resid ()))
      timeoutcb = timecb (timeoutnext, wrap (this, &aios::timeoutcatch));
  }
}

void
aios::abort ()
{
  if (fd < 0)
    return;
  if (debugname)
    warnx << debugname << " === EOF\n";
  rcb = NULL;
  fdcb (fd, selread, NULL);
  fdcb (fd, selwrite, NULL);
  ::close (fd);
  fd = -1;
  eof = true;
  weof = true;
  err = EBADF;
  outb.tosuio ()->clear ();
}

void
aios::input ()
{
  if (rlock)
    return;
  rlock = true;

  ref<aios> hold = mkref (this); // Don't let this be freed under us

  int n = ::readv (fd, const_cast<iovec *> (inb.iniov ()), inb.iniovcnt ());
  if (n > 0)
    inb.addbytes (n);
  else if (n < 0 && errno != EAGAIN) {
    fail (errno);
    rlock = false;
    return;
  }
  else if (!n && !(this->*infn) ()) {
    fail (0);
    rlock = false;
    return;
  }
  while ((this->*infn) ())
    ;
  if (fd >= 0) {
    if (rcb)
      fdcb (fd, selread, wrap (this, &aios::input));
    else
      fdcb (fd, selread, NULL);
    //timeoutbump ();
  }
  rlock = false;
}

bool
aios::rline ()
{
  int lfp = inb.find ('\n');
  if (lfp < 0) {
    if (!inb.space ()) {
      if (debugname)
	warnx << debugname << " === Line too long\n";
      fail (EFBIG);
    }
    return false;
  }

  mstr m (lfp + 1);
  inb.copyout (m, m.len ());
  if (lfp > 1 && m.cstr ()[lfp - 1] == '\r')
    m.setlen (lfp - 1);
  else
    m.setlen (lfp);

  str s (m);
  if (debugname)
    warnx << debugname << " ==> " << s << "\n";
  mkrcb (s);
  return true;
}

bool
aios::rany ()
{
  size_t bufsize = inb.size ();
  if (!bufsize)
    return false;
  mstr m (bufsize);
  inb.copyout (m, bufsize);
  mkrcb (m);
  return true;
}

void
aios::setreadcb (bool (aios::*fn) (), rcb_t cb)
{
  if (rcb)
    panic ("aios::setreadcb: read call made with read already pending\n");
  if (eof || err)
    (*cb) (NULL, err);
  else {
    infn = fn;
    rcb = cb;
    timeoutbump ();
    input ();
  }
}

void
aios::output ()
{
  ref<aios> hold = mkref (this); // Don't let this be freed under us
  suio *out = outb.tosuio ();

  int res;
  if (fdsendq.empty ())
    res = out->output (fd);
  else {
    int cnt = out->iovcnt ();
    if (cnt > UIO_MAXIOV)
      cnt = UIO_MAXIOV;
    res = writevfd (fd, out->iov (), cnt, fdsendq.front ());
    if (res > 0) {
      out->rembytes (res);
      ::close (fdsendq.pop_front ());
    }
    else if (res < 0 && errno == EAGAIN)
      res = 0;
  }
      
  if (res < 0) {
    fail (errno);
    return;
  }
  if (res > 0)
    timeoutbump ();
  if (weof && !out->resid ())
    shutdown (fd, SHUT_WR);
  wblock = !res;
  setoutcb ();
}

void
aios::setoutcb ()
{
  if (err && err != ETIMEDOUT) {
    fdcb (fd, selwrite, NULL);
    outb.tosuio ()->clear ();
  }
  else if (outb.tosuio ()->resid ()) {
    if (!timeoutcb)
      timeoutbump ();
    fdcb (fd, selwrite, wrap (this, &aios::output));
  }
  else
    fdcb (fd, selwrite, NULL);
}

void
aios::schedwrite ()
{
  if (outb.tosuio ()->resid () < defrbufsize || wblock || err)
    setoutcb ();
  else
    output ();
}

void
aios::dumpdebug ()
{
  if (debugiov < 0)
    return;

  bool prefprinted = false, crpending = false;
  strbuf text;

  for (const iovec *iov = outb.tosuio ()->iov () + debugiov,
	 *const lim = outb.tosuio ()->iovlim (); iov < lim; iov++) {
    char *s = reinterpret_cast<char *> (iov->iov_base);
    char *e = s + iov->iov_len;

    char *p;
    for (; s < e && (p = reinterpret_cast<char *> (memchr (s, '\n', e - s)));
	 s = p + 1) {
      if (crpending && p > s)
	text << "\r";
      crpending = false;
      if (!prefprinted)
	text << debugname << " <== ";
      else
	prefprinted = false;

      if (p - 1 >= s && p[-1] == '\r')
	text.buf (s, p - s - 1) << "\n";
      else
	text.buf (s, p - s + 1);
    }

    if (s < e) {
      if (e[-1] == '\r') {
	e--;
	crpending = true;
      }
      if (!prefprinted)
	text << debugname << " <== ";
      prefprinted = true;
      text.buf (s, e - s);
    }
  }
  if (prefprinted)
    text << "\n";

  warnx << text;
}

aios::aios (int fd, size_t rbsz)
  : fd (fd), err (0), eof (false), weof (false), rlock (false), inb (rbsz),
    infn (&aios::rnone), wblock (false), timeoutval (0), timeoutcb (NULL),
    debugiov (-1)
{
  _make_async (fd);
}

aios::~aios ()
{
  if (fd >= 0) {
    if (debugname)
      warnx << debugname << " === EOF\n";
    fdcb (fd, selread, NULL);
    fdcb (fd, selwrite, NULL);
    ::close (fd);
  }
  if (timeoutcb)
    timecb_remove (timeoutcb);
}

void
aios::writev (const iovec *iov, int iovcnt)
{
  assert (!weof);
  int n = 0;
  if (!outb.tosuio ()->resid ()) {
    n = ::writev (fd, const_cast<iovec *> (iov), iovcnt);
    if (n < 0) {
      if (errno != EAGAIN) {
	fail (errno);
	return;
      }
      n = 0;
    }
    if (n > 0)
      timeoutbump ();
  }
  outb.tosuio ()->copyv (iov, iovcnt, n);
  setoutcb ();
}

void
aios::sendeof ()
{
  assert (!weof);
  weof = true;
  if (!outb.tosuio ()->resid ())
    shutdown (fd, SHUT_WR);
}

int
aios::flush ()
{
  ptr<aios> hold;
  if (fd >= 0 && outb.tosuio ()->resid ()) {
    hold = mkref (this);	// Don't let this be freed under us
    make_sync (fd);
    output ();
    _make_async (fd);
  }
  return err;
}

void
aios::finalize ()
{
  if (globaldestruction)
    make_sync (fd);
  if (!outb.tosuio ()->resid () || fd < 0)
    delete this;
  else if (err) {
    // Make one last effort to flush buffer
    if (err == ETIMEDOUT)
      outb.tosuio ()->output (fd);
    delete this;
  }
  else if (outb.tosuio ()->output (fd) < 0)
    delete this;
}

int aiosinit::count;

void
aiosinit::start ()
{
  ain = aios::alloc (0);
  aout = aios::alloc (1);
}

void
aiosinit::stop ()
{
  ain = NULL;
  aout = NULL;
}
