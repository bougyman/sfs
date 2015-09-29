/*	$OpenBSD: kern_subr.c,v 1.6 1998/07/28 00:13:08 millert Exp $	*/
/*	$NetBSD: kern_subr.c,v 1.15 1996/04/09 17:21:56 ragge Exp $	*/

/*
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)kern_subr.c	8.3 (Berkeley) 1/21/94
 */

#if (__OpenBSD__)

#elif (__linux__)

#include <linux/fs.h>
#include <asm/uaccess.h>
#undef LIST_HEAD		/* Linux's list.h conflict with queue.h */
#include "arpc.h"

int
uiomove(caddr_t cp, int n, struct uio *uio)
{
  register struct iovec *iov;
  u_int cnt;
  int error = 0;

  while (n > 0 && uio->uio_resid) {
    iov = uio->uio_iov;
    cnt = iov->iov_len;
    if (cnt == 0) {
      uio->uio_iov++;
      uio->uio_iovcnt--;
      continue;
    }
    if (cnt > n)
      cnt = n;
    switch (uio->uio_segflg) {

    case UIO_USERSPACE:
      if (uio->uio_rw == UIO_READ) {
	error = copy_to_user (iov->iov_base, cp, cnt);
#ifdef KRPC_DEBUG
	warn ("uiomove: copy TO user space; errno = %d\n", error);
#endif
      }
      else {
	error = copy_from_user (cp, iov->iov_base, cnt);
#ifdef KRPC_DEBUG
	warn ("uiomove: copy FROM user space; errno = %d\n", error);
#endif
      }
      if (error)
	return EFAULT;
      break;

    case UIO_SYSSPACE:
      if (uio->uio_rw == UIO_READ)
	bcopy ((caddr_t)cp, iov->iov_base, cnt);
      else
	bcopy (iov->iov_base, (caddr_t)cp, cnt);
      break;
    }
    iov->iov_base += cnt;
    iov->iov_len -= cnt;
    uio->uio_resid -= cnt;
    uio->uio_offset += cnt;
    cp += cnt;
    n -= cnt;
  }
  return error;
}

#else
#warning Please define an analog to uiomove for this OS
#endif
