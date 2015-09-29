/* $Id: uvfs_dev.c,v 1.17 1999/10/06 06:56:41 dm Exp $ */

/*
 * User level VFS driver for OpenBSD.
 * Copyright 1999 Michael Kaminsky <kaminsky@lcs.mit.edu>.
 * Copyright 1998 David Mazieres <dm@uun.org>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project (for instance by leaving this copyright notice
 * intact).
 */

#include "uvfs_kern.h"

static int uvfs_open (dev_t dev, int oflags, int devtype, struct proc *p);
static int uvfs_close (dev_t dev, int fflags, int devtype, struct proc *p);
static int uvfs_read (dev_t dev, struct uio *uio, int ioflag);
static int uvfs_write (dev_t dev, struct uio *uio, int ioflag);
static int uvfs_select (dev_t dev, int which, struct proc *p);
static int uvfs_ioctl (dev_t dev, u_long cmd, caddr_t data, int fflag, 
		       struct proc *p);

struct cdevsw uvfs_cdevsw = {
  uvfs_open, uvfs_close, uvfs_read, uvfs_write,
  uvfs_ioctl, (dev_type_stop((*))) enodev,
  0, uvfs_select, (dev_type_mmap((*))) enodev
};

struct uvfs_softc uvfs_state[NUVFS];

int
uvfs_cb (void *arg, svccb *sbp)
{
  return 0;
}

static void
uvfs_dev_readwakeup (void *_st)
{
  uvfs_softc *st = _st;

  if (st->flags & UVFS_RSEL) {
    st->flags &= ~UVFS_RSEL;
    selwakeup(&st->sel);
  }
  wakeup(st);
}

void
uvfs_dev_init (void)
{
  int i;

  for (i = 0; i < NUVFS; i++) {
    krpc_init (&uvfs_state[i].rpcq, uvfs_dev_readwakeup, &uvfs_state[i]);
    krpc_server_alloc (&uvfs_state[i].rpcq, &uvfsprog_1, uvfs_cb, 0);
  }
}

int
uvfs_dev_busy (void)
{
  int i;
  for (i = 0; i < NUVFS; i++)
    if (uvfs_state[i].busy)
      return 1;
  return 0;
}

static inline uvfs_softc *
getstate (dev_t dev)
{
  int n = minor (dev);
  if (n >= NUVFS)
    panic ("uvfs getstate (dev = 0x%x)\n", dev);
  return &uvfs_state[n];
}

static int
uvfs_open (dev_t dev, int oflags, int devtype, struct proc *p)
{
  uvfs_softc *st;

#ifdef UVFS_DEBUG_DEV
  warn ("uvfs%d: open\n", minor (dev));
#endif /* UVFS_DEBUG_DEV */

  if (minor (dev) >= NUVFS)
    return ENXIO;
  st = &uvfs_state[minor (dev)];
  if (st->busy)
    return EBUSY;
  st->busy = 1;

  krpc_activate (&st->rpcq);

  return 0;
}

static int
uvfs_close (dev_t dev, int fflags, int devtype, struct proc *p)
{
  uvfs_softc *st = getstate (dev);
 
#ifdef UVFS_DEBUG_DEV
  warn ("uvfs%d: close\n", minor (dev));
#endif /* UVFS_DEBUG_DEV */

  /* need to flush all outstanding RPC requests */
  krpc_deactivate (&st->rpcq);
  krpc_flush (&st->rpcq);

  st->busy = 0;

  return 0;
}

static int
uvfs_read (dev_t dev, struct uio *uio, int ioflag)
{
  int error = 0;
  uvfs_softc *st = getstate (dev);

#ifdef UVFS_DEBUG_DEV
  warn ("uvfs%d: read\n", minor (dev));
#endif /* UVFS_DEBUG_DEV */

  error = krpc_copyout(&st->rpcq, uio);
  if (!(ioflag & O_NONBLOCK))
    while (error == EAGAIN) {
      error = tsleep (st, PRIBIO|PCATCH, "uvfs", 0);
      if (error)
	return error;
      error = krpc_copyout(&st->rpcq, uio);
    }

  return error;
}

static int
uvfs_write (dev_t dev, struct uio *uio, int ioflag)
{
  uvfs_softc *st = getstate (dev);
  int error = 0;

#ifdef UVFS_DEBUG_DEV
  warn ("uvfs%d: write\n", minor (dev));
#endif /* UVFS_DEBUG_DEV */

  error = krpc_copyin(&st->rpcq, uio);
  return error;
}

static int
uvfs_select (dev_t dev, int which, struct proc *p)
{
  uvfs_softc *st = getstate (dev);

#ifdef UVFS_DEBUG_DEV
  warn ("uvfs%d: select\n", minor (dev));
#endif /* UVFS_DEBUG_DEV */

  if (which & FWRITE)
    return 1;
  else {
    if (st->rpcq.inq.tqh_first)
      return 1;
    st->flags |= UVFS_RSEL;
    selrecord (p, &st->sel);
    return 0;
  }
}

int
uvfs_ioctl (dev_t dev, u_long cmd, caddr_t data, int fflag, struct proc *p)
{
  switch (cmd) {
  case FIONBIO:
  case FIOASYNC:
    return 0;
  default:
    return EINVAL;
  }
}
