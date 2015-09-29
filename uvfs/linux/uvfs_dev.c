/* $Id: uvfs_dev.c,v 1.5 1999/01/19 20:56:37 kaminsky Exp $ */

/*
 * User level VFS driver for Linux.
 * Copyright 1999 Michael Kaminsky <kaminsky@lcs.mit.edu>
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

#include "uvfs_kern.h"

static int uvfs_dev_open (struct inode *inode, struct file *filp);
static int uvfs_dev_release (struct inode *inode, struct file *filp);
static ssize_t uvfs_dev_read (struct file *filp, char *buf, size_t count, 
			      loff_t *ppos);
static ssize_t uvfs_dev_write (struct file *filp, const char *buf, 
			       size_t count, loff_t *ppos);
static unsigned int uvfs_dev_poll (struct file *filp, 
				   struct poll_table_struct *wait);
static int uvfs_dev_ioctl (struct inode *inode, struct file *filp,
			   unsigned int cmd, unsigned long arg);

struct file_operations uvfs_dev_fops = {
  NULL,
  uvfs_dev_read,
  uvfs_dev_write,
  NULL,
  uvfs_dev_poll,		/* back-end for poll & select in linux 2.2 */
  uvfs_dev_ioctl,
  NULL,
  uvfs_dev_open,
  NULL,
  uvfs_dev_release,		/* close on other OSs */
};

struct uvfs_softc uvfs_state[NUVFS];

static void
uvfs_dev_readwakeup (void *_st)
{
  uvfs_softc *st = _st;

#if 0
  if (st->flags & UVFS_RSEL) {
    st->flags &= ~UVFS_RSEL;
    selwakeup(&st->sel);
  }
#endif

  wake_up_interruptible (&st->inq);
}

void
uvfs_dev_init (void)
{
  int i;

  for (i = 0; i < NUVFS; i++)
    krpc_init(&uvfs_state[i].rpcq, uvfs_dev_readwakeup, &uvfs_state[i]);
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
getstate (kdev_t dev)
{
  int n = MINOR (dev);
  if (n >= NUVFS)
    panic ("uvfs: getstate (dev = 0x%x)\n", dev);
  return &uvfs_state[n];
}

static int
uvfs_dev_open (struct inode *inode, struct file *filp)
{
  uvfs_softc *st;

#ifdef UVFS_DEBUG_DEV
  warn ("uvfs%d: open\n", MINOR (inode->i_rdev));
#endif /* UVFS_DEBUG_DEV */

  if (MINOR (inode->i_rdev) >= NUVFS)
    return -ENXIO;
  st = getstate (inode->i_rdev);
  if (st->busy)
    return -EBUSY;
  st->busy = 1;

  krpc_activate (&st->rpcq);

  MOD_INC_USE_COUNT;
  return 0;
}

static int 
uvfs_dev_release (struct inode *inode, struct file *filp)
{
  uvfs_softc *st = getstate (inode->i_rdev);
 
#ifdef UVFS_DEBUG_DEV
  warn ("uvfs%d: release\n", MINOR (inode->i_rdev));
#endif /* UVFS_DEBUG_DEV */

  krpc_deactivate (&st->rpcq);
  krpc_flush (&st->rpcq);

  st->busy = 0;

  MOD_DEC_USE_COUNT;
  return 0;
}

static ssize_t
uvfs_dev_read (struct file *filp, char *buf, size_t count, loff_t *ppos)
{
  int error = 0;
  uvfs_softc *st = getstate (FILETOKDEV (filp));
  struct uio u;
  struct iovec iov;

#ifdef UVFS_DEBUG_DEV
  warn ("uvfs%d: read\n", FILETOMINOR (filp));
#endif /* UVFS_DEBUG_DEV */

  /* Can't seek (pread) on ttys.  */
  if (ppos != &filp->f_pos)
    return -ESPIPE;

  iov.iov_base = buf;
  iov.iov_len = count;
  u.uio_iov = &iov;
  u.uio_iovcnt = 1;
  u.uio_offset = 0;
  u.uio_resid = count;
  u.uio_segflg = UIO_USERSPACE;
  u.uio_rw = UIO_READ;

  error = krpc_copyout(&st->rpcq, &u);
  if (!(filp->f_flags & O_NONBLOCK))
    while (error == EAGAIN) {
      interruptible_sleep_on (&st->inq);
      if (signal_pending (current))
	return -ERESTARTSYS;
      error = krpc_copyout(&st->rpcq, &u);
    }

  if (error > 0)
    return -error;		/* Linux error codes are negative */
  else
    return count - u.uio_resid;
}

static ssize_t
uvfs_dev_write (struct file *filp, const char *buf, size_t count, 
		loff_t *ppos)
{
  int error = 0;
  uvfs_softc *st = getstate (FILETOKDEV (filp));
  struct uio u;
  struct iovec iov;

#ifdef UVFS_DEBUG_DEV
  warn ("uvfs%d: write\n", FILETOMINOR (filp));
#endif /* UVFS_DEBUG_DEV */

  /* Can't seek (pread) on ttys.  */
  if (ppos != &filp->f_pos)
    return -ESPIPE;

  iov.iov_base = (char *) buf;
  iov.iov_len = count;
  u.uio_iov = &iov;
  u.uio_iovcnt = 1;
  u.uio_offset = 0;
  u.uio_resid = count;
  u.uio_segflg = UIO_USERSPACE;
  u.uio_rw = UIO_WRITE;

  error = krpc_copyin(&st->rpcq, &u);
  if (error > 0)
    return -error;		/* Linux error codes are negative */
  else
    return count - u.uio_resid;
}

static unsigned int
uvfs_dev_poll (struct file *filp, struct poll_table_struct *wait)
{
  uvfs_softc *st = getstate (FILETOKDEV (filp));
  unsigned int mask = 0;

#ifdef UVFS_DEBUG_DEV
  warn ("uvfs%d: select\n", MINORTOKDEV (filp));
#endif /* UVFS_DEBUG_DEV */

  poll_wait (filp, &st->inq, wait);
  poll_wait (filp, &st->outq, wait);
  mask |= POLLOUT | POLLWRNORM;	/* always writeable */
  if (st->rpcq.inq.tqh_first)
    mask |= POLLIN | POLLRDNORM;

  return mask;

#if 0
  if (which & FWRITE)
    return 1;
  else {
    if (st->rpcq.inq.tqh_first)
      return 1;
    st->flags |= UVFS_RSEL;
    selrecord (p, &st->sel);
    return 0;
  }
#endif
}

int
uvfs_dev_ioctl (struct inode *inode, struct file *filp,
		unsigned int cmd, unsigned long arg)
{
  switch (cmd) {
  case FIONBIO:
  case FIOASYNC:
    return 0;
  default:
    return -EINVAL;
  }
}
