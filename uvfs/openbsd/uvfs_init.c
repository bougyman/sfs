/* $Id: uvfs_init.c,v 1.6 1999/09/08 18:04:47 dm Exp $ */

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

#include <sys/lkm.h>

static int
loadfs (int cmd, char *name, struct vfsops *ops)
{
  struct vfsconf *vfsp;
  int err;

  switch(cmd) {
  case LKM_E_LOAD:
    /*
     * Set up file system
     */
    MALLOC (vfsp, struct vfsconf *, sizeof (struct vfsconf), M_VFS, M_WAITOK);
    bzero (vfsp, sizeof (*vfsp));
    vfsp->vfc_vfsops = ops;
    strncpy (vfsp->vfc_name, name, MFSNAMELEN - 1);
    vfsp->vfc_typenum = VT_UVFS;
    vfsp->vfc_refcount = 0;
    vfsp->vfc_flags = 0; /* XXX - should be configurable */
    vfsp->vfc_mountroot = 0;
    vfsp->vfc_next = NULL;

    err = vfs_register (vfsp);
    if (err)
      FREE (vfsp, M_VFS);
    return err;

  case LKM_E_UNLOAD:
    for (vfsp = vfsconf;
	 vfsp && strncmp (vfsp->vfc_name, name, MFSNAMELEN);
	 vfsp = vfsp->vfc_next)
      ;
    if (!vfsp)
      return ENOENT;

    err = vfs_unregister (vfsp);
    if (!err)
      FREE (vfsp, M_VFS);
    return err;

  case LKM_E_STAT:
    break;
  }

  return 0;
}

static int
uvfs_loadfs (int cmd)
{
  int error;

  switch (cmd) {
  case LKM_E_LOAD:
    vfs_opv_init_explicit (&uvfs_vnodeop_opv_desc);
    vfs_opv_init_default (&uvfs_vnodeop_opv_desc);
    if ((error = loadfs (cmd, "uvfs", &uvfs_vfsops))) {
      printf ("uvfs_loadfs: loadfs failed %d\n", error);
      FREE (*(uvfs_vnodeop_opv_desc.opv_desc_vector_p), M_VNODE);
      *(uvfs_vnodeop_opv_desc.opv_desc_vector_p) = NULL;
      return error;
    }
    break;
  case LKM_E_UNLOAD:
    if ((error = loadfs (cmd, "uvfs", &uvfs_vfsops)))
      return error;
    FREE (*(uvfs_vnodeop_opv_desc.opv_desc_vector_p), M_VNODE);
    *(uvfs_vnodeop_opv_desc.opv_desc_vector_p) = NULL;
    break;
  case LKM_E_STAT:
    break;
  }
  return 0;
}

static int
uvfs_loaddev (struct lkm_table *lkmtp, int cmd, int ver)
{
  MOD_DEV("uvfs", LM_DT_CHAR, -1, &uvfs_cdevsw);
  DISPATCH (lkmtp, cmd, ver, lkm_nofunc, lkm_nofunc, lkm_nofunc)
}

int
uvfs_mod (struct lkm_table *lkmtp, int cmd, int ver)
{
  int error;

  switch (cmd) {
  case LKM_E_LOAD:
    if ((error = uvfs_loaddev (lkmtp, cmd, ver)))
      return error;
    uvfs_dev_init ();
    if ((error = uvfs_loadfs (cmd))) {
      uvfs_loaddev (lkmtp, LKM_E_UNLOAD, ver);
      return error;
    }
    break;
  case LKM_E_UNLOAD:
    if (uvfs_dev_busy ())
      return EBUSY;
    if ((error = uvfs_loadfs (cmd)))
      return error;
    if ((error = uvfs_loaddev (lkmtp, cmd, ver))) {
      uvfs_loadfs (LKM_E_LOAD);
      return error;
    }
    break;
  case LKM_E_STAT:
    if ((error = uvfs_loadfs (cmd))
	|| (error = uvfs_loaddev (lkmtp, cmd, ver)))
      return error;
    break;
  }
  return 0;
}
