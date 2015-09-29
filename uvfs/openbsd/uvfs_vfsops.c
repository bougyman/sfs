/* $Id: uvfs_vfsops.c,v 1.22 1999/09/07 15:34:44 dm Exp $ */

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

static struct uvfs_node *
uvfsnode_lookup (struct mount *mp, uvfs_fh fh)
{
  struct uvfs_node *unp = NULL;

#ifdef UVFS_DEBUG_FS
  warn ("uvfsnode_lookup %d\n", fh);
#endif /* UVFS_DEBUG_FS */

  for (unp = VFSTOUVFS(mp)->uvfs_node_tab[fh % UNTSIZE].lh_first;
       unp != NULL && unp->fh != fh;
       unp = unp->entries.le_next)
    /* do we need to call vget here? */
    ;
  return unp;
}

void
uvfsnode_insert (struct mount *mp, struct uvfs_node *unp)
{
#ifdef UVFS_DEBUG_FS
  warn ("uvfsnode_insert %d\n", unp->fh);
#endif /* UVFS_DEBUG_FS */

  LIST_INSERT_HEAD (&(VFSTOUVFS(mp)->uvfs_node_tab[unp->fh % UNTSIZE]), 
		    unp, entries);
}

void
uvfsnode_remove (struct uvfs_node *unp)
{
#ifdef UVFS_DEBUG_FS
  warn ("uvfsnode_remove %d\n", unp->fh);
#endif /* UVFS_DEBUG_FS */

  if (!(unp->uvfsvnode->v_flag & VROOT))
    LIST_REMOVE (unp, entries);
}

static int
uvfs_mount (struct mount *mp, const char *path, caddr_t data,
	    struct nameidata *ndp, struct proc *p)
{
  int error;
  size_t size;
  struct uvfs_args args;
  uvfs_mntpt *mntpt;
  int i;

#if UVFS_DEBUG_FS
  warn ("uvfs_mount: \n");
#endif /* UVFS_DEBUG_FS */

  if (mp->mnt_flag & MNT_UPDATE)
    return EOPNOTSUPP;
  mp->mnt_flag |= MNT_NOSUID | MNT_NODEV;

  if ((error = copyin (data, (caddr_t) &args, sizeof (args))))
    return error;
  if ((size_t) args.uvfs_dev >= NUVFS)
    return EINVAL;

  MALLOC (mntpt, uvfs_mntpt *, sizeof (uvfs_mntpt), M_MISCFSMNT, M_WAITOK);
  if ((error = uvfs_newvnode (mp, &mntpt->root))) {
    FREE (mntpt, M_MISCFSMNT);
    return error;
  }

  mntpt->root->v_type = VDIR;
  mntpt->root->v_flag |= VROOT;
  VTOUVFS(mntpt->root)->fh = args.uvfs_root_fh;
  mntpt->rpcqp = &uvfs_state[args.uvfs_dev].rpcq;
  for(i = 0; i < UNTSIZE; i++) {
    LIST_INIT(&mntpt->uvfs_node_tab[i]);
  }
  mp->mnt_data = (void *) mntpt;

  vfs_getnewfsid (mp);

  copyinstr(path, mp->mnt_stat.f_mntonname, MNAMELEN, &size);
  /* bzero(mp->mnt_stat.f_mntonname + size, MNAMELEN - size); */
  /* bzero(mp->mnt_stat.f_mntfromname, MNAMELEN); */
  sprintf (mp->mnt_stat.f_mntfromname, "uvfs%d", args.uvfs_dev);

  return 0;
}

static int
uvfs_start (struct mount *mp, int flags, struct proc *p)
{
  return 0;
}

static int
uvfs_unmount (struct mount *mp, int mntflags, struct proc *p)
{
  int flags = 0;
  int error;
  struct vnode *rootvp = VFSTOUVFS(mp)->root;

#if UVFS_DEBUG_FS
  warn ("uvfs_umount: \n");
#endif /* UVFS_DEBUG_FS */

  if (mntflags & MNT_FORCE)
      flags |= FORCECLOSE;

  if (rootvp->v_usecount > 1 && !(flags & FORCECLOSE))
      return EBUSY;

  if ((error = vflush (mp, rootvp, flags)))
      return error;

  /* Release reference on underlying root vnode */
  vrele (rootvp);
  /* And blow it away for future re-use */
  vgone (rootvp);
	
  FREE (mp->mnt_data, M_MISCFSMNT);
  mp->mnt_data = 0;
  return 0;
}

static int
uvfs_root (struct mount *mp, struct vnode **vpp)
{
  uvfs_mntpt *mntpt = VFSTOUVFS(mp);

#if UVFS_DEBUG_FS
  warn ("uvfs_root: \n");
#endif /* UVFS_DEBUG_FS */

  VREF (mntpt->root);
  vn_lock (mntpt->root, LK_EXCLUSIVE | LK_RETRY, curproc);
  *vpp = mntpt->root;
  return 0;
}

static int
uvfs_statfs(struct mount *mp, struct statfs *sbp, struct proc *p)
{
  uvfs_fh arg;
  uvfs_statfsres res;
  int error = 0;

#if UVFS_DEBUG_FS
  warn ("uvfs_statfs: \n");
#endif /* UVFS_DEBUG_FS */

  arg = 0;	/* Is this ok?  We don't use it on the other side */

  bzero (&res, sizeof(res));

  error = krpc_callit (VFSTOUVFS(mp)->rpcqp, &uvfsprog_1,
		       UVFSPROC_STATFS,	&arg, &res);


  if (!error && res.status != 0) {
    error = res.status;
  }

  if (!error) {
    /* sbp->f_type = 0; */
    sbp->f_bsize = UVFS_FABLKSIZE;
    sbp->f_iosize = NBPG;
    sbp->f_blocks = res.u.resok.tbytes / UVFS_FABLKSIZE;
    sbp->f_bfree = res.u.resok.fbytes / UVFS_FABLKSIZE;
    sbp->f_bavail = res.u.resok.abytes / UVFS_FABLKSIZE;
    sbp->f_files = res.u.resok.tfiles;
    sbp->f_ffree = res.u.resok.ffiles;
    if (sbp != &mp->mnt_stat) {
      bcopy(&mp->mnt_stat.f_fsid, &sbp->f_fsid, sizeof(sbp->f_fsid));
      bcopy(mp->mnt_stat.f_mntonname, sbp->f_mntonname, MNAMELEN);
      bcopy(mp->mnt_stat.f_mntfromname, sbp->f_mntfromname, MNAMELEN);
    }
    strncpy(sbp->f_fstypename, mp->mnt_vfc->vfc_name, MFSNAMELEN);
  }

  xdr_free (xdr_uvfs_statfsres, &res);
  return error;
}

static int 
uvfs_vget (struct mount *mp, ino_t ino, struct vnode **vpp)
{
  int error = 0;
  struct vnode *vp;
  struct uvfs_node *unp;

  *vpp = NULLVP;
  vp = NULLVP;

#if UVFS_DEBUG_FS
  warn ("uvfs_vget\n");
#endif /* UVFS_DEBUG_FS */

  /* First, look up ino in a hash table, returning existing vnode if found */
  unp = uvfsnode_lookup (mp, ino);
  if (unp != NULL) {
    *vpp = unp->uvfsvnode;
    /* XXX: Do we need to increase the reference count here? */
    vget (*vpp, LK_EXCLUSIVE, curproc);
    VOP_LOCK (*vpp, LK_SHARED | LK_RETRY, curproc);
    return 0;
  }

  /* If not found in hash, create a new vnode */
  error = uvfs_newvnode(mp, &vp);
  if (error) {
    if (vp)
      vrele (vp);
    return error;
  }

  VTOUVFS(vp)->fh = ino;
  vp->v_type = VREG; /* TOTAL HACK; gets set when we return !!! */
  VOP_LOCK (vp, LK_SHARED | LK_RETRY, curproc);

  /* and insert into hash */
  uvfsnode_insert (mp, VTOUVFS(vp));
  *vpp = vp;

  return 0;
}

static int
uvfs_init (struct vfsconf *vfsp)
{
  return 0;
}

#define uvfs_quotactl ((int (*) (struct mount *, int, uid_t, caddr_t,	\
				 struct proc *)) eopnotsupp)
#define uvfs_sync ((int (*) (struct mount *, int, struct ucred *,	\
			     struct proc *)) nullop)
#define uvfs_fhtovp ((int (*) (struct mount *, struct fid *,		\
			       struct mbuf *, struct vnode **,		\
			       int *, struct ucred **)) eopnotsupp)
#define uvfs_vptofh ((int (*) (struct vnode *, struct fid *)) eopnotsupp)
#define uvfs_sysctl ((int (*) (int *, u_int, void *, size_t *, void *,	\
			       size_t, struct proc *)) eopnotsupp)

struct vfsops uvfs_vfsops = {
  uvfs_mount,
  uvfs_start,
  uvfs_unmount,
  uvfs_root,
  uvfs_quotactl,
  uvfs_statfs,
  uvfs_sync,
  uvfs_vget,
  uvfs_fhtovp,
  uvfs_vptofh,
  uvfs_init,
  uvfs_sysctl
};
