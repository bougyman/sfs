/* $Id: uvfs_vnops.c,v 1.53 1999/10/01 03:43:46 dm Exp $ */

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

#define UVFS_FS_NAMECACHE 1

int (**uvfs_vnodeop_p) (void *);

int
uvfs_newvnode (struct mount *mp, struct vnode **vpp)
{
  struct vnode *vp;
  int error = 0;

  if ((error = getnewvnode (VT_UVFS, mp, uvfs_vnodeop_p, &vp)))
    return error;
  VTOUVFS(vp) = xmalloc (sizeof (uvfs_node));
  VTOUVFS(vp)->uvfslockf = NULL;
  VTOUVFS(vp)->uvfsvnode = vp;
  timerclear (&VTOUVFS(vp)->vap_expires);
  *vpp = vp;
  return 0;
}

static void
fattr2vattr (uvfs_fattr *fap, struct vattr *vap, struct vnode *vp)
{
  bzero (vap, sizeof(*vap));
  vattr_null (vap);
  vap->va_uid = fap->uid;
  vap->va_gid = fap->gid;
  vap->va_fsid = vp->v_mount->mnt_stat.f_fsid.val[0];
  vap->va_size = fap->size;
  vap->va_blocksize = DEV_BSIZE;
  vap->va_atime.tv_sec = fap->atime.seconds;
  vap->va_atime.tv_nsec = fap->atime.nseconds;
  vap->va_mtime.tv_sec = fap->mtime.seconds;
  vap->va_mtime.tv_nsec = fap->mtime.nseconds;
  vap->va_ctime.tv_sec = fap->ctime.seconds;
  vap->va_ctime.tv_nsec = fap->ctime.nseconds;
  vap->va_gen = 0;
  vap->va_flags = 0;
  vap->va_rdev = makedev (fap->rdev.major,
			  fap->rdev.minor);
  vap->va_bytes = fap->used;
  vap->va_type = fap->type;
  vap->va_mode = fap->mode;
  vap->va_nlink = fap->nlink;
  vap->va_fileid = fap->fileid;
}

static void
attr_cache_update (uvfs_fattr *fap, struct vnode *vp)
{
  fattr2vattr (fap, &VTOUVFS(vp)->vap, vp);
  VTOUVFS(vp)->vap_expires.tv_sec = time.tv_sec + ATTR_CACHE_TIMEOUT;
#if UVFS_DEBUG_FS
  warn ("updating attribute cache; time = %ld\n",
	VTOUVFS(vp)->vap_expires.tv_sec);
#endif /* UVFS_DEBUG_FS */
}

static int
attr_cache_expired (struct vnode *vp)
{
  if (time.tv_sec < VTOUVFS(vp)->vap_expires.tv_sec) {
#if UVFS_DEBUG_FS
    warn ("attribute cache hit; time = %ld\n", 
	  VTOUVFS(vp)->vap_expires.tv_sec);
#endif /* UVFS_DEBUG_FS */
    return 0;
  }
  else {
    return 1;
  }
}

static int
attr_cache_invalid (struct vnode *vp)
{
  return 1;
}

static int
ensure_attr (uvfs_fattr *fap, int gotattr, struct vnode *vp)
{
  struct vattr va;
  int error;

  if (!gotattr) {
    if ((error = VOP_GETATTR (vp, &va, NULL, NULL)))
      return error;
    vp->v_type = va.va_type;
    /* attr_cache_update already called by VOP_GETATTR */
  }
  else {
    attr_cache_update (fap, vp);
    vp->v_type = fap->type;
  }

  return 0;
}

static int
uvfs_inactive(void *v)
{
  struct vop_inactive_args /* {
     struct vnode *a_vp;
     struct proc *a_p;
  } */ *ap = v;
  struct vnode *vp = ap->a_vp;
  uvfs_node *unp = VTOUVFS(vp);
  int error = 0;

  uvfs_fh arg;
  uvfsstat res;

#if UVFS_DEBUG_FS
  warn ("uvfs_inactive: fileid = %d\n", unp->fh);
#endif /* UVFS_DEBUG_FS */

  bzero (&arg, sizeof(arg));
  bzero (&res, sizeof(res));

  arg = unp->fh;

  error = krpc_callit (VTORPCQ(vp), &uvfsprog_1, 
		       UVFSPROC_INACTIVE, &arg, &res);

  xdr_free (xdr_uvfsstat, &res);
  VOP_UNLOCK(vp, 0, ap->a_p);
  return 0;
}

static int
uvfs_reclaim (void *v)
{
  struct vop_reclaim_args /* {
     struct vnodeop_desc *a_desc;
     struct vnode *a_vp;
     struct proc *a_p;
  } */ *ap = v;
  struct vnode *vp = ap->a_vp;
  uvfs_node *unp = VTOUVFS(vp);
  int error = 0;

  uvfs_fh arg;
  uvfsstat res;

#if UVFS_DEBUG_FS
  warn ("uvfs_reclaim: fileid = %d\n", unp->fh);
#endif /* UVFS_DEBUG_FS */

  bzero (&arg, sizeof(arg));
  bzero (&res, sizeof(res));

  arg = unp->fh;

#ifdef UVFS_FS_NAMECACHE
  cache_purge (vp);
#endif /* UVFS_FS_NAMECACHE */

  /* remove vnode from the hash of active vnodes */
  uvfsnode_remove (unp);

  if (vp->v_data) {
    xfree (vp->v_data);
    vp->v_data = 0;
  }

  /* RPC is just to let the client daemon know it can reuse the fh number */
  error = krpc_callit (VTORPCQ(vp), &uvfsprog_1, 
		       UVFSPROC_INACTIVE, &arg, &res);

  xdr_free (xdr_uvfsstat, &res);

  return 0; /* must always return 0 from reclaim */
}

static int
uvfs_getattr (void *v)
{
  struct vop_getattr_args /* {
     struct vnodeop_desc *a_desc;
     struct vnode *a_vp;
     struct vattr *a_vap;
     struct ucred *a_cred;
     struct proc *a_p;
  } */ *ap = v;
  struct vnode *vp = ap->a_vp;
  struct vattr *vap = ap->a_vap;
  uvfs_node *unp = VTOUVFS(vp);
  int error = 0;

  uvfs_fh arg;
  uvfs_attrres res;

#if UVFS_DEBUG_FS
  warn ("uvfs_getattr: fileid = %d\n", unp->fh);
#endif /* UVFS_DEBUG_FS */

  if (!attr_cache_expired (vp)) {
    *vap = unp->vap;
    return 0;
  }

  bzero (&arg, sizeof(arg));
  bzero (&res, sizeof(res));

  arg = unp->fh;

  error = krpc_callit (VTORPCQ(vp), &uvfsprog_1,
		       UVFSPROC_GETATTR, &arg, &res);

  if (!error && res.status != 0) {
    error = res.status;
  }

  if (!error) {
    vattr_null (vap);
    fattr2vattr (&res.u.attributes, vap, vp);
    attr_cache_update (&res.u.attributes, vp);
  }

  xdr_free (xdr_uvfs_attrres, &res);
  return error;
}

static int
uvfs_setattr (void *v)
{
  struct vop_setattr_args /* {
     struct vnodeop_desc *a_desc;
     struct vnode *a_vp;
     struct vattr *a_vap;
     struct ucred *a_cred;
     struct proc *a_p;
  } */ *ap = v;

  struct vnode *vp = ap->a_vp;
  struct vattr *vap = ap->a_vap;
  uvfs_node *unp = VTOUVFS(vp);
  int error = 0;

  uvfs_setattrargs arg;
  uvfs_wccstat res;

#if UVFS_DEBUG_FS
  warn ("uvfs_setattr: fileid = %d\n", unp->fh);
#endif /* UVFS_DEBUG_FS */

  bzero (&arg, sizeof(arg));
  bzero (&res, sizeof(res));

  arg.file = unp->fh;
  if (vap->va_mode != (ushort) VNOVAL) {
    arg.attributes.mode.set = 1;
    arg.attributes.mode.u.val = vap->va_mode;
  }
  if (vap->va_uid != (uid_t) VNOVAL) {
    arg.attributes.uid.set = 1;
    arg.attributes.uid.u.val = vap->va_uid;
  }
  if (vap->va_gid != (gid_t) VNOVAL) {
    arg.attributes.gid.set = 1;
    arg.attributes.gid.u.val = vap->va_gid;
  }
  if (vap->va_size != (u_quad_t) VNOVAL) {
    arg.attributes.size.set = 1;
    arg.attributes.size.u.val = vap->va_size;
  }
  if (vap->va_atime.tv_sec != (time_t) VNOVAL) {
    arg.attributes.atime.set = SET_TO_CLIENT_TIME;
    arg.attributes.atime.u.time.seconds = vap->va_atime.tv_sec;
    arg.attributes.atime.u.time.nseconds = vap->va_atime.tv_nsec;
  }
  if (vap->va_mtime.tv_sec != (time_t) VNOVAL) {
    arg.attributes.mtime.set = SET_TO_CLIENT_TIME;
    arg.attributes.mtime.u.time.seconds = vap->va_mtime.tv_sec;
    arg.attributes.mtime.u.time.nseconds = vap->va_mtime.tv_nsec;
  }

  error = krpc_callit (VTORPCQ(vp), &uvfsprog_1,
		       UVFSPROC_SETATTR, &arg, &res);

  if (!error && res.status != 0) {
    error = res.status;
  }

  if (!error) {
    if (res.u.wcc.after.present) {
      attr_cache_update (&res.u.wcc.after.u.attributes, vp);
    }
  }

  xdr_free (xdr_uvfs_wccstat, &res);
  return error;
}

static int
uvfs_readdir (void *v)
{
  struct vop_readdir_args /* {
     struct vnodeop_desc *a_desc;
     struct vnode *a_vp;
     struct uio *a_uio;
     struct ucred *a_cred;
     int *a_eofflag;
     int *a_ncookies;
     u_long **a_cookies;
  } */ *ap = v;

  struct uio *uio = ap->a_uio;
  struct vnode *vp = ap->a_vp;
  struct dirent d;
  uvfs_node *unp = VTOUVFS(vp);
  u_int i = 0;
  u_int64_t lastcookie;
  int error = 0;

  uvfs_readdirargs arg;
  uvfs_readdirres res;

#if UVFS_DEBUG_FS
  warn ("uvfs_readdir: fileid = %d\n", unp->fh);
#endif /* UVFS_DEBUG_FS */

  if (vp->v_type != VDIR)
    return ENOTDIR;

#if UVFS_DEBUG_FS
  warn ("resid = %d; offset = %d\n", uio->uio_resid, (int) uio->uio_offset);
#endif /* UVFS_DEBUG_FS */

  if (uio->uio_resid < UIO_MX)
    return EINVAL;
  if (uio->uio_offset < 0)
    return EINVAL;

  bzero (&arg, sizeof(arg));
  bzero (&res, sizeof(res));

  bzero ((caddr_t)&d, sizeof(d));
/*   bcopy (&uio->uio_offset, lastcookie, UVFS_COOKIESIZE); */
  lastcookie = uio->uio_offset;

  arg.dir = unp->fh;
  arg.count = uio->uio_resid;
  arg.cookie = lastcookie;
/*   if (uio->uio_offset == 0) { */
/*     bzero (arg.cookie, UVFS_COOKIESIZE); */
/*   } */
/*   else { */
/*     bcopy (lastcookie, arg.cookie, UVFS_COOKIESIZE); */
/*   } */

  error = krpc_callit (VTORPCQ(vp), &uvfsprog_1,
		       UVFSPROC_READDIR, &arg, &res);

  if (!error && res.status != 0) {
    error = res.status;
  }

  if (!error) {
    for (i = 0; i < res.u.reply.entries.len; i++) {
      d.d_fileno = res.u.reply.entries.val[i].fileid;
      d.d_type = res.u.reply.entries.val[i].type;
      d.d_namlen = strlen (res.u.reply.entries.val[i].name);
      d.d_reclen = DIRENT_SIZE (&d);
/*       d.d_reclen = 512; */
      /* XXX: Need sanity checks here */
      bcopy (res.u.reply.entries.val[i].name, 
	     d.d_name, d.d_namlen + 1);
      if ((error = uiomove((caddr_t)&d, d.d_reclen, uio)) != 0)
	break;
      lastcookie = res.u.reply.entries.val[i].cookie;
/*       bcopy (res.u.reply.entries.val[i].cookie, lastcookie, */
/* 	     UVFS_COOKIESIZE); */
    }
  }

  /* UVFS_COOKIESIZE must be less than sizeof(uio->uio_offset) */
/*   bcopy (lastcookie, &uio->uio_offset, UVFS_COOKIESIZE); */
  uio->uio_offset = lastcookie;
  xdr_free (xdr_uvfs_readdirres, &res);
  return error;
}

static int
uvfs_access (void *v)
{
  struct vop_access_args /* {
     struct vnodeop_desc *a_desc;
     struct vnode *a_vp;
     int a_mode;
     struct ucred *a_cred;
     struct proc *a_p;
  } */ *ap = v;
  struct vnode *vp = ap->a_vp;
  int mode = ap->a_mode;
  uvfs_node *unp = VTOUVFS(vp);
  int error = 0;

  uvfs_accessargs arg;
  uvfs_accessres res;

#if UVFS_DEBUG_FS
  warn ("uvfs_access: fileid = %d\n", unp->fh);
#endif /* UVFS_DEBUG_FS */

  if ((mode & VWRITE) && (vp->v_mount->mnt_flag & MNT_RDONLY)) {
    switch (vp->v_type) {
    case VREG:
    case VDIR:
    case VLNK:
      return EROFS;
    default:
      break;
    }
  }

  bzero (&arg, sizeof(arg));
  bzero (&res, sizeof(res));

  arg.object = unp->fh;
  if (mode & VREAD)
    arg.access = ACCESS3_READ;
  else
    arg.access = 0;
  if (vp->v_type == VDIR) {
    if (mode & VWRITE)
      arg.access |= (ACCESS3_MODIFY | ACCESS3_EXTEND | ACCESS3_DELETE);
    if (mode & VEXEC)
      arg.access |= ACCESS3_LOOKUP;
  } else {
    if (mode & VWRITE)
      arg.access |= (ACCESS3_MODIFY | ACCESS3_EXTEND);
    if (mode & VEXEC)
      arg.access |= ACCESS3_EXECUTE;
  }

  error = krpc_callit (VTORPCQ(vp), &uvfsprog_1,
		       UVFSPROC_ACCESS, &arg, &res);

  if (!error && res.status != 0) {
    error = res.status;
  }

  xdr_free (xdr_uvfs_accessres, &res);
  return error;
}

static int
findfile (struct vnode *dvp, char *pname, int pnamelen, uvfs_fh *fhp, 
	  uvfs_fattr *attr, int *gotattr)
{
  int error = 0;

  uvfs_diropargs arg;
  uvfs_lookupres res;

  bzero (&arg, sizeof(arg));
  bzero (&res, sizeof(res));

  arg.dir = VTOUVFS(dvp)->fh;
  arg.name = xmalloc (pnamelen+1);
  bzero (arg.name, pnamelen+1);
  bcopy (pname, arg.name, pnamelen);  /* need to copy? */

  error = krpc_callit (VTORPCQ(dvp), &uvfsprog_1,
		       UVFSPROC_LOOKUP, &arg, &res);

  if (!error && res.status != 0) {
    error = res.status;
  }

  if (!error) {
    if (fhp != NULL) {
      /* is there anything else to set? */
      *fhp = res.u.resok.object;
      if (res.u.resok.obj_attributes.present) {
	*attr = res.u.resok.obj_attributes.u.attributes;
	*gotattr = 1;
      }
      else {
	*gotattr = 0;
      }
    }
  }

  xfree (arg.name);
  xdr_free (xdr_uvfs_lookupres, &res);
  return error;
}

static int
uvfs_lookup (void *v)
{
  struct vop_lookup_args /*{
     struct vnodeop_desc *a_desc;
     struct vnode *a_dvp;
     struct vnode **a_vpp;
     struct componentname *a_cnp;
  } */ *ap = v;

  struct vnode *dvp = ap->a_dvp;
  struct vnode **vpp = ap->a_vpp;
  struct componentname *cnp = ap->a_cnp;
  char *pname = cnp->cn_nameptr;

  int flags = cnp->cn_flags;
  int islastcn = flags & ISLASTCN;
  int lockparent = flags & LOCKPARENT;
  int wantparent = flags & WANTPARENT;
  int nameiop = cnp->cn_nameiop;

  uvfs_fh newfh;
  uvfs_fattr newattr;
  int gotattr = 0;
  struct vnode *fvp = 0;
  int error = 0;

#if UVFS_DEBUG_FS
  warn ("uvfs_lookup: %s, %d\n", pname, nameiop);
#endif /* UVFS_DEBUG_FS */

  *vpp = NULLVP;

  /* Check accessibility of directory. */
  if (dvp->v_type != VDIR)
    return ENOTDIR;

#if 0
  error = VOP_ACCESS(dvp, VEXEC, cnp->cn_cred, cnp->cn_proc);
  if (error)
    return error;
#endif

  if (islastcn && (dvp->v_mount->mnt_flag & MNT_RDONLY) &&
      (nameiop == DELETE || nameiop == RENAME))
    return EROFS;

#ifdef UVFS_FS_NAMECACHE
  /*
   * Check name cache for directory/name pair.  This returns ENOENT
   * if the name is known not to exist, -1 if the name was found, or
   * zero if not.
   */
  if (attr_cache_expired (dvp)) {
    if (attr_cache_invalid (dvp)) {
      /* update attr cache for directory and purge all name cache entries */
      cache_purge (dvp);
      goto skipcache;
    }
  }

  error = cache_lookup (dvp, vpp, cnp);

  if (error) {
    u_long vpid;

#if UVFS_DEBUG_FS
    warn ("uvfs_lookup: name cache hit\n");
#endif /* UVFS_DEBUG_FS */

    if (error == ENOENT)
      return error;

    fvp = *vpp;
    vpid = fvp->v_id;

    if (dvp == fvp) {
      VREF(fvp);
      error = 0;
    }
    else if (flags & ISDOTDOT) {
      /*
       * We need to unlock the directory before getting
       * the locked vnode for ".." to avoid deadlocks.
       */
      VOP_UNLOCK(dvp, 0, cnp->cn_proc);
      error = vget (fvp, LK_SHARED | LK_RETRY, cnp->cn_proc);
      if (!error) {
	if (lockparent && islastcn)
	  error = VOP_LOCK(dvp, LK_SHARED | LK_RETRY, cnp->cn_proc);
      }
    } else {
      error = vget (fvp, LK_SHARED | LK_RETRY, cnp->cn_proc);
      if (error || !(lockparent && islastcn)) {
	VOP_UNLOCK(dvp, 0, cnp->cn_proc);
      }
    }

    /*
     * Check that the capability number did not change
     * while we were waiting for the lock.
     */
    if (!error) {
      if (vpid == fvp->v_id) {
	/*
	 * dvp is locked if lockparent && islastcn.
	 * fvp is locked.
	 */
	return 0;
      }
      vput (fvp);

      if (dvp != fvp && lockparent && islastcn) {
	warn ("uvfs_lookup: hmmm...\n");
/* 	VOP_UNLOCK(pdp, 0, cnp->cn_proc); */
      }
    }

    /*
     * Re-lock dvp for the directory search below.
     */
    error = VOP_LOCK(dvp, LK_SHARED | LK_RETRY, cnp->cn_proc);
  
    if (error) {
      return (error);
    }
  
    *vpp = NULL;
  }

 skipcache:
#endif /* UVFS_FS_NAMECACHE */


  /* Check for lookups of ourself */

  if (cnp->cn_namelen == 1 && *pname == '.') {
    *vpp = dvp;
    VREF(dvp);
    VOP_LOCK(dvp, LK_SHARED | LK_RETRY, cnp->cn_proc);
    return 0;
  }

  error = findfile (dvp, pname, cnp->cn_namelen, &newfh, &newattr, &gotattr);
  if (error == ENOENT) {
    if ((nameiop == CREATE || nameiop == RENAME)
	&& islastcn
	/* and dir hasn't been removed ? */) {
#if UVFS_DEBUG_FS
      warn ("uvfs_lookup: CREATE or RENAME & file not found\n");
#endif /* UVFS_DEBUG_FS */
#if 0
      error = VOP_ACCESS(dvp, VWRITE, cnp->cn_cred, cnp->cn_proc);
      if (error)
	return error;
#endif
      cnp->cn_flags |= SAVENAME;
      if (!lockparent)
	VOP_UNLOCK(dvp, 0, cnp->cn_proc);
      return EJUSTRETURN;
    }
#ifdef UVFS_FS_NAMECACHE
    if ((cnp->cn_flags & MAKEENTRY) && nameiop != CREATE) {
#if UVFS_DEBUG_FS
      warn ("uvfs_lookup: updating name cache; enter(dvp, NULL, cnp)\n");
#endif /* UVFS_DEBUG_FS */
      cache_enter (dvp, NULL, cnp);
    }
#endif /* UVFS_FS_NAMECACHE */
    return ENOENT;
  }

  else if (!error) {
    if (nameiop == DELETE && islastcn) {
#if UVFS_DEBUG_FS
    warn ("uvfs_lookup: DELETE & file found\n");
#endif /* UVFS_DEBUG_FS */
#if 0
      error = VOP_ACCESS(dvp, VWRITE, cnp->cn_cred, cnp->cn_proc);
      if (error)
	return error;
#endif
      if (newfh == VTOUVFS(dvp)->fh) {
	VREF(dvp);
	*vpp = dvp;
	return 0;
      }
      
      error = VFS_VGET(dvp->v_mount, newfh, &fvp);
      if (error)
	return error;
      error = ensure_attr (&newattr, gotattr, fvp);
      if (error)
	return error;

      *vpp = fvp;
      cnp->cn_flags |= SAVENAME;
      if (!lockparent)
	VOP_UNLOCK(dvp, 0, cnp->cn_proc);
      return 0;
    }

    if (nameiop == RENAME && wantparent && islastcn) {
#if 0
      error = VOP_ACCESS(dvp, VWRITE, cnp->cn_cred, cnp->cn_proc);
      if (error)
	return error;
#endif
      if (newfh == VTOUVFS(dvp)->fh) {
	return EISDIR;
      }

      error = VFS_VGET(dvp->v_mount, newfh, &fvp);
      if (error)
	return error;
      error = ensure_attr (&newattr, gotattr, fvp);
      if (error)
	return error;

      *vpp = fvp;
      cnp->cn_flags |= SAVENAME;
      if (!lockparent)
	VOP_UNLOCK(dvp, 0, cnp->cn_proc);
      return 0;
    }

    if (flags & ISDOTDOT) {
#if UVFS_DEBUG_FS
      warn ("is ..; lockparent = %d, islastcn = %d\n",lockparent,islastcn);
#endif /* UVFS_DEBUG_FS */
      VOP_UNLOCK(dvp, 0, cnp->cn_proc);
      error = VFS_VGET(dvp->v_mount, newfh, &fvp);
      if (error) {
	error = VOP_LOCK(dvp, LK_SHARED | LK_RETRY, cnp->cn_proc);
	return error;
      }
      error = ensure_attr (&newattr, gotattr, fvp);
      if (error)
	return error;

      if (lockparent && islastcn) {
	error = VOP_LOCK(dvp, LK_SHARED | LK_RETRY, cnp->cn_proc);
	if (error) {
	  vput(fvp);
	  return error;
	}
      }
      *vpp = fvp;      
    } 
    else if (newfh == VTOUVFS(dvp)->fh) {
#if UVFS_DEBUG_FS
      warn ("is a self-reference\n");
#endif /* UVFS_DEBUG_FS */
      if (fvp)
	vrele(fvp);
      VREF(dvp);
      *vpp = dvp;
    }
    else {
#if UVFS_DEBUG_FS
      warn ("else; lockparent = %d, islastcn = %d\n", lockparent, islastcn);
#endif /* UVFS_DEBUG_FS */
      error = VFS_VGET(dvp->v_mount, newfh, &fvp);
      if (error)
	return error;
      error = ensure_attr (&newattr, gotattr, fvp);
      if (error)
	return error;

      if (!lockparent || !islastcn)
	VOP_UNLOCK(dvp, 0, cnp->cn_proc);
      *vpp = fvp;
    }
#ifdef UVFS_FS_NAMECACHE
    /* Insert name into cache if appropriate. */
    if (cnp->cn_flags & MAKEENTRY) {
#if UVFS_DEBUG_FS
      warn ("uvfs_lookup: updating name cache; enter(dvp, *vpp, cnp)\n");
#endif /* UVFS_DEBUG_FS */
      cache_enter (dvp, *vpp, cnp);
    }
#endif /* UVFS_FS_NAMECACHE */
    return 0;
  }
  else {
    return error;
  }

  /* not reached ? */
  return EOPNOTSUPP;
}

static int
uvfs_open (void *v)
{
  struct vop_open_args /* {
    struct vnodeop_desc *a_desc;
    struct vnode *a_vp;
    int a_mode;
    struct ucred *a_cred;
    struct proc *a_p;
  } */ *ap = v;
  struct vnode *vp = ap->a_vp;
  uvfs_node *unp = unp = VTOUVFS(vp);
  int error = 0;

  uvfs_fh arg;
  uvfsstat res;

#ifdef UVFS_DEBUG_FS
  warn ("uvfs_open: fileid = %d\n", unp->fh);
#endif /* UVFS_DEBUG_FS */

  bzero (&arg, sizeof(arg));
  bzero (&res, sizeof(res));

  arg = unp->fh;

  error = krpc_callit (VTORPCQ(vp), &uvfsprog_1,
		       UVFSPROC_OPEN, &arg, &res);

  if (!error && res != 0) {
    error = res;
  }

  if (!error) {
  }

  xdr_free (xdr_uvfsstat, &res);
  return error;
}

static int
uvfs_close(void *v)
{
  struct vop_close_args /* {
    struct vnodeop_desc *a_desc;
    struct vnode *a_vp;
    int a_fflag;
    struct ucred *a_cred;
    struct proc *a_p;
  } */ *ap = v;
  struct vnode *vp = ap->a_vp;
  uvfs_node *unp = VTOUVFS(vp);
  int error = 0;

  uvfs_fh arg;
  uvfsstat res;

#ifdef UVFS_DEBUG_FS
  warn ("uvfs_close: fileid = %d\n", unp->fh);
#endif /* UVFS_DEBUG_FS */

  bzero (&arg, sizeof(arg));
  bzero (&res, sizeof(res));

  arg = unp->fh;

  error = krpc_callit (VTORPCQ(vp), &uvfsprog_1,
		       UVFSPROC_CLOSE, &arg, &res);

  if (!error && res != 0) {
    error = res;
  }

  if (!error) {
  }

  xdr_free (xdr_uvfsstat, &res);
  return error;
}

static int
uvfs_read(void *v)
{
  struct vop_read_args /* {
     struct vnodeop_desc *a_desc;
     struct vnode *a_vp;
     struct uio *a_uio;
     int a_ioflag;
     struct ucred *a_cred;
  } */ *ap = v;

  struct vnode *vp = ap->a_vp;
  struct uio *uio = ap->a_uio;
  uvfs_node *unp = VTOUVFS(vp);
  int len;
  int error = 0;

  uvfs_readargs arg;
  uvfs_readres res;

#ifdef UVFS_DEBUG_FS
  warn ("uvfs_read: fileid = %d\n", unp->fh);
#endif /* UVFS_DEBUG_FS */

  if (vp->v_type == VDIR)
    return EOPNOTSUPP;
  if (uio->uio_resid == 0)
    return 0;
  if (uio->uio_offset < 0)
    return EINVAL;
 
  len = min (UVFS_FABLKSIZE, uio->uio_resid);

  bzero (&arg, sizeof(arg));
  bzero (&res, sizeof(res));

  arg.file = unp->fh;
  arg.offset = uio->uio_offset;
  arg.count = len;

  error = krpc_callit (VTORPCQ(vp), &uvfsprog_1,
		       UVFSPROC_READ, &arg, &res);

  if (!error && res.status != 0) {
    error = res.status;
  }

  if (!error) {
    error = uiomove (res.u.resok.data.val, 
		     res.u.resok.data.len,
		     uio);
  }

  xdr_free (xdr_uvfs_readres, &res);
  return error;
}

static int
uvfs_write(void *v)
{
  struct vop_write_args /* {
     struct vnodeop_desc *a_desc;
     struct vnode *a_vp;
     struct uio *a_uio;
     int a_ioflag;
     struct ucred *a_cred;
  } */ *ap = v;

  struct vnode *vp = ap->a_vp;
  struct uio *uio = ap->a_uio;
  uvfs_node *unp = VTOUVFS(vp);
  int error = 0;

  uvfs_writeargs arg;
  uvfs_writeres res;

#ifdef UVFS_DEBUG_FS
  warn ("uvfs_write: fileid = %d\n", unp->fh);
#endif /* UVFS_DEBUG_FS */

  if (vp->v_type == VDIR)
    return EOPNOTSUPP;

  bzero (&arg, sizeof(arg));
  bzero (&res, sizeof(res));

  arg.file = unp->fh;
  arg.offset = uio->uio_offset;
  arg.count = uio->uio_resid;
  arg.data.len = uio->uio_resid;
  arg.data.val = xmalloc (uio->uio_resid);
  uiomove (arg.data.val, uio->uio_resid, uio);

  error = krpc_callit (VTORPCQ(vp), &uvfsprog_1,
		       UVFSPROC_WRITE, &arg, &res);

  if (!error && res.status != 0) {
    error = res.status;
  }

  xfree (arg.data.val);
  xdr_free (xdr_uvfs_writeres, &res);
  return error;
}

static int 
uvfs_create(void *v)
{
  struct vop_create_args /* {
    struct vnodeop_desc *a_desc;
    struct vnode *a_dvp;
    struct vnode **a_vpp;
    struct componentname *a_cnp;
    struct vattr *a_vap;
  } */ *ap = v;

  struct vnode **vpp = ap->a_vpp;
  struct vnode *dvp = ap->a_dvp;
  struct componentname *cnp = ap->a_cnp;
  struct vattr *vap = ap->a_vap;
  char *pname = cnp->cn_nameptr;
  int pnamelen = cnp->cn_namelen;
  struct vnode *vp;
  int error = 0;

  uvfs_createargs arg;
  uvfs_diropres res;

#ifdef UVFS_DEBUG_FS
  warn ("uvfs_create: %s\n", pname);
#endif /* UVFS_DEBUG_FS */

  *vpp = NULL;

  bzero (&arg, sizeof(arg));
  bzero (&res, sizeof(res));

  arg.where.dir = VTOUVFS(dvp)->fh;
  arg.where.name = xmalloc (pnamelen+1);
  bzero (arg.where.name, pnamelen+1);
  bcopy (pname, arg.where.name, pnamelen);  /* need to copy? */

  arg.how.mode = UNCHECKED;
  arg.how.u.obj_attributes.mode.set = 1;
  arg.how.u.obj_attributes.mode.u.val = vap->va_mode;
  arg.how.u.obj_attributes.uid.set = 1;
  arg.how.u.obj_attributes.uid.u.val = vap->va_uid;
  arg.how.u.obj_attributes.gid.set = 1;
  arg.how.u.obj_attributes.gid.u.val = vap->va_gid;
  arg.how.u.obj_attributes.size.set = 1;
  arg.how.u.obj_attributes.size.u.val = vap->va_size;
  arg.how.u.obj_attributes.atime.set = SET_TO_CLIENT_TIME;
  arg.how.u.obj_attributes.atime.u.time.seconds = vap->va_atime.tv_sec;
  arg.how.u.obj_attributes.atime.u.time.nseconds = vap->va_atime.tv_nsec;
  arg.how.u.obj_attributes.mtime.set = SET_TO_CLIENT_TIME;
  arg.how.u.obj_attributes.mtime.u.time.seconds = vap->va_mtime.tv_sec;
  arg.how.u.obj_attributes.mtime.u.time.nseconds = vap->va_mtime.tv_nsec;

  error = krpc_callit (VTORPCQ(dvp), &uvfsprog_1,
		       UVFSPROC_CREATE, &arg, &res);

  if (error) {
  }

  if (!error && res.status != 0) {
    error = res.status;
  }

  if (!error) {
    if (res.u.resok.file.present) {
      error = VFS_VGET (dvp->v_mount, res.u.resok.file.u.handle, &vp);
      if (!error) {
	if (res.u.resok.attributes.present) {
	  vp->v_type = res.u.resok.attributes.u.attributes.type;
	  attr_cache_update (&res.u.resok.attributes.u.attributes, vp);
	}
	*vpp = vp;
#ifdef UVFS_FS_NAMECACHE
	if (cnp->cn_flags & MAKEENTRY) {
#if UVFS_DEBUG_FS
	  warn ("uvfs_create: updating name cache; enter(dvp, vp, cnp)\n");
#endif /* UVFS_DEBUG_FS */
	  cache_enter (dvp, vp, cnp);
	}
#endif /* UVFS_FS_NAMECACHE */
      }
    }
    else {
      error = EBADF;
    }
  }
  
  vput (dvp);
  if ((cnp->cn_flags & SAVESTART) == 0) {
    free (cnp->cn_pnbuf, M_NAMEI);
#if UVFS_DEBUG_FS
    warn ("uvfs_create: FREEING PATHNAME BUFFER\n");
#endif /* UVFS_DEBUG_FS */
  }
  xfree (arg.where.name);
  xdr_free (xdr_uvfs_diropres, &res);
  return error;
}

static int 
uvfs_mkdir(void *v)
{
  struct vop_mkdir_args /* {
    struct vnodeop_desc *a_desc;
    struct vnode *a_dvp;
    struct vnode **a_vpp;
    struct componentname *a_cnp;
    struct vattr *a_vap;
  } */ *ap = v;

  struct vnode **vpp = ap->a_vpp;
  struct vnode *dvp = ap->a_dvp;
  struct componentname *cnp = ap->a_cnp;
  struct vattr *vap = ap->a_vap;
  char *pname = cnp->cn_nameptr;
  int pnamelen = cnp->cn_namelen;
  struct vnode *vp;
  int error = 0;

  uvfs_mkdirargs arg;
  uvfs_diropres res;

#ifdef UVFS_DEBUG_FS
  warn ("uvfs_mkdir: %s\n", pname);
#endif /* UVFS_DEBUG_FS */

  *vpp = NULL;

  bzero (&arg, sizeof(arg));
  bzero (&res, sizeof(res));

  arg.where.dir = VTOUVFS(dvp)->fh;
  arg.where.name = xmalloc (pnamelen+1);
  bzero (arg.where.name, pnamelen+1);
  bcopy (pname, arg.where.name, pnamelen);  /* need to copy? */

  arg.attributes.mode.set = 1;
  arg.attributes.mode.u.val = vap->va_mode;
  arg.attributes.uid.set = 1;
  arg.attributes.uid.u.val = vap->va_uid;
  arg.attributes.gid.set = 1;
  arg.attributes.gid.u.val = vap->va_gid;
  arg.attributes.size.set = 1;
  arg.attributes.size.u.val = vap->va_size;
  arg.attributes.atime.set = SET_TO_CLIENT_TIME;
  arg.attributes.atime.u.time.seconds = vap->va_atime.tv_sec;
  arg.attributes.atime.u.time.nseconds = vap->va_atime.tv_nsec;
  arg.attributes.mtime.set = SET_TO_CLIENT_TIME;
  arg.attributes.mtime.u.time.seconds = vap->va_mtime.tv_sec;
  arg.attributes.mtime.u.time.nseconds = vap->va_mtime.tv_nsec;

  error = krpc_callit (VTORPCQ(dvp), &uvfsprog_1,
		       UVFSPROC_MKDIR, &arg, &res);

  if (error) {
  }

  if (!error && res.status != 0) {
    error = res.status;
  }

  if (!error) {
    if (res.u.resok.file.present) {
      error = VFS_VGET (dvp->v_mount, res.u.resok.file.u.handle, &vp);
      if (!error) {
	if (res.u.resok.attributes.present) {
	  vp->v_type = res.u.resok.attributes.u.attributes.type;
	  attr_cache_update (&res.u.resok.attributes.u.attributes, vp);
	}
	*vpp = vp;
#ifdef UVFS_FS_NAMECACHE
	if (cnp->cn_flags & MAKEENTRY) {
#if UVFS_DEBUG_FS
	  warn ("uvfs_mkdir: updating name cache; enter(dvp, vp, cnp)\n");
#endif /* UVFS_DEBUG_FS */
	  cache_enter (dvp, vp, cnp);
	}
#endif /* UVFS_FS_NAMECACHE */
      }
    }
    else {
      error = EBADF;
    }
  }
  
  vput (dvp);
  if ((cnp->cn_flags & SAVESTART) == 0) {
    free (cnp->cn_pnbuf, M_NAMEI);
#if UVFS_DEBUG_FS
    warn ("uvfs_mkdir: FREEING PATHNAME BUFFER\n");
#endif /* UVFS_DEBUG_FS */
  }
  xfree (arg.where.name);
  xdr_free (xdr_uvfs_diropres, &res);
  return error;
}

static int
uvfs_rename (void *v)
{
  struct vop_rename_args /* {
    struct vnodeop_desc *a_desc;
    struct vnode *a_fdvp;
    struct vnode *a_fvp;
    struct componentname *a_fcnp;
    struct vnode *a_tdvp;
    struct vnode *a_tvp;
    struct componentname *a_tcnp;
  } */ *ap = v;

  struct vnode *fvp = ap->a_fvp;
  struct vnode *fdvp = ap->a_fdvp;
  struct vnode *tvp = ap->a_tvp;
  struct vnode *tdvp = ap->a_tdvp;
  struct componentname *fcnp = ap->a_fcnp;
  struct componentname *tcnp = ap->a_tcnp;
  int error = 0;

  uvfs_renameargs arg;
  uvfs_renameres res;

#ifdef UVFS_DEBUG_FS
  warn ("uvfs_rename: %s -> %s\n", fcnp->cn_nameptr, tcnp->cn_nameptr);
#endif /* UVFS_DEBUG_FS */

  /* Check for cross-device rename. */
  if ((fvp->v_mount != tdvp->v_mount)
      || (tvp && (fvp->v_mount != tvp->v_mount))) {
    error = EXDEV;
  }
  /* Do RPC call */
  else {
    bzero (&arg, sizeof(arg));
    bzero (&res, sizeof(res));

    arg.from.dir = VTOUVFS(fdvp)->fh;
    arg.from.name = xmalloc (fcnp->cn_namelen+1);
    bzero (arg.from.name, fcnp->cn_namelen+1);
    bcopy (fcnp->cn_nameptr, arg.from.name, fcnp->cn_namelen);

    arg.to.dir = VTOUVFS(tdvp)->fh;
    arg.to.name = xmalloc (tcnp->cn_namelen+1);
    bzero (arg.to.name, tcnp->cn_namelen+1);
    bcopy (tcnp->cn_nameptr, arg.to.name, tcnp->cn_namelen);

    error = krpc_callit (VTORPCQ(fdvp), &uvfsprog_1,
			 UVFSPROC_RENAME, &arg, &res);

    if (!error && res.status != 0) {
      error = res.status;
    }

    xfree (arg.from.name);
    xfree (arg.to.name);
  }

#ifdef UVFS_FS_NAMECACHE
  if (fvp->v_type == VDIR) {
    if (tvp != NULL && tvp->v_type == VDIR) {
#if UVFS_DEBUG_FS
      warn ("uvfs_rename: updating name cache; cache_purge (tdvp)\n");
#endif /* UVFS_DEBUG_FS */
      cache_purge (tdvp);
    }
#if UVFS_DEBUG_FS
    warn ("uvfs_rename: updating name cache; cache_purge (fdvp)\n");
#endif /* UVFS_DEBUG_FS */
    cache_purge (fdvp);
  }
#endif /* UVFS_FS_NAMECACHE */

  VOP_ABORTOP(tdvp, tcnp);	/* need? */
  if (tdvp == tvp)
    vrele(tdvp);
  else
    vput(tdvp);
  if (tvp)
    vput(tvp);
  VOP_ABORTOP(fdvp, fcnp);	/* need? */
  vrele(fdvp);
  vrele(fvp);
  xdr_free (xdr_uvfs_renameres, &res);
  return error;
}

/* XXX: Need to look at 'rmdir /uvfs/b/b'---returns Invalid Argument error */
static int
uvfs_rmdir (void *v)
{
  struct vop_rmdir_args /* {
    struct vnodeop_desc *a_desc;
    struct vnode *a_dvp;
    struct vnode *a_vp;
    struct componentname *a_cnp;
  } */ *ap = v;

  struct vnode *dvp = ap->a_dvp;
  struct vnode *vp = ap->a_vp;
  struct componentname *cnp = ap->a_cnp;
  char *pname = cnp->cn_nameptr;
  int pnamelen = cnp->cn_namelen;
  int error = 0;

  uvfs_diropargs arg;
  uvfs_wccstat res;

#ifdef UVFS_DEBUG_FS
  warn ("uvfs_rmdir: fileid = %d\n", VTOUVFS(vp)->fh);
  warn ("uvfs_rmdir: pname = %s\n", pname);
#endif /* UVFS_DEBUG_FS */

  bzero (&arg, sizeof(arg));
  bzero (&res, sizeof(res));

  arg.dir = VTOUVFS(dvp)->fh;
  arg.name = xmalloc (pnamelen+1);
  bzero (arg.name, pnamelen+1);
  bcopy (pname, arg.name, pnamelen);  /* need to copy? */

  error = krpc_callit (VTORPCQ(dvp), &uvfsprog_1,
		       UVFSPROC_RMDIR, &arg, &res);

  if (!error && res.status != 0) {
    error = res.status;
  }

  /* Deal with removing "." directory */
  if (dvp == vp)
    vrele (vp);
  else
    vput (vp);
  vput (dvp);

#ifdef UVFS_FS_NAMECACHE
#if UVFS_DEBUG_FS
  warn ("uvfs_rmdir: updating name cache; cache_purge (dvp)\n");
  warn ("uvfs_rmdir: updating name cache; cache_purge (vp)\n");
#endif /* UVFS_DEBUG_FS */
  cache_purge (dvp);
  cache_purge (vp);
#endif /* UVFS_FS_NAMECACHE */

  if ((cnp->cn_flags & SAVESTART) == 0) {
    free (cnp->cn_pnbuf, M_NAMEI);
#ifdef UVFS_DEBUG_FS
    warn ("uvfs_rmdir: FREEING PATHNAME BUFFER\n");
#endif /* UVFS_DEBUG_FS */
  }
  xfree (arg.name);
  xdr_free (xdr_uvfs_wccstat, &res);
  return error;
}

static int
uvfs_remove (void *v)
{
  struct vop_remove_args /* {
    struct vnodeop_desc *a_desc;
    struct vnode *a_dvp;
    struct vnode *a_vp;
    struct componentname *a_cnp;
  } */ *ap = v;

  struct vnode *dvp = ap->a_dvp;
  struct vnode *vp = ap->a_vp;
  struct componentname *cnp = ap->a_cnp;
  char *pname = cnp->cn_nameptr;
  int pnamelen = cnp->cn_namelen;
  int error = 0;

  uvfs_diropargs arg;
  uvfs_wccstat res;

#ifdef UVFS_DEBUG_FS
  warn ("uvfs_remove: fileid = %d\n", VTOUVFS(vp)->fh);
  warn ("uvfs_remove: pname = %s\n", pname);
#endif /* UVFS_DEBUG_FS */

  bzero (&arg, sizeof(arg));
  bzero (&res, sizeof(res));

  arg.dir = VTOUVFS(dvp)->fh;
  arg.name = xmalloc (pnamelen+1);
  bzero (arg.name, pnamelen+1);
  bcopy (pname, arg.name, pnamelen);  /* need to copy? */

  error = krpc_callit (VTORPCQ(dvp), &uvfsprog_1,
		       UVFSPROC_REMOVE, &arg, &res);

  if (!error && res.status != 0) {
    error = res.status;
  }

  /* Deal with removing "." directory */
  if (dvp == vp)
    vrele (vp);
  else
    vput (vp);
  vput (dvp);

#ifdef UVFS_FS_NAMECACHE
#if UVFS_DEBUG_FS
  warn ("uvfs_remove: updating name cache; cache_purge (vp)\n");
#endif /* UVFS_DEBUG_FS */
  cache_purge (vp);
#endif /* UVFS_FS_NAMECACHE */

  if ((cnp->cn_flags & SAVESTART) == 0) {
    free (cnp->cn_pnbuf, M_NAMEI);
#ifdef UVFS_DEBUG_FS
    warn ("uvfs_remove: FREEING PATHNAME BUFFER\n");
#endif /* UVFS_DEBUG_FS */
  }
  xfree (arg.name);
  xdr_free (xdr_uvfs_wccstat, &res);
  return error;
}

static int
uvfs_readlink (void *v)
{
  struct vop_readlink_args /* {
    struct vnodeop_desc *a_desc;
    struct vnode *a_vp;
    struct uio *a_uio;
    struct ucred *a_cred;
  } */ *ap = v;

  struct vnode *vp = ap->a_vp;
  struct uio *uio = ap->a_uio;
  uvfs_node *unp = VTOUVFS(vp);
  int len;
  int error = 0;
  
  uvfs_fh arg;
  uvfs_readlinkres res;

  if (vp->v_type != VLNK)
    return EPERM;

  bzero (&arg, sizeof(arg));
  bzero (&res, sizeof(res));

  arg = unp->fh;

  error = krpc_callit (VTORPCQ(vp), &uvfsprog_1,
		       UVFSPROC_READLINK, &arg, &res);

  if (!error && res.status != 0) {
    error = res.status;
  }

  if (!error) {
    len = strlen (res.u.resok.data);
    len = min (len - uio->uio_offset, uio->uio_resid);
    if (len > 0)
      error = uiomove (res.u.resok.data + uio->uio_offset, len, uio);
  }

  xdr_free (xdr_uvfs_readlinkres, &res);
  return error;
}

static int
uvfs_link (void *v)
{
  struct vop_link_args /* {
    struct vnodeop_desc *a_desc;
    struct vnode *a_dvp;
    struct vnode *a_vp;
    struct componentname *a_cnp;
  } */ *ap = v;

  struct vnode *vp = ap->a_vp;
  struct vnode *dvp = ap->a_dvp;
  struct componentname *cnp = ap->a_cnp;
  int error = 0;
  
  uvfs_linkargs arg;
  uvfs_linkres res;

#ifdef UVFS_DEBUG_FS
  warn ("uvfs_link: fileid = %d\n", VTOUVFS(vp)->fh);
#endif /* UVFS_DEBUG_FS */

  if (vp->v_mount != dvp->v_mount) {
    VOP_ABORTOP(dvp, cnp);
    if (vp == dvp)
      vrele(dvp);
    else
      vput(dvp);
    return EXDEV;
  }

  bzero (&arg, sizeof(arg));
  bzero (&res, sizeof(res));

  arg.from = VTOUVFS(vp)->fh;
  arg.to.dir = VTOUVFS(dvp)->fh;
  arg.to.name = xmalloc (cnp->cn_namelen+1);
  bzero (arg.to.name, cnp->cn_namelen+1);
  bcopy (cnp->cn_nameptr, arg.to.name, cnp->cn_namelen);

  error = krpc_callit (VTORPCQ(vp), &uvfsprog_1,
		       UVFSPROC_LINK, &arg, &res);

  if (!error && res.status != 0) {
    error = res.status;
  }

  if (!error) {
  }

  xfree (arg.to.name);
  xdr_free (xdr_uvfs_linkres, &res);
  free (cnp->cn_pnbuf, M_NAMEI);

  if (vp != dvp)
    VOP_UNLOCK(vp, 0, cnp->cn_proc);
  vput(dvp);

  return error; 
}

static int
uvfs_symlink (void *v)
{
  struct vop_symlink_args /* {
    struct vnodeop_desc *a_desc;
    struct vnode *a_dvp;
    struct vnode **a_vpp;
    struct componentname *a_cnp;
    struct vattr *a_vap;
    char *a_target;
  } */ *ap = v;

  struct vnode *dvp = ap->a_dvp;
  struct componentname *cnp = ap->a_cnp;
  struct vattr *vap = ap->a_vap;
  char *pname = cnp->cn_nameptr;
  int pnamelen = cnp->cn_namelen;
  char *target = ap->a_target;
  int error = 0;
  
  uvfs_symlinkargs arg;
  uvfs_diropres res;

#ifdef UVFS_DEBUG_FS
  warn ("uvfs_symlink: fileid = %s\n", pname);
#endif /* UVFS_DEBUG_FS */

  bzero (&arg, sizeof(arg));
  bzero (&res, sizeof(res));

  arg.where.dir = VTOUVFS(dvp)->fh;
  arg.where.name = xmalloc (pnamelen+1);
  bzero (arg.where.name, pnamelen+1);
  bcopy (pname, arg.where.name, pnamelen);  /* need to copy? */

  arg.symlink.symlink_attributes.mode.set = 1;
  arg.symlink.symlink_attributes.mode.u.val = vap->va_mode;
  arg.symlink.symlink_attributes.uid.set = 1;
  arg.symlink.symlink_attributes.uid.u.val = vap->va_uid;
  arg.symlink.symlink_attributes.gid.set = 1;
  arg.symlink.symlink_attributes.gid.u.val = vap->va_gid;
  arg.symlink.symlink_attributes.size.set = 1;
  arg.symlink.symlink_attributes.size.u.val = vap->va_size;
  arg.symlink.symlink_attributes.atime.set = SET_TO_CLIENT_TIME;
  arg.symlink.symlink_attributes.atime.u.time.seconds = vap->va_atime.tv_sec;
  arg.symlink.symlink_attributes.atime.u.time.nseconds = vap->va_atime.tv_nsec;
  arg.symlink.symlink_attributes.mtime.set = SET_TO_CLIENT_TIME;
  arg.symlink.symlink_attributes.mtime.u.time.seconds = vap->va_mtime.tv_sec;
  arg.symlink.symlink_attributes.mtime.u.time.nseconds = vap->va_mtime.tv_nsec;

  arg.symlink.symlink_data = xmalloc (MAXNAMLEN);
  bzero (arg.symlink.symlink_data, MAXNAMLEN);
  bcopy (target, arg.symlink.symlink_data, MAXNAMLEN - 1);

  error = krpc_callit (VTORPCQ(dvp), &uvfsprog_1,
		       UVFSPROC_SYMLINK, &arg, &res);

  if (!error && res.status != 0) {
    error = res.status;
  }

  if (!error) {
  }

  vput (dvp);

  if ((cnp->cn_flags & SAVESTART) == 0) {
    free (cnp->cn_pnbuf, M_NAMEI);
#if UVFS_DEBUG_FS
    warn ("uvfs_symlink: FREEING PATHNAME BUFFER\n");
#endif /* UVFS_DEBUG_FS */
  }
  xfree (arg.where.name);
  xfree (arg.symlink.symlink_data);
  xdr_free (xdr_uvfs_diropres, &res);
  return error; 
}

static int
uvfs_fsync (void *v)
{
  struct vop_fsync_args /* {
    struct vnodeop_desc *a_desc;
    struct vnode *a_vp;
    struct ucred *a_cred;
    int a_waitfor;
    struct proc *a_p;
  } */ *ap = v;

  struct vnode *vp = ap->a_vp;
  uvfs_node *unp = VTOUVFS(vp);
  int error = 0;
  
  uvfs_commitargs arg;
  uvfs_commitres res;

#ifdef UVFS_DEBUG_FS
  warn ("uvfs_fsync: fileid = %d\n", VTOUVFS(vp)->fh);
#endif /* UVFS_DEBUG_FS */

  bzero (&arg, sizeof(arg));
  bzero (&res, sizeof(res));

  arg.file = unp->fh;
  arg.offset = 0;
  arg.count = 0; /* XXX */

  error = krpc_callit (VTORPCQ(vp), &uvfsprog_1,
		       UVFSPROC_COMMIT, &arg, &res);

  if (!error && res.status != 0) {
    error = res.status;
  }

  if (!error) {
  }

  xdr_free (xdr_uvfs_commitres, &res);
  return error; 
}

static int
uvfs_advlock (void *v)
{
  struct vop_advlock_args /* {
    struct vnodeop_desc *a_desc;
    struct vnode *a_vp;
    caddr_t  a_id;
    int  a_op;
    struct flock *a_fl;
    int  a_flags;
  } */ *ap = v;

  struct vnode *vp = ap->a_vp;
  uvfs_node *unp = VTOUVFS(vp);

#ifdef UVFS_DEBUG_FS
  warn ("uvfs_advlock: fileid = %d\n", VTOUVFS(vp)->fh);
#endif /* UVFS_DEBUG_FS */

  return (lf_advlock(&unp->uvfslockf, (off_t)0, ap->a_id,
		     ap->a_op, ap->a_fl, ap->a_flags));
}

static int
uvfs_vop_default (void *v)
{
  struct vop_generic_args /* {
     struct vnodeop_desc *a_desc;
  } */ *ap = v;

  warn ("uvfs_default: %s -> EOPNOTSUPP\n", ap->a_desc->vdesc_name);
  return EOPNOTSUPP;
}

struct vnodeopv_entry_desc uvfs_vnodeop_entries[] = {
  { &vop_default_desc, uvfs_vop_default },
  { &vop_reclaim_desc, uvfs_reclaim },
  { &vop_readdir_desc, uvfs_readdir },
  { &vop_getattr_desc, uvfs_getattr },
  { &vop_setattr_desc, uvfs_setattr },
  { &vop_access_desc, uvfs_access },
  { &vop_lookup_desc, uvfs_lookup },
  { &vop_inactive_desc, uvfs_inactive },
  { &vop_open_desc, uvfs_open },
  { &vop_close_desc, uvfs_close },
  { &vop_read_desc, uvfs_read },
  { &vop_write_desc, uvfs_write },
  { &vop_remove_desc, uvfs_remove },
  { &vop_rmdir_desc, uvfs_rmdir },
  { &vop_mkdir_desc, uvfs_mkdir },
  { &vop_rename_desc, uvfs_rename },
  { &vop_create_desc, uvfs_create },
  { &vop_readlink_desc, uvfs_readlink },
  { &vop_link_desc, uvfs_link },
  { &vop_symlink_desc, uvfs_symlink },
  { &vop_fsync_desc, uvfs_fsync },
  { &vop_advlock_desc, uvfs_advlock },
  { &vop_lease_desc, nullop },
  { &vop_lock_desc, vop_generic_lock },
  { &vop_unlock_desc, vop_generic_unlock },
  { &vop_islocked_desc, vop_generic_islocked },
  { &vop_revoke_desc, vop_generic_revoke },
  { &vop_abortop_desc, vop_generic_abortop },
  { 0, 0 }
};

struct vnodeopv_desc uvfs_vnodeop_opv_desc = {
  &uvfs_vnodeop_p, uvfs_vnodeop_entries,
};
