/* $Id: dir.c,v 1.2 1999/10/02 20:06:58 cblake Exp $ */

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
 */
#include "uvfs_kern.h"
#include <linux/kernel.h>
#include <linux/fcntl.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/dirent.h>
#include <asm/uaccess.h>
#include "attr.h"

static int /* struct dentry * */
uvfs_lookup (struct inode * dvp, struct dentry *dentry)
{
  int            error;
  uvfs_diropargs arg;
  uvfs_lookupres res;

  MAYBEWARN ("uvfs_lookup: %x %s\n", ITOUVFS (dvp)->fh, dentry->d_name.name);
  if (!dvp || !S_ISDIR (dvp->i_mode)) {
     warn ("uvfs_lookup: inode is NULL or not a directory\n");
     return -ENOTDIR;
  }
          
  /* XXX: should check that dentry->d_name.len not too big */
  dentry->d_op = &uvfs_dentry_operations;
  dentry->d_fsdata = NULL;
  dentry->d_inode = NULL;

  bzero (&arg, sizeof arg);
  bzero (&res, sizeof res);

  arg.dir = ITOUVFS (dvp)->fh;
  arg.name = xmalloc (dentry->d_name.len+1);	/* need to copy ? */
  bzero (arg.name, dentry->d_name.len+1);
  bcopy (dentry->d_name.name, arg.name, dentry->d_name.len+1);

  error = krpc_callit (ITORPCQ (dvp), &uvfsprog_1,
                       UVFSPROC_LOOKUP, &arg, &res);

  if (error) {
    MAYBEWARN ("uvfs_lookup: RPC error = %d\n", error);
    goto end;
  }
  error = res.status;
  if (error && error != ENOENT) {
    MAYBEWARN ("uvfs_lookup: RPC result error = %d\n", error);
    goto end;
  } 

  if (error != ENOENT) {
    if (uvfs_filledinode (dvp->i_sb, &dentry->d_inode, 
			  res.u.resok.object,
			  res.u.resok.obj_attributes.present ? 
			  &res.u.resok.obj_attributes.u.attributes : NULL)) {
      error = ENOMEM;
      goto end;
    }

    MAYBEWARN ("ino=%d idev.M=%d idev.m=%d\n", (int)dentry->d_inode->i_ino,
	       (int)MAJOR (dentry->d_inode->i_dev), 
	       (int)MINOR (dentry->d_inode->i_dev));
  }
  else {
    MAYBEWARN ("file not found; inserting negative cache entry\n");
    error = 0;
  }
  
  d_add (dentry, dentry->d_inode);
end:
  xfree (arg.name);
  xdr_free (xdr_uvfs_lookupres, &res);
  return -error;
}

static int
uvfs_create (struct inode * dvp, struct dentry *dentry, int mode)
{
  int error;
  uvfs_createargs arg;
  uvfs_diropres res;

  MAYBEWARN ("uvfs_create: %s\n", dentry->d_name.name);

  bzero (&arg, sizeof arg);
  bzero (&res, sizeof res);

  arg.where.dir = ITOUVFS (dvp)->fh;
  arg.where.name = xmalloc (dentry->d_name.len+1);	/* need to copy ? */
  bzero (arg.where.name, dentry->d_name.len+1);
  bcopy (dentry->d_name.name, arg.where.name, dentry->d_name.len+1);

  arg.how.mode = UNCHECKED;
  arg.how.u.obj_attributes.mode.set = 1;
  arg.how.u.obj_attributes.mode.u.val = mode; /*XXX*/
  arg.how.u.obj_attributes.uid.set = 1;
  arg.how.u.obj_attributes.uid.u.val = current->fsuid;
  arg.how.u.obj_attributes.gid.set = 1;
  arg.how.u.obj_attributes.gid.u.val = current->fsgid;

/*   arg.how.u.obj_attributes.size.set = 1; */
/*   arg.how.u.obj_attributes.atime.set = SET_TO_CLIENT_TIME; */
/*   arg.how.u.obj_attributes.mtime.set = SET_TO_CLIENT_TIME; */
/*   arg.how.u.obj_attributes.size.u.val = vap->va_size; */
/*   arg.how.u.obj_attributes.atime.u.time.seconds = vap->va_atime.tv_sec; */
/*   arg.how.u.obj_attributes.atime.u.time.nseconds = vap->va_atime.tv_nsec; */
/*   arg.how.u.obj_attributes.mtime.u.time.seconds = vap->va_mtime.tv_sec; */
/*   arg.how.u.obj_attributes.mtime.u.time.nseconds = vap->va_mtime.tv_nsec; */

  error = krpc_callit (ITORPCQ (dvp), &uvfsprog_1,
		       UVFSPROC_CREATE, &arg, &res);

  if (!error && res.status != 0) {
    error = res.status;
  }

  if (!error) {
    if (!res.u.resok.file.present) {
      error = EBADF;
      goto end;
    }
    if (uvfs_filledinode (dvp->i_sb, &dentry->d_inode, 
			  res.u.resok.file.u.handle,
			  res.u.resok.attributes.present ? 
			  &res.u.resok.attributes.u.attributes : NULL)) {
      error = ENOMEM;
      goto end;
    }
    d_instantiate (dentry, dentry->d_inode);
  }

end:
  if (error)
    d_drop (dentry);
  xfree (arg.where.name);
  xdr_free (xdr_uvfs_diropres, &res);
  return -error;
}

static int
uvfs_mkdir (struct inode *dvp, struct dentry *dentry, int mode)
{
  int error;
  uvfs_mkdirargs arg;
  uvfs_diropres res;

  MAYBEWARN ("uvfs_mkdir: %s\n", dentry->d_name.name);

  bzero (&arg, sizeof arg);
  bzero (&res, sizeof res);

  arg.where.dir = ITOUVFS (dvp)->fh;
  arg.where.name = xmalloc (dentry->d_name.len+1);	/* need to copy ? */
  bzero (arg.where.name, dentry->d_name.len+1);
  bcopy (dentry->d_name.name, arg.where.name, dentry->d_name.len+1);

  arg.attributes.mode.set = 1;
  arg.attributes.mode.u.val = mode; /*XXX*/
  arg.attributes.uid.set = 1;
  arg.attributes.uid.u.val = current->fsuid;
  arg.attributes.gid.set = 1;
  arg.attributes.gid.u.val = current->fsgid;

/*   arg.attributes.size.set = 1; */
/*   arg.attributes.atime.set = SET_TO_CLIENT_TIME; */
/*   arg.attributes.mtime.set = SET_TO_CLIENT_TIME; */
/*   arg.attributes.size.u.val = vap->va_size; */
/*   arg.attributes.atime.u.time.seconds = vap->va_atime.tv_sec; */
/*   arg.attributes.atime.u.time.nseconds = vap->va_atime.tv_nsec; */
/*   arg.attributes.mtime.u.time.seconds = vap->va_mtime.tv_sec; */
/*   arg.attributes.mtime.u.time.nseconds = vap->va_mtime.tv_nsec; */

  error = krpc_callit (ITORPCQ (dvp), &uvfsprog_1,
		       UVFSPROC_MKDIR, &arg, &res);

  if (!error && res.status != 0) {
    error = res.status;
  }

  if (!error) {
    if (!res.u.resok.file.present) {
      error = EBADF;
      goto end;
    }
    if (uvfs_filledinode (dvp->i_sb, &dentry->d_inode, 
			  res.u.resok.file.u.handle,
			  res.u.resok.attributes.present ? 
			  &res.u.resok.attributes.u.attributes : NULL)) {
      error = ENOMEM;
      goto end;
    }
    dvp->i_nlink++;
    d_instantiate (dentry, dentry->d_inode);
  }

end:
  if (error)
    d_drop (dentry);
  xfree (arg.where.name);
  xdr_free (xdr_uvfs_diropres, &res);
  return -error;
}

/* XXX: ??Need to look at 'rmdir /uvfs/b/b'---returns Invalid Argument error */
static int
uvfs_rmdir (struct inode *dvp, struct dentry *dentry)
{
  int error;
  uvfs_diropargs arg;
  uvfs_wccstat res;

  MAYBEWARN ("uvfs_rmdir: fileid = %d\n", ITOUVFS (dvp)->fh);
  MAYBEWARN ("uvfs_rmdir: name = %s\n", dentry->d_name.name);

  bzero (&arg, sizeof arg);
  bzero (&res, sizeof res);

  arg.dir = ITOUVFS (dvp)->fh;
  arg.name = xmalloc (dentry->d_name.len+1);	/* need to copy ? */
  bzero (arg.name, dentry->d_name.len+1);
  bcopy (dentry->d_name.name, arg.name, dentry->d_name.len+1);

  error = krpc_callit (ITORPCQ (dvp), &uvfsprog_1,
		       UVFSPROC_RMDIR, &arg, &res);

  if (!error && res.status != 0) {
    error = res.status;
  }

  xfree (arg.name);
  xdr_free (xdr_uvfs_wccstat, &res);
  return -error;
}

static int
uvfs_unlink (struct inode *dvp, struct dentry *dentry)
{
  int error;
  int rehash = 0;
  uvfs_diropargs arg;
  uvfs_wccstat res;

  MAYBEWARN ("uvfs_unlink: fileid = %d\n", ITOUVFS (dvp)->fh);
  MAYBEWARN ("uvfs_unlink: name = %s\n", dentry->d_name.name);

  bzero (&arg, sizeof arg);
  bzero (&res, sizeof res);

  arg.dir = ITOUVFS (dvp)->fh;
  arg.name = xmalloc (dentry->d_name.len+1);	/* need to copy ? */
  bzero (arg.name, dentry->d_name.len+1);
  bcopy (dentry->d_name.name, arg.name, dentry->d_name.len+1);

  if (!list_empty (&dentry->d_hash)) {
    d_drop (dentry);
    rehash = 1;
  }

  if (dentry->d_inode) {
    if (dentry->d_inode->i_nlink)
      dentry->d_inode->i_nlink--;
    d_delete (dentry);
  }

  error = krpc_callit (ITORPCQ (dvp), &uvfsprog_1, 
		       UVFSPROC_REMOVE, &arg, &res);

  if (!error && res.status != 0)
    error = res.status;

  if (!error && rehash)
    d_add (dentry, NULL);

  xfree (arg.name);
  xdr_free (xdr_uvfs_wccstat, &res);
  return -error;
}

static int
uvfs_symlink (struct inode *dvp, struct dentry *dentry,
	     const char *symname)
{
  int error = 0;
  uvfs_symlinkargs arg;
  uvfs_diropres res;

  MAYBEWARN ("uvfs_symlink: %s -> %s\n", dentry->d_name.name, symname);

  bzero (&arg, sizeof arg);
  bzero (&res, sizeof res);

  arg.where.dir = ITOUVFS (dvp)->fh;
  arg.where.name = xmalloc (dentry->d_name.len+1);	/* need to copy ? */
  bzero (arg.where.name, dentry->d_name.len+1);
  bcopy (dentry->d_name.name, arg.where.name, dentry->d_name.len+1);

  arg.symlink.symlink_attributes.mode.set = 1;
  arg.symlink.symlink_attributes.mode.u.val = S_IFLNK | S_IRWXUGO; /*XXX*/
  arg.symlink.symlink_attributes.uid.set = 1;
  arg.symlink.symlink_attributes.uid.u.val = current->fsuid;
  arg.symlink.symlink_attributes.gid.set = 1;
  arg.symlink.symlink_attributes.gid.u.val = current->fsgid;

  /* XXX: Name too long check? */
  arg.symlink.symlink_data = xmalloc (strlen (symname) + 1);
  bcopy (symname, arg.symlink.symlink_data, strlen (symname) + 1);

  d_drop (dentry);
  error = krpc_callit (ITORPCQ (dvp), &uvfsprog_1,
		       UVFSPROC_SYMLINK, &arg, &res);

  if (!error && res.status != 0) {
    error = res.status;
  }

  if (!error) {
    if (res.u.resok.attributes.present) {
      if (uvfs_filledinode (dvp->i_sb, &dentry->d_inode, 
			    res.u.resok.file.u.handle,
			    &res.u.resok.attributes.u.attributes)) {
	error = ENOMEM;
	goto end;
      }
      d_instantiate (dentry, dentry->d_inode);
    } else {
      d_drop (dentry);
    }
  }

end:
  xfree (arg.where.name);
  xfree (arg.symlink.symlink_data);
  xdr_free (xdr_uvfs_diropres, &res);
  return -error;
}

static int
uvfs_link (struct dentry *old_dentry, struct inode *dvp,
	  struct dentry *dentry)
{
  int error = 0;
  
  uvfs_linkargs arg;
  uvfs_linkres res;

  MAYBEWARN ("uvfs_link: old: %s; new: %s\n", old_dentry->d_name.name, 
	     dentry->d_name.name);

  bzero (&arg, sizeof arg);
  bzero (&res, sizeof res);

  arg.from = ITOUVFS (old_dentry->d_inode)->fh;
  arg.to.dir = ITOUVFS (dvp)->fh;
  arg.to.name = xmalloc (dentry->d_name.len+1);	/* need to copy ? */
  bzero (arg.to.name, dentry->d_name.len+1);
  bcopy (dentry->d_name.name, arg.to.name, dentry->d_name.len+1);

  d_drop (dentry);
  error = krpc_callit (ITORPCQ (dvp), &uvfsprog_1,
		       UVFSPROC_LINK, &arg, &res);

  if (!error && res.status != 0) {
    error = res.status;
  }

  if (!error) {
  }

  xfree (arg.to.name);
  xdr_free (xdr_uvfs_linkres, &res);
  return -error; 
}

static int
uvfs_rename (struct inode *old_dvp, struct dentry *old_dentry,
	     struct inode *new_dvp, struct dentry *new_dentry)
{
  int error = 0;

  uvfs_renameargs arg;
  uvfs_renameres res;

  MAYBEWARN ("uvfs_rename: %s -> %s\n", old_dentry->d_name.name, 
	     new_dentry->d_name.name);

  bzero (&arg, sizeof arg);
  bzero (&res, sizeof res);

  arg.from.dir = ITOUVFS (old_dvp)->fh;
  arg.from.name = xmalloc (old_dentry->d_name.len+1);	/* need to copy ? */
  bzero (arg.from.name, old_dentry->d_name.len+1);
  bcopy (old_dentry->d_name.name, arg.from.name, old_dentry->d_name.len+1);

  arg.to.dir = ITOUVFS (new_dvp)->fh;
  arg.to.name = xmalloc (new_dentry->d_name.len+1);	/* need to copy ? */
  bzero (arg.to.name, new_dentry->d_name.len+1);
  bcopy (new_dentry->d_name.name, arg.to.name, new_dentry->d_name.len+1);

  error = krpc_callit (ITORPCQ (old_dvp), &uvfsprog_1,
		       UVFSPROC_RENAME, &arg, &res);

  if (!error && res.status != 0) {
    error = res.status;
  }

  if (!error) {
    d_move (old_dentry, new_dentry);
  }

  xfree (arg.from.name);
  xfree (arg.to.name);

  xdr_free (xdr_uvfs_renameres, &res);
  return -error;
}

static ssize_t
uvfs_dir_read (struct file * filp, char * buf, size_t count, loff_t *ppos)
{
  return -EISDIR;
}

/*
  Linux does not pass user request sizes to VFS handlers.  Hence this function
  just tries to RPC over 1K of directory data instead.  It would be possible to
  do a loop here doing as many 1K or 4K RPCs as is necessary to sate filldir().
*/
static int
uvfs_readdir (struct file *filp, void *dirent, filldir_t filldir)
{
  struct inode         *inod = filp->f_dentry->d_inode;
  uvfs_node            *unp = ITOUVFS (inod);
  u_int64_t             lastcookie = filp->f_pos;
  uvfs_readdirargs      arg;
  uvfs_readdirres       res;
  int                   error, nents;
  struct uvfs_direntry *e, *elast;

  MAYBEWARN ("uvfs_readdir: fileid = %d\n", unp->fh);
  if (!S_ISDIR (inod->i_mode))
    return -ENOTDIR;

  bzero (&arg, sizeof arg);
  bzero (&res, sizeof res);
  arg.dir    = unp->fh;
  arg.count  = 1024;
  arg.cookie = lastcookie;
  error      = krpc_callit (ITORPCQ (inod), &uvfsprog_1,
                            UVFSPROC_READDIR, &arg, &res);
  if (!error && res.status != 0)
    error = res.status;
  if (error)
    goto done;
  nents = res.u.reply.entries.len;
  MAYBEWARN ("uvfs_readdir: RPC success: %d entries\n", nents);
  for (e = res.u.reply.entries.val, elast = e + nents; e < elast; e++) {
    if (filldir(dirent, e->name, strlen (e->name), e->cookie, e->fileid) < 0)
      break;
    lastcookie = e->cookie;
  }
  filp->f_pos = lastcookie;
done: return 0;
}

/* Invalidate dircache entries for an inode. */

struct dentry_operations uvfs_dentry_operations = {
  NULL,	                /* uvfs_lookup_revalidate (struct dentry *), */
  NULL,			/* d_hash */
  NULL,			/* d_compare */
  NULL,                 /* uvfs_dentry_delete (struct dentry *) */
  NULL,                 /* uvfs_dentry_release (struct dentry *) */
  NULL			/* d_iput */
};

static struct file_operations uvfs_dir_operations = {
  NULL,			/* lseek - default */
  uvfs_dir_read,	/* read */
  NULL,			/* write - bad */
  uvfs_readdir,		/* readdir */
  NULL,			/* poll - default */
  NULL,			/* ioctl - default */
  NULL,			/* mmap */
  NULL,			/* no special open code */
  NULL,			/* flush */
  NULL,			/* no special release code */
  file_fsync		/* default fsync */
};

struct inode_operations uvfs_dir_inode_operations = {
  &uvfs_dir_operations,	/* default directory file-ops */
  uvfs_create,		/* create */
  uvfs_lookup,		/* lookup */
  uvfs_link,		/* link */
  uvfs_unlink,		/* unlink */
  uvfs_symlink,		/* symlink */
  uvfs_mkdir,		/* mkdir */
  uvfs_rmdir,		/* rmdir */
  NULL,		        /* mknod */
  uvfs_rename,		/* rename */
  NULL,			/* readlink */
  NULL,			/* follow_link */
  NULL,			/* readpage */
  NULL,			/* writepage */
  NULL,			/* bmap */
  NULL,			/* truncate */
  NULL			/* permission */
};
