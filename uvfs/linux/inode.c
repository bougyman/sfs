/* $Id: inode.c,v 1.3 1999/10/02 20:06:58 cblake Exp $ */

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

#define UVFS_DEBUG_FS 1

#include "uvfs_kern.h"
#include <linux/locks.h>
#include "attr.h"

struct super_operations uvfs_super_ops;

int
uvfs_newinode (struct super_block *sb, struct inode **ipp, unsigned long fh,
               unsigned long ino)
{
  struct inode *ip;

  ip = iget (sb, ino);
  if (ip == NULL)
    return -ENOMEM;
  ITOUVFS(ip) = xmalloc (sizeof (uvfs_node));
  if (ITOUVFS(ip) == NULL)
    return -ENOMEM;
  ITOUVFS(ip)->uvfslockf = NULL;
  ITOUVFS(ip)->uvfsinode = ip;
  ITOUVFS(ip)->fh = fh;
  *ipp = ip;
  return 0;
}

int
uvfs_filledinode (struct super_block *sb, struct inode **ipp, 
		  unsigned long fh, uvfs_fattr *fattr_arg)
{
  uvfs_fattr fattr;

  if (!fattr_arg)
    uvfs_getattr (fh, sb, &fattr);
  else
    fattr = *fattr_arg;
  if (uvfs_newinode (sb, ipp, fh, fattr.fileid)) {
    return ENOMEM;
  }
  /*       attr_cache_update (&fattr, vp); */
  fattr2inode (&fattr, *ipp);
  if (S_ISDIR ((*ipp)->i_mode))
    (*ipp)->i_op = &uvfs_dir_inode_operations;
  else if (S_ISLNK ((*ipp)->i_mode))
    (*ipp)->i_op = &uvfs_symlink_inode_operations;
  else
    (*ipp)->i_op = &uvfs_file_inode_operations;

  return 0;
}

static struct super_block *
uvfs_read_super (struct super_block *sb, void *data, int silent)
{
  struct uvfs_args *args = (struct uvfs_args *) data;
  struct inode *root_inode;
  uvfs_mntpt *mntpt;
  int i, error;
  uvfs_fattr fattr;

  MOD_INC_USE_COUNT;
  MAYBEWARN ("uvfs_read_super: \n");

  if (!args) {
    MAYBEWARN ("uvfs_read_super: missing data arguments to mount\n");
    sb->s_dev = 0;
    MOD_DEC_USE_COUNT;
    return NULL;
  }
  MAYBEWARN ("uvfs_read_super: args->uvfs_dev = %u; args->uvfs_root_fh = %u\n",
	     args->uvfs_dev, args->uvfs_root_fh);

  if ((size_t) args->uvfs_dev >= NUVFS) {
    MAYBEWARN ("uvfs_read_super: uvfs device minor number out of range\n");
    sb->s_dev = 0;
    MOD_DEC_USE_COUNT;
    return NULL;
  }

/*   if (mp->mnt_flag & MNT_UPDATE) */
/*     return EOPNOTSUPP; */
/*   mp->mnt_flag |= MNT_NOSUID | MNT_NODEV; */

  lock_super (sb);

  sb->s_magic = VT_UVFS;
  sb->s_op = &uvfs_super_ops;
  sb->s_blocksize = 1024;	/* XXX: Is this OK? */
  sb->s_blocksize_bits = 10;	/* XXX: Is this OK? */

  mntpt = xmalloc (sizeof (uvfs_mntpt));
  if (mntpt == NULL) {
    MAYBEWARN ("uvfs_read_super: couldn't allocate mntpt struct\n");
    sb->s_dev = 0;
    unlock_super (sb);
    MOD_DEC_USE_COUNT;
    return NULL;
  }

  SBTOUVFS(sb) = (void *) mntpt;
  mntpt->rpcqp = &uvfs_state[args->uvfs_dev].rpcq;
  for (i = 0; i < UNTSIZE; i++) {
    LIST_INIT(&mntpt->uvfs_node_tab[i]);
  }

  uvfs_getattr (args->uvfs_root_fh, sb, &fattr);
  error = uvfs_newinode (sb, &root_inode, args->uvfs_root_fh, fattr.fileid);
  if (error) {
    MAYBEWARN ("uvfs_read_super: couldn't get root inode\n");
    xfree (mntpt);
    sb->s_dev = 0;
    unlock_super (sb);
    MOD_DEC_USE_COUNT;
    return NULL;
  }
  fattr2inode (&fattr, root_inode);
  root_inode->i_op = &uvfs_dir_inode_operations;
  mntpt->root = root_inode;

  sb->s_root = d_alloc_root (mntpt->root, NULL);
  if (!sb->s_root) {
    MAYBEWARN ("uvfs_read_super: couldn't allocate root dentry\n");
    iput (mntpt->root);
    xfree (mntpt);
    sb->s_dev = 0;
    unlock_super (sb);
    MOD_DEC_USE_COUNT;
    return NULL;
  }
  sb->s_root->d_op = &uvfs_dentry_operations;

  unlock_super (sb);
  return sb;
}

static void
uvfs_put_super (struct super_block *sb)
{
  uvfs_mntpt *mntpt = SBTOUVFS(sb);

  MAYBEWARN ("uvfs_umount: \n");
/*  lock_super (sb);
  sb->s_dev = 0;
  unlock_super (sb); */
  xfree (mntpt);
  MOD_DEC_USE_COUNT;
  MAYBEWARN ("uvfs_umount: done.\n");
  return;
}

static int
uvfs_statfs (struct super_block *sb, struct statfs *buf,
	     int bufsiz)
{
  struct statfs  tmp;
  uvfs_fh        arg = 0;	/* unused on other side of RPC */
  uvfs_statfsres res;
  int            error = 0;

  MAYBEWARN ("uvfs_statfs: \n");
  bzero (&res, sizeof res);
  bzero (&tmp, sizeof tmp);
  error = krpc_callit (SBTOUVFS(sb)->rpcqp, &uvfsprog_1,
                       UVFSPROC_STATFS, &arg, &res);
  if (error) {
    MAYBEWARN ("statfs: RPC error = %d\n", error);
    goto end;
  }
  if (res.status) {
    error = res.status;
    MAYBEWARN ("statfs: RPC result error = %d\n", error);
    goto end;
  } 
  tmp.f_type   = sb->s_magic;
  tmp.f_bsize  = sb->s_blocksize;
  tmp.f_blocks = res.u.resok.tbytes / tmp.f_bsize;
  tmp.f_bfree  = res.u.resok.fbytes / tmp.f_bsize;
  tmp.f_bavail = res.u.resok.abytes / tmp.f_bsize;
  tmp.f_files  = res.u.resok.tfiles;
  tmp.f_ffree  = res.u.resok.ffiles;
  tmp.f_namelen = NAME_MAX;
  error = copy_to_user (buf, &tmp, bufsiz);
end:
  MAYBEWARN ("statfs: error = %d\n", error);
  xdr_free (xdr_uvfs_statfsres, &res);
  if (error)
    return -EFAULT;
  else
    return 0;
}

static void 
uvfs_read_inode (struct inode *ip)
{
  return;
}

struct file_system_type uvfs_fs_type = {
  MOUNT_UVFS,
  0,
  uvfs_read_super,
  NULL
};

struct super_operations uvfs_super_ops = {
  uvfs_read_inode,		/* read_inode */
  NULL,				/* write_inode */
  NULL,				/* put_inode */
  NULL,				/* delete_indo */
  NULL,				/* notify_change */
  uvfs_put_super,
  NULL,				/* write_super */
  uvfs_statfs,
  NULL,
  NULL,
  NULL
};
