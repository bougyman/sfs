/* $Id: uvfs_kern.h,v 1.6 1999/10/02 20:06:58 cblake Exp $ */

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

#ifndef _UVFS_LINUX_UVFS_KERN_H_
#define _UVFS_LINUX_UVFS_KERN_H_ 1

#define __NO_VERSION__		/* don't define kernel_version in module.h */
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/poll.h>
#include <linux/errno.h>

#undef LIST_HEAD		/* Linux's list.h conflict with queue.h */
#include "arpc.h"
#undef NFS_PROGRAM
#include "uvfs_prot.h"
#include "../uvfs.h"

/* uvfs device driver */

#define NUVFS 16
extern struct uvfs_softc uvfs_state[NUVFS];
extern struct file_operations uvfs_dev_fops;

typedef struct uvfs_softc {
  char busy;
  u_int flags;
#if 0
#define UVFS_RSEL 1		/* someone is selecting for reading */
  struct selinfo sel;
#endif
  struct wait_queue *inq, *outq;
  struct uio *uuio;
  krpcq rpcq;
} uvfs_softc;

void uvfs_dev_init (void);
int uvfs_dev_busy (void);

#define FILETOMINOR(fp) (MINOR (fp->f_dentry->d_inode->i_rdev))
#define FILETOKDEV(fp) (fp->f_dentry->d_inode->i_rdev)

/* uvfs filesystem */

#define UNTSIZE 31
extern struct file_system_type uvfs_fs_type;
extern struct inode_operations uvfs_dir_inode_operations;
extern struct file_operations uvfs_dir_operations;
extern struct dentry_operations uvfs_dentry_operations;
extern struct file_operations uvfs_file_operations;
extern struct inode_operations uvfs_file_inode_operations;
extern struct inode_operations uvfs_symlink_inode_operations;

typedef struct uvfs_node {
  uvfs_fh fh;
  struct inode *uvfsinode;
  struct lockf *uvfslockf;
  LIST_ENTRY (uvfs_node) entries;
} uvfs_node;
LIST_HEAD (uvfs_node_list, uvfs_node);

typedef struct uvfs_mntpt {
  struct inode *root;
  krpcq *rpcqp;
  struct uvfs_node_list uvfs_node_tab[UNTSIZE];
} uvfs_mntpt;

#define VT_UVFS 0x137

#define SBTOUVFS(sb) ((struct uvfs_mntpt *)((sb)->u.generic_sbp))
#define ITOUVFS(ip) ((struct uvfs_node *)(ip)->u.generic_ip)
#define ITORPCQ(ip) (SBTOUVFS(ip->i_sb)->rpcqp)
#define SBTORPCQ(sb) (SBTOUVFS(sb)->rpcqp)

#if 0

#define UIO_MX 32
#define DIR_MODE (S_IRUSR|S_IWUSR|S_IXUSR|\
                  S_IRGRP|S_IWGRP|S_IXGRP|\
                  S_IROTH|S_IWOTH|S_IXOTH)
#define FILE_MODE (S_IRUSR|S_IWUSR|\
                   S_IRGRP|S_IWGRP|\
                   S_IROTH|S_IWOTH)

int uvfs_newvnode (struct mount *, struct vnode **);
void uvfsnode_remove (struct uvfs_node *);
void uvfsnode_insert (struct mount *, struct uvfs_node *);

#define VTORPCQ(vp) ((VFSTOUVFS((vp)->v_mount))->rpcqp)

#endif
#ifdef DEBUG
#define MAYBEWARN warn
#else
#define MAYBEWARN (void)
#endif

int
uvfs_newinode (struct super_block *sb, struct inode **ipp, unsigned long fh,
               unsigned long ino);
int
uvfs_filledinode (struct super_block *sb, struct inode **ipp, 
		  unsigned long fh, uvfs_fattr *fattr_arg);

#endif /* _UVFS_LINUX_UVFS_KERN_H_ */
