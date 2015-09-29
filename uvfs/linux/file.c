/* $Id: file.c,v 1.2 1999/10/02 20:06:58 cblake Exp $ */

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

#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/stat.h>
#include <linux/locks.h>
#include <linux/mm.h>
#include <linux/pagemap.h>

#include <asm/uaccess.h>
#include <asm/system.h>

#define	NBUF	32

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

#include <linux/fs.h>

static ssize_t uvfs_file_read(struct file * filp, char * buf,
	                      size_t count, loff_t * ppos)
{
    warn ("uvfs_file_read()\n");
    return 0;
}

static ssize_t uvfs_file_write(struct file * filp, const char * buf,
				size_t count, loff_t *ppos)
{
    warn ("uvfs_file_write()\n");
    return 0;
}

static int uvfs_sync_file(struct file * file, struct dentry *dentry)
{
    warn ("uvfs_sync_file()\n");
    return 0;
}

static int uvfs_bmap(struct inode * inode,int block)
{
    warn ("uvfs_bmap()\n");
    return 0;
}

static void uvfs_truncate(struct inode * inode)
{
    warn ("uvfs_truncate()\n");
}

static struct file_operations uvfs_file_operations = {
	NULL,			/* lseek - default */
	uvfs_file_read,		/* read */
	uvfs_file_write,	/* write */
	NULL,			/* readdir - bad */
	NULL,			/* poll - default */
	NULL,			/* ioctl - default */
	generic_file_mmap,	/* mmap */
	NULL,			/* no special open is needed */
	NULL,			/* flush */
	NULL,			/* release */
	uvfs_sync_file		/* fsync */
};

struct inode_operations uvfs_file_inode_operations = {
	&uvfs_file_operations,	/* default file operations */
	NULL,			/* create */
	NULL,			/* lookup */
	NULL,			/* link */
	NULL,			/* unlink */
	NULL,			/* symlink */
	NULL,			/* mkdir */
	NULL,			/* rmdir */
	NULL,			/* mknod */
	NULL,			/* rename */
	NULL,			/* readlink */
	NULL,			/* follow_link */
	generic_readpage,	/* readpage */
	NULL,			/* writepage */
	uvfs_bmap,		/* bmap */
	uvfs_truncate,		/* truncate */
	NULL			/* permission */
};
