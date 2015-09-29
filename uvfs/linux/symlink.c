#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/stat.h>
/* #include <linux/mm.h> */
/* #include <linux/malloc.h> */
#include <linux/string.h>
#include <asm/uaccess.h>

#include "uvfs_kern.h"

static int uvfs_readlink(struct dentry *dentry, char *buffer, int buflen)
{
  uvfs_fh          arg;
  uvfs_readlinkres res;
  uvfs_node       *unp = ITOUVFS(dentry->d_inode);
  int              error;

  MAYBEWARN ("uvfs_readlink()\n");
  if (!S_ISLNK(dentry->d_inode->i_mode))
    return -EINVAL;
  bzero (&arg, sizeof(arg));
  bzero (&res, sizeof(res));
  arg = unp->fh;
  error = -krpc_callit (ITORPCQ(dentry->d_inode), &uvfsprog_1,
			UVFSPROC_READLINK, &arg, &res);
  if (!error && res.status != 0)
    error = res.status;
  if (!error) {
    int len = strlen (res.u.resok.data);
    if (len > buflen)
      len = buflen;
    copy_to_user(buffer, res.u.resok.data, len);
    error = len;
  }
  xdr_free (xdr_uvfs_readlinkres, &res);
  return error;
}

static struct dentry *
uvfs_follow_link(struct dentry * dentry, struct dentry *base, unsigned int follow)
{
  unsigned int     len;
  char            *path;
  struct dentry   *result;
  int              error;
  uvfs_fh          arg;
  uvfs_readlinkres res;
  uvfs_node       *unp = ITOUVFS(dentry->d_inode);

  MAYBEWARN ("uvfs_follow_link: entered\n");
  if (!S_ISLNK(dentry->d_inode->i_mode))
    return NULL;
  bzero (&arg, sizeof(arg));
  bzero (&res, sizeof(res));
  arg = unp->fh;
  error = -krpc_callit (ITORPCQ(dentry->d_inode), &uvfsprog_1,
			UVFSPROC_READLINK, &arg, &res);
  if (!error && res.status != 0)
    error = res.status;
  if (error) {
    dput(base);
    return ERR_PTR(-error);
  }
  len = strlen(res.u.resok.data) + 1;	/* better be NUL-term! */
  if (!(path = kmalloc(len, GFP_KERNEL))) {
    dput(base);
    return ERR_PTR(-ENOMEM);
  }
  memcpy(path, res.u.resok.data, len);
  result = lookup_dentry(path, base, follow);
  kfree(path);
  return result;
}

struct inode_operations uvfs_symlink_inode_operations = {
	NULL,			/* no file-operations */
	NULL,			/* create */
	NULL,			/* lookup */
	NULL,			/* link */
	NULL,			/* unlink */
	NULL,			/* symlink */
	NULL,			/* mkdir */
	NULL,			/* rmdir */
	NULL,			/* mknod */
	NULL,			/* rename */
	uvfs_readlink,		/* readlink */
	uvfs_follow_link,	/* follow_link */
	NULL,			/* readpage */
	NULL,			/* writepage */
	NULL,			/* bmap */
	NULL,			/* truncate */
	NULL			/* permission */
};
