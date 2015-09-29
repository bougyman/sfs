/* $Id: uvfs.h,v 1.6 1999/01/19 20:15:15 kaminsky Exp $ */

/*
 * User level VFS driver
 * Copyright 1999 Michael Kaminsky <kaminsky@lcs.mit.edu>.
 * Copyright 1998 David Mazieres <dm@uun.org>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project (for instance by leaving this copyright notice
 * intact).
 */

#ifndef _UVFS_H_
#define _UVFS_H_ 1

#if !defined (_KERNEL) && !defined (__KERNEL__)

#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/param.h>

#ifndef export
# ifdef __cplusplus
#  define export fsexport
# endif /* __cplusplus */
# include <sys/mount.h>
# undef export
#else /* !export */
# include <sys/mount.h>
#endif /* !export */

#endif /*! _KERNEL && ! __KERNEL__ */

typedef u_int uvfs_mount_fh;
#define MOUNT_UVFS "uvfs"

struct uvfs_args {
  u_int uvfs_dev;
  uvfs_mount_fh uvfs_root_fh;
};

#endif /* !_UVFS_H_ */
