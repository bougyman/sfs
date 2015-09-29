/* $Id: uvfs_init.c,v 1.6 1999/01/18 20:37:20 kaminsky Exp $ */

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

EXPORT_NO_SYMBOLS;

char kernel_version[] = UTS_RELEASE;

unsigned int dev_major_num = 0;

int
init_module (void)
{
  int result;

  warn ("uvfs: initializing module.\n");

  result = register_chrdev (0, "uvfs", &uvfs_dev_fops);
  if (result < 0) {
    warn ("uvfs: can't allocate a major device number.\n");
    return result;
  }
  dev_major_num = result;

  uvfs_dev_init ();

  result = register_filesystem (&uvfs_fs_type);
  if (result < 0) {
    warn ("uvfs: can't register filesystem.\n");
    unregister_chrdev (dev_major_num, "uvfs");
    return result;
  }

  return 0;
}

void
cleanup_module (void)
{
  warn ("uvfs: deinitializing module.\n");

  unregister_chrdev (dev_major_num, "uvfs");
  unregister_filesystem (&uvfs_fs_type);
}
