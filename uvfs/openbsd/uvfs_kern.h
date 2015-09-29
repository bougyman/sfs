/* $Id: uvfs_kern.h,v 1.24 1999/02/08 21:18:33 kaminsky Exp $ */

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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/exec.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/uio.h>
#include <sys/select.h>
#include <sys/fcntl.h>
#include <sys/filio.h>
#include <sys/ucred.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/dirent.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/namei.h>
#include <sys/lockf.h>
#include <sys/time.h>

#include "arpc.h"
#include "uvfs_prot.h"
#include "../uvfs.h"

#define VT_UVFS 0x137

#define NUVFS 16

#define UNTSIZE 31

#define ATTR_CACHE_TIMEOUT 60
#define NAME_CACHE_TIMEOUT 60

extern struct timeval time;     /* kernel time variable */

extern int (**uvfs_vnodeop_p) (void *);
extern struct vfsops uvfs_vfsops;
extern struct vnodeopv_desc uvfs_vnodeop_opv_desc;

#define UVFS_FABLKSIZE 512
#define UIO_MX 32
#if 0
#define FILE_MODE (S_IRUSR|S_IWUSR|\
                   S_IRGRP|S_IWGRP|\
                   S_IROTH|S_IWOTH)
#endif
#define DIR_MODE (S_IRUSR|S_IWUSR|S_IXUSR|\
                  S_IRGRP|S_IWGRP|S_IXGRP|\
                  S_IROTH|S_IWOTH|S_IXOTH)

typedef struct uvfs_softc {
  char busy;
  u_int flags;
#define UVFS_RSEL 1		/* someone is selecting for reading */
  struct selinfo sel;
  struct uio *uuio;
  krpcq rpcq;
} uvfs_softc;

typedef struct uvfs_node {
  uvfs_fh fh;
  struct timeval vap_expires;
  struct vattr vap;
  struct vnode *uvfsvnode;
  struct lockf *uvfslockf;
  LIST_ENTRY (uvfs_node) entries;
} uvfs_node;
LIST_HEAD (uvfs_node_list, uvfs_node);

typedef struct uvfs_mntpt {
  struct vnode *root;
  krpcq *rpcqp;
  struct uvfs_node_list uvfs_node_tab[UNTSIZE];
} uvfs_mntpt;


extern struct uvfs_softc uvfs_state[NUVFS];
extern struct cdevsw uvfs_cdevsw;

void uvfs_dev_init (void);
int uvfs_dev_busy (void);

int uvfs_newvnode (struct mount *, struct vnode **);
void uvfsnode_remove (struct uvfs_node *);
void uvfsnode_insert (struct mount *, struct uvfs_node *);

#define VFSTOUVFS(mp) ((struct uvfs_mntpt *)((mp)->mnt_data))
#define VTOUVFS(vp) ((struct uvfs_node *)(vp)->v_data)
#define VTORPCQ(vp) ((VFSTOUVFS((vp)->v_mount))->rpcqp)
