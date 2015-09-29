/* -*- Mode: c -*- */
/* $Id: uvfs_prot.x,v 1.15 1999/10/05 16:45:13 dm Exp $ */

/*
 * User level VFS driver (protocol spec)
 * Copyright 1999 Michael Kaminsky <kaminsky@lcs.mit.edu>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project (for instance by leaving this copyright notice
 * intact).
 */

%#include "nfs3exp_prot.h"

#ifdef SFSSVC
struct uvfs_fh {
  opaque data<NFS3_FHSIZE>;
};

%inline bool
%rpc_traverse (XDR *xdrs, uvfs_fh &fh)
%{
%  switch (xdrs->x_op) {
%  case XDR_ENCODE:
%    if (fh.data.size () != 4)
%      return false;
%    return XDR_PUTBYTES (xdrs, fh.data.base (), 4);
%  case XDR_DECODE:
%    fh.data.setsize (4);
%    return XDR_GETBYTES (xdrs, fh.data.base (), 4);
%  default:
%    return true;
%  }
%}

#else /* !SFSSVC */
typedef u_int32_t uvfs_fh;
#endif /* SFSSVC */

typedef ex_fattr3 uvfs_fattr;
typedef ex_getattr3res uvfs_attrres;
typedef ex_wccstat3 uvfs_wccstat;
typedef ex_access3res uvfs_accessres;
typedef ex_readlink3res uvfs_readlinkres;
typedef ex_read3res uvfs_readres;
typedef ex_write3res uvfs_writeres;
typedef ex_rename3res uvfs_renameres;
typedef ex_link3res uvfs_linkres;
typedef ex_fsstat3res uvfs_statfsres;
typedef ex_commit3res uvfs_commitres;

typedef filename3 uvfs_filename;
typedef nfspath3 uvfs_pathname;
typedef nfstime3 uvfs_time;
typedef sattr3 uvfs_sattr;
typedef sattrguard3 uvfs_guard;

typedef int uvfsstat;

struct uvfs_readdirargs {
  uvfs_fh dir;			/* directory handle */
  u_int64_t cookie;
  u_int32_t count;		/* number of directory bytes to read */
};

struct uvfs_direntry {
  u_int64_t fileid;
  u_int64_t cookie;
  u_int32_t type;
  uvfs_filename name;
};

struct uvfs_dirlist {
  uvfs_direntry entries<>;
  bool eof;
};

union uvfs_readdirres switch (uvfsstat status) {
 case 0:
   uvfs_dirlist reply;
 default:
   void;
};

struct uvfs_setattrargs {
  uvfs_fh file;
  uvfs_sattr attributes;
  uvfs_guard guard;
};


union post_op_uvfs_fh switch (bool present) {
 case TRUE:
  uvfs_fh handle;
 case FALSE:
   void;
};

struct uvfs_diropargs {
  uvfs_fh dir;
  uvfs_filename name;
};

struct uvfs_diropresok {
  post_op_uvfs_fh file;
  ex_post_op_attr attributes;
  ex_wcc_data dir_wcc;
};

union uvfs_diropres switch (uvfsstat status) {
 case 0:
   uvfs_diropresok resok;
 default:
   wcc_data resfail;
};

struct uvfs_readargs {
  uvfs_fh file;
  u_int64_t offset;
  u_int32_t count;
};

struct uvfs_writeargs {
  uvfs_fh file;
  u_int64_t offset;
  u_int32_t count;
  stable_how stable;
  opaque data<>;
};

struct uvfs_createargs {
  uvfs_diropargs where;
  createhow3 how;
};

struct uvfs_mkdirargs {
  uvfs_diropargs where;
  uvfs_sattr attributes;
};

struct uvfs_renameargs {
  uvfs_diropargs from;
  uvfs_diropargs to;
};

struct uvfs_commitargs {
  uvfs_fh file;
  u_int64_t offset;
  u_int32_t count;
};

struct uvfs_linkargs {
  uvfs_fh from;
  uvfs_diropargs to;
};

struct uvfs_symlinkargs {
  uvfs_diropargs where;
  symlinkdata3 symlink;
};

struct uvfs_accessargs {
  uvfs_fh object;
  u_int32_t access;
};

struct uvfs_lookupresok {
  uvfs_fh object;
  ex_post_op_attr obj_attributes;
  ex_post_op_attr dir_attributes;
};

union uvfs_lookupres switch (uvfsstat status) {
 case 0:
   uvfs_lookupresok resok;
 default:
   ex_post_op_attr resfail;	/* Directory attributes */
};

program UVFSPROG {
  version UVFSVER {
    void UVFSPROC_NULL (void) = 0;
    uvfs_attrres UVFSPROC_GETATTR (uvfs_fh) = 1;
    uvfs_wccstat UVFSPROC_SETATTR (uvfs_setattrargs) = 2;
    uvfs_lookupres UVFSPROC_LOOKUP (uvfs_diropargs) = 3;
    uvfs_accessres UVFSPROC_ACCESS (uvfs_accessargs) = 4;
    uvfs_readlinkres UVFSPROC_READLINK (uvfs_fh) = 5;
    uvfs_readres UVFSPROC_READ (uvfs_readargs) = 6;
    uvfs_writeres UVFSPROC_WRITE (uvfs_writeargs) = 7;
    uvfs_diropres UVFSPROC_CREATE (uvfs_createargs) = 8;
    uvfs_diropres UVFSPROC_MKDIR (uvfs_mkdirargs) = 9;
    uvfs_diropres UVFSPROC_SYMLINK (uvfs_symlinkargs) = 10;
    void UVFSPROC_MKNOD (void) = 11;
    uvfs_wccstat UVFSPROC_REMOVE (uvfs_diropargs) = 12;
    uvfs_wccstat UVFSPROC_RMDIR (uvfs_diropargs) = 13;
    uvfs_renameres UVFSPROC_RENAME (uvfs_renameargs) = 14;
    uvfs_linkres UVFSPROC_LINK (uvfs_linkargs) = 15;
    uvfs_readdirres UVFSPROC_READDIR (uvfs_readdirargs) = 16;
    void UVFSPROC_READDIRPLUS (void) = 17;
    uvfs_statfsres UVFSPROC_STATFS (uvfs_fh) = 18;
    void UVFSPROC_FSINFO (void) = 19;
    void UVFSPROC_PATHCONF (void) = 20;
    uvfs_commitres UVFSPROC_COMMIT (uvfs_commitargs) = 21;
    uvfsstat UVFSPROC_OPEN (uvfs_fh) = 22;
    uvfsstat UVFSPROC_CLOSE (uvfs_fh) = 23;
    uvfsstat UVFSPROC_INACTIVE (uvfs_fh) = 24;
    uvfsstat UVFSPROC_RECLAIM (uvfs_fh) = 25;
  } = 1;
} = 0x20000001;

struct uvfs_invalidateargs {
  uvfs_fh handle;
  ex_post_op_attr attributes;
};

program UVFSCBPROG {
  version UVFSCBVER {
    void UVFSCBPROC_NULL (void) = 0;
    void UVFSCBPROC_INVALIDATE (uvfs_invalidateargs) = 1;
  } = 1;
} = 0x20000002;
