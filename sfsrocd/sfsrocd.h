// -*-c++-*-
/* $Id: sfsrocd.h,v 1.39 2004/09/15 21:12:50 fubob Exp $ */

/*
 *
 * Copyright (C) 2000, 2001 Kevin Fu (fubob@mit.edu)
 * Copyright (C) 1998, 2000 David Mazieres (dm@uun.org)
 * Copyright (C) 1999 Frans Kaashoek (kaashoek@mit.edu)
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

#ifndef _SFSROCD_H_
#define _SFSROCD_H_ 1

#include "arpc.h"
#include "nfs3_prot.h"
#include "sfscd_prot.h"
#include "sfsmisc.h"
#include "sfsro_prot.h"
#include "qhash.h"
#include "itree.h"
#include "crypt.h"
#include "list.h"
#include "sfsclient.h"
#include "nfstrans.h"
#include "cache.h"
#include "qhash.h"
#include "keyregression.h"

#define MAINTAINER 1

// Profiling for development

struct cache_stat {
  u_int32_t namec_hit;
  u_int32_t namec_miss;
  u_int32_t namec_tot;

  u_int32_t directoryc_hit;
  u_int32_t directoryc_miss;
  u_int32_t directoryc_tot;

  u_int32_t iblockc_hit;
  u_int32_t iblockc_miss;
  u_int32_t iblockc_tot;

  u_int32_t blockc_hit;
  u_int32_t blockc_miss;
  u_int32_t blockc_tot;
};

extern cache_stat cstat;

#ifdef MAINTAINER
extern const bool sfsrocd_noverify;
extern const bool sfsrocd_nocache;
extern const bool sfsrocd_cache_stat;
extern const bool sfsrocd_proxylocal;
extern const bool sfsrocd_proxymaster;
#else /* !MAINTAINER */
enum { sfsrocd_noverify = 0, sfsrocd_nocache = 0, sfsrocd_cache_stat = 0,
       sfsrocd_proxylocal = 0, sfsrocd_proxymaster = 0 };
#endif /* !MAINTAINER */

extern str gk_directory;

class filesys;

typedef callback<void, ref<const nfs_fh3> >::ref cb_nfs_fh3_t;
typedef callback<void, ref<const fattr3> >::ref cb_fattr3_t;
typedef callback<void, str >::ref cb_str_t;
typedef callback<void, ref<const sfsro_data> >::ref cb_sfsro_data_t;
typedef callback<void, ref<const sfsro_inode> >::ref cb_sfsro_inode_t;
typedef callback<void, ptr<const sfsro_directory> >::ref cb_sfsro_directory_t;
typedef 
  callback<void, ref<const rpc_bytes<RPC_INFINITY> > >::ref cb_rpc_bytes_t;
typedef callback<void, ref<const sfsro_indirect> >::ref cb_sfsro_indirect_t;
typedef callback<void, ptr<const sfs_hash> >::ref cb_ptr_sfs_hash_t;
typedef callback<void, ref<const sfs_hash> >::ref cb_sfs_hash_t;


// callbacks that include NFS error conditions
#if 0
typedef
  callback<void, ptr<const nfs_fh3>, nfsstat3 stat>::ref cb_stat_nfs_fh3_t;
typedef 
  callback<void, ptr<const fattr3>, nfsstat3 stat>::ref cb_stat_fattr3_t;
#endif


/* Rep invariant: no name cache entry can have a partially
   filled name_dat.  The fh, ip, and fa must be set before
   adding to cache */
struct name_dat {
  const ref<const sfs_hash> fh;
  ref<const sfsro_inode> ip;
  ref<const fattr3> fa;

  name_dat (const ref<const sfs_hash> fhfh,
	    ref<const sfsro_inode> ipip,
	    ref<const fattr3> fafa)
    : fh (fhfh), ip (ipip), fa (fafa)
  { }

};

typedef callback<void, ref<name_dat> >::ref cb_ref_name_dat_t;
typedef callback<void, ptr<name_dat> >::ref cb_ptr_name_dat_t;

/* SFSRO directory info */
struct dir_dat {
  ref<const cookieverf3> cookieverf;
  ref<const dirlist3> reply;
  ref<name_dat> nd;

  dir_dat (ref<const cookieverf3> cv, ref<const dirlist3> dl,
	   ref<name_dat> ndnd) 
    : cookieverf (cv), reply (dl), nd (ndnd) { }
};

typedef callback<void, ptr<const dir_dat> >::ref cb_dir_dat_t;

struct qhash_nnstr_ret {
  typedef str type;
  typedef str const_type;
  static type ret (str *v) { return v ? *v : str (NULL); }
  static const_type const_ret (const str *v) { return v ? *v : str (NULL); }
};


// Name cache maps pathnames to name_dat
typedef cache<str, ref<name_dat>, 512> namec_t;

/* FH translation table
   Note for fhtt, we use a qhash_nnstr_ret so that
     we can return str's rather than str *'s from the lookup.
     useful for anything refcounted.
 */
typedef qhash<nfs_fh3, str, hashfn<nfs_fh3>,  
  equals<nfs_fh3>, qhash_nnstr_ret> fhtt_t;


class getdata {
  /* 

     Functions that communicate directly with SFSRO servers.
     Should only be called from the filesys class

     Representation: SFSRO file handles and SFSRO blocks of raw data

  */
public:
  getdata (ref<sfsro_public> fsinfo, ref<aclnt> sfsroc, filename3 sname,
	   ptr<keyregression> _kr) 
    : fsi (fsinfo), sfsroc (sfsroc),
      sname (sname), kr (_kr)
  { 
    memcpy (IV, fsi->iv.base (), SFSRO_IVSIZE);
  }

  /* Request blocks from SFSRO server and verify integrity */
  void fetch (cb_sfsro_data_t cb, ref<const sfs_hash> fh);

private:
  ref<sfsro_public> fsi;
  ptr<aclnt> sfsroc;
  filename3 sname;
  ptr<keyregression> kr;
  //  ptr<sfsro_group_key> gk;

  // IV to modify the message space such that if a particular collision
  // is found for SHA1, this does not necessary imply a collision in SFSRO.
  // Our IV is the ASCII hostID.
  char IV[SFSRO_IVSIZE];

  void fetch1 (cb_sfsro_data_t cb, ref<const sfs_hash> fh, 
		 sfsro_datares *res, clnt_stat err);

  void fetch2 (cb_sfsro_data_t cb, ref<const sfs_hash> fh,
	       ref<sfsro_data> data,
	       sfsro_proxyreenc *res, clnt_stat err);

};


class filesys {
  /*
    
    Functions to convert raw SFSRO blocks into data structures
    like directories, file blocks, inodes, and indirect blocks.

    Representation: SFSRO structures and SFSRO file handles.
    
  */

public:
  filesys (ref<sfsro_public> fsinfo, ref<aclnt> sfsroc, filename3 sname,
	   ptr<keyregression> kr)
    : fsi (fsinfo) 
  {
    gd = New refcounted<getdata> (fsinfo, sfsroc, sname, kr);
  }

  inline void getdirectory (cb_sfsro_directory_t cb, ptr<const sfs_hash> fh);
  inline void getfiledata (cb_rpc_bytes_t cb, ptr<const sfs_hash> fh);
  inline void getinode (cb_sfsro_inode_t cb, ptr<const sfs_hash> fh);
  inline void getindir (cb_sfsro_indirect_t cb, ptr<const sfs_hash> fh);

  /* given a file's inode, return the b'th block or NULL if not exist */
  void getblock (cb_ptr_sfs_hash_t cb, ref<const sfsro_inode> ip, uint64 b);


private:
  ref<sfsro_public> fsi;
  ptr<getdata> gd;


  cache<sfs_hash, ref<const sfsro_indirect>, 512> 
  iblockc;    // Indirect block cache

  cache<sfs_hash, ref<const sfsro_directory>, 512> 
  directoryc; // Directory block cache

  cache<sfs_hash, ref<const rpc_bytes<RPC_INFINITY> >, 64> 
  blockc;    // file data buffer cache


  void getdirectory1 (cb_sfsro_directory_t cb, ref<const sfs_hash> fh, 
		      ref<const sfsro_data> data);
  void getfiledata1 (cb_rpc_bytes_t cb, ref<const sfs_hash> fh, 
		     ref<const sfsro_data> data);
  void getinode1 (cb_sfsro_inode_t cb, ref<const sfs_hash> fh, 
		  ref<const sfsro_data> data);
  void getindir1 (cb_sfsro_indirect_t cb, ref<const sfs_hash> fh, 
		  ref<const sfsro_data> data);


  void single_indirectres (cb_ptr_sfs_hash_t cb, size_t i, 
			   ref<const sfsro_inode> ip,
			   ref<const sfsro_indirect> indirect);
  void double_indirectres (cb_ptr_sfs_hash_t cb, size_t i, 
			   ref<const sfsro_inode> ip,
			   ref<const sfsro_indirect> indirect);
  void triple_indirectres (cb_ptr_sfs_hash_t cb, size_t i,
			   ref<const sfsro_inode> ip,
			   ref<const sfsro_indirect> indirect);

};


class pathtrans {
  /* Functions to converts pathnames (the file handle
     representation internal to the "server" class) to 
     inodes and NFS file handles.

     Is called only by self and functions in server class.
  */

public:
  pathtrans (ref<fhtt_t> fhttfhtt, ref<namec_t> namecnamec,
	     ref<filesys> fsfs, ref<const sfs_hash> fh,
	     ref<sfs_hash> id)
    : fhtt (fhttfhtt), namec (namecnamec), fs (fsfs), rootrofh (fh),
      id (id)
  {
    //    rnd.getbytes (nfs_fh3_IV, SFSRO_IVSIZE);
    // for debugging, use a constant IV for now.
    bzero (nfs_fh3_IV, SFSRO_IVSIZE);

  }

  void nd (cb_ptr_name_dat_t cb, str file_path);
  void nfsfh (nfs_fh3 *nfh, str file_path);
  void lookup (cb_ptr_name_dat_t cb, ptr<name_dat> dir_nd, 
	       str dir_path, str filename);    


private:
  ref<fhtt_t> fhtt; 
  ref<namec_t> namec;
  ref<filesys> fs;
  ref<const sfs_hash> rootrofh;
  ref<sfs_hash> id;

  char nfs_fh3_IV[SFSRO_IVSIZE];

  void add_entry (cb_ptr_name_dat_t cb, 
		  str file_path,
		  ref<const sfs_hash> fh,
		  ref<const sfsro_inode> ip);

  void nd1 (cb_ptr_name_dat_t cb, ref<vec<str> > suffix,
	    str dir_path, ptr<name_dat> dir_nd);

  void lookup1 (cb_ptr_name_dat_t cb, ptr<name_dat> dir_nd, 
		str dir_path, str filename);

  void lookup2 (cb_ptr_name_dat_t cb, ptr<name_dat> dir_nd, 
		str dir_path, str filename, 
		uint64 blocknum,
		ptr<const sfsro_directory> dir);
};


class nfstrans {
  /* 

     Translate from NFS FHs to other structures of a similar
     level of abstraction.

  */
public:
  nfstrans (ref<fhtt_t> fhttfhtt, ref<pathtrans> ptpt)
    : fhtt (fhttfhtt), pt (ptpt) { }
  
  inline str path (ref<const nfs_fh3> nfh)
  {
    return (*fhtt)[*nfh];
  }

  inline void nd (cb_ptr_name_dat_t cb, ref<const nfs_fh3> nfh)
  {
    pt->nd (cb, path (nfh));
  }

  inline void close (ref<const nfs_fh3> nfh) 
  {
    fhtt->remove (*nfh);
  }


private:
  ref<fhtt_t> fhtt;   // FH translation table
  ref<pathtrans> pt;
};



class server : public sfsserver {
protected:
  
  server (const sfsserverargs &a)
    : sfsserver (a) { }
  
private:
  ptr<pathtrans> pt;
  ptr<nfstrans> nt;
  ptr<filesys> fs; 

  /* 

     High level functions.

  */
  void dispatch (nfscall *sbp);
  void dispatch_helper (nfscall *sbp, ref<const nfs_fh3> nfh,
			ptr<name_dat> nd);

  sfs_fsinfo *fsinfo_alloc () { return ((sfs_fsinfo*)(New sfsro_fsinfo)); }
  void fsinfo_free (sfs_fsinfo *fsi) { delete (sfsro_fsinfo*)fsi; }
  xdrproc_t fsinfo_marshall () { return xdr_sfsro_fsinfo; }
  void setrootfh (const sfs_fsinfo *fsi, callback<void, bool>::ref err_c);

  void expired ();


  /* 

     These functions reply to NFS.

     Representation: NFS structures 
  
  */
  void nfsproc3_getattrres (nfscall *sbp, ptr<name_dat> nd);
  void nfsproc3_lookupres (nfscall *sbp, 
			   nfsstat3 status,
			   ptr<const nfs_fh3> obj_nfh,
			   ptr<name_dat> obj_nd,
			   ptr<name_dat> dir_nd);
  void nfsproc3_accessres (nfscall *sbp, uint32 ac, 
			   nfsstat3 status,
			   ptr<name_dat> nd);
  void nfsproc3_readlinkres (nfscall *sbp, ptr<name_dat> nd);
  void nfsproc3_readres (nfscall *sbp, uint32 count, uint64 start,
			 bool eof, nfsstat3 status,
			 ptr<const rpc_bytes<RPC_INFINITY> > fdat_start,
			 ptr<const rpc_bytes<RPC_INFINITY> > fdat,
			 ptr<name_dat> nd);
			
  void nfsproc3_readdirres (nfscall *sbp, uint64 cookie, uint32 count,
			    nfsstat3 status,
			    ptr<const sfsro_directory> dir,
			    ptr<const nfs_fh3> dir_nfh,
			    ptr<name_dat> nd);
  void nfsproc3_readdirplusres (nfscall *sbp, uint64 cookie, uint32 count,
				nfsstat3 status,
				ptr<const sfsro_directory> dir,
				ptr<const nfs_fh3> dir_nfh,
				ptr<name_dat> nd);
  
  void nfsproc3_fsstatres (nfscall *sbp, ptr<name_dat> nd);
  void nfsproc3_fsinfores (nfscall *sbp, ptr<name_dat> nd);
  
  
  /* 

     Intermediate callbacks.

  */
  void nfsproc3_lookup1 (nfscall *sbp, 
			 str dir_path, str filename,
			 ref<name_dat> dir_nd, 
			 ref<const nfs_fh3> dir_nfh,
			 ptr<name_dat> obj_nd);
  void nfsproc3_lookup2 (nfscall *sbp,  
			 str dir_path, str filename,
			 ref<const nfs_fh3> dir_nfh,
			 ptr<name_dat> obj_nd,
			 ref<const fattr3> dir_fa);
  
  void nfsproc3_access1 (nfscall *sbp, uint32 access_req,
			  ref<name_dat> nd, ref<const nfs_fh3> nfh,
			  ref<const sfsro_inode> ip);

  void nfsproc3_readlink1 (nfscall *sbp, ref<name_dat> nd, 
			   ref<const nfs_fh3> nfh,
			   ref<const sfsro_inode> ip);

  void nfsproc3_read1 (nfscall *sbp, ref<name_dat> nd,
		       uint64 offset, uint32 count);

  void nfsproc3_read2 (nfscall *sbp, ref<name_dat> nd,
		       uint64 offset, uint32 count, uint64 blknr,
		       ref<const rpc_bytes<RPC_INFINITY> > fdat);

  void nfsproc3_read3 (nfscall *sbp, ref<name_dat> nd,
		       uint64 offset, uint32 count,
		       ptr<const rpc_bytes<RPC_INFINITY> > fdat_start,
		       ref<const rpc_bytes<RPC_INFINITY> > fdat);

  void nfsproc3_readdir1 (nfscall *sbp, ref<const nfs_fh3> dir_nfh,
			  ref<name_dat> nd,
			  uint64 cookie, /* cookieverf3 &cv, */ 
			  uint32 count);

  void nfsproc3_readdir2 (nfscall *sbp, uint64 cookie,
			  ref<const nfs_fh3> dir_nfh, ref<name_dat> nd,
			  uint32 count, ptr<const sfsro_directory> dir);


  void nfsproc3_readdirplus1 (nfscall *sbp, ref<const nfs_fh3> dir_nfh,
			      ref<name_dat> nd,
			      uint64 cookie, /* cookieverf3 &cv, */ 
			      uint32 count);
 

  /* 
     Functions to help the nfsproc3_foo procedures 
  */


};

#define DIR_OFFSET(cookie) ((cookie) >> 16)
#define DIR_BLOCK(cookie) ((cookie) & INT64 (0x000000000000FFFF))
#define DIR_COOKIE(offset, block) (((uint64)(offset) << 16) | (uint64)(block))

#endif /* _SFSROCD_H_ */

