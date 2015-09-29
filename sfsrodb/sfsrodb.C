/* $Id: sfsrodb.C,v 1.88 2004/09/08 17:41:41 fubob Exp $ */

/*
 * Copyright (C) 1999 Kevin Fu (fubob@mit.edu)
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
 * Foundation, Inc.,4 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 */

/*
 * This program will generate the integrity database for the SFS read-only
 * file system.  Run this program after every change to exported files 
 */


/* The hash tree works very similar to that of the indirect data pointers
   in an inode. */

#include "sysconf.h"

#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include "sfsrodb.h"
#include "parseopt.h"
#include "sfscrypt.h"
#include "rxx.h"
#include "aes.h"
#include "keyregression.h"

/* Experiment with proxy re-encryption */
#ifdef SFSRO_PROXY
#include "/home/fubob/src/proxyfs/miracl/elliptic.h"
#include "/home/fubob/src/proxyfs/miracl/monty.h"
#include "/home/fubob/src/proxyfs/miracl/zzn2.h"
extern Miracl precision;
#include "/home/fubob/src/proxyfs/pairing.h"
static CurveParams gParams;
#endif

dbfe *sfsrodb;
dbfe *sfsrofhdb;

bool update_mode;
bool verbose_mode;
bool error_check;
u_int32_t blocksize = SFSRO_BLKSIZE;
extern int errno;
char IV[SFSRO_IVSIZE];
int relpathlen;
extern ptr < rabin_priv > sfsrokey;
str hostname;
ptr<keyregression> kr = NULL;
uint32 curr_vers = 0;
/* Statistics */
u_int32_t reginode_cnt = 0;
u_int32_t lnkinode_cnt = 0;
u_int32_t filedatablk_cnt = 0;
u_int32_t indir_cnt = 0;
u_int32_t directory_cnt = 0;
u_int32_t fhdb_cnt = 0;
u_int32_t fh_cnt = 0;

u_int32_t identical_block = 0;
u_int32_t identical_indir = 0;
u_int32_t identical_dir = 0;
u_int32_t identical_inode = 0;
u_int32_t identical_sym = 0;
u_int32_t identical_fhdb = 0;
u_int32_t identical_fh = 0;

time_t sfsro_duration = 31536000; /* seconds. default to 365 days */
sfs_time old_start;		// XXX Yikes!  this global variable is scary

#ifdef SFSRO_PROXY
extern ProxyPK proxy_PublicKey;
extern ProxySK proxy_SecretKey;
extern ProxyPK proxy_DelegatePublicKey;
extern ProxySK proxy_DelegateSecretKey;
extern CurveParams proxy_params;
#endif

/* True if only can LOOKUP, not READDIR 
   Really should make more fine grained.
   Allow specification of which directories to 
   make opaque.
*/
bool opaque_directory = false; 

vec<str> modified_list;
 

/* Given: A filled stat structure and allocated inode
   Return: A SFSRO inode which reflects all of the stat values.
   The data pointers are initialized with .setsize(0).
   The array of direct pointers is initialize with no members.
   However, the caller will eventually have to set the
   following values: 

   .size, .used, and direct/indirect data pointers.   
 */
void
sfsrodb_setinode (const struct stat *st, sfsro_inode *inode)
{

  /*
     SFSRO has implied read-access by all.  We only care
     whether the file is a non-directory executable.  Everything
     else is synthesised by sfsrocd.

   */

  ftypero t;
  if (S_ISREG (st->st_mode)) {
    t = ((st->st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) ?
		 SFSROREG_EXEC : SFSROREG);
  }
  else if (S_ISDIR (st->st_mode))
    t = opaque_directory ? SFSRODIR_OPAQ : SFSRODIR;
  else if (S_ISLNK (st->st_mode))
    t = SFSROLNK;
  else {
    warn << "Non-supported file type " << st->st_mode << "\n";
    exit (1);
  }

  inode->set_type (t);

  if (inode->type == SFSROLNK) {
    rpc_clear (*inode->lnk);

    inode->lnk->nlink = st->st_nlink; // XXX bogus! cannot rely on this number

#ifdef SFS_HAVE_STAT_ST_ATIMESPEC
    inode->lnk->mtime.seconds = st->st_mtimespec.tv_sec;
    inode->lnk->mtime.nseconds = st->st_mtimespec.tv_nsec;
    inode->lnk->ctime.seconds = st->st_ctimespec.tv_sec;
    inode->lnk->ctime.nseconds = st->st_ctimespec.tv_nsec;
#else
    inode->lnk->mtime.seconds = st->st_mtime;
    inode->lnk->mtime.nseconds = 0;
    inode->lnk->ctime.seconds = st->st_ctime;
    inode->lnk->ctime.nseconds = 0;
#endif /* SFS_HAVE_ST_ATIMESPEC */

  } else {
    rpc_clear (*inode->reg);

    inode->reg->nlink = st->st_nlink;  // XXX bogus! cannot rely on this number
    inode->reg->size = 0;
    inode->reg->used = 0;
    
#ifdef SFS_HAVE_STAT_ST_ATIMESPEC
    inode->reg->mtime.seconds = st->st_mtimespec.tv_sec;
    inode->reg->mtime.nseconds = st->st_mtimespec.tv_nsec;
    inode->reg->ctime.seconds = st->st_ctimespec.tv_sec;
    inode->reg->ctime.nseconds = st->st_ctimespec.tv_nsec;
#else
    inode->reg->mtime.seconds = st->st_mtime;
    inode->reg->mtime.nseconds = 0;
    inode->reg->ctime.seconds = st->st_ctime;
    inode->reg->ctime.nseconds = 0;
#endif /* SFS_HAVE_ST_ATIMESPEC */

    inode->reg->direct.setsize (0);

  }

  // strbuf sb;
  // rpc_print (sb, inode, 5, NULL, NULL);
  // warn << "setinode " << sb << "\n";

}


/* Set "bytes_written" to length of data written to disk and return
   whether new/old data match */
template<class T> 
bool
store (T &data, sfs_hash *fh, sfs_hash *oldfh,
	size_t &bytes_written, sfsro_lockboxtype lt)
{
  assert (fh);

  bytes_written = 0;

  strbuf sb;
  rpc_print (sb, data, 10, NULL, " ");
  warn << "sfsro_data: " << sb;


  /* Read old sealed data if necessary to get the lockbox */ 
  sfsro_data olddata;
  T datacopy = data;
  if (kr) {
    if (update_mode && oldfh) {
      if (!sfsrodb_get (sfsrodb, oldfh->base (), oldfh->size (), olddata)) {
	strbuf sb;
	rpc_print (sb, *oldfh, 5, NULL, " ");
	warn << " oldfh: " << sb;
	fatal << "couldn't load old data\n";
      }
      seal_sfsro_data (kr->gk (olddata.ct->gk_vers), olddata.ct->gk_vers, &data, 
		       lockboxkey (kr->gk (olddata.ct->gk_vers), olddata.ct));
    } else 
      seal_sfsro_data (kr->gk (curr_vers), curr_vers, &data, NULL, lt);
  }

  str datastr = xdr2str (data);
  create_sfsrofh2 (IV, SFSRO_IVSIZE, fh, datastr);
  bytes_written = datastr.len ();

  if (update_mode && oldfh) {
    if (*fh == *oldfh) {
      warn << "sfsro_data unchanged\n";
      return false;
    } else if (kr && (curr_vers != olddata.ct->gk_vers)) {
      data = datacopy;
      seal_sfsro_data (kr->gk (curr_vers), curr_vers, &data, NULL);
      datastr = xdr2str (data);
      create_sfsrofh2 (IV, SFSRO_IVSIZE, fh, datastr);
      bytes_written = datastr.len ();
    }
  }

  warn << "sfsro_data changed:\n";

  if (!sfsrodb_put (sfsrodb, fh->base (), fh->size (), 
		    (void *)datastr.cstr (), datastr.len ())) {
    identical_block++;
    identical_fh++;
  } else {
    //    filedatablk_cnt++;
    fh_cnt++;
  }

  return true;
}

/* Given: A fully specified inode
   Effects: Stores the inode in the database with the fh as the key
   Return: A file handle in fh.  fh must already be allocated.
   This function will set the IV appropriately with prandom bits.
   Return true if during update_mode, old and new data do not match
 */
bool
store_inode (sfsro_inode *inode, sfs_hash *fh, 
	     sfs_hash *oldfh, bool propagate_change)
{
  sfsro_data dat (SFSRO_INODE);
  *dat.inode = *inode;

  size_t s;
  if (store (dat, fh, oldfh, s,
#ifdef SFSRO_PROXY
	     SFSRO_PROXY_REENC
#else
	     SFSRO_AES
#endif
	     )) {
    if (inode->type == SFSROLNK)
      lnkinode_cnt++;
    else
      reginode_cnt++;
    return true;
  }

  return false;  
}

ptr<sfsro_indirect> 
getindir (ptr<const sfs_hash> fh)
{
  assert (fh);
  assert (kr);

  sfsro_data olddata;
  if(!sfsrodb_get (sfsrodb, fh->base (), fh->size (), olddata)) {
    strbuf sb;
    rpc_print (sb, fh, 5, NULL, " ");
    warn << " NO DATA for fh (key): " << sb;
    return NULL;
  }

  if (kr) {
    assert (olddata.type == SFSRO_SEALED);
    if (!unseal (kr->gk (olddata.ct->gk_vers), (sfsro_sealed *)olddata.ct, 
		 (sfsro_data *)&olddata))
      fatal << "Decryption of indirect block failed\n";
  }
  
  assert (olddata.type == SFSRO_INDIR);
  ptr<sfsro_indirect> indir = New refcounted<sfsro_indirect> 
    (*olddata.indir); 

  return indir;
}

ptr<sfs_hash>
single_indirectres (size_t i, ref<sfs_hash> handle)
{
  assert (i < SFSRO_NFH);
    
  ptr<sfsro_indirect> indirect = getindir (handle);
  assert (indirect->handles.size () > i);

  return (New refcounted<sfs_hash> (indirect->handles[i]));
}

ptr<sfs_hash>
double_indirectres (size_t i, 
		    ref<sfs_hash> handle)
{
  assert (i < (SFSRO_NFH * SFSRO_NFH));

  size_t b = i % SFSRO_NFH;
  i = i / SFSRO_NFH;

  ptr<sfsro_indirect> indirect = getindir (handle);
  assert (indirect->handles.size () > i);

  return single_indirectres (b, New refcounted<sfs_hash> 
			     (indirect->handles[i]));
}

ptr<sfs_hash>
triple_indirectres (size_t i,
		    ref<sfs_hash> handle)
{
  assert (i < (SFSRO_NFH * SFSRO_NFH * SFSRO_NFH));

  size_t b = i % (SFSRO_NFH * SFSRO_NFH);
  i = i / (SFSRO_NFH * SFSRO_NFH);

  ptr<sfsro_indirect> indirect = getindir (handle);
  if (indirect->handles.size () <= i)
    return NULL;

  return double_indirectres (b, New refcounted<sfs_hash>
			     (indirect->handles[i]));
}

ptr<sfs_hash>
blkcnt2fh (sfsro_inode *ip, uint32 b)
{  
  if (b < SFSRO_NDIR) {
    if (ip->reg->direct.size () <= b)
      return NULL;
    return New refcounted<sfs_hash> (ip->reg->direct[b]);
  } else {
    size_t i = (b - SFSRO_NDIR);
    
    if (i < SFSRO_NFH) {
      // XXX check if indirect 0
      return single_indirectres (i, New refcounted<sfs_hash> 
				 (ip->reg->indirect));
    }
    else {
      i -= SFSRO_NFH;
      
      if (i < SFSRO_NFH * SFSRO_NFH)
	// XXX check if indirect 0
	return double_indirectres (i, New refcounted<sfs_hash>
				   (ip->reg->double_indirect));
      else { 
	i -= SFSRO_NFH * SFSRO_NFH;
	
	if (i < SFSRO_NFH * SFSRO_NFH * SFSRO_NFH)
	  // XXX check if indirect 0
	  return triple_indirectres (i, New refcounted<sfs_hash>
				     (ip->reg->triple_indirect));
 	else {
	  assert(0);  
	}
      }
    } 
  }
}

/* Return true if change propagates */
bool
vec2indir (sfs_hash *fh, vec<sfs_hash> &ib_vec, sfs_hash *oldfh)
{
  sfsro_data data (SFSRO_INDIR);
  data.indir->handles.setsize (0);
  while (!ib_vec.empty ()) 
    data.indir->handles.push_back (ib_vec.pop_front ());
  
  if (data.indir->handles.size () != 0) {
    sfsro_data olddata;
    sfsro_data datacopy = data;
    if (kr) {
      if (update_mode && oldfh) {
	if (!sfsrodb_get (sfsrodb, oldfh->base (), oldfh->size (), olddata)) {
	  strbuf sb;
	  rpc_print (sb, *oldfh, 5, NULL, " ");
	  warn << " oldfh: " << sb;
	  fatal << "couldn't load old data\n";
	}
	seal_sfsro_data (kr->gk (olddata.ct->gk_vers), olddata.ct->gk_vers, &data, 
			 lockboxkey (kr->gk (olddata.ct->gk_vers), olddata.ct));
      } else 
	seal_sfsro_data (kr->gk (curr_vers), curr_vers, &data, NULL);
    }
    
    str datastr = xdr2str (data);
    create_sfsrofh2 (IV, SFSRO_IVSIZE, fh, datastr);
    
    if (update_mode && oldfh) {
      if (*fh == *oldfh) {
	warn << "sfsro_data indir unchanged\n";
	return false;
      } else if (kr && (curr_vers != olddata.ct->gk_vers)) {
	data = datacopy;
	seal_sfsro_data (kr->gk (curr_vers), curr_vers, &data, NULL);
	datastr = xdr2str (data);
	create_sfsrofh2 (IV, SFSRO_IVSIZE, fh, datastr);
      }
    }
    
    warn << "sfsro_data indir changed:\n";
    
    if (!sfsrodb_put (sfsrodb, fh->base(), fh->size(),
		      (void *)datastr.cstr (), datastr.len ())) {
      // warn << "Found identical indirect, compressing.\n";
      identical_indir++;
      identical_fh++;
    } else {
      indir_cnt++;
      fh_cnt++;
    }
  }

  return true;
}

bool
write_blk_data (sfsro_inode *inode,
		vec<sfs_hash> &sib_vec, // single
		vec<sfs_hash> &dib_vec, // double
		vec<sfs_hash> &tib_vec, // triple
		bool eof, uint32 b, sfs_hash &fh,
		sfsro_inode *oldinode)
{
  bool propagate_change = false;

  if (b < SFSRO_NDIR) {
    assert (inode->reg->direct.size () == b);
    inode->reg->direct.push_back (fh);
  } else {
    sib_vec.push_back (fh);
  
    size_t i = (b - SFSRO_NDIR);
    if (i < SFSRO_NFH) {
      if (eof || sib_vec.size () % SFSRO_NFH == 0)
	if (vec2indir (&inode->reg->indirect, sib_vec, 
		       oldinode ? &oldinode->reg->indirect 
		       : implicit_cast<sfs_hash *> (NULL)))
	  propagate_change = true;
    } else {
      i -= SFSRO_NFH;
      
      if (i < SFSRO_NFH * SFSRO_NFH) {
	if (eof || sib_vec.size () % SFSRO_NFH == 0) {
	  ptr<sfsro_indirect> oldindir = NULL;
	  if (update_mode && oldinode) {
	    oldindir = getindir (New refcounted<sfs_hash> (oldinode->reg->double_indirect));
	  }
	  if (vec2indir (&fh, sib_vec, oldindir ? &oldindir->handles [i/SFSRO_NFH] 
			 : implicit_cast<sfs_hash *> (NULL)))
	    propagate_change = true;
	  dib_vec.push_back (fh);
	}

	if (eof || dib_vec.size () % SFSRO_NFH == 0) {
	  if (update_mode)
	    assert (0); // XXX code not yet written
	  if (vec2indir (&inode->reg->double_indirect, dib_vec,
			 oldinode ? &oldinode->reg->double_indirect 
			 : implicit_cast<sfs_hash *> (NULL)))
	    propagate_change = true;
	}

      } else { 
	i -= SFSRO_NFH * SFSRO_NFH;
	
	if (i < SFSRO_NFH * SFSRO_NFH * SFSRO_NFH) {

	  if (eof || sib_vec.size () % SFSRO_NFH == 0) {
	    if (update_mode)
	      assert (0); // XXX code not yet written
	    if (vec2indir (&fh, sib_vec, NULL))
	      propagate_change = true;
	    dib_vec.push_back (fh);
	  }

	  if (eof || dib_vec.size () % SFSRO_NFH == 0) {
	    if (update_mode)
	      assert (0); // XXX code not yet written
	    if (vec2indir (&fh, dib_vec, NULL))
	      propagate_change = true;
	    tib_vec.push_back (fh);
	  }

	  if (eof || tib_vec.size () % SFSRO_NFH == 0) {
	    if (vec2indir (&inode->reg->triple_indirect, tib_vec,
			   oldinode ? &oldinode->reg->triple_indirect 
			   : implicit_cast<sfs_hash *> (NULL)))
	      propagate_change = true;
	  }

	} else {
	  assert(0);  // too big
	  // XX should fail gracefully?  hang?
	}
      }
    } 
  }
  return propagate_change;
}

/* return true if change propagates */
bool
store_file_block (sfsro_inode *inode, const char *block, size_t size,
		  vec<sfs_hash> &sib_vec, // single
		  vec<sfs_hash> &dib_vec, // double
		  vec<sfs_hash> &tib_vec, // triple
		  bool eof, uint32 b,
		  sfs_hash *oldfh,
		  sfsro_inode *oldinode)
{
  bool propagate_change = false;
 
  sfsro_data dat (SFSRO_FILEBLK);
  dat.data->setsize (size);
  memcpy (dat.data->base (), block, size);

  size_t s;
  sfs_hash fh; 

  if (store (dat, &fh, oldfh, s,
#ifdef SFSRO_NOPROXY
	     SFSRO_PROXY_REENC
#else
	     SFSRO_AES
#endif
)) {
    filedatablk_cnt++;
    propagate_change = true;  
  }

  inode->reg->size += size;
  inode->reg->used += size;

  if (write_blk_data (inode, sib_vec, dib_vec, tib_vec, eof, b, fh, oldinode))
    propagate_change = true;

  return propagate_change;
}


/* Given: A fully specified inode for a file and pointer to its data
   (but not file sizes or data pointers)
   Effects: Store the file data, fully specify the inode
   
   Return: A file handle in fh.  fh must already be allocated.
   This function will set the IV appropriately with prandom bits.
 */
bool
store_file (sfsro_inode *inode, str path, int st_size, 
	    sfs_hash *oldfh)
{
  bool propagate_change = false;
  char block[blocksize];
  int fd;
  size_t size = 0;

  if ((fd = open (path, O_RDONLY)) < 0) {
    fatal << "store_file: open failed" << fd << "\n";
  }

  vec<sfs_hash> sib_vec;
  vec<sfs_hash> dib_vec;
  vec<sfs_hash> tib_vec;
  uint32 blkcnt = 0;

  while ((size = read (fd, block, blocksize))) {
    
    bool eof = (size < blocksize) ||
      (((st_size % blocksize) == 0) && // exact block
       (blkcnt + 1 == (uint32)st_size/blocksize));
    
    ptr<sfsro_data> oldinode = NULL;
    if (update_mode && oldfh) {
      oldinode = New refcounted<sfsro_data> ();
      if (!sfsrodb_get (sfsrodb, oldfh->base (), oldfh->size (), *oldinode))
	fatal << "sfsrodb_get failed on inode\n";
      if (kr) {
	assert (oldinode->type == SFSRO_SEALED);
	if (!unseal (kr->gk (oldinode->ct->gk_vers), 
		     (sfsro_sealed *)oldinode->ct, 
		     (sfsro_data *)oldinode))
	  fatal << "Decryption of inode block failed\n";
      }
      assert (oldinode->type == SFSRO_INODE);
    }
    
    if (update_mode && oldinode) {
      if (store_file_block (inode, block, size,
			    sib_vec, dib_vec, tib_vec, eof, 
			    blkcnt, blkcnt2fh (oldinode->inode, blkcnt),
			    oldinode->inode))
	propagate_change = true;
    } else 
      if (store_file_block (inode, block, size,
			    sib_vec, dib_vec, tib_vec, eof,
			    blkcnt, implicit_cast<sfs_hash *> (NULL), 
			    implicit_cast<sfsro_inode *> (NULL)))
	propagate_change = true;

    blkcnt++;
  }

  if (size < 0) {
    fatal << "store_file: Read failed\n";
  }
  if (close (fd) < 0) {
    fatal << "store_file: close failed\n";
  }

  return propagate_change;
}


/* Given: a fully specified directory, inode filled in by setinode,
   allocated fh

   Return: file handle, store directory contents, final inode values
           return true if change propagates

   Effects: After filling in a directory structure, fill in an inode
   structure, store the directory in the database, and compute file
   handle.  
 */
bool
store_directory_block (sfsro_inode *inode, xdrsuio &x,
		       vec<sfs_hash> &sib_vec, // single
		       vec<sfs_hash> &dib_vec, // double
		       vec<sfs_hash> &tib_vec, // triple
		       bool eof, uint32 b,
		       sfs_hash *oldfh,
		       sfsro_inode *oldinode)
{
  bool propagate_change = false;
  if (oldfh) {
    strbuf sb;
    rpc_print (sb, *oldfh, 5, NULL, " ");
    warn << "oldfh: " << sb;
  }

  sfs_hash fh;
  sfsro_data res;
  if (kr) {
    if (update_mode && oldfh) {
      if (!sfsrodb_get (sfsrodb, oldfh->base (), oldfh->size (), res)) 
	fatal << "couldn't load old data\n";
      seal_xdrsuio (kr->gk (res.ct->gk_vers), res.ct->gk_vers, &res, x,
		    lockboxkey (kr->gk (res.ct->gk_vers), res.ct)); 
    } else 
      seal_xdrsuio (kr->gk (curr_vers), curr_vers, &res, x, NULL);
  } else {
    size_t calllen = x.uio ()->resid ();
    char *callbuf = suio_flatten (x.uio ());
    buf2xdr (res, callbuf, calllen);
    xfree (callbuf);
  }

  str datastr = xdr2str (res);
  create_sfsrofh2 (IV, SFSRO_IVSIZE, &fh, datastr);

  if (update_mode && oldfh) {
    if (fh != *oldfh) {
      propagate_change = true;
      if (kr && (curr_vers != res.ct->gk_vers)) {
	if (!unseal (kr->gk (res.ct->gk_vers), res.ct, &res)) 
	  fatal << "Could not unseal in store_directory_block\n";
	seal_sfsro_data (kr->gk (curr_vers), curr_vers, &res, NULL);
	datastr = xdr2str (res);
	create_sfsrofh2 (IV, SFSRO_IVSIZE, &fh, datastr);
      }
    }
  }

  strbuf sb;
  rpc_print (sb, fh, 5, NULL, " ");
  warn << "fh: " << sb;
  
  if (!update_mode || propagate_change)
    if (!sfsrodb_put (sfsrodb, fh.base (), fh.size (), 
		      (void *)datastr.cstr (), datastr.len ())) {
      //warn << "Found identical directory, compressing.\n";
      identical_dir++;
      identical_fh++;
    } else {
      directory_cnt++;
      fh_cnt++;
    }
    
  inode->reg->size += datastr.len ();
  inode->reg->used += datastr.len ();
  
  if (write_blk_data (inode, sib_vec, dib_vec, tib_vec, eof, b, fh, oldinode))
    propagate_change = true;

  return propagate_change;
}


inline int
compare_name (const void *file1, const void *file2)
{
  return ((str *) file1)->cmp ( *((str *) file2));
}

void
sort_dir (const str path, vec<str> &file_list)
{
  DIR *dirp;
  struct dirent *de = NULL;

  if ((dirp = opendir (path)) == 0) {
    warn << path << " is not a directory\n";
    return;
  }

  while ((de = readdir (dirp))) {
    str filename (de->d_name);

    /* The client manages . and .. */
    if ((filename.cmp (".") == 0) 
	|| (filename.cmp ("..") == 0)) 
      continue;
    
    file_list.push_back (filename);
  }

  if (closedir (dirp) < 0) {
    fatal << "Unable to close directory: " << path << "\n";
    // may run out of file descriptors if we were continue...
  }


  /*  if (verbose_mode) {
    warnx << "Before: file_list.size=" << file_list.size () << "\n";
      
    for (unsigned int i = 0; i < file_list.size (); i++) 
	warnx << file_list[i] << "\n";
  }
  */

  qsort (file_list.base (), file_list.size (),
	 sizeof (str *), compare_name);

  /*
  warnx << "After:\n";

  if (verbose_mode) {
    for (unsigned int i = 0; i < file_list.size (); i++) {
      warnx << file_list[i] << "\n";
    }
  }
  */

}

// Hack to get around memory allocation for str's
static bool
xdr_copy_str (XDR *x, str &filename)
{
  if (!xdr_putint (x, filename.len ()))
    return false;
  if (char *filename2 =
      (char *) XDR_INLINE (x, ((filename.len () + 3) & ~3))) {
    memcpy (filename2, filename.cstr (), filename.len ());
    // If the filname needs no padding, then is the following
    // code legal (arg1 = unallocated memory, but arg3 = 0)?
  
    memcpy (filename2 + filename.len (),
	    const_cast<char *> (__xdr_zero_bytes),
	    (-filename.len ()) & 3);

    return true;
  }
  return false;
}


static bool
xdr_copy_sfs_hash (XDR *x, sfs_hash &fh)
{
  if (char *buf =
      (char *) XDR_INLINE (x, fh.size ())) {
    memcpy (buf, fh.base (), fh.size ());
    return true;
  } else
    return false;
}


static bool
xdr_putsfsro_dirent (XDR *x, sfs_hash &fh, str filename)
{
  rpc_str<RPC_INFINITY> name = filename;

  return
    // sfsro_dirent * (non-null):
    xdr_putint (x, 1)
    // sfs_hash fh
    && xdr_copy_sfs_hash (x, fh)
    // string name<>
    && xdr_copy_str (x, filename);
}

inline bool
changed (struct stat *st) {
#ifdef SFS_HAVE_STAT_ST_ATIMESPEC
  // ignore nseconds - XXX why?
  if (old_start < sfs_time (st->st_mtimespec.tv_sec))
    return true;
#else
  if (old_start < sfs_time (st->st_mtime))
    return true;
#endif /* SFS_HAVE_ST_ATIMESPEC */
  
  return false;
}

bool
getfsinfostart (sfs_time *start, sfs_hash *old_root_fh) 
{
  sfsro_fsinfo fsinfo;
  
  // read fsinfo
  if (!sfsrodb_get (sfsrodb, (void *) "fsinfo", 6, fsinfo)) {
    warn << "couldn't load fsinfo\n";
    return false;
  }

  if (fsinfo.v2->info.type ==  SFSRO_PRIVATE) {
    if (!kr) {
      warn << "No group key provided to unseal private fsinfo\n";
      return false;
    }
    sfsro_public fsinfopub;
    if (!unseal (kr->gk (fsinfo.v2->info.priv->ct.gk_vers),
		 &fsinfo.v2->info.priv->ct, &fsinfopub)) {
      warn << "Cannot unseal old fsinfo\n";
      return false;
    }

    *old_root_fh = fsinfopub.rootfh;
    *start = fsinfopub.start;
    return true;
  }

  *old_root_fh = fsinfo.v2->info.pub->rootfh;
  *start = fsinfo.v2->info.pub->start;
  return true;
}

sfsro_dirent *
directory_getentblk (ptr<sfsro_data> oldinode, 
		     sfsro_data &olddirblk, uint32 *oldblkcnt)
{
  assert (oldinode);
  assert (oldblkcnt);
  ptr<sfs_hash> blkfh;
  if (!(blkfh = blkcnt2fh (oldinode->inode, *oldblkcnt)))
    return NULL;
  if (!sfsrodb_get (sfsrodb, blkfh->base (), blkfh->size (), 
		    olddirblk)) {
    strbuf sb;
    rpc_print (sb, *blkfh, 5, NULL, " ");
    warn << " blkfh: " << sb;
    fatal << "sfsrodb_get failed on dir\n";
  }
  if (kr) {
    assert (olddirblk.type == SFSRO_SEALED);
    if (!unseal (kr->gk (olddirblk.ct->gk_vers), 
		 (sfsro_sealed *)olddirblk.ct, 
		 (sfsro_data *)&olddirblk))
      fatal << "Decryption of dir block failed\n";
  }
  assert (olddirblk.type == SFSRO_DIRBLK);
  (*oldblkcnt)++;
  return olddirblk.dir->entries;
}

/* Return the old handle of a filename 
   Assumes both the old and new directory entries
   are lexicographically sorted */
ptr<sfs_hash>
directory_getoldent (str filename, ptr<sfsro_data> oldinode,
		     sfsro_data &olddirblk, uint32 *oldblkcnt,
		     sfsro_dirent **roep)
{
  assert (oldinode);
  assert (oldblkcnt);
  assert (roep);

  ptr<sfs_hash> oldfh = NULL;
  bool done = false;
  while (!done) {
    if (!*roep) {
      *roep = directory_getentblk (oldinode, olddirblk, oldblkcnt);
      if (!*roep)
	done = true;
    }
    
    while (!done && (*roep) != NULL) {
      if (filename < (*roep)->name) {
	done = true;
      } else {
	if (filename == (*roep)->name) {
	  oldfh = New refcounted<sfs_hash> ((*roep)->fh);
	  done = true;
	}
	(*roep) = (*roep)->nextentry;
      }
    }
  }

  return oldfh;
}

bool recurse_path (const str path, sfs_hash *fh, sfs_hash *oldfh);

/* Return true if propagate change. */ 
bool
recurse_directory (const str path, sfs_hash *fh, sfs_hash *oldfh,
		   sfsro_inode &inode)
{
  vec<sfs_hash> sib_vec;
  vec<sfs_hash> dib_vec;
  vec<sfs_hash> tib_vec;
  uint32 blkcnt = 0;
  bool propagate_change = false;

  vec<str> file_list;
  sort_dir (path, file_list);
  
  if (verbose_mode) {
    warnx << "file_list.size=" << file_list.size () << "\n";
    for (unsigned int i = 0; i < file_list.size (); i++) 
      warnx << file_list[i] << "\n";
  }

  uint32 oldblkcnt = 0;
  sfsro_dirent *roe = NULL;
  ptr<sfsro_data> oldinode = NULL;
  sfsro_data olddirblk;
  if (update_mode && oldfh) {
    oldinode = New refcounted<sfsro_data> ();
    if (!sfsrodb_get (sfsrodb, oldfh->base (), oldfh->size (), *oldinode))
      fatal << "sfsrodb_get failed on inode\n";
    if (kr) {
      assert (oldinode->type == SFSRO_SEALED);
      if (!unseal (kr->gk (oldinode->ct->gk_vers), 
		   (sfsro_sealed *)oldinode->ct, 
		   (sfsro_data *)oldinode))
	fatal << "Decryption of inode block failed\n";
    }
    assert (oldinode->type == SFSRO_INODE);
  }

  bool errors = false;
  while (file_list.size () != 0) {
    xdrsuio x (XDR_ENCODE);
    if (!xdr_putint (&x, SFSRO_DIRBLK))
      errors = true;
    while (file_list.size () > 0) {
      str filename = file_list.front ();
      if (XDR_GETPOS (&x) + 24 + ((filename.len () + 3) & ~3) 
	  > blocksize) { 
	break;
      }
      file_list.pop_front ();
      sfs_hash fh;
      
      ptr<sfs_hash> oldentfh = NULL;
      if (update_mode && oldinode) {
	oldentfh = directory_getoldent (filename, oldinode, 
					olddirblk, &oldblkcnt, &roe);
      }
      if (oldentfh){
	strbuf sb;
	rpc_print (sb, *oldentfh, 5, NULL, " ");
	warn << " oldentfh: " << sb;
      }
      if (recurse_path (path << "/" << filename, &fh, oldentfh))
	propagate_change = true;
      
      if (!xdr_putsfsro_dirent (&x, fh, filename))
	errors=true;
    }      
    
    if (!xdr_putint (&x, 0) 	// NULL entry *
	|| !xdr_putint (&x, !file_list.size())) // bool eof
      errors = true;
    
    bool eof = (file_list.size() == 0);
    if (store_directory_block (&inode, x, sib_vec, dib_vec, tib_vec, eof, 
			       blkcnt, (update_mode && oldinode)
			       ? blkcnt2fh (oldinode->inode, blkcnt)
			       : implicit_cast<sfs_hash *> (NULL),
			       (update_mode && oldinode) ? oldinode->inode 
			       : implicit_cast<sfsro_inode *> (NULL)))
      propagate_change = true;
    blkcnt++;
  }
  return propagate_change;
}

/*
   Given: Path to file (any kind), an allocated fh, the oldfh
   of this file if exists.

   Return: The hash and IV in the fh.
           Return true if old and new data do not match

   Effects: Recursively hash everything beneath a directory
   It computes the cryptographic file handle for the
   given path, inserts the mapping from the fh to its data

   a null oldfh signifies either not in update mode,
   or that this file is new

 */
bool
recurse_path (const str path, sfs_hash *fh, sfs_hash *oldfh)
{
  if (verbose_mode) {
    warn << "recurse_path (" << path << ", " << "fh)\n";
    if (oldfh) {
      strbuf sb;
      rpc_print (sb, *oldfh, 5, NULL, " ");
      warn << " oldfh: " << sb;
    }
  }

  struct stat st;
  if (lstat (path, &st) < 0)
    fatal << path << ": " << strerror (errno) << "\n";
 
  sfsro_inode inode;
  bool propagate_change = false;
  if (S_ISLNK (st.st_mode)) {
    char *buf = New char[st.st_size + 1];
    int nchars = readlink (path, buf, st.st_size);
    if (nchars > PATH_MAX) {
      fatal << "symlink target too large "
	    << path << " " << nchars << "\n";
    }
    sfsrodb_setinode (&st, &inode);
    inode.lnk->dest = nfspath3 (buf, nchars);
    delete[] buf;
  } else if (S_ISREG (st.st_mode)) {
    sfsrodb_setinode (&st, &inode);
    if (!update_mode || changed (&st))
      if (store_file (&inode, path, st.st_size, oldfh)) 
	propagate_change = true;
    if (update_mode && !changed (&st) && oldfh) {
      ptr<sfsro_data> oldinode = New refcounted<sfsro_data> ();
      if (!sfsrodb_get (sfsrodb, oldfh->base (), oldfh->size (), *oldinode))
	fatal << "sfsrodb_get failed on inode\n";
      if (kr) {
	assert (oldinode->type == SFSRO_SEALED);
	if (!unseal (kr->gk (oldinode->ct->gk_vers), 
		     (sfsro_sealed *)oldinode->ct, 
		     (sfsro_data *)oldinode))
	  fatal << "Decryption of inode block failed\n";
      }
      assert (oldinode->type == SFSRO_INODE);
      inode = *oldinode->inode;
    }
  } else if (S_ISDIR (st.st_mode)) {
    sfsrodb_setinode (&st, &inode);
    if (recurse_directory (path, fh, oldfh, inode))
      propagate_change = true;
  }
  else 
    fatal << "Not symlink, reg file, or directory " << path << "\n";
  
  // XXX store inode appears to store a zero-length file.  using wrong inode?
  if (store_inode (&inode, fh, oldfh, propagate_change))
    return true;
  
  return false;
}    


int
sfsrodb_main (const str root, const str keyfile, const char *dbfile)
{
  ref<dbImplInfo> info = dbGetImplInfo();

  for (unsigned int i=0; i < info->supportedOptions.size(); i++) 
    warn << info->supportedOptions[i] << "\n";

  //create the generic object
  sfsrodb = new dbfe();

  //set up the options we want
  dbOptions opts;
  opts.addOption ("opt_async", 0);
  opts.addOption ("opt_cachesize", 80000);
  opts.addOption ("opt_nodesize", 4096);

  if (update_mode) {
    opts.addOption ("opt_flag", 0); 
  } else {
    opts.addOption ("opt_create", 1); // Requires DB not already exist
  }

  if (int err = sfsrodb->opendb (const_cast <char *>(dbfile), opts)) {
    warn << "open returned: " << strerror(err) << err << "\n";
    exit (-1);
  }

  /* Set the sfs_connectres structure (with pub key) to db */
  sfs_connectres cres (SFS_OK);
  cres.reply->servinfo.set_sivers (7);
  cres.reply->servinfo.cr7->release = sfs_release;
  cres.reply->servinfo.cr7->host.type = SFS_HOSTINFO;
  cres.reply->servinfo.cr7->host.hostname = hostname;
  cres.reply->servinfo.cr7->host.port = sfs_defport;

  /* Read the secret key for database authentication */
  ptr<sfspriv> sk;

  if (!keyfile) {
    warn << "cannot locate default file sfs_host_key\n";
    fatal ("errors!\n");
  }
  else {
    str key = file2wstr (keyfile);
    if (!key) {
      warn << keyfile << ": " << strerror (errno) << "\n";
      fatal ("errors!\n");
    }
    else if (!(sk = sfscrypt.alloc_priv (key, SFS_SIGN))) {
      warn << "could not decode " << keyfile << "\n";
      warn << key << "\n";
      fatal ("errors!\n");
    }
    str err;
    if (!sk->export_pubkey (&cres.reply->servinfo.cr7->host.pubkey)) {
      warn << "could not set public key: " << keyfile << "\n";
      fatal ("errors!\n");
    }
  }

  cres.reply->servinfo.cr7->prog = SFSRO_PROGRAM;
  cres.reply->servinfo.cr7->vers = SFSRO_VERSION_V2;
  bzero (&cres.reply->charge, sizeof (sfs_hashcharge));
  ref<sfs_servinfo_w> siw = sfs_servinfo_w::alloc (cres.reply->servinfo);

  // Set IV
  sfs_hash id;
  if (!siw->mkhostid (&id)) 
    fatal ("Could not marshal own servinfo object");
  memcpy (&IV[0], id.base(), SFSRO_IVSIZE);

  // store file system in db
  sfs_hash root_fh;
  relpathlen = root.len ();

  if (update_mode) {
    sfs_hash old_root_fh;
    if (!getfsinfostart (&old_start, &old_root_fh)) {
      fatal << "Unable to get old fsinfo\n";
    }
    recurse_path (root, &root_fh, &old_root_fh); 
  } else 
    recurse_path (root, &root_fh, NULL);
  
  sfsro_public fsinfopub;
  memcpy (fsinfopub.iv.base (), &IV[0], SFSRO_IVSIZE);
  fsinfopub.rootfh = root_fh;
  
#if 0
  // fhdb is not necessary in this shape; XXX FIX
  create_fhdb (&fsinfopub.fhdb, dbfile, IV);
#endif
  time_t start;
  fsinfopub.type = SFS_ROFSINFO;
  fsinfopub.start = start = time (NULL);
  fsinfopub.duration = sfsro_duration;
  fsinfopub.blocksize = blocksize;
  
  // XX Should make sure timezone is correct
#if 0
  str stime (ctime (&start));
  str etime (ctime (&fsinfopub.start + fsinfopub.duration));
  warn << "Database good from: \n " << stime
       << "until:\n " << etime;
#endif

  sfsro_fsinfo res (SFSRO_OK);

  if (!kr) {
    /* Public, read-only */
    res.v2->info.set_type (SFSRO_PUBLIC); 
    *res.v2->info.pub = fsinfopub;
  } else {
    /* Private, read-only */
    res.v2->info.set_type (SFSRO_PRIVATE); 
    res.v2->info.priv->gk_id = kr->get_id ();
#ifdef SFSRO_PROXY
    res.v2->info.priv->ct.lt = SFSRO_PROXY_REENC;
#else
    res.v2->info.priv->ct.lt = SFSRO_AES;
#endif
    res.v2->info.priv->ct.gk_vers = kr->curr_vers ();

    if (!xdr2pkcs (res.v2->info.priv->ct.pkcs7, 
		   fsinfopub)) {
      fatal << "xdr2pkcs failed\n";
    }

    aes ctx;
    res.v2->info.priv->ct.lockbox.setsize (16);
    //    rnd.getbytes (res.v2->info.priv->ct.lockbox.base (),
    //		  res.v2->info.priv->ct.lockbox.size ());
    memcpy (res.v2->info.priv->ct.lockbox.base (),
	    (kr->gk (curr_vers))->base (),
	    res.v2->info.priv->ct.lockbox.size ());
    
    warn << "lox= " <<  hexdump(res.v2->info.priv->ct.lockbox.base (),
				res.v2->info.priv->ct.lockbox.size ()) << "\n\n";
    
    ctx.setkey (res.v2->info.priv->ct.lockbox.base (),
		res.v2->info.priv->ct.lockbox.size ());
    cbcencrypt (&ctx, res.v2->info.priv->ct.pkcs7.base (),
		res.v2->info.priv->ct.pkcs7.base (),
		res.v2->info.priv->ct.pkcs7.size ());

//     if (ku->gk.key.size () == 20) {
//       ctx.setkey (ku->gk.key.base (), 16);
//     } else {
//       ctx.setkey (ku->gk.key.base (), ku->gk.key.size ());
//     }
    
   //ctx.setkey ((kr->gk (curr_vers))->base (), (kr->gk (curr_vers))->size ());
#ifdef SFSRO_PROXY
    // Ugliest P.O.S. code in the world.  All this to deal with
    // ciphertext that is much larger than its plaintext
    Big pt = from_binary (res.v2->info.priv->ct.lockbox.size (),
			  res.v2->info.priv->ct.lockbox.base ());
    ECn c1;
    ZZn2 c2;
    if (proxy_level2_encrypt (proxy_params, pt, proxy_PublicKey, c1, c2) == FALSE) {
      warn << "private fsinfo proxy encryption failed\n";
      exit(1);
    }

    // Ciphertext bytes = params.bits*4/8 + 8
    res.v2->info.priv->ct.lockbox.setsize (proxy_params.bits/2 + 6*sizeof(int));
    int len;

    char *buf = res.v2->info.priv->ct.lockbox.base () + sizeof(int);
    int bufsize = res.v2->info.priv->ct.lockbox.size () - sizeof(int);
    assert  (bufsize > 0);
    len = ECnTochar (c1, buf, bufsize);
    if (len <= 0) {
      fatal << "ECnToChar failed\n";
    }
    memcpy ((char *)(buf-sizeof(int)), &len, sizeof (int));
    buf += len;
    bufsize -= len;

    buf += sizeof (int);
    bufsize -= sizeof(int);
    len = ZZn2Tochar (c2, buf, bufsize);
    if (len <= 0) {
      fatal << "ECnToChar failed\n";
    }
    memcpy ((char *)(buf-sizeof(int)), &len, sizeof (int));
    bufsize -= len;

    warn << "Bufsize leftover space = " << bufsize << "\n";

#else
    ctx.setkey ((kr->gk (curr_vers))->base (), 16);
    cbcencrypt (&ctx, res.v2->info.priv->ct.lockbox.base (),
		res.v2->info.priv->ct.lockbox.base (),
		res.v2->info.priv->ct.lockbox.size ());
#endif
  }

  if (!sk->sign (&res.v2->sig, xdr2str (res.v2->info))) {
    warn << "Could not sign certificate.\n";
    fatal ("errors!\n");
  }

  xdrsuio x (XDR_ENCODE);
  if (xdr_sfsro_fsinfo (x.xdrp (), &res)) {
    void *v = suio_flatten (x.uio ());
    int l =  x.uio ()->resid ();
    if (!sfsrodb_put (sfsrodb, "fsinfo", 6, v, l)) {
      warn << "Found identical fsinfo.  You found a collision!\n";
      exit (-1);
    }
    warn << "Added fsinfo\n";
  }

  // if update_mode then modify to overwrite
  xdrsuio x2 (XDR_ENCODE);
  if (xdr_sfs_connectres (x2.xdrp (), &cres)) {
    int l = x2.uio ()->resid ();
    void *v = suio_flatten (x2.uio ());
    warn << "put conres in db\n";
    if (!sfsrodb_put (sfsrodb, "conres", 6, v, l)) {
      warn << "Found identical conres. You found a collision!\n";
      exit (-1);
    }
  }

  if (verbose_mode) {
    warn << "identical blocks:   " << identical_block << "\n";
    warn << "identical indirs:   " << identical_indir << "\n";
    warn << "identical dirs:     " << identical_dir << "\n";
    warn << "identical inodes:   " << identical_inode << "\n";
    warn << "identical symlinks: " << identical_sym << "\n";
    warn << "identical fhdb:     " << identical_fhdb << "\n\n\n";

    warn << "Database contents:\n";
    warn << "Regular inodes:      " << reginode_cnt << "\n";
    warn << "Symlink inodes:      " << lnkinode_cnt << "\n";
    warn << "Directory blocks     " << directory_cnt << "\n";
    warn << "File data blocks:    " << filedatablk_cnt << "\n";
    warn << "Indir blocks:        " << indir_cnt << "\n";
    warn << "Fhdb blocks:         " << fhdb_cnt << "\n\n\n";

    warn << "identical fh's overall : " << identical_fh << "\n";
    warn << "unique fh's overall    : " << fh_cnt << "\n\n\n";
  }

  warn << "close db\n";

  sfsrodb->closedb ();
  delete sfsrodb;
  
  return 0;
}


static void
usage ()
{
  warnx << "usage: " << progname
	<< " -d <export directory> -s <SK keyfile> -o <dbfile>\n";
  warnx << "              [-i] [-h <hostname for db>] [-v] [-b <blocksize>]\n";
  warnx << "-d <export directory> : The directory hierarchy to export\n";
  warnx << "-s <SK keyfile>       : Path to the secret key file\n";
  warnx << "-o <dbfile>           : Filename to output database\n";
  warnx << "Optional directives:\n";
  warnx << "                        or 256-bit group key in hex\n";
  warnx << "-u                    : Update an existing database\n";
  warnx << "-h <hostname for db>  : Hostname of replication, if not this machine\n";
  warnx << "-p                    : Make all directories opaque\n";
  warnx << "-t <expiration>       : Seconds until signature expires\n";
  warnx << "-v                    : Verbose debugging output\n";
  warnx << "-b <blocksize>        : Page size of underlying database\n";
  warnx << "-g <group key file>   : File containing group key update to seal database\n";

  //  warnx << "usage: " << progname << " [command] [options]\n\n";
  //warnx << "\tinit directory [-d sdb file] [-followsymlinks] [-maxdepth max] [-key keyfile]\n";
  //  warnx << "\tupdate directory \n";
  exit (1);
}


int
main (int argc, char **argv)
{
  setprogname (argv[0]);
  random_update ();

  hostname = myname ();

  char *exp_dir = NULL;
  char *sk_file = NULL;
  char *output_file = NULL;

  update_mode = false;
  verbose_mode = false;
  error_check = true;

#ifdef SFSRO_PROXY
    Big s,p1,p2,p,q,t,n,cof,x,y;
    
    irand((long)123456789);
    ReadParamsFile("publicparams.cfg", proxy_params);

    //
    // Read in the main recipient's public (and secret) key
    //
    str publickeyfile ("master.pub.key");
    str privatekeyfile ("master.pri.key");

    ReadPublicKeyFile(const_cast<char *> (publickeyfile.cstr()), proxy_PublicKey);
    ReadSecretKeyFile(const_cast<char *> (privatekeyfile.cstr()), proxy_SecretKey);

    ECn c1;
    ZZn2 c2;
    p1=rand(proxy_params.q);

    warn << "Params.bits " << proxy_params.bits << "\n";

    char c[1000];
    int len = to_binary (p1, 1000, c, 0);

    if (len<=0) 
      fatal << "to_binary failed\n";
    warn << " Plaintext p1=" << hexdump(c, len) << "\n\n";

    if (proxy_level2_encrypt(proxy_params, p1, proxy_PublicKey, c1, c2) == FALSE) {
      warn << "Encryption failed\n";
      exit(1);
    }


    len = ECnTochar (c1, c, 1000);

    if (len<=0) 
      fatal << "ECnTochar failed\n";
    warn << " Encryption c1=" << hexdump(c, len) << "\n\n";

    c1 = charToECn (c);
    len = ECnTochar (c1, c, 1000);
    warn << "2Encryption c1=" << hexdump(c, len) << "\n\n";

    len = ZZn2Tochar (c2, c, 1000);
    if (len<=0) 
      fatal << "ZZn2Tochar failed\n";
    warn << " Encryption c2=" << hexdump(c, len) << "\n\n";


    c2 = charToZZn2 (c);
    len = ZZn2Tochar (c2, c, 1000);
    if (len<=0) 
      fatal << "2ZZn2Tochar failed\n";
    warn << "2Encryption c2=" << hexdump(c, len) << "\n\n";

    //
    // Decrypt the plaintext under the secret key
    //
    Big decryption;
    if (proxy_decrypt_level2(proxy_params, c1, c2, proxy_SecretKey, decryption) == FALSE ||
	decryption != p1) {
      warn << "Decryption failed\n";
      exit(1);
    }

    
    len = to_binary(decryption,1000,c,FALSE);
    if (len<=0) 
      fatal << "to_binary failed\n";
    warn << "Decrypted result= " <<  hexdump(c, len) << "\n\n";
#endif

  int ch;
  while ((ch = getopt (argc, argv, "b:d:g:s:o:h:t:vupe")) != -1)
    switch (ch) {
    case 'b':
      if (!convertint (optarg, &blocksize)
	  || blocksize < 512 || blocksize > 0x10000)
	usage ();
      break;
    case 'd':
      exp_dir = optarg;
      break;
    case 'e':
      error_check = false;
      break;
    case 'g':
      {
	kr = New refcounted<keyregression> (optarg);
	if (!kr) {
	  warn << "Unable to open keyfile " << optarg << "\n";
	  error_check = true;
	  break;
	}
	curr_vers = kr->curr_vers ();
#ifdef SFSRO_PROXY
	ref<rpc_bytes<> > l = New refcounted<rpc_bytes<> > ();
	l->setsize (16);
	rnd.getbytes (l->base (), l->size ());
	kr->set_proxy (l);
#endif
	break;
      }
    case 'h':
      hostname = optarg;
      break;
    case 'u':
      update_mode = true;
      break;
    case 'o':
      output_file = optarg;
      break;
    case 'p':
      opaque_directory = true;
      break;
    case 's':
      sk_file = optarg;
      break;
    case 't':
      if (!convertint (optarg, &sfsro_duration))
	usage ();
      break;
    case 'v':
      verbose_mode = true;
      break;
    case '?':
    default:
      usage ();
    }
  argc -= optind;
  argv += optind;

  if ( (argc > 0) || !exp_dir || !sk_file || !output_file )
    usage ();

  const char *pp = hostname;
  if (error_check && !sfsgethost (pp)) {
    warnx << "The hostname " << hostname << " does not properly resolve.\n"
	  << "The SFS server requires hostnames to resolve via DNS,\n"
	  << "not /etc/hosts.  If you wish to continue, rerun SFSRODB\n"
	  << "with the -e flag.\n";
    usage ();
  }

  struct stat st;
  bool file_exists = (lstat (output_file, &st) >= 0);
  if (!update_mode && file_exists) {
    warnx << output_file << ": Remove to create new database\n";
    usage ();
  } else if (update_mode && !file_exists) {
    warnx << output_file << ": Database does not exist for updating\n";
    usage ();
  }

  if (verbose_mode) {
    warnx << "export directory : " << exp_dir << "\n";
    warnx << "SK keyfile       : " << sk_file << "\n";
    warnx << "dbfile           : " << output_file << "\n";
    warnx << "Update mode      : ";
    if (update_mode) 
      warnx << "On\n";
    else
      warnx << "Off\n";

    warnx << "hostname for db  : " << hostname << "\n";
  }
  
  return (sfsrodb_main (exp_dir, sk_file, output_file));
}

