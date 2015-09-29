/* $Id: sfsrodb_core.h,v 1.30 2004/09/19 22:02:32 dm Exp $ */

/*
 *
 * Copyright (C) 2000 Kevin Fu (fubob@mit.edu)
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

#ifndef _SFSRODB_CORE_H_
#define _SFSRODB_CORE_H_

#include "sysconf.h"
#include "sfsro_prot.h"
#include "crypt.h"
#include "str.h"
#include "sha1.h"
#include "xdrmisc.h"
#include "dbfe.h"
#include "sfscrypt.h"
#include "aes.h"

/* Define SFSRO_PROXY if using proxy re-encryption */
//#define SFSRO_PROXY 1

/* Experiment with proxy re-encryption */
#ifdef SFSRO_PROXY
#include "/home/fubob/src/proxyfs/miracl/elliptic.h"
#include "/home/fubob/src/proxyfs/miracl/monty.h"
#include "/home/fubob/src/proxyfs/miracl/zzn2.h"
#include "/home/fubob/src/proxyfs/pairing.h"
#endif

template<class T>
bool
sfsrodb_put (dbfe *db, const void *keydata, size_t keylen, T &t)
{
  //xdrsuio x (XDR_ENCODE, scrub); // what is scrub? this doesn't compile -dm
  xdrsuio x (XDR_ENCODE);
  XDR *xp = &x;
  if (!rpc_traverse (xp, const_cast<T &> (t)))
    return false;
  
  ref<dbrec> data = new refcounted<dbrec>(x.uio ()->resid ());
  x.uio ()->copyout (data->value);
  ref<dbrec> key = new refcounted<dbrec>((void *) keydata, keylen);
  int err = db->insert (key, data);

  if (err) {
    warn << "insert returned " << err << strerror(err) << "\n";
    return false;
  } else 
    return true;
}

bool sfsrodb_put (dbfe *db, const void *keydata, size_t keylen, 
		  void *contentdata, size_t contentlen);

template<class T>
bool
sfsrodb_get (dbfe *db, const void *keydata, size_t keylen, T &t)
{
  ref<dbrec> key = new refcounted<dbrec>((void *) keydata, keylen);
  ptr<dbrec> res = db->lookup (key);
  if (!res) {
    warn << "lookup failed on " << (char *)keydata << "\n";
    return false;
  }

  xdrmem x ((char *)res->value, res->len);
  XDR *xp = &x;
  return rpc_traverse (xp, t);
}


/*
  Requires: You have at some point called random_init();
  Given: A filled buffer and allocated fh
  Return: A file handle in fh.  Generate random bytes for the first
  SFSRO_IVSIZE bytes in the opaque fh.  Add fh to fh_list
*/
void create_sfsrofh (char *iv, uint iv_len, sfs_hash *fh,
		     char *buf, size_t buflen);

void create_sfsrofh2 (char *iv, uint iv_len, sfs_hash *fh, str s);


/*
  Given: A filled buffer and allocated fh
  Return: True if the file handle verifies as cryptographically secure
*/
bool verify_sfsrofh (char *iv, uint iv_len,
		     const sfs_hash *fh, 
		     char *buf, size_t buflen);



struct b16 {
  enum { nc = 16, nl = nc / sizeof (long) };
  union {
    char c[nc];
    long l[nl];
  };
};

void cbcencrypt (aes *cp, void *_d, const void *_s, int len);
void cbcdecrypt (aes *cp, void *_d, const void *_s, int len);

/* PKCS 7 padding */
bool xdrsuio2pkcs (xdrsuio &x, size_t n = RPC_INFINITY);

template<class T, size_t n> bool
xdr2pkcs (rpc_bytes<n> &out, const T &t, bool scrub = false)
{
  xdrsuio x (XDR_ENCODE, scrub);
  XDR *xp = &x;
  if (!rpc_traverse (xp, const_cast<T &> (t)) || x.uio ()->resid () > n)
    return false;

  if (!xdrsuio2pkcs (x, n))
    return false;

  if (scrub)
    bzero (out.base (), out.size ());
  out.setsize (x.uio ()->resid ());
  x.uio ()->copyout (out.base ());
  return true;
}


template<class T, size_t n>
bool
pkcs2xdr (T &t, rpc_bytes<n> &in)
{
  /* Size ranges from 1 to 255 */
  int size = (int)in.pop_back ();
  if (size < 1) {
    warn << "pkcs2xdr size too small\n";
    return false;
  }

  for (int i = 1; i < size; i++) {
    if ((int)in.pop_back() != size) {
      warn << "Bad padding\n";
      return false;
    }
  }

  xdrmem x (in.base (), in.size ());
  XDR *xp = &x;
  return rpc_traverse (xp, t);
}

/* Get the key in the lockbox */
ptr<rpc_bytes<> > lockboxkey (ptr<rpc_bytes<> > gk, sfsro_sealed *ct
#ifdef SFSRO_PROXY
			      , ZZn2 *Zc1 = NULL
#endif
);

/* Given: gk, sealed ct, and t
   Return: Decrypt and unmarshal into t
   Modifies: ct, t
*/
template<class T>
bool
unseal (ptr<rpc_bytes<> > gk, sfsro_sealed *ct, T *t
#ifdef SFSRO_PROXY
			      , ZZn2 *Zc1 = NULL
#endif
)
{
  if (!ct || !gk || !t)
    return false;

#ifdef SFSRO_PROXY
  ptr<rpc_bytes<> > lox = lockboxkey (gk, ct, Zc1);
#else
  ptr<rpc_bytes<> > lox = lockboxkey (gk, ct);
#endif

  if (!lox)
    return false;

  aes ctx;
  ctx.setkey (lox->base (), lox->size ());
  cbcdecrypt (&ctx, 
	      ct->pkcs7.base (),
	      ct->pkcs7.base (),
	      ct->pkcs7.size ());
    
  T tmp;
  if (!pkcs2xdr (tmp, ct->pkcs7)) {
    warn << "pkcs2xdr failed\n";
    return false;
  }
  *t = tmp;
  
  return true;
}

void seal (ptr<rpc_bytes<> > gk, sfsro_data &encres, 
	   rpc_bytes<> *lox);
void seal_xdrsuio (ptr<rpc_bytes<> > gk, uint32 vers, 
		   sfsro_data *res, xdrsuio &x, ptr<rpc_bytes<> > lox);
void seal_sfsro_data (ptr<rpc_bytes<> > gk, uint32 vers,
		      sfsro_data *res, ptr<rpc_bytes<> > lox,
		      sfsro_lockboxtype lt = SFSRO_AES);

#endif /* _SFSRODB_CORE_H_ */
