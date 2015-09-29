/* $Id: sfsrodb_core.C,v 1.28 2004/08/24 20:17:00 fubob Exp $ */

/*
 *
 * Copyright (C) 1999 Kevin Fu (fubob@mit.edu)
 * and Frans Kaashoek (kaashoek@mit.edu)
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

#include "sfsrodb_core.h"

/* Experiment with proxy re-encryption */
#ifdef SFSRO_PROXY
#include "/home/fubob/src/proxyfs/miracl/elliptic.h"
#include "/home/fubob/src/proxyfs/miracl/monty.h"
#include "/home/fubob/src/proxyfs/miracl/zzn2.h"
extern Miracl precision;
#include "/home/fubob/src/proxyfs/pairing.h"
CurveParams gParams;
ProxyPK proxy_PublicKey;
ProxySK proxy_SecretKey;
ProxyPK proxy_DelegatePublicKey;
ProxySK proxy_DelegateSecretKey;
CurveParams proxy_params;
ECn proxy_delegationKey;
#endif

/* Return false if duplicate key */
bool
sfsrodb_put (dbfe *db, const void *keydata, size_t keylen, 
	     void *contentdata, size_t contentlen)
{
  int err;

  ref<dbrec> key = new refcounted<dbrec>((void *) keydata, keylen);
  ref<dbrec> data = new refcounted<dbrec>((void *) contentdata, contentlen);
  err = db->insert(key, data);
  if (err) {
    warn << "insert returned " << err << strerror(err) << "\n";
    return false;
  } else 
    return true;
}


/* Library SFRODB routines used by the database creation,
   server, and client.  */

void
create_sfsrofh (char *iv, uint iv_len,
		sfs_hash *fh, char *buf, size_t buflen)
{
  assert (iv_len == SFSRO_IVSIZE);

  bzero(fh->base (), fh->size ());
  struct iovec iov[2];
  iov[0].iov_base = static_cast<char *>(iv);
  iov[0].iov_len = SFSRO_IVSIZE;  
  iov[1].iov_base = buf;
  iov[1].iov_len = buflen;

  sha1_hashv (fh->base (), iov, 2);
}

void create_sfsrofh2 (char *iv, uint iv_len, sfs_hash *fh, str s)
{
  create_sfsrofh (iv, iv_len, fh, (char *)s.cstr (), s.len ());
}

bool
verify_sfsrofh (char *iv, uint iv_len,
		const sfs_hash *fh,
		char *buf, size_t buflen)
{
  assert (iv_len == SFSRO_IVSIZE);

  char tempbuf[fh->size ()];
  struct iovec iov[2];

  iov[0].iov_base = static_cast<char *>(iv);
  iov[0].iov_len = SFSRO_IVSIZE;
  
  iov[1].iov_base = buf;
  iov[1].iov_len = buflen;

  sha1_hashv (tempbuf, iov, 2);

  if (memcmp (tempbuf, fh->base (), fh->size ()) == 0) {
    return true;
  }

  warnx << "XXX verify_sfsrofh: hash doesn't match\n";
  warnx << "Given    fh: " << hexdump(fh->base (), fh->size ()) << "\n";
  warnx << "Computed fh: " << hexdump(tempbuf, fh->size ()) << "\n";

  return false;
}


inline void
b16xor (b16 *d, const b16 &s)
{
  for (int i = 0; i < b16::nl; i++)
    d->l[i] ^= s.l[i];
}
inline void
b16xor (b16 *d, const b16 &s1, const b16 &s2)
{
  for (int i = 0; i < b16::nl; i++)
    d->l[i] = s1.l[i] ^ s2.l[i];
}


// XXX perhaps add an IV.  since each block has separate
// key, might be ok  
void
cbcencrypt (aes *cp, void *_d, const void *_s, int len)
{
  assert (!(len & 15));
  len >>= 4;

  const b16 *s = static_cast<const b16 *> (_s);
  b16 *d = static_cast<b16 *> (_d);

  if (len-- > 0) {
    cp->encipher_bytes (d->c, (s++)->c);
    while (len-- > 0) {
      b16 tmp;
      b16xor (&tmp, *d++, *s++);
      cp->encipher_bytes (d->c, tmp.c);
    }
  }
}


void
cbcdecrypt (aes *cp, void *_d, const void *_s, int len)
{
  assert (!(len & 15));
  len >>= 4;
  const b16 *s = static_cast<const b16 *> (_s) + len;
  b16 *d = static_cast<b16 *> (_d) + len;

  if (len-- > 0) {
    --s;
    while (len-- > 0) {
      cp->decipher_bytes ((--d)->c, s->c);
      b16xor (d, *--s);
    }
    cp->decipher_bytes ((--d)->c, s->c);
  }
}
/* PKCS #7 padding */
bool xdrsuio2pkcs (xdrsuio &x, size_t n)
{
  XDR *xp = &x;
  int size = 16 - (x.uio ()->resid () % 16);
  char *pad;
  if ((pad = (char *) XDR_INLINE (xp, size)) && 
      (x.uio ()->resid () <= n)) {
    memset (pad, (char)size, size);
  } else
    return false;
  
  if (x.uio ()->resid () & 15) {
    warn << "pkcs7 padding didn't make plaintext 16 byte multiple\n";
    return false;
  }
  
  return true;
}

ptr<rpc_bytes<> >
lockboxkey (ptr<rpc_bytes<> > gk, sfsro_sealed *ct
#ifdef SFSRO_PROXY
	    , ZZn2 *Zc1
#endif
	    )
{
  ptr<rpc_bytes<> > lox = New refcounted<rpc_bytes<> > ();

  if (ct->lt == SFSRO_PROXY_REENC) {
#ifdef SFSRO_PROXY
    ECn c1;
    ZZn2 c2;

    char *buf = ct->lockbox.base ();
    int len;

    memcpy (&len, buf, sizeof (int));
    buf += sizeof (int);
    c1 = charToECn (buf);
    buf += len;

    memcpy (&len, buf, sizeof (int));
    buf += sizeof (int);
    c2 = charToZZn2 (buf);

    Big decryption;
    if (Zc1) {
      /*
      char buff[1024];
      int len = ZZn2Tochar (*Zc1, buff, 1024);
      warnx << "XXZc1: (" << len << ") " << hexdump(buff, len) << "\n";

      len = ZZn2Tochar (c2, buff, 1024);
      warnx << "XXc2: (" << len << ") " << hexdump(buff, len) << "\n";

      len = to_binary (proxy_DelegateSecretKey.s1, 1024, buff, FALSE);
      warnx << "XXdelegateS1: (" << len << ") " << hexdump(buff, len) << "\n";

      len = to_binary (proxy_DelegateSecretKey.s2, 1024, buff, FALSE);
      warnx << "XXdelegateS2: (" << len << ") " << hexdump(buff, len) << "\n";
      */

      if (proxy_decrypt_reencrypted(proxy_params, *Zc1, c2, 
				    proxy_DelegateSecretKey, decryption)
	  == FALSE) 
	fatal << "Final delegate decryption failed\n";
    } else {
      warn << "Zc1 null\n";
      if (proxy_decrypt_level2(proxy_params, c1, c2, proxy_SecretKey, decryption)
	  == FALSE) {
	fatal << "Decryption failed\n";
      }
    }

    lox->setsize (16);

    len = to_binary(decryption, lox->size (), lox->base (), TRUE);
    if (len<=0) 
      fatal << "to_binary failed\n";
    warn << "lox= (" << len << ") "
	 << hexdump(lox->base (), lox->size()) << "\n\n";
#endif
  } else {
    aes ctx;
    ctx.setkey (gk->base (), gk->size ());
    
    assert (ct->lockbox.size () == 16);
    lox->setsize (16);
    cbcdecrypt (&ctx, 
		lox->base (),
		ct->lockbox.base (),
		ct->lockbox.size ());
  }
  
  return lox;
}

/* replace plaintext with ciphertext 
   XXX ought to be typed to prevent accidental plaintext leakage
*/
void seal (ptr<rpc_bytes<> > gk, sfsro_data &encres, 
	   rpc_bytes<> *lox)
{
  assert (gk);

  encres.ct->lockbox.setsize (16);
  if (!lox) {
    rnd.getbytes (encres.ct->lockbox.base (), encres.ct->lockbox.size ());
  } else {
    encres.ct->lockbox.set (lox->base (), lox->size ());
  }

  assert (encres.ct->lockbox.size () == 16);

  aes ctx;
  ctx.setkey (encres.ct->lockbox.base (), 
	      encres.ct->lockbox.size ());
  cbcencrypt (&ctx, 
	      encres.ct->pkcs7.base (),
	      encres.ct->pkcs7.base (),
	      encres.ct->pkcs7.size ());


  if (encres.ct->lt == SFSRO_AES) {
    ctx.setkey (gk->base (), gk->size ());
    cbcencrypt (&ctx, 
		encres.ct->lockbox.base (),
		encres.ct->lockbox.base (), 
		encres.ct->lockbox.size ());
  } else {
#ifdef SFSRO_PROXY
    // leading zeros?
    Big pt = from_binary (encres.ct->lockbox.size (),
			  encres.ct->lockbox.base ());
    ECn c1;
    ZZn2 c2;
    if (proxy_level2_encrypt (proxy_params, pt, proxy_PublicKey, c1, c2) == FALSE) {
      warn << "private fsinfo proxy encryption failed\n";
      exit(1);
    }

    // Ciphertext bytes = params.bits*4/8 + 8
    encres.ct->lockbox.setsize (proxy_params.bits/2 + 6*sizeof(int));
    int len;

    char *buf = encres.ct->lockbox.base () + sizeof(int);
    int bufsize = encres.ct->lockbox.size () - sizeof(int);
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
    fatal << "Should never reach this code\n";
#endif
  }
}

/* Given a partially filled xdrsuio, store
   the sealed, PKCS7-padded version in res.
*/
void seal_xdrsuio (ptr<rpc_bytes<> > gk, uint32 vers, 
		   sfsro_data *res, xdrsuio &x, 
		   ptr<rpc_bytes<> > lox)
{
  assert (gk);
  sfsro_data encres (SFSRO_SEALED);
  encres.ct->gk_vers = vers; 
  encres.ct->lt = SFSRO_AES;
    
  if (!xdrsuio2pkcs (x)) {
    fatal << "xdrsuio2pkcs failed\n";
  }
  
  encres.ct->pkcs7.setsize (x.uio ()->resid ());
  x.uio ()->copyout (encres.ct->pkcs7.base ());
  seal (gk, encres, lox);

  *res = encres;
}

/* Given an sfsro_data structure, replace its contents with a sealed,
   PKCS7-padded version.  */
void seal_sfsro_data (ptr<rpc_bytes<> > gk, uint32 vers, sfsro_data *res, 
		      ptr<rpc_bytes<> > lox, sfsro_lockboxtype lt)
{
  assert (res);
  assert (gk);

  sfsro_data encres (SFSRO_SEALED);
  encres.ct->gk_vers = vers; 
  encres.ct->lt = lt;
    
  if (!xdr2pkcs (encres.ct->pkcs7,
		 *res)) {
    fatal << "xdr2pkcs failed\n";
  }

  seal (gk, encres, lox);
  *res = encres;
}
