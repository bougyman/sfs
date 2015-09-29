/* $Id: test_esign.C,v 1.7 2004/09/20 00:53:56 dm Exp $ */

/*
 *
 * Copyright (C) 1998 David Mazieres (dm@uun.org)
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


#include "crypt.h"
#include "esign.h"
#include "bench.h"

u_int64_t vtime;
u_int64_t stime;

void
test_key_sign (esign_priv &sk)
{
  u_int64_t tmp, tmp2, tmp3;
  bool ret;
  for (int i = 0; i < 50; i++) {
    size_t len = rnd.getword () % 256;
    wmstr wmsg (len);
    rnd.getbytes (wmsg, len);
    str msg1 = wmsg;

    tmp = get_time ();
    bigint m = sk.sign (msg1);
    tmp2 = get_time ();
    ret = sk.verify (msg1, m);
    tmp3 = get_time ();

    vtime += (tmp3 - tmp2);
    stime += (tmp2 - tmp);

    if (!ret)
      panic << "Verify failed\n"
	    << "  p = " << sk.p << "\n"
	    << "  q = " << sk.q << "\n"
	    << "msg = " << hexdump (msg1.cstr (), msg1.len ()) << "\n"
	    << "sig = " << m << "\n";
    int bitno = rnd.getword () % mpz_sizeinbase2 (&m);
    m.setbit (bitno, !m.getbit (bitno));
    if (sk.verify (msg1, m))
      panic << "Verify should have failed\n"
	    << "  p = " << sk.p << "\n"
	    << "  q = " << sk.q << "\n"
	    << "msg = " << hexdump (msg1.cstr (), msg1.len ()) << "\n"
	    << "sig = " << m << "\n";
  }
}

int
main (int argc, char **argv)
{
  setprogname (argv[0]);
  random_update ();
  int k = 0;

  vtime = stime = 0;
  int sz = 2048;

  bool opt_v = false;

  if (argc > 1 && !strcmp (argv[1], "-v"))
    opt_v = true;
  if (argc > 2  && !(sz = atoi (argv[2]))) 
    fatal << "bad argument\n";
  if (argc > 3 && !(k = atoi (argv[3])))
    fatal << "bad argument\n";

  for (int i = 0; i < 10; i++) {
    int nbits = 424 + rnd.getword () % 256;
    esign_priv sk = k ? esign_keygen (nbits, k) : esign_keygen (nbits);
    test_key_sign (sk);
  }
  for (int i = 0; i < 10; i++) {
    int nbits = 424 + rnd.getword () % 256;
    esign_priv sk = k ? esign_keygen (nbits, k) : esign_keygen (nbits);
    sk.precompute ();
    test_key_sign (sk);
  }

  if (opt_v) {
    u_int64_t tmp, tmp2, tmp3;
    size_t len = rnd.getword () % 256;
    wmstr wmsg (len);
    rnd.getbytes (wmsg, len);
    str msg1 = wmsg;
    bigint m;
    bool ret;

    esign_priv sk = k ? esign_keygen (sz, k) : esign_keygen (sz);

    tmp = get_time ();
    for (int i = 0; i < 5000; i++)
      m = sk.sign (msg1);
    tmp2 = get_time ();
    for (int i = 0; i < 5000; i++)
      ret = sk.verify (msg1, m);
    tmp3 = get_time ();

    assert (ret);

    vtime = (tmp3 - tmp2);
    stime = (tmp2 - tmp);

    warn ("Signed 5000 msgs with %d bit key in %" U64F "u " 
	  TIME_LABEL " per signature\n", sz, stime / 5000);
    warn ("Verified 5000 msgs with %d bit key in %" U64F "u " 
	  TIME_LABEL " per verify\n", sz, vtime / 5000);

#if 1
    tmp = get_time ();
    for (int i = 0; i < 5000; i++)
      sk.precompute ();
    tmp2 = get_time ();
    for (int i = 0; i < 5000; i++)
      m = sk.sign (msg1);
    tmp3 = get_time ();

    ret = sk.verify (msg1, m);
    assert (ret);
#endif

    tmp = get_time ();
    for (int i = 0; i < 5000; i++)
      sk.precompute ();
    tmp2 = get_time ();
    for (int i = 0; i < 5000; i++)
      m = sk.sign (msg1);
    tmp3 = get_time ();

    ret = sk.verify (msg1, m);
    assert (ret);


    vtime = (tmp3 - tmp2);
    stime = (tmp2 - tmp);

    warn ("Precomputed 5000 sigs with %d bit key in %" U64F "u " 
	  TIME_LABEL " per sig\n", sz, stime / 5000);
    warn ("Did 5000 precomputed sigs with %d bit key in %"
	  U64F "u " TIME_LABEL " per sig\n", sz, vtime / 5000);
  }
  return 0;
}

void
dump (bigint *bi)
{
  warn << *bi << "\n";
}
