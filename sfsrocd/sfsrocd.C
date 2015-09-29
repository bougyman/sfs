/* $Id: sfsrocd.C,v 1.28 2004/08/24 15:51:48 fubob Exp $ */

/*
 *
 * Copyright (C) 1999, 2000, 2001 Kevin Fu (fubob@mit.edu)
 * Copyright (C) 2000 David Mazieres (dm@uun.org)
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

#include "sfsrocd.h"
#include "sfsrodb_core.h"
#include "rxx.h"

/* Experiment with proxy re-encryption */
#ifdef SFSRO_PROXY
#include "/home/fubob/src/proxyfs/miracl/elliptic.h"
#include "/home/fubob/src/proxyfs/miracl/monty.h"
#include "/home/fubob/src/proxyfs/miracl/zzn2.h"
extern Miracl precision;
#include "/home/fubob/src/proxyfs/pairing.h"
static CurveParams gParams;
extern ProxyPK proxy_PublicKey;
extern ProxySK proxy_SecretKey;
extern ProxyPK proxy_DelegatePublicKey;
extern ProxySK proxy_DelegateSecretKey;
extern CurveParams proxy_params;
extern ECn proxy_delegationKey;
#endif

str gk_directory = NULL;

#ifdef MAINTAINER
const bool sfsrocd_noverify = (getenv ("SFSROCD_NOVERIFY"));
const bool sfsrocd_nocache = (getenv ("SFSROCD_NOCACHE"));
const bool sfsrocd_cache_stat = (getenv ("SFSROCD_CACHE_STAT"));
const bool sfsrocd_proxylocal = (getenv ("SFSROCD_PROXYLOCAL")); /* Do re-enc locally? */
const bool sfsrocd_proxymaster = (getenv ("SFSROCD_PROXYMASTER")); /* Don't reenc, just decrypt with master? */


void
show_stats (int sig)
{
  warn << "Caught signal " << sig << "\n";

  if (sfsrocd_cache_stat) {

    warn << "Cache analysis follows.\n";
  
    warn << "Inode cache:\n";
    if (cstat.namec_tot > 0) {
      warn << "Hit  "
	   << static_cast<u_int32_t>((100*cstat.namec_hit)/cstat.namec_tot) 
	   << "% (" << cstat.namec_hit << " hits)\n";
      warn << "Miss "
	   << static_cast<u_int32_t>((100*cstat.namec_miss)/cstat.namec_tot) 
	   << "% (" << cstat.namec_miss << " misses)\n";
      warn << "Total " << cstat.namec_tot << " requests\n\n";
    } else {
      warn << "No inodes requested\n\n";
    }

    warn << "Directory cache:\n";
    if (cstat.directoryc_tot > 0) {
      warn << "Hit  "
	   << static_cast<u_int32_t>
	((100*cstat.directoryc_hit)/cstat.directoryc_tot) 
	   << "% (" << cstat.directoryc_hit << " hits)\n";
      warn << "Miss "
	   << static_cast<u_int32_t>
	((100*cstat.directoryc_miss)/cstat.directoryc_tot) 
	   << "% (" << cstat.directoryc_miss << " misses)\n";
      warn << "Total " << cstat.directoryc_tot << " requests\n\n";
    } else {
      warn << "No directory blocks requested\n\n";
    }
      

    warn << "Indirect block cache:\n";
    if (cstat.iblockc_tot > 0) {
      warn << "Hit  "
	   << static_cast<u_int32_t>((100*cstat.iblockc_hit)/cstat.iblockc_tot)
	   << "% (" << cstat.iblockc_hit << " hits)\n";
      warn << "Miss "
	   << static_cast<u_int32_t>
	((100*cstat.iblockc_miss)/cstat.iblockc_tot) 
	   << "% (" << cstat.iblockc_miss << " misses)\n";
      warn << "Total " << cstat.iblockc_tot << " requests\n\n";
    } else {
      warn << "No indirect blocks requested\n\n";
    }

    warn << "File data block cache:\n";
    if (cstat.blockc_tot > 0) {
      warn << "Hit  "
	   << static_cast<u_int32_t>((100*cstat.blockc_hit)/cstat.blockc_tot) 
	   << "% (" << cstat.blockc_hit << " hits)\n";
      warn << "Miss "
	   << static_cast<u_int32_t>((100*cstat.blockc_miss)/cstat.blockc_tot)
	   << "% (" << cstat.blockc_miss << " misses)\n";
      warn << "Total " << cstat.blockc_tot << " requests\n\n";
    } else {
      warn << "No file data blocks requested\n\n";
    }
  }

  exit(0);
}

void
cpu_time ()

{
  struct rusage ru;
  double res = 0;
  
  if (getrusage (RUSAGE_SELF, &ru) != 0) {
    warnx << "Getrusage: self failed\n";
    exit (1);
  }

  res += (ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) * 1e6;
  res += ru.ru_utime.tv_usec + ru.ru_stime.tv_usec;
    

  if (getrusage (RUSAGE_CHILDREN, &ru) != 0) {
    warnx << "Getrusage: child failed\n";
    exit (1);
  }

  res += (ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) * 1e6;
  res += ru.ru_utime.tv_usec + ru.ru_stime.tv_usec;

  printf ("CPU time: %f\n", res);

  sigcb (SIGUSR1, wrap (cpu_time));
}
#endif /* MAINTAINER */


int
main (int argc, char **argv)
{
#ifdef MAINTAINER
  if (sfsrocd_noverify) 
    warn << "SFSROCD_NOVERIFY\n";
  if (sfsrocd_nocache)
    warn << "SFSROCD_NOCACHE\n";
  if (sfsrocd_cache_stat) 
    warn << "SFSROCD_CACHE_STAT\n";
  if (sfsrocd_proxylocal)
    warn << "SFSROCD_PROXYLOCAL\n";
  if (sfsrocd_proxymaster)
    warn << "SFSROCD_PROXYMASTER\n";
#endif /* MAINTAINER */

  setprogname (argv[0]);
  warn ("version %s, pid %d\n", VERSION, int (getpid ()));

  if (argc == 2) {
    gk_directory = argv[1];
    warn << "Key directory: " << gk_directory << "\n";
  } else if (argc != 1)
    fatal ("usage: %s\n", progname.cstr ());

  sfsconst_init ();
  random_init_file (sfsdir << "/random_seed");
  // Note, we use this randomness later in the fhtt of server.C

  if (ptr<axprt_unix> x = axprt_unix_stdin ())
    vNew sfsprog (x, &sfsserver_alloc<server>);
  else
    fatal ("could not get connection to sfscd.\n");

#ifdef MAINTAINER
  //sigcb (SIGUSR1, wrap (cpu_time));
  sigcb (SIGINT, wrap (show_stats, 1));
#endif

#ifdef SFSRO_PROXY
    ReadParamsFile("publicparams.cfg", proxy_params);

    //
    // Read in the main recipient's public (and secret) key
    //
    str publickeyfile ("master.pub.key");
    str privatekeyfile ("master.pri.key");

    ReadPublicKeyFile(const_cast<char *> (publickeyfile.cstr()), proxy_PublicKey);
    ReadSecretKeyFile(const_cast<char *> (privatekeyfile.cstr()), proxy_SecretKey);

    str dpublickeyfile ("user.pub.key");
    str dprivatekeyfile ("user.pri.key");

    ReadPublicKeyFile(const_cast<char *> (dpublickeyfile.cstr()), 
		      proxy_DelegatePublicKey);
    ReadSecretKeyFile(const_cast<char *> (dprivatekeyfile.cstr()), 
		      proxy_DelegateSecretKey);

    if (proxy_delegate(proxy_params, proxy_DelegatePublicKey, 
		       proxy_SecretKey, proxy_delegationKey)
	== FALSE) {
      fatal << "Delegation failed\n";
    }
#endif

  amain ();
}


