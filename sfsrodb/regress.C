/* $Id: regress.C,v 1.5 2004/04/19 23:43:45 anjali Exp $ */

/*
 *
 * Copyright (C) 2004 Kevin Fu (fubob@mit.edu)
 * Copyright (C) 2004 Anjali Prakash (anjali@cs.jhu.edu)
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


#include "rxx.h"
#include "parseopt.h"
#include "keyregression.h"

ptr<keyregression_owner> kro;

static void usage ()
{
  warnx << "usage: " << progname
	<< " -c -i <id> -d <directory> [-p <protocol>] [-k <key size>] [-l <chain length>] [-m]\n";
  warnx << "-a -i <id> -d <directory> [-o <outfile>] [-W <window start vers>]\n";
  warnx << "-w -i <id> -d <directory>[-W <window start vers>]\n";
  warnx << "-u -i <id> -d <directory>\n";

  warnx << "-c     : Create a new group\n";
  warnx << "-a     : Add a member to a group, produce keyupdate\n";
  warnx << "-w     : Wind group key, produce keyupdate\n";
  warnx << "-u     : Unwind group key, produce keyupdate\n\n";
  
  warnx << "-i <id>        : Use group key with name id\n";
  warnx << "-d <directory> : Store in directory\n";
  warnx << "-p <protocol>  : Specify key regression protocol (e.g., sha1)\n";
  warnx << "-k <key size>  : Specify group key size in bytes\n";
  warnx << "-l <chain length>: For hash-based protocols, specify chain length\n";
  warnx << "-o <outfile>   : Store keyupdate in outfile\n";
  warnx << "-W <vers>      : Specifies the window start (group key version)\n";
  warnx << "-m             : Specifies that windowing is desired\n";
  warnx << "-v             : Prints the owner state and key update message\n";

  exit (1);
}


bool create_mode;
bool add_mode;  
bool wind_mode;
bool unwind_mode;
bool error_check;
bool window_mode;
bool verbose_mode;

uint32 id;
uint32 keysize;
uint32 chainlen;
uint32 window_startvers;
str protocol;
str directory;
str outfile;
sfsro_protocoltype type;

int
main (int argc, char **argv) {
  setprogname  (argv[0]);
  random_update ();

  create_mode = false;
  add_mode = false;
  wind_mode = false;
  unwind_mode = false;
  error_check = true;
  window_mode = false;
  verbose_mode = false;

  id = 0;
  keysize = 16;
  chainlen = 128;
  window_startvers = 0;
  protocol = strbuf () << "sha1";
  type = SFSRO_SHA1;
  directory = NULL;
  outfile = NULL; 

  int ch;
  while ((ch = getopt (argc, argv, "i:k:p:d:o:l:W:cawumv")) != -1)
    switch (ch) {
    case 'i':
      if (!convertint (optarg, &id))
	usage ();
      break;
    case 'k':
      if (!convertint (optarg, &keysize) 
	  || keysize < 16 || keysize > 32)
	usage ();
      break;
    case 'p':
      protocol = optarg;
      if (protocol == "sha1") 
	type = SFSRO_SHA1;
      else if(protocol == "rabin")
	type = SFSRO_RABIN;
      else
	usage ();
      break;
    case 'd':
      directory = optarg;
      break;
    case 'o':
      outfile = optarg;
      break;
    case 'c':
      create_mode= true;
      break;
    case 'a':
      add_mode= true;
      break;
    case 'w':
      wind_mode= true;
      break;
    case 'u':
      unwind_mode= true;
      break;
    case 'l':
      if (!convertint (optarg, &chainlen))
	  usage ();
      break;
    case 'W':
      if (!convertint (optarg, &window_startvers))
	  usage ();
      break;
    case 'm':
      window_mode = true;
      break;
    case 'v':
      verbose_mode = true;
      break;
    default:
      usage ();
    }
  argc -= optind;
  argv += optind;

  if ( (argc > 0) || !directory || !id  
       || ((create_mode + add_mode + wind_mode + unwind_mode) != 1)
       || !(create_mode || !window_mode))
    usage ();

  kro = New refcounted<keyregression_owner> (directory, id, type, keysize,
					     chainlen, create_mode, 
					     window_mode, verbose_mode);

  if (add_mode) {
    if (!kro->add (outfile, window_startvers, verbose_mode)) {
      warn << "kro->add failed\n";
      exit (1);
    }
  }

  if (wind_mode) {
    if (!kro->wind (outfile, verbose_mode)) {
      warn << "kro->wind failed\n";
      exit (1);
    }
  }

  /*
  if (unwind_mode) {
    if (!kro->unwind (outfile)) {
      warn << "kro->unwind failed\n";
      exit (1);
    }
  }
  */
}

