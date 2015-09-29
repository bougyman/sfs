/* $Id: keyregression.C,v 1.14 2004/08/20 20:35:03 fubob Exp $ */

/*
 *
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

#include "keyregression.h"
#include "rxx.h"

static void hashchain (void *out, void *in, uint32 chainlen) { 
  assert (out);
  assert (in);

  memcpy (out, in, sha1::hashsize);

  for (; chainlen > 0; chainlen--) 
    sha1_hash (out, out, sha1::hashsize);

  //warn << "hash: " << hexdump(out, sha1::hashsize) << "\n";
}

template<class T> static bool
file2xdr (ptr<T> t, str file) 
{
  assert (file);
  assert (t);

  str tstr = file2str (file);
  if (!tstr) {
    warn << "Unable to open " << file << "\n";
    warn << (errno ? strerror (errno) : "") << "\n";
    return false;
  }

  tstr = dearmor64 (tstr.cstr (), tstr.len () - 1);
  if (!tstr) {
    warn << "Unable to dearmor64\n";
    return false;
  }

  if (!str2xdr (*t, tstr)) {
    warn << "Unable to convert tstr to T.  Perhaps T type does not match tstr type?\n"; 
    return false;
  }

  return true;
}

template<class T> static bool
xdr2file (str file, ptr<T> t) 
{
  assert (file);
  assert (t);

  str tstr = xdr2str (*t);
  if (!tstr) {
    warn << "xdr2file: xdr2str failed\n";
    return false;
  }

  tstr = armor64 (tstr);
  if (!tstr) {
    warn << "xdr2file: armor64 failed\n";
    return false;
  }

  if (!str2file (file, tstr)) {
    warn << "Could not store T in " << file << "\n";
    warn << (errno ? strerror (errno) : "") << "\n";
    return false;
  }

  return true;
}


keyregression::keyregression (str infile)
{
  assert (infile);

  ku = New refcounted<sfsro_keyupdate> ();
  w = New refcounted<sfsro_window> ();

  str kufile = strbuf () << infile << ".ku";
  str wfile = strbuf () << infile << ".w";

  if (!file2xdr (ku, kufile)) {
    // XXX not a clean way to kill self
    fatal << "Unable to load " << kufile << "\n";
    return;
  }

  if (!file2xdr (w, wfile))
    w = NULL;
}

// Works on SHA1 only

ptr<rpc_bytes<> > 
keyregression::gk (uint32 i) {
#ifdef SFSRO_PROXY
  assert (proxy_lox);
  ptr<rpc_bytes<> > appkey = New refcounted<rpc_bytes<> >;
  appkey->setsize(proxy_lox->size ());
  memcpy(appkey->base (), proxy_lox->base (), proxy_lox->size ());
  return appkey;
#else
  if (i > ku->sub.vers) {
    warnx << "Do not have access to application key in future version " 
	 << i << "\n";
    return NULL;
  }

  if (w && i < w->vers) {
    warnx << "Do not have access to application key in past version " 
	  << i << "\n";
    return NULL;
  }
  
  ptr<rpc_bytes<> > appkey = 
    New refcounted<rpc_bytes<> >;
  ptr<rpc_bytes<> > subkey = 
    New refcounted<rpc_bytes<> >;
  appkey->setsize(ku->keysize);
  subkey->setsize(sha1::hashsize);

  hashchain (subkey->base (), ku->sub.key.base (), ku->sub.vers - i); 

  if (w) {
    ptr<rpc_bytes<> > window = 
      New refcounted<rpc_bytes<> >;
    window->setsize(sha1::hashsize);
    hashchain (window->base (), w->edge.base (), i - w->vers);

    for (uint32 i = 0; i < sha1::hashsize; i++) 
      *(subkey->base () + i) = *(subkey->base () + i) ^ *(window->base () + i);
  }
  
  // truncate the appkey to keysize 
  memcpy(appkey->base (), subkey->base (), ku->keysize);

  return appkey;
#endif
}

uint32
keyregression::curr_vers () {
  return ku->sub.vers;
}

uint32
keyregression::get_id () {
  return ku->id;
}

keyregression_owner::keyregression_owner (str directory, uint32 id,
					  sfsro_protocoltype type,
					  uint32 keysize,
					  uint32 chainlen,
					  bool create,
					  bool window,
					  bool verbose)
{ 
  if (!directory) {
    delete this;
    return;
  }

  osfile = strbuf () << directory << "/" << id;

  /** Create os based on type **/
  os = New refcounted<sfsro_ownerstate> (type);
  if (create) {
    if (type == SFSRO_SHA1) {
      
      if (keysize > sha1::hashsize) {
	delete this;
	return;
      } else
	os->osh->keysize = keysize;
      os->osh->id = id;
      os->osh->current_vers = 0;
      os->osh->final_vers = chainlen;
      os->osh->current_key.setsize (sha1::hashsize);
      os->osh->final_subkey.setsize (sha1::hashsize);
      if (window) {
	os->osh->window_start.setsize (sha1::hashsize);
	rnd.getbytes (os->osh->window_start.base (), 
		      os->osh->window_start.size ());
      } else
	os->osh->window_start.setsize (0);

      rnd.getbytes (os->osh->final_subkey.base (), 
		    os->osh->final_subkey.size ());
      hashchain (os->osh->current_key.base (), os->osh->final_subkey.base (), 
		 os->osh->final_vers);

      if (verbose) {
	warnx << "OWNER STATE\n";
	warnx << "ID              :" << os->osh->id << "\n";
	warnx << "Current version :" << os->osh->current_vers << "\n";
	warnx << "Final version   :" << os->osh->final_vers << "\n";
	warnx << "Current key     :" << hexdump(os->osh->current_key.base (), 
						os->osh->current_key.size ()) 
	      << "\n"; 
	warnx << "Final key       :" << hexdump(os->osh->final_subkey.base (), 
						os->osh->final_subkey.size ()) 
	      << "\n"; 
	warnx << "Window start    :" << hexdump(os->osh->window_start.base (), 
						os->osh->window_start.size ()) 
	      << "\n\n";
      }
      
      
    } else if (type == SFSRO_RABIN) {
      
      // fill rabin structures. eventually with better abstraction
      // get rid of this if else ladder.
    }
    if (!xdr2file (osfile, os)) {
      warn << "Unable to write xdr to " << osfile << "\n";
      delete this;
      return;
    }
  } else 
    if (!file2xdr (os, osfile)) {
      warn << "Unable to read xdr from " << osfile << "\n";
      delete this;
      return;
    }
}


bool
keyregression_owner::add (str outfile, uint32 window_startvers, bool verbose)
{
  ptr<sfsro_keyupdate> ku = NULL;
  ptr<sfsro_window> w = NULL;

  if (!outfile) {
    warn << "No outfile\n";
    return false;
  }
  

  ku = New refcounted<sfsro_keyupdate> ();
  ku->type = os->type;
  
  if (os->type == SFSRO_SHA1) {
    ku->id = os->osh->id;
    ku->keysize = os->osh->keysize;

    if(window_startvers > os->osh->current_vers) {
      warn << "Invalid window start version\n";
      return false;
    }
    
    if (os->osh->window_start.size () > 0) {
      w = New refcounted<sfsro_window> ();
      w->vers = window_startvers;
      w->edge.setsize (20);    
      hashchain(w->edge.base (), os->osh->window_start.base (), 
		window_startvers);
    } 
    
    ku->sub.vers = os->osh->current_vers;
    ku->sub.key.setsize (sha1::hashsize);
    memcpy (ku->sub.key.base (), 
	    os->osh->current_key.base (), os->osh->current_key.size ());


    if (verbose) {
      warnx << "KEY UPDATE STRUCT\n";
      warnx << "Subkey version  :" << ku->sub.vers << "\n";
      warnx << "Subkey          :" << hexdump(ku->sub.key.base (),
					      ku->sub.key.size ()) << "\n";
      warnx << "OWNER STATE\n";
      warnx << "Current version :" << os->osh->current_vers << "\n";
      warnx << "Current key     :" << hexdump(os->osh->current_key.base (), 
					      os->osh->current_key.size ()) 
	    << "\n\n"; 
      
    }

  } else if (os->type == SFSRO_RABIN) {
    // add rabin key
  }
  else {
    warn << "Invalid protocol type\n";
    return false;
  }
  
  str kufile = strbuf () << outfile << ".ku";
  str wfile = strbuf () << outfile << ".w";

  if (!xdr2file (kufile, ku)) {
    warn << "Unable to write ku to " << kufile << "\n";
    return false;
  }

  if (w && !xdr2file (wfile, w)) {
    warn << "Unable to write w to " << wfile << "\n";
    return false;
  }
  return true;
}

bool
keyregression_owner::wind (str outfile, bool verbose) 
{
  ptr<sfsro_keyupdate> ku;
  if (!outfile) {
    warn << "No outfile\n";
    return false;
  }

  ku = New refcounted<sfsro_keyupdate> ();
  ku->type = os->type;
  if (os->type == SFSRO_SHA1) {
    ku->id = os->osh->id;
    ku->keysize = os->osh->keysize;
	
    if(os->osh->current_vers == os->osh->final_vers) {
      warn << "Versions exhausted: Cannot wind group key: " << 
	os->osh->id << "\n";
      return false;
    } else 
      os->osh->current_vers++;

    ku->sub.vers = os->osh->current_vers;
    ku->sub.key.setsize (20);

    hashchain (os->osh->current_key.base (), os->osh->final_subkey.base (), 
	       (os->osh->final_vers - os->osh->current_vers));
    
    memcpy (ku->sub.key.base (), 
	    os->osh->current_key.base (), os->osh->current_key.size ());
    
    if (verbose) {
      warnx << "KEY UPDATE STRUCT\n";
      warnx << "Subkey version  :" << ku->sub.vers << "\n";
      warnx << "Subkey          :" << hexdump(ku->sub.key.base (),
					      ku->sub.key.size ()) << "\n";
      warnx << "OWNER STATE\n";
      warnx << "Current version :" << os->osh->current_vers << "\n";
      warnx << "Current key     :" << hexdump(os->osh->current_key.base (), 
					      os->osh->current_key.size ()) 
	    << "\n\n"; 
    }
  } else if (os->type == SFSRO_RABIN) {
    // wind rabin key
  }
  else {
    warn << "Invalid protocol type\n";
    return false;
  }

  if (!xdr2file (osfile, os)) {
    warn << "Unable to write os to " << osfile << "\n";
    return false;
  }

  str kufile = strbuf () << outfile << ".ku";

  if (!xdr2file (kufile, ku)) {
    warn << "Unable to write ku to " << kufile << "\n";
    return false;
  }
  return true;
}
