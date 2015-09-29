/* $Id: cache.h,v 1.3 2001/09/11 03:03:08 fubob Exp $ */

/*
 *
 * Copyright (C) 2000, 2001 Kevin Fu (fubob@mit.edu)
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

#ifndef _CACHE_H_
#define _CACHE_H_ 1

#include "ihash.h"
#include "qhash.h"

template<class KEY, class VALUE, u_int max_cache_entries = 0,
  class R = qhash_lookup_return<VALUE> > 
  // Kludge so we don't return pointers to refcounted objects
class cache {
  struct cache_entry {
    cache *const c;
    const KEY    k;
    VALUE        v;

    ihash_entry<cache_entry> fhlink;
    tailq_entry<cache_entry> lrulink;
    // should add doubly linked to quickly delete


    cache_entry (cache<KEY, VALUE, max_cache_entries> *cc,
	       const KEY &kk, const VALUE &vv)
      : c (cc), k (kk), v (vv)
    {
      c->lrulist.insert_tail (this);
      c->entries.insert (this);
      c->num_cache_entries++;
      if (max_cache_entries != 0)
	while (c->num_cache_entries > implicit_cast<u_int> (max_cache_entries))
	  delete c->lrulist.first;
      // XXX ^^ implement cache pinning here for the rootfh?
    }

    ~cache_entry ()
    {
      c->lrulist.remove (this);
      c->entries.remove (this);
      c->num_cache_entries--;
    }

    void touch ()
    {
      c->lrulist.remove (this);
      c->lrulist.insert_tail (this);
    }

  };
  

private:
  friend class cache_entry;
  ihash<const KEY, cache_entry, &cache_entry::k, &cache_entry::fhlink> entries;
  u_int num_cache_entries;
  tailq<cache_entry, &cache_entry::lrulink> lrulist;

public:
  cache () { num_cache_entries = 0; }

  ~cache () { entries.deleteall (); }

  void flush () { entries.deleteall (); }

  bool insert (const KEY& kk, const VALUE &vv)
  {
    cache_entry *ad = entries[kk];
    if (ad) 
      return false;
    
    New cache_entry (this, kk, vv);
    return true;
  }

  bool remove (const KEY& kk)
  {
    cache_entry *ad = entries[kk];
    if (!ad)
      return false;

    delete ad;
    return true;
  }

  typename R::type operator[] (const KEY& kk) {
    cache_entry *ad = entries[kk];
    if (ad) {
      ad->touch ();
      return R::ret (&ad->v);
    } else
      return R::ret (NULL);
  }


};

#endif /* !_CACHE_H_ */
