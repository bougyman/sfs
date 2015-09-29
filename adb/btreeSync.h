/*
 *
 * Copyright (C) 1999 Frank Dabek (fdabek@mit.edu)
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

/*
 * btreeSync
 *
 *
 * btreeSync provides synchronous access to class btree. Create a new
 * btree using this class by specifying the filename of it's on-disk
 * representation (created previously by mktree). This is a
 * convenience class and uses the btree and btreeDispatch classes
 * internally to provide the appearance of simple, synchronous access
 * to the tree
 */

#ifndef _BTREE_SYNC_H
#define _BTREE_SYNC_H

#include <btreeDispatch.h>

class btreeSync {

 public:
  btreeSync();
  ~btreeSync();

  bError_t create(char *filename, char create, short nodeSize, short dataLenFactor);
  bError_t open(char *filename, long cacheSize);

  bError_t lookup(void *key, int len, record **res);
  bError_t insert(void *key, int keyLen, void *value, int valueLen);
  bError_t remove(void *key, int len);
  bError_t iterate(bIteration *it, record **res);
  bError_t finalize();
  void     setInsertPolicy(int pol) { btd->setInsertPolicy(pol);};
  void     setLookupPolicy(int pol) { btd->setLookupPolicy(pol);};
  void     printRep() {btd->printRep();};
  
 private:
  void prepForAsync();
  void blockOnAiod();
  void wait_cb(tid_t tid, int err, record *res);

  int spinFlag;
  record *tmpRes;
  int tmpErr;

  btreeDispatch *btd;

};

#endif
