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
 * btreeDispatch
 *
 *
 * btreeDispatch provides an asyncronous interface to the btree
 * class. Each of the methods of this class require a call back as the
 * final argument. All error conditions and data returned by the tree
 * are returned via that callback. If async access is not a
 * requirement, use the simpler btreeSync abstraction.  
 */


#ifndef _BTREE_DISPATCH_H_ 

#define _BTREE_DISPATCH_H_

#include <btree.h>
#include <btree_types.h>
#include <refcnt.h>
#include <bIteration.h>

// void bcb(tid_t tid, int err, record *res);
typedef callback<void, tid_t, int, record *>::ref bcb;


struct transaction {
  tid_t tid;
  bcb cb;
  char operation;
  transaction(tid_t Tid, bcb Cb, char op) : cb(Cb) {
    tid = Tid; operation = op;
  }
};

class btreeDispatch {

 public:
  btreeDispatch(char *filename, long cacheSize);
  ~btreeDispatch();

  bError_t lookup(void *key, int len, bcb cb);
  bError_t insert(void *key, int keyLen, void *value, int valuelen, bcb cb);
  bError_t remove(void *key, int len, bcb cb);
  bError_t iterate(bIteration *it, bcb cb);
  bError_t finalize(bcb cb);
  void     setInsertPolicy(int pol) { t->setInsertPolicy(pol);};
  void     setLookupPolicy(int pol) { t->setLookupPolicy(pol);};
  void     printRep() {t->printRep("from btreeDispatch");};

 private:

  btree *t;
  
  tid_t lastNonce;

  void dispatcher(tid_t tid, int err, record *result);
  tid_t getNonce();
  
  qhash<tid_t, transaction *> cbTable;

};

#endif
