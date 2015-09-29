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

#include <btreeDispatch.h>

btreeDispatch::btreeDispatch(char *filename, long cacheSize) {
  
  t = New btree(wrap(this, &btreeDispatch::dispatcher));
  t->open(filename, cacheSize);
  lastNonce = 1;
}

btreeDispatch::~btreeDispatch() {

  delete t;
}

bError_t
btreeDispatch::lookup(void *key, int len, bcb cb) {

  tid_t tid = getNonce();
  transaction *trn = New transaction(tid, cb, OP_SEARCH);
  cbTable.insert(tid, trn);

  return t->search(tid, key, len);
}

bError_t
btreeDispatch::insert(void *key, int keyLen, void *value, int valueLen, bcb cb) {

  tid_t tid = getNonce();
  transaction *trn = New transaction(tid, cb, OP_INSERT);
  cbTable.insert(tid, trn);
 
  return t->insert(tid, key, keyLen, value, valueLen);
}

bError_t
btreeDispatch::remove(void *key, int len, bcb cb) {

  tid_t tid = getNonce();
  transaction *trn = New transaction(tid, cb, OP_DELETE);
  cbTable.insert(tid, trn);

  return t->remove(tid, key, len);
}

bError_t 
btreeDispatch::iterate(bIteration *it, bcb cb) {

  tid_t tid = getNonce();
  transaction *trn = New transaction(tid, cb, OP_ITERATE);
  cbTable.insert(tid, trn);
  
  return t->iterate(tid, it);
}

bError_t
btreeDispatch::finalize(bcb cb) {
  tid_t tid = getNonce();
  transaction *trn = New transaction(tid, cb, OP_FINALIZE);
  cbTable.insert(tid, trn);

  return t->finalize(tid);
}

void
btreeDispatch::dispatcher(tid_t tid, int err, record *result) {
  
  transaction *trn = *cbTable[tid];
  if (trn == NULL) {
    fatal("tid not in table");
  }

  (*(trn->cb))(tid, err, result);

  cbTable.remove(tid);
  delete trn;

}

tid_t
btreeDispatch::getNonce() {

  return lastNonce++;
}
