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
#include <btreeSync.h>
#include <aiod.h>

btreeSync::btreeSync() {
  btd = NULL;
}

bError_t btreeSync::create(char *filename, char create, short nodeSize, short dataLenFactor) {

  return createTree(filename, create, nodeSize, dataLenFactor);

}


bError_t btreeSync::open(char *filename, long cacheSize) {

  btd = New btreeDispatch(filename, cacheSize);
  return 0;

}

btreeSync::~btreeSync() {

  delete btd;
}

void
btreeSync::prepForAsync() {
  spinFlag = 0;
  tmpErr = 0;
}

void
btreeSync::blockOnAiod() {

  while (!spinFlag) acheck();
}

void
btreeSync::wait_cb(tid_t tid, int err, record *res) {

  tmpRes = res;
  tmpErr = err;
  spinFlag = 1;
}

//-------------------------------------------------------

bError_t
btreeSync::lookup(void *key, int len, record **res) {

  if (!btd) return -1;

  prepForAsync();
  btd->lookup(key, len, wrap(this, &btreeSync::wait_cb));
  blockOnAiod();

  *res = tmpRes;
  return tmpErr;
}

  
bError_t 
btreeSync::insert(void *key, int keyLen, void *value, int valueLen) {

  if (!btd) return -1;

  prepForAsync();
  int err = btd->insert(key, keyLen, value, valueLen, wrap(this, &btreeSync::wait_cb));
  if (err != 0) return err;
  blockOnAiod();

  return tmpErr;
}

bError_t 
btreeSync::remove(void *key, int len) {

  if (!btd) return -1;

  prepForAsync();
  btd->remove(key, len, wrap(this, &btreeSync::wait_cb));
  blockOnAiod();

  return tmpErr;
}

bError_t
btreeSync::iterate(bIteration *it, record **res) {
  
  if (!btd) return -1;

  prepForAsync();
  btd->iterate(it, wrap(this, &btreeSync::wait_cb));
  blockOnAiod();
  
  *res = tmpRes;
  return tmpErr;
}

bError_t
btreeSync::finalize() {
  
  if (!btd) return -1;

  prepForAsync();
  btd->finalize(wrap(this, &btreeSync::wait_cb));
  blockOnAiod();
  
  return tmpErr;
}
