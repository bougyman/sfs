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
 * node.h 
 *
 * node provides an abstraction for a node in the B-tree. 
 *
 * SEARCH: search returns either
 *      -- 0, in which case the key was found and the value can be found in retValue
 *                             --  or --
 *      -- nonzero, in which case the key does not exist in the node and the nonzero
 *         return value is the nodeID of the node which could contain the key. If 
 *         the nodeID returned is equal to -1, the item was not found in a leaf
 *	   and therefore does not exists in the tree
 *
 *             |-----header--------------|               |---|<----free space
 *    Layout (leaf, index):  /tag/data size/number elems/local pointers/..../elems/
 *    where elem = /key len/value len/key/val
 */

#include <node.h>
#include <btree.h>

#define maxValueLen 256

/*
 * Construction/Destruction
 */
node::node(nodeStorage *b, btree* tree, int Size)  {

  data = b;
  size = Size;
  this->tree = tree;
  bottomOfFreeSpace = NULL;
  ID = 0;
  lockbits = 0;
  lockQTail = NULL;
  lockOwner = -1;
}

node::~node() {

  delete data;
}


/*
 * per-node Lock mangement
 *
 */

bError_t
node::getLock(bLock_t type, tid_t tid, callback<void>::ref cb) {

  if ((lockbits == 0) || (lockOwner == tid)) {
    lockbits |= type;
    lockOwner = tid;
    (*cb)();
  }
  else { 
    enqueueLockCallback(cb, tid);
  }
  return 0;
}

bError_t 
node::freeLock() {
  
  //check to see if anyone is waiting on this lock
  if (lockRequestsPending()) {
    dequeueLockCallback();
    return 0;
  }
  
  //no one waiting? free the lock
  lockbits = 0;
  return 0;
}

void
node::enqueueLockCallback(callback<void>::ref cb, tid_t tid) {
  lockQTail = new lockCallbackRec(cb, tid, lockQTail);
  return;
}

void
node::dequeueLockCallback() {
  assert(lockQTail);

  callback<void>::ref retVal = lockQTail->cb;

  lockOwner = lockQTail->tid;
  lockQTail = lockQTail->prev;

  (*retVal)();
}

char
node::lockRequestsPending() {

  return (lockQTail != NULL);
}

char
node::haveLock(tid_t tid) {
  return ((lockbits != 0) && (lockOwner == tid));
}
