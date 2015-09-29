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
 * node provides an abstraction for a node in the B-tree. Node is an
 * abstract class and is extended by leafNode, indexNode and
 * dataNode. Several functions return integers which must be
 * interpreted in a non-obvious way:
 *
 * SEARCH: search returns either
 *      -- 0, in which case the key was found and the value can be found in retValue
 *                             --  or --
 *      -- nonzero, in which case the key does not exist in the node and the nonzero
 *         return value is the nodeID of the node which could contain the key. If 
 *         the nodeID returned is equal to -1, the item was not found in a leaf
 *	   and therefore does not exists in the tree
 *
 *
 *    
 */

#ifndef _NODE_H
#define _NODE_H

#define KEYNOTFOUND 0

class node;

#include <record.h>
#include "btree.h"
#include <btree_types.h>
#include <nodeStorage.h>

#define TOUCH() (tree->bufPool()->touchNode(ID))

class node { //abstract class

  class lockCallbackRec {
  public:
    tid_t tid;
    callback<void>::ref cb;
    lockCallbackRec *prev;
    
    lockCallbackRec(callback<void>::ref p_cb, tid_t p_tid, lockCallbackRec *p_prev) : cb(p_cb) {
      prev = p_prev;
      tid = p_tid;
    }
  };

 public:
  node(nodeStorage *b, btree* tree, int size);
  virtual ~node();

  virtual void insert(record *item, int policy, callback<void, int>::ref cb) = 0;
  virtual void remove(void *key, bSize_t len) = 0;
  virtual nodeID_t search(void *key, bSize_t len, void **retValue, bSize_t *retLen) = 0;
  virtual void merge(callback<void>::ref cb) = 0;
  virtual void GC(callback<void>::ref cb) = 0;
  virtual bSize_t shift(char direction, record **item) = 0;

  nodeID_t  nodeID() {return ID;};
  virtual int isLeaf() = 0;
  nodeStorage *storage() { return data;};
  bSize_t nodeSize() { return size; };
  virtual char nodeType() = 0;
  virtual int numElems() = 0;
  virtual char underflow() = 0;
  virtual bSize_t surplus() = 0;
  virtual nodeID_t getParent() = 0;
  virtual void setParent(nodeID_t p) = 0;
  
  bError_t getLock(bLock_t type, tid_t tid, callback<void>::ref cb);
  bError_t freeLock();
  bLock_t testLock() { return lockbits; };
  char haveLock(tid_t tid);
  
  virtual void printRep() = 0;
  virtual char repOK() = 0;

  //access methods
  virtual void *nth_key(int n) = 0;
  virtual bSize_t nth_keyLen(int n) = 0;
  virtual bSize_t nth_valueLen(int n) = 0;
  virtual void *nth_value(int n) = 0;

 protected:
  nodeID_t ID;
  char *bottomOfFreeSpace;
  btree* tree;  
  //int dirty;

  nodeStorage *data;
  int size;
  
  char lockbits;
  lockCallbackRec *lockQTail;
  tid_t lockOwner;

 private:
  virtual void split(record *item, callback<void, int>::ref cb) = 0;
  virtual void compact() = 0;
  virtual int locateKey(void *key, int len) = 0;
  virtual char splitRequired(int bytesAdded) = 0;
  virtual void * derefLocalKey(localPtr_t lPtr) = 0;
  virtual bLocalSize_t derefLocalKeyLen(localPtr_t lPtr) = 0; 
  virtual void * derefLocalValue(localPtr_t lPtr) = 0;
  virtual bLocalSize_t derefLocalValueLen(localPtr_t lPtr) = 0;
  
  void enqueueLockCallback(callback<void>::ref cb, tid_t tid);
  void dequeueLockCallback();
  char lockRequestsPending();
};

#endif


