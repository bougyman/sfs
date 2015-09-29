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
 * dataNode.h 
 *  
 *  Class dataNode is another node variant. Data nodes are associated
 *  with leaf nodes, have no descendants, and hold only data (no
 *  keys). Data in data nodes (also called segments) are referencd by
 *  a long word which specifies both the node's ID (high word) and the
 *  offset within the node (low word)
 *
 * Memory Representation:
 *
 *  | header | offsets | data 1 | free space | data 2 | data 3 | free space | ... | data n |
 *  
 *  Several functions modify the interpretation of arguments from node.h. See individual
 *  function comments in dataNode.C.  */


#ifndef _DATA_NODE_H
#define _DATA_NODE_H

#include <node.h>
#include <nodeStorage.h>
#include <btree_types.h>
#include <leafNode.h>

#define kAllowLargeInsert -2
#define kUniqueItem -1

struct dataElemRep {
  bLocalSize_t len;
  char pad[2];
  nodeID_t parent;
  char data[0];
};

struct dataNodeHeader {
  char nodeType;
  bLocalSize_t nodeSize;
  char reserved[1];
  nodeID_t tag;
  nodeID_t parent; //obsolete
  nodeID_t next;
  bLocalSize_t dataSize;
  bLocalSize_t numElems;
  bLocalSize_t maxElems;
  bLocalSize_t offsets[0];
};

class dataNode : public virtual node {

 public:
  dataNode(nodeStorage *b, btree *tree, int size);
  ~dataNode();
  
  void insert(record *item, int policy, callback<void, int>::ref cb);
  void remove(void *key, bSize_t len);
  nodeID_t search(void *key, bSize_t len, void **retValue, bSize_t *retLen);
  bSize_t shift(char direction, record **item) { warn("not implemented"); return -1; };
  bSize_t shift(void **value, bOffset_t *offset, nodeID_t *parent);
  void GC(callback<void>::ref cb);
  void merge(callback<void>::ref cb) { GC(cb); };

  char underflow();
  bSize_t surplus();

  int isLeaf() { return 0; };  
  char nodeType() {  return header->nodeType; }; 
  void setItemParent(bOffset_t offset, nodeID_t newParent);
  bSize_t dataSize() { return header->dataSize; };
  void setParent(nodeID_t p) { header->parent = p; TOUCH(); };
  nodeID_t getParent() { return header->parent;};
  void setNext(nodeID_t n) { header->next = n; TOUCH(); };
  nodeID_t next() { return header->next; };
  int numElems() { return header->numElems; };
  char splitRequired(int bytesAdded);

  void * nth_key(int i);
  bSize_t  nth_keyLen(int i);
  void *  nth_value(int i);
  bSize_t nth_valueLen(int i);
  
  void printRep();
  char repOK();

 private:
  void split(record *item, callback<void, int>::ref cb);
  void compact();
  void insertIndNode(record *item, callback<void, int>::ref cb);
  void insertIndNode_cb_allocateNode(record *item, callback<void, int>::ref cb, node *dnode);
  int locateKey(void *key, int len) { return 0; };
  void * derefLocalKey(localPtr_t lPtr) { return NULL;};
  void * derefLocalValue(localPtr_t lPtr);
  bLocalSize_t  derefLocalValueLen(localPtr_t lPtr);
  bLocalSize_t  derefLocalKeyLen(localPtr_t lPtr) { return 0; };

  void split_cb_readParent(record *item, callback<void, int>::ref cb, node *parent);
  void split_cb_allocateBuffer(record *item, callback<void, int>::ref cb, node *n);
  void insert_cb_getLock(record *item, int policy, callback<void, int>::ref cb);
  
  void GC_cb_haveNext(callback<void>::ref cb, node *next);
  void GC_cb_doShift(node *next, callback<void>::ref cb);
  void GC_cb_doMerge(node *next, callback<void>::ref cb);
  void GC_cb_fixParent(node *next, record *item, 
		       bOffset_t offsetInParent, 
		       callback<void>::ref cb,
		       char merge,
		       node *parent);
  void GC_cb_reinsertDone(node *next, 
			  dataPtr * dPtrToModify, 
			  callback<void>::ref cb, 
			  char merge, 
			  int hiddenDataPtr);
  
dataNodeHeader *header;

  void *startOfFreeSpace;

};
  
#endif

