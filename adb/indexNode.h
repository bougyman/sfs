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
 * indexNode.h 
 *
 * indexNode provides an abstraction for an internal node in the
 * B+-tree. Index nodes are those nodes which have non-data node
 * child.
 *
 * Memory representation of an index node: 
 * 
 *    | header | pointers (0 ... n) | free space | (key, index node ID)_0..n |
 *
 * Note: Search returns the ID of the leaf node which contains the
 * requsted key,data pair. This non-zero return value is not an error
 * condition
 *    
 */

#ifndef _INDEX_NODE_H
#define _INDEX_NODE_H

#include <node.h>
#include <nodeStorage.h>

struct indexElemRep {
  nodeID_t p;
  bLocalSize_t keyLen;
  char pad1;
  char pad2;
  char key[0];
};

struct indexNodeHeader {
  char nodeType;
  char reserved[3];
  nodeID_t tag;
  nodeID_t parent;
  bLocalSize_t dataSize;
  bLocalSize_t numElems;
  nodeID_t p_zero;
  localPtr_t localPointers[0];
};

#define kRightNeighbor 1
#define kLeftNeighbor 2
#define kExtremum -1

class indexNode : public virtual node {

  friend class btree;
  
 public:
  indexNode(nodeStorage *buf, btree* tree, int size);
  indexNode::~indexNode();
  
  void insert(record *item, int policy, callback<void, int>::ref cb);
  void remove(void *key, bSize_t len);
  nodeID_t search(void *key, bSize_t len, void **retValue, bSize_t *retLen);
  void merge(callback<void>::ref cb);
  void GC(callback<void>::ref cb);
  bSize_t shift(char direction, record **item);

  nodeID_t nodeID() {return ID;};
  char nodeType() {  return header->nodeType; }; 
  int isLeaf() { return 0; };
  void setParent(nodeID_t p) { header->parent = p; TOUCH(); };
  nodeID_t getParent() { return header->parent;};
  virtual int numElems() { return header->numElems; };
  char underflow();
  bSize_t surplus();

  void printRep();
  char repOK();

  void setPZero(nodeID_t node) { header->p_zero = p_zero = node; TOUCH(); };
  void setChild(nodeID_t current, nodeID_t newID);
  void deleteChild(nodeID_t ID);
  void updatePointer(void *keyInModNode, bSize_t keylen, 
		     void *newSep, bSize_t sepLen);
  
  virtual void *nth_key(int n);
  virtual bSize_t nth_keyLen(int n);
  virtual bSize_t nth_valueLen(int n);
  virtual void *nth_value(int n);

 protected:
  nodeID_t ithChild(int i);

 private:
  void split(record *item, callback<void, int>::ref cb);
  void compact();
  int locateKey(void *key, int n);
  char splitRequired(int bytesAdded);
  void * derefLocalKey(localPtr_t lPtr);
  bLocalSize_t derefLocalKeyLen(localPtr_t lPtr); 
  void * derefLocalValue(localPtr_t lPtr);
  bLocalSize_t derefLocalValueLen(localPtr_t lPtr);

  void split_cb_allocateNode(record *item, callback<void,int>::ref cb, node *NewNode);
  void split_cb_readParent(record *rec, callback<void, int>::ref, node * parent);
  void split_cb_allocateRootNode(callback<void, int>::ref cb, record *rec, nodeID_t newID, node *root);
  void GC_cb_readParent(node *parent);
  void nullcb(int err);
  void findNeighbor(char which, callback<void, node *>::ref cb);
  void findNeighbor_cb_readParent(char which, int level, nodeID_t ref, callback<void, node *>::ref cb, node *p);

  void merge_cb_getRight(callback<void>::ref cb, node *rightNeighbor);
  void merge_cb_haveNeighbors(node *rightNeighbor, callback<void>::ref cb, node *leftNeighbor);
  void merge_cb_finishShift(void *sep, bSize_t sepLen, void *keyInNode, bSize_t keyLen, 
			    callback<void>::ref cb, node *anchor);
  void merge_cb_recurseOnParent(callback<void>::ref cb, char direction, nodeID_t deleted, node *parent);

  nodeID_t p_zero;
  indexNodeHeader *header;
};

#endif
