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
 * leafNode.h 
 *
 * leafNode subclasses Node and provides an abstraction for a leaf
 *    node in a b-tree. Leaf nodes are nodes which have no descendants
 *    that are not dataNodes. Each leaf node may have one or more data
 *    nodes. The value for each key found in the leaf node is stored
 *    in one of the data nodes.
 *
 * SEARCH: search returns either
 *      -- kFoundInLeaf, in which case the key was found and the value can be found in retValue
 *                             --  or --
 *      -- kNotFound, in which case the node is not present in the leaf and the search terminates
 *
 *
 * Memory representation of a leaf node:
 *
 * | header | pointers 0...n | free space | (key, data node pointer) 0...n |
 *
 * The pointers are sorted by key order, the actual data is not.
 *
 *    */

#ifndef _LEAF_NODE_H
#define _LEAF_NODE_H

#define kMinUtilization 0.3

#include <node.h>
#include <record.h>
#include <nodeStorage.h>

struct dataPtr {
  nodeID_t dataID;
  bSize_t offset;
};

struct leafElemRep {
  bLocalSize_t keyLen;
  char pad[2];
  dataPtr dPtr; //if dataID == -1, offset bytes of data are stored in this element after the key
  char key[0];
};

struct leafNodeHeader {
  char nodeType;
  char pad[3];
  nodeID_t tag;
  nodeID_t parent;
  nodeID_t dataIDHint;
  bLocalSize_t dataSize;
  bLocalSize_t numElems;
  nodeID_t backPtr;
  nodeID_t nextPtr;
  localPtr_t localPointers[0];
};

#define kDataInNode -1

class leafNode : public virtual node {

 public:
  leafNode(nodeStorage *b, btree* tree, int size);
  ~leafNode();

  void insert(record *item, int policy, callback<void, int>::ref cb);
  void insertNoData(record *item, callback<void, int>::ref cb);
  void remove(void *key, bSize_t len);
  nodeID_t search(void *key, bSize_t len, void **retValue, bSize_t *retLen);
  void merge(callback<void>::ref cb);
  void GC(callback<void>::ref cb);

  int isLeaf() { return 1;};
  char nodeType() {  return header->nodeType; }; 
  void setParent(nodeID_t p) { if (header->parent != p) {
    header->parent = p;
    TOUCH();
  }};
  nodeID_t getParent() { return header->parent; };
  void setDataHint(nodeID_t h) {header->dataIDHint = h; TOUCH();};
  nodeID_t getDataHint() {return header->dataIDHint;};
  void setBackPtr(nodeID_t bp) {header->backPtr = bp; TOUCH();};
  void setNextPtr(nodeID_t np) {header->nextPtr = np; TOUCH();};
  nodeID_t nextPtr() { return header->nextPtr;};
  nodeID_t backPtr() { return header->backPtr;};
  virtual int numElems() { return header->numElems; };
  bSize_t surplus();
  char underflow();

  void printRep();
  char repOK();
  void deleteSelf(callback<void>::ref cb);
  bSize_t shift(char direction, record **item);

  void * nth_key(int i);
  bSize_t  nth_keyLen(int i);
  void *  nth_value(int i);
  bSize_t nth_valueLen(int i);

  dataPtr *nthDataPtr(int i);

 private:
  void split(record* item, callback<void, int>::ref cb);
  void compact();
  int locateKey(void *key, int len);
  void * derefLocalKey(localPtr_t lPtr);
  bLocalSize_t derefLocalKeyLen(localPtr_t lPtr); 
  void * derefLocalValue(localPtr_t lPtr);
  bLocalSize_t derefLocalValueLen(localPtr_t lPtr);
  bLocalSize_t elemSize(int i);
  bLocalSize_t recordSize(record *rec);
  void createElement(leafElemRep *elem, record *rec);
  char dataResident(leafElemRep *elem);

  char splitRequired(int bytesAdded);
  void split_cb_insertInSibling(int i, 
				leafNode *NewNode, 
				record *item,
				callback<void, int>::ref cb,
				int err);
  void split_cb_allocateNode(record *item, callback<void, int>::ref cb, node *NewNode);
  void split_cb_insertMedian(record * rec, callback<void, int>::ref cb, node * parent);
  void split_cb_allocateRootNode(callback<void, int>::ref cb, record *rec, leafNode *sibling, nodeID_t id, node *root);
  void split_cb_finish(record *item, leafNode *NewNode, callback<void, int>::ref cb);
  void split_cb_parentInsert(record *rec, leafNode *NewNode, callback<void, int>::ref cb, int err);
  void split_cb_allocateRootNode_readDataNode(callback<void, int>::ref cb, 
					      record *rec, 
					      node *root, 
					      node *dn);
  void split_cb_fixBackChain(nodeID_t backPtr, node *oldSibling);

  void insert_cb_readDataNode(callback<void, int>::ref cb, record *item, int policy, node *dnode);
  void insert_cb_dataNodeInsert(callback<void, int>::ref cb, record *item, int hiddenPointer);

  void remove_cb_readDataNode(bSize_t off, node *dnode);

  void GC_cb_getLock(callback<void>::ref cb);
  void GC_cb_readDataNode(node *prev, node *dnode);
  void GC_cb_readDataNode_mt(node *dnode); 
  void GC_cb_readParent(callback<void>::ref cb, node *parent);
  void GC_cb_getDataNodeLock(node *dnode);
  void GC_cb_fixChainBack(callback<void>::ref cb, node *prev);
  void GC_cb_fixChainNext(callback<void>::ref cb, node *next);
  void GC_cb_finishMerge(callback<void>::ref cb);
  void GC_cb_dataNodeGCdone(node *dnode);
  void split_cb_updateDataItemParentPointer(int i, 
					    leafNode *NewNode, 
					    record *item, 
					    callback<void, int>::ref cb,
					    dataPtr *dPtr, 
					    int err);
  void split_cb_readDataNode(int i,
			     leafNode *NewNode,
			     record *item,
			     callback<void, int>::ref cb,
			     dataPtr *dPtr,
			     node *dNode);

  void nullcb(int err);

  void merge_cb_insertNoData(void *value, bSize_t len, int err);
  void merge_cb_fixDataParentPtr(dataPtr *dPtr, node *data);
  void merge_cb_readNext(callback<void>::ref cb, node *next);
  void merge_cb_haveNeighbors(node *n1, callback<void>::ref cb, node *n2);
  void merge_cb_finishShift(void *sep, bSize_t sepLen, void *keyInNode, bSize_t keyLen, callback<void>::ref cb, node *anchor);
  void merge_cb_recurseOnParent(callback<void>::ref cb, char direction, nodeID_t deleted, node *parent);
  void merge_cb_deleteMergedNode(callback<void>::ref cb, char direction, nodeID_t victimID);

  leafNodeHeader *header;

};

#endif    

    







