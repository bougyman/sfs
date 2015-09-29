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
 * nodeBuf.h 
 *
 * nodeBuf encapsulates a memory buffer which holds a fixed number of
 * nodes. nodeBuf is resposible for reading nodes from disk, and
 * writing them back to disk when necessary.
 */

#ifndef _NODEBUF_H_
#define _NODEBUF_H_

class nodeBuf;

#include "qhash.h"
#include "btreeExceptions.h"
#include "node.h"
#include "replacement.h"
#include "btree.h"
#include "bAlloc.h"
#include "bAllocFF.h"
#include "superBlock.h"
#include "nodeStorage.h"

#define kGuessSize 0
#define kOrphan -1
#define kIgnoreParent -1

struct hashEntry {
  node *b;
  char dirty;
  replacementRec *entry;
  hashEntry(node *pb, replacementRec *pentry);
};
  
class nodeBuf {
  
 public:
  
  nodeBuf(btree* Tree, int Size, char *file);
  ~nodeBuf();

  node *fetch(nodeID_t nodeID);
  void readNode(nodeID_t nodeID, bSize_t size, nodeID_t parent, callback<void, node*>::ref cb);
  void release(nodeID_t nodeID);
  int flush(nodeID_t nodeID, callback<void, int>::ref cb);
  void kill(nodeID_t node);
  int nodeSize() { return sb->nodeSize(); };
  int dataNodeFactor() { return sb->dataLenFactor(); };
  void touchNode(nodeID_t nodeID);
  void usedNode(nodeID_t nodeID);
  void allocateNewNode(char index, nodeID_t parent, bSize_t size, callback<void, node *>::ref cb);
  void allocateNewRootNode(callback<void, nodeID_t, node *>::ref cb);
  void flushMetaData();
  void finalize(callback<void, int>::ref cb);
  void init();
  void Bufalloc(char type, bSize_t size, callback<void, bSize_t, ptr<aiobuf> >::ref cb);
  int preflightAllocation(bSize_t blockLen) { return fm->preflightAllocation(blockLen); };
  void allocateLeafNode(nodeStorage *b, btree *tree, int Size, callback<void, node *>::ref cb);
  void allocateIndexNode(nodeStorage *b, btree *tree, int Size, callback<void, node *>::ref cb);
  void allocateDataNode(nodeStorage *b, btree *tree, int Size, callback<void, node *>::ref cb);
  void compact();

 private:
  
  void handleErr(int err);
  
  int idToOffset(nodeID_t id);
  nodeID_t blockToID(blockID_t b);
  blockID_t nodeBuf::IDToBlock(nodeID_t n);
 
  void verifySpace(bSize_t nsize);
  void initNode(void* buf, char, blockID_t, nodeID_t, bSize_t);
  void insertNode(nodeID_t nodeID, ptr<aiobuf> buf, nodeID_t parent, callback<void, node *>::ref cb);
  blockID_t findEmptyPage();
  void flushSuperBlock();

  //callbacks
  void opencb(ptr<aiofh> ff, int err);
  void readcb(off_t pos, int cnt, nodeID_t id, nodeID_t parent, callback<void, node*>::ref cb, 
	      ptr<aiobuf> b, ssize_t count, int err);
  void writecb(off_t pos, bSize_t cnt, callback<void, int>::ref cb, 
			ptr<aiobuf> b, ssize_t count, int err);
  void initcb(node *N);
  void nullCB(int err) {return;};
  void bufwaitcb();
  void _release(node *dead);
  void allocateLeafNode_cb_allocateDataNode(node *n, callback<void, node *>::ref cb, node *newDataNode);
  void allocateNewNode_cb_getBuffer(char type,
				    nodeID_t parent,
				    callback<void, node *>::ref cb,
				    bSize_t size,
				    ptr<aiobuf> NewBuf);
  void allocateNewNode_cb_initNode(callback<void, node*>::ref cb, node *newNode);
  void insertNode_cb_createNode(callback<void, node *>::ref cb, nodeID_t parent, nodeID_t ID, node *n);
  void allocateNewRootNode_cb_getBuffer(callback<void, nodeID_t, node *>::ref cb, bSize_t size, ptr<aiobuf> NewBuf);
  void allocateNewRootNode_cb_getIndexNode(callback<void, nodeID_t, node*>::ref cb, node *retVal);
  
  void readNode_cb_getBuffer(nodeID_t nodeID, bSize_t size, nodeID_t parent,
			       callback<void, node *>::ref cb, bSize_t retSize, 
			     ptr<aiobuf> buf);

  void finalize_cb_flush(callback<void, int>::ref cb, nodeID_t node_id, int *cnt, int err);
  void verifySpace_cb_flush(nodeID_t victim, int err);
  void kill_cb_readTarget(node *target);
  void compact_cb_readNode(blockID_t newAddr, node *node);

  ptr<aiofh> f;
  int fd;
  aiod *a;

  qhash<nodeID_t, ref<hashEntry> > bufPool;
  replacementQ q;

  superBlock *sb;
  // ALLOC
  //bAlloc *fm;
  bAllocFF *fm;

  btree* tree;
  char *diskFile;
  int coreBytesUsed;
  int size; //of node cache
  char syncFlag;
  char initFlag;
  char memWaitLock;
};

#endif



















