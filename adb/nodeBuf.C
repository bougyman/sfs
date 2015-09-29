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

#include "nodeBuf.h"
#include "leafNode.h"
#include "indexNode.h"
#include "nodeStorage.h"
#include "dataNode.h"
#include "btree_types.h"
#ifdef DMALLOC
#include "dmalloc.h"
#endif
#include "assert.h"
#include "bAllocFF.h"

////////////////////callbacks///////////////////////////////

void compact_cb(int err);
void statcb(struct stat *s, int err);
/*
 * opencb - asynchronously open the btree's disk file.
 *
 */
void nodeBuf::opencb(ptr<aiofh> fh, int err) {

  if (!fh) {
    printf("nodeBuf::opencb: error %d (%s)", err, strerror(err));
    exit(1);
    return;
  }

  //set the file handle field (f)
  f = fh;
  initFlag = 1;
}


/*
 * readcb - general read callback. Reads a node off disk and
 *          hashes its buffer into the memory pool
 */
void nodeBuf::readcb(off_t pos, int cnt, nodeID_t id, nodeID_t parent, callback<void, node *>::ref cb, 
		     ptr<aiobuf> b, ssize_t count, int err) {


  //test (again) to see if the node isn't already in core and short-cut to return
  node * n = fetch(id);
  if (n) { 
    if (parent > 0) n->setParent(parent);
    (*cb)(n);
    return;
  }
  
  if (cnt - count <= 0) {
    if (err) fatal("error reading node");

#ifdef STATS
    stopTimer();
    stats.readBeforeInsertSplit += elapsedmsecs();
#endif

      insertNode(id, b, parent, cb);
    return;
  }
 
  f->read(pos + count, b, wrap(this, &nodeBuf::readcb, pos + count, cnt - count, id, parent, cb));
}


/*
 * writecb - write callback. Writes a dirty node back to disk
 *
 */
void nodeBuf::writecb(off_t pos, bSize_t cnt, callback<void, int>::ref cb, 
		      ptr<aiobuf> b, ssize_t count, int err) {
  
  if ((count < 0) || (err != 0)) fatal("error writing node");
  if (cnt - count <= 0) {
    //done writing
    (*cb)(err);
    return;
  }
  
  //reschedule ourselves
  f->write(pos + count, b, wrap(this, &nodeBuf::writecb, pos + count, cnt - count, cb));
}


///////////////////////////////////////////////////////////////////////
hashEntry::hashEntry(node *pb, replacementRec *pentry) { 
  assert(pentry); 
  b = pb; 
  entry = pentry; 
  dirty = 0; //XXX should be 0, but touch is broken
};



////////////////////////////////////////////////////////////////////
/*
 * constructor
 */
nodeBuf::nodeBuf(btree* Tree, int Size, char *diskFile) {

  //init superblock
  char metaName[128];
  strcpy(metaName, diskFile);
  strcat(metaName, ".data");
  sb = new superBlock(metaName);

  //init aiod
  a = New aiod(4, Size*2);
  assert(a);

  //allocate and read free map
  // ALLOC:
  //fm = New bAlloc(sb);
  fm = New bAllocFF(sb);

  initFlag = 0;
  syncFlag = 0;
  size = Size;
  tree = Tree;
  coreBytesUsed = 0;

  //setup size of resident data in leaves based on nodeSize, data size factor
  if (sb->dataLenFactor() == 0) kResidentDataMaxSize = sb->nodeSize();
  else kResidentDataMaxSize = sb->nodeSize()/10;

  /* open the disk file for aiod now that we are initialized */
  a->open(diskFile, O_RDWR, 0, wrap(this, &nodeBuf::opencb));
  while(!initFlag) acheck();
}

void
nodeBuf::init() {

  //get the root node
  initFlag = 0;
  readNode(1, kGuessSize, kOrphan, wrap(this, &nodeBuf::initcb));
  while(!initFlag) acheck();
}

void
nodeBuf::initcb(node *N) {
  initFlag = 1;
}


/*
 * readNode - reads a node from disk and hashes it into the 
 *            table.
 */
void
nodeBuf::readNode(nodeID_t nodeID, bSize_t size, nodeID_t parent, callback<void, node *>::ref cb) {

  assert(nodeID > 0);

  //test to see if this node isn't already in core
  node * n = fetch(nodeID);

#ifdef STATS
  if (n) {
    if (n->isLeaf()) stats.cache_leafHits++;
    else stats.cache_indexHits++;
  }
  stats.cache_requests++;
#endif

  if (n) {
    if (parent > 0) n->setParent(parent);
    (*cb)(n);
    return;
  }

#ifdef STATS
  startTimer();
#endif 

  //autosizing
  if (size == 0) size = fm->nodeSize(nodeID); 
  
  //get it off disk
  Bufalloc(kNone, size, wrap(this, &nodeBuf::readNode_cb_getBuffer, nodeID, size, parent, cb));
  return;

}

void
nodeBuf::readNode_cb_getBuffer(nodeID_t nodeID, bSize_t size, nodeID_t parent, 
			       callback<void, node *>::ref cb, bSize_t retSize, 
			       ptr<aiobuf> buf) {

  if (retSize != size) {
    fprintf(stderr, "(%ld) request for %ld bytes failed\n", nodeID, size);
    exit(1);
  }
  
  //translate the nodeID into an offset in the file
  int offset = idToOffset(nodeID);
  
#ifdef STATS
  stopTimer();
  stats.readBufSplitTotal += elapsedmsecs();
#endif

  readcb(offset, size, nodeID, parent, cb, buf, 0, 0);

  //insertNode will be called from the read callback
}

/*
 * form a node from the data and insert it into the core pool
 */
void
nodeBuf::insertNode(nodeID_t nodeID, ptr<aiobuf> buf, nodeID_t parent, callback<void, node *>::ref cb) {

  //create the storage
  nodeStorage *nodeData = New nodeStorage(buf);

  char type = *(buf->base()); 
  int ns = sb->nodeSize();
  
#ifdef STATS
  if ((type == kLeafTag) || (type == kSegTag)) stats.cache_leafMisses++;
  else stats.cache_indexMisses++;
  stopTimer();
  stats.readTotalTime += elapsedmsecs();
  if (elapsedmsecs() > stats.readMax) stats.readMax = elapsedmsecs();
  if (elapsedmsecs() < stats.readMin) stats.readMin = elapsedmsecs();
  stats.readCount++;
#endif

  if (type == kLeafTag)
    allocateLeafNode(nodeData, tree, ns, wrap(this, &nodeBuf::insertNode_cb_createNode, cb, parent, nodeID));
  else if (type == kIndexTag)
    allocateIndexNode(nodeData, tree, ns, wrap(this, &nodeBuf::insertNode_cb_createNode, cb, parent, nodeID));
  else if (type == kSegTag) {
    dataNodeHeader *dh = (dataNodeHeader *)buf->base();
    allocateDataNode(nodeData, tree, dh->nodeSize, wrap(this, &nodeBuf::insertNode_cb_createNode, cb, parent, nodeID));
  } else {
    printf("unknown type reading node %ld\n", nodeID);
    (*cb)(NULL);
  }
}

void
nodeBuf::insertNode_cb_createNode(callback<void, node *>::ref cb, nodeID_t parent, nodeID_t ID, node *n) {

    //put it in the hash table and LRU queue
  replacementRec *r = q.add(ID);  
  ref<hashEntry> entry = New refcounted<hashEntry>(n, r);
  bufPool.insert(ID, entry);

  coreBytesUsed += n->nodeSize();

  if (parent > 0) n->setParent(parent);
  

  //  if (!n->repOK()) {
  //  printf("rep invalid on read\n");
  // exit(0);
  // }

  //return the node to the caller via the final callback
  (*cb)(n);
  
  return;
}

/*
 * Conversions: pretty much null now that i've moved meta-data to a separate file
 * idToOffset - convert the nodeID id to an offset in the disk file
 */
int nodeBuf::idToOffset(nodeID_t id) {

  // ALLOC
  //return (id)*sb->nodeSize();
  return fm->derefHandle(id); 
}

nodeID_t nodeBuf::blockToID(blockID_t b) {
  return b;
}

blockID_t 
nodeBuf::IDToBlock(nodeID_t n) {
  return n;
}

/*
 * fetch - return the node nodeID from the memory pool if it is
 *         resident. return NULL if it must be read from disk
 */
node *nodeBuf::fetch(nodeID_t nodeID) {

  //try to find the ID in the hash table
  ptr<hashEntry> he = bufPool[nodeID];
  //page fault if it's not there
  if (!he) return NULL;
  
  //note that it has been used
  q.touch(he->entry);

  return he->b;

}

/*
 * release - signal that the node nodeID is no longer needed in core
 */
void 
nodeBuf::release(nodeID_t nodeID) {
  node *dead = fetch(nodeID);
  //if it's not in core, can't release it.
  if (!dead) return;
  
  ptr<hashEntry> he = bufPool[nodeID];
    
  if (!he) { 
    fatal("null hash entry on release\n");
  }
    
  free(q.remove(nodeID));
  bufPool.remove(nodeID);

  coreBytesUsed -= he->b->nodeSize();
  delete dead;
}

/*
 * flush - write a node back to disk
 *
 */
int nodeBuf::flush(nodeID_t nodeID, callback<void, int>::ref cb) {

  ptr<hashEntry> he = bufPool[nodeID];
  if (!he) {
    (*cb)(-1);
    return 0;
  }

  if (he->dirty) {
    int offset = idToOffset(nodeID);
    if (!he->b->repOK()) {
      printf("rep invalid on flush\n");
      exit(0);
    }

    fflush(stderr);
    writecb(offset, he->b->nodeSize(), cb, he->b->storage()->abuf(), 0, 0);
    he->dirty = 0;
    return 1;
  }
 
  //  fprintf(stderr, "node %ld clean, not flushing\n", nodeID);
  fflush(stderr);
  //not an error to flush a clean node
  return 0;
}

/*
 * touchNode() - tells the buffer pool that this node has been modified
 *               and should be flushed to disk when it is released
 */
void nodeBuf::touchNode(nodeID_t node) {
  
  //try to find the ID in the hash table
  ptr<hashEntry> he = bufPool[node];
  //page fault if it's not there
  assert(he);
  
  //note that it has been used
  q.touch(he->entry);

  //set it dirty
  he->dirty = 1;
}

/*
 * usedNode() -- like the above, except doesn't mark the node as
 * modified. Useful for LRU calcs
 * 
 */
void nodeBuf::usedNode(nodeID_t node) {

  ptr<hashEntry> he = bufPool[node];
  assert(he);

  q.touch(he->entry);
}

/*
 * verifySpace - check to see if enough unallocated memory is currently
 *               available to store this node. If not, purge the least
 *		 recently used node
 */
void nodeBuf::verifySpace(bSize_t nSize) {

  while  (coreBytesUsed > (size - nSize) ) {
    
    //select victim
    nodeID_t victim = q.next();
    
    ptr<hashEntry> he = bufPool[victim];
    if (!he) {
      printf("target node %ld not in memory on flush\n", victim);
      exit(0);
    }

#ifdef REALLYDUMBSTATS
    if (he->b->nodeType() == kIndexTag) { fprintf(stderr, "i "); fflush(stderr);}
    else if (he->b->nodeType() == kLeafTag)  { fprintf(stderr, "l "); fflush(stderr);}
    else  { fprintf(stderr, "d "); fflush(stderr);}
#endif

    //flush victim node
    flush(victim, wrap(this, &nodeBuf::verifySpace_cb_flush, victim));
    release(victim);
  }
  return;
}

void
nodeBuf::verifySpace_cb_flush(nodeID_t victim, int err) {
  //  release(victim);
  return;
}


/*
 * kill
 *
 * Bump a given node off: release it, and free up it's disk blocks
 */
void
nodeBuf::kill(nodeID_t target) {
  readNode(target, kGuessSize, kIgnoreParent, wrap(this, &nodeBuf::kill_cb_readTarget));
  return;
}
void
nodeBuf::kill_cb_readTarget(node *target) {

#ifdef STATS
  stats.allocation -= target->nodeSize();
#endif

  fm->dealloc(IDToBlock(target->nodeID()), target->nodeSize());

  release(target->nodeID());
}


    
void nodeBuf::initNode(void *buf, char type, blockID_t block, nodeID_t parent, bSize_t size) {
  
  switch (type) {
  case kIndexTag:
    indexNodeHeader ih;
    ih.nodeType = kIndexTag;
    ih.tag = blockToID(block);
    ih.parent = parent;
    ih.dataSize = 0;
    ih.numElems = 0;
    ih.p_zero = 0;
    memcpy(buf, &ih, sizeof(ih));
    break;
  case kLeafTag:
    leafNodeHeader lh;
    lh.nodeType = kLeafTag;
    lh.tag = blockToID(block);
    lh.dataIDHint = -1;
    lh.parent = parent;
    lh.dataSize = 0;
    lh.numElems = 0;
    lh.backPtr = lh.nextPtr = 0;
    //    memset(buf, 0xc5, size);
    memcpy(buf, &lh, sizeof(lh));
    break;
  case kSegTag:
    dataNodeHeader dh;
    dh.nodeType = kSegTag;
    dh.nodeSize = size;
    dh.tag = blockToID(block);
    dh.parent = parent;
    dh.dataSize = 0;
    dh.numElems = 0;
    dh.maxElems = 0;
    dh.next = 0;
    memcpy(buf, &dh, sizeof(dh));
    break;
  default:
    fatal("improper node type in initNode");
    break;
  }

  return;
}

/*
 *  allocateNewRootNode
 *
 *  Allocates a new root node and returns it via a callback. The
 *  callback also returns a nodeID_t which is the new id of the old
 *  root node. 
 */
void
nodeBuf::allocateNewRootNode(callback<void, nodeID_t, node *>::ref cb) {

  //get space for the new node
  bSize_t size = sb->nodeSize();
#ifdef STATS
  stats.allocation += size;
#endif
  Bufalloc(kIndexTag, size, wrap(this, &nodeBuf::allocateNewRootNode_cb_getBuffer, cb));
  return;
}

void
nodeBuf::allocateNewRootNode_cb_getBuffer(callback<void, nodeID_t, node *>::ref cb, bSize_t size, ptr<aiobuf> NewBuf) {

  initNode(NewBuf->base(), kIndexTag, IDToBlock(1), -1, size);
  nodeStorage *ns = New nodeStorage(NewBuf);
  allocateIndexNode(ns,tree, size, wrap(this, &nodeBuf::allocateNewRootNode_cb_getIndexNode, cb));
  
  return;
}

void 
nodeBuf::allocateNewRootNode_cb_getIndexNode(callback<void, nodeID_t, node*>::ref cb, node *retVal) {

  //stash the old root
  node *oldroot = fetch(1);

  //unhash the old root
  bufPool.remove(1);
  free(q.remove(1));

  replacementRec *r = q.add(1);
  ref<hashEntry> he = New refcounted<hashEntry>(retVal, r);
  bufPool.insert(1, he);

  //rehash the old node w/ a New id
  // ALLOC
  //blockID_t bID = fm->alloc(1);
  blockID_t bID = fm->alloc(sb->nodeSize());
  if (bID == 0) return;
  nodeID_t newID = blockToID(bID);
  replacementRec *r2 = q.add(newID);
  ref<hashEntry> he2 = New refcounted<hashEntry>(oldroot, r2);
  bufPool.insert(newID, he2);
  coreBytesUsed += sb->nodeSize();

  flushMetaData();
  
  (*cb)(newID, retVal);

  return;
}

void 
nodeBuf::Bufalloc(char type, bSize_t size, callback<void, bSize_t, ptr<aiobuf> >::ref cb) {

  verifySpace(size);

  ptr<aiobuf> NewBuf = a->bufalloc(size);
  if (NewBuf == NULL) {
    a->bufwait(wrap(this, &nodeBuf::Bufalloc, type, size, cb));
    return;
  }
  
  //  memset(NewBuf->base(), 0, size);

  (*cb)(size, NewBuf);
  return;
}

void
nodeBuf::bufwaitcb() {
  memWaitLock = 1;
}

/*
 * allocateNewNode - allocate an empty node and reserve a disk page
 *
 */
void 
nodeBuf::allocateNewNode(char type, nodeID_t parent, bSize_t size, callback<void, node *>::ref cb) {

  // support auto-sizing 
  if (size <= 0) 
    if (type == kSegTag) size = sb->nodeSize()*sb->dataLenFactor();
    else size = sb->nodeSize();
  
  Bufalloc(type, size, wrap(this, &nodeBuf::allocateNewNode_cb_getBuffer, type, parent, cb));
  return;
}

void nodeBuf::allocateNewNode_cb_getBuffer(char type, 
					   nodeID_t parent, 
					   callback<void, node*>::ref cb, 
					   bSize_t size, 
					   ptr<aiobuf> NewBuf) {
  
  // ALLOC
  //int blocks = size/sb->nodeSize() + 1;
  //if (size % sb->nodeSize() == 0) blocks--;
  //blockID_t id = fm->alloc(blocks);
  blockID_t id = fm->alloc(size);
  if (id == 0) return;

  initNode(NewBuf->base(), type, id, parent, size);
  coreBytesUsed += size; 
  nodeStorage *ns = New nodeStorage(NewBuf);
 
#ifdef STATS
  stats.allocation += size;
#endif

  switch(type) {
  case kIndexTag:
    allocateIndexNode(ns,tree, size, wrap(this, &nodeBuf::allocateNewNode_cb_initNode, cb));
    break;
  case kLeafTag:
    allocateLeafNode(ns,tree, size, wrap(this, &nodeBuf::allocateNewNode_cb_initNode, cb));
    break;
  case kSegTag:
    allocateDataNode(ns,tree, size, wrap(this, &nodeBuf::allocateNewNode_cb_initNode, cb));
    break;
  default:
    fatal("improper node type requested");
    break;
  }

  return;
}

void
nodeBuf::allocateNewNode_cb_initNode(callback<void, node*>::ref cb, node *newNode) {
  replacementRec *r = q.add(newNode->nodeID());
  ref<hashEntry> he = New refcounted<hashEntry>(newNode, r);
  he->dirty = 1;
  bufPool.insert(newNode->nodeID(), he); 
    
  flushMetaData();
 
  (*cb)(newNode);
  return;
}



/*
 * destructor 
 */
nodeBuf::~nodeBuf() {
  
  //close the file and free buffers
  close(fd);
  a->finalize();
  delete fm;
}

void
nodeBuf::finalize(callback<void, int>::ref cb) {

  //flush any metaData/dirty blocks
  flushMetaData();

  int *cnt = new int;
  *cnt = 0;
  int callbacksQd = 0;
  nodeID_t node_id;
  do {
    //XXX    node_id = q.next();
    node_id = q.purgeOne();
    if (node_id > 0) 
      if (flush(node_id, wrap(this, &nodeBuf::finalize_cb_flush, cb, node_id, cnt))) {
	*cnt += 1;
	callbacksQd++;
      }
  } while (node_id > 0);
  
  if (callbacksQd == 0) (*cb)(0);
  return;
}

void
nodeBuf::finalize_cb_flush(callback<void, int>::ref cb, nodeID_t node_id, int *cnt, int err) {
  
  if (err) {
    warn("error flushing block on close");
    (*cb)(err);
    return;
  }

  fflush(stderr);
  release(node_id);
  *cnt -= 1;
  if (*cnt == 0) {
    fm->finalize();
    flushMetaData();
    (*cb)(0);
  }
}

void
nodeBuf::flushMetaData() {
  
  sb->flush();
}

void
nodeBuf::compact() {

  int handle;
  blockID_t newAddr;
  if (fm->compactOne(&handle, &newAddr)) {
    readNode(handle, kGuessSize, kOrphan, wrap(this, &nodeBuf::compact_cb_readNode, newAddr));
  } else {
    bSize_t truncdSize = fm->minFileSize();
    printf("truncing to %ld\n", truncdSize);
    f->ftrunc(truncdSize, wrap(&compact_cb));
  }
}

void 
statcb(struct stat *s, int err) {

  long size = s->st_size;
  printf("COMPACT: file is currently %ld\n", size);
}

void
compact_cb(int err) {

}

void
nodeBuf::compact_cb_readNode(blockID_t newAddr, node *node) {

  touchNode(node->nodeID());
  fm->doSwap(node->nodeID(), newAddr);
  flush(node->nodeID(), wrap(&compact_cb));
  compact();

}
/*
 *  NODE FACTORY STUFF (keep here?)
 */


/*
 *  allocateLeafNode
 *
 *  pseudo-constructor that returns in a call-back (all the rage, you
 *  know, for async-savvy apps) 
 */
void
nodeBuf::allocateLeafNode(nodeStorage *b, btree *tree, int Size, callback<void, node *>::ref cb) {

  leafNode *n = new leafNode(b, tree, Size);
  
  //create our data node
  /*  if (n->getDataHint() <= 0) 
    allocateNewNode(kSegTag, n->nodeID(), 0, wrap(this, &nodeBuf::allocateLeafNode_cb_allocateDataNode, n, cb));
    else */
    (*cb)(n);
  
}

/*
 * leafNode_cb_allocateDataNode
 *
 * Callback (from allocateNewNode) which sets the dataID of this (the
 * leaf node)
 */
void
nodeBuf::allocateLeafNode_cb_allocateDataNode(node *n, callback<void, node *>::ref cb, node *newDataNode) {
  if (newDataNode == NULL) fatal("failed to create child node, full disk");
  leafNode *parent = (dynamic_cast<leafNode *>(n));
  assert(parent);
  parent->setDataHint(newDataNode->nodeID());
  (*cb)(n);
  return;
}

/*
 *  allocateIndexNode
 *
 *  pseudo-constructor that returns in a call-back (even though index node doesn't really need to)
 */
void
nodeBuf::allocateIndexNode(nodeStorage *b, btree *tree, int Size, callback<void, node *>::ref cb) {

  indexNode *n = new indexNode(b, tree, Size);

  (*cb)(n);
  return;
}

/*
 *  allocateDataNode
 *
 *  pseudo-constructor that returns in a call-back
 */
void
nodeBuf::allocateDataNode(nodeStorage *b, btree *tree, int Size, callback<void, node *>::ref cb) {

  dataNode *n = new dataNode(b, tree, Size);

  (*cb)(n);
  return;
}


