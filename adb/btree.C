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

#include <btree.h>
#include <btree_types.h>
#include <bSearchPath.h>
#include <dataNode.h>
#include <indexNode.h>
#include <leafNode.h>
#include <record.h>

#ifdef DMALLOC
#include "dmalloc.h"
#endif

//global variable definition
long gc_deleteCount;
nodeID_t rootForwardingAddress;
bSize_t kResidentDataMaxSize;
struct timeval gStartTime;
struct timeval gFinishTime;

btree::btree(cbdispatch cb) : dispatch_cb(cb) {
  
  treeHeight = 0;
  insertPolicy = kNoDuplicates;
  lookupPolicy = kExactMatchOnly;
  gc_deleteCount = 0;
  
#ifdef STATS
  memset(&stats, 0, sizeof(stats));
  stats.readMin = RAND_MAX;
  char *statsFile = getenv("BTREE_STATS");
  if (statsFile == NULL) statsFile = "/dev/stdout";
  stats.output = fopen(statsFile, "a");

#endif /*STATS*/

}

btree::~btree() {
#ifdef STATS
  FILE *statsFile = stats.output;
  time_t t = time(NULL);
  fprintf(statsFile, "\n\nbtree statistics run ending %s\n", ctime(&t));
  fprintf(statsFile, "general info: \n");
  fprintf(statsFile, "   node size: %d\n", nodeSize());
  fprintf(statsFile, "   height: %d\n", treeHeight);
  fprintf(statsFile, "space usage: \n");
  fprintf(statsFile, "   %ld bytes allocated\n", stats.allocation);
  fprintf(statsFile, "   %ld bytes used\n", stats.stored);
  fprintf(statsFile, "   efficency: %f\n", ((float)stats.stored)/stats.allocation);
  fprintf(statsFile, "cache statistics: \n");
  fprintf(statsFile, "   %ld total requests\n", stats.cache_requests);
  fprintf(statsFile, "   %ld total hits\n", stats.cache_indexHits + stats.cache_leafHits);
  fprintf(statsFile, "   %ld index hits\n", stats.cache_indexHits);
  fprintf(statsFile, "   %ld non-index hits\n", stats.cache_leafHits);
  fprintf(statsFile, "   hit rate (leaf): %f\n", 
	  ((float)stats.cache_leafHits)/(stats.cache_leafHits + stats.cache_leafMisses));
  fprintf(statsFile, "   hit rate (index): %f\n", 
	  ((float)stats.cache_indexHits)/(stats.cache_indexHits + stats.cache_indexMisses));
  fprintf(statsFile, "   hit rate (total): %f\n", 
	  ((float)stats.cache_indexHits + stats.cache_leafHits)/stats.cache_requests);
  fprintf(statsFile, "GC:\n");
  fprintf(statsFile, "   %ld nodes removed\n", stats.gc_emptyNodes);
  fprintf(statsFile, "   usage: %f\n", ((float)stats.gc_spaceUsed)/stats.gc_totalSpace);
  fprintf(statsFile, "Read timing (%ld reads):\n", stats.readCount);
  fprintf(statsFile, "   min: %ld\n", stats.readMin);
  fprintf(statsFile, "   max: %ld\n", stats.readMax);
  fprintf(statsFile, "   avg: %f\n", (float)stats.readTotalTime/stats.readCount);
  fprintf(statsFile, "   avg buffer alloc. split: %f\n", (float)stats.readBufSplitTotal/stats.readCount);
  fprintf(statsFile, "   avg before insert split: %f\n", (float)stats.readBeforeInsertSplit/stats.readCount);
  //primitiveTiming(buffer);

#endif

}

/*
 * open
 *
 * Open an existing database named by filename. cacheSize specifies
 * the size of the in memory node cache in bytes.
 * 
 */

bError_t 
btree::open(char * filename, long cacheSize) {
  
  buffer = New nodeBuf(this, cacheSize, filename);
  if (buffer == NULL) return bOpenError;
  buffer->init();

  root = buffer->fetch(1);
  assert(root);
  root->isLeaf();
  return 0;
}

/*
 * Search  
 *
 * Search the tree for key, return correspnding value
 *
 *
 */
bError_t
btree::search(tid_t tid, void *key, int len) {

#ifdef DEBUG
  char message[128];
  sprintf(message, "op: search %ld", tid);
  printRep(message);
#endif

  bSearchPath *path = New bSearchPath();
  search(tid, key, len, path, root);
  return 0;
}

void
btree::search(tid_t tid, void *key, int len, 
	       bSearchPath *path, node *curNode) {

  assert(curNode);

  void *value;
  bSize_t valueLen;
  nodeID_t nodeId;

  nodeId = curNode->search(key, len, &value, &valueLen);
  
  switch (nodeId) {
  case kEmptyNode: //would be in leaf node that was garbage collected
  case kNotFound: //not in tree or fatal error
    delete path;
    (*dispatch_cb)(tid, bKeyNotFoundError, NULL);
    break;
  case kFoundInLeaf: //found in leaf, search data node
    buffer->readNode(((dataPtr *)value)->dataID, kGuessSize, path->lastNode(),
		     wrap(this, &btree::search, tid, key, 
			  ((dataPtr *)value)->offset,path));
    break;
  case kFoundInData: //found in data node
    delete path;
    (*dispatch_cb)(tid, kNoErr, New record(key, len, value, valueLen));
    break;
  default:
    //continuing search in index part of tree
    path->addNode(curNode->nodeID());
    buffer->usedNode(curNode->nodeID());
    buffer->readNode(nodeId, kGuessSize, path->lastNode(), 
		     wrap(this, &btree::search, tid, key, len, path));
    break;
  }
  return;
}

/*
 *  Insert
 *
 *  Insert the key, value pair into the tree
 *
 */
bError_t
btree::insert(tid_t tid, void *key, int keyLength, void *value, int valueLength) {
  
  //reject extremely long keys TODO: store them externally?
  if (keyLength > root->nodeSize()/2) return bLongKeyError;
  
#ifdef DEBUG
  char message[128];
  sprintf(message, "op: insert %ld", tid);
  printRep(message);
#endif

#ifdef STATS
  stats.stored += keyLength + valueLength;
#endif

  record *rec = New record(key,keyLength, value, valueLength);
  if (rec == NULL) fatal("out of memory");
  return insert(tid, rec);

}

bError_t
btree::insert(tid_t tid, record *item) {
  
  //test for full disk
  if (!buffer->preflightAllocation(treeHeight + buffer->dataNodeFactor())) return bOutOfMemError;
  bSearchPath *path = New bSearchPath();
  insert_cb_readIndex(tid, item, path, root);
  return 0;
}

void
btree::insert_cb_readIndex(tid_t tid, record *item, bSearchPath *path, node *curNode) {

  assert(curNode);
  curNode->getLock(bLockEx, tid, wrap(this, &btree::insert_cb_getLock, tid, item, path, curNode));
}

void
btree::insert_cb_getLock(tid_t tid, record *item, bSearchPath *path, node *curNode) {

  path->addNode(curNode->nodeID());

  //extract data from the record
  void *key;
  bSize_t len;
  key = item->getKey(&len);

  if (!curNode->isLeaf()) {
    nodeID_t nodeId = curNode->search(key, len, NULL, NULL);
    buffer->usedNode(curNode->nodeID());
    buffer->readNode(nodeId, kGuessSize, path->lastNode(), wrap(this, &btree::insert_cb_readIndex, tid, item, path));
    return;
  }
 
  if (curNode->isLeaf()) {
    curNode->insert(item, insertPolicy, wrap(this, &btree::insert_cb_readLeaf, tid, path));
    return;
  }
  
}
 
void
btree::insert_cb_readLeaf(tid_t tid, bSearchPath *path, int err) {

  nodeID_t n;
  //free all of the locks
  // we can use fetch because they are locked in core
  do {
    n = path->pop();
    if (n > 0) {
      node *N = buffer->fetch(n);
      N->freeLock();
    }
  } while (n != -1);

  delete path;

  (*dispatch_cb)(tid, err, NULL);
}

/*
 * remove
 *
 * Delete the key from the tree
 *
 */
bError_t
btree::remove(tid_t tid, void *key, int len) {

  if (gc_deleteCount > GC_LIMIT) {
    GC(wrap(this, &btree::remove_cb_GCdone, tid, key, len));
    gc_deleteCount = 0;
    return 0;
  }
  gc_deleteCount++;
  remove_cb_GCdone(tid, key,len);
  return 0;
}

void
btree::remove_cb_GCdone(tid_t tid, void *key, int len) {
  bSearchPath *path = New bSearchPath();
  remove(tid, key, len, path, root);
  return;
}

void
btree::remove(tid_t tid, void *key, int len, bSearchPath *path, node *curNode) {
  
  assert(curNode);
  
  if (!curNode->isLeaf()) {
    //search for the leaf node containing key 
    //(index nodes will be untouched on way down tree)
    nodeID_t id = curNode->search(key, len, NULL, NULL);
    path->addNode(curNode->nodeID());
    buffer->readNode(id, kGuessSize , path->lastNode(), wrap(this, &btree::remove, tid, key, len, path));
    return;
  }

  if (curNode->isLeaf()) {
    if (curNode->search(key, len, NULL, NULL) != kFoundInLeaf) 
      (*dispatch_cb)(tid, bKeyNotFoundError, NULL); 
    else {
      curNode->remove(key, len);
      (*dispatch_cb)(tid, 0, NULL);
    }
  }
}

/*
 * firstLeaf
 *
 * return the id of the first leaf of the tree. Used by iterate
 */
void
btree::firstLeaf(callback<void, nodeID_t>::ref cb) {

  firstLeaf_cb_readNode(cb, root);
}

void
btree::firstLeaf_cb_readNode(callback<void, nodeID_t>::ref cb, node *n) {
  
  assert(n);

  nodeID_t nodeId;
  char key[8];
  key[0] = 0;
  void *value;
  bSize_t valueLen;

  if (n->isLeaf()) {
    (*cb)(n->nodeID());
    return;
  }

  nodeId = n->search(key, 1, &value, &valueLen);

  if (nodeId == -1) {
    (*cb)(-1);
    return;
  }

  buffer->readNode(nodeId, kGuessSize, kOrphan, wrap(this, &btree::firstLeaf_cb_readNode, cb));
  return;
}

/*
 * Iterate
 *
 * Return each element in the tree in key order
 *
 */
bError_t
btree::iterate(tid_t tid, bIteration *it) {

  assert(it);
  if (it->null()) {
    //iteration is starting, find leftmost leaf node
    firstLeaf(wrap(this, &btree::generateIteration, it, tid));
    return 0;
  }

  if (it->lastNode() == 0) { 
    (*dispatch_cb)(tid, -1, NULL);
    return -1;
  }
  else
    buffer->readNode(it->lastNode(), kGuessSize, kOrphan, wrap(this, &btree::iterate_cb_readNode, tid, it));
  
  return 0;
}

void
btree::generateIteration(bIteration *it, tid_t tid, nodeID_t n) {

  it->setNode(n);
  it->setOffset(0);

  iterate(tid, it);
  return;
}

void
btree::iterate_cb_readNode(tid_t tid, bIteration *it, node *n) {

  int offset = it->off();
  //special case for empty nodes
  if (offset >= n->numElems()) {
    it->setNode( (dynamic_cast<leafNode *>(n))->nextPtr());
    it->setOffset(0);
    iterate(tid, it);
    return;
  }
  
  //get the ID of the data record
  //  record *rec =  (dynamic_cast<leafNode *>(n))->ithRecord(offset);
  record *rec = new record(n->nth_key(offset),
			   n->nth_keyLen(offset),
			   n->nth_value(offset),
			   n->nth_valueLen(offset));
  
  //update the iteration record (non-empty case)
  if (it->off() < (n->numElems() - 1))
    it->setOffset(it->off() + 1);
  else {
    it->setNode( (dynamic_cast<leafNode *>(n))->nextPtr());
    it->setOffset(0);
  }

  //read the data node
  bSize_t len;
  void *value = rec->getValue(&len);
  if (len > kResidentDataMaxSize) {
    dataPtr *dp = (dataPtr *)value;
    buffer->readNode(dp->dataID, kGuessSize, kOrphan, wrap(this, &btree::iterate_cb_readDataNode, tid, dp->offset, rec));
  } else {
    (*dispatch_cb)(tid, 0, rec);
  }
    
return;
}

void
btree::iterate_cb_readDataNode(tid_t tid, bSize_t off, record *rec, node *dn) {
  
  void *res;
  bSize_t len;

  dn->search(NULL, off, &res, &len);
  rec->setValue(res,len); 

  (*dispatch_cb)(tid, 0, rec);
}

int
btree::nodeSize() {

  return buffer->nodeSize();
}

int
btree::comparisonFunction(void *key1, int len1, void *key2, int len2) {

  int len = (len1 < len2) ? len1 : len2;
  int res = memcmp(key1, key2, len);
  if (res == 0) {
    if (len1 < len2) return -1;
    else if (len1 > len2) return 1;
    else return 0;
  } else
    return res;
}

/*
 * finalize
 *
 * make sure that all cached nodes are written to disk and pending
 * operations completed
 * 
 */
bError_t
btree::finalize(tid_t tid) {
  //GC(wrap(this, &btree::finalize_cb_lastGC, tid));
  finalize_cb_lastGC(tid);
  return 0;
}
void
btree::finalize_cb_lastGC(tid_t tid) {
  buffer->finalize(wrap(this, &btree::finalize_cb_completion, tid));
  return;
}

void
btree::finalize_cb_completion(int tid, int err) {
  (*dispatch_cb)(tid, err, NULL);
}

/*
 * GC
 *
 * Garbage collect the tree to reduce space wastage.
 *
 */
bError_t
btree::GC(callback<void>::ref cb_done) {

#ifdef STATS
  //clear out global statistics variables
  stats.gc_spaceUsed = 0;
  stats.gc_totalSpace = 0;
  stats.gc_emptyNodes = 0;
#endif

  //lock the tree
  root->getLock(bLockEx, -1, wrap(this, &btree::GC_cb_getLock, cb_done));
  return 0;
}

void
btree::GC_cb_getLock(callback<void>::ref cb) {
  //find the first leaf, then do the leaves by walking links
  firstLeaf(wrap(this, &btree::GC_cb_startLeaves, cb));
  return;
}

void
btree::GC_cb_startLeaves(callback<void>::ref cb, nodeID_t nid) {
  buffer->readNode(nid, kGuessSize, kOrphan, 
		   wrap(this, &btree::GC_cb_doLeaves, cb));
  return;
}

void
btree::GC_cb_doLeaves(callback<void>::ref cb, node *leaf) {
  //recurse
  printf("leaf %ld, surplus = %ld\n", leaf->nodeID(), leaf->surplus());
  leaf->GC(wrap(this, &btree::GC_cb_readNextLeaf, cb, leaf));
}
void btree::GC_cb_readNextLeaf(callback<void>::ref cb, node *leaf) {

  nodeID_t newNode = (dynamic_cast<leafNode *>(leaf))->nextPtr();
  if (newNode > 0)
    buffer->readNode(newNode, kGuessSize, kOrphan, 
		     wrap(this, &btree::GC_cb_doLeaves,cb));
  else
    GC_cb_doIndex(cb, new bSearchPath(), new bSearchPath(), -1, root);
  
}

void
btree::GC_cb_null() {};

void
btree::GC_cb_doIndex(callback<void>::ref done_cb, 
		     bSearchPath *nodes, 
		     bSearchPath *offsets, 
		     int i, 
		     node *currentNode) {

  if ((currentNode->isLeaf()) || (i == currentNode->numElems())) {
    //examine current node since children are done 
    if (i == currentNode->numElems())
      currentNode->GC(wrap(this, &btree::GC_cb_null));
    //go back up and recurse down another branch
    nodeID_t pID = nodes->pop();
    nodeID_t pOffset = offsets->pop();
    if (pID == -1) {
      printf("\nindex node GC done\n");
      printf("running compact\n");
      buffer->compact();
      root->freeLock();
      (*done_cb)(); //really done
      return;
    } 
    buffer->readNode(pID, kGuessSize, kOrphan, 
		     wrap(this, &btree::GC_cb_doIndex, done_cb, nodes, offsets, pOffset + 1));
    return;
  }

  //recursive calls
  nodes->addNode(currentNode->nodeID());
  offsets->addNode(i);
  while ((dynamic_cast<indexNode *>(currentNode))->ithChild(i) <= 0) i++;
  nodeID_t nid =  (dynamic_cast<indexNode *>(currentNode))->ithChild(i);
  buffer->readNode(nid, kGuessSize, kIgnoreParent, wrap(this, &btree::GC_cb_doIndex, done_cb, nodes, offsets, -1));
  return;
}

void
btree::GC_cb_done() {

  printf("Garbage collection done\n");
  root->freeLock();
  return;
}

/*
 * printRep
 *
 * print out a representation of the tree which may be displayed using
 * the included java program btreeDebug.class
 * 
 */
void
btree::printRep(char *msg) {

  FILE* debugFile;
  char *debugFileName = getenv("BTREE_DEBUG");
  if (debugFileName == NULL) {
    debugFile = stdout;
  } else {
    debugFile = fopen(debugFileName, "a");
  }
  fprintf(debugFile, "START tree debug output : %s\n", msg);
  fclose(debugFile);

  buffer->readNode(1, kGuessSize, kIgnoreParent, wrap(this, &btree::printRep_cb_readNode));
  
}
void
btree::printRep_cb_readNode(node *n) {

  n->printRep();
  if (n->isLeaf()) return;

  nodeID_t pz = (dynamic_cast<indexNode *>(n))->p_zero;
  if (pz > 0)
    buffer->readNode(pz, kGuessSize, kIgnoreParent, wrap(this, &btree::printRep_cb_readNode));
  for (int i = 0 ; i < n->numElems(); i++) {
    nodeID_t nid;
    while ( (nid = (dynamic_cast<indexNode *>(n))->ithChild(i)) <= 0) i++;
    buffer->readNode(nid, kGuessSize, kIgnoreParent, wrap(this, &btree::printRep_cb_readNode));
  }
}

/*
 * FindAnchor -- return the anchor for two given nodes. An anchor is
 * defined as the node at which the search paths to the given nodes
 * diverge
 * 
 */
void
btree::findAnchor(void *key1, bSize_t len1, void *key2, bSize_t len2,
		  callback<void, node *>::ref cb) {
  
  findAnchor_cb(key1, len1, key2, len2, cb, root);
}
void
btree::findAnchor_cb(void *key1, bSize_t len1, void *key2, bSize_t len2,
		     callback<void, node *>::ref cb, node *nextNode) {

  nodeID_t node1 = nextNode->search(key1, len1, NULL, NULL);
  nodeID_t node2 = nextNode->search(key2, len2, NULL, NULL);
  
  if (node1 != node2) (*cb)(nextNode);
  else
    buffer->readNode(node1, kGuessSize, kIgnoreParent,
		     wrap(this, &btree::findAnchor_cb,
			  key1, len1, key2, len2, cb));
  return;
}

void btree::incHeight() { treeHeight++; }
void btree::decHeight() { treeHeight--; }


