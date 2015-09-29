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
 * btree.h 
 *
 * btree provides the API to a B+-tree capable of supporting the
 *   search, insert, delete(soon) and iterate operations. This class
 *   provides a general implementation of a btree and is not used
 *   directly. Instance btreeSync or btreeDispatch to use this library.
 */
 
#ifndef _BTREE_H_
#define _BTREE_H_

class btree;

#include "bSearchPath.h"
#include "bIteration.h"
#include "node.h"
#include "nodeBuf.h"
#include "opnew.h"
#include "record.h"

#define kNotFound -1
#define kFoundInLeaf -2
#define kFoundInData 0
#define kNoErr 0
#define kOutOfMem -3
#define kEmptyNode -3

#define kOverwrite 2
#define kNoDuplicates 4
#define kExactMatchOnly 1
#define kNearestKey 2

#define bFileCreationError -128
#define bOpenError -129
#define bKeyNotFoundError -130
#define bOutOfMemError -131
#define bWriteError -132
#define bLongKeyError -133
#define bDuplicateKeyError -134

#define kShiftRight 1
#define kShiftLeft 2

#define timediff(start, end) ((end.tv_sec - start.tv_sec)*1000000 + (end.tv_usec -  start.tv_usec))

//static methods
bError_t createTree(char *filename, char create, short nodeSize, short dataLenFactor);
char * bstrerror(bError_t err);
void primitiveTiming(nodeBuf *buffer);
void primitiveTiming_cb_readNode(long elapsed);
void testReadNode(nodeBuf *,int, int, struct timeval *, callback<void, long>::ref, node *);
void startTimer();
void stopTimer();
long elapsedmsecs();

//global vars (mostly for stats)
struct statsRec {
  long gc_spaceUsed;
  long gc_totalSpace;
  long gc_emptyNodes;
  long cache_requests;
  long cache_indexHits;
  long cache_leafHits;
  long cache_indexMisses;
  long cache_leafMisses;
  long allocation;
  long stored;
  long readMin;
  long readMax;
  long readCount;
  long readTotalTime;
  long readBufSplitTotal;
  long readBeforeInsertSplit;
  FILE* output;
};

extern statsRec stats;
extern nodeID_t rootForwardingAddress;
extern bSize_t  kResidentDataMaxSize;
extern struct timeval gStartTime, gFinishTime;

#define GC_LIMIT 100


//types
typedef callback<void, tid_t, int, record *>::ref cbdispatch;

class btree {
  
  friend class indexNode;

 public:
  btree(cbdispatch cb);
  virtual ~btree();

  bError_t open(char* filename, long cacheSize);

  bError_t search(tid_t tid, void *key, int len);
  bError_t insert(tid_t tid, void *key, int keyLength, void *value, int valueLength);
  bError_t insert(tid_t tid, record *item);
  bError_t remove(tid_t tid, void *key, int len);
  bError_t iterate(tid_t tid, bIteration *it);
 
  bError_t GC(callback<void>::ref cb_done);
  void findAnchor(void *key1, bSize_t len1, void *key2, bSize_t len2,
		  callback<void, node *>::ref cb);
  void firstLeaf(callback<void, nodeID_t>::ref cb);
  
  bError_t setInsertPolicy(int policy) { insertPolicy = policy; return 0;};
  int      getInsertPolicy() { return insertPolicy; }
  bError_t setLookupPolicy(int policy) { lookupPolicy = policy; return 0;};
  int      getLookupPolicy() { return lookupPolicy; }

  bError_t finalize(tid_t tid);
  int      nodeSize();
  nodeBuf *bufPool() {return buffer;};
  void     setRoot(node *newRoot) {root = newRoot;};
  
  virtual int comparisonFunction(void *key1, int len1, void *key2, int len2);
  
  void printRep(char *msg);

 private:
  node *root;
  nodeBuf *buffer;
  cbdispatch dispatch_cb;
  int treeHeight;
  int insertPolicy;
  int lookupPolicy;

  void incHeight();
  void decHeight();

  void firstLeaf_cb_readNode(callback<void, nodeID_t>::ref cb, node *n);

  void search(tid_t tid, void *key, int len,  
	       bSearchPath *path, node *curNode);

  void insert_cb_readIndex(tid_t tid, record *item, bSearchPath *path, node *curNode);
  void insert_cb_getLock(tid_t tid, record *item, bSearchPath *path, node *curNode);
  void insert_cb_readLeaf(tid_t tid, bSearchPath *path, int err);

  void generateIteration(bIteration *it, tid_t tid, nodeID_t n);
  void iterate_cb_readNode(tid_t tid, bIteration *it, node *n);
  void iterate_cb_readDataNode(tid_t tid, bSize_t off, record *rec, node *n);

  void remove(tid_t tid, void *key, int len, bSearchPath *path, node *curNode);
  void remove_cb_GCdone(tid_t tid, void *key, int len);

  void finalize_cb_completion(int tid, int err);
  void finalize_cb_lastGC(tid_t tid);
  void printRep_cb_readNode(node *n);

  void GC_cb_doIndex(callback<void>::ref done_cb,
		     bSearchPath *nodes,
		     bSearchPath *offsets,
		     int i,
		     node *currentNode);
  void GC_cb_getLock(callback<void>::ref cb);
  void GC_cb_doLeaves(callback<void>::ref cb, node *leaf);
  void GC_cb_startLeaves(callback<void>::ref cb, nodeID_t nid);
  void GC_cb_readNextLeaf(callback<void>::ref cb, node *leaf);
  void GC_cb_done();
  void GC_cb_null();


  void findAnchor_cb(void *key1, bSize_t len1, void *key2, bSize_t len2,
		     callback<void, node *>::ref cb, node *nextNode);
};

#endif /* !_BTREE_H_ */






