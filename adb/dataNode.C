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

#include <dataNode.h>
#include <leafNode.h>
#include <stdlib.h>
#include <btree.h>
#ifdef DMALLOC
#include <dmalloc.h>
#endif

int dcf(const void *aa, const void *bb);

dataNode::dataNode(nodeStorage *b, btree *tree, int Size) : node(b, tree, Size) {

  header = (dataNodeHeader *)b->base();
  ID = header->tag;
  startOfFreeSpace = (char *)b->base() + Size - header->dataSize;
  size = Size;

  repOK();

}

dataNode::~dataNode() {

}

/* insert - insert will add the item to the data node. The
 *          callback will return the item's index into the
 *          localPointer's array. Using indexes allows us
 *          to compact the node w/o updating our parent.
 *
 *          WARNING: policy is overloaded. 
 *              0 -> new key
 *              non-zero -> replace this key (for duplicate inserts)
 */
void
dataNode::insert(record *item, int policy, callback<void, int>::ref cb) {

  //lock ourselves down (fake the tid)
  getLock(bLockEx, (tid_t)item, wrap(this, &dataNode::insert_cb_getLock, item, policy, cb));
  return;
}

void
dataNode::insert_cb_getLock(record *item, int policy, callback<void, int>::ref cb) {

  bSize_t valueLen;
  void *val = item->getValue(&valueLen);
  nodeID_t parentID;
  item->getKey(&parentID);

  TOUCH();

  if ( (policy != kAllowLargeInsert) && ((valueLen) > header->nodeSize/2)) {
    freeLock();
    insertIndNode(item, cb);
    return;
  }

  //remove the data that exists currently for this key
  int adj_len = valueLen;
  if (policy > 0) {
    adj_len -= nth_valueLen(policy);
    header->offsets[policy] = 0;
    compact();
  }

  if (splitRequired(adj_len)) {
    split(item, cb);
    return;
  }
  
  //copy in data
  startOfFreeSpace = (void *)( (char *)startOfFreeSpace - (valueLen + sizeof(dataElemRep)) ); 
  dataElemRep *de = (dataElemRep *)(startOfFreeSpace);
  de->len = valueLen;
  memcpy(de->data, val, valueLen);
  de->parent = parentID;
  item->dealloc();
  delete item;

  //update pointers
  int pos = (policy < 0) ? 0 : policy;
  while ( (pos < header->maxElems) && (header->offsets[pos] != 0)) pos++;
  header->offsets[pos] = (char *)startOfFreeSpace - (char *)data->base();
  
  //update header
  header->dataSize += valueLen + sizeof(dataElemRep);
  if (pos == header->maxElems) header->maxElems++;
  if (policy < 0) header->numElems++;

  dataPtr *dp = new dataPtr;
  dp->dataID = ID;
  dp->offset = pos;
  (*cb)((int)dp);
  freeLock();
}

/*
 * InsertIndNode -- insert in independent data node
 *
 * Independendent data nodes are a second class of data nodes which
 * are used to hold large data items. They give up the locality aspect
 * of dataNodes in return for allowing large items in a otherwise
 * small tree.
 * 
 */
void
dataNode::insertIndNode(record *item, callback<void, int>::ref cb) {

  bSize_t totalSize = item->recordLen() + sizeof(dataNodeHeader) + 128; 
  tree->bufPool()->allocateNewNode(kSegTag, kOrphan, totalSize, 
				   wrap(this, &dataNode::insertIndNode_cb_allocateNode, item, cb));
  
}
void
dataNode::insertIndNode_cb_allocateNode(record *item, callback<void, int>::ref cb, node *dnode) {

  (dynamic_cast<dataNode *>(dnode))->setNext(-1);
  dnode->insert(item, kAllowLargeInsert, cb);
  return;
}

// NOTE: interpret len as an indirect offset
void
dataNode::remove(void *key, bSize_t len) {

  TOUCH();

  int i = len;
  if (header->offsets[i] == 0) return;
  header->dataSize -= nth_valueLen(i);
  header->offsets[i] = 0;
  header->numElems--;
  
  //independent nodes GC themselves since they have no parent
  if ((header->next == -1) && (header->numElems == 0)) tree->bufPool()->kill(ID);

  compact();
}

/* search - return the value associated w/ item at offset len 
 *
 * NOTE: overloaded arguments: ignore key, interrpret len as an offset (others as in node.h)
 */
nodeID_t
dataNode::search(void *key, bSize_t len, void **retValue, bSize_t *retLen) {

  if (header->offsets[len] == 0) 
    return -1;

  *retLen = nth_valueLen(len);
  *retValue = nth_value(len);
  return kFoundInData;
}

bSize_t
dataNode::surplus() {
  return (bSize_t)(header->dataSize - 0.5*header->nodeSize);
}
char
dataNode::underflow() {
  float ut = ((float)(header->dataSize))/header->nodeSize;
  return (ut < 0.5);
}

/*
 * --- Shift - 
 *
 *    Delete an item from an extreme end of the node and
 *    return it. Data nodes are an exception as usual since items are
 *    stored in no particular order. just return an item from the front of
 *    the node
 *  
 */
bSize_t
dataNode::shift(void **value, bOffset_t *offset, nodeID_t *parent) {

  int off = 0;
  while (header->offsets[off] == 0) off++;
  bSize_t len = nth_valueLen(off);

  dataElemRep * elem =  ((dataElemRep *)( (char *)data->base() + header->offsets[off]));

  *parent = (elem->parent == 1) ? rootForwardingAddress : elem->parent;
  *offset = off;
  *value = nth_value(off);

  remove(NULL, off);
  TOUCH();
  return len;
}

void *
dataNode::nth_key(int i) {
  return NULL; //data nodes don't store keys
}
bSize_t 
dataNode::nth_keyLen(int i) {
  return -1; //ditto
}
void *
dataNode::nth_value(int i) {
  return derefLocalValue(header->offsets[i]);
}
bSize_t
dataNode::nth_valueLen(int i) {
  return derefLocalValueLen(header->offsets[i]);
}

void * 
dataNode::derefLocalValue(localPtr_t lPtr) {
  //return the value associated with the local pointer lPtr
   
  dataElemRep *de = (dataElemRep *)( (char *)data->base() + lPtr);
  return de->data;
}

bLocalSize_t
dataNode::derefLocalValueLen(localPtr_t lPtr) {
  //return the length of the data associated w/localPointer lPtr

  return ((dataElemRep *)( (char *)data->base() + lPtr))->len;
}

struct lpp {
  localPtr_t lp;
  int i;
};

int dcf(const void *aa, const void *bb) {

  lpp *a = (lpp *)aa;
  lpp *b = (lpp *)bb;
  if (a->lp < b->lp) return -1;
  else if (a->lp > b->lp) return 1;
  else return 0;
}

void 
dataNode::compact() {

  lpp *lp = (lpp *)malloc(sizeof(lpp)*header->maxElems);
  
  //copy out the local pointer values
  for (int i=0; i < header->maxElems; i++) {
    lp[i].lp = header->offsets[i];  
    lp[i].i = i;
  }

  //sort them
  qsort(lp, header->maxElems, sizeof(lpp), &dcf);
  
  startOfFreeSpace = (char *)data->base() + size;
  //move each towards the bottom starting with the largest offset
  for (int i = header->maxElems - 1; i >= 0; i--) {
    if (lp[i].lp == 0) continue;
    dataElemRep * de = (dataElemRep *)((char *)data->base() + lp[i].lp);
    startOfFreeSpace = (void *)( (char *)startOfFreeSpace - (de->len + sizeof(dataElemRep)));
    memmove((char *)startOfFreeSpace, de, de->len + sizeof(dataElemRep));
    //and update the actual pointer
    header->offsets[lp[i].i] = (char *)startOfFreeSpace - (char *)data->base();
  }
  
  free(lp);
  TOUCH();
  return;
}

int locateKey(void *key, int len) {

  warn("not applicable to data nodes");
  return 1;
}

char
dataNode::splitRequired(int bytesAdded) {

  return ( ( (char *)startOfFreeSpace - bytesAdded - 4) < 
	  ((char *)header + sizeof(dataNodeHeader) + sizeof(dataElemRep)*header->maxElems));


}

void
dataNode::split(record *item, callback<void, int>::ref cb) {

  //get a handle om my parent
  /*  tree->bufPool()->readNode(header->parent, kGuessSize, kOrphan, 
			    wrap(this, &dataNode::split_cb_allocateBuffer, item, cb));
  */
  tree->bufPool()->allocateNewNode(kSegTag, header->parent, 0, 
				   wrap(this, &dataNode::split_cb_allocateBuffer, item, cb));
  TOUCH();
  return;
}

void
dataNode::split_cb_readParent(record *item, callback<void, int>::ref cb, node *parent) {

  //allocate a New node
  tree->bufPool()->allocateNewNode(kSegTag, header->parent, 0, 
				   wrap(this, &dataNode::split_cb_allocateBuffer, item, cb));
  
  return;
}

void
dataNode::split_cb_allocateBuffer(record *item, callback<void, int>::ref cb, node *n) {
  
  if (n == NULL) fatal("data node split on full disk");
  
  repOK();

  //fix the chain
  (dynamic_cast<dataNode *>(n))->setNext(ID);
  n->setParent(header->parent);
  //int id = n->nodeID();
  //  leafNode *parent_leaf = (dynamic_cast<leafNode *>(parent));
  //if (parent_leaf)
  //  parent_leaf->setDataHint(id);

  n->insert(item, -1, cb);
  freeLock();
    
  return;
}

void
dataNode::printRep() {

  printf("dataNode: %ld |", ID);
  for (int i = 0; i < header->maxElems; i++) {
    if (header->offsets[i] != 0) {
      int len = nth_valueLen(i);
      char val[64000];
      memcpy(val, nth_value(i), len);
      val[len] = 0;
      printf("| %s |", val);
    }
  }
  printf("\n");
}

char 
dataNode::repOK() {

  if ((header->nodeType != kSegTag) ||
      (startOfFreeSpace == NULL)) {
    char *p = (char *)10;
    *(p - 10) = 's';
  }

  return 1;
}

void
dataNode::GC(callback<void>::ref cb) {

  assert(underflow());

  //get our next node
  TOUCH();
  tree->bufPool()->readNode(header->next, kGuessSize, kOrphan, wrap(this, &dataNode::GC_cb_haveNext, cb));
  return;
}

void
dataNode::GC_cb_haveNext(callback<void>::ref cb, node *next) {
  if (next->underflow()) {
    printf("GC (datanode) shift case: %ld\n", ID);
    GC_cb_doShift(next, cb);
  } else {
    printf("GC (datanode) merge case: %ld\n", ID);
    GC_cb_doMerge(next, cb);
  }

}

void
dataNode::GC_cb_doShift(node *next, callback<void>::ref cb) {

  if (next->surplus() > 0) {
    void *value;
    nodeID_t parentID;
    bOffset_t offset;
    bSize_t valueLen = (dynamic_cast<dataNode *>(next))->shift(&value, &offset, &parentID);
    record *item = new record(NULL, 0, value, valueLen);
    tree->bufPool()->readNode(parentID, kGuessSize, kOrphan, 
			      wrap(this, &dataNode::GC_cb_fixParent, next, item, offset, cb, 0));
  } else {
    (*cb)();
  } 
  return;
}

void
dataNode::GC_cb_doMerge(node *next, callback<void>::ref cb) {
  header->next = (dynamic_cast<dataNode *>(next))->next();
  
  if (next->numElems() != 0) {
    void *value;
    nodeID_t parentID;
    bOffset_t offset;
    bSize_t valueLen = (dynamic_cast<dataNode *>(next))->shift(&value, &offset, &parentID);
    record *item = new record(new record(NULL, 0, value, valueLen));
    tree->bufPool()->readNode(parentID, kGuessSize, kOrphan, 
			      wrap(this, &dataNode::GC_cb_fixParent, next, item, offset, cb, 1));
  } else 
    (*cb)();
}

void
dataNode::GC_cb_fixParent(node *next, record *item, 
			  bOffset_t offsetInParent, 
			  callback<void>::ref cb,
			  char merge, node *itemsParent) {

  leafNode *parent = (dynamic_cast<leafNode *>(itemsParent));
  int i = 0;
  while (parent->nthDataPtr(i)->offset != offsetInParent) i++;
  dataPtr *parentsDataPtr = parent->nthDataPtr(i); 
  this->insert(item, kUniqueItem, wrap(this, &dataNode::GC_cb_reinsertDone, next, parentsDataPtr, cb, merge));
  return;
}

void
dataNode::GC_cb_reinsertDone(node *next, 
			     dataPtr *dPtrToModify, 
			     callback<void>::ref cb, 
			     char merge, 
			     int hiddenDataPtr) {

  dataPtr *newDataPtr = (dataPtr *)(hiddenDataPtr);
  memcpy(dPtrToModify, newDataPtr, sizeof(dataPtr));
  delete newDataPtr;

  if (merge)
    GC_cb_doMerge(next, cb);
  else
    GC_cb_doShift(next, cb);
}

void
dataNode::setItemParent(bOffset_t offset, nodeID_t parent) {
  TOUCH();
  dataElemRep *de = (dataElemRep *)((char *)data->base() + header->offsets[offset]);
  de->parent = parent;
}

