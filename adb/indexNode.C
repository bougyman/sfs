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

int icf(const void *aa, const void *bb);

#include <node.h>
#include <indexNode.h>
#include <leafNode.h>
#ifdef DMALLOC
#include <dmalloc.h>
#endif

void update_cb_insert(int err);

indexNode::indexNode(nodeStorage *b, btree* tree, int size) : node(b,tree, size) {

  header = (indexNodeHeader *)b->base();
  p_zero = header->p_zero;
  ID = header->tag;
  bottomOfFreeSpace = (char *)b->base() + size;

}

indexNode::~indexNode() {

}

/* 
 * insert - This function blindly inserts the item which it assumes
 *          consists of a key/pointer pair into the appropriate place
 *          in the node. This will only be called by split() and split()
 *          is required to juggle the pointers
 */
void indexNode::insert(record *item, int policy, callback<void, int>::ref cb) {

  void *key;
  bSize_t keyLen;
  void *value;
  bSize_t valLen;
  bSize_t totalLen;
  indexElemRep *elem;
  int i=0, keyLoc;

  repOK();
  TOUCH();

  //extract the data from the record
  value = item->getValue(&valLen);
  key = item->getKey(&keyLen);
  if (valLen != sizeof(nodeID_t))  {
    fatal("bad index record format");
  }

  totalLen = keyLen + sizeof(indexElemRep);

  if (splitRequired(totalLen)) { 
    split(item, cb);
    return;
  }

  repOK();
  compact();

  //fill in the record
  elem = (indexElemRep *)(bottomOfFreeSpace - totalLen);
  elem->p = *((nodeID_t *)value); //the only thing this can be is a nodeID_t *
  elem->keyLen = keyLen;
  memcpy(&(elem->key[0]), key, keyLen);
  
  //find the place to insert (items are in ascending order)
  keyLoc = locateKey(key, keyLen);
  //insert it
  for (i = header->numElems; i > keyLoc; i--) 
    header->localPointers[i] = header->localPointers[i-1]; 
  bottomOfFreeSpace -= totalLen;
  int tmp = (bottomOfFreeSpace - (char *)data->base());
  header->localPointers[keyLoc] = tmp;
  
  
  //update the header
  header->dataSize += totalLen;
  header->numElems++;

  repOK();

  //success
  (*cb)(0);

  return;
}

/*
 * Remove -- remove an entry from this node
 *
 * 
 */
void 
indexNode::remove(void *key, bSize_t len) {

  repOK();
  TOUCH();

  //find the index of the record corresponding to key
  int i=0;
  while ( (i < header->numElems) && (tree->comparisonFunction(key, len, nth_key(i),
							      nth_keyLen(i))) ) i++;
  if (i == header->numElems) {
    warn("attempt to delete non-existent element (indexNode)");
    exit(1);
  }

  //shuffle the localPointers
  for (int j = i; j < header->numElems - 1; j++) 
    header->localPointers[j] = header->localPointers[j+1];

  header->numElems--;

  repOK();
  compact();
  return;
}

/*
 * Search - search called on an indexNode will return a nodeID_t. It will
 *          never return a value since store those only in the leaves
 *
 *          This version uses a binary search
 */
nodeID_t indexNode::search(void *key, bSize_t len, void **retValue, bSize_t *retLen) {
  
  /*  int l, h,m, comp;
  l=0; h = header->numElems - 1;
      
  do {
    m = (l + h) / 2;
    void *cKey = nth_key(m);
    bSize_t cLen = nth_keyLen(m);
    comp = tree->comparisonFunction(key, len, cKey, cLen);
    if (comp == 0) {
      goto end;
    } else if (comp < 0)
      if (h==m) goto end; else h = m;
    else
      l = m+1;
  } while (l <= h);
  
 end:

  
  //the search has hit one of the duplicate keys, return the associated pointer
  if (comp == 0) return *(nodeID_t *)nth_value(m);

  //the key isn't in the list, but return the right pointer
  nodeID_t *p = NULL;
  if (comp < 0)
    if (m > 0)
      p = (nodeID_t *)nth_value(m-1);
    else
      p = &p_zero;
  else
    p = (nodeID_t *)nth_value(m);
  return *p;
  */
  
  
  int i = 0;
  int c = -1;
  
  while ( (i < header->numElems) && 
	  ((c = tree->comparisonFunction(key, len, nth_key(i), nth_keyLen(i))) > 0)) i++;
  
  //hit dup
  nodeID_t retVal=-666;
  if (c == 0)  retVal = *(nodeID_t *)nth_value(i);
  //last pointer case
  else if (i == header->numElems) retVal = *(nodeID_t *)nth_value(header->numElems - 1);
  //p_zero case
  else if (i == 0) retVal =  p_zero;
  else retVal = *(nodeID_t *)nth_value(i-1);
  
  return retVal;
}


/*
 * locateKey - determine where key is ordered with respect 
 *             to the node's existing keys. Function returns
 *             the existing key that immediately follows key
 */
int indexNode::locateKey(void *key, int len) {

  int i=0;
  while ((i < header->numElems) && (tree->comparisonFunction(nth_key(i), 
				  nth_keyLen(i), 
						key, 
						len) < 0)) i++;
  return i;
}

/*
 * compact
 *
 * Move all elements stored in this node to a contiguous region of
 * memory at the bottom of the node
 */
struct lpp {
  localPtr_t lp;
  int i;
};

int icf(const void *aa, const void *bb) {

  lpp *a = (lpp *)aa;
  lpp *b = (lpp *)bb;
  if (a->lp < b->lp) return -1;
  else if (a->lp > b->lp) return 1;
  else return 0;
}

void 
indexNode::compact() {

  repOK();
  TOUCH();

  lpp *lp = (lpp *)malloc(sizeof(lpp)*header->numElems);
  
  //copy out the local pointer values
  for (int i=0; i < header->numElems; i++) {
    lp[i].lp = header->localPointers[i];  
    lp[i].i = i;
  }
  //sort them
  qsort(lp, header->numElems, sizeof(lpp), &icf);
  
  bottomOfFreeSpace = (char *)data->base() + size;
  //move each towards the bottom starting with the largest pointer (largest offset)
  for (int i = header->numElems - 1; i >= 0; i--) {
    indexElemRep *elem = (indexElemRep *)((char *)data->base() + lp[i].lp);
    int elemSize = elem->keyLen + sizeof(indexElemRep);
    bottomOfFreeSpace -= elemSize;
    memmove((char *)bottomOfFreeSpace, elem, elemSize);
    //and update the actual pointer
    header->localPointers[lp[i].i] = bottomOfFreeSpace - (char *)data->base();
  }

  repOK();

  free(lp);
  return;
  
}

/*
 * GC
 *
 * garbage collect this node
 */
void
indexNode::GC(callback<void>::ref cb) {

  
  /*  if ((header->numElems == 0) && (p_zero == kEmptyNode)) {
    printf("FOUND EMPTY INDEX NODE\n");
    tree->bufPool()->readNode(header->parent, kGuessSize, kOrphan, 
			      wrap(this, &indexNode::GC_cb_readParent));
    //#ifdef STATS
    stats.gc_emptyNodes++;
    //#endif
    } */
  (*cb)();
  return;
}

void
indexNode::GC_cb_readParent(node *parent) {
  
#ifdef STATS
  stats.gc_totalSpace += size;
  stats.gc_spaceUsed += header->dataSize;
#endif
  (dynamic_cast<indexNode *>(parent))->deleteChild(ID);
  return;
}


/* -------------- access methods --------------------- */
/*
 * --- UpdatePointer ------
 * 
 * update an internal pointer (usually because a node merged)
 */
void
indexNode::updatePointer(void *keyInModNode, bSize_t keylen, 
			 void *newSep, bSize_t sepLen) {

  TOUCH();

  //decide which pointer to modify
  int targetPointer = locateKey(keyInModNode, keylen);
  if ( (tree->comparisonFunction(keyInModNode, 
				 keylen, 
				 nth_key(targetPointer),
				 nth_keyLen(targetPointer))) )
    targetPointer--;
  

  nodeID_t *pointerCopy = new nodeID_t;
  *pointerCopy = *(nodeID_t *)nth_value(targetPointer);
  printf("MERGE insert: old sep = <%s, %ld>\n", (char *)nth_key(targetPointer), *(nodeID_t *)nth_value(targetPointer));
  if (targetPointer >= 0) {
    printf("insert: new sep = <%s, %ld>\n", (char *)newSep, *pointerCopy);
    record *newSepRec = new record(newSep, sepLen, pointerCopy, sizeof(nodeID_t));  
    remove(nth_key(targetPointer), nth_keyLen(targetPointer));
    insert(newSepRec, kNoDuplicates, wrap(&update_cb_insert));
  } //else {
    //do nothing
  //}
  return;
}
void update_cb_insert(int err) { assert(!err); printf("MERGE: inserted new anchor record\n"); };

/*
 * printRep
 *
 * output a string describing the node
 */
void
indexNode::printRep() {

  FILE* debugFile;
  char *debugFileName = getenv("BTREE_DEBUG");
  if (debugFileName == NULL) {
    return;
  } else {
    debugFile = fopen(debugFileName, "a");
  }

  fprintf(debugFile, "i ");
  fprintf(debugFile, "%ld %d %ld ", ID, 0, header->p_zero);
  for (int i = 0; i < header->numElems; i++) {
    char key[512];
    int len = nth_keyLen(i);
    memcpy(key, (char *)nth_key(i), len);
    key[len] = 0;

    nodeID_t n = *(nodeID_t *)nth_value(i);
    fprintf(debugFile, "%s %ld ", key, n);
  }
  fprintf(debugFile, "\n");
  fflush(debugFile);
  fclose(debugFile);
}

/*
 * (set)ithChild
 *
 * get or modify the pointers of the node (protected)
 */
nodeID_t 
indexNode::ithChild(int i) {
  if (i == -1) return p_zero;
  if (i >= header->numElems) return 0;
  nodeID_t n = *(nodeID_t *)nth_value(i);
  return n;
}

void
indexNode::setChild(nodeID_t oldID, nodeID_t newID) {
  int pos=0;

  if (p_zero == oldID) 
    p_zero = newID;
  else {
    while ( (pos < header->numElems) && (*((nodeID_t *)nth_value(pos)) != oldID) ) pos++;
    if (pos == header->numElems) fatal("error on setChild -- key not found");
    *(nodeID_t *)nth_value(pos) = newID;
  }
  TOUCH();
  return;
}

void
indexNode::deleteChild(nodeID_t deletedID) {
  int pos=0;

  if (p_zero == deletedID) {
    if (header->numElems == 0) p_zero = kEmptyNode;
    else {
      p_zero = *((nodeID_t *)nth_value(0));
      remove(nth_key(0), nth_keyLen(0));
    }
  } else {
    while ( (pos < header->numElems) && (*((nodeID_t *)nth_value(pos)) != deletedID) ) pos++;
    if (pos == header->numElems) warn("error on deleteChild -- key not found");
    remove(nth_key(pos), nth_keyLen(pos));
  }
  TOUCH();
  return;
}

/*
 * deref* - the following functions translate local pointers 
 *          which are just offsets withing the node into
 *          value pointers and lenghts
 */
void * indexNode::derefLocalKey(localPtr_t lPtr) {
  //return the value associated with the local pointer lPtr
   
  indexElemRep *e = (indexElemRep *)((char *)data->base() + lPtr);
  return e->key;
}

void * indexNode::derefLocalValue(localPtr_t lPtr) {
  indexElemRep *e = (indexElemRep *)((char *)data->base() + lPtr);
  return &(e->p);
}

bLocalSize_t indexNode::derefLocalValueLen(localPtr_t lPtr) {
  //doesn't apply to index nodes
  return sizeof(nodeID_t);
}

bLocalSize_t indexNode::derefLocalKeyLen(localPtr_t lPtr) {
  //return the length of the data associated w/localPointer lPtr
   indexElemRep *e = (indexElemRep *)((char *)data->base() + lPtr);
   return e->keyLen;
}

void *
indexNode::nth_key(int n) {
  return derefLocalKey(header->localPointers[n]);
}
bSize_t 
indexNode::nth_keyLen(int n) {
  return derefLocalKeyLen(header->localPointers[n]);
}
bSize_t 
indexNode::nth_valueLen(int n) {
  return derefLocalValueLen(header->localPointers[n]);
}
void *
indexNode::nth_value(int n) {
  return derefLocalValue(header->localPointers[n]);
}


char
indexNode::underflow() {
  float ut = (float)(header->dataSize)/size;
  return (ut < 0.5);
}
bSize_t 
indexNode::surplus() {
  return (bSize_t)(header->dataSize - size*0.5);
}

void
indexNode::findNeighbor(char which, callback<void, node *>::ref cb) {

  tree->bufPool()->readNode(header->parent, kGuessSize, kIgnoreParent, wrap(this, &indexNode::findNeighbor_cb_readParent, which, 0, ID, cb));
  return;
}
void
indexNode::findNeighbor_cb_readParent(char which, int level, nodeID_t ref, callback<void, node *>::ref cb, node *p) {
  indexNode *parent = (dynamic_cast<indexNode *>(p));
  
  nodeID_t lastNode = 0, curNode = 0;
  int i=-1;
  do {
    lastNode = curNode;
    curNode = parent->ithChild(i++);
  } while ( (curNode > 0) && (curNode != ref));

  nodeID_t targetNode;
  if (which  == kRightNeighbor) targetNode = parent->ithChild(i);
  else targetNode = lastNode;
        
  nodeID_t nextNode = (which == kRightNeighbor) ? parent->ithChild(i) : parent->ithChild(parent->numElems() - 1);
  //done not in edge case
  if ( (targetNode) && (level == 0) ) 
    tree->bufPool()->readNode(targetNode, kGuessSize, kIgnoreParent, cb);
  
  //found anchor for node and neighbor
  else if ( (targetNode) && (level != 0) ) 
    tree->bufPool()->readNode(targetNode, kGuessSize, kIgnoreParent, 
			      wrap(this, &indexNode::findNeighbor_cb_readParent, which, level - 1, kExtremum, cb));
  
  // node is rightmost, go up a level
  else if ( (!targetNode) && (ref) ) {
    if (parent->nodeID() != 1)
      tree->bufPool()->readNode(parent->getParent(), kGuessSize, kIgnoreParent, 
				wrap(this, &indexNode::findNeighbor_cb_readParent, which, level + 1, p->nodeID(), cb));
    else (*cb)(NULL); //can't go up from here
  }
  //on way back down
  else if ( (ref == -1) && (level > 0) ) 
    tree->bufPool()->readNode(nextNode, kGuessSize, kIgnoreParent, 
			      wrap(this, &indexNode::findNeighbor_cb_readParent, which, level - 1, kExtremum, cb));
  
  //on way down and at level 0, return leftmost/rightmost node
  else tree->bufPool()->readNode(nextNode, kGuessSize, kIgnoreParent, cb);
  
  
}


/*
 * repOK
 *
 * return 1 if the rep invariant is intact, zero otherwise
 */
char 
indexNode::repOK() {

#ifdef DEBUG
  //check local pointer uniqueness
  int dup = 0;
  for (int i = 0; i < header->numElems; i++) {
    for (int j = 0; j < header->numElems; j++) {
      if ((header->localPointers[i] == header->localPointers[j]) && (i != j))
	dup = 1;
    }
  }

  if ((header->nodeType != kIndexTag) 
      || ((header->numElems >= 2) && 
	  (header->localPointers[0] == header->localPointers[1])) 
      || ((char *)bottomOfFreeSpace < (char *)header)
      || (dup) ) {
    printf("invalid rep\n");
    exit(2);
  }
#endif
  return 1;
}





