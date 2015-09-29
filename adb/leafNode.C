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
 * leafNode.C 
 *
 * leafNode provides an abstraction for a node in the B-tree. 
 *
 * SEARCH: search returns either
 *      -- kFoundInLeaf, in which case the key was found and the value can be found in retValue
 *                             --  or --
 *      -- kNotFound, in whihc case the key was not found and is not present in the tree
 *
 *                                      
 *    Layout:  /header/local pointers/..free space../elems/
 *    where elem is defined by the struct leafElemRep
 */

#include <leafNode.h>
#include <btree.h>
#include <indexNode.h>
#include <dataNode.h>
#ifdef DMALLOC
#include <dmalloc.h>
#endif

int cf(const void *a, const void *b);
int syncFlag;

#define maxValueLen 256

/*
 * Constructor - construct a leafNode in tree from the storage
 *               pointed to by b.
 *
 */
leafNode::leafNode(nodeStorage *b, btree* tree, int Size) : node(b,tree, Size) {
  assert(b);
  assert(b->base());
  header = (leafNodeHeader *)b->base();
  ID = header->tag;
  size = Size;
  bottomOfFreeSpace = (char *)b->base() + size - header->dataSize;
  lockbits = 0;
  header->dataIDHint = -1;

  repOK();

 }

leafNode::~leafNode() {

}


/* 
 * insert - This function blindly inserts the item which it assumes
 *          consists of a key/value pair into the appropriate place
 *          in the node. This function assumes that the caller has
 *          found the appropriate node to do the insert.
 */
void leafNode::insert(record *item, int policy, callback<void, int>::ref cb) {

  void *key;
  bSize_t keyLen;
  void *value;
  bSize_t valueLen;
  bSize_t totalLen;
  int i, keyLoc;
  char duplicateInsert = 0, dataInNode = 0;

  repOK();
  TOUCH();

  //get the key value pointers from the record 
  value = item->getValue(&valueLen);
  key = item->getKey(&keyLen);
  totalLen = recordSize(item); //recordSize accounts for in node data

  //look for duplicate insert
  keyLoc = locateKey(key, keyLen);
  if ( (header->numElems > keyLoc) && 
       (tree->comparisonFunction(nth_key(keyLoc),nth_keyLen(keyLoc), key, keyLen) == 0)) {
    if (policy == kNoDuplicates) { (*cb)(bDuplicateKeyError); return; }
    duplicateInsert = 1;  
  }

  if (!duplicateInsert) {
    
    //see if this insert requires a split
    if (splitRequired(totalLen)) {
      split(item, cb);
      return;
    }
    
    //otherwise it's just a simple insert
    //append the data to the bottom of the free space (data grows towards the head)
    leafElemRep *elem = (leafElemRep *)((char *)bottomOfFreeSpace - totalLen);
    createElement(elem, item);
    dataInNode = dataResident(elem);

    bottomOfFreeSpace -= totalLen;

    //update the local pointers
    for (i = header->numElems; i > keyLoc; i--) header->localPointers[i] = header->localPointers[i-1]; 
    header->localPointers[keyLoc] = ((char *)bottomOfFreeSpace - (char *)data->base());

    //update the header
    header->dataSize += totalLen + sizeof(localPtr_t);
    header->numElems++;
  }

  if (duplicateInsert) {
    leafElemRep * elem = (leafElemRep *)((char *)data->base() + header->localPointers[keyLoc]);
    if (dataResident(elem)) {
      remove(key, keyLen);
      insert(item, policy, cb); //re-insert
      return;
    } else
      //case III/IV data in data node stays there
      policy = elem->dPtr.offset;
  } 
  else policy = -1;
 
  //call the data Node's insert method from the callback
  if (!dataInNode) {
    if (header->dataIDHint > 0)
      tree->bufPool()->readNode(header->dataIDHint, kGuessSize, kOrphan, 
				wrap(this, &leafNode::insert_cb_readDataNode, cb, item, policy));
    else
      tree->bufPool()->allocateNewNode(kSegTag, ID, 0, wrap(this, &leafNode::insert_cb_readDataNode, cb, item,policy));

  } else
    if (cb)
      (*cb)(0);

}

/* 
 * insertNoData - inserts a record which consists of a key/data node
 * pointer. Used only by leafNode::split. No data node changes are
 * made since in this case the data is already stashed in a different
 * data node. Implemented as a stand-alone method since insert already
 * has so many special cases 
 */
void leafNode::insertNoData(record *item, callback<void, int>::ref cb) { 
  repOK();
  TOUCH();

  //get the key value pointers from the record 
  bSize_t keyLen, valueLen, totalLen;
  void *value = item->getValue(&valueLen);
  void *key = item->getKey(&keyLen);
  totalLen = recordSize(item);

  //look for duplicate insert
  int keyLoc = locateKey(key, keyLen);

  //append the data to the bottom of the free space (data grows towards the head)
  leafElemRep *elem = (leafElemRep *)((char *)bottomOfFreeSpace - totalLen);
  elem->keyLen = keyLen;
  memmove(elem->key, key, keyLen);
  //value could be an in-node value, or a data ptr
  if (valueLen > kResidentDataMaxSize)
    memmove(&elem->dPtr, value, sizeof(dataPtr));
  else {
    memmove((void *)((char *)elem->key + keyLen), value, valueLen);
    elem->dPtr.offset = valueLen;
    elem->dPtr.dataID = kDataInNode;
  }

  bottomOfFreeSpace -= totalLen;

  //update the local pointers
  for (int i = header->numElems; i > keyLoc; i--) header->localPointers[i] = header->localPointers[i-1]; 
  header->localPointers[keyLoc] = ((char *)bottomOfFreeSpace - (char *)data->base());

  //update the header
  header->dataSize += totalLen + sizeof(leafElemRep);
  header->numElems++;
  
  (*cb)(0);
  }

void
leafNode::insert_cb_readDataNode(callback<void, int>::ref cb, record *item, int policy, node *dnode) {
  
    //  printf("%ld: insert_cb_readDataNode\n", ID);
  //piggy back some data in the key (specifically the new parent field)
  record *newRec = new record(item);
  newRec->setKey(NULL, ID);
  dnode->insert(newRec, policy, wrap(this, &leafNode::insert_cb_dataNodeInsert, cb, item));
}

void
leafNode::insert_cb_dataNodeInsert(callback<void, int>::ref cb, record *item, int dPtr) {

  //printf("%ld: insert_cb_dataNodeInsert\n", ID);
  bSize_t s;
  void *key = item->getKey(&s);
  int keyLoc = locateKey(key, s);
  if (tree->comparisonFunction(nth_key(keyLoc), nth_keyLen(keyLoc), key, s) != 0) {
    printf("key not found? ID = %ld\n", ID);
    exit(-1);
  }
  leafElemRep * elem = (leafElemRep *)((char *)data->base() + header->localPointers[keyLoc]);
  //hiding a pointer in an int is tacky but i'm stuck with it
  memcpy(&elem->dPtr, (void *)dPtr, sizeof(dataPtr));
  //update hint on split
  if (elem->dPtr.dataID != header->dataIDHint) {
    header->dataIDHint = elem->dPtr.dataID;
  }
   tree->bufPool()->touchNode(ID);

  repOK();
  delete item;

  (*cb)(0);
}

/*
 * locateKey - determine where key is ordered with respect 
 *             to the node's existing keys. Function returns
 *             the existing key that immediately follows key
 *
 *     TODO: use a better search
 */
int 
leafNode::locateKey(void *key, int len) {
  int i=0;

  while ((i < header->numElems) && 
	 (tree->comparisonFunction(nth_key(i), nth_keyLen(i), key, len) < 0)) i++;
  return i;
}

/*
 * The derefLocal* functions take a localPointer and return the 
 *   key/value/keylen/valuelen associated with it
 *
 *  
 */
inline void * 
leafNode::derefLocalKey(localPtr_t lPtr) {
  //return the value associated with the local pointer lPtr
   
  leafElemRep *le = (leafElemRep *)((char *)data->base() + lPtr);
  return le->key;
}

dataPtr *
leafNode::nthDataPtr(int i) {
  leafElemRep *le = (leafElemRep*)((char *)data->base() + header->localPointers[i]);
  return &(le->dPtr);
}

inline void * 
leafNode::derefLocalValue(localPtr_t lPtr) {
  //return the value associated with the local pointer lPtr
   
  leafElemRep *le = (leafElemRep *)((char *)data->base() + lPtr);
  if (le->dPtr.dataID != kDataInNode)
    return &(le->dPtr);
  else
    return (void *) ((char *)le->key + le->keyLen);
}

inline bLocalSize_t
leafNode::derefLocalValueLen(localPtr_t lPtr) {
  //return the length of the data associated w/localPointer lPtr
  leafElemRep *le = (leafElemRep *)((char *)data->base() + lPtr);
  if (le->dPtr.dataID != kDataInNode)
    return kResidentDataMaxSize + 1;
  else
    return le->dPtr.offset;
}

inline bLocalSize_t
leafNode::derefLocalKeyLen(localPtr_t lPtr) {
  //return the length of the data associated w/localPointer lPtr
   leafElemRep *le = (leafElemRep *)((char *)data->base() + lPtr);
   return le->keyLen;
}

inline void * 
leafNode::nth_key(int i) {
  return derefLocalKey(header->localPointers[i]);
}
inline bSize_t  
leafNode::nth_keyLen(int i) {
  return derefLocalKeyLen(header->localPointers[i]);
}
inline void *  
leafNode::nth_value(int i) {
  return derefLocalValue(header->localPointers[i]);
}
inline bSize_t 
leafNode::nth_valueLen(int i) {
  return derefLocalValueLen(header->localPointers[i]);
}


bLocalSize_t
leafNode::elemSize(int i) {
  leafElemRep * elem = (leafElemRep *)((char *)data->base() + header->localPointers[i]);
  int totalSize = elem->keyLen + sizeof(leafElemRep);
  if (elem->dPtr.dataID == kDataInNode) totalSize += elem->dPtr.offset;
  return totalSize;
}

bLocalSize_t 
leafNode::recordSize(record *rec) {
  bSize_t len;
  rec->getKey(&len);
  int totalSize = len + sizeof(leafElemRep);
  rec->getValue(&len);
  if ((len > 0) && (len < kResidentDataMaxSize)) totalSize += len;
  return totalSize;
}

void
leafNode::createElement(leafElemRep *elem, record *rec) {
  bSize_t keyLen, valueLen;
  void *key = rec->getKey(&keyLen);
  void *value = rec->getValue(&valueLen);

  elem->keyLen = keyLen;
  memmove(&(elem->key), key, keyLen);
  if (valueLen < kResidentDataMaxSize) {
    elem->dPtr.dataID = kDataInNode;
    elem->dPtr.offset = valueLen;
    memmove( (void *)(((char *)elem->key) + keyLen), value, valueLen);
  }
  else elem->dPtr.dataID = 0;
}

char
leafNode::dataResident(leafElemRep *elem) {
  return (elem->dPtr.dataID == kDataInNode);
}
/*
 * Remove
 *
 *  Delete the element named by key from the node (and pertinent data
 *  node)
 */

void 
leafNode::remove(void *key, bSize_t len) {

  repOK();
  TOUCH();

  int keyLoc = locateKey(key, len);
  nodeID_t n = ((dataPtr *)(nth_value(keyLoc)))->dataID;
  bSize_t off = ((dataPtr *)(nth_value(keyLoc)))->offset;

  for (int i = keyLoc; i < header->numElems - 1; i++) 
    header->localPointers[i] = header->localPointers[i+1];
  header->numElems--;
  compact();
  tree->bufPool()->touchNode(ID);

  if (n != kDataInNode)
    tree->bufPool()->readNode(n, kGuessSize, kOrphan, 
			      wrap(this, &leafNode::remove_cb_readDataNode, off));
  
  repOK();
}

void
leafNode::remove_cb_readDataNode(bSize_t off, node *dnode) {

  dnode->remove(NULL, off);
}

		
/*
 * search - look for the key key in the node. Since this is a leaf node
 *          possible return values are -1 implying that the key is not
 *          in the tree and 0 (plus nonnull *retValue) which means that
 *          the key was found in the node.
 */

nodeID_t 
leafNode::search(void *key, bSize_t len, void **retValue, bSize_t *retLen) {
 
  int l=0,  h = header->numElems - 1, m=0;
  short comp = 1;
  
  while ((l <= h) && (comp != 0)){
    m = (l + h) / 2;
    comp = tree->comparisonFunction(key, len, nth_key(m), nth_keyLen(m));
    if (comp == 0)
      break;
    else if (comp < 0)
      h = m - 1;
    else // if (comp > 0)
      l = m + 1;
  };

  int pol = tree->getLookupPolicy();
  if ((comp == 0) || (pol == kNearestKey)) {
    if (retValue == NULL) return kFoundInLeaf; //to allow existence check
    dataPtr * d = nthDataPtr(m);
    if (d->dataID > 0) {
      *retValue = malloc(sizeof(dataPtr));
      memcpy(*retValue, d, sizeof(dataPtr));
      *retLen = sizeof(dataPtr);
      return kFoundInLeaf;
    } else { //data is resident in node
      *retValue = malloc(d->offset);
      *retLen = d->offset;
      memcpy(*retValue, (void *)((char *)nth_key(m) + nth_keyLen(m)), d->offset);
      return kFoundInData;
    }
  } else {
    return kNotFound;
  }
}


char
leafNode::underflow() {

  float ut = ((float)header->dataSize)/size;
  return (ut < 0.5);
}

bSize_t 
leafNode::surplus() {
  return (bSize_t)(header->dataSize - 0.5*size);
}

//move an item out of this node leaving its data intact
bSize_t
leafNode::shift(char direction, record **item) {
  
  if (header->numElems == 0) return 0;

  int itemToShift = (direction == kShiftRight) ? header->numElems - 1 : 0;

  bSize_t valueLen;
  valueLen = nth_valueLen(itemToShift);
  //  if (valueLen > kResidentDataMaxSize) valueLen = sizeof(dataPtr);
  *item = recordDup(new record(nth_key(itemToShift), nth_keyLen(itemToShift),
		     nth_value(itemToShift), valueLen));
  
  //remove it
  if (direction == kShiftLeft)
    for (int i = itemToShift; i < header->numElems - 1; i++) 
      header->localPointers[i] = header->localPointers[i+1];

  header->numElems--;
  compact();
  TOUCH();

  return elemSize(itemToShift);
}
 

/* --------- Compact --
 * The node layout does not require that the elements be contiguous.
 * Deletes or splits may create gaps. This function moves all free
 * space to a single contiguous block after the local pointers
 */

struct lpp {
  localPtr_t lp;
  int i;
};

void 
leafNode::compact() {

  lpp *lp = (lpp *)malloc(sizeof(lpp)*header->numElems);
  
  //copy out the local pointer values
  for (int i=0; i < header->numElems; i++) {
    lp[i].lp = header->localPointers[i];  
    lp[i].i = i;
  }
  //sort them
  qsort(lp, header->numElems, sizeof(lpp), &cf);
  
  bottomOfFreeSpace = (char *)data->base() + size;
  header->dataSize = 0;
  //move each towards the bottom starting with the largest pointer (largest offset)
  for (int i = header->numElems - 1; i >= 0; i--) {
    leafElemRep *elem = (leafElemRep *)((char *)data->base() + lp[i].lp);
    int elemSize = this->elemSize(lp[i].i);
    header->dataSize += elemSize + sizeof(localPtr_t);
    bottomOfFreeSpace -= elemSize;
    memmove((char *)bottomOfFreeSpace, elem, elemSize);
    //and update the actual pointer
    header->localPointers[lp[i].i] = bottomOfFreeSpace - (char *)data->base();
  }

  free(lp);
  TOUCH();
  return;
}

int cf(const void *aa, const void *bb) {

  lpp *a = (lpp *)aa;
  lpp *b = (lpp *)bb;
  if (a->lp < b->lp) return -1;
  else if (a->lp > b->lp) return 1;
  else return 0;
}

/*
 * PrintRep - output a text string describing the node
 */
void
leafNode::printRep() {

#ifdef DEBUG  
  FILE* debugFile;
  char *debugFileName = getenv("BTREE_DEBUG");
  if (debugFileName == NULL) {
    return;
  } else {
    debugFile = fopen(debugFileName, "a");
  }
  
  fprintf(debugFile, "l ");
  fprintf(debugFile, "%ld ", ID);
  for (int i = 0 ; i < header->numElems; i++) {
    char key[512];
    memcpy(key, (char *)nth_key(i), nth_keyLen(i));
    key[nth_keyLen(i)] = 0;
    nodeID_t n = ((dataPtr *)(nth_value(i)))->dataID;
    bSize_t off = ((dataPtr *)(nth_value(i)))->offset;
    fprintf(debugFile, "%s %02ld%03ld ", key, n, off);
  }
  fprintf(debugFile, "\n");
  fflush(debugFile);
  fclose(debugFile);

#endif
  return;
}


/*
 * repOK
 *
 * output a text string describing the node
 */
char
leafNode::repOK() {

  //check local pointer uniqueness
#ifdef DEBUG
  int dup = 0;
  int oocpv = 0;
  for (int i = 0; i < header->numElems; i++) {
    for (int j = 0; j < header->numElems; j++) {
      if ((header->localPointers[i] == header->localPointers[j]) && (i != j)) {
	printf("localpointers %d and %d match (%d == %d)\n", i, j, 
	       header->localPointers[i], header->localPointers[j]);
	dup = 1;
      }
    }
  }
  
  if ((header->nodeType != kLeafTag) ||
      (oocpv) ||
      (dup) ||
      (header->dataSize > size) ||
      ((char *)bottomOfFreeSpace == NULL) ||
      ((char *)bottomOfFreeSpace < (char *)header)) {
    printf("invalid rep (leaf node %ld)\n", ID);
    char *p = (char *)10;
    *(p - 10) = 's';
  }
#endif
  return 1;
}

