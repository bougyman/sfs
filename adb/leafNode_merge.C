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
 * leafNode_merge.C -- methods related to merging leaf nodes.
 * 
 *
 *
 *
 * --- Merge -------------- 
 * handle underflow by transferring items or
 * merging w/ another node
 *
 * */

#include "leafNode.h"
#include "indexNode.h"
#include "dataNode.h"

void 
leafNode::merge(callback<void>::ref cb) {

  printf("MERGING (leaf: %ld)\n", ID);
  //get pointers to neighbors
  if (header->nextPtr) {
    tree->bufPool()->readNode(header->nextPtr, kGuessSize, kOrphan, 
			      wrap(this, &leafNode::merge_cb_readNext, cb));
  } else if (header->backPtr) {
    node *n=NULL;
    tree->bufPool()->readNode(header->backPtr, kGuessSize, kOrphan, 
			      wrap(this, &leafNode::merge_cb_haveNeighbors, n, cb));
  } else {
    merge_cb_haveNeighbors(NULL, cb, NULL);
  }

}

void
leafNode::merge_cb_readNext(callback<void>::ref cb, node *next) {
  if (header->backPtr) {
    tree->bufPool()->readNode(header->nextPtr, kGuessSize, kOrphan, wrap(this, &leafNode::merge_cb_haveNeighbors, next, cb));
  } else {
    merge_cb_haveNeighbors(next, cb, NULL);
  }
}

void
leafNode::merge_cb_haveNeighbors(node *ln1, callback<void>::ref cb, node *ln2) {
 
  if ( (ln1 == NULL) && (ln2 == NULL)) return;

  //check to see if they have surplus items
  char canSlosh = ( ((ln1) && (!ln1->underflow())) || ( (ln2) && (!ln2->underflow())));

  if (canSlosh) {
    //move elements
    node *donor;
    if ((ln1) && (!ln1->underflow())) donor = ln1;
    else donor = ln2;
    bSize_t halfOfSurplus = donor->surplus()/2;
    bSize_t shiftedBytes = 0;
    char direction = ((dynamic_cast<leafNode *>(donor))->nextPtr() == ID) ? kShiftRight : kShiftLeft;
    do {
      record *item;
      shiftedBytes += donor->shift(direction, &item);
      bSize_t len; void *value = item->getValue(&len);
      insertNoData(item, wrap(this, &leafNode::merge_cb_insertNoData, value, len));
      delete item;
    } while (shiftedBytes < halfOfSurplus);
    
    //adjust anchor
    //pick new separator
    void *sep;
    bSize_t sepLen;
    if (direction == kShiftRight) {
      printf("SHIFTING right\n");
      sep = nth_key(0); //'in' left neighbor till anchor updated
      sepLen = nth_keyLen(0);
      tree->findAnchor(sep, sepLen, nth_key(header->numElems - 1), //in this node 
		       nth_keyLen(header->numElems - 1), 
		       wrap(this, &leafNode::merge_cb_finishShift, sep, sepLen,
			    nth_key(header->numElems - 1), nth_keyLen(header->numElems - 1), cb));
    } else {
      printf("SHIFTING left\n");
      //record *drec = donor->ithRecord(0); // in right neighbor
      record *drec = new record(donor->nth_key(0),
				donor->nth_keyLen(0),
				donor->nth_value(0),
				donor->nth_valueLen(0));
      sep = drec->getKey(&sepLen);
      
      tree->findAnchor(sep, sepLen, nth_key(0), nth_keyLen(0), 
		       wrap(this, &leafNode::merge_cb_finishShift, sep, sepLen,
			    sep, sepLen, cb));
      
      
      
    }
    return;
  } //if canSlosh
    
  //else 
  printf("MERGE: node %ld, merging w/ neighbor\n", ID);
  //move elements from neighbor
  node *victim;
  if ((ln1) && (ln1->getParent() == header->parent)) victim = ln1;
  else victim = ln2;
  leafNode *lvictim = (dynamic_cast<leafNode *>(victim));

  char direction = (lvictim->nextPtr() == ID) ? kShiftRight : kShiftLeft;
  long shiftedBytes;
  do {
    record *item;
    shiftedBytes = victim->shift(direction, &item);
    if (shiftedBytes) {
      bSize_t len; void *value = item->getValue(&len);
      insertNoData(item, wrap(this, &leafNode::merge_cb_insertNoData, value, len));
      delete item;
    }
  } while (shiftedBytes);

  //delete neighbor
  nodeID_t vicID = victim->nodeID();
  lvictim->deleteSelf(wrap(this, &leafNode::merge_cb_deleteMergedNode, cb, direction, vicID));
  printf("deleted node %ld\n", vicID);

  return;
  
}


void
leafNode::merge_cb_insertNoData(void *value, bSize_t len, int err) {

  if (len > kResidentDataMaxSize) {
    dataPtr *dPtr = (dataPtr *)value;
    tree->bufPool()->readNode(dPtr->dataID, kGuessSize, kOrphan, 
			      wrap(this, &leafNode::merge_cb_fixDataParentPtr, dPtr));
  }
}

void
leafNode::merge_cb_fixDataParentPtr(dataPtr *dPtr, node *data) {
  
  (dynamic_cast<dataNode *>(data))->setItemParent(dPtr->offset,ID);
}


void
leafNode::merge_cb_deleteMergedNode(callback<void>::ref cb, char direction, nodeID_t victimID) {
  
  //remove entry from parent node
  if (ID != 1) {
    printf("reading parent (%ld)\n", header->parent);
    tree->bufPool()->readNode(header->parent, kGuessSize, kIgnoreParent, 
			      wrap(this, &leafNode::merge_cb_recurseOnParent, cb, direction, victimID));
    return;
    
  }
}
void
leafNode::merge_cb_recurseOnParent(callback<void>::ref cb, char direction, nodeID_t deleted, node *parent) {
  if (direction == kShiftLeft) {
    (dynamic_cast<indexNode *>(parent))->deleteChild(deleted);
  } else { //if shiftRight
    printf("deleting pointer to %ld == %ld\n", ID, header->tag);
    (dynamic_cast<indexNode *>(parent))->deleteChild(ID);
    printf("updating pointer %ld\n", deleted);
    (dynamic_cast<indexNode *>(parent))->setChild(deleted, ID);
  }

  if (parent->underflow()) parent->merge(cb);
  else {
    freeLock(); 
    (*cb)();
  }

}

void
leafNode::merge_cb_finishShift(void *sep, bSize_t sepLen, void *keyInNode, bSize_t keyLen, 
			       callback<void>::ref cb, node *anchor) {
  
  
  //update pointer in anchor
  (dynamic_cast<indexNode *>(anchor))->updatePointer(keyInNode, keyLen, sep, sepLen);
  
  freeLock();
  (*cb)();
  return;

}

