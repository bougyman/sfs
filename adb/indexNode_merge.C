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
 * indexNode_merge.C -- implements methods to merge a
 * node (the other "unsafe" tree operation)
 * 
 */

#include "indexNode.h"

/*
 * Merge -- combine this node with a neighbor or exchange elements
 * with a neibhbor as necessary to maintain 50 percent usage
 *
 */
void 
indexNode::merge(callback<void>::ref cb) {

  printf("MERGING (index: %ld)\n", ID);
  //are we the root?
  if (ID == 1) {
    warn("ROOT COLLAPSE NOT SUPPORTED");
    (*cb)();
  } else {
    //find neighbors
    findNeighbor(kRightNeighbor, wrap(this, &indexNode::merge_cb_getRight, cb));
  }
}
void
indexNode::merge_cb_getRight(callback<void>::ref cb, node *rightNeighbor) {
  findNeighbor(kLeftNeighbor, wrap(this, &indexNode::merge_cb_haveNeighbors, rightNeighbor, cb));
}
void
indexNode::merge_cb_haveNeighbors(node *rightN, callback<void>::ref cb, node *leftN) {
    
  indexNode *rightNeighbor = (dynamic_cast<indexNode *>(rightN));
  indexNode *leftNeighbor = (dynamic_cast<indexNode *>(leftN));

  //check if shift possible
  char canShift = (((rightNeighbor) && (!rightNeighbor->underflow())) || (((leftNeighbor) && (!leftNeighbor->underflow()))));

  if (canShift) {
    bSize_t rightSurplus = rightNeighbor->surplus();
    bSize_t leftSurplus = leftNeighbor->surplus();
    indexNode * donor;
    bSize_t surplus;
    char direction ;
    if (rightSurplus > leftSurplus) { donor = (dynamic_cast<indexNode *>(rightNeighbor)); surplus = rightSurplus; direction = kShiftLeft;}
    else { donor = (dynamic_cast<indexNode *>(leftNeighbor)); surplus = leftSurplus; direction = kShiftLeft; }

    //shift
    bSize_t shiftedBytes = 0;
    do {
      record *item;
      shiftedBytes += donor->shift(direction, &item);
      insert(item, kNoDuplicates, wrap(this, &indexNode::nullcb));
    } while (shiftedBytes < surplus/2);
    
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
		       wrap(this, &indexNode::merge_cb_finishShift, sep, sepLen,
			    nth_key(header->numElems - 1), nth_keyLen(header->numElems - 1), cb));
    } else {
      printf("SHIFTING left\n");
      sep = donor->nth_key(0);
      sepLen = donor->nth_keyLen(0);
      tree->findAnchor(sep, sepLen, nth_key(0), nth_keyLen(0), 
		       wrap(this, &indexNode::merge_cb_finishShift, sep, sepLen,
			    sep, sepLen, cb));
      
      
      
    }
  } else {
    //if not, merge w/ neigbhor
    printf("MERGE: node %ld, merging w/ neighbor\n", ID);
    //move elements from neighbor
    indexNode *victim;
    if ((rightNeighbor) && (rightNeighbor->getParent() == header->parent)) victim = rightNeighbor;
    else victim = leftNeighbor;
    
    char direction = (victim == leftNeighbor) ? kShiftRight : kShiftLeft;
    long shiftedBytes;
    do {
      record *item;
      shiftedBytes = victim->shift(direction, &item);
      bSize_t len;
      printf("MERGE (delete case): shifted <%s> from node %ld\n", (char *)item->getKey(&len), victim->nodeID());
      if (shiftedBytes) {
	insert(item, kNoDuplicates, wrap(this, &indexNode::nullcb));
	delete item;
      }
    } while (shiftedBytes);
    
    //delete neighbor
    nodeID_t victimID = victim->nodeID();
    tree->bufPool()->kill(victim->nodeID());
    printf("deleted node %ld\n", victim->nodeID());
    
    //remove entry from parent node
    if (ID != 1) {
      printf("reading parent (%ld)\n", header->parent);
      tree->bufPool()->readNode(header->parent, kGuessSize, kIgnoreParent, 
				wrap(this, &indexNode::merge_cb_recurseOnParent, cb, direction, victimID));
      return;
    }
    //recurse to parent
  }
    
}
void
indexNode::merge_cb_finishShift(void *sep, bSize_t sepLen, void *keyInNode, bSize_t keyLen, 
			       callback<void>::ref cb, node *anchor) {
  
  
  //update pointer in anchor
  (dynamic_cast<indexNode *>(anchor))->updatePointer(keyInNode, keyLen, sep, sepLen);
  
  freeLock();
  (*cb)();
  return;

}
void
indexNode::merge_cb_recurseOnParent(callback<void>::ref cb, char direction, nodeID_t deleted, node *parent) {
  if (direction == kShiftLeft) {
    (dynamic_cast<indexNode *>(parent))->deleteChild(deleted);
  } else { //if shiftRight
    printf("deleting pointer to %ld == %ld\n", ID, header->tag);
    (dynamic_cast<indexNode *>(parent))->deleteChild(ID);
    printf("updating pointer %ld\n", deleted);
    (dynamic_cast<indexNode *>(parent))->setChild(deleted, ID);
  }

  if ((dynamic_cast<indexNode *>(parent))->underflow()) (dynamic_cast<indexNode *>(parent))->merge(cb);
  else {
    freeLock(); (*cb)();
  }

}
bSize_t
indexNode::shift(char direction, record **item) {
  
  if (header->numElems == 0) return 0;

  int itemToShift = (direction == kShiftRight) ? header->numElems - 1 : 0;
  
  bSize_t targetLen = nth_keyLen(itemToShift) + sizeof(indexElemRep);
  //  if (valueLen > kResidentDataMaxSize) valueLen = sizeof(dataPtr);
  *item = recordDup(new record(nth_key(itemToShift), nth_keyLen(itemToShift),
			       nth_value(itemToShift), nth_valueLen(itemToShift)));
  
  //remove it
  if (direction == kShiftLeft)
    for (int i = itemToShift; i < header->numElems - 1; i++) 
      header->localPointers[i] = header->localPointers[i+1];
  
  header->numElems--;
  compact();
  tree->bufPool()->touchNode(ID);

  return targetLen;
  
}
