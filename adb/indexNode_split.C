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
 * indexNode_split.C -- implements methods to split a
 * node (the "unsafe" tree operations)
 * 
 */

/* 
 * split - split this node around its median (in terms of size)
 *         and simultaneously insert item
 */

#include "indexNode.h"

void indexNode::nullcb(int err) {
  return;
}

void 
indexNode::split(record *item, callback<void, int>::ref cb) {

  //create a New node
  nodeID_t parent = (header->parent <= 0) ? 1 : header->parent;
  tree->bufPool()->allocateNewNode(kIndexTag, parent,0, 
				   wrap(this, &indexNode::split_cb_allocateNode, item, cb));
  return;
}

void
indexNode::split_cb_allocateNode(record *item, callback<void, int>::ref cb, node *NewNode) {

  int s=0;
  bSize_t len;
  void *key = item->getKey(&len);
  
  repOK();

  if (NewNode == NULL) fatal("indexNode split on full disk");

  //find the median (harder than in leaf nodes since we can't leave it behind)
  int targetNodes = (header->numElems + 1)/2;
  int currentNode = 0;
  char usedItem = 0;
  for (int nodesCollected = 0; nodesCollected < targetNodes; nodesCollected++) {
    if (tree->comparisonFunction(nth_key(currentNode), nth_keyLen(currentNode), key, len) < 0)
      currentNode++;
    else
      usedItem = 1;
  }
  int m = currentNode;
  
  //copy elements greater than or equal to the median to the New node
  for (int i=m+1; i < header->numElems; i++)  {
    record *rec = New record(nth_key(i), nth_keyLen(i), 
			     nth_value(i), nth_valueLen(i));
    NewNode->insert(rec, kNoDuplicates, wrap(this, &indexNode::nullcb));
 
   delete rec;
    s += nth_keyLen(i) + sizeof(indexElemRep);
  }

  //delete items moved to other nodes
  header->numElems = m + 1;
  header->dataSize = header->dataSize - s;
  compact();

#ifdef DEBUG
  tree->printRep("indexNode: split");
#endif

  //create item to insert into parent
  char itemIsMedian = 0;
  nodeID_t *n = (nodeID_t *)malloc(sizeof(nodeID_t));
  void *keyCpy = malloc( (nth_keyLen(m) < len) ? len : nth_keyLen(m) );
  int cpyLen = 0;
  *n = NewNode->nodeID();
  //is it the item we just added?
  if ( (!usedItem) && (tree->comparisonFunction(nth_key(m), nth_keyLen(m),
						key, len) > 0)) {
    memcpy(keyCpy, key, len);
    cpyLen = len;
    itemIsMedian = 1;
  } else {
    memcpy(keyCpy, nth_key(m), nth_keyLen(m));
    cpyLen = nth_keyLen(m);
  }

  record *medianRec = New record(keyCpy,
			   cpyLen,
		   (void *)n, sizeof(nodeID_t));

  //special case for the p_zero element of the New node
  if (!itemIsMedian)
    (dynamic_cast<indexNode *>(NewNode))->setPZero(*(nodeID_t *)nth_value(m));
  else {
    bSize_t valLen = 0;
    void *value = item->getValue(&valLen);
    (dynamic_cast<indexNode *>(NewNode))->setPZero(*(nodeID_t *)value);
  }

  //insert the item into the proper node (all in core, will return immediately)
  if (usedItem) {
    insert(item, kNoDuplicates, wrap(this, &indexNode::nullcb));
    remove(nth_key(m+1),nth_keyLen(m+1));
  }else if (itemIsMedian) {
    NewNode->insert(new record(nth_key(m), nth_keyLen(m),
			       nth_value(m), nth_valueLen(m)), 
		    kNoDuplicates, wrap(this, &indexNode::nullcb));
    //key[m] is still in this node, delete it
    //    remove(nth_key(m),nth_keyLen(m));
  } else {
    NewNode->insert(item, kNoDuplicates, wrap(this, &indexNode::nullcb));
    remove(nth_key(m),nth_keyLen(m));
  }


  //root node case
  if (ID == 1) {
    tree->bufPool()->allocateNewRootNode(wrap(this, &indexNode::split_cb_allocateRootNode, cb, medianRec));
  }  else {
    nodeID_t parent = (header->parent <= 0) ? 1 : header->parent;
    //insert the median element/a pointer to the New node into the parent
    tree->bufPool()->readNode(parent, kGuessSize, kOrphan, wrap(this, 
			   &indexNode::split_cb_readParent, medianRec, cb));
  }
  repOK();
#ifdef DEBUG
    tree->printRep("indexNode: split (done)");
#endif
    
    return;
}

void
indexNode::split_cb_allocateRootNode(callback<void, int>::ref cb, record *rec, nodeID_t newID, node *root) {
  //patch ourselves up as an index node on the second level of the tree
  ID = header->tag = newID;
  header->parent = 1;
  
  (dynamic_cast<indexNode *>(root))->setPZero(newID);
  root->insert(rec, kNoDuplicates, cb);
  tree->setRoot(root);
  tree->incHeight();
  freeLock();
#ifdef DEBUG
  tree->printRep("indexNode: split (root case)");
#endif
    
  return;
}

void 
indexNode::split_cb_readParent(record *rec, callback<void, int>::ref cb, node * parent) {

  parent->insert(rec, kNoDuplicates, cb);
  delete rec;
  return;
}

/*
 * splitRequired - returns non-zero if the addition of byteAdded data to the node
 *                 implies that the node should be split. This is implemented as 
 *                 its own method so that we can override to implement early-split
 *                 or other optimizations
 */
char indexNode::splitRequired(int bytesAdded) {

   long newSize = (long)(bytesAdded + header->dataSize + sizeof(indexNodeHeader));
   return (newSize > size);
}

