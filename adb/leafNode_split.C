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
 * leafNode_split.C -- methods related to splitting leaf nodes
 *
 */

#include <leafNode.h>
#include <indexNode.h>
#include <dataNode.h>

/*
 * split - split this node around its median (in terms of size)
 *         and simultaneously insert item
 */
void 
leafNode::split(record *item, callback<void, int>::ref cb) {
  
  //create a New node
  nodeID_t parent = (header->parent <= 0) ? 1 : header->parent;
  tree->bufPool()->allocateNewNode(kLeafTag, parent,0, wrap(this, &leafNode::split_cb_allocateNode, item, cb));
}

void
leafNode::split_cb_allocateNode(record *item, callback<void, int>::ref cb, node *NewNode) {

  int i=0,s=0;
  //printf("%ld: split_cb_allocateNode (new id = %ld)\n", ID, NewNode->nodeID());
  if (NewNode == NULL) fatal("leafNode split on full disk");

  repOK();

  //median goes to parent, median and everthing after goes into the New node
  int m = header->numElems/2;

  //fix up prev, next pointers
  leafNode *nn = (dynamic_cast<leafNode *>(NewNode));

  if (ID != 1) {
    if (header->nextPtr)
      tree->bufPool()->readNode(header->nextPtr, kGuessSize, kOrphan, 
				wrap(this, &leafNode::split_cb_fixBackChain, nn->nodeID()));
    nn->setNextPtr(header->nextPtr);
    nn->setBackPtr(ID);
  } else {
    nn->setNextPtr(0);
    nn->setBackPtr(ID);
    setBackPtr(0);
  }
  setNextPtr(NewNode->nodeID());

  //calculate size of elements moved to new node
  for (i=m; i < header->numElems; i++) 
    s += elemSize(i) + sizeof(localPtr_t);

  //ok to do before the copy?
  header->dataSize = header->dataSize - s;

  //copy elements greater than the median to the New node using the no data insert method
  split_cb_insertInSibling(m, nn, item, cb,0);
  return;
}

void
leafNode::split_cb_fixBackChain(nodeID_t backPtr, node *oldSibling) {
  (dynamic_cast<leafNode *>(oldSibling))->setBackPtr(backPtr);
  return;
}

void
leafNode::split_cb_finish(record *item, leafNode *NewNode, callback<void, int>::ref cb) {
  
  //find place for new item
  bSize_t len;
  void *key = item->getKey(&len);

  //printf("%ld: split_cb_finish\n", ID);
  //create the record to copy into our parent
  nodeID_t *NewID = (nodeID_t *)malloc(sizeof(nodeID_t));
  *NewID = NewNode->nodeID();
  int m = header->numElems/2;
  int medianKeyLen = nth_keyLen(m);
  void *NewKey = malloc(medianKeyLen);
  memcpy(NewKey, nth_key(m), medianKeyLen);
  record *rec = New record(NewKey, 
			   medianKeyLen, 
			   (void *)NewID, sizeof(nodeID_t));


  //delete copied elements from this node
  header->numElems = m;
  compact();

  //printf("%ld: doing last insert\n", ID);
  if (tree->comparisonFunction(key, len, NewKey, medianKeyLen) < 0) {
    insert(item, kNoDuplicates, wrap(this, &leafNode::split_cb_parentInsert, 
				     rec, NewNode, cb));
  } else {
    NewNode->insert(item, kNoDuplicates,wrap(this, &leafNode::split_cb_parentInsert,rec, NewNode, cb));
  }
    return;
}

 void
leafNode::split_cb_parentInsert(record *rec, leafNode *NewNode, callback<void, int>::ref cb, int err) {

   //printf("%ld: split_cb_parentInsert\n", ID);
  if (err) fatal("error inserting in leafNode split");

  //special case for root node
  if (ID == 1) {
    tree->bufPool()->allocateNewRootNode(wrap(this, &leafNode::split_cb_allocateRootNode, cb, rec, NewNode));
    return;
  }
  else
    //finish insert after reading parent node
    tree->bufPool()->readNode(header->parent, kGuessSize, kOrphan, wrap(this, &leafNode::split_cb_insertMedian, rec, cb));

  return;
}


void
leafNode::split_cb_allocateRootNode(callback<void, int>::ref cb, record *rec, leafNode *sibling, nodeID_t id, node *root) {

   //printf("%ld: split_cb_allocateRootNode\n", ID);
    //patch ourselves up as a leaf node
    ID = header->tag = id;
    rootForwardingAddress = id;
    sibling->setBackPtr(id);
    sibling->setNextPtr(0);
    header->parent = 1;
    (dynamic_cast<indexNode *>(root))->setPZero(id);

    if (header->dataIDHint > 0)
      tree->bufPool()->readNode(header->dataIDHint, kGuessSize, id, 
				wrap(this, &leafNode::split_cb_allocateRootNode_readDataNode, cb, rec, root));
    else  {
      root->insert(rec,kNoDuplicates, cb);
      tree->setRoot(root);
      //since the search path no longer inclues us
      freeLock();
    }
      
    return;
}

void
leafNode::split_cb_allocateRootNode_readDataNode(callback<void, int>::ref cb, record *rec, node *root, node *dn) {
  
  dn->setParent(header->tag);
  nodeID_t nextDataNode = (dynamic_cast<dataNode *>(dn))->next();
  if (nextDataNode > 0) {
    tree->bufPool()->readNode(nextDataNode, kGuessSize, ID, 
			    wrap(this, &leafNode::split_cb_allocateRootNode_readDataNode, cb, rec, root));
  } else {
    root->insert(rec,kNoDuplicates, cb);
    tree->setRoot(root);
    //since the search path no longer inclues us
    freeLock();
  }
  return;
}

void
leafNode::split_cb_insertInSibling(int i, 
				   leafNode *NewNode,
				   record *item,
				   callback<void, int>::ref cb,
				   int err) {
  
  //  printf("%ld: split_cb_readDataNode\n", ID);
  
  if (i == header->numElems) {
    split_cb_finish(item, NewNode, cb);
    return;
  }

  record *nextRec = New record(nth_key(i),
			       nth_keyLen(i),
			       nth_value(i),
			       nth_valueLen(i));
  
  if (nth_valueLen(i) > kResidentDataMaxSize) {
    //    printf("%ld updating parent pointers\n", ID);
    dataPtr *dPtr = (dataPtr *)nth_value(i);
    NewNode->insertNoData(nextRec, wrap(this, &leafNode::split_cb_updateDataItemParentPointer, i+1,
					NewNode, item, cb, dPtr));
  } else {
    NewNode->insertNoData(nextRec, wrap(this, &leafNode::split_cb_insertInSibling, i+1,
					NewNode, item, cb));
  }

    return;
}

void
leafNode::split_cb_updateDataItemParentPointer(int i, 
					       leafNode *NewNode, 
					       record *item, 
					       callback<void, int>::ref cb,
					       dataPtr *dPtr,
					       int err) {
  
  assert(!err);
  split_cb_insertInSibling(i, NewNode, item, cb, 0);
  // tree->bufPool()->readNode(dPtr->dataID, kGuessSize, kOrphan, 
  //			    wrap(this, &leafNode::split_cb_readDataNode,
  //				 i, NewNode, item, cb, dPtr));
  return;
}

void
leafNode::split_cb_readDataNode(int i,
				leafNode *NewNode,
				record *item,
				callback<void, int>::ref cb,
				dataPtr *dPtr,
				node *dNode) {
  
  bOffset_t offset = dPtr->offset;
  //  printf("parent pointer of node %ld, offset %ld changed to %ld\n", dNode->nodeID(), offset, NewNode->nodeID()); 
  (dynamic_cast<dataNode *>(dNode))->setItemParent(offset, NewNode->nodeID());
  split_cb_insertInSibling(i, NewNode, item, cb, 0);
}
				

void 
leafNode::split_cb_insertMedian(record * rec, callback<void, int>::ref cb, node * parent) {

  //  printf("%ld: split_cb_insertMedian\n", ID);
  //insert the median key/a pointer to the New node into the parent
  parent->insert(rec, kNoDuplicates, cb);

}
/*
 * splitRequired - returns non-zero if the addition of byteAdded data to the node
 *                 implies that the node should be split. This is implemented as 
 *                 its own method so that we can override to implement early-split
 *                 or other optimizations
 */
char 
leafNode::splitRequired(int bytesAdded) {
  char needSplit =  (((char *)bottomOfFreeSpace - (bytesAdded)) < 
		     ((char *)header + sizeof(leafNodeHeader) + (header->numElems + 1)*sizeof(leafElemRep)));

  return needSplit;
}

