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

#include <leafNode.h>
#include <dataNode.h>
#include <indexNode.h>

/*
 * GC
 *
 * Garbage collect this leaf Node
 */
void
leafNode::GC(callback<void>::ref cb) {
  getLock(bLockEx, -1, wrap(this, &leafNode::GC_cb_getLock, cb));
  return;
}

void leafNode::GC_cb_getLock(callback<void>::ref cb) {

  //if empty, delete ourselves and data nodes
  /* if (header->numElems == 0) {
    printf("FOUND EMPTY NODE\n");
       if (header->dataIDHint > 0) 
       tree->bufPool()->readNode(header->dataIDHint, kGuessSize, kOrphan, 
    				wrap(this, &leafNode::GC_cb_readDataNode_mt));
       //fix parent before deleting
       tree->bufPool()->readNode(header->parent, kGuessSize, kOrphan,
			      wrap(this, &leafNode::GC_cb_readParent, cb));
       //#ifdef STATS
       stats.gc_emptyNodes++;
       //#endif
       return;
  } 
  // else if the node is 'minimal' merge
  else*/ 
  if (underflow()) {
    merge(wrap(this, &leafNode::GC_cb_finishMerge, cb));
    return;
  }
  
  //else look at data nodes for empties to splice out
  else if (header->dataIDHint > 0)
    tree->bufPool()->readNode(header->dataIDHint, kGuessSize, kOrphan, 
			      wrap(this, &leafNode::GC_cb_readDataNode, this));
  
#ifdef STATS
  stats.gc_totalSpace += size;
  stats.gc_spaceUsed += header->dataSize;
#endif
  freeLock();
  (*cb)();
  return;
}

void
leafNode::GC_cb_finishMerge(callback<void>::ref cb) {
  
  //  tree->bufPool()->readNode(header->dataIDHint, kGuessSize, kOrphan, 
  //			    wrap(this, &leafNode::GC_cb_readDataNode, this));
  (*cb)();
}
void
leafNode::GC_cb_readDataNode(node *prev, node *dnode) {
 
  nodeID_t nextNode = (dynamic_cast<dataNode *>(dnode))->next();

  //empty?
  if (dnode->numElems() == 0) {
    printf("FOUND EMPTY DATA NODE %ld\n", dnode->nodeID());
    if (!prev->isLeaf())
      (dynamic_cast<dataNode *>(prev))->setNext(nextNode);
    else
      (dynamic_cast<leafNode *>(prev))->setDataHint(nextNode);
    tree->bufPool()->kill(dnode->nodeID());
    if (nextNode > 0)
      tree->bufPool()->readNode(nextNode, kGuessSize, kOrphan,
				wrap(this, &leafNode::GC_cb_readDataNode, prev));
    return;

  } else if (dnode->underflow()) {
    dnode->GC(wrap(this, &leafNode::GC_cb_dataNodeGCdone, dnode));
    prev->freeLock();
    return;
  }
  
  //done?
  prev->freeLock();
  if (nextNode <= 0) {
    return;
  }

  //we are passing this node as the prev pointer, make sure it doesn't get flushed
  dnode->getLock(bLockEx, -1, wrap(this, &leafNode::GC_cb_getDataNodeLock, dnode));
  return;
}

void
leafNode::GC_cb_getDataNodeLock(node *dnode) {
  nodeID_t next =  (dynamic_cast<dataNode *>(dnode))->next();
  if (next > 0) tree->bufPool()->readNode(next, kGuessSize, kOrphan,
					  wrap(this, &leafNode::GC_cb_readDataNode, dnode));
}

void 
leafNode::GC_cb_dataNodeGCdone(node *dnode) {
  dnode->getLock(bLockEx, -1, wrap(this, &leafNode::GC_cb_getDataNodeLock, dnode));
  return;
}
void
leafNode::GC_cb_readDataNode_mt(node *dnode) {
  nodeID_t next = (dynamic_cast<dataNode *>(dnode))->next();
  if (next > 0) 
    tree->bufPool()->readNode(next, kGuessSize, kOrphan,
			    wrap(this, &leafNode::GC_cb_readDataNode_mt));

  if (header->numElems == 0)
    tree->bufPool()->kill(dnode->nodeID());
  else
    (dynamic_cast<dataNode *>(dnode))->setNext(-1); //cut them loose as independent nodes (not the best but...)
  return;
}

void
leafNode::GC_cb_readParent(callback<void>::ref cb, node *parent) {
  
  (dynamic_cast<indexNode *>(parent))->deleteChild(ID);
  deleteSelf(cb);
  return;
}

void
leafNode::deleteSelf(callback<void>::ref cb) {
  if (header->nextPtr > 0) 
    tree->bufPool()->readNode(header->nextPtr, kGuessSize, kOrphan,
			      wrap(this, &leafNode::GC_cb_fixChainBack,cb));
  else if (header->backPtr > 0) 
   tree->bufPool()->readNode(header->backPtr, kGuessSize, kOrphan,
			     wrap(this, &leafNode::GC_cb_fixChainNext,cb));
  else {
    tree->bufPool()->kill(ID);
    (*cb)();
  }
  
  //fix chain
  return;
}

void
leafNode::GC_cb_fixChainNext(callback<void>::ref cb, node *prev) {
  
  (dynamic_cast<leafNode *>(prev))->setNextPtr(header->nextPtr);

  //suicide
  tree->bufPool()->kill(ID);
  (*cb)();
  return;
}

void
leafNode::GC_cb_fixChainBack(callback<void>::ref cb,node *next) {
  
  (dynamic_cast<leafNode *>(next))->setBackPtr(header->backPtr);
  
  if (header->backPtr > 0) 
    tree->bufPool()->readNode(header->backPtr, kGuessSize, kOrphan,
			      wrap(this, &leafNode::GC_cb_fixChainNext, cb));
  else {
    tree->bufPool()->kill(ID);
    (*cb)();
  }

  return;
}




