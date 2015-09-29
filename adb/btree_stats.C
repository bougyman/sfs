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
 * btree_stats.C -- methods for gathering tree performance statistics
 *
 */
#include <btree.h>
#include <btree_types.h>

#ifdef DMALLOC
#include <dmalloc.h>
#endif
#include "stdio.h"
#include "stdlib.h"

#ifdef STATS
statsRec stats;

void
primitiveTiming(nodeBuf *buffer) {
  //primitive timing
  struct timeval t_start, t_end;
  gettimeofday(&t_start, NULL);
  for (int i = 0; i < 100; i++) buffer->fetch(1);
  gettimeofday(&t_end, NULL);
  FILE *statsFile = stats.output;
  fprintf(statsFile, "primitive timing\n");
  fprintf(statsFile, "  fetch:");
  fprintf(statsFile, "    100 operations in %ld microseconds\n", timediff(t_start, t_end));
  fprintf(statsFile, "    %ld operations per second\n", 100*1000000/timediff(t_start, t_end));
  
  struct timeval *start = (struct timeval *)malloc(sizeof(struct timeval));
  testReadNode(buffer, 101, 0, start, wrap(&primitiveTiming_cb_readNode), buffer->fetch(1));
  
  
  return;
}

void
primitiveTiming_cb_readNode(long elapsed) {
  fprintf(stats.output, "  readNode (in cache):\n");
  fprintf(stats.output, "    100 operations in %ld microseconds\n", elapsed);
  fprintf(stats.output, "    %ld operations per second\n", 100*1000000/elapsed);
  return;
}

void
testReadNode(nodeBuf* buffer, int nops, int state, struct timeval *startTime, callback<void, long>::ref cb, node *n) { 
  n->nodeID();
  if (nops == 0) {
    struct timeval t_end;
    gettimeofday(&t_end, NULL);
    (*cb)(timediff((*startTime), t_end));
    return;
  }
  if (state == 0) 
    gettimeofday(startTime, NULL);
  buffer->readNode(1, kGuessSize, kOrphan, wrap(&testReadNode, buffer, nops - 1, 1, startTime, cb));
  return;
}
#endif


