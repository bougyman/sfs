## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.7 2000/08/11 05:59:35 dm Exp $

noinst_LIBRARIES = libbtree.a

libbtree_a_SOURCES = bAlloc.C bSearchPath.C btree.C btreeDebug.C \
	btreeDispatch.C btreeSync.C dataNode.C indexNode.C leafNode.C \
	node.C nodeBuf.C record.C replacement.C superBlock.C bAllocFF.C \
	btree_static.C btree_stats.C leafNode_merge.C leafNode_split.C \
	indexNode_merge.C indexNode_split.C leafNode_GC.C

noinst_HEADERS = \
bAlloc.h bAllocFF.h bIteration.h bSearchPath.h btd_prot.h btree.h btreeDebug.h btreeDispatch.h btreeExceptions.h btreeSync.h btree_types.h dataNode.h indexNode.h leafNode.h node.h nodeBuf.h nodeStorage.h record.h replacement.h superBlock.h

if REPO
btree_repo_OBJECTS = $(libbtree_a_OBJECTS) $(LIBASYNC)
stamp-btree-repo: $(btree_repo_OBJECTS)
	-$(CXXLINK) $(btree_repo_OBJECTS)
	@rm -f a.out
	touch $@
libbtree_a_DEPENDENCIES = stamp-btree-repo
endif

EXTRA_DIST = .cvsignore
CLEANFILES = core *.core *~ *.rpo stamp-sfsmisc-repo
MAINTAINERCLEANFILES = Makefile.in
