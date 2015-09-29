## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.14 1999/11/29 01:27:46 dm Exp $

if OPENBSD
INCLUDES = -Wall -Werror -D_KERNEL -I/sys
endif
if LINUX
KERNINC = /usr/include
INCLUDES = -Wall -Werror -D__KERNEL__ -DMODULE -DMODVERSIONS -I$(KERNINC) -include $(KERNINC)/linux/modversions.h
endif

RPCGEN = $(top_builddir)/arpcgen/arpcgen

pkglib_LIBRARIES = libuvfs.a

SUFFIXES = .x .c .h
.x.h:
	-$(RPCGEN) -h -o $@ $< || rm -f $@
.x.c:
	-$(RPCGEN) -c -o $@ $< || rm -f $@

uvfs_prot.h: uvfs_prot.x
uvfs_prot.c: uvfs_prot.x
uvfs_prot.o: uvfs_prot.h uvfs_prot.c nfs3_prot.h nfs3_prot.c
	$(COMPILE) -w -c uvfs_prot.c
#uvfs_prot_tbl.c: uvfs_prot.x
#	$(RPCGEN) -t -o $@ $< || rm -f $@

nfs3_prot.h: nfs3_prot.x
nfs3_prot.c: nfs3_prot.x
nfs3_prot.o: nfs3_prot.h nfs3_prot.c
	$(COMPILE) -w -c nfs3_prot.c 

nfs3exp_prot.h: nfs3exp_prot.x
nfs3exp_prot.c: nfs3exp_prot.x
nfs3exp_prot.o: nfs3exp_prot.h nfs3exp_prot.c
	$(COMPILE) -w -c nfs3exp_prot.c 

libuvfs_a_SOURCES = \
krpc.c rpc_prot.c suio.c xdr.c xdr_array.c xdr_mem.c xdr_reference.c xdr_suio.c nfs3_prot.c nfs3exp_prot.c uvfs_prot.c uiomove.c

noinst_HEADERS = \
arpc.h clnt.h rpc_msg.h xdr.h auth.h queue.h suio.h types.h uvfs_prot.h xdr_suio.h nfs3_prot.h

CLEANFILES = core *.core *~ nfs3_prot.c nfs3_prot.h uvfs_prot.c uvfs_prot.h uvfs_prot_tbl.c

EXTRA_DIST = .cvsignore nfs3_prot.x nfs3exp_prot.x uvfs_prot.x
MAINTAINERCLEANFILES = Makefile.in
