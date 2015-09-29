## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.12 2002/08/17 02:59:40 dm Exp $

RPCC = ../../rpcc/rpcc

INCLUDES = -I$(top_builddir) -I$(top_builddir)/.. \
	-I/usr/local/include -I$(top_srcdir)/.. \
	-I$(top_srcdir)/../async -I$(top_srcdir)/../arpc \
	-I$(top_srcdir)/../crypt -I$(top_builddir)/../svc \
	-I$(top_srcdir)

if OPENBSD
condCXXFLAGS = $(CXXDEBUG) -ansi -Wall -Wsign-compare -Wchar-subscripts -Werror -DDMALLOC
else
if LINUX
condCXXFLAGS = $(CXXDEBUG) -Wall -Werror  -DDMALLOC
endif
endif
CXXFLAGS = $(condCXXFLAGS)
LDFLAGS = -L../../arpc -L../../async -L../../svc -L../../crypt -L/usr/local/lib
LIBS = -larpc -lasync -lsvc -lcrypt -lgmp -ldmalloc

UVFSPROT = $(top_srcdir)/common/uvfs_prot.x
NFS3PROT = $(top_srcdir)/common/nfs3_prot.x

#uvfs_prot.x: $(UVFSPROT)
#	@rm -f $@
#	ln -s $(UVFSPROT) .

#nfs3_prot.x: $(NFS3PROT)
#	@rm -f $@
#	ln -s $(NFS3PROT) .

SUFFIXES = .x .C .h
.x.h:
	-$(RPCC) -h -o $@ $< || rm -f $@
.x.C:
	-$(RPCC) -c -o $@ $< || rm -f $@

nfs3_prot.h: $(NFS3PROT)
	-$(RPCC) -h -o $@ $< || rm -f $@
nfs3_prot.C: $(NFS3PROT) 
	-$(RPCC) -c -o $@ $< || rm -f $@
nfs3_prot.o: nfs3_prot.h

uvfs_prot.h: $(UVFSPROT)
	-$(RPCC) -h -o $@ $< || rm -f $@
uvfs_prot.C: $(UVFSPROT) 
	-$(RPCC) -c -o $@ $< || rm -f $@
uvfs_prot.o: nfs3_prot.h nfs3_prot.C uvfs_prot.h uvfs_prot.C

noinst_PROGRAMS = uvfs_server

noinst_HEADERS = nfs3_prot.h uvfs_prot.h

uvfs_server_SOURCES = nfs3_prot.C uvfs_prot.C uvfs_server.C

CLEANFILES = core *.core *~ uvfs_server uvfs_prot.h uvfs_prot.C nfs3_prot.C nfs3_prot.h

MAINTAINERCLEANFILES = Makefile.in

