## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.20 2002/10/03 23:50:21 dm Exp $

$(PROGRAMS): $(LDEPS)

sfsexec_PROGRAMS = sfsrwcd

noinst_HEADERS = \
sfsrwcd.h

sfsrwcd_SOURCES = server.C sfsrwcd.C
sfsrwcd_LDFLAGS = $(NOPAGING) $(MALLOCK)

$(sfsexec_PROGRAMS): $(MALLOCK)

EXTRA_DIST = .cvsignore
CLEANFILES = core *.core *~ *.rpo
MAINTAINERCLEANFILES = Makefile.in

