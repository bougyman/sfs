## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.19 2004/08/20 20:35:03 fubob Exp $

$(PROGRAMS): $(LDEPS) $(DBDEPS)

sfsexec_PROGRAMS = sfsrocd
noinst_PROGRAMS = rxx_test

noinst_HEADERS = \
sfsrocd.h cache.h

sfsrocd_SOURCES = \
server.C sfsrocd.C

rxx_test_SOURCES = rxx_test.C

# XXX - this should not be required!
sfsrocd_LDADD = $(DBLIB) $(LDADD) $(SFSRO_PROXY_LIB)

EXTRA_DIST = .cvsignore
CLEANFILES = core *.core *~ *.rpo
MAINTAINERCLEANFILES = Makefile.in

