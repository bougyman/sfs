## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.10 2004/08/20 21:24:42 fubob Exp $

$(PROGRAMS): $(LDEPS) $(DBDEPS)

sfsexec_PROGRAMS = sfsrosd

noinst_HEADERS = \
sfsrosd.h

sfsrosd_SOURCES = sfsrosd.C replica.C client.C gcc2_95_3_sucks.C

sfsrosd_LDADD = $(DBLIB) $(LDADD) $(SFSRO_PROXY_LIB)

EXTRA_DIST = .cvsignore
CLEANFILES = core *.core *~ *.rpo
MAINTAINERCLEANFILES = Makefile.in

