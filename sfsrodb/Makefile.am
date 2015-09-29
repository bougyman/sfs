## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.16 2004/08/24 20:17:00 fubob Exp $

$(PROGRAMS): $(LDEPS) $(DBDEPS)

noinst_LIBRARIES = libsfsrodb.a

bin_PROGRAMS = sfsrodb pulldb printdb regress maxproxy

noinst_HEADERS = \
dbfe.h sfsrodb.h sfsrodb_core.h keyregression.h maxproxyrenc_cps.h

libsfsrodb_a_SOURCES = \
sfsrodb_core.C dbfe.C keyregression.C

sfsrodb_SOURCES = \
sfsrodb.C fhdb.C 

printdb_SOURCES = \
printdb.C

pulldb_SOURCES = \
pulldb.C

regress_SOURCES = \
regress.C

maxproxy_SOURCES = \
maxproxyrenc_cps.C

#test_callback_SOURCES = test_callback.C
#test_fhdb_SOURCES = sfsrodb_core.C test_fhdb.C fhdb.C

sfsrodb_LDADD = $(DBLIB) $(LDADD) $(SFSRO_PROXY_LIB)
printdb_LDADD = $(DBLIB) $(LDADD) $(SFSRO_PROXY_LIB)
pulldb_LDADD = $(DBLIB) $(LDADD) $(SFSRO_PROXY_LIB)
maxproxy_LDADD = $(DBLIB) $(LDADD) $(SFSRO_PROXY_LIB)
regress_LDADD = $(DBLIB) $(LDADD)


EXTRA_DIST = .cvsignore
CLEANFILES = core *.core *~ *.rpo
MAINTAINERCLEANFILES = Makefile.in
