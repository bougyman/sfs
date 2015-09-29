## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.7 2003/10/12 05:22:41 dm Exp $

$(PROGRAMS): $(LDEPS)

sbin_PROGRAMS = sfssd

noinst_HEADERS = \
sfssd.h

sfssd_SOURCES = \
sfssd.C tcpproxy.C whatport.C

EXTRA_DIST = .cvsignore
CLEANFILES = core *.core *~ *.rpo
MAINTAINERCLEANFILES = Makefile.in
