## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.15 2002/10/03 23:50:21 dm Exp $

$(PROGRAMS): $(LDEPS)

sfsexec_PROGRAMS = sfsrwsd

noinst_HEADERS = \
sfsrwsd.h

sfsrwsd_SOURCES = \
client.C fhtrans.C filesrv.C lease.C sfsrwsd.C

EXTRA_DIST = .cvsignore
CLEANFILES = core *.core *~ *.rpo
MAINTAINERCLEANFILES = Makefile.in
