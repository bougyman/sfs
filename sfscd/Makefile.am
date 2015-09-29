## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.13 2002/09/26 19:10:30 dm Exp $

$(PROGRAMS): $(LDEPS)

sbin_PROGRAMS = sfscd

noinst_HEADERS = \
afsroot.h ctlnode.h sfscd.h

sfscd_SOURCES = \
afs.C afsroot.C ctlnode.C delaypt.C mnt.C pathrevoke.C	\
sfscd.C srvinfo.C usrinfo.C

EXTRA_DIST = .cvsignore
CLEANFILES = core *.core *~ *.rpo
MAINTAINERCLEANFILES = Makefile.in
