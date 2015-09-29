## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.13 2003/12/12 22:29:45 dm Exp $

$(PROGRAMS): $(LDEPS)

sfsexec_PROGRAMS = nfsmounter
sbin_PROGRAMS = funmount

noinst_HEADERS = \
nfsmnt.h

nfsmounter_SOURCES = \
domount.C mpfsnode.C nfsfd.C nfsmounter.C safechdir.C staleserv.C uvfsmount.C
nfsmounter_LDFLAGS = $(NOPAGING) $(MALLOCK)

funmount_SOURCES = funmount.c
funmount_LDADD = 

$(sfsexec_PROGRAMS): $(MALLOCK)

EXTRA_DIST = .cvsignore
CLEANFILES = core *.core *~ *.rpo
MAINTAINERCLEANFILES = Makefile.in
