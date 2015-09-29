## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.3 2003/01/17 06:14:47 dm Exp $

$(PROGRAMS): $(LDEPS)

bin_PROGRAMS = sfsacl
sfsexec_PROGRAMS = sfsaclsd

noinst_HEADERS = \
sfsaclsd.h acl.h acltargetlist.h acldefs.h

sfsaclsd_SOURCES = \
client.C fhtrans.C filesrv.C lease.C sfsaclsd.C acl.C acltargetlist.C acldefs.C

sfsacl_SOURCES = sfsacl.c
sfsacl_LDADD = $(top_builddir)/libsfs/libsfs.a

sfsacl.o: sfsacl.c
	$(CC) -I$(top_srcdir)/libsfs -I$(top_builddir)/libsfs \
		$(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) \
		$(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) \
		-c $(srcdir)/sfsacl.c

EXTRA_DIST = .cvsignore
CLEANFILES = core *.core *~ *.rpo
MAINTAINERCLEANFILES = Makefile.in
