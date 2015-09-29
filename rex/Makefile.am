## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.18 2004/07/01 05:46:39 dm Exp $

$(PROGRAMS): $(LDEPS)

bin_PROGRAMS = rex
sfsexec_PROGRAMS = ptyd rexd proxy ttyd listen connect moduled

noinst_HEADERS = \
proxy.h ptyd.h connect.h uasync.h

listen_SOURCES = listen.c uasync.c relay.c
listen_LDADD = $(top_builddir)/libsfs/libsfs.a

connect_SOURCES = connect.c uasync.c
connect_LDADD = 

moduled_SOURCES = moduled.C
moduled_LDADD = $(LIBASYNC)

ptyd_SOURCES = pty.C ptyd.C
ptyd_LDADD = $(LDADD) $(PTYLIB)

rex_SOURCES = rex.C

rexd_SOURCES = rexd.C

proxy_SOURCES = chan.C proxy.C

ttyd_SOURCES = ttyd.C
ttyd_LDADD = $(LDADD) $(PTYLIB)

EXTRA_DIST = .cvsignore
CLEANFILES = core *.core *~ *.rpo
MAINTAINERCLEANFILES = Makefile.in
