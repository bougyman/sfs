## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.29 2003/08/08 16:00:58 kaminsky Exp $

$(PROGRAMS): $(LDEPS)

#if USE_DB
#noinst_PROGRAMS = tst
#tst_SOURCES = tst.C # authdb_types.C authdb_db.C authdb.C dbrec2str.C
#tst_LDADD = $(DB_LIB) # $(LDADD) $(DB_LIB)
#endif

sfsexec_PROGRAMS = sfsauthd xfer 
bin_PROGRAMS = sfsdeclog
sbin_PROGRAMS = vidb

noinst_HEADERS = authdb.h sfsauthd.h authdb_types.h authgrps.h authdb_db.h

sfsauthd_SOURCES = authdb_types.C authclnt.C dbrec2str.C sfsauthd.C	\
authdb.C authgrps.C authdb_db.C
sfsauthd_LDADD = $(LDADD) $(LIBCRYPT) $(DB_LIB)

vidb_SOURCES = authdb_types.C authdb.C authdb_db.C dbrec2str.C vidb.C
vidb_LDADD = $(LDADD) $(DB_LIB)
#vidb_LDADD = $(LIBSFSCRYPT) $(LIBARPC) $(LIBASYNC) $(LIBGMP)

sfsdeclog_SOURCES = sfsdeclog.C
sfsdeclog_LDADD = $(LIBARPC) $(LIBASYNC) $(LIBCRYPT) $(LIBSFSCRYPT) \
	          $(LIBSVC) $(LIBGMP)

xfer_SOURCES = xfer.C

authdb_types.h: $(srcdir)/authdb_types.x
	@rm -f $@
	-$(RPCC) -h $(srcdir)/authdb_types.x || rm -f $@

authdb_types.C: $(srcdir)/authdb_types.x
	@rm -f $@
	-$(RPCC) -c $(srcdir)/authdb_types.x || rm -f $@

dist-hook:
	cd $(distdir) && rm -f authdb_types.h authdb_types.C

authdb_types.o authdb_types.lo: authdb_types.h
$(tst_OBJECTS) $(authdb_OBJECTS) $(vidb_OBJECTS): authdb_types.h

EXTRA_DIST = authdb_types.x .cvsignore
CLEANFILES = core *.core *~ *.rpo
MAINTAINERCLEANFILES = Makefile.in

