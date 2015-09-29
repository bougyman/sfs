## Process this file with automake to produce Makefile.in
## $Id: Makefile.am,v 1.14 2004/06/03 20:22:07 dm Exp $

if UVFS
COMMON = common
NOT_COMMON =
MOUNT_UVFS = mount_uvfs
else
COMMON =
NOT_COMMON = common
MOUNT_UVFS =
endif

SUBDIRS = arpcgen $(COMMON) @OSDIR@ #server
#DIST_SUBDIRS = $(NOT_COMMON) @NOTOSDIR@
DIST_SUBDIRS = arpcgen common openbsd linux server

noinst_PROGRAMS = $(MOUNT_UVFS)

noinst_HEADERS = uvfs.h
mount_uvfs_SOURCES = mount_uvfs.c

EXTRA_DIST = setup

dist-hook:
	cd $(distdir) && chmod -x setup

CLEANFILES = core *.core *~

distclean: distclean-extra
maintainer-clean: maintainer-clean-extra
.PHONY: distclean-extra maintainer-clean-extra

distclean-extra maintainer-clean-extra:
	for dir in ${DIST_SUBDIRS}; do \
	    needed=yes; \
	    for ddir in ${SUBDIRS}; do \
		test "$$dir" = "$$ddir" && needed=no; \
	    done; \
	    if test "$$needed" = yes; then \
		(cd $$dir && test ! -f Makefile \
			|| $(MAKE) `echo $@ | sed -e 's/-extra$$//'`); \
	    fi; \
	done

DISTCLEANFILES = autom4te*.cache
MAINTAINERCLEANFILES = 				\
	aclocal.m4 install-sh mkinstalldirs missing depcomp \
	configure config.guess config.sub config.h.in \
	INSTALL COPYING Makefile.in stamp-h.in
