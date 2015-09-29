## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.12 2002/08/17 02:59:40 dm Exp $

libuvfs = ${top_builddir}/common/libuvfs.a

INCLUDES = -Wall -Werror -D_KERNEL -I/sys -I${top_srcdir}/common -I${top_builddir}/common

noinst_HEADERS = uvfs_kern.h

libexec_PROGRAMS = uvfs_mod.o

uvfs_mod_o_SOURCES = uvfs_dev.c uvfs_init.c uvfs_vfsops.c uvfs_vnops.c 

uvfs_mod.o$(EXEEXT): $(uvfs_mod_o_OBJECTS) $(libuvfs)
	ld -r -o $@ $(uvfs_mod_o_OBJECTS) $(libuvfs)

.PHONY: load
load:
	test -f load || ln -s $(srcdir)/load .

all: mkdevs unload
mkdevs unload: load
	@rm -f $@
	ln -s load $@

CLEANFILES = core *.core *~ uvfs_mod 

DISTCLEANFILES = unload mkdevs

MAINTAINERCLEANFILES = Makefile.in
