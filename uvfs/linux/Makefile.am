## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.9 2002/08/17 02:59:40 dm Exp $

libuvfs = ../common/libuvfs.a

KERNINC = /usr/include
GCCLIB = /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66
INCLUDES = -Wall -Werror -D__KERNEL__ -DMODULE -DMODVERSIONS -I$(KERNINC) -I${top_srcdir}/common -I${top_builddir}/common -include $(KERNINC)/linux/modversions.h

libexec_PROGRAMS = uvfs.o

noinst_HEADERS = uvfs_kern.h

uvfs_o_SOURCES = uvfs_init.c uvfs_dev.c inode.c dir.c file.c symlink.c

.PHONY: load
load:
	test -f load || ln -s $(srcdir)/load .

all: unload
unload: load
	@rm -f $@
	ln -s load $@

uvfs.o$(EXEEXT): $(uvfs_o_OBJECTS) $(libuvfs)
	ld -r -o $@ $(uvfs_o_OBJECTS) $(libuvfs) $(GCCLIB)/libgcc.a

CLEANFILES = core *.core *~ uvfs.o

DISTCLEANFILES = unload

MAINTAINERCLEANFILES = Makefile.in
