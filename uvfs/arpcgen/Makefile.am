## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.1 1999/01/13 04:46:56 kaminsky Exp $

LDADD=

noinst_PROGRAMS = arpcgen

noinst_HEADERS = \
rpc_parse.h rpc_scan.h rpc_util.h

arpcgen_SOURCES = \
rpc_cout.c rpc_hout.c rpc_main.c rpc_parse.c rpc_scan.c rpc_tblout.c rpc_util.c

CLEANFILES = core *.core *~

MAINTAINERCLEANFILES = Makefile.in
