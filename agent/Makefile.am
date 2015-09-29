## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.75 2004/06/12 16:53:47 dm Exp $

$(PROGRAMS): $(LDEPS)

if HAVE_X
confirm_program = confirm
else
confirm_program =
endif

bin_PROGRAMS = sfsagent sfskey ssu dirsearch sfsproac
sfsexec_PROGRAMS = newaid $(confirm_program)
sfsexec_SCRIPTS = confirm.py srpcache-manager.sh
noinst_PROGRAMS = sfsdea 
noinst_HEADERS = agent.h sfskey.h agentrex.h smallutils.h sexpr.h
sfsinclude_HEADERS = sfsextauth.h

sfsagent_SOURCES = sfsagent.C agentdir.C agentrex.C sfsauthmgr.C	\
agent_gcc_xxx.C

sfsdea_SOURCES = sfsauthmgr.C sfsextauth.C sfsdea.C
sfsproac_SOURCES = sfsauthmgr.C sfsextauth.C sfsproac.C

sfskey_SOURCES = \
sfskey.C sfskeycert.C sfskeyconf.C sfskeyctl.C sfskeygen.C sfskeygroup.C \
sfskeyhostid.C sfskeylogin.C sfskeyreg.C sfskeyrevoke.C sfskeyrexsess.C \
sfskeysrpcache.C sfskeyupdate.C sfskeyuser.C sfskey2gen.C sfskey2edit.C

newaid_SOURCES = newaid.C
if STATIC
newaid_LDADD = $(top_builddir)/libsfs/libsfs.a \
	$(LIBSFSMISC) $(LIBARPC) $(LIBASYNC) $(LIBGMP) $(SETUSERCONTEXTLIB)
newaid_DEPENDENCIES = $(top_builddir)/libsfs/libsfs.a
else
newaid_LDADD = $(top_builddir)/libsfs/libsfs.a $(LDADD)
newaid_DEPENDENCIES = $(top_builddir)/libsfs/libsfs.a
endif

ssu_SOURCES = ssu.C

dirsearch_SOURCES = dirsearch.c
dirsearch_LDADD = 

if HAVE_X
confirm_SOURCES = smallutils.C sexpr.C confirm.C
confirm_LDADD = $(X_PRE_LIBS) $(X_LIBS) -lX11
endif
# also, gui.C and dialog.C are #included by confirm.C

install-exec-hook:
if DMALLOC
	-chmod u-s $(DESTDIR)$(sfsexecdir)/newaid
else
	-chown root $(DESTDIR)$(sfsexecdir)/newaid \
	   && chmod 4555 $(DESTDIR)$(sfsexecdir)/newaid
endif
	rm -f $(DESTDIR)$(bindir)/newaid
	$(LN_S) $(sfsexecdir)/newaid $(DESTDIR)$(bindir)

uninstall-local:
	rm -f $(DESTDIR)$(bindir)/newaid

EXTRA_DIST = .cvsignore confirm.py srpcache-manager.sh gui.C dialog.C
CLEANFILES = core *.core *~ *.rpo
MAINTAINERCLEANFILES = Makefile.in
