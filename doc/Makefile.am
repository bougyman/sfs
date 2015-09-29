## Process this file with automake to produce Makefile.in
## $Id: Makefile.am,v 1.31 2004/09/07 17:26:55 fubob Exp $

info_TEXINFOS = sfs.texi sfslib.texi
man_MANS = $(srcdir)/sfs.7 $(TEXIMANS)
pkgdata_DATA = sfs.html sfslib.html

TEXIMANS = ssu.1 sfs_config.5 sfs_srp_params.5 sfs_hosts.5 sfs_users.5	\
sfsagent.1 sfsauthd.8 sfsauthd_config.5 sfscd.8 sfscd_config.5		\
sfskey.1 sfsrwcd.8 sfsrwsd.8 sfsrwsd_config.5 sfssd.8 sfssd_config.5	\
rex.1 sfs_environ.7 funmount.8 dirsearch.1 vidb.8 newaid.1		\
nfsmounter.8


INFODEPS = dirs-stamp version.texi
DVIDEPS = components.eps epsf.tex $(INFODEPS)

components.eps: $(srcdir)/components.fig
	fig2dev -L ps -e $(srcdir)/components.fig > components.eps

epsf.tex:
	@rm -f epsf.tex
	epsftex=`find $(prefix)/share/texmf \
		/usr/share/texmf \
		/usr/local/share/texmf \
		/usr/athena/share/texmf \
		-name epsf.tex | head -1`; \
		test "$$epsftex" && ln -s $$epsftex .

PATHFILT = sed -e 's!\([^ ]\)/!\1@dslash{}!g'
dirs-stamp: Makefile
	-@rm -f $(srcdir)/dirs.texi~
	-(echo @set PREFIX $(prefix); \
		echo @set ETCDIR $(etcdir); \
		echo @set SFSDIR $(sfsdir); \
		echo @set PKGDATADIR $(pkgdatadir); \
		echo @set PKGLIBDIR $(pkglibdir); \
		echo @set SFSLIBDIR $(sfslibdir); \
		echo @set PKGINCLUDEDIR $(pkgincludedir)) \
		| $(PATHFILT) >> $(srcdir)/dirs.texi~ \
	&& mv -f $(srcdir)/dirs.texi~ $(srcdir)/dirs.texi
	touch dirs-stamp

sfs.info sfslib.info: $(INFODEPS)
sfs.dvi sfslib.dvi: $(DVIDEPS)
sfs.html sfslib.html: dirs-stamp

SUFFIXES = .texi .dvi .ps .pdf .html

.dvi.ps:
	$(DVIPS) -Ppdf $< -o $@

.ps.pdf:
	ps2pdf $< $@

.texi.html:
	output=$@; (cd $(srcdir) \
		&& rm -f $$output~ \
		&& makeinfo --html --no-headers --no-split sfs.texi -o $$output~ \
		&& mv -f $$output~ $$output)

#sfs.ps: sfs.dvi
#	$(DVIPS) -Ppdf sfs.dvi -o sfs.ps
#
#sfs.pdf: sfs.ps
#	ps2pdf sfs.ps sfs.pdf
#
#sfs.html: $(srcdir)/sfs.texi dirs-stamp
#	output=sfs.html; (cd $(srcdir) \
#		&& rm -f $$output~ \
#		&& makeinfo --html --no-headers --no-split sfs.texi \
#			-o $$output~ \
#		&& mv -f $$output~ $$output)

stamp-man: $(srcdir)/sfs.texi $(srcdir)/manpager.pl
	-cd $(srcdir) && \
	  SFSDIR=$(sfsdir) VERSION=$(VERSION) ETCDIR=$(etcdir) \
	  PKGDATADIR=$(pkgdatadir) PKGLIBDIR=$(pkglibdir) \
	  SFSLIBDIR=$(sfslibdir) PKGINCLUDEDIR=$(pkgincludedir) \
	  POD_MAN=$(PERL_POD_MAN) POD2MAN=$(POD2MAN) \
		$(PERL) manpager.pl sfs.texi .
	touch $(srcdir)/stamp-man

.PHONY: manclean
manclean: clean
	cd $(srcdir) && rm -f stamp-man $(man_MANS) sfs.info sfs.info-*
	rm -f dirs-stamp epsf.tex  components.eps \
		sfs.html sfs.dvi sfs.ps sfs.pdf \
		sfslib.info sfslib.info-* \
		sfslib.html sfslib.dvi sfslib.ps sfslib.pdf

$(TEXIMANS): stamp-man
	@:

$(srcdir)/sfs.7: $(srcdir)/sfs.pod
	@rm -f $@~
	pod2man -c "SFS $(VERSION)" -s 7 $(srcdir)/sfs.pod > $@~
	mv -f $@~ $@

am_maintainer_clean = maintainer-clean
$(am_maintainer_clean): manclean

EXTRA_DIST = .cvsignore epsf.tex components.eps components.fig \
	README manpager.pl sfs.pod stamp-man dirs.texi sfs.html \
	$(man_MANS)
CLEANFILES = core *.core *~ sfs.tmp sfs.dvi sfs.ps \
	$(srcdir)/stamp-vti $(srcdir)/stamp-vti.1
DISTCLEANFILES = sfs.html sfs.pdf dirs-stamp
MAINTAINERCLEANFILES = Makefile.in texinfo.tex epsf.tex components.eps	\
	$(man_MANS) stamp-man $(srcdir)/dirs.texi $(srcdir)/sfs.7
