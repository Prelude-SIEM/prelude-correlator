ACLOCAL_AMFLAGS = -I m4 -I libmissing/m4
SUBDIRS = libmissing plugins src
EXTRA_DIST = AUTHORS COPYING HACKING.README INSTALL NEWS README prelude-correlator.conf


install-data-local:
	$(INSTALL) -m 700 -d $(DESTDIR)$(prelude_correlator_context_dir)
	@if test -f $(DESTDIR)$(configdir)/prelude-correlator.conf; then                                        \
		echo "********************************************************************************";        \
		echo;                                                                                           \
		echo "$(DESTDIR)$(configdir)/prelude-correlator.conf already exist...";                         \
		echo "Installing default configuration in $(DESTDIR)$(configdir)/prelude-correlator.conf-dist"; \
		echo;                                                                                           \
		echo "********************************************************************************";        \
		$(INSTALL) -m 600 $(top_srcdir)/prelude-correlator.conf $(DESTDIR)$(configdir)/prelude-correlator.conf-dist;  \
	else                                                                                                    \
		$(INSTALL) -m 600 $(top_srcdir)/prelude-correlator.conf $(DESTDIR)$(configdir)/;                \
	fi

uninstall-local:
	rm -f $(DESTDIR)$(configdir)/prelude-correlator.conf;
