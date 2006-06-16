ACLOCAL_AMFLAGS = -I m4 
SUBDIRS = plugins src
EXTRA_DIST = AUTHORS COPYING HACKING.README INSTALL NEWS README prelude-correlator.conf


install-data-local:
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
