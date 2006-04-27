SUBDIRS = include

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/src/include @LIBPRELUDE_CFLAGS@ -DCORRELATION_PLUGIN_DIR=\"@CORRELATION_PLUGIN_DIR@\"

bin_PROGRAMS = prelude-correlator
prelude_correlator_LDADD = @LIBPRELUDE_LIBS@
prelude_correlator_LDFLAGS = @LIBPRELUDE_LDFLAGS@ -export-dynamic
prelude_correlator_SOURCES = prelude-correlator.c \
			     correlation-plugins.c

