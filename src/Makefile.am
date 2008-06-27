SUBDIRS = include

AM_CPPFLAGS = -I$(srcdir)/include/ -I$(top_srcdir)/libmissing -I$(top_srcdir)/libev @LIBPRELUDE_CFLAGS@ -DCORRELATION_PLUGIN_DIR=\"@CORRELATION_PLUGIN_DIR@\"
AM_CFLAGS = @PRELUDE_MANAGER_CFLAGS@ @GLOBAL_CFLAGS@

bin_PROGRAMS = prelude-correlator
prelude_correlator_LDADD = @LIBPRELUDE_LIBS@ $(top_builddir)/libmissing/libmissing.la
prelude_correlator_LDFLAGS = @LIBPRELUDE_LDFLAGS@ -export-dynamic #"-dlopen" $(top_builddir)/plugins/pcre/pcre.la
prelude_correlator_SOURCES = prelude-correlator.c \
			     correlation-plugins.c


