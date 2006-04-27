SUBDIRS = ruleset
AM_CPPFLAGS = @LIBPRELUDE_CFLAGS@ @PCRE_CFLAGS@ -I$(top_srcdir) -I$(top_srcdir)/src/include 

noinst_HEADERS = pcre-mod.h rule-object.h rule-regex.h value-container.h

pcre_la_SOURCES = pcre-mod.c rule-object.c rule-regex.c value-container.c
pcre_la_LDFLAGS = -module -avoid-version
pcre_la_LIBADD  = @PCRE_LIBS@
pcredir = $(CORRELATION_PLUGIN_DIR)
pcre_LTLIBRARIES = pcre.la
