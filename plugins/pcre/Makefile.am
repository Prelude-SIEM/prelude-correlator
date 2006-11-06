SUBDIRS = ruleset
AM_CPPFLAGS = @LIBPRELUDE_CFLAGS@ @PCRE_CFLAGS@ -I$(top_srcdir) -I$(top_srcdir)/src/include 

noinst_HEADERS = capture-string.h pcre-mod.h rule-object.h rule-regex.h value-container.h

pcre_la_SOURCES = 			\
		capture-string.c 	\
		pcre-context.c		\
		pcre-mod.c		\
		pcre-parser.c		\
		rule-object.c		\
		rule-regex.c		\
		value-container.c

pcre_la_LDFLAGS = -module -avoid-version
pcre_la_LIBADD  = @PCRE_LIBS@
pcredir = $(CORRELATION_PLUGIN_DIR)
pcre_LTLIBRARIES = pcre.la
