SUBDIRS = ruleset

AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_srcdir)/libmissing @LIBPRELUDE_CFLAGS@ @PCRE_CFLAGS@ @LUA_CFLAGS@ -DLUA_DATADIR=\"@LUA_DATADIR@\"
AM_CFLAGS = @GLOBAL_CFLAGS@

noinst_HEADERS = lua-timer.h lua-idmef.h lua-idmef-value.h regex.h

lua_la_SOURCES = lua.c lua-idmef.c lua-idmef-value.c lua-timer.c regex.c
lua_la_LDFLAGS = -module -avoid-version
lua_la_LIBADD  = @LUA_LIBS@ @PCRE_LIBS@
luadir = $(CORRELATION_PLUGIN_DIR)
lua_LTLIBRARIES = lua.la

lualibdir = @LUA_DATADIR@
dist_lualib_DATA = lib.lua
