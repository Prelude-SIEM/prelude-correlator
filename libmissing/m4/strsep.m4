# strsep.m4 serial 5
dnl Copyright (C) 2002, 2003, 2004, 2007 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

AC_DEFUN([gl_FUNC_STRSEP],
[
  dnl Persuade glibc <string.h> to declare strsep().
  AC_REQUIRE([AC_GNU_SOURCE])

  AC_REQUIRE([gl_HEADER_STRING_H_DEFAULTS])
  AC_REPLACE_FUNCS(strsep)
  if test $ac_cv_func_strsep = no; then
    HAVE_STRSEP=0
    gl_PREREQ_STRSEP
  fi
])

# Prerequisites of lib/strsep.c.
AC_DEFUN([gl_PREREQ_STRSEP], [:])