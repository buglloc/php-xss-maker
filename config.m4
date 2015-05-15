dnl $Id$
dnl config.m4 for extension xss_maker

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

PHP_ARG_WITH(xss_maker, for xss_maker support,
dnl Make sure that the comment is aligned:
[  --with-xss_maker             Include xss_maker support])

dnl Otherwise use enable:

dnl PHP_ARG_ENABLE(xss_maker, whether to enable xss_maker support,
dnl Make sure that the comment is aligned:
dnl [  --enable-xss_maker           Enable xss_maker support])

if test "$PHP_xss_maker" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-xss_maker -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/xss_maker.h"  # you most likely want to change this
  dnl if test -r $PHP_xss_maker/$SEARCH_FOR; then # path given as parameter
  dnl   xss_maker_DIR=$PHP_xss_maker
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for xss_maker files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       xss_maker_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$xss_maker_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the xss_maker distribution])
  dnl fi

  dnl # --with-xss_maker -> add include path
  dnl PHP_ADD_INCLUDE($xss_maker_DIR/include)

  dnl # --with-xss_maker -> check for lib and symbol presence
  dnl LIBNAME=xss_maker # you may want to change this
  dnl LIBSYMBOL=xss_maker # you most likely want to change this

  dnl PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $xss_maker_DIR/lib, xss_maker_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_xss_makerLIB,1,[ ])
  dnl ],[
  dnl   AC_MSG_ERROR([wrong xss_maker lib version or lib not found])
  dnl ],[
  dnl   -L$xss_maker_DIR/lib -lm
  dnl ])
  dnl
  dnl PHP_SUBST(xss_maker_SHARED_LIBADD)

  PHP_NEW_EXTENSION(xss_maker, xss_maker.c, $ext_shared)
fi
