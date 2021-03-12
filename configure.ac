AC_INIT([mqtt_websockets], [0.1])

AC_CONFIG_HEADERS([src/include/config.h])
AC_CONFIG_SRCDIR([src/mqtt_wss_client.c])

PKG_PROG_PKG_CONFIG
AC_USE_SYSTEM_EXTENSIONS

AC_PROG_CC
AC_PROG_CC_C99

AC_PROG_RANLIB
AM_PROG_AR

AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_CHECK_LIB(
    [ssl],
    [SSL_connect],
    [SSL_LIBS="-lcrrypto -lssl"],
    AC_MSG_ERROR([SSL Library is required e.g. OpenSSL])
)

AC_CONFIG_FILES([
    Makefile
])

AC_SUBST([SSL_LIBS])

AC_OUTPUT