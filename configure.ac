AC_PREREQ([2.69])
AC_INIT([wilqifstats], [0.1], [fatwildcat@gmail.com])
AC_CONFIG_SRCDIR([src/wilqifstatsd.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([pcap], [pcap_open_live])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h malloc.h memory.h netdb.h netinet/in.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT16_T

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([gethostbyaddr inet_ntoa memmove memset mkdir strdup strerror strtoul])

AC_CONFIG_FILES([Makefile src/Makefile debian/Makefile])
AC_OUTPUT
