# Copyright (c) 2020 The HIBA Authors All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.
VERSION_INFO = -version-info $(SONAME_CURRENT):$(SONAME_REVISION):$(SONAME_AGE)
ACLOCAL_AMFLAGS = -I m4

CFLAGS = -I@opensshdir@ -Wall -Wextra -Werror -Wno-attributes -Wno-unused-parameter -Wformat-security -O2 -D_FORTIFY_SOURCE=2 -fPIE -Wa,--noexecstack
LDFLAGS = -pie -Wl,-z,relro,-z,now
ARFLAGS = cr

include_HEADERS = hiba.h extensions.h errors.h checks.h certificates.h

lib_LIBRARIES = libhiba.a
libhiba_a_SOURCES = extensions.c errors.c checks.c certificates.c
libhiba_a_LIBADD =

lib_LTLIBRARIES = libhiba.la
libhiba_la_SOURCES = extensions.c errors.c checks.c certificates.c
libhiba_la_CFLAGS =
libhiba_la_LDFLAGS = $(VERSION_INFO)

sbin_PROGRAMS = hiba-chk hiba-gen

hiba_chk_SOURCES = hiba-chk.c util.c
hiba_chk_LDADD = -L@opensshdir@ -L@opensshdir@/openbsd-compat -L. -lhiba -lssh -lopenbsd-compat -lcrypto
hiba_chk_DEPENDENCIES = libhiba.a

hiba_gen_SOURCES = hiba-gen.c util.c
hiba_gen_LDADD = -L@opensshdir@ -L@opensshdir@/openbsd-compat -L. -lhiba -lssh -lopenbsd-compat -lcrypto
hiba_gen_DEPENDENCIES = libhiba.a

dist_sbin_SCRIPTS = hiba-ca.sh

man1_MANS = hiba-chk.1 hiba-gen.1 hiba-ca.sh.1
