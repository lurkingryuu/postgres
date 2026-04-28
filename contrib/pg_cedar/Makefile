# contrib/pg_cedar/Makefile
#
# pg_cedar — Embedded Cedar authorization engine for PostgreSQL
# Links against an installed libcedar package discoverable via pkg-config.
#

MODULE_big = pg_cedar
OBJS = \
	$(WIN32RES) \
	pg_cedar.o

LIBCEDAR_PC ?= libcedar
LIBCEDAR_CFLAGS := $(shell pkg-config --cflags $(LIBCEDAR_PC) 2>/dev/null)
LIBCEDAR_LIBS := $(shell pkg-config --libs $(LIBCEDAR_PC) 2>/dev/null)

ifeq ($(strip $(LIBCEDAR_CFLAGS) $(LIBCEDAR_LIBS)),)
$(error pg_cedar requires an installed libcedar package discoverable via pkg-config. Set PKG_CONFIG_PATH if libcedar is installed in a non-default prefix.)
endif

PG_CPPFLAGS += $(LIBCEDAR_CFLAGS)
SHLIB_LINK  += $(LIBCEDAR_LIBS)

EXTENSION = pg_cedar
DATA = pg_cedar--1.0.sql pg_cedar--1.0--1.1.sql pg_cedar--1.1.sql
PGFILEDESC = "pg_cedar - embedded Cedar authorization engine for PostgreSQL"

REGRESS = pg_cedar
TAP_TESTS = 1

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/pg_cedar
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
