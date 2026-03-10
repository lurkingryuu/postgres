# contrib/pg_cedar/Makefile
#
# pg_cedar — Embedded Cedar authorization engine for PostgreSQL
# Links against libcedar (Rust/C bindings for the Cedar policy engine)
#

MODULE_big = pg_cedar
OBJS = \
	$(WIN32RES) \
	pg_cedar.o

# --------------------------------------------------------------------------
# libcedar dependency (fetched and built from GitHub)
# --------------------------------------------------------------------------
# Override these with environment variables if needed:
#   LIBCEDAR_REPO   — Git URL for libcedar (default: GitHub)
#   LIBCEDAR_DIR    — Local directory to clone/build libcedar into
#   LIBCEDAR_BRANCH — Git branch/tag to use
LIBCEDAR_REPO   ?= https://github.com/lurkingryuu/libcedar.git
LIBCEDAR_DIR    ?= $(CURDIR)/libcedar
LIBCEDAR_BRANCH ?= main

LIBCEDAR_LIB    = $(LIBCEDAR_DIR)/target/release/libcedar.a
LIBCEDAR_HEADER = $(LIBCEDAR_DIR)/include/libcedar.h

PG_CPPFLAGS = -I$(LIBCEDAR_DIR)/include
SHLIB_LINK  = $(LIBCEDAR_LIB) -lm -ldl -lpthread -lresolv

EXTENSION = pg_cedar
DATA = pg_cedar--1.0.sql pg_cedar--1.0--1.1.sql pg_cedar--1.1.sql
PGFILEDESC = "pg_cedar - embedded Cedar authorization engine for PostgreSQL"

REGRESS = pg_cedar
TAP_TESTS = 1

# Ensure libcedar is built before compiling the extension
pg_cedar.o: $(LIBCEDAR_LIB)

$(LIBCEDAR_LIB): $(LIBCEDAR_HEADER)
	cd $(LIBCEDAR_DIR) && cargo build --release

$(LIBCEDAR_HEADER):
	@if [ ! -d "$(LIBCEDAR_DIR)" ]; then \
		echo "Cloning libcedar from $(LIBCEDAR_REPO)..."; \
		git clone --branch $(LIBCEDAR_BRANCH) --depth 1 $(LIBCEDAR_REPO) $(LIBCEDAR_DIR); \
	fi
	@test -f $(LIBCEDAR_HEADER) || (cd $(LIBCEDAR_DIR) && cargo build --release)

# Clean libcedar build artifacts too
clean: clean-libcedar
clean-libcedar:
	@if [ -d "$(LIBCEDAR_DIR)/target" ]; then \
		cd $(LIBCEDAR_DIR) && cargo clean; \
	fi

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
