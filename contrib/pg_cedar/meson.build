# Copyright (c) 2024, PostgreSQL Global Development Group
#
# pg_cedar — Embedded Cedar authorization engine for PostgreSQL
#
# This extension requires an installed libcedar package discoverable via
# pkg-config. Set PKG_CONFIG_PATH when libcedar is installed in a non-default
# prefix.
libcedar_lib = dependency('libcedar', method: 'pkg-config', required: true)

pg_cedar_sources = files('pg_cedar.c')

if host_system == 'windows'
  pg_cedar_sources += rc_lib_gen.process(win32ver_rc, extra_args: [
    '--NAME', 'pg_cedar',
    '--FILEDESC', 'pg_cedar - embedded Cedar authorization engine for PostgreSQL',])
endif

pg_cedar = shared_module('pg_cedar',
  pg_cedar_sources,
  kwargs: contrib_mod_args + {
    'dependencies': [libcedar_lib, contrib_mod_args['dependencies']],
  },
)
contrib_targets += pg_cedar

install_data(
  'pg_cedar.control',
  'pg_cedar--1.0.sql',
  kwargs: contrib_data_args,
)

tests += {
  'name': 'pg_cedar',
  'sd': meson.current_source_dir(),
  'bd': meson.current_build_dir(),
  'regress': {
    'sql': [
      'pg_cedar',
    ],
  },
  'tap': {
    'tests': [
      't/001_basic.pl',
    ],
  },
}
