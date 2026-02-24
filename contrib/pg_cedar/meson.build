# Copyright (c) 2024, PostgreSQL Global Development Group
#
# pg_cedar — Embedded Cedar authorization engine for PostgreSQL
#
# This extension requires libcedar (C bindings for the Cedar policy engine).
# Build libcedar first:
#   git clone https://github.com/lurkingryuu/libcedar.git
#   cd libcedar && cargo build --release
#
# Then configure with: -Dlibcedar_dir=/path/to/libcedar

# Allow user to specify libcedar location
libcedar_dir = get_option('libcedar_dir')
if libcedar_dir == ''
  # Try a few common locations
  candidate_dirs = [
    meson.current_source_dir() / 'libcedar',
    meson.project_source_root() / '..' / 'libcedar',
  ]
  foreach d : candidate_dirs
    if fs.is_file(d / 'include' / 'libcedar.h')
      libcedar_dir = d
      break
    endif
  endforeach
endif

if libcedar_dir == ''
  warning('libcedar not found — pg_cedar will not be built. Clone from https://github.com/lurkingryuu/libcedar.git')
  subdir_done()
endif

libcedar_inc = include_directories(libcedar_dir / 'include')

# Declare the static library as an external dependency
libcedar_lib = declare_dependency(
  include_directories: libcedar_inc,
  dependencies: [
    cc.find_library('cedar', dirs: [libcedar_dir / 'target' / 'release'], static: true),
    cc.find_library('m'),
    cc.find_library('dl'),
    cc.find_library('pthread'),
    cc.find_library('resolv'),
  ],
)

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
