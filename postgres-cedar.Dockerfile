# Modified PostgreSQL with Cedar authorization hooks
# Builds from the modified PostgreSQL source with universal authorization hooks

# Use the same base for the builder to ensure library compatibility
FROM postgres:17.7 AS builder

# Install build dependencies
ENV DEBIAN_FRONTEND=noninteractive
ARG LIBCEDAR_VERSION=v0.1.0
ARG LIBCEDAR_PKG_BASE_URL=https://github.com/lurkingryuu/libcedar/releases/download
ARG LIBCEDAR_PREFIX=/opt/libcedar
# TARGETARCH is a Docker predefined platform arg (set by BuildKit / --platform).
# It must be redeclared inside the stage with ARG to be visible in RUN shells.
ARG TARGETARCH
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    curl \
    ca-certificates \
    libreadline-dev \
    zlib1g-dev \
    flex \
    bison \
    libxml2-dev \
    libxslt-dev \
    libssl-dev \
    libpam0g-dev \
    libedit-dev \
    libkrb5-dev \
    libldap2-dev \
    libcurl4-openssl-dev \
    libselinux1-dev \
    libnss-wrapper \
    gettext \
    python3-dev \
    tcl-dev \
    perl \
    pkg-config \
    uuid-dev \
    libicu-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /postgres-build

# Copy the modified PostgreSQL source
COPY . /postgres-build/

# Install the packaged libcedar SDK from GitHub Releases.
RUN set -eux; \
    target_arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "${target_arch}" in \
      amd64) libcedar_target="x86_64-unknown-linux-gnu" ;; \
      arm64) libcedar_target="aarch64-unknown-linux-gnu" ;; \
      *) echo "Unsupported TARGETARCH: ${target_arch}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/libcedar.tar.gz \
      "${LIBCEDAR_PKG_BASE_URL}/${LIBCEDAR_VERSION}/libcedar-${LIBCEDAR_VERSION#v}-${libcedar_target}.tar.gz"; \
    mkdir -p "${LIBCEDAR_PREFIX}"; \
    tar -xzf /tmp/libcedar.tar.gz -C "${LIBCEDAR_PREFIX}"; \
    rm -f /tmp/libcedar.tar.gz; \
    libcedar_pc_dir=""; \
    for candidate in "${LIBCEDAR_PREFIX}/lib/pkgconfig" "${LIBCEDAR_PREFIX}"/lib/*/pkgconfig; do \
      if [ -f "${candidate}/libcedar.pc" ]; then libcedar_pc_dir="${candidate}"; break; fi; \
    done; \
    test -n "${libcedar_pc_dir}"; \
    ln -sfn "${libcedar_pc_dir}" "${LIBCEDAR_PREFIX}/lib/pkgconfig"

ENV PKG_CONFIG_PATH="${LIBCEDAR_PREFIX}/lib/pkgconfig"

# Configure and build PostgreSQL
# We use --with-uuid=e2fs which requires uuid-dev
# Optimized build for production performance
RUN ./configure \
    --prefix=/usr/local/pgsql \
    --with-openssl \
    --with-libxml \
    --with-libxslt \
    --with-uuid=e2fs \
    --enable-depend \
    CFLAGS="-O2 -march=native -mtune=native" \
    && make -j$(nproc) \
    && make -j$(nproc) -C contrib \
    && make install \
    && make -C contrib install

# Final stage: Use the official PostgreSQL 17.7 image as base
# This provides the entrypoint, default configuration, and standard environment
FROM postgres:17.7

# Install additional runtime dependencies that might not be in the base image
# CRITICAL: libcurl4 is required for the pg_authorization extension
ARG LIBCEDAR_PREFIX=/opt/libcedar
RUN apt-get update && apt-get install -y \
    libxslt1.1 \
    libselinux1 \
    libuuid1 \
    libxml2 \
    libcurl4 \
    libicu76 \
    && rm -rf /var/lib/apt/lists/*

# Copy our built PostgreSQL over the existing one or to a separate prefix
# We'll put it in /usr/local/pgsql as before, but ensure it's used
COPY --from=builder /usr/local/pgsql /usr/local/pgsql
COPY --from=builder ${LIBCEDAR_PREFIX} ${LIBCEDAR_PREFIX}

# Prepend our build to PATH so the entrypoint and users use our modified version
ENV PATH=/usr/local/pgsql/bin:$PATH
ENV PGDATA=/var/lib/postgresql/data

# Ensure the postgres user owns the new files
RUN chown -R postgres:postgres /usr/local/pgsql

# Update shared library cache and ensure our lib directory is searched
RUN libcedar_lib_dir="$(dirname "$(readlink -f "${LIBCEDAR_PREFIX}/lib/pkgconfig")")" \
    && printf "/usr/local/pgsql/lib\n%s\n" "${libcedar_lib_dir}" > /etc/ld.so.conf.d/00-postgres-custom.conf \
    && ldconfig

# Also symlink our built PostgreSQL components to the official locations.
# This ensures that the official image's entrypoint and scripts find our modified
# versions instead of the standard ones.
RUN mkdir -p /usr/lib/postgresql/17/lib/ /usr/share/postgresql/17/extension/ && \
    ln -sf /usr/local/pgsql/lib/pg_authorization.so /usr/lib/postgresql/17/lib/pg_authorization.so && \
    ln -sf /usr/local/pgsql/lib/pg_cedar.so      /usr/lib/postgresql/17/lib/pg_cedar.so && \
    ln -sf /usr/local/pgsql/share/extension/pg_authorization* /usr/share/postgresql/17/extension/ && \
    ln -sf /usr/local/pgsql/share/extension/pg_cedar*         /usr/share/postgresql/17/extension/ && \
    ln -sf /usr/local/pgsql/bin/postgres /usr/lib/postgresql/17/bin/postgres && \
    ln -sf /usr/local/pgsql/bin/pg_config /usr/lib/postgresql/17/bin/pg_config

# Copy initialization scripts (official image entrypoint uses this directory)
COPY postgres-init.sql /docker-entrypoint-initdb.d/

# Note: The official image already has EXPOSE 5432, ENTRYPOINT, and CMD
