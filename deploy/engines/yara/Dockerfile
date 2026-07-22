# Pin-digest build image for the `yara` OSS engine (coding spec §10A). No
# Dockerfile ships in the upstream repo (vendor/yara/) - build dependencies
# and ./configure flags below are taken from the real upstream CI recipe
# (vendor/yara/.github/workflows/build.yml), not guessed, per coding spec
# §10A.3's "读真实 vendor 源码,不臆测接口" (read the real vendored source,
# don't guess the interface) applied to the build system too.
#
# SECURITY: this builds the standalone `yara` CLI binary (autotools,
# `configure && make`) - NOT the `yara-python` bindings package, matching
# services/engine_runner/adapters/yara.py's INV-15 resolution (subprocess CLI
# only, never `import yara`).
#
# Build context MUST be the repo root:
#   docker build -f deploy/engines/yara/Dockerfile -t skillscan-engine-yara:4.5.7 .
#
# This engine's dependencies (autoconf/automake/libtool/libssl-dev/etc.) come
# from the base image's OS package manager, not PyPI/Go proxy/git clone - no
# ARG-parametrized mirror is needed here (unlike bandit/osv-scanner), but the
# apt sources themselves must already point at an internal Debian mirror at
# the base-image layer for a genuinely air-gapped build - that is a property
# of the enterprise's own base-image pipeline, out of scope for this
# per-engine Dockerfile (same assumption skillspector's/bandit's Dockerfiles
# make about their own `apt-get install` steps).
#
# NOT VERIFIED: no Docker daemon is available in this development environment
# - this Dockerfile has not been built here (same posture as this directory's
# other Dockerfiles). Base image pinned by tag only, not digest - see
# bandit/Dockerfile's comment for why (resolving the exact digest is an
# enterprise build-pipeline step, not fabricated here).
FROM debian:bookworm-slim AS builder

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        autoconf \
        automake \
        libtool \
        pkg-config \
        bison \
        flex \
        make \
        gcc \
        libjansson-dev \
        libmagic-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY vendor/yara /build/yara
WORKDIR /build/yara

RUN ./bootstrap.sh \
    && ./configure --enable-magic \
    && make

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        libjansson4 \
        libmagic1 \
        libssl3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/yara/yara /usr/local/bin/yara

WORKDIR /scan
ENTRYPOINT ["/usr/local/bin/yara"]
