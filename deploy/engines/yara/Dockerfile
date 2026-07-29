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
# VERIFIED 2026-07-29: built and run on the dev VM (10.211.55.10); the CLI it
# produces reports 4.5.7. This recipe was sound - unlike bandit/Dockerfile next
# door, which had been silently unbuildable - and it is the recipe
# services/engine_runner/Dockerfile's yara-builder stage was adapted from when
# that image stopped apt-installing Debian's yara 4.2.3. Two things were
# brought back the other way, so the two copies do not drift:
#   --enable-cuckoo (+ libjansson) - measured against the outgoing apt-installed
#     4.2.3, which linked libjansson.so.4; without it this image quietly has a
#     narrower module set than the one skillscan actually runs.
#   --disable-shared and `strip` - yara's CLI already links libyara statically
#     by default here (confirmed with ldd: no libyara.so in the built binary's
#     dependencies), so `--disable-shared` changes nothing today; it is stated
#     explicitly because the single-file `COPY` below silently depends on it,
#     and a future upstream default flip would produce an image whose `yara`
#     dies at exec on a missing shared object.
# Base image pinned by tag only, not digest - see bandit/Dockerfile's comment
# for why (resolving the exact digest is an enterprise build-pipeline step, not
# fabricated here).
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
    && ./configure --disable-shared --enable-magic --enable-cuckoo \
    && make -j"$(nproc)" \
    && strip yara

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        libjansson4 \
        libmagic1 \
        libssl3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/yara/yara /usr/local/bin/yara
# The pin manifest and its reader, for the guard below only - removed with it.
COPY vendor/engines.lock.yaml /tmp/engines.lock.yaml
COPY scripts/vendor_pinned_version.sh /usr/local/bin/vendor_pinned_version.sh

# VERSION GUARD (INV-7), the same one services/engine_runner/Dockerfile applies
# to the combined image - see that file's header for why this is a build step
# and not a comment, and bandit/Dockerfile for why it is duplicated rather than
# centralised. This is the engine the guard exists because of: the shipped
# image ran 4.2.3 for months against a lock file recording v4.5.7, and a
# comment describing that gap accurately is what let it persist.
RUN set -eu; \
    pin="$(vendor_pinned_version.sh /tmp/engines.lock.yaml yara)"; \
    built="$(/usr/local/bin/yara --version)"; \
    echo "yara  built=${built}  pinned=${pin}"; \
    if [ "$built" != "$pin" ]; then \
        echo "!!! yara ${built} != vendor/engines.lock.yaml's pinned ${pin}. Refusing." >&2; \
        exit 1; \
    fi; \
    rm -f /tmp/engines.lock.yaml /usr/local/bin/vendor_pinned_version.sh

WORKDIR /scan
ENTRYPOINT ["/usr/local/bin/yara"]
