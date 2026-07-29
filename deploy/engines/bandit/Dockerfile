# Pin-digest build image for the `bandit` OSS engine (coding spec §10A: "从
# vendor/<engine> 本地构建 (禁外网)" - build locally from vendored source, no
# external network). Adapted from vendor/bandit/docker/Dockerfile (the
# engine's own upstream Dockerfile) - not written from scratch - to add the
# internal-mirror-only constraint that upstream doesn't need.
#
# Build context MUST be the repo root (not this directory), so `vendor/bandit`
# is reachable:
#   docker build -f deploy/engines/bandit/Dockerfile \
#     --build-arg PIP_INDEX_URL=https://pypi.internal.example/simple \
#     -t skillscan-engine-bandit:1.9.4 .
#
# SECURITY (INV-15/§10A): no `git clone`/public `pip install` here - `COPY`
# pulls the already-vendored, pinned source out of vendor/bandit (see
# vendor/engines.lock.yaml's commit pin); PIP_INDEX_URL has NO default here on
# purpose, so an operator who forgets to pass it gets a hard pip failure
# (invalid/empty index URL), never a silent fall-through to public PyPI.
#
# VERIFIED 2026-07-29: built and run on the dev VM (10.211.55.10). It had NOT
# been, before that date, and it did not work: the comment here used to say "no
# Docker daemon is available in this development environment", and behind that
# comment `pip install .` failed outright, every time, with
#
#   Exception: Versioning for this project requires either an sdist tarball,
#   or access to an upstream git repository.
#
# bandit's packaging is `pbr`-based (setup.py: `setup_requires=["pbr>=2.0.0"],
# pbr=True`) and pbr derives the version from GIT TAGS. A vendored subtree
# carries source, not git history, so there is no tag to read - and this was
# equally true back when vendor/bandit was a submodule, whose `.git` is a file
# pointing into the superproject. `PBR_VERSION` (pbr's own documented escape
# hatch) is fed in below FROM engines.lock.yaml, which is also the version the
# guard at the bottom then asserts the built CLI reports. Base image is still
# pinned by tag only, not digest - resolving that digest is an enterprise
# build-pipeline step against their own registry mirror, not fabricated here.
FROM python:3.12-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

ARG PIP_INDEX_URL
ARG ALLOW_PUBLIC_INDEXES

# INV-14 build-time egress gate - see scripts/require_build_index.sh. An empty
# PIP_INDEX_URL does not fail closed; it silently uses pypi.org.
COPY scripts/require_build_index.sh /usr/local/bin/require_build_index.sh
RUN require_build_index.sh PIP_INDEX_URL "${PIP_INDEX_URL}" "${ALLOW_PUBLIC_INDEXES}" pypi.org

RUN apt-get update \
    && apt-get install --no-install-recommends -y git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY vendor/bandit /build/bandit
# The pin manifest and its reader, so the version this image installs and the
# version it asserts both come from the one authoritative file rather than a
# number transcribed into this Dockerfile.
COPY vendor/engines.lock.yaml /tmp/engines.lock.yaml
COPY scripts/vendor_pinned_version.sh /usr/local/bin/vendor_pinned_version.sh
WORKDIR /build/bandit

# SECURITY: an empty/unset PIP_INDEX_URL makes this an invalid index url and
# pip fails closed, rather than silently defaulting to public PyPI.
#
# NETWORK, stated plainly: `COPY` above removes the dependency on an index
# serving bandit's own SOURCE, but not on an index. pbr (build backend),
# PyYAML, stevedore and rich are still resolved from PIP_INDEX_URL - vendoring
# an engine's source does not vendor its dependency graph.
RUN BANDIT_PIN="$(vendor_pinned_version.sh /tmp/engines.lock.yaml bandit)" \
    && PBR_VERSION="${BANDIT_PIN}" \
        pip install --no-cache-dir --index-url "${PIP_INDEX_URL}" .

# VERSION GUARD (INV-7), the same one services/engine_runner/Dockerfile applies
# to the combined image - see that file's header for why this is a build step
# and not a comment. Kept in both places deliberately: these two Dockerfiles are
# two copies of one recipe, and a guard present in only one of them is exactly
# how the copies drift apart again.
RUN set -eu; \
    pin="$(vendor_pinned_version.sh /tmp/engines.lock.yaml bandit)"; \
    built="$(bandit --version 2>&1 | head -1 | awk '{print $2}')"; \
    echo "bandit  built=${built}  pinned=${pin}"; \
    if [ "$built" != "$pin" ]; then \
        echo "!!! bandit ${built} != vendor/engines.lock.yaml's pinned ${pin}. Refusing." >&2; \
        exit 1; \
    fi; \
    rm -f /tmp/engines.lock.yaml /usr/local/bin/vendor_pinned_version.sh

WORKDIR /scan
ENTRYPOINT ["bandit"]
