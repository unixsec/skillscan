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
# NOT VERIFIED: no Docker daemon is available in this development environment
# (see docs/USER_GUIDE.md's honesty notes on environment-blocked verification,
# same posture as gVisor/M7) - this Dockerfile has not been built here. Base
# image is pinned by tag only, not digest - resolving and recording the exact
# digest is an enterprise build-pipeline step against the enterprise's own
# internal registry mirror (same "fill in at real build time" honesty as
# vendor/engines.lock.yaml's now-resolved `role: fill_in` placeholders were
# before M5 filled them in).
FROM python:3.12-slim-bookworm

ARG PIP_INDEX_URL

RUN apt-get update \
    && apt-get install --no-install-recommends -y git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY vendor/bandit /build/bandit
WORKDIR /build/bandit

# SECURITY: an empty/unset PIP_INDEX_URL makes this an invalid index url and
# pip fails closed, rather than silently defaulting to public PyPI.
RUN pip install --no-cache-dir --index-url "${PIP_INDEX_URL}" .

WORKDIR /scan
ENTRYPOINT ["bandit"]
