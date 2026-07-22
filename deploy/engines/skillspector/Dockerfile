# Pin-digest build image for the `skillspector` OSS engine (coding spec
# §10A). Adapted from vendor/skillspector/Dockerfile (the engine's own
# upstream Dockerfile) - not written from scratch - to build from the
# already-vendored source tree with an internal-mirror-only pip index instead
# of upstream's unparametrized `pip install .`.
#
# Build context MUST be the repo root:
#   docker build -f deploy/engines/skillspector/Dockerfile \
#     --build-arg PIP_INDEX_URL=https://pypi.internal.example/simple \
#     -t skillscan-engine-skillspector:dde36f2 .
#
# SECURITY (INV-15/§10A/INV-14): no `git clone`/public `pip install` here -
# `COPY` pulls the already-vendored, pinned source out of vendor/skillspector
# (see vendor/engines.lock.yaml's commit pin - skillspector has no upstream
# release tag, pinned to a bare commit). PIP_INDEX_URL has no default, same
# fail-closed rationale as bandit/Dockerfile in this same directory tree.
# `OPENAI_BASE_URL` (INV-14, internal vLLM only) and OSV endpoint config are
# runtime concerns for the adapter/orchestrator, not this build stage - see
# services/engine_runner/adapters/skillspector.py's own module docstring for
# the still-open OSV-lookup network-control gap this image alone can't close.
#
# NOT VERIFIED: no Docker daemon is available in this development environment
# - this Dockerfile has not been built here (same posture as this directory's
# other Dockerfiles).
FROM python:3.12-slim-bookworm AS builder

ARG PIP_INDEX_URL

WORKDIR /build
COPY vendor/skillspector/ ./
RUN python -m venv .venv
# SECURITY: an empty/unset PIP_INDEX_URL makes this an invalid index url and
# pip fails closed, rather than silently defaulting to public PyPI.
RUN .venv/bin/pip install --no-cache-dir --index-url "${PIP_INDEX_URL}" .

FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

WORKDIR /scan
ENTRYPOINT ["skillspector"]
