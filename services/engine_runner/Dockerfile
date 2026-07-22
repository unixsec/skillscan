# engine-runner build image (coding spec §10/§11.7, INV-10).
#
# SECURITY: this image ends up holding zero DB/Vault/IdP credentials at
# runtime (see deploy/helm/skillscan/templates/engine-runner-deployment.yaml's
# env list) - only SKILLSCAN_REDIS_URL and the two engine-specific endpoints
# (SKILLSCAN_VLLM_BASE_URL, SKILLSCAN_OSV_SOURCE). Mirrors
# apps/monolith/Dockerfile's build shape for consistency, not because this
# service needs anything the monolith needs beyond the shared uv/venv layout.
#
# bandit is installed here from an internal index (PIP_INDEX_URL), not from
# vendor/bandit - the vendor/ submodule tree exists for the enterprise-side
# air-gapped build path (coding spec §10A); this Dockerfile builds the
# consumer-loop *service* itself, and bandit's own CLI happens to be a normal
# PyPI-installable Python package regardless of which source built it.
# osv-scanner: built from the real vendored source (vendor/osv-scanner, pinned
# v2.4.0 per engines.lock.yaml) via a Go builder stage, adapted from
# deploy/engines/osv_scanner/Dockerfile's already-authored recipe (same base
# image digest, same `go build` invocation) rather than a separate per-engine
# image, so it lands in this single combined engine-runner image. `--offline`
# mode additionally needs a local vulnerability database
# (OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY, per vendor/osv-scanner/docs/
# offline-mode.md) - a separate, genuinely external data fetch (Google's own
# GCS bucket) this Dockerfile does NOT perform; without it the binary runs
# and fails closed with an honest "no local database" error rather than
# reaching api.osv.dev (INV-14 preserved either way) - provisioning that
# database is a distinct, flagged-separately decision.
#
# skillspector: built from the real vendored source (vendor/skillspector,
# pinned commit dde36f2 - no upstream release tag) via `uv pip install` of
# the local source tree, same "install in the final stage" fix as bandit
# above (avoids the cross-build-stage shebang bug).
#
# aig-mcp-scan: only `vendor/aig/mcp-scan/` is copied in (NOT the whole
# 650k-line vendor/aig tree - the other subsystems there have no static/
# offline adapter, see engines.lock.yaml's aig entry), into its OWN isolated
# venv (`/app/.venv-aig`), never `uv pip install`ed into the shared
# `/app/.venv` alongside skillscan's own code - confirmed real conflict, not
# a hypothetical one: mcp-scan/requirements.txt pins pydantic==2.12.4, this
# project's own pyproject.toml pins pydantic==2.10.*, and both bandit and
# skillspector land in that same shared venv already. Isolating avoids
# silently upgrading pydantic under every other adapter and the service's
# own code to satisfy one LLM-only, currently-ungated-by-default engine.
#
# NOT VERIFIED beyond real builds+runs on the dev VM (10.211.55.10,
# 2026-07-08/09) - no gVisor RuntimeClass available there, same posture as
# every other Dockerfile in this repo.
FROM golang:1.26.4-alpine3.23@sha256:f23e8b227fb4493eabe03bede4d5a32d04092da71962f1fb79b5f7d1e6c2a17f AS osv-builder

ARG GOPROXY

WORKDIR /src
COPY vendor/osv-scanner/ ./
ENV GOPROXY=${GOPROXY}
RUN go mod download
RUN go build -o osv-scanner ./cmd/osv-scanner/

FROM python:3.12-slim-bookworm AS builder

ARG PIP_INDEX_URL

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.5 /uv /uvx /usr/local/bin/

WORKDIR /build
COPY pyproject.toml uv.lock ./
COPY libs/ libs/
COPY apps/ apps/
COPY services/ services/
COPY policies/ policies/
RUN UV_INDEX_URL="${PIP_INDEX_URL}" uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim-bookworm

ARG PIP_INDEX_URL

# yara: installed from the Debian bookworm archive (4.2.3-4), NOT built from
# vendor/yara (v4.5.7 pinned in engines.lock.yaml) - vendor/yara's actual
# submodule content isn't present on this dev VM (only engines.lock.yaml is
# - the submodules were never checked out here), and compiling from source
# is real, separate follow-up work. Getting a genuinely running yara CLI end
# to end now, even at a slightly older version, beats staying unwired -
# flagging the version gap explicitly rather than pretending 4.2.3 is 4.5.7.
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates yara \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 10002 engine-runner

COPY --from=ghcr.io/astral-sh/uv:0.5 /uv /uvx /usr/local/bin/
COPY --from=builder /build/.venv /app/.venv
COPY --from=osv-builder /src/osv-scanner /usr/local/bin/osv-scanner
COPY policies/yara/ /app/policies/yara/
COPY vendor/skillspector/ /tmp/skillspector-src/
ENV PATH="/app/.venv/bin:$PATH"
# SECURITY/CORRECTNESS: installed HERE, in the final stage, not the builder -
# `uv pip install`'s generated console-script shebangs bake in an ABSOLUTE
# interpreter path at install time (confirmed live: installing in the
# builder stage produced `#!/build/.venv/bin/python`, which silently doesn't
# exist once `.venv` is copied to `/app/.venv` in the final stage - every
# invocation failed with a misleading "No such file or directory: 'bandit'",
# indistinguishable from a missing binary, even though the file itself was
# present and executable). Installing after the venv is already at its real
# runtime path avoids the mismatch entirely, at the cost of a few more MB
# for `uv`/`uvx` themselves in the final image (acceptable for this dev
# build; a leaner build could `rm` them after this step).
RUN UV_INDEX_URL="${PIP_INDEX_URL}" uv pip install --python /app/.venv/bin/python bandit==1.9.4
RUN UV_INDEX_URL="${PIP_INDEX_URL}" uv pip install --python /app/.venv/bin/python /tmp/skillspector-src \
    && rm -rf /tmp/skillspector-src

# aig-mcp-scan: isolated venv, see the header comment above for why this
# can't share /app/.venv. Only mcp-scan/ is copied - not the rest of
# vendor/aig, which has no static adapter (engines.lock.yaml's aig entry).
COPY vendor/aig/mcp-scan/ /app/vendor-aig-mcp-scan/
RUN uv venv /app/.venv-aig --python python3.12 \
    && UV_INDEX_URL="${PIP_INDEX_URL}" uv pip install --python /app/.venv-aig/bin/python \
        -r /app/vendor-aig-mcp-scan/requirements.txt

USER engine-runner
WORKDIR /app
ENTRYPOINT ["python", "-m", "engine_runner.main"]
