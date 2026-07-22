# core-monolith build image (coding spec §3/§7.2). Referenced by
# .ci/pipeline.yml's image-sign job and deploy/helm/skillscan's own
# Deployment template.
#
# SECURITY: the monolith holds every module's DB/Vault/IdP credentials at
# runtime (injected via env, never baked into this image) - this build stage
# itself needs no network access beyond an internal PyPI mirror (PIP_INDEX_URL
# via uv's own env var support), same air-gapped posture as
# deploy/engines/*/Dockerfile (M5).
#
# NOT VERIFIED: no Docker daemon is available in this development environment
# - this Dockerfile has not been built here, same posture as M5's
# deploy/engines/*/Dockerfile.
FROM python:3.12-slim-bookworm AS builder

ARG PIP_INDEX_URL

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# uv's dedicated multi-arch binary image (scratch, exposes /uv+/uvx at root) -
# NOT the -python3.12-bookworm-slim variant, whose uv lives on PATH under
# /usr/local/bin, so `COPY /uv` from it fails (found on first real image build).
COPY --from=ghcr.io/astral-sh/uv:0.5 /uv /uvx /usr/local/bin/

WORKDIR /build
COPY pyproject.toml uv.lock ./
COPY libs/ libs/
COPY apps/ apps/
COPY services/ services/
COPY scripts/ scripts/
COPY policies/ policies/
# SECURITY: an empty/unset PIP_INDEX_URL makes uv's resolution fail closed,
# rather than silently falling back to the public PyPI (same rationale as
# deploy/engines/bandit/Dockerfile's own PIP_INDEX_URL handling).
RUN UV_INDEX_URL="${PIP_INDEX_URL}" uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 10001 skillscan

COPY --from=builder /build/.venv /app/.venv
COPY --from=builder /build/policies /app/policies
ENV PATH="/app/.venv/bin:$PATH"

USER skillscan
WORKDIR /app
EXPOSE 8000
ENTRYPOINT ["uvicorn", "monolith.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
