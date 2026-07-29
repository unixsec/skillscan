# core-monolith build image (coding spec §3/§7.2). Referenced by
# .ci/pipeline.yml's image-sign job, deploy/helm/skillscan's own Deployment
# template, and (M-E task 3) migration-job.yaml - the same image doubles as
# the migration Job's container, so it must carry alembic.ini, db/
# (migrations + setup_grants.py) and a `mysql` client binary too, not just
# the installed venv/policies.
#
# SECURITY: the monolith holds every module's DB/Vault/IdP credentials at
# runtime (injected via env, never baked into this image) - this build stage
# itself needs no network access beyond an internal PyPI mirror (PIP_INDEX_URL
# via uv's own env var support), same air-gapped posture as
# deploy/engines/*/Dockerfile (M5).
#
# VERIFIED 2026-07-28: built + run for real on the dev VM (M-E task 3,
# migration-job.yaml) after two real bugs (documented at their fix sites
# below) surfaced this way - this Dockerfile was never actually built before
# that, only inspected, same "NOT VERIFIED" posture M5's
# deploy/engines/*/Dockerfile still carries.
FROM python:3.12-slim-bookworm AS builder

ARG PIP_INDEX_URL

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# uv's dedicated multi-arch binary image (scratch, exposes /uv+/uvx at root) -
# NOT the -python3.12-bookworm-slim variant, whose uv lives on PATH under
# /usr/local/bin, so `COPY /uv` from it fails (found on first real image build).
COPY --from=ghcr.io/astral-sh/uv:0.5 /uv /uvx /usr/local/bin/

# BUG (found running deploy/helm/skillscan/templates/migration-job.yaml
# against the real dev VM, not by inspection): this WORKDIR used to be
# /build, one path segment different from the final stage's /app. `uv sync`
# bakes the venv's OWN absolute path into every console-script wrapper's
# shebang (e.g. .venv/bin/alembic's first line becomes literally
# `#!/build/.venv/bin/python`) - copying that venv to a different absolute
# path (`COPY --from=builder /build/.venv /app/.venv` below) does not rewrite
# those shebangs, so every wrapper script, including this image's own
# `uvicorn` ENTRYPOINT, exec'd against a python interpreter path
# (/build/.venv/bin/python) that does not exist in the final image at all -
# "exec: no such file or directory" at container start. Building the venv at
# /app directly (matching the final image's real location) means the
# shebangs are already correct with no copy-time relocation. This was
# invisible before because no Docker daemon had ever built+run this image
# (see this Dockerfile's own former "NOT VERIFIED" header) - `python3 -m X`
# invocations were never affected (they resolve the interpreter via PATH,
# not a hardcoded shebang), only bare wrapper-script commands were broken.
WORKDIR /app
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

# BUG (found running deploy/helm/skillscan/templates/migration-job.yaml
# against the real dev VM, not by inspection): this stage used to install
# only ca-certificates and copy .venv + policies/ - db/migrations,
# alembic.ini and db/setup_grants.py were never in the final image at all
# (only in the builder's /build, which this stage never copies from), and
# no `mysql` client existed to run the Job's own post-migration verification
# query. Every prior "alembic upgrade head" (docker-compose.yml's `migrate`
# service, this file's own header comment) had only ever run via `uv run`
# from a full checkout on a dev machine/VM, never from inside this image -
# so the gap was invisible until the Job actually tried to run in-container.
# default-mysql-client is the Debian bookworm metapackage (resolves to
# mariadb-client, matching skillscan-mysql's own MySQL 8 server).
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates default-mysql-client \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 10001 skillscan

COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/policies /app/policies
COPY db/ /app/db/
COPY alembic.ini /app/alembic.ini
# The engine pin manifest, read by modules/reporting/service.py's
# build_engine_coverage. Not vendored source - vendor/engines.lock.yaml is a
# tracked repo file listing which OSS engines are pinned to which commit, and
# shipping it is packaging, not a VENDOR.md change. Without it the dashboard's
# engine panel is permanently empty: that reader is deliberately fail-soft on
# OSError (an informational panel must not 500 the whole dashboard), so the
# only visible symptom is total_engines: 0, rows: [] - measured against the
# deployed monolith before this line existed. The chart points
# SKILLSCAN_ENGINES_LOCK_PATH here, because the code's default resolves
# relative to the source tree and lands in /app/.venv/lib/python3.12/vendor.
COPY vendor/engines.lock.yaml /app/vendor/engines.lock.yaml
ENV PATH="/app/.venv/bin:$PATH"

USER skillscan
WORKDIR /app
EXPOSE 8000
ENTRYPOINT ["uvicorn", "monolith.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
