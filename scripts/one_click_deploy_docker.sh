#!/bin/bash
# One-click PRODUCTION-SHAPED deployment via docker-compose (coding spec §4.3
# Topology B2). Requires real Vault/OIDC-or-SAML/enterprise-DB-password
# configuration in .env - see .env.example. Unlike scripts/one_click_dev.sh,
# this path has NO dev-only shortcuts or fallback credentials of any kind.
#
# NOT VERIFIED: no Docker daemon is available in this development environment
# - see docker-compose.yml's own header for the full honest-verification-
# depth note (same posture as every other Dockerfile in this repo).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! command -v docker >/dev/null; then
  echo "ERROR: docker is required (https://docs.docker.com/engine/install/)" >&2
  exit 1
fi
compose() { docker compose "$@" 2>/dev/null || docker-compose "$@"; }

if [ ! -f .env ]; then
  echo "ERROR: .env not found - copy .env.example to .env and fill in real values first" >&2
  echo "       (see docs/DEPLOYMENT_GUIDE.md for what each variable needs to be)" >&2
  exit 1
fi

echo "==> Validating docker-compose.yml + .env..."
compose config >/dev/null

echo "==> Building images (monolith, migrate, web)..."
compose build

echo "==> Starting MySQL + Redis, waiting for healthy..."
compose up -d mysql redis

echo "==> Running migrations + GRANT manifest (one-shot)..."
compose up migrate

echo "==> Starting monolith + web..."
compose up -d monolith web

echo ""
echo "================================================================"
echo "skillscan is starting. Once monolith reports healthy:"
echo "  Web console: http://localhost/"
echo "  API health:  http://localhost:8000/healthz"
echo ""
echo "No login path works until you've configured Vault + OIDC/SAML in"
echo ".env (or explicitly enabled break-glass) - see docs/DEPLOYMENT_GUIDE.md."
echo "================================================================"
echo ""
echo "Follow logs:   docker compose logs -f monolith web"
echo "Stop:          docker compose down"
