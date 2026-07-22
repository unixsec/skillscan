#!/bin/bash
# One-click LOCAL dev/demo deployment (not the production path - see
# scripts/one_click_deploy_docker.sh + docker-compose.yml for the
# containerized, production-shaped target). Brings up local MySQL 8/Redis
# (Homebrew services, macOS), applies migrations + per-module GRANTs, builds
# the frontend, and starts the backend via scripts/dev/run_local.py (a
# clearly-labeled dev-only launcher - real create_app(), but with break-glass
# forced on using a fixed dev credential instead of a real Vault server).
#
# Idempotent: safe to re-run - CREATE DATABASE IF NOT EXISTS, `alembic upgrade
# head`, and setup_grants.py's CREATE USER IF NOT EXISTS are all no-ops on an
# already-provisioned environment.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "==> [1/7] Checking prerequisites..."
command -v uv >/dev/null || { echo "ERROR: uv is required (https://docs.astral.sh/uv/)" >&2; exit 1; }
command -v npm >/dev/null || { echo "ERROR: npm/Node.js is required" >&2; exit 1; }
command -v mysql >/dev/null || { echo "ERROR: mysql client is required (brew install mysql@8.0)" >&2; exit 1; }
command -v redis-cli >/dev/null || { echo "ERROR: redis-cli is required (brew install redis)" >&2; exit 1; }

echo "==> [2/7] Starting local MySQL 8 + Redis (Homebrew services)..."
if command -v brew >/dev/null; then
  brew services start mysql@8.0 >/dev/null 2>&1 || true
  brew services start redis >/dev/null 2>&1 || true
else
  echo "    (no Homebrew found - assuming MySQL/Redis are already running/managed another way)"
fi

echo "    Waiting for MySQL to accept connections..."
for _ in $(seq 1 30); do
  mysql -u root -e "SELECT 1;" >/dev/null 2>&1 && break
  sleep 1
done
mysql -u root -e "SELECT 1;" >/dev/null 2>&1 || {
  echo "ERROR: MySQL root@localhost still not reachable after 30s - check it's running and passwordless-root works, or set up access manually per docs/BUILD_GUIDE.md" >&2
  exit 1
}
echo "    Waiting for Redis to accept connections..."
for _ in $(seq 1 30); do
  redis-cli -h 127.0.0.1 ping >/dev/null 2>&1 && break
  sleep 1
done
redis-cli -h 127.0.0.1 ping >/dev/null 2>&1 || {
  echo "ERROR: Redis still not reachable after 30s" >&2
  exit 1
}

echo "==> [3/7] Installing backend dependencies (uv sync)..."
uv sync --quiet

echo "==> [4/7] Creating database + applying migrations..."
mysql -u root -e "CREATE DATABASE IF NOT EXISTS skillscan"
SKILLSCAN_MIGRATION_DB_URL="mysql+aiomysql://root@localhost/skillscan" \
  uv run alembic upgrade head

echo "==> [5/7] Applying per-module GRANT manifest..."
SKILLSCAN_ADMIN_DB_DSN="mysql://root@localhost/skillscan" \
  uv run python3 db/setup_grants.py

echo "==> [6/7] Building frontend..."
(cd web && npm install --silent && npm run build --silent)

echo "==> [7/7] Starting backend (dev launcher, real create_app() + dev-only break-glass)..."
echo ""
uv run python3 scripts/dev/run_local.py &
backend_pid=$!
trap 'echo ""; echo "Stopping..."; kill "$backend_pid" 2>/dev/null || true' EXIT

sleep 2
if ! kill -0 "$backend_pid" 2>/dev/null; then
  echo "ERROR: backend failed to start - see output above" >&2
  exit 1
fi

echo ""
echo "Backend running (PID $backend_pid) at http://127.0.0.1:8000"
echo "To serve the frontend too, in another terminal run:  cd web && npm run dev"
echo "  (proxies /v1 to the backend above - see web/vite.config.ts)"
echo ""
echo "Press Ctrl-C to stop the backend."
wait "$backend_pid"
