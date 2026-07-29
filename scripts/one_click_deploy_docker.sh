#!/bin/bash
# One-click PRODUCTION-SHAPED deployment via docker-compose (coding spec §4.3
# Topology B2). Requires real Vault/OIDC-or-SAML/enterprise-DB-password
# configuration in .env - see .env.example. Unlike scripts/one_click_dev.sh,
# this path has NO dev-only shortcuts or fallback credentials of any kind.
#
# VERIFIED 2026-07-29 on the dev VM (10.211.55.10): run end to end, a real
# skill package submitted through the running stack, and the sandbox engines
# confirmed to have reported via `scan_engine_health`. See docker-compose.yml's
# own header for what this brings up and how it differs from Topology A.
#
# BUILDS FROM SOURCE, including all five engines out of `vendor/`. That needs
# base images, a Go module proxy, an apt archive and a Python index at BUILD
# time - the same list docs/DEPLOYMENT_GUIDE.md §0 gives for a clone. It is not
# the offline bundle and does not have its properties.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! command -v docker >/dev/null; then
  echo "ERROR: docker is required (https://docs.docker.com/engine/install/)" >&2
  exit 1
fi

# Resolve the compose CLI ONCE, up front. The previous form
# (`docker compose "$@" 2>/dev/null || docker-compose "$@"`) discarded the real
# command's stderr and fell through to the other CLI on ANY non-zero exit - so
# a genuine build failure was reported as "docker-compose: command not found",
# naming the wrong problem entirely and hiding the compiler error that caused
# it.
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null; then
  COMPOSE=(docker-compose)
else
  echo "ERROR: neither 'docker compose' (v2 plugin) nor 'docker-compose' (v1) is available" >&2
  echo "       install the compose plugin: https://docs.docker.com/compose/install/" >&2
  exit 1
fi
compose() { "${COMPOSE[@]}" "$@"; }

if [ ! -f .env ]; then
  echo "ERROR: .env not found - copy .env.example to .env and fill in real values first" >&2
  echo "       (see docs/DEPLOYMENT_GUIDE.md for what each variable needs to be)" >&2
  exit 1
fi

echo "==> Validating docker-compose.yml + .env..."
compose config >/dev/null

# The engine-runner build compiles yara from vendor/yara with autotools and
# builds osv-scanner from vendor/osv-scanner with Go - several minutes on a
# cold cache, and it refuses to produce an image whose engine versions disagree
# with vendor/engines.lock.yaml.
echo "==> Building images (monolith, migrate, blobstore-init, engine-runner, web)..."
compose build

echo "==> Starting MySQL + Redis, waiting for healthy..."
compose up -d mysql redis

echo "==> Running migrations + GRANT manifest (one-shot)..."
compose up migrate

echo "==> Preparing the shared blobstore volume (one-shot)..."
compose up blobstore-init

echo "==> Starting monolith + engine-runner + web..."
compose up -d monolith engine-runner web

# ---------------------------------------------------------------------------
# The blobstore share check, actually asked rather than assumed.
#
# If the monolith and the engine-runner are not looking at the same store,
# NOTHING ERRORS - both containers stay up, both /healthz are 200, every log is
# clean, and every scan sits in RUNNING forever. Each side writes a probe file
# naming itself and looks for the other's; the engine-runner's /readyz reports
# the answer, and its compose healthcheck asks. Its `start_period` is 90s
# because /readyz answers 200 for the whole 60s grace window regardless - so
# this wait is deliberately longer than it looks necessary. A shorter one would
# be measuring the grace period, not the sharing.
# ---------------------------------------------------------------------------
echo "==> Verifying monolith <-> engine-runner blobstore sharing (up to 3 min)..."
deadline=$((SECONDS + 180))
share_ok=false
while [ "$SECONDS" -lt "$deadline" ]; do
  cid="$(compose ps -q engine-runner || true)"
  if [ -n "$cid" ]; then
    status="$(docker inspect --format '{{.State.Health.Status}}' "$cid" 2>/dev/null || echo unknown)"
    if [ "$status" = "healthy" ]; then
      share_ok=true
      break
    fi
    if [ "$status" = "unhealthy" ]; then
      break
    fi
  fi
  sleep 5
done

if [ "$share_ok" != true ]; then
  echo "" >&2
  echo "ERROR: the engine-runner never reported ready - the monolith and the" >&2
  echo "       engine-runner are probably NOT sharing one blob store. Scans" >&2
  echo "       would sit in RUNNING forever with every container healthy." >&2
  echo "" >&2
  echo "  docker compose logs engine-runner | grep -i 'blobstore not shared'" >&2
  echo "  docker compose exec engine-runner ls -la /app/var/blobstore/_probe" >&2
  echo "" >&2
  echo "       Expect one file per role there (monolith-* and engine-runner-*)." >&2
  echo "       Only one means the two are on different volumes." >&2
  exit 1
fi
echo "    OK - the engine-runner can see the monolith's probe file."

echo ""
echo "================================================================"
echo "skillscan is up."
echo "  Web console: http://localhost/"
echo "  API health:  http://localhost:8000/healthz"
echo ""
echo "Engines: the five sandbox engines (yara, bandit, osv-scanner,"
echo "skillspector, aig-mcp-scan) run in the engine-runner container,"
echo "alongside the monolith's own in-process floor engines. aig-mcp-scan"
echo "is only constructed when SKILLSCAN_VLLM_BASE_URL names an internal"
echo "model endpoint - see .env.example."
echo ""
echo "No login path works until you've configured Vault + OIDC/SAML in"
echo ".env (or explicitly enabled break-glass) - see docs/DEPLOYMENT_GUIDE.md."
echo "================================================================"
echo ""
echo "Which engines actually reported on a scan (per scan, per engine):"
echo "  GET /v1/admin/engines/health   - report_state / engine_status /"
echo "                                   analyze_duration_ms per engine."
echo "  An engine that never reported and one that returned ERROR are"
echo "  different states and that table distinguishes them."
echo ""
echo "Follow logs:   docker compose logs -f monolith engine-runner web"
echo "Stop:          docker compose down"
