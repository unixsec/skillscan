#!/bin/bash
# One-click PRODUCTION-SHAPED deployment via docker-compose (coding spec §4.3
# Topology B2). Requires real Vault/OIDC-or-SAML/enterprise-DB-password
# configuration in .env - see .env.example. Unlike scripts/one_click_dev.sh,
# this path has NO dev-only shortcuts or fallback credentials of any kind.
#
# VERIFIED 2026-07-29 on the dev VM (10.211.55.10): run end to end from a
# pruned layer cache, run twice more against the live stack to prove the
# re-run path, every preflight check below individually made to fail on
# purpose, and the stack torn down afterwards. See docker-compose.yml's own
# header for what this brings up, how it differs from Topology A, and what an
# earlier version of that header claimed without having run it.
#
# BUILDS FROM SOURCE, including all five engines out of `vendor/`. That needs
# base images, a Go module proxy, an apt archive, a Python index and an npm
# registry at BUILD time - docs/DEPLOYMENT_GUIDE.md §0 lists every one of them
# by name and digest, and §0.5 gives the host requirements this script's
# preflight enforces. It is not the offline bundle and does not have its
# properties.
#
# RE-RUNNING IS SAFE, and deliberately so - a half-finished deploy is the
# normal case, not the exception:
#   * `compose build` reuses the layer cache (see §0.6 for the warm number).
#   * `alembic upgrade head` is a no-op at head; `db/setup_grants.py` uses
#     CREATE USER IF NOT EXISTS *followed by* ALTER USER ... IDENTIFIED BY, so
#     a password rotated in .env between two runs really is applied rather
#     than silently kept at the old value.
#   * `blobstore-init` re-runs mkdir/chgrp/chmod on an already-correct volume.
#   * `compose up -d` recreates a service only when its config changed.
# The ONE thing a re-run does not do is reset data: the MySQL/Redis/blobstore
# named volumes survive, and migrations only ever move forward. To start from
# nothing, `docker compose down -v` first (that destroys the database).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# ---------------------------------------------------------------------------
# Preflight thresholds. MEASURED on the dev VM 2026-07-29, not guessed - see
# docs/DEPLOYMENT_GUIDE.md §0.5/§0.6 for the measurements these come from.
# ---------------------------------------------------------------------------
# MEASURED on the dev VM: a cold build (pruned layer cache, base images
# already pulled) grows the docker data-root by 6.1 GiB; the base images add
# ~0.5 GiB more on a first-time host, and the running stack's volumes another
# ~0.4 GiB with an empty database. ~7 GiB for a genuine first run. 15 GB is
# that plus room for one rebuild's worth of cache on top, without a mid-build
# ENOSPC - which is the failure this check exists to prevent.
readonly REQUIRED_FREE_GB=15
# The engine-runner build runs `make -j$(nproc)` over yara and a Go build;
# node's `npm run build` alone peaks near 1 GB. Measured OK at 7.7 GB on 2
# cores; 4 is the floor below which the npm build is the first thing to die.
readonly MIN_DAEMON_MEM_GB=4
# Compose v1 cannot read this file at all: it has no `version:` key, so v1
# parses the top level as version-1 service names and reports something about
# an unsupported `services` key rather than about being the wrong compose.
readonly MIN_COMPOSE_VERSION=2.0
# `depends_on: condition:` + BuildKit as the default builder.
readonly MIN_DOCKER_VERSION=20.10

PHASE="startup"
PHASE_START=0
RUN_START=$SECONDS

phase() {
  PHASE="$1"
  PHASE_START=$SECONDS
  printf '\n==> [%s] %s\n' "$(date +%H:%M:%S)" "$1"
}

phase_done() {
  printf '    ...done in %ds\n' "$((SECONDS - PHASE_START))"
}

fail() {
  echo "" >&2
  echo "ERROR: $*" >&2
  exit 1
}

check_ok() {
  printf '    OK   %s\n' "$*"
}

# ---------------------------------------------------------------------------
# What is left behind when this script dies, and how to get back to clean.
#
# The build runs to completion BEFORE anything is started, so a build failure -
# the long, likely one, at the yara/Go/npm stages - leaves no new container
# running at all, only build cache. A failure after that leaves a partial
# stack. Rather than assume which happened, this reports the real state.
#
# It deliberately does NOT tear down for you: a container that failed its
# healthcheck still holds the logs that say why, and `down` would delete them
# along with the evidence.
# ---------------------------------------------------------------------------
on_exit() {
  local rc=$?
  if [ "$rc" -eq 0 ]; then
    return 0
  fi
  echo "" >&2
  echo "----------------------------------------------------------------" >&2
  echo "FAILED during: ${PHASE}   (exit ${rc}, ${SECONDS}s elapsed)" >&2
  # A preflight or build failure started nothing, so printing a teardown
  # recipe there would bury the one line that matters under advice about a
  # stack that does not exist. Only say it when there is something to say.
  if [ "${STACK_TOUCHED:-false}" != true ]; then
    echo "Nothing was started, so there is nothing to clean up - fix the above" >&2
    echo "and re-run. (Build failures land here too: every image is built" >&2
    echo "before any container starts.)" >&2
    echo "----------------------------------------------------------------" >&2
    return "$rc"
  fi
  echo "" >&2
  echo "Containers this project currently has:" >&2
  compose ps -a 2>&1 | sed 's/^/  /' >&2 || true
  echo "" >&2
  echo "Diagnose:" >&2
  echo "  docker compose logs --tail=100 <service>" >&2
  echo "" >&2
  echo "Back to clean:" >&2
  echo "  docker compose down            # stop+remove containers, KEEP the" >&2
  echo "                                 # MySQL/Redis/blobstore volumes" >&2
  echo "  docker compose down -v         # ...and DESTROY that data too" >&2
  echo "" >&2
  echo "Re-running this script is safe and resumes from wherever it got to" >&2
  echo "(see the header). Nothing here needs a teardown first unless you" >&2
  echo "want an empty database." >&2
  echo "----------------------------------------------------------------" >&2
  return "$rc"
}
trap on_exit EXIT

# ---------------------------------------------------------------------------
# PREFLIGHT. Everything here runs before `compose build`, on purpose: the build
# takes minutes (§0.6), and discovering that port 80 was already taken, or that
# the disk had 3 GB left, at the END of a yara compile is a bad trade for
# checks that cost milliseconds. Every check below is one that has been made to
# fail on purpose - a preflight step that cannot fail is noise.
# ---------------------------------------------------------------------------
phase "Preflight (host, docker, .env, ports, disk)"

if ! command -v docker >/dev/null; then
  fail "docker is required (https://docs.docker.com/engine/install/)"
fi
check_ok "docker CLI present"

# Resolve the compose CLI ONCE, up front. The previous form
# (`docker compose "$@" 2>/dev/null || docker-compose "$@"`) discarded the real
# command's stderr and fell through to the other CLI on ANY non-zero exit - so
# a genuine build failure was reported as "docker-compose: command not found",
# naming the wrong problem entirely and hiding the compiler error that caused
# it.
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
  compose_version="$(docker compose version --short 2>/dev/null || echo 0)"
elif command -v docker-compose >/dev/null; then
  COMPOSE=(docker-compose)
  compose_version="$(docker-compose version --short 2>/dev/null || echo 0)"
else
  echo "ERROR: neither 'docker compose' (v2 plugin) nor 'docker-compose' (v1) is available" >&2
  echo "       install the compose plugin: https://docs.docker.com/compose/install/" >&2
  exit 1
fi
compose() { "${COMPOSE[@]}" "$@"; }

# Docker's own error for "daemon not running" and for "your user is not in the
# docker group" are both a wall of text ending in a socket path, and both would
# otherwise surface from `compose config` below as if the compose file were at
# fault. Ask directly instead.
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: the docker CLI is installed but the daemon is not reachable." >&2
  echo "       Start it (systemctl start docker / open Docker Desktop), or if" >&2
  echo "       this says 'permission denied', add yourself to the docker group:" >&2
  echo "         sudo usermod -aG docker \"\$USER\"   # then log out and back in" >&2
  echo "" >&2
  docker info 2>&1 | tail -5 | sed 's/^/       /' >&2
  exit 1
fi
check_ok "docker daemon reachable"

# major.minor comparison only - these are floors, not exact pins, and every
# Docker/compose version string in the wild has a third component or a suffix
# (29.1.3-0ubuntu3, v2.29.1, 1.29.2) that a string compare gets wrong.
version_at_least() {
  local have="${1#v}" want="${2#v}"
  local have_major have_minor want_major want_minor
  have_major="${have%%.*}"
  want_major="${want%%.*}"
  case "$have" in *.*) have_minor="${have#*.}"; have_minor="${have_minor%%.*}" ;; *) have_minor=0 ;; esac
  case "$want" in *.*) want_minor="${want#*.}"; want_minor="${want_minor%%.*}" ;; *) want_minor=0 ;; esac
  have_major="${have_major//[!0-9]/}"
  have_minor="${have_minor//[!0-9]/}"
  want_major="${want_major//[!0-9]/}"
  want_minor="${want_minor//[!0-9]/}"
  [ -n "$have_major" ] || return 1
  [ -n "$have_minor" ] || have_minor=0
  if [ "$have_major" -gt "$want_major" ]; then return 0; fi
  if [ "$have_major" -lt "$want_major" ]; then return 1; fi
  [ "$have_minor" -ge "$want_minor" ]
}

docker_version="$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo 0)"
if ! version_at_least "$docker_version" "$MIN_DOCKER_VERSION"; then
  fail "Docker Engine ${MIN_DOCKER_VERSION}+ required, found '${docker_version}'.
       docker-compose.yml uses depends_on conditions and BuildKit-era build
       args that older daemons ignore rather than reject - the stack would
       come up in the wrong order instead of telling you why."
fi
if ! version_at_least "$compose_version" "$MIN_COMPOSE_VERSION"; then
  fail "docker compose ${MIN_COMPOSE_VERSION}+ required, found '${compose_version}'.
       Compose v1 cannot read docker-compose.yml at all (no 'version:' key, so
       it parses the top level as v1 service names) and does not implement
       'depends_on: condition: service_completed_successfully', which is what
       keeps the monolith from starting against an unmigrated schema.
       Install the v2 plugin: https://docs.docker.com/compose/install/"
fi
check_ok "docker ${docker_version} + compose ${compose_version}"

# Disk. The build writes 6.1 GiB before a single container starts (§0.6), and
# BuildKit's failure mode when it runs out mid-layer is an ENOSPC from
# whichever tool happened to be writing - a linker error, an apt error, a
# truncated npm cache - never "the disk is full".
docker_root="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)"
# On Docker Desktop (macOS/Windows) DockerRootDir names a path inside the
# daemon's own VM that does not exist on this host; the host filesystem backing
# it is the one that actually runs out, so fall back to the build context.
if [ -z "$docker_root" ] || [ ! -d "$docker_root" ]; then
  docker_root="."
fi
avail_kb="$(df -Pk "$docker_root" | awk 'NR==2 {print $4}')"
avail_gb=$((avail_kb / 1024 / 1024))
if [ "$avail_gb" -lt "$REQUIRED_FREE_GB" ]; then
  fail "only ${avail_gb} GB free on ${docker_root}, need >= ${REQUIRED_FREE_GB} GB.
       A cold build writes 6.1 GiB of images plus layer cache before anything
       starts (measured), and the running stack adds volumes on top.
       Reclaim with: docker system prune -a --volumes"
fi
check_ok "disk: ${avail_gb} GB free on ${docker_root} (need ${REQUIRED_FREE_GB})"

# RAM, as the DAEMON sees it - on Docker Desktop that is the VM's allocation,
# which is the number that actually constrains the build, and it is routinely
# left at a default far below the host's real memory.
mem_bytes="$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)"
mem_gb=$((mem_bytes / 1024 / 1024 / 1024))
if [ "$mem_gb" -lt "$MIN_DAEMON_MEM_GB" ]; then
  fail "the docker daemon reports ${mem_gb} GB of memory, need >= ${MIN_DAEMON_MEM_GB} GB.
       yara's 'make -j\$(nproc)' and the web image's 'npm run build' are the
       two that die here, and node's OOM kill surfaces as a bare
       'Killed'/exit 137 with no mention of memory.
       On Docker Desktop: Settings > Resources > Memory."
fi
check_ok "memory: ${mem_gb} GB available to the docker daemon (need ${MIN_DAEMON_MEM_GB})"

# The vendored engine sources. `git clone` brings them (they stopped being
# submodules on 2026-07-29), but a source tarball, an export, or a `git
# archive` built from a partial checkout does not - and the COPY that discovers
# it is minutes into the engine-runner build.
missing_vendor=""
for required in \
  vendor/engines.lock.yaml \
  vendor/yara/configure.ac \
  vendor/osv-scanner/go.mod \
  vendor/bandit/setup.py \
  vendor/skillspector/pyproject.toml \
  vendor/aig/mcp-scan/requirements.txt; do
  if [ ! -s "$required" ]; then
    missing_vendor="${missing_vendor} ${required}"
  fi
done
if [ -n "$missing_vendor" ]; then
  fail "the vendored engine sources are incomplete - missing:${missing_vendor}
       The engine-runner build COPYs these; without them it fails several
       minutes in with a bare 'file not found' from BuildKit. Get the tree
       from git (they are committed, not submodules) rather than from an
       archive."
fi
check_ok "vendored engine sources present (5 engines + engines.lock.yaml)"

if [ ! -f .env ]; then
  echo "ERROR: .env not found - copy .env.example to .env and fill in real values first" >&2
  echo "       cp .env.example .env && chmod 600 .env" >&2
  echo "       (see docs/DEPLOYMENT_GUIDE.md for what each variable needs to be)" >&2
  exit 1
fi

# .env holds every DB password, the Vault token and the IdP client secrets. A
# plain `cp .env.example .env` under the usual umask leaves it 0644 - readable
# by every account on the host, including the ones a container escape lands in.
# GNU stat wants -c, BSD/macOS stat wants -f; try both rather than assume.
env_mode="$(stat -c '%a' .env 2>/dev/null || stat -f '%Lp' .env 2>/dev/null || true)"
if [ -z "$env_mode" ]; then
  echo "    WARN neither 'stat -c' nor 'stat -f' worked here - .env's permission" >&2
  echo "         bits were NOT checked. Confirm by hand that it is 0600." >&2
else
  case "${env_mode: -2}" in
    00) check_ok ".env present, mode 0${env_mode} (owner-only)" ;;
    *)
      fail ".env is mode 0${env_mode} - readable by users other than its owner, and
       it holds the MySQL passwords, the Vault token and the IdP client
       secrets. A plain 'cp .env.example .env' under the default umask lands
       here. Fix with:
         chmod 600 .env"
      ;;
  esac
fi

# ---------------------------------------------------------------------------
# The `$` trap. MEASURED against compose v5.3.1 on 2026-07-29, all four cases:
#
#   PW=ab$cd        -> container sees `ab`             (warns: "cd" not set)
#   PW=ab$HOME      -> container sees `ab/home/alex`   (NO warning at all)
#   PW=ab$$cd       -> container sees `ab$cd`          (correct)
#   PW=abc$ / p$1x  -> container sees `abc$` / `p$1x`  (literal; `$` before a
#                                                       digit or punctuation is
#                                                       not an interpolation)
#
# So the rule is exact: an unescaped `$` followed by `{` or by an identifier
# character is interpolated, everything else is literal. Only the FIRST two
# lines are the defect, and the second one is completely silent - if the name
# after the `$` happens to be set in the deploying shell's environment (HOME,
# USER, PATH, anything), compose substitutes it without a word.
#
# Why this is a security defect and not a formatting nit: the truncation is
# CONSISTENT. `migrate` creates the MySQL account with the short password and
# the monolith connects with the same short password, so the deployment comes
# up green and stays green. Nothing is broken until someone tries the password
# they actually chose - or an auditor asks how many characters it has.
#
# Fail closed rather than warn: compose's own warning (when there is one) is
# emitted once per service into the middle of build output, which is precisely
# where a warning goes to die.
# ---------------------------------------------------------------------------
dollar_offenders=""
while IFS= read -r env_line || [ -n "$env_line" ]; do
  # only KEY=VALUE lines; skip blanks, comments and anything indented
  case "$env_line" in
    [A-Za-z_]*=*) ;;
    *) continue ;;
  esac
  env_key="${env_line%%=*}"
  env_value="${env_line#*=}"
  # remove correctly-escaped `$$` pairs, then remove `${` - what is left is
  # only the forms compose actually interpolates.
  env_probe="${env_value//\$\$/}"
  case "$env_probe" in
    *\$[A-Za-z_]* | *\$\{*)
      dollar_offenders="${dollar_offenders}
         ${env_key}" ;;
  esac
done < .env

if [ -n "$dollar_offenders" ]; then
  fail "these .env values contain an unescaped \$ that docker compose will
       interpolate away BEFORE any container sees them:
${dollar_offenders}

       Write every literal \$ as \$\$ - 'ab\$cd' must be written 'ab\$\$cd'.
       This is checked rather than warned about because the result is a
       password that silently becomes a PREFIX of the one you chose, in a
       stack that then works perfectly with the short value."
fi
check_ok ".env has no unescaped \$ (would silently truncate passwords)"

# ---------------------------------------------------------------------------
# INV-14 build-time egress. The Dockerfiles enforce this themselves
# (scripts/require_build_index.sh, first RUN of every network-touching stage),
# so this check exists only to fail in a second with the .env-shaped wording
# instead of one `docker build` layer later with the --build-arg-shaped one.
# Deliberately reads the same values compose will actually interpolate.
# ---------------------------------------------------------------------------
env_get() { sed -n "s/^$1=//p" .env | tail -1; }
if [ -z "$(env_get SKILLSCAN_PIP_INDEX_URL)$(env_get SKILLSCAN_NPM_REGISTRY)$(env_get SKILLSCAN_GOPROXY)" ] \
   && [ "$(env_get SKILLSCAN_ALLOW_PUBLIC_INDEXES)" != "true" ]; then
  fail "no package index is configured, and the build will refuse to start.

       Leaving SKILLSCAN_PIP_INDEX_URL / _NPM_REGISTRY / _GOPROXY blank has
       never meant 'no network' - uv, npm and go each treat an empty value as
       unset and silently use pypi.org / registry.npmjs.org /
       proxy.golang.org. Pick one, in .env:

         SKILLSCAN_PIP_INDEX_URL=https://<mirror>/simple   (+ the other two)
           - the air-gapped path, INV-14 preserved
         SKILLSCAN_ALLOW_PUBLIC_INDEXES=true
           - public internet, on purpose (dev machine, evaluation, CI)"
fi
if [ "$(env_get SKILLSCAN_ALLOW_PUBLIC_INDEXES)" = "true" ]; then
  check_ok "build indexes: PUBLIC, declared explicitly (INV-14 waived on purpose)"
else
  check_ok "build indexes: internal mirror(s) configured"
fi

# Ports, read back out of the composed config rather than hardcoded here, so
# adding a published port to docker-compose.yml cannot leave this check behind.
compose_config="$(compose config 2>/dev/null)" || fail "docker-compose.yml + .env did not validate - run 'docker compose config' to see why"

# `port_state PORT` -> 0 occupied, 1 free, 2 could not tell
port_state() {
  local port="$1" err
  if err="$(LC_ALL=C bash -c "exec 3<>/dev/tcp/127.0.0.1/${port}" 2>&1)"; then
    return 0
  fi
  case "$err" in
    *"onnection refused"* | *"onnect: "* | *"onnection timed out"* | *"o route to host"*) return 1 ;;
    *) return 2 ;;
  esac
}

# Ports THIS project already publishes do not count as a conflict: on a re-run
# against a live stack (the supported, documented case - see the header) 80 and
# 8000 are held by our own web/monolith containers, and treating that as
# "address already in use" would refuse to redeploy the very stack it just
# deployed. Found by running this script twice, which is exactly the case it
# claims to support.
own_ports=""
for cid in $(compose ps -q 2>/dev/null || true); do
  own_ports="${own_ports} $(docker inspect --format '{{range $p, $conf := .NetworkSettings.Ports}}{{range $conf}}{{.HostPort}} {{end}}{{end}}' "$cid" 2>/dev/null || true)"
done

busy_ports=""
reused_ports=""
unprobed_ports=""
for port in $(printf '%s\n' "$compose_config" | awk '/^[[:space:]]*published:/ { gsub(/[^0-9]/, "", $2); if ($2 != "") print $2 }' | sort -u); do
  set +e
  port_state "$port"
  port_rc=$?
  set -e
  case "$port_rc" in
    0)
      case " ${own_ports} " in
        *" ${port} "*) reused_ports="${reused_ports} ${port}" ;;
        *) busy_ports="${busy_ports} ${port}" ;;
      esac
      ;;
    2) unprobed_ports="${unprobed_ports} ${port}" ;;
    *) ;;
  esac
done

if [ -n "$busy_ports" ]; then
  fail "these host ports are already in use:${busy_ports}
       docker-compose.yml publishes them, so 'compose up' would fail with
       'address already in use' - but only AFTER the build, minutes from now.
       Find the holder (ss -ltnp / lsof -nP -iTCP -sTCP:LISTEN) and stop it,
       or change the published port in docker-compose.yml."
fi
if [ -n "$unprobed_ports" ]; then
  echo "    WARN this bash could not probe ports:${unprobed_ports} (no /dev/tcp support)." >&2
  echo "         A collision there will surface as 'address already in use' after the build." >&2
elif [ -n "$reused_ports" ]; then
  check_ok "published host ports free or held by this project already (re-run:${reused_ports})"
else
  check_ok "published host ports are free"
fi
phase_done

# ---------------------------------------------------------------------------
# BUILD. Broken out service by service so there is a visible clock: a cold
# engine-runner build compiles yara with autotools and osv-scanner with Go and
# is minutes of near-silence, which reads exactly like a hang to anyone seeing
# it for the first time. Measured numbers are in §0.6.
#
# It also refuses to produce an engine-runner image whose engine versions
# disagree with vendor/engines.lock.yaml (INV-7).
# ---------------------------------------------------------------------------
echo ""
echo "Building 5 images from source. MEASURED on 2 cores: ~8 min cold (empty"
echo "layer cache), ~2 s warm. The engine-runner alone is 411 s of that - 6+"
echo "minutes of near-silence while 292 Go modules download and yara compiles,"
echo "which reads exactly like a hang the first time. Per-image numbers and"
echo "what changes them: docs/DEPLOYMENT_GUIDE.md §0.6."

build_index=0
for service in monolith migrate blobstore-init engine-runner web; do
  build_index=$((build_index + 1))
  phase "Build ${build_index}/5: ${service}"
  compose build "$service"
  phase_done
done

phase "Starting MySQL + Redis, waiting for healthy"
# From here on a failure can leave containers behind, which changes what the
# exit trap should say - see on_exit().
STACK_TOUCHED=true
compose up -d mysql redis
phase_done

# ---------------------------------------------------------------------------
# One-shot services, with their exit code actually read.
#
# `docker compose up <one-shot>` returns 0 when the container exits non-zero -
# the exit code it reports is compose's own, not the container's. So a failed
# `alembic upgrade head` used to print its traceback and be stepped straight
# over. The monolith's `depends_on: service_completed_successfully` does
# eventually catch it, but as a refusal to start several steps later, naming
# the dependency rather than the migration that broke.
# ---------------------------------------------------------------------------
run_one_shot() {
  local service="$1" cid exit_code
  compose up "$service"
  cid="$(compose ps -aq "$service" | head -1)"
  if [ -z "$cid" ]; then
    fail "the one-shot '${service}' service left no container to inspect - cannot confirm it succeeded"
  fi
  exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$cid")"
  if [ "$exit_code" != "0" ]; then
    fail "the one-shot '${service}' service exited ${exit_code}.
       Its output is above, and in full via:
         docker compose logs ${service}
       Nothing downstream of it has been started."
  fi
}

phase "Running migrations + GRANT manifest (one-shot)"
run_one_shot migrate
phase_done

phase "Preparing the shared blobstore volume (one-shot)"
run_one_shot blobstore-init
phase_done

phase "Starting monolith + engine-runner + web"
compose up -d monolith engine-runner web
phase_done

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
phase "Verifying monolith <-> engine-runner blobstore sharing (up to 3 min)"
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
  printf '    waiting... %ds\n' "$((SECONDS - PHASE_START))"
  sleep 10
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
phase_done

echo ""
echo "================================================================"
echo "skillscan is up. Total elapsed: $((SECONDS - RUN_START))s."
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
echo "Stop:          docker compose down       (keeps the data volumes)"
echo "Wipe:          docker compose down -v    (destroys the database too)"
