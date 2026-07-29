#!/bin/bash
# Push the current working tree to the dev VM, rebuild+redeploy all 3 images
# (monolith/engine-runner/web), then run the full backend test suite
# against a fresh throwaway MySQL/Redis pair on the VM.
#
# Run this FROM YOUR MAC in the skillscan repo root:
#   bash deploy_and_test_vm.sh
#
# Assumes: SSH key auth to parallels@10.211.55.10 already works (confirmed),
# VM checkout lives at /home/parallels/skillscan (per prior session records),
# k3s namespace is "skillscan", NOPASSWD sudo for
# `k3s ctr -n k8s.io images import *` is already configured on the VM.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

VM=parallels@10.211.55.10
VM_PATH=/home/parallels/skillscan

echo "=== [1/9] static gates: ruff + mypy (the same three .ci/pipeline.yml runs) ==="
# Deliberately run these HERE, on the Mac, before anything is shipped anywhere:
# they need no MySQL/Redis/k3s, so CLAUDE.md's VM-only rule (which covers
# deployment and integration testing) does not apply - and running them FIRST
# means a lint/type regression fails in seconds instead of after a multi-minute
# rsync plus three Docker builds. `set -e` aborts the whole script on any
# failure, so a red gate can never reach the VM.
uv run ruff check .
uv run ruff format --check .
uv run mypy
# Architecture boundary: no NEW cross-module ORM imports (stdlib-only, see the
# script's docstring for why ruff's banned-api cannot express this rule).
python3 scripts/check_import_boundaries.py

# Detection-catalog drift, and it MUST run here rather than on the VM: the
# authoritative 企业Skill安全评估测试维度清单.xlsx is gitignored and excluded from
# the rsync below, so this Mac is the only machine that has it - and therefore
# the only machine where it can be edited. `policies/detection_catalog.json` is
# what every other environment validates test_item_ids against, so an edit to
# the spreadsheet that never reached the manifest would leave two disagreeing
# sources of truth with nothing to notice. `--check` fails if the spreadsheet
# is missing too: silently passing on absence is exactly the defect that let
# the catalog guard sit switched off on the VM for its whole life (milestone C
# task 6).
uv run python scripts/gen_detection_catalog.py --check

echo "=== [2/9] rsync working tree to VM ($VM_PATH) ==="
# `--exclude=*.xlsx` KEPT deliberately: the detection catalog is a binary
# working document holding 62 items of security content, and it does not belong
# on the VM. Its ids now travel instead as policies/detection_catalog.json -
# generated, checked in, and drift-guarded in step 1 - which is what
# tests/test_test_item_catalog.py reads. Until that manifest existed, this one
# exclusion silently switched that guard off for every run on this VM.
# (No comment lines inside the argument list below: a `#` after a `\`-joined
# line terminates the whole rsync command.)
rsync -az --delete \
  --exclude='.git' \
  --exclude='.venv' \
  --exclude='node_modules' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='web/dist' \
  --exclude='web/node_modules' \
  --exclude='.claude' \
  --exclude='.remember' \
  --exclude='.superpowers' \
  --exclude='*.png' \
  --exclude='*.xlsx' \
  --exclude='deploy_and_test_vm.sh' \
  ./ "$VM:$VM_PATH/"

echo "=== [3/9] rebuild all 3 images on the VM ==="
ssh "$VM" bash -s <<'REMOTE_BUILD'
set -euo pipefail
cd /home/parallels/skillscan
echo "--- monolith ---"
docker build -f apps/monolith/Dockerfile -t skillscan/monolith:dev .
echo "--- engine-runner ---"
docker build -f services/engine_runner/Dockerfile -t skillscan/engine-runner:dev .
echo "--- web ---"
docker build -f web/Dockerfile -t skillscan/web:dev .
REMOTE_BUILD

echo "=== [4/9] import images into k3s containerd + rollout restart ==="
ssh "$VM" bash -s <<'REMOTE_IMPORT'
set -euo pipefail
for img in monolith engine-runner web; do
  echo "--- importing skillscan/$img:dev ---"
  docker save "skillscan/$img:dev" -o "/tmp/skillscan-$img-dev.tar"
  sudo k3s ctr -n k8s.io images import "/tmp/skillscan-$img-dev.tar"
  rm -f "/tmp/skillscan-$img-dev.tar"
done

echo "--- live Deployments in ns=skillscan ---"
kubectl get deployments -n skillscan -o name

for name in monolith engine-runner web; do
  dep=$(kubectl get deployments -n skillscan -o name | grep -i "$name" || true)
  if [ -n "$dep" ]; then
    echo "--- restarting $dep ---"
    kubectl rollout restart "$dep" -n skillscan
  else
    echo "!!! no Deployment matching '$name' found in ns=skillscan - skipped, check manually"
  fi
done

for name in monolith engine-runner web; do
  dep=$(kubectl get deployments -n skillscan -o name | grep -i "$name" || true)
  [ -n "$dep" ] && kubectl rollout status "$dep" -n skillscan --timeout=180s
done

echo "--- pods after rollout ---"
kubectl get pods -n skillscan -o wide
REMOTE_IMPORT

echo "=== [5/9] migrate the REAL k3s database (NOT the throwaway test pair) ==="
# Added 2026-07-28 after a schema change shipped without this. Step 8 migrates a
# THROWAWAY database it creates itself, so the suite went 1103-green while the
# deployed monolith logged 88 "Unknown column 'sandbox_wait_started_at'" errors
# against the real one. The test DB and the deployed DB had no consistency check
# between them at all - green tests actively hid the broken deployment.
#
# Runs the real `alembic upgrade head` (never hand-stamped DDL) through a
# port-forward, then VERIFIES the recorded revision advanced to the repo's head
# and fails the whole script if it did not. An earlier hand-rolled version of
# this step piped alembic into `tail` and swallowed the failure into a warning -
# same class of bug as `| tee` masking pytest's exit code (see step 8).
ssh "$VM" bash -s <<'REMOTE_MIGRATE'
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
cd /home/parallels/skillscan
kubectl port-forward -n skillscan svc/mysql 13306:3306 >/tmp/pf-migrate.log 2>&1 &
PF_PID=$!
trap 'kill $PF_PID 2>/dev/null || true' EXIT
for _ in $(seq 1 20); do
  mysql -uroot -h 127.0.0.1 -P 13306 -e "SELECT 1" >/dev/null 2>&1 && break
  sleep 1
done
mysql -uroot -h 127.0.0.1 -P 13306 -e "SELECT 1" >/dev/null 2>&1 || {
  echo "!!! port-forward to the k3s MySQL never came up"; cat /tmp/pf-migrate.log; exit 1; }

before=$(mysql -uroot -h 127.0.0.1 -P 13306 -N -e "SELECT version_num FROM skillscan.alembic_version;")
echo "--- k3s DB revision before: $before"
SKILLSCAN_MIGRATION_DB_URL="mysql+aiomysql://root@127.0.0.1:13306/skillscan" uv run alembic upgrade head
after=$(mysql -uroot -h 127.0.0.1 -P 13306 -N -e "SELECT version_num FROM skillscan.alembic_version;")
expected=$(uv run alembic heads | awk '{print $1}' | head -1)
echo "--- k3s DB revision after:  $after   (repo head: $expected)"
if [ "$after" != "$expected" ]; then
  echo "!!! the k3s database is NOT at the repo's head revision - the deployed code"
  echo "!!! expects a schema this database does not have. Refusing to continue."
  exit 1
fi

# Grants, same story as the migration above: step 8 runs setup_grants.py against
# the THROWAWAY database it builds for the test suite, and nothing ever ran it
# against the deployed one. A module whose least-privilege user was never created
# does not crash - engines connect lazily, so the process starts healthy and only
# that module's writes fail. `marketplace_api`'s audit write swallows its own
# errors by design (it must never fail a poll), so the symptom is an empty audit
# table on a system that looks fine.
#
# ORDERING CONSTRAINT (2026-07-29, milestone C correctness review N-1): this
# step MUST follow the migration above and must never be skipped when the
# migration ran. A migration that creates a table grants nothing, so between the
# two the deployment has a schema its module users cannot write to. Milestone C
# Task 8 is when that stopped being harmless: `scan_engine_health`'s INSERTs
# live inside the transaction that scores EVERY scan, so a migrated-but-
# ungranted database fails every decide, permanently and silently.
#
# The check below no longer asks "does the user exist" - a user can exist and
# hold none of the grants a just-migrated schema needs, which is exactly this
# failure. `--verify` (folded into setup_grants.py's normal run, and available
# standalone for an out-of-band migration) asserts every manifest grant is
# actually IN EFFECT, per user AND per host.
echo "--- applying least-privilege grants to the k3s database, then verifying they took ---"
SKILLSCAN_ADMIN_DB_DSN="mysql://root@127.0.0.1:13306/skillscan" uv run python3 db/setup_grants.py
echo "--- every manifest grant is in effect"
REMOTE_MIGRATE

echo "=== [6/9] health check ==="
ssh "$VM" bash -s <<'REMOTE_HEALTH'
set -euo pipefail
# --field-selector=status.phase=Running: right after `rollout restart`, the
# old pod can still be Terminating for a few seconds and match `grep
# monolith` too - `head -1` picked it once and died on a NotFound exec
# because it was gone by the time this ran (2026-07-23).
mono_pod=$(kubectl get pods -n skillscan --field-selector=status.phase=Running -o name | grep monolith | head -1)
echo "--- $mono_pod /healthz, /readyz ---"
kubectl exec -n skillscan "${mono_pod#pod/}" -- python3 -c "
import urllib.request
for path in ('/healthz', '/readyz'):
    try:
        r = urllib.request.urlopen('http://localhost:8000' + path, timeout=5)
        print(path, r.status)
    except Exception as e:
        print(path, 'FAILED', e)
"
REMOTE_HEALTH

echo "=== [7/9] NetworkPolicy posture of the LIVE namespace ==="
# Added 2026-07-29, after TWO config drifts in one day that nothing could see.
# `~/k8s/10-data.yaml` had lost the label mysql's and redis's policies select
# on, and the deployed `monolith-ingress` had lost its `from` selector - so
# anything in the namespace could reach the monolith on 8000, measured with an
# unlabelled probe pod that read all 16 /metrics series. A task that same
# morning had added `monolith-metrics-ingress` BECAUSE it checked that
# `monolith-ingress` only allowed web: it had read the checked-in file, not the
# cluster.
#
# Runs against the live namespace and nothing else - the throwaway environments
# the test suite builds have no NetworkPolicy to check, which is precisely why
# a green suite said nothing about either drift. See the script's own docstring
# for why this asks whether the policies DO anything rather than comparing them
# to deploy/networkpolicy/*.yaml (measured: 3 of 4 differences there are
# legitimate on this VM, and a check that cries wolf is a check nobody runs).
ssh "$VM" bash -s <<'REMOTE_NETPOL'
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
cd /home/parallels/skillscan
kubectl -n skillscan get networkpolicy -o json > /tmp/skillscan-netpol.json
kubectl -n skillscan get pods -o json > /tmp/skillscan-pods.json
python3 deploy/check_netpol_posture.py \
  --from-json /tmp/skillscan-netpol.json /tmp/skillscan-pods.json
rm -f /tmp/skillscan-netpol.json /tmp/skillscan-pods.json
REMOTE_NETPOL

echo "=== [8/9] sweep for stray dev processes that could race the test suite ==="
ssh "$VM" "ps aux | grep -E 'run_local\.py|uvicorn' | grep -v grep || echo '(none found)'"

echo "=== [9/9] fresh throwaway MySQL/Redis + full pytest suite ==="
ssh "$VM" bash -s <<'REMOTE_TEST'
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
cd /home/parallels/skillscan

echo "--- recreating throwaway test MySQL/Redis (host network) ---"
docker rm -f skillscan-test-mysql skillscan-test-redis >/dev/null 2>&1 || true
# Tear these down on ANY exit, not just the happy path: with `set -e` a failing
# pytest run used to skip the cleanup at the bottom entirely and leave both
# containers listening on the host network, where they silently became the
# "throwaway" pair the NEXT run reused - carrying over mutated schema/data.
# Same class of cross-run contamination the stray-process sweep in step 7 exists
# to catch.
trap 'docker rm -f skillscan-test-mysql skillscan-test-redis >/dev/null 2>&1 || true' EXIT
docker run -d --name skillscan-test-mysql --network host \
  -e MYSQL_ALLOW_EMPTY_PASSWORD=yes mysql:8 >/dev/null
docker run -d --name skillscan-test-redis --network host redis:7 >/dev/null

echo "--- waiting for MySQL ---"
for _ in $(seq 1 30); do
  mysql -u root -h 127.0.0.1 -e "SELECT 1;" >/dev/null 2>&1 && break
  sleep 1
done
mysql -u root -h 127.0.0.1 -e "SELECT 1;" >/dev/null 2>&1 || { echo "MySQL never came up"; exit 1; }

echo "--- waiting for Redis ---"
for _ in $(seq 1 30); do
  redis-cli -h 127.0.0.1 ping >/dev/null 2>&1 && break
  sleep 1
done
redis-cli -h 127.0.0.1 ping >/dev/null 2>&1 || { echo "Redis never came up"; exit 1; }

echo "--- schema + grants ---"
mysql -u root -h 127.0.0.1 -e "CREATE DATABASE IF NOT EXISTS skillscan"
SKILLSCAN_MIGRATION_DB_URL="mysql+aiomysql://root@localhost/skillscan" uv run alembic upgrade head
SKILLSCAN_ADMIN_DB_DSN="mysql://root@localhost/skillscan" uv run python3 db/setup_grants.py

echo "--- full pytest suite ---"
# `tests/` (the dependency-light kernel suite) is listed EXPLICITLY because
# pyproject's testpaths is only `apps/monolith/tests`, so a bare pytest never
# collected it here. That omission is half of why the detection-catalog guard
# had never once executed on this VM (the other half was the rsync excluding
# the .xlsx it used to read). Adding the path is what makes step 1's manifest
# actually get checked against the live engine sources in the deployed
# checkout - milestone C task 6.
#
# Capture rather than pipe: `... | tail` reports tail's exit code, not pytest's,
# which historically made a failing suite look successful. Capturing also lets
# the known-failure filter below inspect the actual FAILED lines.
set +e
pytest_out=$(uv run pytest apps/monolith/tests/ tests/ -q 2>&1)
pytest_rc=$?
set -e
echo "$pytest_out" | tail -100

# test_vendor_engines.py's pin checks compare the committed git tree of each
# vendor/<engine>/ against the `tree:` recorded in engines.lock.yaml, via
# `git -C <repo> rev-parse HEAD:vendor/<x>`. This VM's checkout arrives by rsync
# with `--exclude=.git`, so those tests can NEVER pass here - they are an
# environment fact, not a regression. (Before 2026-07-29 the same checks read
# each submodule's own HEAD; the engines are committed source now, but the
# dependency on a real git checkout is unchanged.)
#
# CAVEAT, learned 2026-07-29: this filter is per-FILE, not per-test, so it also
# suppresses failures in test_vendor_engines.py that have nothing to do with
# `.git` - one stale assertion sat green-by-omission here for months. If that
# file grows non-pin tests, narrow this to the pin tests by name.
#
# Filtering them out is what makes this script's exit code a TRUSTWORTHY signal:
# leaving them in meant every single run exited non-zero, so a red exit code
# carried no information and got ignored - exactly the failure mode that let the
# old `| tee` exit-code bug hide for as long as it did. Any OTHER failure still
# fails the run.
if [ "$pytest_rc" -ne 0 ]; then
  unexpected=$(echo "$pytest_out" | grep '^FAILED' | grep -v 'test_vendor_engines\.py' || true)
  if [ -n "$unexpected" ]; then
    echo "!!! UNEXPECTED test failures (not the known vendor-pin ones):"
    echo "$unexpected"
    exit 1
  fi
  known=$(echo "$pytest_out" | grep -c '^FAILED apps/monolith/tests/test_vendor_engines\.py' || true)
  echo "--- $known known environment-only vendor-pin failure(s) (VM checkout has no .git) - not a regression"
fi

echo "--- cleanup throwaway test containers (also runs via the EXIT trap above) ---"
REMOTE_TEST

echo "=== DONE - paste the pytest summary (and anything marked !!! or FAILED above) back to Claude ==="
