#!/bin/bash
# Push feat/m2-m8-platform (currently at commit 7b9c14d, includes the
# code-review fix batch) to the dev VM, rebuild+redeploy all 3 images
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

echo "=== [1/6] rsync working tree to VM ($VM_PATH) ==="
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

echo "=== [2/6] rebuild all 3 images on the VM ==="
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

echo "=== [3/6] import images into k3s containerd + rollout restart ==="
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

echo "=== [4/6] health check ==="
ssh "$VM" bash -s <<'REMOTE_HEALTH'
set -euo pipefail
mono_pod=$(kubectl get pods -n skillscan -o name | grep monolith | head -1)
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

echo "=== [5/6] sweep for stray dev processes that could race the test suite ==="
ssh "$VM" "ps aux | grep -E 'run_local\.py|uvicorn' | grep -v grep || echo '(none found)'"

echo "=== [6/6] fresh throwaway MySQL/Redis + full pytest suite ==="
ssh "$VM" bash -s <<'REMOTE_TEST'
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
cd /home/parallels/skillscan

echo "--- recreating throwaway test MySQL/Redis (host network) ---"
docker rm -f skillscan-test-mysql skillscan-test-redis >/dev/null 2>&1 || true
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
uv run pytest apps/monolith/tests/ -q 2>&1 | tail -100

echo "--- cleanup throwaway test containers ---"
docker rm -f skillscan-test-mysql skillscan-test-redis >/dev/null 2>&1 || true
REMOTE_TEST

echo "=== DONE - review the pytest summary above (check anything marked !!! or FAILED) ==="
