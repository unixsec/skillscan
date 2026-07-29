#!/bin/bash
# Build the air-gapped offline image bundle (M-E spec §6).
#
# RUN THIS WHERE THERE IS INTERNET. services/engine_runner/Dockerfile runs
# `go mod download`, `go build` and two `uv pip install` passes at build time;
# apps/monolith/Dockerfile runs `uv sync`; web/Dockerfile runs `npm ci`. None of
# that works inside the isolated network, so the enterprise receives finished
# images instead of a build.
#
# Five images travel: the three skillscan images built here, plus the mysql and
# redis images templates/{mysql,redis}.yaml reference - those are just as
# unpullable inside the isolated network as skillscan's own, and a release whose
# database never starts is not a working install.
#
# Output is one directory that is the whole transfer unit:
#
#   dist/skillscan-offline-<tag>-<arch>/
#     images.tar                  all five images, one `docker save`
#     manifest.txt                image refs + provenance (see below)
#     SHA256SUMS                  covers the other three files
#     import_offline_bundle.sh    copied from scripts/, run this on the far side
#
# NO REGISTRY IS INVOLVED, on either side. The image references are read out of
# deploy/helm/skillscan/values.yaml rather than hardcoded here, so the bundle
# cannot be tagged differently from what the chart's `skillscan.image` helper
# will ask kubelet for - that mismatch is invisible until every pod is sitting
# in ImagePullBackOff at the end of a full install.
#
# Usage:
#   bash scripts/build_offline_bundle.sh [--tag TAG] [--output-dir DIR]
#
# Optional env, passed through to `docker build` only when non-empty (all three
# Dockerfiles read them as build args to point at internal mirrors):
#   PIP_INDEX_URL  GOPROXY  NPM_CONFIG_REGISTRY
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

VALUES_FILE="deploy/helm/skillscan/values.yaml"
CHART_FILE="deploy/helm/skillscan/Chart.yaml"
IMPORT_SCRIPT="scripts/import_offline_bundle.sh"

die() {
  echo "" >&2
  echo "!!! $*" >&2
  exit 1
}

TAG_OVERRIDE=""
OUTPUT_DIR="dist"
while [ $# -gt 0 ]; do
  case "$1" in
    --tag)
      [ $# -ge 2 ] || die "--tag needs a value"
      TAG_OVERRIDE="$2"; shift 2 ;;
    --output-dir)
      [ $# -ge 2 ] || die "--output-dir needs a value"
      OUTPUT_DIR="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,38p' "$0"; exit 0 ;;
    *)
      die "unknown argument: $1 (see --help)" ;;
  esac
done

# ---------------------------------------------------------------------------
# 1. Preflight. Every one of these is a hard stop: half a bundle is worse than
#    no bundle, because it looks like a bundle.
# ---------------------------------------------------------------------------
echo "=== [1/6] preflight ==="
command -v docker >/dev/null || die "docker is required to build the bundle"
docker info >/dev/null 2>&1 || die "the docker daemon is not reachable (try: docker info)"

for f in "$VALUES_FILE" "$CHART_FILE" "$IMPORT_SCRIPT" \
         apps/monolith/Dockerfile services/engine_runner/Dockerfile web/Dockerfile; do
  [ -f "$f" ] || die "missing $f - run this from a full skillscan checkout"
done

if command -v sha256sum >/dev/null; then
  SHA256_CMD="sha256sum"
elif command -v shasum >/dev/null; then
  SHA256_CMD="shasum -a 256"
else
  die "need sha256sum (coreutils) or shasum to write the integrity manifest"
fi
echo "    docker: $(docker version --format '{{.Server.Version}}')   sha256: $SHA256_CMD"

# ---------------------------------------------------------------------------
# 2. Read the image references straight out of the chart.
#    This mirrors _helpers.tpl's `skillscan.image`: an EMPTY registry emits no
#    prefix at all, not a leading "/".
# ---------------------------------------------------------------------------
echo "=== [2/6] reading image references from $VALUES_FILE ==="

# yaml_block_pairs <top-level key>: emits "key<TAB>value" for every scalar one
# level under it. Enough for this file's flat image/mysql/redis blocks, and it
# deliberately does NOT know how to skip a key it cannot find - callers assert.
yaml_block_pairs() {
  awk -v blk="$1" '
    $0 ~ "^" blk ":[[:space:]]*$" { inblk = 1; next }
    inblk && /^[^[:space:]#]/ { inblk = 0 }
    inblk {
      line = $0
      sub(/^[[:space:]]+/, "", line)
      if (line ~ /^#/ || line == "") next
      sub(/[[:space:]]+#.*$/, "", line)
      idx = index(line, ":")
      if (idx == 0) next
      k = substr(line, 1, idx - 1)
      v = substr(line, idx + 1)
      sub(/^[[:space:]]*/, "", v)
      sub(/[[:space:]]*$/, "", v)
      gsub(/^"|"$/, "", v)
      print k "\t" v
    }
  ' "$VALUES_FILE"
}

block_key() {
  # Prints the value, returns non-zero when the key is absent, so an upstream
  # rename of e.g. monolithRepository stops this script instead of silently
  # producing a bundle tagged with an empty repository name.
  printf '%s\n' "$2" | awk -F'\t' -v k="$1" '$1 == k { print $2; found = 1 } END { exit !found }'
}

image_block="$(yaml_block_pairs image)"

require_image_key() {
  local value
  value="$(block_key "$1" "$image_block")" \
    || die "$VALUES_FILE has no image.$1 - the chart and this script have diverged"
  printf '%s' "$value"
}

# registry is legitimately empty by default, so it is fetched with the same
# presence check but no non-empty assertion.
IMAGE_REGISTRY="$(require_image_key registry)"
MONOLITH_REPO="$(require_image_key monolithRepository)"
RUNNER_REPO="$(require_image_key engineRunnerRepository)"
WEB_REPO="$(require_image_key webRepository)"
CHART_TAG="$(require_image_key tag)"

for pair in "monolithRepository=$MONOLITH_REPO" "engineRunnerRepository=$RUNNER_REPO" \
            "webRepository=$WEB_REPO" "tag=$CHART_TAG"; do
  [ -n "${pair#*=}" ] || die "image.${pair%%=*} is empty in $VALUES_FILE"
done

TAG="${TAG_OVERRIDE:-$CHART_TAG}"
REGISTRY_PREFIX=""
[ -n "$IMAGE_REGISTRY" ] && REGISTRY_PREFIX="$IMAGE_REGISTRY/"

MONOLITH_REF="${REGISTRY_PREFIX}${MONOLITH_REPO}:${TAG}"
RUNNER_REF="${REGISTRY_PREFIX}${RUNNER_REPO}:${TAG}"
WEB_REF="${REGISTRY_PREFIX}${WEB_REPO}:${TAG}"

echo "    built here:"
echo "      $MONOLITH_REF"
echo "      $RUNNER_REF"
echo "      $WEB_REF"

# THE CHART ALSO SHIPS MySQL AND REDIS. templates/{mysql,redis}.yaml reference
# upstream images by their public names, and those are exactly as unpullable in
# an isolated network as skillscan's own. A bundle holding only the three
# skillscan images installs and then leaves mysql/redis in ImagePullBackOff,
# which takes the whole release down with them (migration Job, then monolith).
# They are not built here, only carried - hence "pull-or-reuse" below.
VENDORED_REFS=()
for comp in mysql redis; do
  block="$(yaml_block_pairs "$comp")"
  enabled="$(block_key enabled "$block")" \
    || die "$VALUES_FILE has no $comp.enabled - the chart and this script have diverged"
  ref="$(block_key image "$block")" \
    || die "$VALUES_FILE has no $comp.image - the chart and this script have diverged"
  if [ "$enabled" = "true" ]; then
    [ -n "$ref" ] || die "$comp.image is empty in $VALUES_FILE"
    VENDORED_REFS+=("$ref")
  else
    echo "    NOTE: $comp.enabled is false in $VALUES_FILE - $ref left out of the bundle."
    echo "    The chart will then expect an external $comp reachable from the cluster."
  fi
done
echo "    carried as-is:"
for ref in "${VENDORED_REFS[@]+"${VENDORED_REFS[@]}"}"; do echo "      $ref"; done

if [ "$TAG" != "$CHART_TAG" ]; then
  echo ""
  echo "    NOTE: --tag $TAG differs from the chart default ($CHART_TAG)."
  echo "    The install MUST then pass:  --set image.tag=$TAG"
  echo "    Without it every pod asks for :$CHART_TAG, which this bundle does not contain."
fi

# ---------------------------------------------------------------------------
# 3. Build. `set -e` aborts on the first failing build - do not add a
#    `|| echo "build failed"` here, this repo has been burned by exactly that.
# ---------------------------------------------------------------------------
echo "=== [3/6] building three images, collecting two more ==="

build_args=()
for arg in PIP_INDEX_URL GOPROXY NPM_CONFIG_REGISTRY; do
  value="${!arg:-}"
  if [ -n "$value" ]; then
    build_args+=(--build-arg "$arg=$value")
    echo "    build-arg $arg=$value"
  fi
done

build_image() {
  local dockerfile="$1" ref="$2"
  echo "--- $ref  (-f $dockerfile) ---"
  docker build -f "$dockerfile" -t "$ref" "${build_args[@]+"${build_args[@]}"}" .
  # `docker build` exiting 0 with no image is not a thing, but the bundle's
  # whole value is that the ref exists under exactly this name - assert it.
  docker image inspect "$ref" >/dev/null \
    || die "docker build reported success but $ref does not exist"
}

build_image apps/monolith/Dockerfile "$MONOLITH_REF"
build_image services/engine_runner/Dockerfile "$RUNNER_REF"
build_image web/Dockerfile "$WEB_REF"

# Pull-or-reuse, deliberately not an unconditional `docker pull`: mysql:8.0 and
# redis:7-alpine are floating tags, and re-pulling would silently swap in
# whatever digest the tag points at today for the one this build host was
# verified against. A host that has never seen them pulls once.
for ref in "${VENDORED_REFS[@]+"${VENDORED_REFS[@]}"}"; do
  if docker image inspect "$ref" >/dev/null 2>&1; then
    echo "--- $ref  (already present locally, not re-pulled) ---"
  else
    echo "--- $ref  (docker pull) ---"
    docker pull "$ref"
    docker image inspect "$ref" >/dev/null \
      || die "docker pull reported success but $ref does not exist"
  fi
done

# ---------------------------------------------------------------------------
# 4. Architecture. An arm64 bundle imported onto amd64 nodes produces
#    "exec format error" at container start, which reads like an application
#    bug. Record the arch and let the import side refuse it up front.
# ---------------------------------------------------------------------------
echo "=== [4/6] recording platform ==="
ALL_REFS=("$MONOLITH_REF" "$RUNNER_REF" "$WEB_REF" "${VENDORED_REFS[@]+"${VENDORED_REFS[@]}"}")
PLATFORM=""
for ref in "${ALL_REFS[@]}"; do
  p="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$ref")"
  if [ -z "$PLATFORM" ]; then
    PLATFORM="$p"
  elif [ "$p" != "$PLATFORM" ]; then
    die "images disagree on platform ($PLATFORM vs $p for $ref) - refusing to bundle"
  fi
done
echo "    $PLATFORM"

# ---------------------------------------------------------------------------
# 5. Save + manifest + checksums.
# ---------------------------------------------------------------------------
ARCH_SUFFIX="${PLATFORM##*/}"
BUNDLE_NAME="skillscan-offline-${TAG}-${ARCH_SUFFIX}"
BUNDLE_DIR="${OUTPUT_DIR%/}/${BUNDLE_NAME}"

echo "=== [5/6] writing $BUNDLE_DIR ==="
rm -rf "$BUNDLE_DIR"
mkdir -p "$BUNDLE_DIR"

docker save "${ALL_REFS[@]}" -o "$BUNDLE_DIR/images.tar"
[ -s "$BUNDLE_DIR/images.tar" ] || die "docker save produced an empty images.tar"

chart_version="$(awk '/^version:/ { print $2; exit }' "$CHART_FILE")"
source_commit="(not a git checkout)"
if command -v git >/dev/null && git rev-parse --git-dir >/dev/null 2>&1; then
  source_commit="$(git rev-parse HEAD)"
  git diff --quiet HEAD 2>/dev/null || source_commit="$source_commit (working tree dirty)"
fi

# One `key value` per line: greppable from the import script without a YAML
# parser, which the isolated side is not guaranteed to have.
{
  echo "# skillscan offline image bundle - see scripts/build_offline_bundle.sh"
  echo "bundle_format 1"
  echo "chart_version $chart_version"
  echo "image_tag $TAG"
  echo "image_registry ${IMAGE_REGISTRY:-(none - bare names, side-loaded)}"
  echo "platform $PLATFORM"
  echo "built_at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "source_commit $source_commit"
  echo "archive images.tar"
  # These are the references the CHART asks kubelet for. containerd stores
  # bare names under docker.io/<name>; the import script normalizes before
  # comparing, and that normalization is documented in exactly one place.
  for ref in "${ALL_REFS[@]}"; do echo "image $ref"; done
} > "$BUNDLE_DIR/manifest.txt"

cp "$IMPORT_SCRIPT" "$BUNDLE_DIR/import_offline_bundle.sh"
chmod +x "$BUNDLE_DIR/import_offline_bundle.sh"

# Written last, and covers the import script itself: the far side verifies the
# code it is about to run, not just the payload.
( cd "$BUNDLE_DIR" && $SHA256_CMD images.tar manifest.txt import_offline_bundle.sh > SHA256SUMS )
[ -s "$BUNDLE_DIR/SHA256SUMS" ] || die "failed to write SHA256SUMS"

# ---------------------------------------------------------------------------
# 6. Instructions.
# ---------------------------------------------------------------------------
bundle_size="$(du -sh "$BUNDLE_DIR" | awk '{print $1}')"
bundle_abs="$(cd "$BUNDLE_DIR" && pwd)"   # --output-dir may be absolute
echo "=== [6/6] done ==="
echo ""
echo "================================================================"
echo "Bundle: $bundle_abs  ($bundle_size, $PLATFORM)"
echo ""
echo "Transfer the WHOLE directory to the isolated network (all four files;"
echo "SHA256SUMS is what makes the transfer verifiable), then on EVERY"
echo "kubernetes node that may run skillscan pods, as root:"
echo ""
echo "    bash $BUNDLE_NAME/import_offline_bundle.sh"
echo ""
echo "Then install the chart. With this bundle the image settings need NO"
if [ -n "$IMAGE_REGISTRY" ]; then
  echo "changes beyond the registry already recorded in values.yaml:"
  echo "    helm install skillscan deploy/helm/skillscan -n skillscan --create-namespace \\"
  echo "        --set image.registry=$IMAGE_REGISTRY --set image.tag=$TAG"
elif [ "$TAG" != "$CHART_TAG" ]; then
  echo "override except the tag, which you changed with --tag:"
  echo "    helm install skillscan deploy/helm/skillscan -n skillscan --create-namespace \\"
  echo "        --set image.tag=$TAG"
else
  echo "overrides at all - values.yaml's defaults (registry \"\", tag $TAG) are"
  echo "exactly what this bundle ships:"
  echo "    helm install skillscan deploy/helm/skillscan -n skillscan --create-namespace"
fi
echo "================================================================"
