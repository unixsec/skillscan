#!/bin/bash
# Import the air-gapped offline image bundle into a node's container runtime
# (M-E spec §6). RUN THIS INSIDE THE ISOLATED NETWORK, as root, on every
# kubernetes node that may run skillscan pods.
#
# A copy of this script travels inside the bundle directory produced by
# scripts/build_offline_bundle.sh, so the normal invocation is:
#
#     bash skillscan-offline-<tag>-<arch>/import_offline_bundle.sh
#
# NO REGISTRY IS INVOLVED. The images are side-loaded straight into
# containerd's k8s.io namespace, which is where kubelet looks; the chart's
# `imagePullPolicy: IfNotPresent` then never reaches out to a network that
# is not there.
#
# Every check here aborts. In particular the sha256 verification refuses to
# import on mismatch rather than warning about it: an image tampered with in
# transit is the one thing an air-gapped install cannot detect later.
#
# Usage:
#   bash import_offline_bundle.sh [--bundle-dir DIR] [--namespace NS]
#                                 [--ctr "COMMAND"] [--no-sudo]
#
# Defaults: bundle dir = this script's own directory, namespace = k8s.io,
# ctr command = auto-detected (k3s ctr / ctr / rke2's bundled ctr).
set -euo pipefail

die() {
  echo "" >&2
  echo "!!! $*" >&2
  exit 1
}

BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="k8s.io"
CTR_CMD=""
USE_SUDO="auto"

while [ $# -gt 0 ]; do
  case "$1" in
    --bundle-dir)
      [ $# -ge 2 ] || die "--bundle-dir needs a value"
      BUNDLE_DIR="$2"; shift 2 ;;
    --namespace)
      [ $# -ge 2 ] || die "--namespace needs a value"
      NAMESPACE="$2"; shift 2 ;;
    --ctr)
      [ $# -ge 2 ] || die "--ctr needs a value"
      CTR_CMD="$2"; shift 2 ;;
    --no-sudo)
      USE_SUDO="no"; shift ;;
    -h|--help)
      sed -n '2,25p' "$0"; exit 0 ;;
    *)
      die "unknown argument: $1 (see --help)" ;;
  esac
done

[ -d "$BUNDLE_DIR" ] || die "bundle directory not found: $BUNDLE_DIR"
BUNDLE_DIR="$(cd "$BUNDLE_DIR" && pwd)"
for f in images.tar manifest.txt SHA256SUMS; do
  [ -f "$BUNDLE_DIR/$f" ] \
    || die "$BUNDLE_DIR/$f is missing - transfer the WHOLE bundle directory, not just the tar"
done

manifest_value() {
  awk -v k="$1" '$1 == k { $1 = ""; sub(/^ /, ""); print; found = 1; exit } END { exit !found }' \
    "$BUNDLE_DIR/manifest.txt"
}

# ---------------------------------------------------------------------------
# 1. Platform. Checked before anything expensive: importing an arm64 bundle
#    onto amd64 nodes succeeds, and then every container dies with
#    "exec format error", which reads like an application bug.
# ---------------------------------------------------------------------------
echo "=== [1/5] bundle and node platform ==="
bundle_platform="$(manifest_value platform)" \
  || die "manifest.txt has no 'platform' line - bundle is incomplete or not a skillscan bundle"
bundle_tag="$(manifest_value image_tag)" || die "manifest.txt has no 'image_tag' line"

case "$(uname -m)" in
  x86_64|amd64)   node_arch="amd64" ;;
  aarch64|arm64)  node_arch="arm64" ;;
  armv7l|armv7)   node_arch="arm" ;;
  *)              node_arch="$(uname -m)" ;;
esac
node_platform="linux/$node_arch"

echo "    bundle: $bundle_platform     node: $node_platform (uname -m: $(uname -m))"
if [ "$bundle_platform" != "$node_platform" ]; then
  die "architecture mismatch: this bundle holds $bundle_platform images and this node is
    $node_platform. Importing anyway would leave every pod crash-looping with
    'exec format error'. Rebuild the bundle on a $node_arch builder."
fi

# while-read rather than `mapfile`: bash 3.2 (still what macOS ships, and what
# a minimal rescue environment may offer) has no mapfile.
expected_refs=()
while IFS= read -r line; do
  [ -n "$line" ] && expected_refs+=("$line")
done < <(awk '$1 == "image" { print $2 }' "$BUNDLE_DIR/manifest.txt")
[ "${#expected_refs[@]}" -gt 0 ] || die "manifest.txt lists no images"
echo "    images in bundle:"
for ref in "${expected_refs[@]}"; do echo "      $ref"; done

# ---------------------------------------------------------------------------
# 2. Integrity. Abort on ANY mismatch - do not import, do not warn and carry
#    on. SHA256SUMS covers this script too, so what runs is verified as well
#    as what is imported.
# ---------------------------------------------------------------------------
echo "=== [2/5] verifying sha256 (SHA256SUMS) ==="
if command -v sha256sum >/dev/null; then
  sha256_check="sha256sum -c SHA256SUMS"
elif command -v shasum >/dev/null; then
  sha256_check="shasum -a 256 -c SHA256SUMS"
else
  die "need sha256sum (coreutils) or shasum to verify the bundle - refusing to import unverified images"
fi

if ! ( cd "$BUNDLE_DIR" && $sha256_check ); then
  die "sha256 verification FAILED. The bundle is corrupt or was modified in transit.
    Nothing has been imported. Re-transfer the bundle and run this again -
    do not import it by hand to work around this."
fi

# ---------------------------------------------------------------------------
# 3. Locate the container runtime CLI.
# ---------------------------------------------------------------------------
echo "=== [3/5] locating containerd CLI ==="
if [ -z "$CTR_CMD" ]; then
  CTR_CMD="${SKILLSCAN_CTR:-}"
fi
if [ -z "$CTR_CMD" ]; then
  if command -v k3s >/dev/null; then
    CTR_CMD="k3s ctr"
  elif command -v ctr >/dev/null; then
    CTR_CMD="ctr"
  elif [ -x /var/lib/rancher/rke2/bin/ctr ]; then
    CTR_CMD="/var/lib/rancher/rke2/bin/ctr --address /run/k3s/containerd/containerd.sock"
  else
    die "no containerd CLI found. Install one, or pass the right invocation, e.g.
    --ctr 'ctr --address /run/containerd/containerd.sock'"
  fi
fi

# CTR_CMD is a whole invocation ("k3s ctr", or a path plus --address), so it
# must be split into words - kept in an array rather than relying on unquoted
# expansion, which also happens to be the only way to keep shellcheck honest
# about every other variable in these command lines.
ctr_words=()
read -r -a ctr_words <<< "$CTR_CMD"
[ "${#ctr_words[@]}" -gt 0 ] || die "empty containerd command"

RUNTIME=()
PROBE=()
if [ "$USE_SUDO" != "no" ] && [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null \
    || die "not running as root and sudo is not available - containerd's socket is root-owned"
  RUNTIME+=(sudo)
  PROBE+=(sudo -n)   # -n: a probe must never sit waiting on a password prompt
fi
RUNTIME+=("${ctr_words[@]}")
PROBE+=("${ctr_words[@]}")
echo "    using: ${RUNTIME[*]} -n $NAMESPACE"

# The image store must be LISTABLE, not just writable, and that is checked here
# rather than after the import: step 5's verification is the only thing standing
# between a subtly mis-tagged bundle and a cluster-wide ImagePullBackOff, so a
# run that cannot perform it must not proceed to import. Listing needs the same
# root-owned containerd socket the import does, so on any normal node this
# succeeds whenever the import would.
if ! "${PROBE[@]}" -n "$NAMESPACE" images ls -q >/dev/null 2>&1; then
  die "cannot list images with '${PROBE[*]} -n $NAMESPACE images ls'.
    containerd's socket is root-owned - run this script as root (or with a sudo
    rule that covers 'ctr images ls' as well as 'ctr images import'). Nothing has
    been imported: without listing there is no way to verify that the names
    containerd registered are the ones the chart will ask kubelet for."
fi
echo "    image store is readable - post-import verification will run"

# ---------------------------------------------------------------------------
# 4. Import.
# ---------------------------------------------------------------------------
echo "=== [4/5] importing $BUNDLE_DIR/images.tar into containerd namespace $NAMESPACE ==="

# Run unpiped so the exit status is containerd's own and nothing can mask it -
# this repo has twice shipped a `cmd | tail`/`cmd | tee` whose exit code came
# from the last stage. The names it prints below are for the operator's eyes
# only; step 5 does not read them (see the note there).
if ! "${RUNTIME[@]}" -n "$NAMESPACE" images import "$BUNDLE_DIR/images.tar"; then
  die "'${RUNTIME[*]} images import' failed - see the output above. Nothing to clean up:
    containerd imports are idempotent, so fix the cause and run this again."
fi

# ---------------------------------------------------------------------------
# 5. Verify the names. This is the whole point of the exercise: the chart asks
#    kubelet for the reference in manifest.txt, kubelet normalizes a bare name
#    to docker.io/<name>, and containerd stores it under that normalized form.
#    A bundle whose names do not line up installs cleanly and leaves every pod
#    in ImagePullBackOff.
# ---------------------------------------------------------------------------
echo "=== [5/5] verifying imported image names ==="

normalize_ref() {
  # containerd/kubelet reference normalization, restricted to what this bundle
  # can produce: a first path segment that is not a hostname (no dot, no colon,
  # not "localhost") means the implicit docker.io registry.
  local ref="$1" first="${1%%/*}"
  if [ "$first" = "$ref" ]; then
    printf 'docker.io/library/%s' "$ref"          # single-segment: nginx:1.27
    return
  fi
  case "$first" in
    localhost|*.*|*:*) printf '%s' "$ref" ;;      # already registry-qualified
    *)                 printf 'docker.io/%s' "$ref" ;;  # skillscan/monolith:0.1.0
  esac
}

# THE STORE, NOT THE IMPORT OUTPUT. Measured on k3s v1.36.2 (containerd) while
# writing this: `ctr images import` echoed
#     docker.io/skillscan/engine runner:0.1.0   saved
# for an image the store actually holds as
#     docker.io/skillscan/engine-runner:0.1.0
# - its progress display renders a hyphen as a space. An earlier version of this
# script parsed that display and reported a perfectly good bundle as broken.
# `images ls -q` prints the real reference, one per line, and is what kubelet
# resolves against.
store_list="$("${RUNTIME[@]}" -n "$NAMESPACE" images ls -q)"
[ -n "$store_list" ] || die "'${RUNTIME[*]} -n $NAMESPACE images ls -q' returned nothing right
    after a successful import - refusing to claim the import worked."

missing=""
for ref in "${expected_refs[@]}"; do
  normalized="$(normalize_ref "$ref")"
  # -F -x: exact whole-line match. A substring match would accept
  # ":0.1.0-rc1" for ":0.1.0".
  if printf '%s\n' "$store_list" | grep -qFx "$normalized"; then
    echo "    OK  $ref  ->  $normalized"
  else
    missing="$missing $ref"
  fi
done

if [ -n "$missing" ]; then
  echo "--- the store holds these instead: ---" >&2
  printf '%s\n' "$store_list" | grep -F "$(printf '%s' "${expected_refs[0]}" | cut -d/ -f1)" >&2 || true
  die "imported, but these references are NOT in the image store:$missing
    kubelet resolves the chart's image names to exactly the strings above, so
    every pod would end up in ImagePullBackOff with no registry to fall back on.
    Rebuild the bundle with scripts/build_offline_bundle.sh (it reads the names
    from the chart itself) and import it again."
fi

echo ""
echo "================================================================"
echo "Imported skillscan $bundle_tag images into containerd/$NAMESPACE."
echo ""
echo "Repeat this on EVERY node that may run skillscan pods - a side-loaded"
echo "image is local to one node, and a pod scheduled anywhere else will sit"
echo "in ImagePullBackOff with no registry to fall back on."
echo ""
echo "Then install the chart (see docs/DEPLOYMENT_GUIDE.md):"
echo "    helm install skillscan deploy/helm/skillscan -n skillscan --create-namespace"
echo "================================================================"
