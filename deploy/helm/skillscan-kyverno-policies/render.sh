#!/bin/bash
# Renders this chart's Kyverno ClusterPolicies for one specific skillscan
# release and prints the manifest to stdout (pipe to `kubectl apply -f -`).
#
# Exists because these policies used to hardcode `namespaces: [skillscan]`:
# installing skillscan anywhere else got silent zero admission enforcement.
# The chart now templates the namespace from what you pass here - there is
# no working default, on purpose, so a forgotten -n cannot silently apply
# the wrong (or no) enforcement.
#
# require-signed-images.yaml is opt-in (-k) because its signing key is
# genuinely site-specific and cannot be defaulted. The old static YAML
# shipped a placeholder key that Kyverno accepted at `kubectl apply` time
# without complaint and then rejected EVERY image at admission with "PEM
# decoding failed". This script runs `openssl pkey -pubin -noout` on
# whatever file you give -k BEFORE rendering, so a placeholder or garbage
# key fails loudly here instead of surfacing later as a broken deployment.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: render.sh -n <release-namespace> [-k <cosign-public-key-file>]

  -n   The SAME namespace `deploy/helm/skillscan` was (or will be) installed
       into. Required - there is no default namespace.
  -k   PEM-encoded cosign public key file. Enables require-signed-images.yaml
       when given; validated with `openssl pkey -pubin -noout` before
       rendering. Omit to render only the two on-by-default policies
       (pod-security-baseline, require-gvisor-sandbox-runtimeclass).

Output goes to stdout: render.sh -n skillscan | kubectl apply -f -
EOF
  exit 1
}

namespace=""
keyfile=""
while getopts "n:k:h" opt; do
  case "$opt" in
    n) namespace="$OPTARG" ;;
    k) keyfile="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done

[ -n "$namespace" ] || usage

if ! [[ "$namespace" =~ ^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$ ]]; then
  echo "ERROR: '$namespace' is not a valid Kubernetes namespace name (RFC 1123 label)." >&2
  exit 1
fi

if ! command -v helm >/dev/null 2>&1; then
  echo "ERROR: helm not found on PATH." >&2
  exit 1
fi

chart_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

helm_args=(template skillscan-kyverno-policies "$chart_dir" -n "$namespace")

if [ -n "$keyfile" ]; then
  if [ ! -r "$keyfile" ]; then
    echo "ERROR: cannot read cosign public key file '$keyfile'." >&2
    exit 1
  fi
  if ! command -v openssl >/dev/null 2>&1; then
    echo "ERROR: openssl not found on PATH - cannot validate '$keyfile' before rendering." >&2
    exit 1
  fi
  if ! openssl pkey -pubin -in "$keyfile" -noout 2>/tmp/render-sh-openssl-err.$$; then
    echo "ERROR: '$keyfile' does not parse as a PEM public key (openssl: $(cat /tmp/render-sh-openssl-err.$$ 2>/dev/null))." >&2
    echo "This is exactly the failure Kyverno used to defer to admission time (\"PEM decoding failed\", rejecting EVERY image). Fix the key, don't bypass this check." >&2
    rm -f "/tmp/render-sh-openssl-err.$$"
    exit 1
  fi
  rm -f "/tmp/render-sh-openssl-err.$$"
  helm_args+=(--set requireSignedImages.enabled=true --set-file requireSignedImages.cosignPublicKey="$keyfile")
fi

exec helm "${helm_args[@]}"
