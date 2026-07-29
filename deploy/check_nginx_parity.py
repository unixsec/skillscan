#!/usr/bin/env python3
"""Guard against silent drift between the two hand-maintained nginx configs.

skillscan ships nginx.conf TWICE, deliberately not from one shared source:

  - web/nginx.conf: baked into the web image, what docker-compose serves.
    Talks to `monolith:8000` on :80. It runs as the image's own non-root
    `skillscan` user - NOT, as this docstring claimed until 2026-07-29,
    "nginx's own root-ish default user". That wrong belief is why this file
    shipped for months without relocating nginx's temp paths and could not
    start at all under compose, while the chart's own copy (which does
    relocate them) kept the K8s path healthy and the divergence invisible.
  - deploy/helm/skillscan/templates/web.yaml (the `skillscan-web-nginx`
    ConfigMap): what the Helm chart mounts over the baked-in file. Talks to
    `skillscan-monolith:{{ .Values.web.monolithServicePort }}`, runs as a
    non-root uid with `readOnlyRootFilesystem: true`, relocates every
    writable nginx path under /tmp.

Those differences (host, port, uid, temp-file layout) are real - the two
files run in genuinely different environments and are SUPPOSED to keep
diverging on them. Nothing keeps them from also drifting on things that DO
need to agree: which backend paths get proxied at all, how large an upload
is allowed, which client-identity headers are forwarded on which path.
Commit e040962 found one such gap (a missing client_max_body_size) by hand
and fixed it, and reported a second gap (inconsistent header forwarding)
that it deliberately left open. This script is the test that should have
caught the first gap, and it encodes a considered answer to the second.

USAGE
    uv run python deploy/check_nginx_parity.py

Requires `helm` on PATH - the same requirement as the `helm lint` gate this
project already runs before every deploy/ commit. The chart side is
rendered for real with `helm template` rather than hand-parsed as a Go
template, so `{{ .Values.web.maxUploadSize }}` is compared as the actual
"64m" it renders to, not as template source text.

WHAT THIS DELIBERATELY DOES NOT CHECK
    - proxy_pass target hosts/ports (expected to differ - different
      runtimes, see above)
    - listen port, pid/temp-file paths, worker/user directives (same reason)
    - client_max_body_size on any path other than /v1/ - it is the only
      path either file actually accepts uploads on; a larger limit
      elsewhere is a harmless byproduct (GET-only probes/JWKS traffic sends
      no body), not a defect worth chasing.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WEB_NGINX_CONF = REPO_ROOT / "web" / "nginx.conf"
CHART_DIR = REPO_ROOT / "deploy" / "helm" / "skillscan"

# Satisfies secret.yaml's `required` gate on localAccounts.seed
# (config.localAuthEnabled defaults to true) - a throwaway value, never
# installed anywhere, only needed so `helm template` renders at all.
_DUMMY_SEED = '[{"username":"parity-check","password_hash":"scrypt$00$00","role":"admin"}]'

LOCATION_RE = re.compile(r"location\s+(?:(?P<mod>~|=)\s+)?(?P<match>\S+)\s*\{(?P<body>[^{}]*)\}")
HEADER_RE = re.compile(r"^\s*proxy_set_header\s+(\S+)", re.MULTILINE)
BODY_SIZE_RE = re.compile(r"^\s*client_max_body_size\s+(\S+);", re.MULTILINE)
PROXY_PASS_RE = re.compile(r"^\s*proxy_pass\s+(\S+);", re.MULTILINE)

# The four headers web/nginx.conf's /v1/ block and the chart's combined
# regex block both know about. Anything forwarded by only one side that
# isn't in this set would still be caught (set comparison below is exact),
# this just names the ones worth reasoning about explicitly.
TRACKED_HEADERS = {"Host", "X-Real-IP", "X-Forwarded-For", "X-Forwarded-Proto"}


def _strip_comments(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.strip().startswith("#"))


def _normalize_prefix_set(match_pattern: str) -> set[str] | None:
    """Map an nginx `location` match to the canonical short token(s) it
    covers, or None for a location that proxies nowhere (the SPA fallback).
    """
    if match_pattern == "/":
        return None
    combined = re.match(r"^\^?/\(([^)]*)\)$", match_pattern)
    tokens = combined.group(1).split("|") if combined else [match_pattern]
    out: set[str] = set()
    for tok in tokens:
        tok = tok.replace("\\", "").strip("/.")
        if tok:
            out.add(tok)
    return out or None


class LocationInfo:
    def __init__(self, body: str) -> None:
        clean = _strip_comments(body)
        self.headers = set(HEADER_RE.findall(clean)) & TRACKED_HEADERS
        self.proxied = bool(PROXY_PASS_RE.search(clean))
        size_match = BODY_SIZE_RE.search(clean)
        self.body_size = size_match.group(1) if size_match else None


def _parse_locations(nginx_text: str) -> dict[str, LocationInfo]:
    """Return {canonical prefix token: LocationInfo}, skipping the SPA
    fallback and any location with no proxy_pass (nothing to compare)."""
    by_prefix: dict[str, LocationInfo] = {}
    for m in LOCATION_RE.finditer(nginx_text):
        prefixes = _normalize_prefix_set(m.group("match"))
        if prefixes is None:
            continue
        info = LocationInfo(m.group("body"))
        if not info.proxied:
            continue
        for prefix in prefixes:
            if prefix in by_prefix:
                raise AssertionError(
                    f"prefix {prefix!r} claimed by more than one proxying location "
                    "block - parser assumption (one owner per path) broken, fix the "
                    "parser or the nginx config"
                )
            by_prefix[prefix] = info
    return by_prefix


def _render_helm_nginx_conf() -> str:
    try:
        proc = subprocess.run(
            [
                "helm",
                "template",
                "skillscan",
                str(CHART_DIR),
                "--show-only",
                "templates/web.yaml",
                "--set-json",
                f"localAccounts.seed={_DUMMY_SEED}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        print(
            "ERROR: `helm` not found on PATH. This guard renders the chart's "
            "ConfigMap for real rather than hand-parsing Go template syntax - "
            "install helm (same requirement as the `helm lint` deploy gate).",
            file=sys.stderr,
        )
        sys.exit(2)
    if proc.returncode != 0:
        print("ERROR: `helm template` failed:\n" + proc.stderr, file=sys.stderr)
        sys.exit(2)

    # Pull the `nginx.conf: |` block scalar back out of the rendered
    # ConfigMap YAML. Not using a YAML parser: this matches this project's
    # stdlib-only scripts convention (see scripts/check_import_boundaries.py)
    # and the block's shape is fixed by web.yaml, which deploy/ owns.
    lines = proc.stdout.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.strip() == "nginx.conf: |":
            start = i + 1
            break
    if start is None:
        print(
            "ERROR: could not find `nginx.conf: |` in the rendered ConfigMap - "
            "did templates/web.yaml's structure change?",
            file=sys.stderr,
        )
        sys.exit(2)
    key_indent = len(lines[start - 1]) - len(lines[start - 1].lstrip())
    body_lines = []
    for line in lines[start:]:
        if line.strip() and (len(line) - len(line.lstrip())) <= key_indent:
            break
        body_lines.append(line)
    return "\n".join(body_lines)


# Forwarded headers, per path - checked against a DOCUMENTED expectation,
# not against each other. The two files structure their location blocks
# differently (web/nginx.conf: one location per path; the chart: one
# combined regex covering all four), so the chart forwards headers to
# healthz/readyz as a byproduct of that merge, not as a considered per-path
# decision. Asserting straight equality would either force a needless split
# of the chart's single location into four, or silently accept the
# byproduct by having no check at all - this table is the alternative: each
# side's actual behaviour, and the reason they're allowed to differ, is an
# assertion here instead of a comment nobody re-reads. Changing what either
# file actually forwards fails this check until EXPECTATION is edited to
# match and re-justify it.
EXPECTATION: dict[str, tuple[set[str], set[str], str]] = {
    "v1": (
        TRACKED_HEADERS,
        TRACKED_HEADERS,
        "primary API/upload traffic on both runtimes - identical by design",
    ),
    "well-known": (
        TRACKED_HEADERS,
        TRACKED_HEADERS,
        "JWKS is fetched by an external client (the marketplace, INV-13) over "
        "the network, not by an in-cluster probe - forwarded for the same "
        "OIDC-discovery-style provenance reason as /v1/, even though "
        "gate/signer.py's jwks() does not read these headers today",
    ),
    "healthz": (
        set(),
        TRACKED_HEADERS,
        "liveness probe; infra_router.healthz() takes no Request parameter at "
        "all and cannot read a header - web/nginx.conf omits them "
        "deliberately, the chart forwards them only as a byproduct of sharing "
        "one location block with /v1/",
    ),
    "readyz": (
        set(),
        TRACKED_HEADERS,
        "readiness probe; infra_router.readyz() only checks redis/db/"
        "blobstore, never reads a request header - same byproduct as healthz",
    ),
}


def main() -> int:
    web_locations = _parse_locations(WEB_NGINX_CONF.read_text())
    helm_locations = _parse_locations(_render_helm_nginx_conf())

    failures: list[str] = []

    # 1. Proxied paths must match exactly - a route added to one config and
    #    not the other is exactly the silent-drift shape this guard exists
    #    to catch.
    web_prefixes = set(web_locations)
    helm_prefixes = set(helm_locations)
    if web_prefixes != helm_prefixes:
        only_web = web_prefixes - helm_prefixes
        only_helm = helm_prefixes - web_prefixes
        if only_web:
            failures.append(
                f"proxied in web/nginx.conf but not in the chart's ConfigMap: {sorted(only_web)}"
            )
        if only_helm:
            failures.append(
                f"proxied in the chart's ConfigMap but not in web/nginx.conf: {sorted(only_helm)}"
            )

    # 2. Upload size: /v1/ is the only path either file actually accepts
    #    uploads on, so it's the only one compared (see module docstring).
    web_v1 = web_locations.get("v1")
    helm_v1 = helm_locations.get("v1")
    if web_v1 and helm_v1 and web_v1.body_size != helm_v1.body_size:
        failures.append(
            f"/v1/ client_max_body_size differs: web/nginx.conf={web_v1.body_size!r} "
            f"vs chart={helm_v1.body_size!r}"
        )

    # 3. Forwarded headers per path, against the documented expectation.
    for prefix, (want_web, want_helm, why) in EXPECTATION.items():
        got_web = web_locations[prefix].headers if prefix in web_locations else None
        got_helm = helm_locations[prefix].headers if prefix in helm_locations else None
        if got_web is None or got_helm is None:
            continue  # already reported by the proxied-paths check above
        if got_web != want_web or got_helm != want_helm:
            failures.append(
                f"{prefix}: forwarded headers no longer match the documented "
                f"expectation ({why}).\n"
                f"    web/nginx.conf forwards {sorted(got_web)}, expected {sorted(want_web)}\n"
                f"    chart ConfigMap forwards {sorted(got_helm)}, expected {sorted(want_helm)}\n"
                "    If this is a deliberate change, update EXPECTATION in this "
                "script to match and re-justify it - don't just delete the check."
            )

    if failures:
        print("nginx parity check FAILED:\n")
        for f in failures:
            print(f"  - {f}\n")
        return 1

    print(
        "nginx parity check passed: proxied paths, /v1/ upload size, and "
        "forwarded headers on all four paths all match their documented "
        "expectations."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
