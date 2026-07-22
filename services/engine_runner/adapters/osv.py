"""osv-scanner adapter (coding spec §10: `osv-scanner --offline --format json`)
→ SUP-01 已知脆弱组件 CVE.

Real JSON schema confirmed by reading
`vendor/osv-scanner/pkg/models/results.go` directly (coding spec's own
instruction - read the real vendored source, don't guess the interface):
  {"results": [{"source": {"path","type"}, "packages": [{"package":
    {"name","version","ecosystem"}, "vulnerabilities": [{"id","summary",
    "aliases",...osv-schema fields}], "groups": [{"ids","max_severity"}]}]}]}

SECURITY (INV-14): `--offline` is mandatory - this adapter must never let
osv-scanner reach `api.osv.dev` (a public external endpoint); offline mode
requires a local vulnerability DB pre-populated at image-build time (coding
spec §10A's build pipeline), not something this adapter manages at scan time.

SECURITY: osv-scanner, like bandit, exits nonzero (1) when vulnerabilities are
found - not a crash - so `treat_nonzero_exit_as_error=False`; stdout JSON-
parseability is the real usability signal.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from skillscan_core import (
    DetectionCategory,
    EngineCapability,
    EngineMetadata,
    Finding,
    Severity,
)

from .base import SubprocessEngineAdapter


def _metadata(*, ruleset_digest: str, version: str) -> EngineMetadata:
    return EngineMetadata(
        name="osv-scanner",
        version=version,
        ruleset_digest=ruleset_digest,
        capabilities=frozenset({EngineCapability.SCA}),
    )


def _build_argv(target_dir: Path) -> list[str]:
    # SECURITY (INV-14): --offline is non-negotiable here - never invoke
    # without it (would otherwise reach the public api.osv.dev).
    return ["osv-scanner", "--offline", "--format", "json", "--recursive", str(target_dir)]


def _severity_from_max_severity(raw: str) -> Severity:
    try:
        score = float(raw)
    except (TypeError, ValueError):
        return Severity.MEDIUM  # SECURITY: unparseable/missing -> fail toward stricter, not laxer
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


_EXPECTED_RETURNCODES = frozenset({0, 1})  # per vendor/osv-scanner/docs/output.md's own table


def parse_output(
    completed: subprocess.CompletedProcess[bytes], _target_dir: Path, _files: dict[str, bytes]
) -> tuple[Finding, ...]:
    # SECURITY: confirmed live (a real DB-less run) - osv-scanner still prints
    # syntactically valid JSON (`{"results": [], ...}`) on STDOUT even when it
    # completely failed to load its vulnerability database (the real error -
    # "could not load db for PyPI ecosystem" - goes to stderr only). Parsing
    # stdout without checking the return code would silently report a full
    # PASS ("ran fine, 0 findings") for a scan that never actually checked
    # anything - indistinguishable from a genuinely clean package, exactly
    # the false-negative `base.py`'s own docstring warns against. Per
    # osv-scanner's own documented contract (vendor/osv-scanner/docs/
    # output.md "Return Codes" table): 0=clean, 1=vulnerabilities found (a
    # real, non-error result - this is why the adapter sets
    # `treat_nonzero_exit_as_error=False`), 127=general error, 128=no
    # packages found, 129-255=other errors. Anything outside {0,1} means the
    # scan didn't actually complete - fail closed rather than trust stdout.
    if completed.returncode not in _EXPECTED_RETURNCODES:
        raise ValueError(
            f"osv-scanner exited {completed.returncode} (expected 0 or 1 per its documented "
            f"Return Codes table - anything else means the scan did not complete): "
            f"stderr={completed.stderr.decode('utf-8', errors='replace')[:500]!r}"
        )
    if not completed.stdout.strip():
        # SECURITY: osv-scanner prints nothing when the scan found zero packages/vulns.
        return ()
    payload = json.loads(
        completed.stdout
    )  # SECURITY: malformed JSON -> raises -> caller fail-closes
    if not isinstance(payload, dict) or "results" not in payload:
        raise ValueError("osv-scanner output missing 'results' key")

    findings: list[Finding] = []
    for source_result in payload["results"]:
        source_path = str(source_result.get("source", {}).get("path", ""))
        for pkg_result in source_result.get("packages", []):
            package = pkg_result.get("package", {})
            pkg_name = str(package.get("name", "unknown"))
            pkg_version = str(package.get("version", "unknown"))
            severity_by_vuln_id: dict[str, Severity] = {}
            for group in pkg_result.get("groups", []):
                sev = _severity_from_max_severity(str(group.get("max_severity", "")))
                for vuln_id in group.get("ids", []):
                    severity_by_vuln_id[vuln_id] = sev

            for vuln in pkg_result.get("vulnerabilities", []):
                vuln_id = str(vuln.get("id", "unknown"))
                summary = str(vuln.get("summary") or vuln.get("details") or vuln_id)
                findings.append(
                    Finding(
                        rule_id=f"osv.{vuln_id}",
                        test_item_id="SUP-01",
                        category=DetectionCategory.SUPPLY_CHAIN,
                        title=f"known vulnerability {vuln_id} in {pkg_name}@{pkg_version}",
                        severity=severity_by_vuln_id.get(vuln_id, Severity.MEDIUM),
                        # SECURITY: OSV entries are curated, CVE-equivalent - high-confidence.
                        confidence=0.9,
                        source_engine="osv-scanner",
                        source_capability=EngineCapability.SCA,
                        file_path=source_path or None,
                        snippet_hash=hashlib.sha256(
                            f"{pkg_name}@{pkg_version}".encode()
                        ).hexdigest(),
                        evidence_redacted=summary[:200],
                    )
                )
    return tuple(findings)


def make_adapter(*, ruleset_digest: str, version: str) -> SubprocessEngineAdapter:
    return SubprocessEngineAdapter(
        metadata=_metadata(ruleset_digest=ruleset_digest, version=version),
        build_argv=_build_argv,
        parse_output=parse_output,
        treat_nonzero_exit_as_error=False,
    )
