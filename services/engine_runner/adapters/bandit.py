"""bandit adapter (coding spec §10: `bandit -f json`) → CODE-12 弱加密,
FILE-04 TOCTOU/符号链接, 部分 CODE-08.

Real JSON schema confirmed by reading `vendor/bandit/bandit/formatters/json.py`
directly (coding spec's own instruction - read the real vendored source,
don't guess the interface):
  {"results": [{"filename", "issue_confidence", "issue_severity",
    "issue_cwe": {"id","link"}, "issue_text", "line_number", "line_range",
    "test_name", "test_id"}], "errors": [...], "metrics": {...}}

SECURITY: bandit exits 1 (not 0) when it finds issues at/above its default
threshold - that is NOT a crash, so `treat_nonzero_exit_as_error=False` here;
stdout JSON-parseability is what actually determines usability (a genuine
crash produces no valid JSON, which still fails closed via the parser
raising).
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

# SECURITY: bandit test IDs the coding spec explicitly names as mapping to a
# specific detection-catalog item; everything else falls back to a generic
# CODE category with the bandit test_id itself as the traceable identifier
# (honest about not having built a full 70+-rule mapping table).
_FILE_04_TEST_IDS = frozenset({"B108"})  # hardcoded_tmp_directory
# weak crypto/random: B303-B305/B311 are bandit's older blacklist-style IDs;
# B324 ("hashlib") is the current AST-based plugin that actually fires for
# `hashlib.md5(...)`/`hashlib.sha1(...)` on the installed bandit 1.9.4 CLI
# (confirmed empirically - a live hashlib.md5() sample emits B324, not B303).
_CODE_12_TEST_IDS = frozenset({"B303", "B304", "B305", "B311", "B324"})

_SEVERITY_MAP = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    # SECURITY: fail toward stricter, not laxer, on an unexpected/unmapped value.
    "UNDEFINED": Severity.MEDIUM,
}
_CONFIDENCE_MAP = {"LOW": 0.3, "MEDIUM": 0.6, "HIGH": 0.9, "UNDEFINED": 0.5}


def _metadata(*, ruleset_digest: str, version: str) -> EngineMetadata:
    return EngineMetadata(
        name="bandit",
        version=version,
        ruleset_digest=ruleset_digest,
        capabilities=frozenset({EngineCapability.STATIC}),
    )


def _build_argv(target_dir: Path) -> list[str]:
    return ["bandit", "-r", "-f", "json", str(target_dir)]


def _test_item_id_and_category(test_id: str) -> tuple[str, DetectionCategory]:
    if test_id in _FILE_04_TEST_IDS:
        return "FILE-04", DetectionCategory.FILE_PACKAGE
    if test_id in _CODE_12_TEST_IDS:
        return "CODE-12", DetectionCategory.CODE
    return test_id, DetectionCategory.CODE


def parse_output(
    completed: subprocess.CompletedProcess[bytes], _target_dir: Path, _files: dict[str, bytes]
) -> tuple[Finding, ...]:
    payload = json.loads(
        completed.stdout
    )  # SECURITY: malformed JSON -> raises -> caller fail-closes
    if not isinstance(payload, dict) or "results" not in payload:
        raise ValueError("bandit output missing 'results' key")

    findings: list[Finding] = []
    for result in payload["results"]:
        test_id = str(result["test_id"])
        test_item_id, category = _test_item_id_and_category(test_id)
        severity = _SEVERITY_MAP.get(str(result.get("issue_severity")), Severity.MEDIUM)
        confidence = _CONFIDENCE_MAP.get(str(result.get("issue_confidence")), 0.5)
        code_snippet = str(result.get("code", ""))
        findings.append(
            Finding(
                rule_id=f"bandit.{test_id}",
                test_item_id=test_item_id,
                category=category,
                title=str(result.get("test_name", test_id)),
                severity=severity,
                confidence=confidence,
                source_engine="bandit",
                source_capability=EngineCapability.STATIC,
                file_path=str(result.get("filename")) or None,
                start_line=result.get("line_number"),
                # SECURITY (INV-9): bandit's own "code" field is a plaintext
                # snippet from the scanned file - hash it, never forward it.
                snippet_hash=hashlib.sha256(code_snippet.encode("utf-8")).hexdigest()
                if code_snippet
                else None,
                evidence_redacted=str(result.get("issue_text", ""))[:200],
            )
        )
    return tuple(findings)


def make_adapter(*, ruleset_digest: str, version: str) -> SubprocessEngineAdapter:
    """`ruleset_digest`/`version` come from the pinned vendored commit
    (coding spec: 'name@version#ruleset_digest 来自 pin 的镜像 digest') - the
    caller (wherever engines are wired up) is responsible for deriving these
    from `vendor/engines.lock.yaml`, not this module."""
    return SubprocessEngineAdapter(
        metadata=_metadata(ruleset_digest=ruleset_digest, version=version),
        build_argv=_build_argv,
        parse_output=parse_output,
        treat_nonzero_exit_as_error=False,
    )
