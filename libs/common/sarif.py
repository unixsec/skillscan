"""SARIF 2.1.0 serialization (coding spec §9: `GET /v1/scans/{scan_id}/sarif`,
§16.2 reporting module export formats).

Builds a SARIF log from ALREADY-SERIALIZED finding dicts (the exact shape
`libs.schemas.findings.serialize_finding` produces, and what `scan_result.
findings` stores as JSON) - never from raw engine output, which is untrusted
and must go through `libs.schemas.findings.parse_engine_result` first.

SECURITY: every finding's `evidence_redacted` field is already redacted at
the point it was produced (coding spec §16.2: "报表不含明文密钥/PII(仅脱敏 +
snippet_hash)") - `Finding`/its serialized form has no raw-evidence field at
all, so there is nothing here for this module to accidentally leak.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

_SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
_SARIF_VERSION = "2.1.0"

# SECURITY: fail-closed default - an unrecognized severity value (e.g. a stored
# finding from some future/unknown severity level) maps to the STRICTEST SARIF
# level, never silently downgraded to "note".
_SEVERITY_TO_SARIF_LEVEL = {
    4: "error",  # Severity.CRITICAL
    3: "error",  # Severity.HIGH
    2: "warning",  # Severity.MEDIUM
    1: "note",  # Severity.LOW
    0: "note",  # Severity.NONE
}


def _severity_to_level(severity: object) -> str:
    if not isinstance(severity, int):
        return "error"
    return _SEVERITY_TO_SARIF_LEVEL.get(severity, "error")


def _finding_to_sarif_result(finding: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding["rule_id"],
        "level": _severity_to_level(finding.get("severity")),
        "message": {"text": finding.get("evidence_redacted") or finding.get("title", "")},
    }
    file_path = finding.get("file_path")
    if file_path:
        region: dict[str, Any] = {}
        start_line = finding.get("start_line")
        if start_line is not None:
            region["startLine"] = start_line
        location = {"physicalLocation": {"artifactLocation": {"uri": file_path}}}
        if region:
            location["physicalLocation"]["region"] = region
        result["locations"] = [location]
    snippet_hash = finding.get("snippet_hash")
    if snippet_hash:
        # SECURITY: the hash, never the underlying snippet - a stable dedup
        # fingerprint that carries no evidentiary content itself.
        result["partialFingerprints"] = {"snippetHash/v1": snippet_hash}
    return result


def _finding_to_sarif_rule(finding: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": finding["rule_id"],
        "name": finding.get("test_item_id", finding["rule_id"]),
        "shortDescription": {"text": finding.get("title", finding["rule_id"])},
    }


def findings_to_sarif(
    findings: Sequence[Mapping[str, Any]], *, tool_name: str = "skillscan"
) -> dict[str, Any]:
    """Builds one SARIF run from a flat sequence of serialized-finding dicts
    (as produced across one or more scans) - callers needing a per-scan SARIF
    document just pass that one scan's findings."""
    seen_rule_ids: set[str] = set()
    rules: list[dict[str, Any]] = []
    for finding in findings:
        rule_id = finding["rule_id"]
        if rule_id not in seen_rule_ids:
            seen_rule_ids.add(rule_id)
            rules.append(_finding_to_sarif_rule(finding))

    return {
        "$schema": _SARIF_SCHEMA_URI,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {"driver": {"name": tool_name, "rules": rules}},
                "results": [_finding_to_sarif_result(f) for f in findings],
            }
        ],
    }
