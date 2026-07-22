"""Tests for `common.sarif` (coding spec §9 SARIF export, §16.2 reporting).

Findings are built via the REAL `skillscan_core.Finding` + `libs.schemas.
findings.serialize_finding` round-trip, not hand-written dicts - proves the
SARIF builder actually matches what `scan_result.findings` stores in the DB.
"""

from __future__ import annotations

from common.sarif import findings_to_sarif
from schemas.findings import serialize_finding
from skillscan_core import DetectionCategory, EngineCapability, Finding, Severity


def _finding(
    *,
    rule_id: str = "static.hardcoded_secret",
    severity: Severity = Severity.HIGH,
    file_path: str | None = "skill/main.py",
    start_line: int | None = 12,
    snippet_hash: str | None = "a" * 64,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        test_item_id="T-001",
        category=DetectionCategory.DATA_CREDENTIAL,
        title="Hardcoded secret detected",
        severity=severity,
        confidence=0.9,
        source_engine="bandit",
        source_capability=EngineCapability.STATIC,
        file_path=file_path,
        start_line=start_line,
        snippet_hash=snippet_hash,
        evidence_redacted="secret=<redacted>",
    )


class TestFindingsToSarif:
    def test_produces_valid_top_level_shape(self) -> None:
        sarif = findings_to_sarif([serialize_finding(_finding())])
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "skillscan"

    def test_result_carries_rule_id_and_message(self) -> None:
        sarif = findings_to_sarif([serialize_finding(_finding(rule_id="static.foo"))])
        result = sarif["runs"][0]["results"][0]
        assert result["ruleId"] == "static.foo"
        assert result["message"]["text"] == "secret=<redacted>"

    def test_never_leaks_anything_beyond_evidence_redacted(self) -> None:
        # SECURITY: Finding has no raw-evidence field at all - this asserts the
        # SARIF message is built from evidence_redacted, never from title alone
        # when redacted text is present (title could be more revealing).
        f = _finding()
        sarif = findings_to_sarif([serialize_finding(f)])
        assert sarif["runs"][0]["results"][0]["message"]["text"] == f.evidence_redacted

    def test_location_includes_file_and_line(self) -> None:
        sarif = findings_to_sarif([serialize_finding(_finding(file_path="a/b.py", start_line=42))])
        location = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "a/b.py"
        assert location["region"]["startLine"] == 42

    def test_missing_file_path_omits_locations(self) -> None:
        sarif = findings_to_sarif([serialize_finding(_finding(file_path=None))])
        assert "locations" not in sarif["runs"][0]["results"][0]

    def test_snippet_hash_becomes_partial_fingerprint(self) -> None:
        sarif = findings_to_sarif([serialize_finding(_finding(snippet_hash="b" * 64))])
        assert sarif["runs"][0]["results"][0]["partialFingerprints"]["snippetHash/v1"] == "b" * 64

    def test_missing_snippet_hash_omits_fingerprints(self) -> None:
        sarif = findings_to_sarif([serialize_finding(_finding(snippet_hash=None))])
        assert "partialFingerprints" not in sarif["runs"][0]["results"][0]

    def test_severity_maps_to_sarif_level(self) -> None:
        critical = findings_to_sarif([serialize_finding(_finding(severity=Severity.CRITICAL))])
        medium = findings_to_sarif([serialize_finding(_finding(severity=Severity.MEDIUM))])
        low = findings_to_sarif([serialize_finding(_finding(severity=Severity.LOW))])
        assert critical["runs"][0]["results"][0]["level"] == "error"
        assert medium["runs"][0]["results"][0]["level"] == "warning"
        assert low["runs"][0]["results"][0]["level"] == "note"

    def test_unknown_severity_fails_closed_to_error(self) -> None:
        finding_dict = serialize_finding(_finding())
        finding_dict["severity"] = 99  # not a real Severity value
        sarif = findings_to_sarif([finding_dict])
        assert sarif["runs"][0]["results"][0]["level"] == "error"

    def test_dedups_rules_by_rule_id(self) -> None:
        findings = [serialize_finding(_finding(rule_id="static.dup")) for _ in range(3)]
        sarif = findings_to_sarif(findings)
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1
        assert len(sarif["runs"][0]["results"]) == 3

    def test_empty_findings_produces_empty_results(self) -> None:
        sarif = findings_to_sarif([])
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []
