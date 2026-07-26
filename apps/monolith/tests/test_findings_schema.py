"""Tests for `schemas.findings` (coding spec INV-11): the one trust boundary
where Pydantic validates untrusted sandbox-produced JSON. No infra needed."""

from __future__ import annotations

import json

import pytest
from schemas.findings import (
    UntrustedFindingsError,
    deserialize_finding,
    parse_engine_result,
    serialize_engine_result,
    serialize_finding,
)
from skillscan_core import (
    DetectionCategory,
    EngineCapability,
    EngineMetadata,
    EngineResult,
    EngineStatus,
    Finding,
    ScanMode,
    Severity,
)


def _valid_engine_result() -> EngineResult:
    # NOTE: "检测到 eval() 调用" / "static.eval_call" below are inert string
    # literals naming the finding that skillscan_core's real StaticKeywordEngine
    # (libs/skillscan_core/engines.py) emits when it finds eval( in scanned
    # content - nothing here calls eval() itself.
    metadata = EngineMetadata(
        name="static-keyword",
        version="1.0.0",
        ruleset_digest="a" * 64,
        capabilities=frozenset({EngineCapability.STATIC}),
    )
    finding = Finding(
        rule_id="static.eval_call",
        test_item_id="static.eval_call",
        category=DetectionCategory.CODE,
        title="检测到 eval() 调用",
        severity=Severity.HIGH,
        confidence=1.0,
        source_engine="static-keyword",
        source_capability=EngineCapability.STATIC,
        file_path="skill.py",
        start_line=3,
        snippet_hash="b" * 64,
    )
    return EngineResult(
        engine=metadata,
        findings=(finding,),
        status=EngineStatus.OK,
        scan_mode=ScanMode.STATIC,
    )


class TestRoundTrip:
    def test_serialize_then_parse_recovers_equivalent_result(self) -> None:
        original = _valid_engine_result()
        raw = json.dumps(serialize_engine_result(original)).encode("utf-8")
        recovered = parse_engine_result(raw)
        assert recovered.engine.name == original.engine.name
        assert recovered.status == original.status
        assert len(recovered.findings) == 1
        assert recovered.findings[0].rule_id == "static.eval_call"
        assert recovered.findings[0].severity == Severity.HIGH

    def test_serialize_finding_matches_engine_result_finding_shape(self) -> None:
        original = _valid_engine_result()
        as_dict = serialize_engine_result(original)
        assert as_dict["findings"][0] == serialize_finding(original.findings[0])

    def test_deserialize_finding_recovers_original(self) -> None:
        original = _valid_engine_result().findings[0]
        recovered = deserialize_finding(serialize_finding(original))
        assert recovered == original


class TestFailClosedOnSchemaViolation:
    def test_malformed_json_raises(self) -> None:
        with pytest.raises(UntrustedFindingsError):
            parse_engine_result(b"not json at all {{{")

    def test_missing_required_field_raises(self) -> None:
        payload = json.dumps({"status": "ok", "scan_mode": "static"}).encode("utf-8")
        with pytest.raises(UntrustedFindingsError):
            parse_engine_result(payload)

    def test_unknown_severity_value_raises(self) -> None:
        original = serialize_engine_result(_valid_engine_result())
        original["findings"][0]["severity"] = 999
        with pytest.raises(UntrustedFindingsError):
            parse_engine_result(json.dumps(original).encode("utf-8"))

    def test_confidence_out_of_range_raises(self) -> None:
        original = serialize_engine_result(_valid_engine_result())
        original["findings"][0]["confidence"] = 1.5
        with pytest.raises(UntrustedFindingsError):
            parse_engine_result(json.dumps(original).encode("utf-8"))

    def test_plaintext_snippet_hash_raises_domain_invariant_violation(self) -> None:
        # SECURITY (INV-9): Finding.__post_init__ rejects a non-hex-digest
        # snippet_hash - this is a domain-model violation, not a schema one,
        # and parse_engine_result must fail-closed on it identically.
        original = serialize_engine_result(_valid_engine_result())
        original["findings"][0]["snippet_hash"] = "plaintext evidence, not a digest"
        with pytest.raises(UntrustedFindingsError):
            parse_engine_result(json.dumps(original).encode("utf-8"))

    def test_none_severity_finding_raises_domain_invariant_violation(self) -> None:
        original = serialize_engine_result(_valid_engine_result())
        original["findings"][0]["severity"] = int(Severity.NONE)
        with pytest.raises(UntrustedFindingsError):
            parse_engine_result(json.dumps(original).encode("utf-8"))

    def test_requires_network_engine_raises_domain_invariant_violation(self) -> None:
        original = serialize_engine_result(_valid_engine_result())
        original["engine"]["requires_network"] = True
        with pytest.raises(UntrustedFindingsError):
            parse_engine_result(json.dumps(original).encode("utf-8"))

    def test_deserialize_finding_malformed_dict_raises(self) -> None:
        with pytest.raises(UntrustedFindingsError):
            deserialize_finding({"not": "a valid finding"})
