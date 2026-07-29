"""Tests for `schemas.findings` (coding spec INV-11): the one trust boundary
where Pydantic validates untrusted sandbox-produced JSON. No infra needed."""

from __future__ import annotations

import json

import pytest
from pydantic import BaseModel, Field
from schemas.findings import (
    EngineMetadataDTO,
    EngineResultDTO,
    FindingDTO,
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


class _PreTask7EngineResultDTO(BaseModel):
    """A frozen copy of `EngineResultDTO` as it stood BEFORE milestone C Task 7.

    The findings blob is written by `services/engine_runner` and read by the
    monolith - two independently deployed images - so a rollout always has a
    window where the writer knows a key the reader does not. Validating a NEW
    blob against this is the only way to say anything true about the image
    still running in the other pod; asserting "unknown keys are ignored"
    against the current model would just be testing the current model.
    """

    engine: EngineMetadataDTO
    status: EngineStatus
    scan_mode: ScanMode
    llm_used: bool = False
    error: str | None = None
    findings: list[FindingDTO] = Field(default_factory=list)


class TestAnalyzeDurationWireCompatibility:
    """Milestone C Task 7 - the blob half of the per-engine timing.

    Interval: the wall-clock span of one `engine.analyze()` call. Definition
    lives on `common.airlock.ResultMessage.analyze_duration_ms`; the stream half
    of these compatibility checks lives in `tests/test_airlock_result_duration.py`.
    """

    def test_omitted_entirely_when_not_measured(self) -> None:
        # Not `"analyze_duration_ms": null`: the dead-letter markers and every
        # existing fixture must keep producing byte-identical blobs, and an
        # explicit null is one more shape old readers were never shown.
        assert "analyze_duration_ms" not in serialize_engine_result(_valid_engine_result())

    def test_measured_value_is_emitted_and_validates(self) -> None:
        raw = json.dumps(
            serialize_engine_result(_valid_engine_result(), analyze_duration_ms=1234)
        ).encode("utf-8")
        assert EngineResultDTO.model_validate_json(raw).analyze_duration_ms == 1234

    def test_zero_is_kept_because_zero_is_a_real_measurement(self) -> None:
        blob = serialize_engine_result(_valid_engine_result(), analyze_duration_ms=0)
        assert blob["analyze_duration_ms"] == 0

    def test_old_blob_without_the_key_still_parses_to_none(self) -> None:
        # New reader, old writer. None, never 0 - "not measured" must not be
        # indistinguishable from "finished instantly".
        raw = json.dumps(serialize_engine_result(_valid_engine_result())).encode("utf-8")
        assert EngineResultDTO.model_validate_json(raw).analyze_duration_ms is None
        # ...and the domain object it becomes is unaffected either way.
        assert parse_engine_result(raw).status is EngineStatus.OK

    def test_new_blob_is_still_readable_by_the_pre_task_7_schema(self) -> None:
        # Old reader, new writer: the mixed-version window in the other
        # direction. A `model_config = ConfigDict(extra="forbid")` on the old
        # DTO would make this raise, and every sandbox engine's findings would
        # be discarded fail-closed for the length of the rollout.
        raw = json.dumps(
            serialize_engine_result(_valid_engine_result(), analyze_duration_ms=77)
        ).encode("utf-8")
        recovered = _PreTask7EngineResultDTO.model_validate_json(raw)
        assert recovered.status is EngineStatus.OK
        assert len(recovered.findings) == 1

    def test_negative_duration_is_rejected_fail_closed(self) -> None:
        # The blob is an untrusted-input boundary (INV-11), unlike the stream
        # entry - a bad value here means the WRITER is wrong, and this file's
        # whole posture is that a schema violation makes the result unusable
        # rather than partially trusted. Costs nothing in practice: the field
        # is optional, so no old blob can trip it.
        blob = serialize_engine_result(_valid_engine_result())
        blob["analyze_duration_ms"] = -1
        with pytest.raises(UntrustedFindingsError):
            parse_engine_result(json.dumps(blob).encode("utf-8"))

    def test_non_integer_duration_is_rejected_fail_closed(self) -> None:
        blob = serialize_engine_result(_valid_engine_result())
        blob["analyze_duration_ms"] = "instantly"
        with pytest.raises(UntrustedFindingsError):
            parse_engine_result(json.dumps(blob).encode("utf-8"))


class TestBoundedByTheDestinationColumn:
    """Every value read out of a findings blob that reaches a TYPED column must
    be bounded here (2026-07-29, milestone C correctness review N-2).

    THE FAILURE THIS PREVENTS is not a bad number in a report. MySQL runs in
    strict mode, so an out-of-range or over-length value is an ERROR, and both
    destinations below are written inside a transaction that also carries
    `ScanResultRow` and `scan_job.state = 'scored'` (for the duration) or the
    `audit_intent` recording the grant (for the rule_id). The rollback takes
    those with it, so the visible symptom is a scan with no verdict, or an
    allowlist grant that silently does not exist - never a message about a
    number being too large.

    `ge=0` was here from the start and `le=` was not, which is the shape worth
    naming: half a bound reads as a bounded field at a glance, and the missing
    half was the only one that could abort a transaction.

    NOT bounded here, deliberately, and recorded so the omission is a decision:
    `finding_count` (`len(findings)` -> INT) and `findings_total` need ~2^31
    findings in one blob, i.e. hundreds of GB that `blobstore.get` reads into
    memory first - the process dies long before the column does. And the
    per-finding text fields (`title`, `evidence_redacted`, `file_path`) reach
    only JSON columns; their risk is total blob size against
    `max_allowed_packet`, which is a blob-size limit to impose on the read, not
    a per-field bound to impose here.
    """

    def test_duration_beyond_the_int_column_is_rejected_fail_closed(self) -> None:
        """`scan_engine_health.analyze_duration_ms` is INT. One over its max is
        the whole bug: it aborted the scoring transaction, and the scan was
        left permanently undecided while the results stream retried forever."""
        blob = serialize_engine_result(_valid_engine_result())
        blob["analyze_duration_ms"] = 2_147_483_648
        with pytest.raises(UntrustedFindingsError):
            parse_engine_result(json.dumps(blob).encode("utf-8"))

    def test_the_largest_storable_duration_is_still_accepted(self) -> None:
        """The bound is the column's capacity, so the boundary value itself
        must pass - an off-by-one here would reject a storable measurement."""
        blob = serialize_engine_result(_valid_engine_result())
        blob["analyze_duration_ms"] = 2_147_483_647
        parse_engine_result(json.dumps(blob).encode("utf-8"))

    def test_an_over_length_rule_id_is_rejected_fail_closed(self) -> None:
        """`allowlist.rule_id` is VARCHAR(128), and `gate.router._known_rule_ids`
        offers rule_ids read straight back out of these blobs as the allowlist
        form's candidates - so an engine that emits one longer than the column
        hands an operator a candidate whose grant can only 500. Two adapters
        build rule_ids out of model output with no cap of their own
        (`adapters/aig.py`, `adapters/skillspector.py`)."""
        blob = serialize_engine_result(_valid_engine_result())
        blob["findings"][0]["rule_id"] = "aig." + "x" * 125
        with pytest.raises(UntrustedFindingsError):
            parse_engine_result(json.dumps(blob).encode("utf-8"))

    def test_a_rule_id_exactly_the_column_width_is_accepted(self) -> None:
        blob = serialize_engine_result(_valid_engine_result())
        blob["findings"][0]["rule_id"] = "a" * 128
        result = parse_engine_result(json.dumps(blob).encode("utf-8"))
        assert result.findings[0].rule_id == "a" * 128

    def test_every_real_rule_id_in_the_tree_fits(self) -> None:
        """The bound must not be tighter than what this repo's own engines
        emit. Longest today is 31 characters; asserted against the real
        detector sources so a future rule that overshoots fails here rather
        than fail-closing that engine on a live deployment."""
        import re
        from pathlib import Path

        repo_root = Path(__file__).resolve().parents[3]
        pattern = re.compile(r'rule_id\s*=\s*f?"([^"{}]+)"')
        longest = ""
        for directory in ("libs", "services", "apps/monolith/modules"):
            for path in (repo_root / directory).rglob("*.py"):
                for match in pattern.finditer(path.read_text(encoding="utf-8")):
                    if len(match.group(1)) > len(longest):
                        longest = match.group(1)
        assert longest, "the source scan found no rule_id literals at all"
        assert len(longest) <= 128, longest
