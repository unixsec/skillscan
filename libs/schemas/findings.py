"""Untrusted-input Pydantic schema for sandbox-produced findings JSON (coding
spec §8/§9, INV-11).

SECURITY: this is the ONE place in the whole system where Pydantic validates
security-relevant data at a trust boundary (coding spec §2: "仅 API/外部数据边界
层校验;核心域不用" - only the API/external-data boundary validates with
Pydantic, the core domain does not). Everything a sandboxed engine writes to
the blob store's `findings/<scan_id>/<engine>.json` prefix is untrusted, even
though the engine itself is a vetted OSS tool - the *content* being scanned is
adversarial and could influence what the engine emits. Any schema violation
here means that engine's result is treated as unusable (fail-closed), never
partially trusted.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, ValidationError
from skillscan_core import (
    DetectionCategory,
    EngineCapability,
    EngineMetadata,
    EngineResult,
    EngineStatus,
    Finding,
    ScanMode,
    Severity,
    TrifectaSignal,
)

# BOUNDS FOR VALUES THAT REACH A TYPED COLUMN (2026-07-29, milestone C
# correctness review N-2). MySQL runs in strict mode, so a value that does not
# fit its column is an ERROR, not a silent truncation - and both writes below
# share a transaction whose rollback takes real work with it. An unbounded
# field here is therefore not a cosmetic gap: it is a remote input that can
# abort a database transaction.
#
# WHY THE BOUND IS THE COLUMN'S CAPACITY AND NOT A SEMANTIC LIMIT. "No engine
# should take more than an hour" and "no rule_id is longer than 40 characters"
# are both true today and both policy judgements that would start rejecting
# legitimate data the moment either stopped being true. The column width is a
# hard fact about where the value is going, and a value that cannot be stored
# is unusable no matter how plausible it looks.
#
# WHY REJECT RATHER THAN CLAMP, unlike `aggregate._truncate_error`'s
# truncation of the sibling `error` column. `error` is free text with no valid
# maximum - a long error message is legitimate and losing its tail costs
# nothing. These two are not: a duration outside INT and a rule_id that could
# never be allowlisted are both statements a working engine does not make, and
# this module's whole posture (see the docstring above) is that an engine
# result which violates the schema is unusable, never partially trusted.

#: `scan_engine_health.analyze_duration_ms` is `INT NULL` (migration
#: d5a1c07f9e42), written inside the transaction that scores the scan. A blob
#: claiming more than this rolled back `ScanResultRow` and `state='scored'`
#: with it, so the scan got no verdict at all.
_MAX_ANALYZE_DURATION_MS = 2_147_483_647

#: `allowlist.rule_id` is `VARCHAR(128)` (migration 1d6112d0e997). A finding's
#: rule_id is not written to a typed column by the scan path - it lands in
#: `scan_result.findings`, a JSON column - but `gate.router._known_rule_ids`
#: reads those rule_ids straight back out and offers them as the allowlist
#: form's candidates, precisely so an operator waives a rule that really fired.
#: Granting one over-length is then a 500 with the audit intent rolled back
#: alongside it. Two engines build rule_ids from model output with no cap of
#: their own (`engine_runner/adapters/aig.py`'s `risk_type` tag,
#: `skillspector.py`'s SARIF `ruleId`), and the scanned content is what steers
#: it. Longest rule_id in the tree today is 31 characters.
_MAX_RULE_ID_CHARS = 128


class FindingDTO(BaseModel):
    rule_id: str = Field(max_length=_MAX_RULE_ID_CHARS)
    test_item_id: str
    category: DetectionCategory
    title: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    source_engine: str
    source_capability: EngineCapability
    trifecta_signals: list[TrifectaSignal] = Field(default_factory=list)
    file_path: str | None = None
    start_line: int | None = None
    snippet_hash: str | None = None
    evidence_redacted: str = ""


class EngineMetadataDTO(BaseModel):
    name: str
    version: str
    ruleset_digest: str
    capabilities: list[EngineCapability]
    requires_network: bool = False
    requires_llm: bool = False
    deterministic: bool = True


class EngineResultDTO(BaseModel):
    engine: EngineMetadataDTO
    status: EngineStatus
    scan_mode: ScanMode
    llm_used: bool = False
    error: str | None = None
    # Milestone C Task 7. Same interval as `common.airlock.ResultMessage.
    # analyze_duration_ms` (that field's comment is the authoritative
    # definition) and written from the same variable in the same loop
    # iteration, so the blob and the stream entry cannot disagree.
    #
    # WHY IT IS ALSO HERE and not only on the stream: the stream entry is
    # consumed once and ACKed away, while this blob is the durable per-engine
    # record. Whether the shipped per-engine timeout defaults are wrong (they
    # sum to 480s against a 300s scan deadline - milestone C Task 4) is a
    # question you answer by sweeping a corpus of past scans, which requires
    # the number to have outlived the message that carried it.
    #
    # Optional with no default value on the wire: a blob written by a
    # pre-Task-7 engine-runner image simply has no such key and still parses.
    # `parse_engine_result` does not surface it (`skillscan_core.EngineResult`
    # is a deterministic domain object and a stopwatch reading has no business
    # in it); a reader that wants the timing validates with this DTO directly.
    #
    # `le` as well as `ge` (2026-07-29, review N-2): the lower bound was here
    # from the start and the upper one was not, which left the only half that
    # could abort a transaction unguarded. See `_MAX_ANALYZE_DURATION_MS`.
    analyze_duration_ms: int | None = Field(default=None, ge=0, le=_MAX_ANALYZE_DURATION_MS)
    findings: list[FindingDTO] = Field(default_factory=list)


class UntrustedFindingsError(Exception):
    """SECURITY: raised for ANY schema violation - callers must treat the
    originating engine's result as unusable (fail-closed), never partially
    accept whatever findings happened to parse."""


def parse_engine_result(raw_json: bytes | str) -> EngineResult:
    """SECURITY: the single entry point for turning sandbox-produced bytes into
    a trusted `skillscan_core.EngineResult`. Any failure - malformed JSON,
    schema violation, or a domain-model invariant violation inside
    `Finding.__post_init__`/`EngineMetadata.__post_init__` (e.g. severity<LOW,
    requires_network=True) - raises `UntrustedFindingsError` rather than
    returning a partially-valid result.
    """
    return parse_engine_result_with_duration(raw_json)[0]


def parse_engine_result_with_duration(raw_json: bytes | str) -> tuple[EngineResult, int | None]:
    """`parse_engine_result` plus the blob's `analyze_duration_ms` (milestone C
    Task 7), from ONE validation pass over the same bytes.

    WHY A SECOND ENTRY POINT rather than putting the duration on
    `EngineResult`: `skillscan_core.EngineResult` is a deterministic domain
    object, and a stopwatch reading is not part of what the gate adjudicates -
    two runs of the same engine over the same content must produce equal
    `EngineResult`s. So the timing leaves through a separate return value
    instead of a domain field.

    The alternative - having the health-capture path call `EngineResultDTO`
    itself after `parse_engine_result` had already run - would validate the
    same untrusted bytes TWICE against two independently-evolving call sites.
    Two validations of one input is how a reader ends up trusting a shape the
    other reader rejected; there is exactly one here.

    `None` means NOT MEASURED (a blob written by a pre-Task-7 engine-runner
    image), and is never conflated with `0`, which is a real measurement - the
    monolith's in-process floor engines genuinely complete in 0-1ms.
    """
    try:
        dto = EngineResultDTO.model_validate_json(raw_json)
    except ValidationError as exc:
        raise UntrustedFindingsError(f"engine result failed schema validation: {exc}") from exc

    try:
        metadata = EngineMetadata(
            name=dto.engine.name,
            version=dto.engine.version,
            ruleset_digest=dto.engine.ruleset_digest,
            capabilities=frozenset(dto.engine.capabilities),
            requires_network=dto.engine.requires_network,
            requires_llm=dto.engine.requires_llm,
            deterministic=dto.engine.deterministic,
        )
        findings = tuple(
            Finding(
                rule_id=f.rule_id,
                test_item_id=f.test_item_id,
                category=f.category,
                title=f.title,
                severity=f.severity,
                confidence=f.confidence,
                source_engine=f.source_engine,
                source_capability=f.source_capability,
                trifecta_signals=frozenset(f.trifecta_signals),
                file_path=f.file_path,
                start_line=f.start_line,
                snippet_hash=f.snippet_hash,
                evidence_redacted=f.evidence_redacted,
            )
            for f in dto.findings
        )
        result = EngineResult(
            engine=metadata,
            findings=findings,
            status=dto.status,
            scan_mode=dto.scan_mode,
            llm_used=dto.llm_used,
            error=dto.error,
        )
    except ValueError as exc:
        # SECURITY: a domain-model __post_init__ rejection (e.g. severity<LOW,
        # requires_network=True) is exactly as untrusted as a schema violation.
        raise UntrustedFindingsError(f"engine result violated a domain invariant: {exc}") from exc
    return result, dto.analyze_duration_ms


def serialize_finding(f: Finding) -> dict[str, Any]:
    return {
        "rule_id": f.rule_id,
        "test_item_id": f.test_item_id,
        "category": f.category.value,
        "title": f.title,
        "severity": int(f.severity),
        "confidence": f.confidence,
        "source_engine": f.source_engine,
        "source_capability": f.source_capability.value,
        "trifecta_signals": [s.value for s in f.trifecta_signals],
        "file_path": f.file_path,
        "start_line": f.start_line,
        "snippet_hash": f.snippet_hash,
        "evidence_redacted": f.evidence_redacted,
    }


def deserialize_finding(d: dict[str, Any]) -> Finding:
    """Inverse of serialize_finding - reconstructs a Finding from its stored
    JSON shape (e.g. a ScanResultRow.findings row), for callers that need to
    recompute something from a scan's already-decided findings rather than
    treat them as opaque JSON. Same fail-closed posture as parse_engine_result:
    any schema violation raises UntrustedFindingsError rather than silently
    accepting a partially-valid finding.
    """
    try:
        dto = FindingDTO.model_validate(d)
    except ValidationError as exc:
        raise UntrustedFindingsError(f"finding failed schema validation: {exc}") from exc
    try:
        return Finding(
            rule_id=dto.rule_id,
            test_item_id=dto.test_item_id,
            category=dto.category,
            title=dto.title,
            severity=dto.severity,
            confidence=dto.confidence,
            source_engine=dto.source_engine,
            source_capability=dto.source_capability,
            trifecta_signals=frozenset(dto.trifecta_signals),
            file_path=dto.file_path,
            start_line=dto.start_line,
            snippet_hash=dto.snippet_hash,
            evidence_redacted=dto.evidence_redacted,
        )
    except ValueError as exc:
        raise UntrustedFindingsError(f"finding violated a domain invariant: {exc}") from exc


def serialize_engine_result(
    result: EngineResult, *, analyze_duration_ms: int | None = None
) -> dict[str, Any]:
    """Inverse of parse_engine_result - used by the real dispatch loops, and by
    test fixtures / reference engines, to produce the bytes a sandboxed worker
    writes to `findings/<scan_id>/<engine>.json`.

    `analyze_duration_ms` (milestone C Task 7) is the wall-clock span of the
    `engine.analyze()` call that produced `result`; see
    `EngineResultDTO.analyze_duration_ms`. The key is OMITTED when it is None
    rather than written as null, so every existing caller - the dead-letter
    markers and every fixture - keeps producing byte-identical blobs, and so a
    reader can never mistake "not measured" for a recorded value.
    """
    payload: dict[str, Any] = {
        "engine": {
            "name": result.engine.name,
            "version": result.engine.version,
            "ruleset_digest": result.engine.ruleset_digest,
            "capabilities": [c.value for c in result.engine.capabilities],
            "requires_network": result.engine.requires_network,
            "requires_llm": result.engine.requires_llm,
            "deterministic": result.engine.deterministic,
        },
        "status": result.status.value,
        "scan_mode": result.scan_mode.value,
        "llm_used": result.llm_used,
        "error": result.error,
        "findings": [serialize_finding(f) for f in result.findings],
    }
    if analyze_duration_ms is not None:
        payload["analyze_duration_ms"] = int(analyze_duration_ms)
    return payload
