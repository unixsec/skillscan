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


class FindingDTO(BaseModel):
    rule_id: str
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
        return EngineResult(
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


def serialize_engine_result(result: EngineResult) -> dict[str, Any]:
    """Inverse of parse_engine_result - used by test fixtures / reference
    engines to produce the bytes a real sandboxed worker would write."""
    return {
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
