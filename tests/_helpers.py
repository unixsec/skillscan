"""Shared construction helpers for the M1 kernel test suite.

Not itself a test module - `unittest discover` only collects test*.py, so this
file is importable by the real test modules without being collected as one.
"""

from __future__ import annotations

from collections.abc import Iterable

from skillscan_core import (
    DetectionCategory,
    EngineCapability,
    EngineMetadata,
    EngineResult,
    EngineStatus,
    Finding,
    GatePolicy,
    ScanMode,
    ScanResult,
    Severity,
    aggregate,
)

DUMMY_CONTENT_HASH = "0" * 64


def make_finding(
    *,
    rule_id: str,
    severity: Severity = Severity.MEDIUM,
    confidence: float = 1.0,
    capability: EngineCapability = EngineCapability.STATIC,
    category: DetectionCategory = DetectionCategory.CODE,
    trifecta_signals: frozenset = frozenset(),
    file_path: str | None = "scripts/run.sh",
    start_line: int | None = 1,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        test_item_id=rule_id,
        category=category,
        title=f"finding {rule_id}",
        severity=severity,
        confidence=confidence,
        source_engine="test-engine",
        source_capability=capability,
        trifecta_signals=trifecta_signals,
        file_path=file_path,
        start_line=start_line,
    )


def make_engine_metadata(
    name: str = "static-keyword",
    *,
    version: str = "1.0.0",
    ruleset_digest: str = "digest",
    capabilities: frozenset = frozenset({EngineCapability.STATIC}),
) -> EngineMetadata:
    return EngineMetadata(
        name=name, version=version, ruleset_digest=ruleset_digest, capabilities=capabilities
    )


def scan_result_from_findings(
    findings: Iterable[Finding],
    policy: GatePolicy,
    *,
    content_hash_value: str = DUMMY_CONTENT_HASH,
    max_findings: int = 5000,
    engine_name: str = "static-keyword",
    engine_status: EngineStatus = EngineStatus.OK,
) -> ScanResult:
    metadata = make_engine_metadata(engine_name)
    engine_result = EngineResult(
        engine=metadata,
        findings=tuple(findings),
        status=engine_status,
        scan_mode=ScanMode.STATIC,
    )
    return aggregate(content_hash_value, [engine_result], policy, max_findings=max_findings)


def default_policy(**overrides: object) -> GatePolicy:
    params: dict[str, object] = dict(
        version="policy-v1", required_engines=frozenset({"static-keyword"})
    )
    params.update(overrides)
    return GatePolicy(**params)  # type: ignore[arg-type]
