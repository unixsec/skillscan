"""Deterministic aggregation and scoring (coding spec M1, §5.3 — INV-4/INV-5).

Pure stdlib, zero runtime dependencies.
"""

from __future__ import annotations

from collections.abc import Iterable

from skillscan_core.models import (
    ALL_TRIFECTA_SIGNALS,
    EngineResult,
    Finding,
    GatePolicy,
    ScanResult,
    Severity,
    TrifectaSignal,
)


def evaluate_findings(
    findings: Iterable[Finding],
    min_confidence: float = 0.0,
    hard_gate_rules: frozenset[str] = frozenset(),
) -> tuple[Severity, float, bool, tuple[str, ...]]:
    findings = tuple(findings)

    # SECURITY: hard-gate hits match the FULL set, independent of min_confidence - a
    # confidence filter must never be able to switch off a hard gate.
    hard_gate_hits = tuple(sorted({f.rule_id for f in findings if f.rule_id in hard_gate_rules}))

    counted = tuple(f for f in findings if f.confidence >= min_confidence)

    severity = max((f.severity for f in counted), default=Severity.NONE)
    confidence_at_max = max((f.confidence for f in counted if f.severity == severity), default=0.0)

    trifecta_signals: set[TrifectaSignal] = set()
    for f in counted:
        trifecta_signals |= f.trifecta_signals
    # SECURITY (INV-4): fatal trifecta (all three signals co-occurring) forces
    # severity >= CRITICAL regardless of any individual finding's own severity.
    trifecta_present = ALL_TRIFECTA_SIGNALS.issubset(trifecta_signals)
    if trifecta_present and severity < Severity.CRITICAL:
        severity = Severity.CRITICAL

    return severity, confidence_at_max, trifecta_present, hard_gate_hits


def _dedup(findings: Iterable[Finding]) -> tuple[tuple[Finding, ...], frozenset[str]]:
    # SECURITY: partition by (dedup_key, is_llm_sourced) so an LLM finding can never
    # shadow/replace a deterministic finding at the same key - that would be a
    # laundering channel for washing out real findings via a lower-severity LLM re-finding.
    best: dict[tuple[object, ...], Finding] = {}
    # SECURITY: track which rule_ids had a real collision (2+ findings at the same
    # key) - gate.decide() uses this to check whether the finding(s) dedup
    # dropped are already covered by an active allowlist waiver, rather than
    # forcing a severity/trifecta restoration blind to waiver state.
    collided_rule_ids: set[str] = set()
    for f in findings:
        key = (f.dedup_key, f.is_llm_sourced)
        current = best.get(key)
        if current is not None:
            collided_rule_ids.add(f.rule_id)
        if current is None or (f.severity, f.confidence) > (current.severity, current.confidence):
            best[key] = f
    deduped = tuple(sorted(best.values(), key=lambda f: (f.dedup_key, f.is_llm_sourced)))
    return deduped, frozenset(collided_rule_ids)


def aggregate(
    content_hash: str,
    engine_results: Iterable[EngineResult],
    policy: GatePolicy,
    *,
    min_confidence: float = 0.0,
    max_findings: int = 5000,
) -> ScanResult:
    engine_results = tuple(engine_results)

    # SECURITY: defensive second rejection of requires_network engines - EngineMetadata
    # already forbids constructing one; this is defense in depth against that guard
    # somehow being bypassed upstream (e.g. deserialized data).
    safe_results = tuple(r for r in engine_results if not r.engine.requires_network)

    present_and_usable = {r.engine.name for r in safe_results if r.usable}
    missing_or_failed = tuple(
        sorted(name for name in policy.required_engines if name not in present_and_usable)
    )
    required_ok = not missing_or_failed

    usable_results = tuple(r for r in safe_results if r.usable)
    all_findings = [f for r in usable_results for f in r.findings]
    # Worst-first: highest severity, then highest confidence.
    all_findings.sort(key=lambda f: (-int(f.severity), -f.confidence))

    # SECURITY (INV-5): compute hard-gate hits and trifecta on the FULL, pre-cap set so
    # a finding flood can't truncate them out of visibility.
    pre_cap_hard_gate_hits = frozenset(
        f.rule_id for f in all_findings if f.rule_id in policy.hard_gate_rules
    )
    pre_cap_counted = [f for f in all_findings if f.confidence >= min_confidence]
    pre_cap_trifecta_signals: set[TrifectaSignal] = set()
    for f in pre_cap_counted:
        pre_cap_trifecta_signals |= f.trifecta_signals
    pre_cap_trifecta_present = ALL_TRIFECTA_SIGNALS.issubset(pre_cap_trifecta_signals)

    findings_capped = len(all_findings) > max_findings
    capped_findings = all_findings[:max_findings] if findings_capped else all_findings

    deduped, collided_rule_ids = _dedup(capped_findings)

    severity, confidence_at_max, _trifecta_postcap, hard_gate_hits_postcap = evaluate_findings(
        deduped, min_confidence, policy.hard_gate_rules
    )

    final_hard_gate_hits = tuple(sorted(pre_cap_hard_gate_hits | set(hard_gate_hits_postcap)))
    final_trifecta_present = pre_cap_trifecta_present or _trifecta_postcap
    if final_trifecta_present and severity < Severity.CRITICAL:
        severity = Severity.CRITICAL

    engine_provenance = tuple(
        sorted((r.engine.name, r.engine.version, r.engine.ruleset_digest) for r in safe_results)
    )

    return ScanResult(
        content_hash=content_hash,
        severity=severity,
        confidence_at_max=confidence_at_max,
        trifecta_present=final_trifecta_present,
        hard_gate_hits=final_hard_gate_hits,
        findings=deduped,
        engine_provenance=engine_provenance,
        findings_capped=findings_capped,
        required_ok=required_ok,
        missing_or_failed_required=missing_or_failed,
        dedup_collision_rule_ids=collided_rule_ids,
    )
