"""Deterministic aggregation and scoring (coding spec M1, §5.3 — INV-4/INV-5).

Pure stdlib, zero runtime dependencies.
"""

from __future__ import annotations

import math
from collections.abc import Iterable

from skillscan_core.models import (
    ALL_TRIFECTA_SIGNALS,
    CategoryWeights,
    EngineResult,
    Finding,
    GatePolicy,
    ScanResult,
    Severity,
    TrifectaSignal,
    Verdict,
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

    # SECURITY: captured BEFORE truncation, same reasoning as pre_cap_hard_gate_hits/
    # pre_cap_trifecta_present above - a finding flood must not make the true count
    # unrecoverable, only the full findings list.
    findings_total = len(all_findings)
    findings_capped = findings_total > max_findings
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
        findings_total=findings_total,
        required_ok=required_ok,
        missing_or_failed_required=missing_or_failed,
        dedup_collision_rule_ids=collided_rule_ids,
    )


_SCORE_BAND: dict[Verdict, tuple[int, int]] = {
    Verdict.BLOCK: (0, 39),
    Verdict.REVIEW: (40, 74),
    Verdict.PASS: (75, 100),
}

_SEVERITY_PENALTY_WEIGHT: dict[Severity, float] = {
    Severity.NONE: 0.0,
    Severity.LOW: 3.0,
    Severity.MEDIUM: 8.0,
    Severity.HIGH: 18.0,
    Severity.CRITICAL: 35.0,
}

_DEFAULT_WEIGHTS = CategoryWeights()


def security_score(
    verdict: Verdict,
    findings: Iterable[Finding],
    *,
    pin_to_floor: bool = False,
    weights: CategoryWeights = _DEFAULT_WEIGHTS,
) -> int:
    """0-100 advisory score, deterministically derived from an ALREADY-DECIDED
    verdict (2026-07-24 scoring design doc). NEVER an input to decide() -
    verdict/band selection always happens first; this only positions the
    score within that band, so a score can never contradict (or be used to
    relitigate) the verdict that produced it.

    Because the band is chosen first, comparing scores ACROSS verdicts is
    meaningless: a BLOCK with one CRITICAL scores below a REVIEW with ten
    HIGHs, by construction. The score ranks packages within a verdict, not
    between verdicts.

    `pin_to_floor` puts the score at the band floor. Three situations call for
    it: a hard-gate hit (the unwaivable, most-severe class of finding - INV-3
    parity); a fail-closed verdict, where the scan could not be completed at
    all (rejected archive, missing required engine); and a non-PASS verdict
    reached with an EMPTY `findings` argument even though the verdict itself
    says something is wrong - e.g. gate.decide()'s dedup-collision signal
    restoration (INV-4/INV-5) or its flood-cap-forces-REVIEW step (INV-5) can
    push the verdict up from information outside the scored set, leaving
    nothing in `findings` to price the severity that actually produced it. All
    three carry the same shape: we know LESS about this package than about one
    with real findings we can see and score, so letting it land at the band's
    top - which is what an empty finding set used to produce - was backwards.

    The penalty saturates rather than accumulating linearly: a linear sum hit
    the band floor at 9 LOW findings (PASS) or 2 HIGH findings (REVIEW) and
    stayed there, so the score stopped discriminating exactly where it mattered
    most. `band_width * (1 - exp(-raw/K))` with K = band width is strictly
    increasing, never reaches the floor, and keeps near-linear behaviour for
    small finding counts.
    """
    band_min, band_max = _SCORE_BAND[verdict]
    if pin_to_floor:
        return band_min
    raw_penalty = sum(
        _SEVERITY_PENALTY_WEIGHT[f.severity] * f.confidence * weights.for_category(f.category)
        for f in findings
    )
    band_width = band_max - band_min
    if band_width <= 0:  # defensive: a degenerate band would divide by zero below
        return band_min
    penalty = band_width * (1.0 - math.exp(-raw_penalty / band_width))
    # The clamp is mathematically unnecessary now (penalty < band_width always)
    # but kept as a backstop against a mis-configured weight or a future band.
    return max(band_min, min(band_max, round(band_max - penalty)))
