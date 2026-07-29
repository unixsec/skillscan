"""Fail-closed gate decision (coding spec M1, §5.4). Pure function, no I/O.

Covers INV-1 (fail-closed), INV-2 (LLM monotonicity), INV-3 (hard-gate
unwaivable), INV-5 (flood cap can't PASS), INV-8 (four-eyes allowlist).
"""

from __future__ import annotations

from collections.abc import Iterable

from skillscan_core.models import (
    AllowlistEntry,
    Finding,
    GatePolicy,
    ScanResult,
    Severity,
    TrustTier,
    Verdict,
    VerdictResult,
)
from skillscan_core.scoring import evaluate_findings, security_score


def _classify(
    severity: Severity, confidence: float, policy: GatePolicy, tier: TrustTier
) -> Verdict:
    if severity >= policy.block_threshold(tier):
        return Verdict.BLOCK
    if severity >= policy.review_on_severity:
        return Verdict.REVIEW
    if severity >= Severity.LOW and confidence < policy.review_confidence:
        return Verdict.REVIEW
    return Verdict.PASS


def decide(
    scan_result: ScanResult,
    policy: GatePolicy,
    trust_tier: TrustTier,
    allowlist: Iterable[AllowlistEntry] = (),
    *,
    now: float,
    min_confidence: float = 0.0,
    skill_id: str | None = None,
) -> VerdictResult:
    """SECURITY (INV-7, milestone C Task 5): the scoring weights are read off
    `policy.category_weights` and are NOT a parameter of this function. They
    used to be one, defaulting to all-1.0, which meant a caller could score a
    verdict under weights no `policy_version` mentions - and `score` is a
    persisted field the INV-7 cache serves. With the policy as the only source,
    `GatePolicy.cache_policy_version` covers every weight that can reach a
    score. A caller that wants different weights builds a different policy,
    which is exactly the thing the cache key can see."""
    weights = policy.category_weights

    # SECURITY (INV-1): required engine missing/failed -> fail-closed, no exceptions.
    if not scan_result.required_ok:
        verdict = policy.fail_closed_verdict
        return VerdictResult(
            verdict=verdict,
            reasons=(
                "fail_closed:required_engine_missing_or_failed:"
                + ",".join(scan_result.missing_or_failed_required),
            ),
            policy_version=policy.version,
            effective_severity=scan_result.severity,
            trifecta_present=scan_result.trifecta_present,
            hard_gate_hits=scan_result.hard_gate_hits,
            score=security_score(
                verdict,
                scan_result.findings,
                # Fail-closed: the scan could not be completed, so we know less
                # about this package than about any package with real findings.
                # (Passing bool(hard_gate_hits) here was also meaningless - those
                # hits were computed from an incomplete finding set.)
                pin_to_floor=True,
                weights=weights,
            ),
        )

    # SECURITY (INV-3): hard-gate hits (recorded UNION recomputed against the CURRENT
    # policy) -> unconditional BLOCK. Never waivable inside the core, and this check
    # runs before allowlisting is even consulted.
    recomputed_hard_gate = frozenset(
        f.rule_id for f in scan_result.findings if f.rule_id in policy.hard_gate_rules
    )
    combined_hard_gate = frozenset(scan_result.hard_gate_hits) | recomputed_hard_gate
    if combined_hard_gate:
        return VerdictResult(
            verdict=Verdict.BLOCK,
            reasons=("hard_gate_hit:" + ",".join(sorted(combined_hard_gate)),),
            policy_version=policy.version,
            effective_severity=scan_result.severity,
            trifecta_present=scan_result.trifecta_present,
            hard_gate_hits=tuple(sorted(combined_hard_gate)),
            score=security_score(
                Verdict.BLOCK, scan_result.findings, pin_to_floor=True, weights=weights
            ),
        )

    allowlist = tuple(allowlist)

    def _rule_id_actively_waived(rule_id: str) -> bool:
        # SECURITY (INV-8): same "never waivable" floor as _is_waived below, but
        # checkable from a bare rule_id alone (dedup collisions only preserve the
        # rule_id of what they dropped, not the full Finding).
        if rule_id in policy.hard_gate_rules:
            return False
        return any(
            entry.rule_id == rule_id and entry.is_active(now, scan_result.content_hash, skill_id)
            for entry in allowlist
        )

    def _dedup_collisions_fully_waived() -> bool:
        # SECURITY: only report "yes" when EVERY rule_id involved in a dedup
        # collision this scan is confidently, actively waived - if even one
        # isn't, fall through to the conservative (signal-restoring) behavior.
        # Deliberately does NOT check allowlistable_max_severity (the dropped
        # finding's own severity is unknown - dedup discards everything but its
        # rule_id), so an unverifiable case correctly stays on the restoring
        # side, never the silently-more-permissive side.
        if not scan_result.dedup_collision_rule_ids:
            return False
        return all(
            _rule_id_actively_waived(rule_id) for rule_id in scan_result.dedup_collision_rule_ids
        )

    def _is_waived(finding: Finding) -> bool:
        # SECURITY (INV-8): hard-gate findings are never waivable, even with a
        # matching active entry (defense in depth - unreachable in practice once the
        # combined_hard_gate check above has passed, but kept explicit and enforced).
        if finding.rule_id in policy.hard_gate_rules:
            return False
        if finding.severity > policy.allowlistable_max_severity:
            return False
        return any(
            entry.waives(finding) and entry.is_active(now, scan_result.content_hash, skill_id)
            for entry in allowlist
        )

    effective = tuple(f for f in scan_result.findings if not _is_waived(f))
    non_llm_effective = tuple(f for f in effective if not f.is_llm_sourced)

    sev_all, conf_all, trif_all, _ = evaluate_findings(
        effective, min_confidence, policy.hard_gate_rules
    )
    sev_non_llm, conf_non_llm, _, _ = evaluate_findings(
        non_llm_effective, min_confidence, policy.hard_gate_rules
    )

    # SECURITY (INV-1/INV-4): scan_result.severity/trifecta_present are computed by
    # scoring.aggregate() on the FULL pre-cap, pre-dedup finding set and are the
    # authoritative floor for this scan - a _dedup() key collision can drop the one
    # finding that carried a trifecta-completing signal from scan_result.findings
    # entirely (dedup keeps only the higher-(severity,confidence) finding per key),
    # silently losing that signal for any recomputation based on scan_result.findings
    # alone. Detect this by recomputing on scan_result.findings BEFORE waiving is
    # applied: waiving is the only LEGITIMATE way to reduce a trifecta/severity signal
    # (spec §5.4 step 6 - "pre-cap trifecta 未被(经四眼加白)移除" - not removed via
    # four-eyes allowlisting - forces the uplift), so if the unwaived recomputation
    # already disagrees with ScanResult's own fields, that gap is dedup information
    # loss, not a policy decision, and must never be allowed to silently stand.
    sev_unwaived, _, trif_unwaived, _ = evaluate_findings(
        scan_result.findings, min_confidence, policy.hard_gate_rules
    )
    raw_dedup_signal_restored = (scan_result.trifecta_present and not trif_unwaived) or (
        scan_result.severity > sev_unwaived
    )
    # SECURITY: a dedup collision losing a trifecta/severity-carrying finding is
    # NOT itself a policy decision - restoring it is the correct default. But if
    # every rule_id that collided is already actively, legitimately (four-eyes)
    # waived, the restoration has nothing left to protect: whatever the dropped
    # finding was, a finding at that same rule_id was already going to be waived
    # out of `effective` regardless of dedup. Only in that fully-covered case do
    # we trust the waiver-aware sev_all/trif_all instead of force-restoring.
    dedup_signal_restored = raw_dedup_signal_restored and not _dedup_collisions_fully_waived()
    if dedup_signal_restored:
        if scan_result.trifecta_present and not trif_unwaived:
            trif_all = True
        if scan_result.severity > sev_unwaived:
            sev_all = max(sev_all, scan_result.severity)
        if trif_all and sev_all < Severity.CRITICAL:
            sev_all = Severity.CRITICAL

    # SECURITY (INV-2): LLM-sourced findings may only escalate a verdict, never
    # de-escalate it - take the stricter of (full effective set) vs (deterministic-only
    # subset). By construction sev_all/conf_all can never be weaker than the non-LLM
    # subset (MAX aggregation is monotonic under adding findings), but this recomputation
    # is deliberate: it makes the monotonicity property explicit, testable (INV-2), and
    # robust to future refactors rather than relying on an implicit proof.
    verdict_all = _classify(sev_all, conf_all, policy, trust_tier)
    verdict_non_llm = _classify(sev_non_llm, conf_non_llm, policy, trust_tier)
    verdict = max(verdict_all, verdict_non_llm)

    reasons = [f"severity_all={sev_all.name}", f"severity_non_llm={sev_non_llm.name}"]
    if dedup_signal_restored:
        reasons.append("dedup_collision_signal_restored_from_scan_result")

    # SECURITY (INV-5): a flood-capped result can never resolve to PASS.
    if scan_result.findings_capped and verdict == Verdict.PASS:
        verdict = Verdict.REVIEW
        reasons.append("findings_capped_forces_review")

    # SECURITY: verdict can be pushed to REVIEW/BLOCK by something outside
    # `effective` - dedup-collision signal restoration (dedup_signal_restored
    # above, INV-4/INV-5) or the flood cap (INV-5) - so `effective` can end up
    # EMPTY (every visible finding legitimately waived) while the verdict says
    # otherwise. Scoring that empty set with the ordinary per-finding formula
    # would land at the band's TOP (39 for BLOCK) - the same "empty findings
    # score highest" inversion the fail-closed/hard-gate branches above exist
    # to prevent, reached through this third path instead. Same fix: pin to
    # the floor, because the score has nothing in `effective` to price the
    # severity that actually produced this verdict. PASS is unaffected - an
    # empty finding set under a PASS verdict is genuinely clean and must still
    # score 100.
    pin_to_floor = verdict != Verdict.PASS and not effective
    return VerdictResult(
        verdict=verdict,
        reasons=tuple(reasons),
        policy_version=policy.version,
        effective_severity=sev_all,
        trifecta_present=trif_all,
        hard_gate_hits=(),
        score=security_score(verdict, effective, pin_to_floor=pin_to_floor, weights=weights),
    )
