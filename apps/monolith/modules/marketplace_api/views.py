"""Projection: internal scan data -> the marketplace-facing view (spec §5).

Pure functions only - no database, no network, no clock. Everything time-related
arrives as an argument. That is what lets the whole projection be tested without
MySQL/Redis, and it is also what keeps this file reviewable as the contract
itself rather than as glue.

SECURITY (spec §3.2): the field sets below are a WHITELIST. Adding an internal
field must not expose it; a projection that omits a field is a missing feature
(noticed), a filter that forgets one is a leak (not noticed).

2026-07-30 - THE CONTRACT IS NOW SKILL-KEYED AND BINARY. It was scan-keyed with a
three-valued `verdict`; the owner replaced both outright (no dual-run). What the
marketplace asks is "is skill X safe", and it gets one bit plus, when that bit is
false, the reasons - the same findings detail the console renders as 「发现明细」.

`is_safe` is TRUE only for `PASS` on a `COMPLETED` scan. Everything else - REVIEW,
a pending review, PENDING/RUNNING, a fail-closed BLOCK - is false. See
`classify_safety` for why that direction is a TIGHTENING of design spec §5.2's
recorded rejection of "二值判定折叠" and not a reversal of it.
"""

from __future__ import annotations

from typing import Any

from monolith.modules.orchestration.engine_health import (
    COVERAGE_BASIS_CURRENT_CONFIG,
    ScanEngineCoverage,
)

# Internal state machine: queued -> running -> scored -> decided/failed
# (orchestration.service.SCAN_STATES - the constant, which test_marketplace_
# views.py checks this mapping against). `scored` is an internal step
# with no external meaning; `failed` is NOT "no result" - _dead_letter_and_decide
# writes a signed BLOCK verdict, it just writes no findings blob. Reporting
# "FAILED" would invite a retry, and retrying a fail-closed BLOCK is exactly
# wrong (spec §5.1).
_STATUS_PROJECTION: dict[str, str] = {
    "queued": "PENDING",
    "running": "RUNNING",
    "scored": "RUNNING",
    "decided": "COMPLETED",
    "failed": "COMPLETED",
}

POLL_AFTER_MS: dict[str, int] = {
    "PENDING": 5_000,
    "RUNNING": 15_000,
    "COMPLETED": 0,
}


def project_status(internal_state: str) -> str:
    """Map an internal `scan_job.state` to the external status vocabulary.

    Raises on an unknown state rather than defaulting: a new internal state that
    silently projects to a plausible-looking external one is exactly the class of
    defect this milestone's predecessor kept finding (an unmapped value dressed
    up as a classified one).
    """
    try:
        return _STATUS_PROJECTION[internal_state]
    except KeyError:
        raise ValueError(f"unmapped internal scan state: {internal_state!r}") from None


SAFE_VERDICT = "PASS"
STATUS_COMPLETED = "COMPLETED"

# The machine-readable classification that accompanies `is_safe: false`. The bit
# stays strictly binary as required; this says WHICH KIND of unsafe, so an
# integrator can tell "we could not scan this" from "this is dangerous" without
# parsing prose and without a third verdict value creeping back into the contract.
#
# Deliberately a small closed set of CODES rather than `VerdictRow.reasons`.
# `reasons` never reached this projection anyway (narrowed at
# `gate.service.get_verdict_view`), and it is free-form text carrying engine names
# and rule ids - fine for an auditor, wrong as the branch key of a machine
# consumer that would then depend on its wording.
UNSAFE_NOT_YET_SCANNED = "not_yet_scanned"
UNSAFE_SCAN_INCOMPLETE = "scan_incomplete"
UNSAFE_HARD_GATE = "hard_gate"
UNSAFE_PENDING_REVIEW = "pending_review"
UNSAFE_CONTENT_FINDINGS = "content_findings"

UNSAFE_REASONS: frozenset[str] = frozenset(
    {
        UNSAFE_NOT_YET_SCANNED,
        UNSAFE_SCAN_INCOMPLETE,
        UNSAFE_HARD_GATE,
        UNSAFE_PENDING_REVIEW,
        UNSAFE_CONTENT_FINDINGS,
    }
)


def classify_safety(
    *,
    status: str,
    verdict: str | None,
    fail_closed: bool,
    hard_gate_hits: list[str],
) -> tuple[bool, str | None]:
    """The binary answer, plus its machine-readable kind when it is "no".

    Returns `(is_safe, unsafe_reason)`. Exactly one of the two carries
    information: a safe answer has `unsafe_reason is None`, an unsafe one always
    names a code from `UNSAFE_REASONS`. There is no third state and no "unknown".

    SECURITY - WHY COLLAPSING TO TWO VALUES IS SAFE HERE, when design spec §5.2
    recorded 「二值判定折叠」 as an explicit ANTI-GOAL. That objection was about
    collapsing REVIEW into *safe*: the flood cap forces REVIEW (INV-5), so an
    attacker who floods findings until `findings_capped` trips would have bought
    themselves a publishable verdict. This mapping sends REVIEW to *unsafe*, which
    closes that channel rather than opening it - strictly tighter than the
    three-valued contract it replaces, since PASS is the only publishable answer.
    The objection stands as written; it just does not apply to this direction.

    `is_safe` requires `COMPLETED` as well as PASS (owner decision, 2026-07-30:
    "not passed is unsafe" read strictly). A verdict can exist while the scan is
    still `scored` internally - the gate commits before `scan_job` is marked
    decided - and answering "safe" inside that window would publish on a scan the
    system does not yet consider finished.

    Deliberately NOT `and not fail_closed`: `GatePolicy` forbids
    `fail_closed_verdict == PASS`, so a fail-closed verdict can only read PASS if a
    human reviewer decided it (`gate.reviews`), and overriding a human's explicit
    approval forever is not conservatism, it is a stuck state.
    """
    if status == STATUS_COMPLETED and verdict == SAFE_VERDICT:
        return True, None
    # No verdict at all: the honest answer is "we have not judged this yet", which
    # under a binary contract is still unsafe (owner decision 3).
    if verdict is None:
        return False, UNSAFE_NOT_YET_SCANNED
    # A signed verdict exists, so report what IT says, in order of specificity.
    if fail_closed:
        # "We could not complete the scan." The single most important code on this
        # surface: on a real 226-package run, 17 of 18 BLOCKs were this, with zero
        # findings - so without it the marketplace gets "unsafe, no findings, no
        # explanation", the least actionable answer the system can give.
        return False, UNSAFE_SCAN_INCOMPLETE
    if hard_gate_hits:
        return False, UNSAFE_HARD_GATE
    if verdict == "REVIEW":
        return False, UNSAFE_PENDING_REVIEW
    if verdict == SAFE_VERDICT:
        # PASS on a scan that is not externally terminal yet (see above).
        return False, UNSAFE_NOT_YET_SCANNED
    return False, UNSAFE_CONTENT_FINDINGS


EXTERNAL_TOP_LEVEL_FIELDS: frozenset[str] = frozenset(
    {
        # 2026-07-30: skill-keyed, not scan-keyed. `scan_id` is GONE from the
        # contract - the marketplace asks about a skill and never learns which
        # internal scan answered, which also stops the replaced scan_id contract
        # being rebuilt on top of this one by accident.
        "skill_id",
        # WHICH VERSION this answer is about (owner decision 1: latest-version
        # semantics, and say which one it is). Without it "skill X is safe" is
        # unfalsifiable - the bytes it was true of are not named.
        "content_hash",
        "status",
        "poll_after_ms",
        "is_safe",
        "unsafe_reason",
        # 2026-07-30: reverses the deliberate exclusion recorded below. Under the
        # three-valued contract `hard_gate_hits` was "internal adjudication
        # detail; exposing them makes them part of the contract" - and that was
        # right when the caller also received `verdict` and could see BLOCK. A
        # binary answer without it cannot say WHY, and "unsafe because a
        # never-waivable rule fired" is materially different from "unsafe because
        # findings accumulated": the first is unfixable by negotiation (INV-3),
        # the second is a code change. It is a rule_id list, not evidence.
        "hard_gate_hits",
        "score",
        "policy_version",
        "decided_at",
        "verdict_jws",
        "judged_at_tier",
        # 里程碑 F Task 18. Added deliberately, as this whitelist requires:
        # `judged_at_tier` alone said which tier the verdict was reached at and
        # left the caller to assume it was their own. It usually is not - a
        # marketplace service account defaults to PUBLIC, the STRICTEST tier
        # (policies/gate/v1.yaml blocks it at HIGH, every other tier only at
        # CRITICAL), so a submission deduplicated onto an earlier console
        # submission at `internal` gets a verdict adjudicated under a MORE
        # PERMISSIVE ruleset than it asked for. Neither field is internal
        # adjudication detail: both are facts about this caller's own request
        # and the answer it is being handed.
        "requested_tier",
        "tier_direction",
        # 2026-07-29 residual triage. Added deliberately, as this whitelist
        # requires: `tier_direction` is computed from the policy loaded NOW, and
        # a policy approved between signing and polling can relabel a verdict
        # that is already in the caller's hands. This says which policy the
        # label came from ("signing_policy" | "current_policy"), so an
        # integrator can tell a live comparison from a retrospective one. It is
        # not adjudication detail - it qualifies a field this surface already
        # returns. See `gate.policy.tier_divergence`.
        "tier_direction_basis",
        # 2026-07-30 - PER-SCAN ENGINE COVERAGE. Added deliberately, as this
        # whitelist requires, and for the sharpest reason any field on this
        # surface has had: `required_engines` fails closed, and EVERY OTHER
        # ENGINE FAILS OPEN. An advisory engine that does not deliver has its
        # findings discarded and the verdict is computed on what remains, as
        # though it had found nothing. On a 290-scan real-world run that was not
        # hypothetical - scans with complete evidence came back 38% PASS / 60%
        # REVIEW, scans without it 57% PASS / 29% REVIEW. Under load the
        # effective ruleset shrinks and `is_safe: true` gets EASIER to obtain,
        # and until these fields there was nothing in the contract a caller
        # could read to notice.
        #
        # Owner decision: verdict semantics do not change (a caller that
        # ignores these gets exactly the answer it got before). What changes is
        # that the incompleteness stops being invisible.
        #
        # NOT adjudication detail - the excluded-by-design list above is about
        # how the gate reasons. This is about how much of the evidence existed
        # when it reasoned, which is a property of the answer being handed over.
        # Counts and a boolean, never prose: a machine consumer has to branch on
        # this, not parse it.
        "engines_expected",
        "engines_reported",
        "engines_not_applicable",
        "evidence_complete",
        "engine_coverage_basis",
        "summary",
        "findings",
    }
)

EXTERNAL_FINDING_FIELDS: frozenset[str] = frozenset(
    {
        "rule_id",
        "test_item_id",
        "category",
        "title",
        "severity",
        "confidence",
        "source_engine",
        "source_capability",
        "trifecta_signals",
        "file_path",
        "start_line",
        "evidence_redacted",
    }
)

# SECURITY (INV-9): deliberately absent from EXTERNAL_FINDING_FIELDS -
#   snippet_hash  a hash of a low-entropy secret is brute-forceable offline
#   (raw snippet) never stored in the first place
# and from EXTERNAL_TOP_LEVEL_FIELDS -
#   provenance / required_ok  internal adjudication detail; exposing them makes
#   them part of the contract.
#
# `hard_gate_hits` was on that second list until 2026-07-30 and now is not - see
# EXTERNAL_TOP_LEVEL_FIELDS for the argument. `snippet_hash` and `provenance` were
# re-examined at the same time and stay out: the exclusions are not a package deal,
# and INV-9's applies with undiminished force to a hash of a low-entropy secret.
#
# Also gone from the contract, and not by omission:
#   scan_id          the key was replaced (owner decision 4)
#   verdict          three-valued; `is_safe` + `unsafe_reason` is the whole answer
#   fail_closed      -> `unsafe_reason == "scan_incomplete"`
#   requires_review  -> `unsafe_reason == "pending_review"`
# The last two were dropped rather than kept alongside their codes: a contract with
# two spellings of one fact has two sources of truth, and they drift.

_SEVERITY_BUCKET: dict[int, str] = {1: "low", 2: "medium", 3: "high", 4: "critical"}


def _project_finding(raw: dict[str, Any]) -> dict[str, Any]:
    return {field: raw.get(field) for field in EXTERNAL_FINDING_FIELDS}


def _summarize(
    findings: list[dict[str, Any]], *, truncated: bool, findings_total: int | None
) -> dict[str, Any]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        bucket = _SEVERITY_BUCKET.get(int(finding.get("severity", 0)))
        if bucket is not None:
            counts[bucket] += 1
    # SECURITY (spec §5.3): `total` must be the real pre-cap count, not just
    # `len(findings)` - once `findings` is the post-cap list, its length IS the cap,
    # not the truth. `findings_total` (ScanResultRow, nullable) carries that real
    # count for every row written after the 2026-07-28 migration.
    #
    # `findings_total is None` only happens for rows written before that migration.
    # For those: if they were never capped, `len(findings)` already equals the true
    # total (correct, not a fallback). If they WERE capped, `len(findings)` is the
    # cap, not the truth - a degraded answer, but an honest one (it does not invent
    # a number that was never recorded).
    total = findings_total if findings_total is not None else len(findings)
    return {"total": total, **counts, "truncated": truncated}


def project_skill_verdict(
    *,
    skill_id: str,
    content_hash: str | None,
    internal_state: str | None,
    verdict_row: dict[str, Any] | None,
    result_row: dict[str, Any] | None,
    judged_at_tier: str | None = None,
    requested_tier: str | None = None,
    tier_direction: str | None = None,
    tier_direction_basis: str | None = None,
    coverage: ScanEngineCoverage | None = None,
) -> dict[str, Any]:
    """Build the marketplace-facing answer for one skill's LATEST version.

    `verdict_row`/`result_row` are plain dicts (or None), never ORM rows - the
    router does the extraction. That keeps this function free of any database
    dependency and therefore testable with no infrastructure at all.

    `content_hash` is the version this answer is about (owner decision 1). None
    means the skill is registered but has no recorded version at all, which is the
    same "nothing to report yet" case as `internal_state is None`.

    `internal_state is None` means no scan job exists for that version. It projects
    to `PENDING`, the only non-terminal external status, because that is what it
    means operationally: keep polling, there is no answer yet. It does NOT project
    to a terminal status - a caller told COMPLETED with no verdict would have to
    invent its own interpretation of the gap, and every interpretation available to
    it is worse than "not yet".

    `judged_at_tier` (C2) is the tier this verdict was ACTUALLY adjudicated at,
    which is not always the polling caller's own. Submissions are single-flight
    on content + toolchain: a marketplace submission of a package the console
    already scanned collapses onto that existing scan, and its verdict was
    decided at the FIRST submitter's tier - the decision is not re-run, so it
    cannot be re-tiered either. Reporting it is what stops the caller silently
    assuming its own tier applied; a PARTNER-tier verdict read by a PUBLIC-tier
    caller is a real difference in BLOCK threshold (CRITICAL vs HIGH).

    None means the scan records no tier at all - see `ScanJob.trust_tier`. Not
    substituted with a guess: the deployment default that such a scan actually
    fell back to is runtime configuration this pure function has no access to,
    and inventing the likely value would misreport the basis of a decision.

    `requested_tier` / `tier_direction` (Task 18) complete that disclosure.
    `judged_at_tier` on its own reports a tier and leaves the caller to assume
    it was the one they asked for; these two say whether it was, and which way
    a divergence cuts ("looser" | "stricter" | "equivalent", from
    `gate.policy.tier_direction` - the router computes it, because the answer
    depends on `GatePolicy.block_threshold` and this function stays pure).

    "looser" is the dangerous one and, on THIS surface, the common one: an
    unconfigured service account holds PUBLIC, the STRICTEST tier, while the
    console commonly submits at `internal`, so a marketplace poll of content
    the console scanned first is reading a verdict decided under a more
    permissive threshold than it asked for. Until Task 18 that was reported as
    nothing at all.

    `requested_tier` is None when this caller has no recorded request -
    a `scan_submitter` row written before that column existed. Deliberately NOT
    defaulted to `judged_at_tier` the way the CONSOLE's equivalent field is:
    there the fallback preserves the prior meaning of a pre-existing field,
    whereas here the field is new and has no meaning to preserve, so null keeps
    its plain sense of "not recorded" rather than silently asserting agreement.
    `tier_direction` is then null too, since there is nothing to compare.

    `tier_direction_basis` (2026-07-29) qualifies `tier_direction` with the
    policy it was computed under - `"signing_policy"` when the verdict's own
    `policy_version` is the one loaded, `"current_policy"` otherwise, and null
    whenever `tier_direction` is. Both come from the same
    `gate.policy.tier_divergence` call, so this function cannot be handed a
    direction and a basis that disagree; passing them separately is only what
    keeps this projection pure.

    `coverage` (2026-07-30) is HOW MUCH EVIDENCE the verdict was reached on.
    Taken as the whole `ScanEngineCoverage` object rather than as three loose
    ints, precisely because `tier_direction`/`tier_direction_basis` above are
    the other pattern and it costs something: this function cannot be handed
    counts that disagree with the boolean, because `complete` is that object's
    own property and the console reads the identical property. Two surfaces,
    one definition - the "second registry never updated" defect shape this
    repository produced five times in one milestone.

    `None` means "no coverage read was attempted" (no scan exists yet), and
    projects to zeroed counts with `evidence_complete: null` - the same answer
    a scan with no retained health rows gets, because from the caller's side
    they are the same fact: nobody can tell them what the coverage was. It is
    NOT projected as `true`; a completeness claim requires records.
    """
    status = "PENDING" if internal_state is None else project_status(internal_state)
    raw_findings: list[dict[str, Any]] = list((result_row or {}).get("findings") or [])
    # SECURITY (2026-07-30): the gate's OWN recorded answer (`VerdictRow.fail_closed`
    # -> `gate.service.get_verdict_view`), not an inference. This used to be
    # `verdict_row is not None and result_row is None` - "a verdict with no
    # ScanResultRow is the fail-closed signature" - which is only true of the
    # dead-letter path. The ordinary result-collector path writes a `scan_result` row
    # carrying `required_ok=False`, so its fail-closed BLOCKs had a row and reported
    # `false`. On a real 226-package run that was 17 of 18 BLOCKs, each an engine
    # timeout with zero findings, reported as an ordinary content BLOCK. Under a
    # binary contract that mislabel is worse still: it becomes "unsafe, no findings,
    # no explanation".
    fail_closed = bool((verdict_row or {}).get("fail_closed"))
    hard_gate_hits: list[str] = [str(r) for r in (result_row or {}).get("hard_gate_hits") or []]
    is_safe, unsafe_reason = classify_safety(
        status=status,
        verdict=(verdict_row or {}).get("verdict"),
        fail_closed=fail_closed,
        hard_gate_hits=hard_gate_hits,
    )
    return {
        "skill_id": skill_id,
        "content_hash": content_hash,
        "status": status,
        "poll_after_ms": POLL_AFTER_MS[status],
        "is_safe": is_safe,
        "unsafe_reason": unsafe_reason,
        "hard_gate_hits": hard_gate_hits,
        "score": (verdict_row or {}).get("score"),
        "policy_version": (verdict_row or {}).get("policy_version"),
        "decided_at": (verdict_row or {}).get("issued_at"),
        "verdict_jws": (verdict_row or {}).get("jws_signature"),
        "judged_at_tier": judged_at_tier,
        "requested_tier": requested_tier,
        "tier_direction": tier_direction,
        "tier_direction_basis": tier_direction_basis,
        # Engines whose findings this verdict was supposed to include, and how
        # many actually delivered. `expected` already excludes engines this
        # deployment does not run at all (counted in `engines_not_applicable`
        # instead) - see `summarize_scan_coverage` for why a flag that fires on
        # every scan of every LLM-less deployment would be worse than no flag.
        "engines_expected": 0 if coverage is None else coverage.expected,
        "engines_reported": 0 if coverage is None else coverage.reported,
        "engines_not_applicable": 0 if coverage is None else coverage.not_applicable,
        # THREE-valued on purpose. `true`/`false` are answers; `null` is "no
        # per-engine record exists for this scan" (a dead-lettered scan, one
        # older than the health-table retention window, or one scored before
        # the table existed). Reporting `true` there would be the strongest
        # claim on the weakest evidence, which is the exact mistake
        # `fail_closed` shipped as a structural inference and had to be
        # reverted for hours before this field was written.
        "evidence_complete": None if coverage is None else coverage.complete,
        # WHICH configuration the counts were computed against. Mandatory
        # company for `engines_expected`, for the same reason
        # `tier_direction_basis` is for `tier_direction`: the exclusion above is
        # read from configuration NOW, and nothing recorded the configuration
        # the scan actually ran under. An engine disabled this morning would
        # make last week's scans read complete.
        "engine_coverage_basis": (
            None if coverage is None or not coverage.observed else COVERAGE_BASIS_CURRENT_CONFIG
        ),
        "summary": _summarize(
            raw_findings,
            truncated=bool((result_row or {}).get("findings_capped", False)),
            findings_total=(result_row or {}).get("findings_total"),
        ),
        "findings": [_project_finding(f) for f in raw_findings],
    }
