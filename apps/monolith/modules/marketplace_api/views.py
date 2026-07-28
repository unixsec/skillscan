"""Projection: internal scan data -> the marketplace-facing view (spec §5).

Pure functions only - no database, no network, no clock. Everything time-related
arrives as an argument. That is what lets the whole projection be tested without
MySQL/Redis, and it is also what keeps this file reviewable as the contract
itself rather than as glue.

SECURITY (spec §3.2): the field sets below are a WHITELIST. Adding an internal
field must not expose it; a projection that omits a field is a missing feature
(noticed), a filter that forgets one is a leak (not noticed).
"""

from __future__ import annotations

from typing import Any

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


EXTERNAL_TOP_LEVEL_FIELDS: frozenset[str] = frozenset(
    {
        "scan_id",
        "status",
        "verdict",
        "score",
        "policy_version",
        "decided_at",
        "verdict_jws",
        "fail_closed",
        "requires_review",
        "poll_after_ms",
        "judged_at_tier",
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
#   provenance / required_ok / hard_gate_hits  internal adjudication detail;
#   exposing them makes them part of the contract.

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


def project_scan(
    *,
    scan_id: str,
    internal_state: str,
    verdict_row: dict[str, Any] | None,
    result_row: dict[str, Any] | None,
    judged_at_tier: str | None = None,
) -> dict[str, Any]:
    """Build the marketplace-facing view of one scan.

    `verdict_row`/`result_row` are plain dicts (or None), never ORM rows - the
    router does the extraction. That keeps this function free of any database
    dependency and therefore testable with no infrastructure at all.

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
    """
    status = project_status(internal_state)
    raw_findings: list[dict[str, Any]] = list((result_row or {}).get("findings") or [])
    return {
        "scan_id": scan_id,
        "status": status,
        "verdict": (verdict_row or {}).get("verdict"),
        "score": (verdict_row or {}).get("score"),
        "policy_version": (verdict_row or {}).get("policy_version"),
        "decided_at": (verdict_row or {}).get("issued_at"),
        "verdict_jws": (verdict_row or {}).get("jws_signature"),
        # A verdict with no ScanResultRow is the fail-closed signature: the gate
        # decided (and signed) without a completed finding set.
        "fail_closed": verdict_row is not None and result_row is None,
        "requires_review": (verdict_row or {}).get("verdict") == "REVIEW",
        "poll_after_ms": POLL_AFTER_MS[status],
        "judged_at_tier": judged_at_tier,
        "summary": _summarize(
            raw_findings,
            truncated=bool((result_row or {}).get("findings_capped", False)),
            findings_total=(result_row or {}).get("findings_total"),
        ),
        "findings": [_project_finding(f) for f in raw_findings],
    }
