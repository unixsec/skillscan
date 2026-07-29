"""EngineResult read-back + aggregation (coding spec §11.3, INV-11).

SECURITY: `load_and_aggregate` is the only path from blob-store bytes into
`skillscan_core.aggregate()`. Every findings blob is untrusted (INV-11) - schema
validation happens in `schemas.findings`, and this module additionally treats a
*missing* blob (engine never reported) identically to a validation failure: both
become an ERROR placeholder result, never a silent gap that `aggregate()` might
mistake for "this engine had zero findings."

HEALTH CAPTURE (milestone C Task 8, 2026-07-29). That deliberate collapse - a
missing blob and a corrupt blob both becoming `EngineStatus.ERROR` - is exactly
right for adjudication and exactly wrong for telemetry, and it is why the
storage layer could not tell "the engine returned ERROR" from "the engine never
reported at all" (design §3, acceptance criterion 8). So this module now returns
BOTH: the `ScanResult` the gate decides on, in which the collapse still happens,
and a separate `EngineHealthRecord` per engine, in which it does not.

Captured HERE, at the one place that already reads each blob, rather than in a
second sweep: a second read would be a second, independently-evolving opinion
about what a blob says, and the two would diverge the first time one of them
learned about a new failure mode.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence
from enum import StrEnum

from common.blobstore import BlobNotFoundError, BlobStorePort, findings_key
from schemas.findings import UntrustedFindingsError, parse_engine_result_with_duration
from skillscan_core import (
    EngineMetadata,
    EngineResult,
    EngineStatus,
    GatePolicy,
    ScanMode,
    ScanResult,
)
from skillscan_core import (
    aggregate as core_aggregate,
)

# `ScanEngineHealthRow.error` is VARCHAR(1024) and MySQL runs in strict mode, so
# an over-length value is an ERROR, not a silent truncation - and this INSERT
# shares the transaction that scores the scan. A pydantic `ValidationError`
# rendered into that column can be several KB, which would abort the decide and
# leave the scan permanently stuck rather than losing the tail of a message
# nobody reads past the first line of. Truncated at the boundary, visibly.
_ERROR_MAX_CHARS = 1000
_ERROR_TRUNCATION_SUFFIX = "... (truncated)"


class EngineReportState(StrEnum):
    """Whether we heard from an engine at all - OUR observation, not the
    engine's self-report.

    THE WHOLE POINT of this being a separate axis from `EngineStatus`: the two
    answer different questions, and merging them is the defect. `EngineStatus`
    is what the engine said about its own run; a missing blob is not the engine
    saying anything, it is us not hearing. `unavailable_engine_result` below
    fabricates `EngineStatus.ERROR` for that case - correctly, because the gate
    must fail closed - and a health table that stored only that fabrication
    would report "this engine failed" for an engine that was never even
    constructed on this deployment.
    """

    #: The blob was present and parsed. `engine_status` carries what it said.
    REPORTED = "reported"
    #: No blob at this scan's key for this engine. Never dispatched, still
    #: running past the wait, crashed before writing, admin-disabled (the
    #: engine-runner skips those with a bare `continue` - no blob, ever), or
    #: (the standing case on an LLM-less deployment) never constructed by the
    #: engine-runner at all.
    #:
    #: DELIBERATELY NOT SUBDIVIDED. This process cannot tell those apart at
    #: read-back time without asserting a reason it did not observe, and a
    #: wrong reason is worse than none. The two that ARE knowable elsewhere are
    #: knowable from an authoritative source: the admin-disabled set lives in
    #: Redis (`admin.engine_registry.list_disabled_engines`) and the LLM gate in
    #: `engine_runner.sandbox_engines.llm_gated_engine_names()`. A read path
    #: that wants "why" must join those, not guess here.
    NOT_REPORTED = "not_reported"
    #: A blob existed but could not be trusted - schema violation, or an
    #: identity mismatch between the key we looked up and the name inside.
    #: Distinct from NOT_REPORTED because *something* wrote there, which is an
    #: operational fact worth being able to query for on its own.
    UNREADABLE = "unreadable"


@dataclasses.dataclass(frozen=True, slots=True)
class EngineHealthRecord:
    """One engine's outcome on one scan, as observed at read-back.

    INVARIANT, enforced by this class AND by a DB CHECK constraint (see the
    `scan_engine_health` migration): `engine_status is not None` if and only if
    `report_state is REPORTED`. That is the acceptance-criterion-8 distinction
    made unforgeable rather than merely intended - a future writer cannot
    record "ERROR" for an engine it never heard from without tripping both.

    `analyze_duration_ms` has THREE states, not two (milestone C Task 7's own
    concern, restated because collapsing them is the easy mistake):
      * an integer `>= 1` - measured
      * `0` - ALSO measured. Floor engines are in-process byte matchers and
        genuinely finish in under a millisecond. Rendering this as "unknown" or
        "-" is wrong.
      * `None` - NOT measured: the blob predates Task 7, or came from an
        engine-runner image that does not yet emit the field. Only this one is
        unknown.
    A fourth state exists above the field: no record at all for that engine,
    which is `NOT_REPORTED` - nothing ran, so nothing was timed.
    """

    engine_name: str
    report_state: EngineReportState
    engine_status: EngineStatus | None
    analyze_duration_ms: int | None
    finding_count: int | None
    error: str | None

    def __post_init__(self) -> None:
        reported = self.report_state is EngineReportState.REPORTED
        if reported != (self.engine_status is not None):
            raise ValueError(
                "engine_status must be set exactly when report_state is REPORTED "
                f"(got report_state={self.report_state!r}, engine_status={self.engine_status!r})"
            )
        if not reported and self.analyze_duration_ms is not None:
            raise ValueError(
                "an engine we never read a result from cannot have a measured duration "
                f"(report_state={self.report_state!r}, "
                f"analyze_duration_ms={self.analyze_duration_ms!r})"
            )


@dataclasses.dataclass(frozen=True, slots=True)
class AggregatedScan:
    """What `load_and_aggregate` returns: the adjudicated result, plus the
    per-engine telemetry that used to be dropped on the floor beside it.

    A dataclass rather than a bare tuple so a caller that only wants the
    verdict input says `.scan_result` instead of `[0]` - and so adding a third
    captured fact later is not a silent arity change at every call site.
    """

    scan_result: ScanResult
    engine_health: tuple[EngineHealthRecord, ...]


def _truncate_error(text: str | None) -> str | None:
    if text is None:
        return None
    if len(text) <= _ERROR_MAX_CHARS:
        return text
    return text[: _ERROR_MAX_CHARS - len(_ERROR_TRUNCATION_SUFFIX)] + _ERROR_TRUNCATION_SUFFIX


def unavailable_engine_result(engine_name: str, *, reason: str) -> EngineResult:
    """SECURITY (INV-11 fail-closed): built from the *expected* engine name (our
    own dispatch list), never from anything read out of an untrusted/missing
    blob - a corrupted or absent findings blob must not be able to spoof a
    different engine's identity into the provenance record."""
    metadata = EngineMetadata(
        name=engine_name,
        version="unknown",
        ruleset_digest="unknown",
        capabilities=frozenset(),
        requires_network=False,
        requires_llm=False,
        deterministic=True,
    )
    return EngineResult(
        engine=metadata,
        findings=(),
        status=EngineStatus.ERROR,
        scan_mode=ScanMode.STATIC,
        llm_used=False,
        error=reason,
    )


def _unavailable(
    engine_name: str, *, reason: str, state: EngineReportState
) -> tuple[EngineResult, EngineHealthRecord]:
    """The fail-closed placeholder for adjudication, paired with a health record
    that does NOT inherit its fabricated `EngineStatus.ERROR`."""
    return (
        unavailable_engine_result(engine_name, reason=reason),
        EngineHealthRecord(
            engine_name=engine_name,
            report_state=state,
            engine_status=None,
            analyze_duration_ms=None,
            finding_count=None,
            error=_truncate_error(reason),
        ),
    )


def load_engine_result(
    blobstore: BlobStorePort, *, scan_id: str, engine_name: str
) -> tuple[EngineResult, EngineHealthRecord]:
    """SECURITY: any schema violation OR an engine-identity mismatch between the
    key we looked up and the identity claimed inside the blob is treated as
    unusable (fail-closed) - defense in depth against a misdirected or spoofed
    write landing at the wrong findings/<scan_id>/<engine>.json key.

    Returns the result the gate adjudicates on AND this engine's health record;
    see this module's docstring for why the two disagree about what a missing
    blob means, and why that disagreement is the feature.
    """
    key = findings_key(scan_id, engine_name)
    try:
        raw = blobstore.get(key)
    except BlobNotFoundError:
        return _unavailable(
            engine_name,
            reason=f"no findings reported at {key} (fail-closed, INV-11)",
            state=EngineReportState.NOT_REPORTED,
        )
    try:
        result, analyze_duration_ms = parse_engine_result_with_duration(raw)
    except UntrustedFindingsError as exc:
        return _unavailable(
            engine_name,
            reason=f"schema validation failed (fail-closed, INV-11): {exc}",
            state=EngineReportState.UNREADABLE,
        )
    if result.engine.name != engine_name:
        return _unavailable(
            engine_name,
            reason=(
                f"engine identity mismatch: key={engine_name!r} but blob claimed "
                f"{result.engine.name!r} (fail-closed, INV-11)"
            ),
            state=EngineReportState.UNREADABLE,
        )
    return (
        result,
        EngineHealthRecord(
            # SECURITY: the health row is keyed on the name we LOOKED UP, the
            # same posture `unavailable_engine_result` takes - identical to
            # `result.engine.name` only because the mismatch branch above
            # already returned. Reading it back off the blob would let a
            # misdirected write file its telemetry under another engine's name.
            engine_name=engine_name,
            report_state=EngineReportState.REPORTED,
            engine_status=result.status,
            analyze_duration_ms=analyze_duration_ms,
            finding_count=len(result.findings),
            error=_truncate_error(result.error),
        ),
    )


def load_and_aggregate(
    blobstore: BlobStorePort,
    *,
    scan_id: str,
    content_hash: str,
    engine_names: Sequence[str],
    policy: GatePolicy,
    min_confidence: float = 0.0,
    max_findings: int = 5000,
) -> AggregatedScan:
    """`engine_names` are RUNTIME engine names (`EngineMetadata.name`) - the
    namespace `findings_key`, `GatePolicy.required_engines` and every
    provenance tuple already use, and the namespace the health records
    therefore carry. NOT `vendor/engines.lock.yaml` keys: those spell two of
    the five differently (`osv_scanner`, `aig`) and agree by accident on the
    other three, which is what let a mis-keyed join stay wrong for years. Any
    caller holding lock keys must convert through `common.engine_names` before
    calling this - there is no fallback here and there must not be one.
    """
    loaded = [
        load_engine_result(blobstore, scan_id=scan_id, engine_name=name) for name in engine_names
    ]
    scan_result = core_aggregate(
        content_hash,
        [result for result, _ in loaded],
        policy,
        min_confidence=min_confidence,
        max_findings=max_findings,
    )
    return AggregatedScan(
        scan_result=scan_result, engine_health=tuple(health for _, health in loaded)
    )
