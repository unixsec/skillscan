"""SQLAlchemy ORM for orchestration's own tables (coding spec §7.1): scan_job,
scan_result, plus a SELECT-only view onto inventory's `baseline` table (the
deliberate cross-module contract seam for drift.py, coding spec §7.2 -
svc_orchestration is granted SELECT on baseline and nothing else on it,
mirroring gate's INSERT-only view onto audit_intent). svc_orchestration has no
other access to any other module's tables (enforced by MySQL GRANTs,
policies/grants/manifest.yaml)."""

from __future__ import annotations

import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, SmallInteger, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ScanJob(Base):
    __tablename__ = "scan_job"

    scan_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    toolchain_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    cache_key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    submitter: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)
    # Parsed once at submission time from the package's SKILL.md frontmatter
    # `name:` field (gateway/router.py's create_scan) - nullable because not
    # every upload has a valid SKILL.md/name. Deliberately NOT derived from
    # skill_id/skill_version: most ad-hoc scans never register a skill_id at
    # all, but should still show something to distinguish them in the list.
    skill_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # When this scan first started WAITING for a sandbox-tier engine: set once
    # by `_try_score_and_decide` the first time it observes every required
    # engine reported but a waited-advisory (sandbox) engine still missing.
    #
    # SECURITY (2026-07-27 final review, F-2): `sweep_sandbox_wait_timeouts`
    # used to measure the wait from `created_at`, the only timestamp this table
    # had - i.e. "how old is this submission", not "how long have we been
    # waiting for the sandbox". Those differ by the whole queue backlog. After
    # a worker outage longer than the wait budget, a scan's floor blobs land
    # and the sweep immediately force-decides it in the SAME tick, because its
    # `created_at` is already ~10 minutes old - so the verdict is signed from
    # floor findings only and a package whose only HIGH finding comes from
    # bandit gets PASS instead of REVIEW. NULL means "has never started
    # waiting" and is never swept, which is also what keeps a never-dispatched
    # scan out of the sweep entirely.
    sandbox_wait_started_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=False), nullable=True
    )
    # SECURITY (2026-07-28, milestone B' Task 4): the trust tier this submission is
    # judged at, recorded AT SUBMIT TIME. The worker decides asynchronously, long
    # after the submitting session is gone, so the tier cannot be read from a
    # request context - it has to travel with the scan. Before this column every
    # verdict used `runtime.default_trust_tier` (a process-wide TrustTier.INTERNAL,
    # the most permissive tier), so a machine caller submitting third-party content
    # was judged by the internal-content threshold regardless of its identity.
    #
    # Nullable with no backfill: rows written before this column genuinely have no
    # recorded tier, and inventing one would be fabricating the basis of a past
    # decision. NULL falls back to `runtime.default_trust_tier` at decide time,
    # which is exactly the behaviour those rows were actually decided under.
    #
    # 2026-07-28 (C3): NULL means "this row records no tier" and nothing more.
    # It is NOT a reliable marker of "written before the column existed" -
    # `reeval.controller.build_rescan_job` produced NULL rows continuously
    # after the migration because it never mapped the column. Both production
    # writers now always record a tier; that is a property of those two call
    # sites, and any third writer must uphold it deliberately.
    trust_tier: Mapped[str | None] = mapped_column(String(16), nullable=True)


class ScanSubmitterRow(Base):
    """Who is authorized to read one scan (里程碑 B' review, C2).

    SECURITY: object-level authorization for `GET /v1/scans/{scan_id}`,
    `.../sarif`, `GET /v1/scans` and `GET /v1/market/scans/{scan_id}` is
    membership in THIS table, not equality against `ScanJob.submitter`.
    `submit_scan` is single-flight on `cache_key`, so a second caller
    submitting byte-identical content under the same toolchain is handed the
    FIRST caller's scan_job - and was then refused it, permanently, because
    the row still named someone else. A scan legitimately has N submitters.

    `ScanJob.submitter` is kept as the FIRST submitter: it is what the scan
    list displays, and the trust tier the verdict was judged at is that
    submission's (the adjudication is not redone for a later arrival, so the
    tier must not be reattributed either - see `views.project_scan`'s
    `judged_at_tier`).

    Append-only by design, and granted INSERT+SELECT only: revoking a
    submitter's access to a scan they really did submit is not a use case, and
    an UPDATE here would silently re-attribute someone else's scan.
    """

    __tablename__ = "scan_submitter"

    scan_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    submitter: Mapped[str] = mapped_column(String(255), primary_key=True)
    # SECURITY (2026-07-29, milestone F Task 12): the CHANNEL this submitter's
    # submission arrived through - `service.SubmissionChannel` ("console" or
    # "marketplace"). Written at INSERT time by `_associate_submitter`, because
    # that is the only moment the fact exists: the sole other carrier of the
    # distinction is `SessionContext.is_machine`, a per-request auth fact that
    # dies with the request. Task 2 had to report BLOCKED on surfacing it for
    # exactly that reason.
    #
    # A write-time column, not a read-time derivation: inferring the channel
    # from the submitter STRING would be a shape check standing in for a
    # membership check (see `SubmissionChannel`'s docstring for the SUP-01
    # precedent this project already paid for).
    #
    # PER SUBMITTER, deliberately not per scan. Single-flight dedup means one
    # scan legitimately has N submitters, and the console and the marketplace
    # scanning the same skill is this product's NORMAL case (see this table's
    # own migration) - a scan-level single value would silently drop one of the
    # two channels the moment both are involved.
    #
    # Nullable with no backfill, same posture as `ScanJob.trust_tier` and
    # `ScanResultRow.findings_total` and for the same reason: rows written
    # before this column genuinely have no recorded channel, nothing anywhere
    # records it retroactively, and inventing one would fabricate provenance.
    # NULL means "this row records no channel" and is surfaced verbatim, never
    # defaulted to "console". Contrast the backfill in 3c7e1b40d95a, which was
    # honest precisely because `scan_job.submitter` DID hold the value.
    #
    # NOT `skill_version.source` (a provenance label such as "web-upload") -
    # different table, different question.
    #
    # Never rewritten: this table is granted INSERT+SELECT only (see the
    # docstring above), and `_associate_submitter` returns early when the
    # (scan_id, submitter) pair already exists, so the FIRST recorded channel
    # for a given pair stands. That is the correct value - it is the channel
    # that submission actually came through.
    source: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # SECURITY (2026-07-29, milestone F Task 14): the trust tier THIS submitter
    # asked their submission to be judged at - a `TrustTier` value.
    #
    # THE GAP THIS CLOSES. `ScanJob.trust_tier` is the FIRST submitter's tier
    # and the tier the verdict was actually adjudicated at; the docstring above
    # says why that must not be reattributed to a later arrival. But nothing
    # recorded what the later arrival ASKED FOR, so the two facts were one
    # column and the console showed the same value twice under two labels
    # ("trust tier" / "judged at tier"), which is to say it disclosed nothing.
    #
    # The dangerous case is concrete: `policies/gate/v1.yaml` gives `public` a
    # HIGH block override while `internal`/`partner` block only at CRITICAL, so
    # `public` is the STRICTEST tier. A submitter asking for `public` whose
    # byte-identical content was already scanned at `internal` is handed a
    # verdict reached under a MORE PERMISSIVE ruleset than they asked for. A
    # HIGH finding that would have blocked for them reads PASS, and before this
    # column there was no way to tell - not in the response, not in the
    # database. The reverse direction (asking `internal`, getting a `public`
    # verdict) is the safe side but is disclosed too: over-blocking that nobody
    # can explain is its own failure.
    #
    # PER SUBMITTER, like `source` above and for the identical reason: dedup
    # means one scan legitimately has N submitters who may have asked for N
    # different tiers, and a scan-level column could keep only one of them.
    #
    # Written at INSERT by `_associate_submitter` and never rewritten (this
    # table is granted INSERT+SELECT only). `submit_scan` takes it as a
    # REQUIRED keyword argument, so a missed writer is a type error rather than
    # a silently unrecorded request - the same posture `trust_tier` and
    # `source` already take, and for the same reason.
    #
    # NOT the same fact as `ScanJob.trust_tier`, even though both current
    # writers happen to pass the same resolved tier: this one is recorded on
    # EVERY path including dedup (where `ScanJob.trust_tier` is deliberately
    # left alone), and it belongs to this submitter rather than to the scan.
    #
    # Nullable with NO backfill, same posture as `source` and
    # `ScanJob.trust_tier`: rows written before this column record no request,
    # nothing anywhere reconstructs one, and copying `ScanJob.trust_tier` into
    # it would fabricate exactly the divergence this column exists to reveal -
    # it would assert every past submitter asked for the tier they were judged
    # at, which is the unverified assumption in the first place. NULL means
    # "this row records no request" and is surfaced as unknown, never guessed.
    requested_trust_tier: Mapped[str | None] = mapped_column(String(16), nullable=True)


class ScanResultRow(Base):
    __tablename__ = "scan_result"

    scan_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    confidence_at_max: Mapped[float] = mapped_column(Float, nullable=False)
    trifecta_present: Mapped[bool] = mapped_column(Boolean, nullable=False)
    findings_capped: Mapped[bool] = mapped_column(Boolean, nullable=False)
    # SECURITY: nullable with no backfill, on purpose. Every row written from this
    # point on gets the real pre-cap count (skillscan_core.ScanResult.findings_total,
    # itself computed before truncation - see scoring.py). Pre-existing rows never
    # captured that number, and it cannot be reconstructed after the fact (the
    # dropped findings are gone); NULL is the honest answer for them, not 0 or the
    # post-cap length. See db/migrations/versions for the migration that added this
    # column, and marketplace_api.views._summarize for the NULL fallback.
    findings_total: Mapped[int | None] = mapped_column(Integer, nullable=True)
    required_ok: Mapped[bool] = mapped_column(Boolean, nullable=False)
    findings: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    provenance: Mapped[list[list[str]]] = mapped_column(JSON, nullable=False)
    hard_gate_hits: Mapped[list[str]] = mapped_column(JSON, nullable=False)


class ScanEngineHealthRow(Base):
    """Per-(scan, engine) runtime health - milestone C Task 8, design §3.

    WHY A TABLE AND NOT A COLUMN. `ScanResultRow.provenance` already carries one
    `(name, version, ruleset_digest)` triple per engine, so "add the status
    there" looks like the small change. It is not: provenance is written only
    for engines that produced a usable result, and the fact this table exists to
    record - "this engine never reported" - has no provenance triple to hang
    off. The row for a never-reported engine is the row that matters.

    WHY THE MONOLITH WRITES IT. INV-10 forbids the engine-runner a DB session
    (`services/engine_runner/worker.py`), so the service that MEASURES this
    physically cannot store it. The telemetry travels engine-runner -> findings
    blob / Redis results stream -> this process, and is persisted here, in the
    same transaction that writes `ScanResultRow` - so health rows exist exactly
    when a scan was scored, and a decide can never half-succeed with telemetry
    but no verdict or vice versa.

    NOT written by `_dead_letter_and_decide` (poison pill / unpack rejected):
    that path never aggregates, because no engine ran and there is no engine
    set to report on. Those scans have no rows here at all, deliberately -
    inventing 15 `not_reported` rows for a package that was rejected before
    dispatch would attribute an engine-level failure to a content-level one.
    """

    __tablename__ = "scan_engine_health"

    scan_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    # RUNTIME engine name (`EngineMetadata.name`) - the same namespace
    # `findings_key`, `GatePolicy.required_engines`, `ScanResultRow.provenance`
    # and the admin toggle all use. NEVER a `vendor/engines.lock.yaml` key:
    # `osv_scanner`/`aig` differ between the two namespaces while the other
    # three collide by accident, so a wrong-namespace write here would join
    # correctly for three engines and silently mis-join for two - precisely how
    # `reporting.service.build_engine_coverage`'s `disabled` flag stayed wrong
    # for years. `common.engine_names` is the one sanctioned conversion, and
    # `test_engine_health.py` pins that every real dispatch set is already in
    # the runtime namespace so no conversion is needed on this path at all.
    # 64 chars against a longest-today of 31 (`inhouse-jailbreak-inducement-zh`).
    engine_name: Mapped[str] = mapped_column(String(64), primary_key=True)
    # `aggregate.EngineReportState`. Whether we HEARD from the engine - our own
    # observation, deliberately a different column from what the engine SAID.
    report_state: Mapped[str] = mapped_column(String(16), nullable=False)
    # `skillscan_core.EngineStatus` - what the engine said about its own run.
    # NULL exactly when `report_state != 'reported'`, enforced by a DB CHECK
    # (chk_engine_health_status_iff_reported) and by
    # `EngineHealthRecord.__post_init__`, because THIS is acceptance criterion
    # 8: "returned ERROR" is (reported, error); "never reported at all" is
    # (not_reported, NULL). Before this table they were the same value, since
    # `aggregate.unavailable_engine_result` fabricates EngineStatus.ERROR for a
    # missing blob so the gate fails closed. That fabrication must not leak
    # into telemetry, and the schema is what stops it.
    engine_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Milestone C Task 7's wall-clock span of one `engine.analyze()` call.
    # THREE states: an integer (measured), `0` (ALSO measured - in-process
    # floor engines really do finish in under a millisecond, so a reader must
    # not render 0 as "unknown"), and NULL (NOT measured - a blob from a
    # pre-Task-7 engine-runner image, or an engine we never heard from).
    analyze_duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Pre-dedup, pre-cap, pre-min_confidence count as the engine reported it -
    # NOT derivable from `ScanResultRow.findings`, which is the aggregated,
    # deduplicated, capped set. "Engine ran fine and found nothing" and "engine
    # found 40 things that all deduplicated away" are different operational
    # facts. NULL when there was nothing to count.
    finding_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # The engine's own `error` when reported; our fail-closed reason otherwise
    # (which key was missing, which schema check failed). Truncated to fit by
    # `aggregate._truncate_error` - MySQL strict mode ERRORS on over-length
    # data, and this INSERT shares the scoring transaction, so an untruncated
    # multi-KB pydantic message would abort the decide rather than lose a tail.
    error: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    # When the observation was made (naive UTC, like every other timestamp in
    # this schema). The scan's own `created_at` is not a substitute: it is the
    # submission time, and the two differ by the whole queue backlog. This is
    # also the column a retention sweep has to key on.
    recorded_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)


class BaselineReadOnly(Base):
    """SECURITY: orchestration's view onto inventory's `baseline` table is
    SELECT-only at the DB GRANT level (svc_orchestration has no INSERT/UPDATE
    on this table) - this ORM class exists only so drift.py can read the
    approved baseline for a skill_id; it must never be written from here."""

    __tablename__ = "baseline"

    skill_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    approved_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)
