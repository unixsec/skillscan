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


class BaselineReadOnly(Base):
    """SECURITY: orchestration's view onto inventory's `baseline` table is
    SELECT-only at the DB GRANT level (svc_orchestration has no INSERT/UPDATE
    on this table) - this ORM class exists only so drift.py can read the
    approved baseline for a skill_id; it must never be written from here."""

    __tablename__ = "baseline"

    skill_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    approved_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)
