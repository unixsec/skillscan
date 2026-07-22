"""Report generation + export + schedule persistence (coding spec §16.2
FR-REP: "模板(执行摘要/合规态/风险趋势/引擎覆盖/例外审计)· 导出(PDF/CSV/SARIF)·
推送计划(cron → SIEM/邮件内网)").

SECURITY: every template is built EXCLUSIVELY from data other modules have
already committed (audit_entry / scan_result, both SELECT-only grants) or
from non-sensitive fleet-wide config (Redis engine-disable set, the vendored
engines lock file) - reporting never touches a live operational table, and
every finding it can ever surface already went through `evidence_redacted`
(coding spec §16.2: "报表不含明文密钥/PII(仅脱敏 + snippet_hash)") long before
it reached this module.

SCOPE NOTE: `schedule_report` only persists the DECLARATIVE
`{template, cron, targets}` tuple - actually firing on that cron schedule and
delivering to SIEM/email requires a live background worker process (plus a
real SIEM/mail relay to deliver to) that this environment cannot stand up or
verify, the same class of gap as M6's live marketplace push / M7's live DR
drill (see docs/stories/BACKLOG.md's S8 status note).
"""

from __future__ import annotations

import csv
import datetime
import io
import os
import re
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import redis.asyncio as aioredis
import yaml
from common.sarif import findings_to_sarif
from fpdf import FPDF
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from monolith.modules.admin.engine_registry import list_disabled_engines
from monolith.modules.orchestration.floor import floor_engine_names

from .models import AuditEntryReadOnly, ReportScheduleRow, ScanResultReadOnly

TEMPLATES: tuple[str, ...] = (
    "executive_summary",
    "compliance_status",
    "risk_trend",
    "engine_coverage",
    "exception_audit",
)

# The vendored-engines pin manifest (coding spec §10A.2). Env-overridable
# (SKILLSCAN_ENGINES_LOCK_PATH) because the repo-relative default resolves wrong
# in an installed/containerized layout AND vendor/ is not copied into the
# runtime image - a deployment mounts the lock file and points this at it, same
# pattern as SKILLSCAN_GATE_POLICY_PATH.
_DEFAULT_ENGINES_LOCK_PATH = Path(
    os.environ.get(
        "SKILLSCAN_ENGINES_LOCK_PATH",
        str(Path(__file__).resolve().parents[4] / "vendor" / "engines.lock.yaml"),
    )
)
_MAX_PDF_ROWS = 500  # SECURITY (no silent caps): truncation is NOTED in the PDF, never silent


def _naive_utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


class ReportingError(ValueError):
    pass


class UnknownReportTemplateError(ReportingError):
    pass


class InvalidCronError(ReportingError):
    pass


@dataclass(frozen=True, slots=True)
class Report:
    template: str
    since: datetime.datetime | None
    until: datetime.datetime | None
    summary: dict[str, Any] = field(default_factory=dict)
    rows: list[dict[str, Any]] = field(default_factory=list)


_CRON_FIELD_PATTERN = re.compile(r"^(\*|[0-9*,\-/]+)$")
# (minute, hour, day-of-month, month, day-of-week) value bounds; weekday hi=7
# because cron lets 0 AND 7 mean Sunday.
_CRON_FIELD_BOUNDS = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))


def validate_cron(expression: str) -> None:
    """SECURITY: fail-closed FULL validation (structure + semantics) - each
    field must parse as `*`, `*/n`, `a`, `a-b`, `a-b/n`, or a comma list of
    those, with every value inside its field's legal range. A schedule that
    can't be evaluated must be rejected at creation time, never stored to
    fail (or silently never fire) at execution time in the worker."""
    fields = expression.split()
    if len(fields) != 5:
        raise InvalidCronError(
            f"cron expression must have exactly 5 whitespace-separated fields, "
            f"got {len(fields)}: {expression!r}"
        )
    for f, (lo, hi) in zip(fields, _CRON_FIELD_BOUNDS, strict=True):
        if not _CRON_FIELD_PATTERN.match(f):
            raise InvalidCronError(f"invalid cron field {f!r} in {expression!r}")
        # Semantic check: raises InvalidCronError on out-of-range values,
        # zero steps, malformed ranges. The probe value is irrelevant - only
        # the parse (with its range checks) matters here.
        _cron_field_matches(f, lo, lo=lo, hi=hi)


def _cron_field_matches(field_expr: str, value: int, *, lo: int, hi: int) -> bool:
    """One cron field against one value. Supports `*`, `*/n`, `a`, `a-b`,
    `a-b/n`, and comma-separated lists of those. Raises InvalidCronError on
    anything else (fail-closed - a schedule that can't be evaluated must
    never silently fire, or silently never fire without a log)."""
    for token in field_expr.split(","):
        base, _, step_raw = token.partition("/")
        try:
            step = int(step_raw) if step_raw else 1
        except ValueError as exc:
            raise InvalidCronError(f"invalid cron step in {token!r}") from exc
        if step < 1:
            raise InvalidCronError(f"cron step must be >= 1 in {token!r}")
        if base == "*":
            start, end = lo, hi
        elif "-" in base:
            start_raw, _, end_raw = base.partition("-")
            try:
                start, end = int(start_raw), int(end_raw)
            except ValueError as exc:
                raise InvalidCronError(f"invalid cron range in {token!r}") from exc
        else:
            try:
                start = end = int(base)
            except ValueError as exc:
                raise InvalidCronError(f"invalid cron value in {token!r}") from exc
        if not (lo <= start <= hi and lo <= end <= hi and start <= end):
            raise InvalidCronError(f"cron value out of range [{lo},{hi}] in {token!r}")
        if start <= value <= end and (value - start) % step == 0:
            return True
    return False


def cron_matches(expression: str, at: datetime.datetime) -> bool:
    """Standard 5-field cron semantics (minute hour day-of-month month
    day-of-week) against a specific minute. Day-of-month vs day-of-week use
    classic cron's OR rule when BOTH are restricted. Weekday: 0 and 7 both
    mean Sunday (cron convention; Python's weekday() has Monday=0)."""
    validate_cron(expression)
    minute_f, hour_f, dom_f, month_f, dow_f = expression.split()
    if not _cron_field_matches(minute_f, at.minute, lo=0, hi=59):
        return False
    if not _cron_field_matches(hour_f, at.hour, lo=0, hi=23):
        return False
    if not _cron_field_matches(month_f, at.month, lo=1, hi=12):
        return False
    cron_weekday = (at.weekday() + 1) % 7  # Monday=0 -> cron Sunday=0
    dom_ok = _cron_field_matches(dom_f, at.day, lo=1, hi=31)
    dow_ok = _cron_field_matches(dow_f, cron_weekday, lo=0, hi=7) or (
        cron_weekday == 0 and _cron_field_matches(dow_f, 7, lo=0, hi=7)
    )
    if dom_f != "*" and dow_f != "*":
        return dom_ok or dow_ok
    return dom_ok and dow_ok


async def schedule_report(
    session: AsyncSession,
    *,
    template: str,
    cron: str,
    targets: Sequence[str],
    created_by: str,
) -> ReportScheduleRow:
    if template not in TEMPLATES:
        raise UnknownReportTemplateError(
            f"unknown report template {template!r} - must be one of {TEMPLATES}"
        )
    validate_cron(cron)
    if not targets:
        raise ReportingError("at least one delivery target is required")
    row = ReportScheduleRow(
        template=template,
        cron=cron,
        targets=list(targets),
        created_by=created_by,
        created_at=_naive_utcnow(),
    )
    session.add(row)
    await session.flush()
    return row


async def list_schedules(session: AsyncSession) -> Sequence[ReportScheduleRow]:
    result = await session.execute(select(ReportScheduleRow).order_by(ReportScheduleRow.id.asc()))
    return result.scalars().all()


async def _audit_entries(
    session: AsyncSession,
    *,
    action: str,
    since: datetime.datetime | None,
    until: datetime.datetime | None,
) -> Sequence[AuditEntryReadOnly]:
    stmt = select(AuditEntryReadOnly).where(AuditEntryReadOnly.action == action)
    if since is not None:
        stmt = stmt.where(AuditEntryReadOnly.chained_at >= since)
    if until is not None:
        stmt = stmt.where(AuditEntryReadOnly.chained_at <= until)
    result = await session.execute(stmt.order_by(AuditEntryReadOnly.seq.asc()))
    return result.scalars().all()


async def build_executive_summary(
    session: AsyncSession,
    *,
    since: datetime.datetime | None = None,
    until: datetime.datetime | None = None,
) -> Report:
    verdicts = await _audit_entries(session, action="verdict_issued", since=since, until=until)
    transitions = await _audit_entries(
        session, action="skill_lifecycle_transition", since=since, until=until
    )
    activations = await _audit_entries(
        session, action="breakglass_activated", since=since, until=until
    )

    verdict_counts = Counter(str(e.payload.get("verdict")) for e in verdicts)
    rows = [
        {
            "scan_id": e.payload.get("scan_id"),
            "verdict": e.payload.get("verdict"),
            "policy_version": e.payload.get("policy_version"),
            "occurred_at": e.chained_at.isoformat(),
        }
        for e in verdicts
    ]
    return Report(
        template="executive_summary",
        since=since,
        until=until,
        summary={
            "total_verdicts": len(verdicts),
            "verdict_counts": dict(verdict_counts),
            "lifecycle_transitions": len(transitions),
            "breakglass_activations": len(activations),
        },
        rows=rows,
    )


async def build_compliance_status(
    session: AsyncSession,
    *,
    since: datetime.datetime | None = None,
    until: datetime.datetime | None = None,
) -> Report:
    verdicts = await _audit_entries(session, action="verdict_issued", since=since, until=until)
    proposed = await _audit_entries(session, action="policy_proposed", since=since, until=until)
    approved = await _audit_entries(session, action="policy_approved", since=since, until=until)
    rejected = await _audit_entries(session, action="policy_rejected", since=since, until=until)
    engine_changes = await _audit_entries(
        session, action="engine_enabled_changed", since=since, until=until
    )

    verdict_counts = Counter(str(e.payload.get("verdict")) for e in verdicts)
    decision_rows = [
        {
            "proposal_id": e.payload.get("proposal_id"),
            "action": action_name,
            "operator": e.operator,
            "occurred_at": e.chained_at.isoformat(),
        }
        for action_name, entries in (
            ("proposed", proposed),
            ("approved", approved),
            ("rejected", rejected),
        )
        for e in entries
    ]
    decision_rows.sort(key=lambda r: str(r["occurred_at"]))
    return Report(
        template="compliance_status",
        since=since,
        until=until,
        summary={
            "verdict_counts": dict(verdict_counts),
            "policy_proposals": {
                "pending": len(proposed) - len(approved) - len(rejected),
                "approved": len(approved),
                "rejected": len(rejected),
            },
            "engine_changes": len(engine_changes),
        },
        rows=decision_rows,
    )


async def build_risk_trend(
    session: AsyncSession,
    *,
    since: datetime.datetime | None = None,
    until: datetime.datetime | None = None,
) -> Report:
    """SECURITY/HONESTY: bucketed by VERDICT outcome (PASS/REVIEW/BLOCK), not
    by numeric severity - audit_entry's verdict_issued payload (gate.service.
    decide_and_record) does not carry effective_severity, only the verdict
    string + reasons. Verdict outcome is still a defensible risk-trend proxy
    (it IS the gate's own risk judgment); a severity-level trend would need a
    new grant onto gate's `verdict` table, out of this template's scope."""
    verdicts = await _audit_entries(session, action="verdict_issued", since=since, until=until)
    by_day: defaultdict[str, Counter[str]] = defaultdict(Counter)
    for e in verdicts:
        day = e.chained_at.date().isoformat()
        by_day[day][str(e.payload.get("verdict"))] += 1

    rows = [
        {"date": day, "verdict": verdict, "count": count}
        for day in sorted(by_day)
        for verdict, count in sorted(by_day[day].items())
    ]
    return Report(
        template="risk_trend",
        since=since,
        until=until,
        summary={"total_verdicts": len(verdicts), "days_covered": len(by_day)},
        rows=rows,
    )


async def build_engine_coverage(
    redis: aioredis.Redis, *, engines_lock_path: Path = _DEFAULT_ENGINES_LOCK_PATH
) -> Report:
    # SECURITY/robustness: fail-soft on a missing/unreadable lock file - engine
    # coverage is an INFORMATIONAL dashboard panel, so a deployment that hasn't
    # mounted the lock file must degrade to "no OSS-engine data" (empty rows),
    # never a 500 that breaks the whole report/dashboard (observed live: the
    # containerized image doesn't ship vendor/engines.lock.yaml).
    try:
        with engines_lock_path.open(encoding="utf-8") as f:
            lock = yaml.safe_load(f)
    except OSError:
        lock = None
    engines: Mapping[str, Mapping[str, Any]] = (
        lock.get("engines", {}) if isinstance(lock, dict) else {}
    )

    required = floor_engine_names()
    disabled = await list_disabled_engines(redis)

    rows = [
        {
            "name": name,
            "role": spec.get("role"),
            "adapter_status": spec.get("adapter_status", "not_built"),
            "required": name in required,
            "disabled": name in disabled,
        }
        for name, spec in sorted(engines.items())
    ]
    return Report(
        template="engine_coverage",
        since=None,
        until=None,
        summary={
            "total_engines": len(engines),
            "required_floor": sorted(required),
            "currently_disabled": sorted(disabled),
        },
        rows=rows,
    )


async def build_exception_audit(
    session: AsyncSession,
    *,
    since: datetime.datetime | None = None,
    until: datetime.datetime | None = None,
) -> Report:
    """SCOPE NOTE: allowlist grant/revoke is not wired to an HTTP endpoint or
    audited yet (tracked separately) - this query is correct and forward-
    compatible (it will start returning rows the moment those actions exist),
    but returns an empty `rows` today. Not a placeholder: the aggregation
    logic itself is exercised by tests using directly-inserted audit rows."""
    granted = await _audit_entries(session, action="allowlist_granted", since=since, until=until)
    revoked = await _audit_entries(session, action="allowlist_revoked", since=since, until=until)
    rows = [
        {
            "rule_id": e.payload.get("rule_id"),
            "scope_value": e.payload.get("scope_value"),
            "action": action_name,
            "operator": e.operator,
            "occurred_at": e.chained_at.isoformat(),
        }
        for action_name, entries in (("granted", granted), ("revoked", revoked))
        for e in entries
    ]
    rows.sort(key=lambda r: str(r["occurred_at"]))
    return Report(
        template="exception_audit",
        since=since,
        until=until,
        summary={"total_granted": len(granted), "total_revoked": len(revoked)},
        rows=rows,
    )


async def generate_report(
    template: str,
    *,
    session: AsyncSession,
    redis: aioredis.Redis,
    since: datetime.datetime | None = None,
    until: datetime.datetime | None = None,
) -> Report:
    if template == "executive_summary":
        return await build_executive_summary(session, since=since, until=until)
    if template == "compliance_status":
        return await build_compliance_status(session, since=since, until=until)
    if template == "risk_trend":
        return await build_risk_trend(session, since=since, until=until)
    if template == "engine_coverage":
        return await build_engine_coverage(redis)
    if template == "exception_audit":
        return await build_exception_audit(session, since=since, until=until)
    raise UnknownReportTemplateError(
        f"unknown report template {template!r} - must be one of {TEMPLATES}"
    )


async def export_sarif_for_scans(session: AsyncSession, scan_ids: Sequence[str]) -> dict[str, Any]:
    result = await session.execute(
        select(ScanResultReadOnly).where(ScanResultReadOnly.scan_id.in_(scan_ids))
    )
    all_findings = [finding for row in result.scalars().all() for finding in row.findings]
    return findings_to_sarif(all_findings)


def export_csv(report: Report) -> str:
    buffer = io.StringIO()
    if report.rows:
        fieldnames = list(report.rows[0].keys())
        dict_writer = csv.DictWriter(buffer, fieldnames=fieldnames)
        dict_writer.writeheader()
        dict_writer.writerows(report.rows)
    else:
        plain_writer = csv.writer(buffer)
        plain_writer.writerow(["key", "value"])
        for key, value in report.summary.items():
            plain_writer.writerow([key, value])
    return buffer.getvalue()


def export_pdf(report: Report) -> bytes:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, f"skillscan report: {report.template}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    range_text = f"range: {report.since or 'all-time'} .. {report.until or 'now'}"
    pdf.cell(0, 8, range_text, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    for key, value in report.summary.items():
        # SECURITY/BUG: multi_cell does NOT reset the cursor to the left
        # margin by default (unlike cell()) - without new_x/new_y here, each
        # successive call starts from wherever the previous line's text
        # ended, and the available width shrinks call over call until fpdf2
        # raises "Not enough horizontal space to render a single character"
        # (caught by actually running this against a real multi-row report,
        # not assumed correct from reading fpdf2's docs).
        pdf.multi_cell(0, 6, f"{key}: {value}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    if report.rows:
        pdf.set_font("Helvetica", "B", 12)
        shown_rows = report.rows[:_MAX_PDF_ROWS]
        title = "Detail"
        if len(report.rows) > _MAX_PDF_ROWS:
            title += f" (showing {_MAX_PDF_ROWS} of {len(report.rows)} rows)"
        pdf.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        header = list(shown_rows[0].keys())
        pdf.multi_cell(0, 5, " | ".join(header), new_x="LMARGIN", new_y="NEXT")
        for row in shown_rows:
            line = " | ".join(str(row.get(k, "")) for k in header)
            pdf.multi_cell(0, 5, line, new_x="LMARGIN", new_y="NEXT")

    output = pdf.output()
    return bytes(output)
