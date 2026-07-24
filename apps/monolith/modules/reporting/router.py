"""`GET/POST /v1/reports*` (coding spec §9/§16.2 FR-REP).

SECURITY: every route requires at least approver/auditor/admin (read) or
admin (schedule-write) - never a lower role, since reports surface aggregate
security posture (verdict outcomes, policy decisions, break-glass activity).
State-changing routes also depend on `require_csrf` (coding spec §16.1
INV-16), same as every other admin-adjacent module this session.
"""

from __future__ import annotations

import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from monolith.modules.gateway.auth.dependencies import require_csrf, require_role
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime

from . import service

router = APIRouter(prefix="/v1/reports")

_REPORT_READ_ROLES = ("approver", "auditor", "admin")
_reader = require_role(*_REPORT_READ_ROLES)
_admin_only = require_role("admin")


def _get_scan_runtime(request: Request) -> ScanRuntime:
    runtime: ScanRuntime = request.app.state.scan
    return runtime


def _require_reporting_session_factory(runtime: ScanRuntime) -> Any:
    if runtime.reporting_session_factory is None:
        # SECURITY: fail-closed - a misconfigured deployment (module not
        # wired) must never look like "no data", it must be an explicit 500.
        raise HTTPException(status_code=500, detail="reporting module is not configured")
    return runtime.reporting_session_factory


def _report_to_dict(report: service.Report) -> dict[str, Any]:
    return {
        "template": report.template,
        "since": report.since.isoformat() if report.since else None,
        "until": report.until.isoformat() if report.until else None,
        "summary": report.summary,
        "rows": report.rows,
    }


class _ScheduleReportBody(BaseModel):
    template: str
    cron: str
    targets: list[str]


@router.get("")
async def get_report(
    template: str,
    since: datetime.datetime | None = None,
    until: datetime.datetime | None = None,
    export: str = "json",
    session: SessionContext = Depends(_reader),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> Response:
    # BUG (reported 2026-07-23): the UI's date-range picker is a bare
    # `<input type="date">` (no time component) - pydantic parses that as
    # midnight, so `until` on its own means "through 00:00:00 of that day,"
    # not through the end of it. Picking the same since/until day then
    # compared as `>= day 00:00 AND <= day 00:00`, an empty instant, making
    # the filter look like it "finds nothing." Treat a midnight `until` as
    # end-of-day inclusive - a caller that explicitly wants an exact midnight
    # cutoff (a non-midnight time never triggers this) is unaffected.
    if until is not None and until.time() == datetime.time.min:
        until = until + datetime.timedelta(days=1) - datetime.timedelta(microseconds=1)
    session_factory = _require_reporting_session_factory(runtime)
    try:
        async with session_factory() as db_session:
            report = await service.generate_report(
                template, session=db_session, redis=runtime.redis, since=since, until=until
            )
    except service.UnknownReportTemplateError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if export == "json":
        return JSONResponse(content=_report_to_dict(report))
    if export == "csv":
        return Response(
            content=service.export_csv(report),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{template}.csv"'},
        )
    if export == "pdf":
        return Response(
            content=service.export_pdf(report),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{template}.pdf"'},
        )
    raise HTTPException(
        status_code=400, detail=f"unknown export format {export!r} - must be json/csv/pdf"
    )


@router.get("/sarif")
async def get_report_sarif(
    scan_ids: str,
    session: SessionContext = Depends(_reader),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    session_factory = _require_reporting_session_factory(runtime)
    ids = [s for s in scan_ids.split(",") if s]
    if not ids:
        raise HTTPException(status_code=400, detail="scan_ids must contain at least one scan id")
    async with session_factory() as db_session:
        return await service.export_sarif_for_scans(db_session, ids)


@router.get("/schedule")
async def list_report_schedules(
    session: SessionContext = Depends(_reader),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    session_factory = _require_reporting_session_factory(runtime)
    async with session_factory() as db_session:
        schedules = await service.list_schedules(db_session)
    return {
        "schedules": [
            {
                "id": s.id,
                "template": s.template,
                "cron": s.cron,
                "targets": s.targets,
                "created_by": s.created_by,
                "created_at": s.created_at.isoformat(),
            }
            for s in schedules
        ]
    }


@router.post("/schedule", status_code=201, dependencies=[Depends(require_csrf)])
async def create_report_schedule(
    body: _ScheduleReportBody,
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    session_factory = _require_reporting_session_factory(runtime)
    try:
        async with session_factory() as db_session, db_session.begin():
            row = await service.schedule_report(
                db_session,
                template=body.template,
                cron=body.cron,
                targets=body.targets,
                created_by=session.subject,
            )
    except service.ReportingError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "id": row.id,
        "template": row.template,
        "cron": row.cron,
        "targets": row.targets,
        "created_by": row.created_by,
    }
