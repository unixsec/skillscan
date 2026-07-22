"""`GET /v1/admin/intel`, `POST /v1/admin/intel/import` (coding spec §9,
SEC-UPD-010).

SECURITY: admin only. Import fails closed with no partial credit - an
unverifiable or unsigned package applies ZERO indicators (`intel_sync.
import_offline_package`'s own invariant); this router only translates that
into the right HTTP status, never loosens it.
"""

from __future__ import annotations

import datetime
import os
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile
from intel_sync.sync import (
    IntelSyncError,
    import_offline_package,
    summarize_intel_status,
    sync_from_internal_source,
)

from monolith.modules.gateway.auth.dependencies import require_csrf, require_role
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime

router = APIRouter(prefix="/v1/admin/intel")

_admin_only = require_role("admin")

# SECURITY: the internal sync endpoint is server-side config, never a
# caller-supplied request field - if a client could pass an arbitrary URL
# here, require_internal_endpoint's "must be internal/private" check would
# still block public addresses, but this endpoint would become a generic
# internal-network probe (SSRF-adjacent) for any admin session. One fixed,
# operator-configured source keeps this a "sync from THE known internal
# intel feed" action, not "fetch whatever internal URL you like".
# TODO: move into a unified apps/monolith/config.py Settings class once that
# lands (tracked in the same spec-compliance push as this fix) - a direct env
# read is deliberately the smallest safe wiring for now, not a design choice.
_INTEL_SYNC_ENDPOINT_ENV = "SKILLSCAN_INTEL_SYNC_ENDPOINT_URL"


def _get_scan_runtime(request: Request) -> ScanRuntime:
    runtime: ScanRuntime = request.app.state.scan
    return runtime


def _require_intel_session_factory(runtime: ScanRuntime) -> Any:
    if runtime.intel_session_factory is None:
        raise HTTPException(status_code=500, detail="intel module is not configured")
    return runtime.intel_session_factory


@router.get("")
async def get_intel_status(
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    session_factory = _require_intel_session_factory(runtime)
    async with session_factory() as db_session:
        summary = await summarize_intel_status(db_session)
    sources: list[dict[str, Any]] = []
    for row in summary:
        last_imported_at = row["last_imported_at"]
        sources.append(
            {
                "source": row["source"],
                "indicator_count": row["indicator_count"],
                "last_imported_at": (
                    last_imported_at.isoformat()
                    if isinstance(last_imported_at, datetime.datetime)
                    else None
                ),
            }
        )
    return {"sources": sources}


@router.post("/import", status_code=201, dependencies=[Depends(require_csrf)])
async def import_intel_package(
    package: UploadFile,
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    session_factory = _require_intel_session_factory(runtime)
    package_bytes = await package.read()
    try:
        async with session_factory() as db_session, db_session.begin():
            applied = await import_offline_package(
                package_bytes,
                trusted_public_keys=runtime.trusted_intel_public_keys,
                session=db_session,
                source_label=f"offline_package:{session.subject}",
            )
    except IntelSyncError as exc:
        # SECURITY (SEC-UPD-010): every failure here - bad JSON, missing
        # fields, failed signature verification, no trusted keys configured -
        # is fail-closed (zero indicators applied), reported as 400.
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"indicators_applied": applied}


@router.post("/sync", status_code=201, dependencies=[Depends(require_csrf)])
async def sync_intel_from_internal_source(
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    """coding spec §11.4 "内网情报系统同步" - the internal-network-sync half of
    intel-sync (services/intel_sync/sync.py's sync_from_internal_source),
    previously implemented and tested but never invoked by any live process;
    this endpoint is that missing caller, mirroring how /import already wires
    the offline-package half."""
    session_factory = _require_intel_session_factory(runtime)
    endpoint_url = os.environ.get(_INTEL_SYNC_ENDPOINT_ENV)
    if not endpoint_url:
        raise HTTPException(
            status_code=500,
            detail=f"intel network sync is not configured ({_INTEL_SYNC_ENDPOINT_ENV} unset)",
        )
    try:
        async with httpx.AsyncClient() as http_client:
            async with session_factory() as db_session, db_session.begin():
                applied = await sync_from_internal_source(
                    http_client, endpoint_url=endpoint_url, session=db_session
                )
    except (IntelSyncError, httpx.HTTPError, ValueError) as exc:
        # SECURITY: same fail-closed posture as /import - an unreachable
        # endpoint, a non-internal address (require_internal_endpoint raises
        # ValueError - INV-14), or a malformed response all fail the whole
        # sync, never a silent partial apply.
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"indicators_applied": applied, "source": endpoint_url}
