"""`GET /v1/audit` (coding spec §9: "审计(只读)+ 链校验状态").

SECURITY: auditor/admin only - this exposes the full audit trail (every
verdict, policy decision, lifecycle transition, break-glass event system-
wide), a higher-sensitivity read than any other list endpoint in this system.
Read-only by construction - svc_audit's own INSERT is only ever used by
audit.service's chain-append drain, never by this router.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select

from monolith.modules.gateway.auth.dependencies import require_role
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime

from .models import AuditEntry
from .service import verify_chain

router = APIRouter(prefix="/v1/audit")

_reader = require_role("auditor", "admin")
_MAX_LIMIT = 500
_DEFAULT_LIMIT = 100


def _get_scan_runtime(request: Request) -> ScanRuntime:
    runtime: ScanRuntime = request.app.state.scan
    return runtime


def _require_audit_session_factory(runtime: ScanRuntime) -> Any:
    if runtime.audit_session_factory is None:
        raise HTTPException(status_code=500, detail="audit module is not configured")
    return runtime.audit_session_factory


@router.get("")
async def get_audit_log(
    since_seq: int = 0,
    limit: int = _DEFAULT_LIMIT,
    session: SessionContext = Depends(_reader),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    session_factory = _require_audit_session_factory(runtime)
    # SECURITY: fail-closed bound - a caller-supplied `limit` can never force
    # an unbounded scan of the whole ledger.
    bounded_limit = max(1, min(limit, _MAX_LIMIT))
    async with session_factory() as db_session:
        if since_seq > 0:
            # Caller asked for a specific starting point (incremental sync /
            # resuming chain verification from a checkpoint) - ascending order
            # from there is the natural read direction.
            result = await db_session.execute(
                select(AuditEntry)
                .where(AuditEntry.seq >= since_seq)
                .order_by(AuditEntry.seq.asc())
                .limit(bounded_limit)
            )
            entries = list(result.scalars().all())
        else:
            # BUG (caught by testing against this session's real, ~3000-row
            # accumulated audit_entry table, not an empty test DB): plain
            # "seq >= 0 ORDER BY seq ASC LIMIT N" returns the OLDEST N rows,
            # not recent activity - useless as an audit-log viewer default.
            # Fetch the most recent page (DESC) instead, then reverse back to
            # chronological order for display.
            result = await db_session.execute(
                select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(bounded_limit)
            )
            entries = list(reversed(result.scalars().all()))
        # SECURITY (milestone F Task 17): `since_seq` pages the READ; it must
        # never narrow the VERIFICATION. It used to be passed straight through
        # to verify_chain(), which anchored the scan on the entry at the cursor
        # - so a request for a page near the tail reported "chain intact" while
        # never looking at (let alone re-hashing) any entry before the cursor,
        # which is precisely where a rewrite would be hidden. `chain_valid` is
        # a whole-ledger claim on every response, whatever page was asked for.
        chain_valid = await verify_chain(db_session)
    return {
        "chain_valid": chain_valid,
        "entries": [
            {
                "seq": e.seq,
                "operator": e.operator,
                "action": e.action,
                "payload": e.payload,
                "chained_at": e.chained_at.isoformat(),
            }
            for e in entries
        ],
    }
