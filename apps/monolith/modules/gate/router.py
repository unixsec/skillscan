"""`GET/POST /v1/allowlist`, `DELETE /v1/allowlist/{id}` (coding spec §9,
INV-8).

SECURITY: `approved_by` is ALWAYS the authenticated caller (`session.subject`)
- never client-supplied - so four-eyes (`approved_by != requested_by`,
enforced by `skillscan_core.AllowlistEntry.__post_init__`) can't be spoofed by
naming a fake approver. `requested_by` names whoever originally asked for the
exemption (may be any identity, e.g. a submitter who asked out-of-band) and
IS caller-supplied - only who *approves* it is trusted from the session.
A hard-gate-rule exemption additionally requires admin specifically (coding
spec: "硬门禁豁免需 admin"), checked against the ACTIVE policy's
`hard_gate_rules`, mirroring gate.policy_workflow's own hard-gate scoping.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from monolith.modules.gateway.auth.dependencies import require_csrf, require_role
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.modules.inventory.models import SkillRow, SkillVersionRow
from monolith.modules.orchestration.models import ScanResultRow

from .service import (
    AllowlistError,
    grant_allowlist_entry,
    list_active_allowlist_rows,
    revoke_allowlist_entry,
)

router = APIRouter(prefix="/v1/allowlist")

_reader_or_writer = require_role("approver", "admin")
_admin_only = require_role("admin")


def _get_scan_runtime(request: Request) -> ScanRuntime:
    runtime: ScanRuntime = request.app.state.scan
    return runtime


class _GrantAllowlistBody(BaseModel):
    scope_type: str
    scope_value: str
    # `allowlist.rule_id` is VARCHAR(128) and MySQL runs in strict mode, so an
    # over-length value is a DataError, not a truncation - and `create_allowlist_entry`
    # only catches `AllowlistError`, so it escapes as a 500 with the
    # same-transaction `audit_intent` rolled back beside it: the grant silently
    # does not exist and nothing recorded the attempt.
    #
    # SECOND of two bounds, not the only one (2026-07-29, review N-2). The
    # candidates this field is filled from come from `_known_rule_ids` below,
    # i.e. out of untrusted findings blobs, and that is bounded at the blob
    # trust boundary (`schemas.findings._MAX_RULE_ID_CHARS`). This one bounds
    # the OTHER way in: an operator, or a script, POSTing a rule_id by hand -
    # a 422 naming the field instead of a 500 naming nothing.
    rule_id: str = Field(max_length=128)
    expires_at: float
    requested_by: str
    reason: str = ""


def _row_to_dict(row: Any, *, skill_id_by_content_hash: dict[str, str]) -> dict[str, Any]:
    # UX (2026-07-14, item #8): a `content_hash`-scoped entry is otherwise a
    # bare hash with no indication of which skill it belongs to - resolved
    # here, best-effort (None if the hash isn't in inventory, e.g. an
    # anonymous/unregistered scan), never blocking the entry from rendering.
    resolved_skill_id = (
        skill_id_by_content_hash.get(row.scope_value) if row.scope_type == "content_hash" else None
    )
    return {
        "id": row.id,
        "scope_type": row.scope_type,
        "scope_value": row.scope_value,
        "resolved_skill_id": resolved_skill_id,
        "rule_id": row.rule_id,
        "expires_at": row.expires_at.isoformat(),
        "approved_by": row.approved_by,
        "requested_by": row.requested_by,
        "reason": row.reason,
    }


async def _known_rule_ids(runtime: ScanRuntime) -> list[dict[str, Any]]:
    """UX (2026-07-14, item #8): rule_id is otherwise a free-text field the
    operator must know and type exactly right, with no indication of which
    ones are hard-gate (INV-3/INV-8: exempting one requires admin - see this
    router's own module docstring). Sourced from findings actually recorded
    on real scans, never a hand-maintained/guessable list (the exact bug
    class engine_runner/sandbox_engines.py's SANDBOX_ENGINE_NAMES comment
    warns about for a different list) - so it can never drift out of sync
    with what real engines actually emit."""
    if runtime.orchestration_session_factory is None:
        return []
    seen: set[str] = set()
    async with runtime.orchestration_session_factory() as orch_session:
        rows = (await orch_session.execute(select(ScanResultRow.findings))).scalars().all()
    for findings in rows:
        for finding in findings or ():
            rule_id = finding.get("rule_id") if isinstance(finding, dict) else None
            if isinstance(rule_id, str):
                seen.add(rule_id)
    return [
        {"rule_id": rid, "is_hard_gate": rid in runtime.policy.hard_gate_rules}
        for rid in sorted(seen)
    ]


async def _known_skills(runtime: ScanRuntime) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Returns (candidates for the form, content_hash->skill_id lookup for
    _row_to_dict) in one pass - both need the same skill/skill_version data."""
    if runtime.inventory_session_factory is None:
        return [], {}
    async with runtime.inventory_session_factory() as inv_session:
        skill_ids = (await inv_session.execute(select(SkillRow.skill_id))).scalars().all()
        version_rows = (
            await inv_session.execute(
                select(SkillVersionRow.skill_id, SkillVersionRow.content_hash)
            )
        ).all()
    skill_id_by_content_hash = {content_hash: skill_id for skill_id, content_hash in version_rows}
    versions_by_skill: dict[str, list[str]] = {}
    for skill_id, content_hash in version_rows:
        versions_by_skill.setdefault(skill_id, []).append(content_hash)
    candidates = [
        {"skill_id": s, "content_hashes": versions_by_skill.get(s, [])} for s in sorted(skill_ids)
    ]
    return candidates, skill_id_by_content_hash


@router.get("")
async def list_allowlist(
    session: SessionContext = Depends(_reader_or_writer),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    async with runtime.gate_session_factory() as db_session:
        rows = await list_active_allowlist_rows(db_session, now=time.time())
    known_skills, skill_id_by_content_hash = await _known_skills(runtime)
    return {
        "entries": [
            _row_to_dict(row, skill_id_by_content_hash=skill_id_by_content_hash) for row in rows
        ],
        "candidates": {
            "skills": known_skills,
            "rule_ids": await _known_rule_ids(runtime),
        },
    }


@router.post("", status_code=201, dependencies=[Depends(require_csrf)])
async def create_allowlist_entry(
    body: _GrantAllowlistBody,
    session: SessionContext = Depends(_reader_or_writer),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    if body.rule_id in runtime.policy.hard_gate_rules and not session.has_role("admin"):
        # SECURITY: "硬门禁豁免需 admin" - an approver (non-admin) may grant
        # ordinary exemptions, but never one that waives a hard-gate rule.
        raise HTTPException(
            status_code=403, detail="exempting a hard-gate rule requires the admin role"
        )
    try:
        async with runtime.gate_session_factory() as db_session, db_session.begin():
            row = await grant_allowlist_entry(
                db_session,
                scope_type=body.scope_type,
                scope_value=body.scope_value,
                rule_id=body.rule_id,
                expires_at=body.expires_at,
                approved_by=session.subject,
                requested_by=body.requested_by,
                reason=body.reason,
            )
    except AllowlistError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    # Task 13 (2026-07-29): `allowlist_entries_total` (coding spec §11.7's
    # "加白增长"). Counted AFTER the transaction that wrote the row committed,
    # never before - an entry that failed four-eyes/expiry validation, or
    # whose transaction rolled back, did not grow the allowlist, and a
    # growth indicator that counts attempts is not a growth indicator.
    #
    # It counts GRANTS, not the live entry count: revocation
    # (`delete_allowlist_entry`) does not decrement, because a Counter cannot
    # go down and must not pretend to. The question this answers is "how fast
    # are we accumulating exemptions", which is the risk that matters; "how
    # many are active right now" is `GET /v1/allowlist`.
    runtime.security_metrics.allowlist_entries_total.inc()
    _, skill_id_by_content_hash = await _known_skills(runtime)
    return _row_to_dict(row, skill_id_by_content_hash=skill_id_by_content_hash)


@router.delete("/{allowlist_id}", dependencies=[Depends(require_csrf)])
async def delete_allowlist_entry(
    allowlist_id: str,
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, str]:
    try:
        async with runtime.gate_session_factory() as db_session, db_session.begin():
            await revoke_allowlist_entry(
                db_session, allowlist_id=allowlist_id, actor=session.subject
            )
    except AllowlistError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"id": allowlist_id, "status": "revoked"}
