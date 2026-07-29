"""§9 /v1/admin/* endpoints (coding spec §16.1 Admin·Engines/Policy/Users,
§16.3 Admin·BreakGlass).

SECURITY: every route requires `admin` (never a lower role, even read-only
GETs - these expose operational/security-relevant configuration) EXCEPT
`POST /v1/admin/breakglass/login`, which by necessity has no prior session to
require (that's the entire point of break-glass - the IdP, and therefore
every normal path to a session, may be unreachable); every OTHER
state-changing route also depends on `require_csrf`, but the login endpoint
does not (a login endpoint creates the very session CSRF would otherwise
protect - it has nothing to ride on yet, same as any login endpoint).
"""

from __future__ import annotations

from typing import Any

from common.log import get_logger

# SECURITY/HONESTY (2026-07-13): the sandboxed OSS engines (bandit/osv-scanner/
# yara/skillspector/aig-mcp-scan) run in the separate engine-runner service,
# not in-process here, so they were never in `runtime.engine_metadatas` and
# never showed up on this admin page at all - every engine an admin COULD see
# was a floor engine, which INV-1 correctly never lets you disable, so the
# disable control looked permanently broken. `SANDBOX_ENGINE_NAMES` is the
# one canonical name list (services/engine_runner/sandbox_engines.py's own
# docstring explains why a second hardcoded copy of this list already caused
# a real bug once) - imported, never duplicated.
from engine_runner.sandbox_engines import SANDBOX_ENGINE_NAMES
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from monolith.modules.gate.models import AuditIntentInsertOnly, PolicyProposalRow
from monolith.modules.gate.policy_workflow import (
    PolicyProposalError,
    approve_policy_proposal,
    propose_policy_change,
    reject_policy_proposal,
)
from monolith.modules.gateway.auth.dependencies import AuthRuntime, require_csrf, require_role
from monolith.modules.gateway.auth.middleware import (
    BREAKGLASS_SESSION_COOKIE_NAME,
    LOCAL_SESSION_COOKIE_NAME,
    generate_csrf_token,
    set_csrf_cookie,
    set_session_cookie,
)
from monolith.modules.gateway.auth.rbac import KNOWN_ROLES
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.modules.orchestration.floor import floor_engine_names

from . import accounts_service, breakglass, local_auth
from .engine_registry import EngineDisableError, list_disabled_engines, set_engine_enabled
from .models import GroupRoleMappingRow, LocalAccountRow

router = APIRouter(prefix="/v1/admin")

_admin_only = require_role("admin")
_logger = get_logger("skillscan.admin.breakglass")


def _get_scan_runtime(request: Request) -> ScanRuntime:
    runtime: ScanRuntime = request.app.state.scan
    return runtime


class _SetEngineEnabledBody(BaseModel):
    enabled: bool


class _ProposePolicyBody(BaseModel):
    policy_yaml: str


class _DecideProposalBody(BaseModel):
    reason: str = ""


def _proposal_to_dict(proposal: PolicyProposalRow) -> dict[str, Any]:
    return {
        "id": proposal.id,
        "changes_hard_gate_rules": proposal.changes_hard_gate_rules,
        "status": proposal.status,
        "proposed_by": proposal.proposed_by,
        "approved_by": proposal.approved_by,
        "reason": proposal.reason,
        "created_at": proposal.created_at.isoformat(),
        "decided_at": proposal.decided_at.isoformat() if proposal.decided_at else None,
    }


@router.get("/engines")
async def list_engines(
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    required = floor_engine_names()
    disabled = await list_disabled_engines(runtime.redis)
    engines = [
        {
            "name": metadata.name,
            "version": metadata.version,
            "required": metadata.name in required,
            "enabled": metadata.name not in disabled,
            "capabilities": sorted(c.value for c in metadata.capabilities),
        }
        for metadata in runtime.engine_metadatas
    ]
    # SANDBOX_ENGINE_NAMES has no version/capabilities metadata reachable from
    # the monolith (that lives in the separate engine-runner service/image) -
    # "sandboxed" itself is the meaningful capability tag here, distinguishing
    # these rows from the floor engines above.
    engines += [
        {
            "name": name,
            "version": None,
            "required": False,
            "enabled": name not in disabled,
            "capabilities": ["sandboxed"],
        }
        for name in SANDBOX_ENGINE_NAMES
    ]
    return {"engines": engines}


@router.patch("/engines/{name}", dependencies=[Depends(require_csrf)])
async def set_engine_enabled_endpoint(
    name: str,
    body: _SetEngineEnabledBody,
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    required = floor_engine_names()
    known_names = {metadata.name for metadata in runtime.engine_metadatas} | set(
        SANDBOX_ENGINE_NAMES
    )
    if name not in known_names:
        # Without this, is_disableable() only checks "not a required floor
        # engine" - any unknown/misspelled name is silently accepted and
        # written into the shared disabled-engines Redis set (200 response,
        # no row in list_engines to ever notice or undo it from the UI).
        raise HTTPException(status_code=404, detail=f"no such engine {name!r}")
    try:
        await set_engine_enabled(runtime.redis, name, enabled=body.enabled, required_names=required)
    except EngineDisableError as exc:
        # SECURITY (INV-1): a required floor engine can never be disabled -
        # a 409, never a silent no-op that would look like it worked.
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    # SECURITY (coding spec §16.1: "admin 高危操作...经审计"): engine enable/
    # disable state lives in Redis only (admin has no DB user of its own,
    # policies/grants/manifest.yaml), so this can't be the same atomic
    # transaction as the Redis write above - same best-effort-after-mutation
    # shape already established for breakglass activate/login below.
    async with runtime.gate_session_factory() as gate_session, gate_session.begin():
        gate_session.add(
            AuditIntentInsertOnly(
                operator=session.subject,
                action="engine_enabled_changed",
                payload={"name": name, "enabled": body.enabled},
            )
        )
    return {"name": name, "enabled": body.enabled}


@router.get("/policy")
async def get_policy(
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    policy = runtime.policy
    async with runtime.gate_session_factory() as gate_session:
        pending = (
            (
                await gate_session.execute(
                    select(PolicyProposalRow).where(PolicyProposalRow.status == "pending")
                )
            )
            .scalars()
            .all()
        )
    return {
        "active_policy": {
            "version": policy.version,
            "required_engines": sorted(policy.required_engines),
            "hard_gate_rules": sorted(policy.hard_gate_rules),
            "review_confidence": policy.review_confidence,
            "block_on_severity": policy.block_on_severity.name,
            "review_on_severity": policy.review_on_severity.name,
        },
        "pending_proposals": [_proposal_to_dict(p) for p in pending],
    }


@router.post("/policy", status_code=201, dependencies=[Depends(require_csrf)])
async def propose_policy(
    body: _ProposePolicyBody,
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    async with runtime.gate_session_factory() as gate_session, gate_session.begin():
        try:
            proposal = await propose_policy_change(
                gate_session,
                proposed_by=session.subject,
                current_hard_gate_rules=runtime.policy.hard_gate_rules,
                proposed_policy_yaml=body.policy_yaml,
            )
        except PolicyProposalError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _proposal_to_dict(proposal)


@router.post("/policy/{proposal_id}/approve", dependencies=[Depends(require_csrf)])
async def approve_policy(
    proposal_id: int,
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    async with runtime.gate_session_factory() as gate_session, gate_session.begin():
        proposal = await gate_session.get(PolicyProposalRow, proposal_id)
        if proposal is None:
            raise HTTPException(status_code=404, detail="proposal not found")
        try:
            # SECURITY (four-eyes): raises if session.subject == proposal.proposed_by.
            await approve_policy_proposal(gate_session, proposal, approved_by=session.subject)
        except PolicyProposalError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
    # Apply THIS approved proposal to the running gate (previously an approved
    # proposal changed nothing until someone hand-edited the policy yaml - the
    # approve button had no operational effect). promote_approved_policy has
    # fail-closed guards (unparseable yaml / required engines unavailable in
    # this deployment refuse to apply and leave the row at 'approved'); on
    # success the row becomes 'applied', which the background worker re-reads
    # every tick - that's what makes the apply durable across restarts and
    # convergent across replicas.
    from monolith.worker import promote_approved_policy  # local: worker composes many modules

    applied = await promote_approved_policy(runtime, proposal_id=proposal_id)
    result = _proposal_to_dict(proposal)
    result["applied"] = applied
    return result


@router.post("/policy/{proposal_id}/reject", dependencies=[Depends(require_csrf)])
async def reject_policy(
    proposal_id: int,
    body: _DecideProposalBody,
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    async with runtime.gate_session_factory() as gate_session, gate_session.begin():
        proposal = await gate_session.get(PolicyProposalRow, proposal_id)
        if proposal is None:
            raise HTTPException(status_code=404, detail="proposal not found")
        try:
            await reject_policy_proposal(
                gate_session, proposal, rejected_by=session.subject, reason=body.reason
            )
        except PolicyProposalError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _proposal_to_dict(proposal)


@router.get("/users")
async def list_users(
    request: Request,
    session: SessionContext = Depends(_admin_only),
) -> dict[str, Any]:
    # SECURITY (§16.3): "用户/角色可见(IdP 派生,只读)". 2026-07-14 (item #13):
    # this endpoint's SHAPE is unchanged (still the live group->role mapping),
    # but it's no longer read-only-by-construction - group_role_mapping is now
    # a DB table an admin can edit at runtime (see the /rbac/group-role-map
    # endpoints below); `auth_runtime.group_role_map` is kept in sync with the
    # DB in-place (main.py's `_seed_admin_tables_if_empty` on boot, these
    # endpoints on every edit), so this GET always reflects current state
    # either way.
    auth_runtime: AuthRuntime = request.app.state.auth
    return {"group_role_map": dict(auth_runtime.group_role_map)}


class _CreateAccountBody(BaseModel):
    username: str
    role: str
    initial_password: str


class _UpdateAccountBody(BaseModel):
    role: str | None = None
    status: str | None = None


class _ResetPasswordBody(BaseModel):
    new_password: str


class _UpsertGroupRoleMapBody(BaseModel):
    role: str


def _require_admin_session_factory(runtime: ScanRuntime) -> Any:
    if runtime.admin_session_factory is None:
        # SECURITY: fail-closed - a misconfigured deployment (module not
        # wired) must never look like "no accounts", it must be an explicit
        # 500, same posture as reporting.router's own guard.
        raise HTTPException(status_code=500, detail="admin accounts module is not configured")
    return runtime.admin_session_factory


def _account_to_dict(row: LocalAccountRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "username": row.username,
        "role": row.role,
        "status": row.status,
        "created_by": row.created_by,
        "created_at": row.created_at.isoformat(),
        "updated_at": row.updated_at.isoformat(),
    }


@router.get("/accounts")
async def list_accounts_endpoint(
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    session_factory = _require_admin_session_factory(runtime)
    async with session_factory() as admin_session:
        rows = await accounts_service.list_accounts(admin_session)
    return {"accounts": [_account_to_dict(r) for r in rows]}


@router.post("/accounts", status_code=201, dependencies=[Depends(require_csrf)])
async def create_account_endpoint(
    body: _CreateAccountBody,
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    session_factory = _require_admin_session_factory(runtime)
    try:
        async with session_factory() as admin_session, admin_session.begin():
            row = await accounts_service.create_account(
                admin_session,
                username=body.username,
                role=body.role,
                initial_password=body.initial_password,
                created_by=session.subject,
                known_roles=KNOWN_ROLES,
            )
    except accounts_service.AdminAccountError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except IntegrityError as exc:
        # TOCTOU: two concurrent creates for the same username can both pass
        # accounts_service's own uniqueness pre-check before either commits -
        # the `local_account.username` UNIQUE constraint is the real backstop,
        # surfaced here as the same 400 the pre-check itself would give.
        raise HTTPException(
            status_code=400, detail=f"username {body.username!r} is already taken"
        ) from exc
    return _account_to_dict(row)


@router.patch("/accounts/{account_id}", dependencies=[Depends(require_csrf)])
async def update_account_endpoint(
    account_id: int,
    body: _UpdateAccountBody,
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    session_factory = _require_admin_session_factory(runtime)
    try:
        async with session_factory() as admin_session, admin_session.begin():
            row = await accounts_service.set_account_role_status(
                admin_session,
                account_id=account_id,
                role=body.role,
                status=body.status,
                actor=session.subject,
                known_roles=KNOWN_ROLES,
            )
    except accounts_service.AdminAccountError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _account_to_dict(row)


@router.post("/accounts/{account_id}/reset-password", dependencies=[Depends(require_csrf)])
async def reset_account_password_endpoint(
    account_id: int,
    body: _ResetPasswordBody,
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, str]:
    session_factory = _require_admin_session_factory(runtime)
    try:
        async with session_factory() as admin_session, admin_session.begin():
            await accounts_service.reset_password(
                admin_session,
                account_id=account_id,
                new_password=body.new_password,
                actor=session.subject,
            )
    except accounts_service.AdminAccountError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"id": str(account_id), "status": "password_reset"}


def _group_role_map_row_to_dict(row: GroupRoleMappingRow) -> dict[str, Any]:
    return {
        "group_name": row.group_name,
        "role": row.role,
        "updated_by": row.updated_by,
        "updated_at": row.updated_at.isoformat(),
    }


@router.put("/rbac/group-role-map/{group_name}", dependencies=[Depends(require_csrf)])
async def upsert_group_role_map_endpoint(
    group_name: str,
    body: _UpsertGroupRoleMapBody,
    request: Request,
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    session_factory = _require_admin_session_factory(runtime)
    try:
        async with session_factory() as admin_session, admin_session.begin():
            row = await accounts_service.upsert_group_role_mapping(
                admin_session,
                group_name=group_name,
                role=body.role,
                actor=session.subject,
                known_roles=KNOWN_ROLES,
            )
    except accounts_service.AdminAccountError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    # SECURITY: takes effect immediately for THIS process - mutates the SAME
    # dict object every request dependency already holds a reference to (see
    # main.py's _seed_admin_tables_if_empty docstring for the documented
    # single-replica limitation of this approach).
    auth_runtime: AuthRuntime = request.app.state.auth
    auth_runtime.group_role_map[group_name] = body.role
    return _group_role_map_row_to_dict(row)


@router.delete("/rbac/group-role-map/{group_name}", dependencies=[Depends(require_csrf)])
async def delete_group_role_map_endpoint(
    group_name: str,
    request: Request,
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, str]:
    session_factory = _require_admin_session_factory(runtime)
    try:
        async with session_factory() as admin_session, admin_session.begin():
            await accounts_service.delete_group_role_mapping(
                admin_session, group_name=group_name, actor=session.subject
            )
    except accounts_service.AdminAccountError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    auth_runtime: AuthRuntime = request.app.state.auth
    auth_runtime.group_role_map.pop(group_name, None)
    return {"group_name": group_name, "status": "removed"}


class _ActivateBreakGlassBody(BaseModel):
    second_activator: str
    totp_code: str


class _LoginBreakGlassBody(BaseModel):
    credential: str
    totp_code: str


@router.get("/breakglass")
async def get_breakglass_status(
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    armed = await breakglass.is_armed(runtime.redis) if runtime.breakglass_enabled else False
    return {"enabled": runtime.breakglass_enabled, "armed": armed}


@router.post("/breakglass/activate", dependencies=[Depends(require_csrf)])
async def activate_breakglass_endpoint(
    request: Request,
    body: _ActivateBreakGlassBody,
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    if not runtime.breakglass_enabled or runtime.breakglass_credentials is None:
        raise HTTPException(status_code=404, detail="break-glass is not configured")

    # SECURITY (BUG 2 fix - four-eyes was not real): explicitly reject
    # `body.second_activator` naming the CALLER's own identity, even in some
    # edge case where it might differ textually from `activator_a` as passed
    # below (today `activator_a` is always exactly `session.subject`, so this
    # duplicates breakglass.activate_breakglass's own `activator_a ==
    # activator_b` check - kept here too, at the layer that actually knows
    # "who is calling", as defense in depth against a future refactor where
    # `activator_a` might stop being a straight passthrough of
    # `session.subject`).
    if body.second_activator == session.subject:
        raise HTTPException(
            status_code=403,
            detail="break-glass activation requires the second activator to be someone other "
            "than the caller themselves",
        )

    # SECURITY (BUG 2 fix): `known_admin_subjects` is this deployment's best
    # available allowlist for validating `body.second_activator` is a real,
    # known admin identity - NOT a live IdP lookup of that specific identity
    # (this system has no local user/identity directory at all - see
    # `list_users`'s docstring above). `group_role_map.yaml` is a group name
    # -> role mapping, not an identity registry, so this reuses the
    # admin-mapped GROUP NAMES themselves as the allowlist - the closest
    # config-as-code, deployment-owned source of truth this codebase
    # actually has, per breakglass.activate_breakglass's own docstring on
    # this fix's documented limitation. A real per-identity check would
    # require this system to grow an actual user directory, which is out of
    # scope for this fix.
    auth_runtime: AuthRuntime = request.app.state.auth
    known_admin_subjects = frozenset(
        group for group, role in auth_runtime.group_role_map.items() if role == "admin"
    )

    totp_secret = await runtime.breakglass_credentials.fetch_totp_secret()
    try:
        # SECURITY (four-eyes + MFA): `session.subject` is the FIRST activator
        # (the admin who is actually authenticated and calling this endpoint) -
        # never client-supplied, so this can't be spoofed to claim a different
        # first activator than whoever is really logged in.
        activation = await breakglass.activate_breakglass(
            runtime.redis,
            activator_a=session.subject,
            activator_b=body.second_activator,
            totp_code=body.totp_code,
            totp_secret=totp_secret,
            known_admin_subjects=known_admin_subjects,
        )
    except breakglass.BreakGlassError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    # SECURITY (§16.3): every activation is fully audited + alerts SecOps -
    # never a silent state flip. Audited via GATE's own INSERT-only grant
    # (admin has no DB user of its own - gate.models.AuditIntentInsertOnly's
    # cross-module write pattern is already established for exactly this).
    async with runtime.gate_session_factory() as gate_session, gate_session.begin():
        gate_session.add(
            AuditIntentInsertOnly(
                operator=session.subject,
                action="breakglass_activated",
                payload={
                    "activated_by": list(activation.activated_by),
                    "expires_at": activation.expires_at.isoformat(),
                },
            )
        )
    _logger.warning(
        "BREAK-GLASS ACTIVATED",
        extra={
            "context": {
                "activated_by": activation.activated_by,
                "expires_at": activation.expires_at.isoformat(),
                "alert": "secops",
            }
        },
    )
    return {
        "activated_by": list(activation.activated_by),
        "expires_at": activation.expires_at.isoformat(),
    }


@router.post("/breakglass/login")
async def login_breakglass(
    body: _LoginBreakGlassBody, request: Request, response: Response
) -> dict[str, Any]:
    """SECURITY: deliberately NOT gated by `require_role`/`require_csrf` -
    there is no prior session to require or protect (the entire premise of
    break-glass is that the IdP, and therefore every NORMAL path to a
    session, may be unreachable). Authenticated purely by the break-glass
    credential + TOTP code themselves."""
    runtime: ScanRuntime = request.app.state.scan
    if not runtime.breakglass_enabled or runtime.breakglass_credentials is None:
        raise HTTPException(status_code=404, detail="break-glass is not configured")

    expected_credential = await runtime.breakglass_credentials.fetch_credential()
    totp_secret = await runtime.breakglass_credentials.fetch_totp_secret()
    ok = await breakglass.authenticate_breakglass(
        runtime.redis,
        supplied_credential=body.credential,
        expected_credential=expected_credential,
        totp_code=body.totp_code,
        totp_secret=totp_secret,
    )
    if not ok:
        # SECURITY (FR-API-060): one generic failure reason - not armed? wrong
        # credential? wrong TOTP? - never distinguished in the response, which
        # would help an attacker narrow down which check to focus on.
        raise HTTPException(status_code=401, detail="break-glass authentication failed")

    session_token = await breakglass.create_breakglass_session(
        runtime.redis, subject="breakglass-admin"
    )
    set_session_cookie(
        response,
        name=BREAKGLASS_SESSION_COOKIE_NAME,
        value=session_token,
        max_age_s=breakglass.BREAKGLASS_SESSION_TTL_S,
    )
    csrf_token = generate_csrf_token()
    set_csrf_cookie(response, csrf_token)

    # SECURITY (§16.3): full audit + SecOps alert on every LOGIN too, not just
    # activation - a break-glass session being USED is exactly as significant
    # as it being armed.
    async with runtime.gate_session_factory() as gate_session, gate_session.begin():
        gate_session.add(
            AuditIntentInsertOnly(
                operator="breakglass-admin", action="breakglass_login", payload={}
            )
        )
    _logger.warning("BREAK-GLASS LOGIN USED", extra={"context": {"alert": "secops"}})
    return {"status": "ok"}


class _LoginLocalBody(BaseModel):
    username: str
    password: str


@router.post("/local/login")
async def login_local(
    body: _LoginLocalBody, request: Request, response: Response
) -> dict[str, Any]:
    """SECURITY (2026-07-13 local-auth addition): deliberately NOT gated by
    `require_role`/`require_csrf` - same reasoning as `login_breakglass`
    above, there is no prior session to require or protect. Authenticated
    purely by the local account's username + password."""
    runtime: ScanRuntime = request.app.state.scan
    if not runtime.local_auth_enabled or runtime.local_account_store is None:
        raise HTTPException(status_code=404, detail="local auth is not configured")

    account = await local_auth.authenticate_local(
        runtime.redis, runtime.local_account_store, username=body.username, password=body.password
    )
    if account is None:
        # SECURITY (FR-API-060): one generic failure reason, matching
        # login_breakglass - never distinguishes unknown username / locked
        # out / wrong password in the response.
        raise HTTPException(status_code=401, detail="local authentication failed")

    session_token = await local_auth.create_local_session(
        runtime.redis, subject=account.username, role=account.role
    )
    set_session_cookie(
        response,
        name=LOCAL_SESSION_COOKIE_NAME,
        value=session_token,
        max_age_s=local_auth.LOCAL_SESSION_TTL_S,
    )
    csrf_token = generate_csrf_token()
    set_csrf_cookie(response, csrf_token)

    # SECURITY (§16.3 precedent): full audit on every local-account login too,
    # same posture as break-glass logins.
    async with runtime.gate_session_factory() as gate_session, gate_session.begin():
        gate_session.add(
            AuditIntentInsertOnly(
                operator=account.username, action="local_login", payload={"role": account.role}
            )
        )
    _logger.info("local account login", extra={"context": {"username": account.username}})
    return {"status": "ok"}
