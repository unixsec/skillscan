"""Marketplace-facing endpoints (里程碑 B' spec §4) - the pull-model contract.

The marketplace submits through `POST /v1/market/scans` and then polls
`GET /v1/market/skills/{skill_id}`. Both live under their own `/v1/market`
prefix, entirely separate from the console's `/v1/scans` (spec §3.1 rule 3):
two audiences, two surfaces, so an internal refactor of the console's response
shape can never become a breaking change for an external integrator.

2026-07-30 - THE POLL IS KEYED ON `skill_id`, AND THE OLD SCAN-KEYED ENDPOINT IS
GONE. `GET /v1/market/scans/{scan_id}` was REPLACED, not deprecated alongside a
successor (owner decision: replace outright). Three consequences ripple from that
one decision, each recorded where it lands:

  * submit now REQUIRES `skill_id`, reversing this module's own prior "no skill_id,
    the external contract is scan-in verdict-out" - see `submit_marketplace_scan`;
  * authorization moves from `scan_submitter` membership to `skill.owner` - see
    `get_marketplace_skill`;
  * the answer is BINARY (`is_safe` + `unsafe_reason`), see `views`.

SECURITY / ARCHITECTURE - the four rules this file exists to enforce:

1. **Nothing internal leaks out.** Every response body is
   `views.project_skill_verdict`'s output and nothing else - never an ORM row,
   never an internal dataclass. The projection is a WHITELIST (see views.py), so
   a new internal column is invisible externally by default. One `return job`
   here would make the internal model the contract, permanently.

2. **No caller-supplied `trust_tier`.** That value decides the BLOCK threshold
   (spec §4.1), so accepting it would let a caller submitting untrusted public
   content declare itself `internal` and downgrade a HIGH finding that should
   have blocked. The tier comes from `session.tier`, resolved per service
   account by `gateway.auth.m2m.resolve_grant`. A caller that sends the field
   anyway gets a 400 rather than silent removal - silently ignoring it leaves
   them believing their setting took effect.

3. **Object-level authz answers 404, not 403.** A 403 on someone else's skill
   confirms that skill_id exists, which is enough to enumerate the console's
   inventory. Same shape as `gateway/router.py`'s `get_scan`, and unchanged by the
   2026-07-30 re-key: what is compared moved from `scan_submitter` membership to
   `skill.owner` (`inventory.ownership.authorize_skill_read`), the answer did not.
   There is deliberately NO reviewer/admin escape hatch on this surface.

4. **The fetch audit can never fail a fetch.** `_record_fetch` swallows
   everything and logs - same fail-soft posture as `integration_relay.siem`'s
   adapter, and for the same reason: the polled result is already decided and
   signed, so an audit-sink problem must not be able to withhold it.

This module holds no business logic and imports no other module's ORM classes
(scripts/check_import_boundaries.py). Scan/verdict data arrives through the
owning modules' own service-layer accessors, already reduced to plain dicts.
"""

from __future__ import annotations

import datetime
from typing import Any

from common.frontmatter import parse_frontmatter
from common.log import get_logger
from common.skill_package import root_skill_md_path
from engine_runner.detectors.skill_permissions import declared_tools
from engine_runner.normalizer import UnpackRejected, unpack_package_archive
from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile
from skillscan_core import TrustTier
from skillscan_core import content_hash as compute_content_hash
from skillscan_core import toolchain_digest as compute_toolchain_digest

from monolith.modules.admin.engine_registry import (
    filter_enabled_engines,
    list_disabled_engines,
    llm_unconfigured_engine_names,
    structurally_absent_engine_names,
)
from monolith.modules.gate.policy import tier_divergence
from monolith.modules.gate.service import get_verdict_view
from monolith.modules.gateway.auth.dependencies import require_csrf, require_role
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.modules.inventory.lifecycle import InvalidTransitionError, validate_transition
from monolith.modules.inventory.ownership import (
    SkillOwnershipError,
    authorize_skill_read,
    authorize_skill_write,
)
from monolith.modules.inventory.service import (
    ContentRegisteredToAnotherSkillError,
    current_state,
    get_registered_skill,
    latest_skill_version_hashes,
    register_skill_version,
    skill_id_for_content,
    transition_skill,
)
from monolith.modules.orchestration.engine_health import load_scan_engine_coverage
from monolith.modules.orchestration.service import (
    SubmissionChannel,
    get_scan_result_view,
    latest_scan_identities_for_content,
    submit_scan,
    submitter_attribution,
)

from . import views
from .models import MarketplaceFetchLogRow
from .ratelimit import check_rate_limit

router = APIRouter(prefix="/v1/market", tags=["marketplace"])

_logger = get_logger("skillscan.marketplace_api.router")

# spec §4: submit needs `scan:submit`, polling needs `scan:read`. Both are
# granted PER SERVICE ACCOUNT (m2m.M2MGrant) - an identity that was never
# configured keeps the pre-2026-07-28 default of `scan:submit` only, so this
# module cannot hand any existing caller a capability it did not already have.
_SUBMIT_SCOPE = "scan:submit"
_READ_SCOPE = "scan:read"

# NOTE: hoisted so `Depends(...)` below wraps a plain reference rather than a
# nested call - the convention gateway/router.py established (ruff B008).
_authenticated = require_role()


def _get_scan_runtime(request: Request) -> ScanRuntime:
    runtime: ScanRuntime = request.app.state.scan
    return runtime


def _naive_utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


async def _rate_limited_session(
    session: SessionContext = Depends(_authenticated),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> SessionContext:
    """Authentication plus the per-service-account request budget (spec §6.3).

    Applied to the WHOLE `/v1/market` surface, not just polling: the budget is
    "requests per minute per service account", and leaving submission
    unmetered would leave the more expensive endpoint of the two uncapped.

    Counted BEFORE the per-endpoint scope check on purpose, so probing for
    scopes one does not hold is itself rate-limited.

    The 429 carries `Retry-After` (seconds). It is the penalty half of spec
    §6.3; `poll_after_ms` in the response body is the guidance half - a
    well-behaved client never reaches this path.
    """
    retry_after = await check_rate_limit(
        runtime.redis,
        service_account=session.subject,
        limit_per_min=runtime.marketplace_rate_limit_per_min,
    )
    if retry_after is not None:
        raise HTTPException(
            status_code=429,
            detail="request rate limit exceeded for this service account",
            headers={"Retry-After": str(retry_after)},
        )
    return session


def _require_scope(session: SessionContext, scope: str) -> None:
    # SECURITY: 403 (authenticated but not permitted), distinct from the 404 a
    # foreign scan_id gets - the scope a caller holds is its OWN configuration,
    # so naming it leaks nothing about anyone else's data.
    if scope not in session.scopes:
        raise HTTPException(
            status_code=403, detail=f"this service account is not granted the {scope!r} scope"
        )


async def _record_fetch(
    runtime: ScanRuntime,
    *,
    skill_id: str,
    scan_id: str | None,
    service_account: str,
    projected: dict[str, Any],
    verdict_shown: str | None,
) -> None:
    """Append one `marketplace_fetch_log` row (spec §7): what we told whom, when.

    2026-07-30: keyed on `skill_id` (what the caller asked with) while still
    recording `scan_id` (which scan answered, NULL when none has yet) and
    `verdict_shown` (the internal verdict the binary answer was derived from - the
    response itself no longer carries it, so it arrives as its own argument rather
    than being fished out of `projected`, where it no longer exists).

    SECURITY / DESIGN: fail-soft, exactly like `integration_relay.siem`'s
    adapter. By the time this runs the verdict has already been decided and
    signed, and the response body is already built - a full disk, a revoked
    grant, or a dropped connection on the audit sink must degrade to a logged
    error, never to a withheld or failed poll. The inverse (blocking the
    marketplace from reading a BLOCK verdict because a log write failed) would
    be a strictly worse security outcome than the missing audit row.

    The write IS awaited rather than dispatched to a background task: what
    spec §7 requires is that it cannot fail the response, and swallowing the
    exception is what delivers that. An un-awaited task would additionally be
    able to disappear at shutdown, trading a bounded latency cost for silently
    lost audit records.
    """
    if runtime.marketplace_session_factory is None:
        _logger.warning(
            "marketplace fetch audit is not configured - this fetch went unrecorded",
            extra={
                "context": {
                    "metric": "marketplace_fetch_audit_unconfigured",
                    "skill_id": skill_id,
                    "scan_id": scan_id,
                    "service_account": service_account,
                }
            },
        )
        return
    unsafe_reason = projected.get("unsafe_reason")
    content_hash_shown = projected.get("content_hash")
    try:
        async with runtime.marketplace_session_factory() as db_session, db_session.begin():
            db_session.add(
                MarketplaceFetchLogRow(
                    skill_id=skill_id,
                    scan_id=scan_id,
                    content_hash_shown=(
                        None if content_hash_shown is None else str(content_hash_shown)
                    ),
                    service_account=service_account,
                    fetched_at=_naive_utcnow(),
                    status_shown=str(projected["status"]),
                    verdict_shown=None if verdict_shown is None else str(verdict_shown),
                    is_safe_shown=bool(projected["is_safe"]),
                    unsafe_reason_shown=None if unsafe_reason is None else str(unsafe_reason),
                )
            )
    except Exception:
        _logger.exception(
            "marketplace fetch audit write failed - the polled result was still returned",
            extra={
                "context": {
                    "metric": "marketplace_fetch_audit_write_failed",
                    "skill_id": skill_id,
                    "scan_id": scan_id,
                    "service_account": service_account,
                }
            },
        )


@router.post("/scans", status_code=202, dependencies=[Depends(require_csrf)])
async def submit_marketplace_scan(
    request: Request,
    package: UploadFile,
    skill_id: str = Form(max_length=128),
    trust_tier: str | None = Form(default=None),
    session: SessionContext = Depends(_rate_limited_session),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, str]:
    """Submit a package for scanning. Response is `{"scan_id": ...}` only.

    This endpoint exists so the marketplace submits under the SAME identity it
    later polls with - without that, §6.2's "you may only read your own skills"
    has nothing to compare against (spec §4).

    `skill_id` IS REQUIRED (2026-07-30). This reverses this endpoint's own prior
    decision - "deliberately narrower than the console's POST /v1/scans: no
    `skill_id` and therefore no inventory-lifecycle side effects... the external
    contract is scan-in, verdict-out" - and it reverses as a NECESSARY CONSEQUENCE
    of replacing the scan-keyed poll, not as a change of mind about lifecycle
    exposure. A poll keyed on skill_id can only work if skill_id exists in the
    marketplace's world at all, and registering the skill under this service
    account as `skill.owner` is also the ONLY thing that makes the poll's
    ownership check able to say yes to anyone.

    Required rather than optional, for the same reason: an accepted submission with
    no skill_id would be permanently unpollable on the only surface this contract
    offers, and answering 202 to a request whose result can never be read is the
    "a 202 that changes nothing is worse than an error" failure
    `register_skill_version` already documents.

    The tier still comes from the service account, never the caller - see the
    `trust_tier` rejection below and the resubmission note further down.
    """
    _require_scope(session, _SUBMIT_SCOPE)
    skill_id = skill_id.strip()
    if not skill_id:
        raise HTTPException(
            status_code=400,
            detail="skill_id is required: the marketplace polls verdicts by skill_id",
        )
    if runtime.inventory_session_factory is None:
        raise HTTPException(status_code=503, detail="inventory module is not configured")
    # SECURITY (spec §4.1, constraint 2 in this module's docstring): reject,
    # never ignore. The query-string is checked too - a `?trust_tier=internal`
    # would otherwise be dropped with no signal at all, which is the exact
    # false-confidence failure the 400 exists to prevent.
    if trust_tier is not None or "trust_tier" in request.query_params:
        raise HTTPException(
            status_code=400,
            detail=(
                "trust_tier is determined server-side from the calling service "
                "account's configuration and must not be supplied by the caller"
            ),
        )

    raw = await package.read()
    try:
        # tar or zip, dispatched on magic bytes - same boundary the console
        # uses (normalizer.unpack_package_archive).
        files = unpack_package_archive(raw)
    except UnpackRejected as exc:
        # SECURITY (FR-API-060): the reason describes the caller's OWN upload,
        # never internal state - safe to return verbatim, same as the console's
        # equivalent rejection.
        raise HTTPException(status_code=400, detail=f"invalid package archive: {exc}") from exc

    c_hash = compute_content_hash(files)
    # SECURITY: the inventory PRE-FLIGHT, before `submit_scan` commits anything.
    # A deliberate sibling of `gateway.router.create_scan`'s block, not an
    # extraction of it: this surface resolves the tier from the service account
    # rather than a form field, has no admin override to thread through, and
    # answers different status codes. The three refusals and their ORDER are
    # identical, and each one re-runs INSIDE `register_skill_version`'s
    # transaction below, which stays authoritative - this pass exists to refuse
    # the ordinary case before a scan_job, an artifact blob and a
    # `scan_submitter` row are committed on behalf of a caller being turned away.
    tier = session.tier
    async with runtime.inventory_session_factory() as inv_session:
        registered = await get_registered_skill(inv_session, skill_id=skill_id)
        content_owner = await skill_id_for_content(inv_session, content_hash=c_hash)
        prior_state = await current_state(inv_session, skill_id=skill_id)
    if registered is not None:
        try:
            authorize_skill_write(
                skill_id=skill_id,
                recorded_owner=registered.owner,
                actor=session.subject,
                # No admin override is reachable here: this surface is closed to
                # human roles by construction (see rule 3 in the module
                # docstring), so passing True would only be a way to grant an
                # override nobody asked for.
                actor_is_admin=False,
            )
        except SkillOwnershipError as exc:
            # Task 13: the write-side cross-scope attempt, same counter the poll
            # below feeds. 403 here rather than the poll's 404 - this is the WRITE
            # path, where the console already accepts that refusing names the
            # skill_id as taken (you had to know it to type it), and where a 202
            # that scanned nothing into the caller's namespace would be a lie.
            runtime.security_metrics.record_cross_scope_attempt()
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        # SECURITY: a resubmission is judged at the skill's RECORDED tier, not at
        # whatever this session happens to hold now. On this surface the two
        # normally agree (the caller cannot supply a tier at all), but they can
        # diverge after an admin re-tiers a skill or re-issues the grant, and the
        # tier IS the BLOCK threshold - so the recorded one wins, exactly as it
        # does on the console path.
        try:
            tier = TrustTier(registered.trust_tier)
        except ValueError:
            # A stored tier that is not a valid TrustTier means a corrupt row.
            # Fail CLOSED to the strictest tier rather than falling back to the
            # session's, or 500-ing on an otherwise submittable skill.
            tier = TrustTier.PUBLIC

    # AFTER the ownership decision and never before it: "these bytes belong to
    # another skill" names a skill_id this caller may have no relationship with.
    if content_owner is not None and content_owner != skill_id:
        raise HTTPException(
            status_code=409,
            detail=f"this content is already registered to skill {content_owner!r}",
        )
    # `scanning` (races an in-flight verdict), `retired` (terminal) and
    # `quarantined` (an admin restores first) have no `-> submitted` edge. Same
    # pure function `register_skill_version` reaches through `_record_transition`.
    try:
        validate_transition(prior_state, "submitted")
    except InvalidTransitionError as exc:
        raise HTTPException(
            status_code=409,
            detail=f"cannot submit a new scan for skill {skill_id!r}: {exc}",
        ) from exc

    # Same admin engine-disable filter the console applies: beyond honouring
    # the toggle, `submit_scan` derives `toolchain_digest` (and thus the
    # single-flight `cache_key`) from this set, so an unfiltered set here would
    # fork identical content into two scan_jobs depending on which door it
    # arrived through.
    enabled_engine_metadatas = await filter_enabled_engines(runtime.redis, runtime.engine_metadatas)
    async with runtime.orchestration_session_factory() as db_session, db_session.begin():
        scan_id = await submit_scan(
            db_session,
            runtime.redis,
            runtime.blobstore,
            files=files,
            submitter=session.subject,
            engine_metadatas=enabled_engine_metadatas,
            policy=runtime.policy,
            # SECURITY: the tier this identity was GRANTED (m2m.M2MGrant.tier,
            # PUBLIC for any unconfigured account - the strictest), persisted
            # onto the scan by submit_scan so the worker judges by it long
            # after this session is gone. Never runtime.default_trust_tier,
            # and never anything the caller said.
            #
            # 2026-07-30: `tier`, which is `session.tier` EXCEPT for a
            # resubmission of an already-registered skill, where the pre-flight
            # above replaced it with the skill's recorded tier.
            trust_tier=tier,
            # 里程碑 F Task 12: this handler IS the marketplace channel, and
            # this is the only moment that is knowable - `session.is_machine`
            # does not outlive the request. Recorded on this caller's OWN
            # `scan_submitter` row, so a package the console already scanned
            # (dedup: the same bytes collapse onto the existing scan_job) ends
            # up with BOTH channels on record rather than only the first one.
            # Never inferred later from the service-account NAME - see
            # `SubmissionChannel`'s docstring.
            source=SubmissionChannel.MARKETPLACE,
            # 里程碑 F Task 14: the tier THIS service account asked for, on its
            # OWN `scan_submitter` row. Same value as `trust_tier` above - a
            # marketplace caller cannot supply a tier at all (400 above), so
            # its granted tier IS its request - but a different fate: this one
            # is recorded even when dedup hands it a scan_job the console
            # already created and a verdict reached at the console's tier.
            #
            # This is the dangerous direction in practice. An unconfigured
            # service account gets PUBLIC, the STRICTEST tier
            # (`policies/gate/v1.yaml` blocks it at HIGH), while the console
            # commonly submits at `internal` (blocks only at CRITICAL). A
            # marketplace poll of content the console scanned first therefore
            # returns a verdict made under a more permissive ruleset than this
            # caller asked for, and until this column that was invisible.
            # `tier` for the same reason the console records the RESOLVED tier:
            # recording the discarded value would report the override itself as a
            # divergence.
            requested_trust_tier=tier,
            deadline_s=runtime.scan_deadline_s,
        )

    # Register the skill + this version and enter the lifecycle state machine.
    # `operator=session.subject` is what writes `skill.owner` at genesis, and that
    # is the whole basis of the poll's authorization below - a submission that
    # skipped this would produce a scan nobody could ever read.
    t_digest = compute_toolchain_digest(
        enabled_engine_metadatas, runtime.policy.cache_policy_version
    )
    # FR-PAR-013: record the package's declared permissions for the gate and human
    # reviewers. ROOT SKILL.md only, via the one shared implementation - a bundled
    # `examples/SKILL.md` must never populate this field.
    declared: dict[str, Any] | None = None
    root_skill_md = root_skill_md_path(f_path for f_path, _mode, _data in files)
    for f_path, _mode, f_data in files:
        if f_path == root_skill_md:
            frontmatter = parse_frontmatter(f_data)
            if frontmatter is not None:
                declared = {"tools": declared_tools(frontmatter)}
            break
    async with runtime.inventory_session_factory() as inv_session, inv_session.begin():
        try:
            await register_skill_version(
                inv_session,
                skill_id=skill_id,
                source="marketplace-api",
                trust_tier=tier.value,
                content_hash=c_hash,
                toolchain_digest=t_digest,
                declared_perms=declared,
                operator=session.subject,
                actor_is_admin=False,
            )
            await transition_skill(
                inv_session,
                skill_id=skill_id,
                to_state="scanning",
                reason=f"scan {scan_id} submitted",
                actor=session.subject,
                content_hash=c_hash,
                scan_id=scan_id,
            )
        except SkillOwnershipError as exc:
            # The TOCTOU loser: someone registered this skill_id between the
            # pre-flight read and this transaction. Same 403, so the race resolves
            # to "whoever got there first owns it".
            runtime.security_metrics.record_cross_scope_attempt()
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ContentRegisteredToAnotherSkillError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except InvalidTransitionError as exc:
            raise HTTPException(
                status_code=409,
                detail=f"cannot submit a new scan for skill {skill_id!r}: {exc}",
            ) from exc
    return {"scan_id": scan_id}


@router.get("/skills/{skill_id:path}")
async def get_marketplace_skill(
    skill_id: str,
    session: SessionContext = Depends(_rate_limited_session),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    """Poll one SKILL's safety answer for its LATEST version (spec §4/§5).

    Replaces `GET /v1/market/scans/{scan_id}` outright (owner decision, 2026-07-30
    - no dual-run). Returns `views.project_skill_verdict`'s output verbatim: a
    binary `is_safe`, an `unsafe_reason` code when it is false, the whitelisted
    findings behind that answer, and `content_hash` naming the version the answer
    is about.

    `{skill_id:path}` rather than a plain path parameter because skill ids in this
    ecosystem are commonly `@handle/slug` (skillhub/clawhub canonical form) and a
    bare `{skill_id}` would 404 on the slash - a whole class of skill silently
    unpollable. The value is only ever used as a bound database parameter, never as
    a filesystem path.

    `failed` scans still report `COMPLETED`, never a failure: the system made and
    signed a real conservative decision, and calling it "failed" would invite a
    retry that bypasses it (spec §5.1). Under the binary contract that decision
    surfaces as `is_safe: false` + `unsafe_reason: "scan_incomplete"`.
    """
    _require_scope(session, _READ_SCOPE)
    skill_id = skill_id.strip()
    if runtime.inventory_session_factory is None:
        raise HTTPException(status_code=503, detail="inventory module is not configured")

    async with runtime.inventory_session_factory() as inv_session:
        registered = await get_registered_skill(inv_session, skill_id=skill_id)
        # SECURITY (spec §6.2, re-keyed 2026-07-30): an unknown skill and someone
        # else's skill are the SAME 404, deliberately indistinguishable - a 403
        # would confirm the skill_id exists and turn this endpoint into an
        # inventory enumerator. There is no reviewer/admin escape hatch here: every
        # caller on this surface is a machine identity reading back its own
        # submissions, so "read anyone's skill" has no legitimate use.
        if registered is None:
            raise HTTPException(status_code=404, detail="skill not found")
        try:
            # SECURITY: `skill.owner`, NOT `scan_submitter` membership. The old
            # check asked "did you submit this scan", which cannot answer a
            # skill-keyed question: the caller may be asking about a skill it owns
            # whose latest version was scanned on someone else's submission (dedup
            # is single-flight on content+toolchain), or about a skill it never
            # submitted at all. Ownership is the property the question is actually
            # about. See `inventory.ownership.authorize_skill_read` for why the
            # read side takes no admin override.
            authorize_skill_read(
                skill_id=skill_id, recorded_owner=registered.owner, actor=session.subject
            )
        except SkillOwnershipError as exc:
            # Task 13 (2026-07-29): `cross_scope_access_attempts_total`. Preserved
            # verbatim through the re-key - reaching this branch still always means
            # one service account named an object belonging to another principal,
            # and this remains the strongest form of that signal in the codebase
            # because there is no escape hatch above it. Counted here and not on
            # the `registered is None` 404, which is an unknown skill.
            runtime.security_metrics.record_cross_scope_attempt()
            raise HTTPException(status_code=404, detail="skill not found") from exc
        candidate_hashes = await latest_skill_version_hashes(inv_session, skill_id=skill_id)

    if not candidate_hashes:
        # Registered but no version on record. Answered, not 404'd: the caller owns
        # this skill and the honest answer is "nothing judged yet", which under a
        # binary contract is unsafe.
        projected = views.project_skill_verdict(
            skill_id=skill_id,
            content_hash=None,
            internal_state=None,
            verdict_row=None,
            result_row=None,
        )
        await _record_fetch(
            runtime,
            skill_id=skill_id,
            scan_id=None,
            service_account=session.subject,
            projected=projected,
            verdict_shown=None,
        )
        return projected

    # SECURITY: every candidate is projected and the LEAST SAFE one is returned.
    # `candidate_hashes` holds more than one entry only on an exact `created_at`
    # tie between two versions of this skill (MySQL DATETIME has no fractional
    # seconds), and `latest_scan_identities_for_content` returns more than one only
    # on the same tie between two scans of identical bytes. Both accessors hand the
    # tie up rather than breaking it arbitrarily, because submission timing is
    # caller-controlled: "register v1 and v2 in the same second, take whichever
    # answer comes back safe" is a bypass. Normal case: exactly one candidate, and
    # this loop runs once.
    answers: list[tuple[dict[str, Any], str | None, str | None]] = []
    # 2026-07-30 per-scan engine coverage. Read ONCE for the whole request, not
    # per candidate scan: both authorities are request-scoped configuration
    # (`structurally_absent_engine_names`'s own docstring is explicit that its
    # tense is "now"), so reading them per scan would only invite two candidate
    # answers computed against two different reads of the same Redis key.
    #
    # Redis is already a hard dependency of this endpoint (`_rate_limited_
    # session`), so this adds no new failure mode. Deliberately NOT folded into
    # the admin console's `GET /engines/health` posture of a separate endpoint:
    # there the point was that an admin must still be able to disable an engine
    # when telemetry is down, and there is no such action here.
    structurally_absent = structurally_absent_engine_names(
        disabled=await list_disabled_engines(runtime.redis),
        llm_unconfigured=llm_unconfigured_engine_names(
            sandbox_llm_configured=runtime.sandbox_llm_configured
        ),
    )
    async with runtime.orchestration_session_factory() as db_session:
        for content_hash in candidate_hashes:
            scans = await latest_scan_identities_for_content(db_session, content_hash=content_hash)
            if not scans:
                answers.append(
                    (
                        views.project_skill_verdict(
                            skill_id=skill_id,
                            content_hash=content_hash,
                            internal_state=None,
                            verdict_row=None,
                            result_row=None,
                        ),
                        None,
                        None,
                    )
                )
                continue
            for scan in scans:
                # 里程碑 F Task 18: the tier THIS service account asked for, off its
                # OWN `scan_submitter` row - so the response can say whether the
                # verdict it is handing back was adjudicated under the ruleset that
                # was requested. Read AFTER authorization and never as part of it:
                # authorization is `skill.owner` now, so a later change to the
                # attribution shape cannot become a change to who may read.
                #
                # SECURITY: the full submitter list this returns must NOT reach the
                # marketplace - a machine identity has no business knowing which
                # console user submitted the same bytes. Only this caller's own
                # entry is read, and the projection's whitelist is what makes that
                # structural rather than a promise.
                attribution = (
                    await submitter_attribution(db_session, scan_ids=[scan.scan_id])
                ).get(scan.scan_id, {})
                requested_tier = next(
                    (
                        entry["requested_trust_tier"]
                        for entry in attribution.get("submitter_sources", ())
                        if entry["submitter"] == session.subject
                        and entry["requested_trust_tier"] is not None
                    ),
                    None,
                )
                result_row = await get_scan_result_view(db_session, scan_id=scan.scan_id)
                # `scan_engine_health` is orchestration's OWN table, read on
                # orchestration's own session - no new `svc_marketplace` GRANT,
                # the same reasoning `admin.router.get_engine_health` records
                # (`db/setup_grants.py` is additive with no REVOKE, so a grant
                # issued for a read like this could never be taken back off a
                # dev database).
                coverage = await load_scan_engine_coverage(
                    db_session,
                    scan_id=scan.scan_id,
                    structurally_absent=structurally_absent,
                )
                # Separate session: gate's tables are behind gate's own
                # least-privilege MySQL user, same reason the console's get_scan
                # does two queries rather than one join.
                async with runtime.gate_session_factory() as gate_session:
                    verdict_row = await get_verdict_view(gate_session, scan_id=scan.scan_id)
                # Computed here rather than in `views`, which is pure by contract:
                # the answer depends on `GatePolicy.block_threshold`, since
                # strictness lives in `tier_block_overrides` and not in the order of
                # the tier names. `signed_policy_version` is read off the verdict
                # this response is carrying, so a policy approved since it was
                # signed cannot silently relabel it.
                divergence = tier_divergence(
                    runtime.policy,
                    requested=requested_tier,
                    judged=scan.trust_tier,
                    signed_policy_version=(verdict_row or {}).get("policy_version"),
                )
                answers.append(
                    (
                        views.project_skill_verdict(
                            skill_id=skill_id,
                            content_hash=content_hash,
                            internal_state=scan.state,
                            verdict_row=verdict_row,
                            result_row=result_row,
                            judged_at_tier=scan.trust_tier,
                            requested_tier=requested_tier,
                            tier_direction=divergence.direction,
                            tier_direction_basis=divergence.basis,
                            coverage=coverage,
                        ),
                        scan.scan_id,
                        None if verdict_row is None else str(verdict_row.get("verdict")),
                    )
                )

    # Unsafe wins; among equals the order is `candidate_hashes` x scan_id, both
    # already sorted, so the choice is deterministic rather than driver-dependent.
    projected, answered_scan_id, verdict_shown = min(
        answers, key=lambda answer: bool(answer[0]["is_safe"])
    )
    await _record_fetch(
        runtime,
        skill_id=skill_id,
        scan_id=answered_scan_id,
        service_account=session.subject,
        projected=projected,
        verdict_shown=verdict_shown,
    )
    return projected
