"""§9 /v1 API endpoints - M3 wires `POST/GET /v1/scans` end-to-end;
allowlist/gate policy land in M6, reconciliation/rescan-trigger in M7,
inventory/admin/reports/breakglass in M8 (§16) - see each module's own router
file (admin_router.py, inventory_router.py) for the rest of §9.

SECURITY: every route requires authentication via M2's `require_human_role()`
(fail-closed 401/403, enforced server-side - never trust a client-supplied
role). Object-level authorization (a submitter may only read their OWN scans;
approver/auditor/admin may read any) is enforced here in the handler, never
left to the frontend (FR-API defense against IDOR). The WRITE side of that
same rule is `POST /v1/scans`'s skill-ownership check: `skill_id` is a
caller-supplied form field, so a submission naming an already-registered skill
must belong to that skill's owner (or an admin) or it is refused 403 - see
`inventory.ownership.authorize_skill_write`. Every state-changing
route also depends on `require_csrf` (coding spec §16.1 INV-16) - a no-op for
bearer-token (M2M/API) callers, enforced for cookie-authenticated (BFF)
callers.

SECURITY: this is the CONSOLE surface and it is closed to machine identities
(403). Its responses are the internal scan shape - findings blobs with
`snippet_hash`, plus `provenance`/`required_ok`/`hard_gate_hits` - which
`marketplace_api` deliberately withholds from external callers. A service
account belongs on `/v1/market/*`, where the same scans are served through the
projection. See `auth/dependencies.require_human_role`.
"""

from __future__ import annotations

import json
import time
from typing import Any

from common.frontmatter import parse_frontmatter
from common.skill_package import root_skill_md_path
from engine_runner.detectors.skill_permissions import declared_tools
from engine_runner.normalizer import UnpackRejected, unpack_hardened
from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile
from skillscan_core import TrustTier
from skillscan_core import content_hash as compute_content_hash
from skillscan_core import toolchain_digest as compute_toolchain_digest
from sqlalchemy import select

from monolith.modules.admin.engine_registry import filter_enabled_engines
from monolith.modules.gate.models import VerdictRow
from monolith.modules.gate.policy import tier_divergence
from monolith.modules.gateway.auth.dependencies import require_csrf, require_human_role
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.inventory.lifecycle import InvalidTransitionError, validate_transition
from monolith.modules.inventory.models import SkillVersionRow
from monolith.modules.inventory.ownership import SkillOwnershipError, authorize_skill_write
from monolith.modules.inventory.service import (
    ContentRegisteredToAnotherSkillError,
    current_state,
    get_registered_skill,
    register_skill_version,
    skill_id_for_content,
    transition_skill,
)
from monolith.modules.orchestration.models import ScanJob, ScanResultRow, ScanSubmitterRow
from monolith.modules.orchestration.service import (
    SubmissionChannel,
    is_scan_submitter,
    submit_scan,
    submitter_attribution,
)
from monolith.modules.reeval.reconciliation import (
    MarketplacePublishedEntry,
    PushEventVerificationError,
    verify_push_event_signature,
)
from monolith.modules.reeval.service import apply_push_event
from monolith.modules.reporting import service as reporting_service

from .runtime import ScanRuntime

router = APIRouter(prefix="/v1")

# NOTE: hoisted so Depends(...) below wraps a plain reference, not a nested
# call - matches the convention established in auth/dependencies tests (ruff
# B008 flags function calls in argument defaults otherwise).
#
# SECURITY (2026-07-28, milestone B' C1): `require_human_role`, not
# `require_role`. Every route below returns the INTERNAL scan shape, so a
# machine identity reaching any of them walks straight around
# `marketplace_api.views`'s projection using the same token it submitted with.
# See `require_human_role`'s docstring for the full reasoning and for why the
# refusal is keyed on the KIND of identity rather than on a scope.
_submitter_or_above = require_human_role()

_REVIEWER_ROLES = ("approver", "admin", "auditor")

# 里程碑 F Task 16: what a scan with NO `scan_submitter` rows renders as.
# `submitter_attribution` deliberately omits such a scan rather than returning
# empty lists, so that decision belongs to each caller - and here it is empty
# lists, never the scalar `ScanJob.submitter` promoted into a one-element list.
# Promoting it would state that the first submitter is the ONLY authorized
# reader, which is the claim `scan_submitter` exists to stop making.
#
# Read-only by construction: every value is an immutable empty tuple, so a
# handler that mutated the shared default in place could not corrupt the next
# request's response.
_EMPTY_ATTRIBUTION: dict[str, Any] = {
    "submitters": (),
    "submitter_sources": (),
    "source": (),
}


def get_scan_runtime(request: Request) -> ScanRuntime:
    runtime: ScanRuntime = request.app.state.scan
    return runtime


@router.post("/scans", status_code=202, dependencies=[Depends(require_csrf)])
async def create_scan(
    package: UploadFile,
    skill_id: str | None = Form(default=None, max_length=255),
    trust_tier: str | None = Form(default=None),
    session: SessionContext = Depends(_submitter_or_above),
    runtime: ScanRuntime = Depends(get_scan_runtime),
) -> dict[str, str]:
    # Optional inventory registration (coding spec §7.1/§16.2, FR-INV): a
    # submission that names a skill_id registers skill + skill_version and
    # enters the lifecycle state machine (submitted -> scanning here; the
    # background worker drives scanning -> published/review_pending off the
    # verdict). Anonymous submissions (no skill_id) scan exactly as before.
    tier = runtime.default_trust_tier
    if trust_tier is not None:
        try:
            tier = TrustTier(trust_tier)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"invalid trust_tier {trust_tier!r}, expected one of "
                f"{[t.value for t in TrustTier]}",
            ) from exc
    raw = await package.read()
    try:
        files = unpack_hardened(raw)
    except UnpackRejected as exc:
        # SECURITY: hardening rejections (oversized/malformed/traversal/
        # symlink/decompression-bomb) are all a 400, and the specific reason
        # is safe to return here - it describes the upload the caller just
        # made, not any internal system state (FR-API-060 only forbids
        # leaking internals, not caller-supplied-input diagnostics).
        raise HTTPException(status_code=400, detail=f"invalid package archive: {exc}") from exc

    caller_is_admin = session.has_role("admin")
    c_hash = compute_content_hash(files)
    if skill_id:
        if runtime.inventory_session_factory is None:
            raise HTTPException(status_code=503, detail="inventory module is not configured")
        # SECURITY (2026-07-29, milestone F Task 11 follow-up C1) - the
        # inventory pre-flight, and it runs BEFORE `submit_scan` on purpose.
        # A submission that is going to be REFUSED must not leave a scan_job,
        # an artifact blob or a `scan_submitter` row behind on its way out;
        # those are the rows every object-level authz check in the system
        # reads, so creating them for a caller we are about to refuse would
        # hand them readable state they should never have had. Worse for the
        # `scan_submitter` row specifically: via single-flight dedup it
        # attaches the caller to an EXISTING scan of the same bytes as an
        # authorized reader - of a scan that may belong to another skill
        # entirely, which is precisely the situation one of the refusals below
        # exists to prevent.
        #
        # 2026-07-29 (milestones E+F review): all THREE refusals are checked
        # here now, not just the ownership 403. `submit_scan` commits before
        # the inventory transaction, so both 409 paths
        # (`ContentRegisteredToAnotherSkillError` and `InvalidTransitionError`)
        # used to tell the caller the submission failed while leaving exactly
        # those rows committed. Each check below re-runs INSIDE
        # `register_skill_version`'s writing transaction, and THAT run stays
        # authoritative - this one is for fail-fast, for the status code, and
        # for leaving nothing behind. What remains is the narrow TOCTOU race
        # (someone registers the skill_id or these bytes between this read and
        # that transaction), which still commits the rows before losing; that
        # is the same window the ownership check has always accepted, and
        # losing it safely is the point of the in-transaction re-check.
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
                    actor_is_admin=caller_is_admin,
                )
            except SkillOwnershipError as exc:
                # SECURITY: 403, NOT the 409 this situation used to get by
                # accident. "You may not modify this object" is not a
                # conflict, and a client told 409 would retry with different
                # content forever against a wall that is about identity.
                raise HTTPException(status_code=403, detail=str(exc)) from exc
            # SECURITY: the tier a RESUBMISSION is judged at is the skill's
            # RECORDED tier, never the caller's form field. `trust_tier`
            # decides the BLOCK threshold (policies/gate/v1.yaml: `public`
            # blocks at HIGH, every other tier only at CRITICAL), so honouring
            # the form here let any submitter re-judge an existing `public`
            # skill as `internal` and downgrade a finding that had to block -
            # the second half of the takeover this task closes, and separately
            # logged as finding I2. It was also plainly inconsistent:
            # `register_skill_version` writes `skill.trust_tier` only when the
            # skill is NEW, so inventory kept reporting the original tier while
            # the verdict was being made at another one. The resolved tier is
            # not silently swallowed either - it lands on `ScanJob.trust_tier`
            # and is what `GET /v1/scans/{scan_id}` reports as `trust_tier`/
            # `judged_at_tier`, the fields that exist to make the judged tier
            # visible rather than assumed.
            #
            # Only the CONSOLE needs this. `marketplace_api`'s submit endpoint
            # accepts no `skill_id` at all (and rejects a caller-supplied
            # `trust_tier` outright with a 400), so no marketplace submission
            # can ever be a resubmission of a registered skill - verified, not
            # assumed: `register_skill_version` has exactly one caller in the
            # tree, this handler.
            try:
                tier = TrustTier(registered.trust_tier)
            except ValueError:
                # A stored tier that is not a valid `TrustTier` means the row
                # is corrupt. Fail CLOSED to the strictest tier rather than
                # falling back to the caller's value (which is the input we
                # just decided not to trust) or 500-ing on a skill that is
                # otherwise perfectly submittable.
                tier = TrustTier.PUBLIC

        # SECURITY: AFTER the ownership decision above and never before it.
        # "These bytes belong to another skill" names a skill_id the caller may
        # have no relationship with, so it must not be answerable to someone
        # who is not even allowed to write the skill_id they DID name - the
        # same ordering `register_skill_version` documents for the same reason.
        # (For an unregistered `skill_id` there is no owner to check: anyone
        # may register a free name, so answering is not a disclosure.)
        #
        # Same wording as the in-transaction refusal it front-runs, so the two
        # are indistinguishable to a client.
        if content_owner is not None and content_owner != skill_id:
            raise HTTPException(
                status_code=409,
                detail=f"this content is already registered to skill {content_owner!r}",
            )
        # The lifecycle refusal: `scanning` (racing an in-flight verdict),
        # `retired` (terminal) and `quarantined` (an admin restores first) have
        # no `-> submitted` edge. `validate_transition` is the SAME pure
        # function `register_skill_version` reaches through `_record_transition`
        # - not a second copy of the rule - and it accepts `prior_state is
        # None` as the legitimate genesis case, so a brand-new skill_id passes
        # here exactly as it does there.
        try:
            validate_transition(prior_state, "submitted")
        except InvalidTransitionError as exc:
            raise HTTPException(
                status_code=409,
                detail=f"cannot submit a new scan for skill {skill_id!r}: {exc}",
            ) from exc

    # coding spec §9 Admin·Engines: an admin-disabled engine (never a required
    # floor engine - engine_registry.set_engine_enabled enforces that INV-1
    # invariant at write time) takes effect on the NEXT submission.
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
            # SECURITY (2026-07-28, milestone B' Task 4): `tier` (above) is what
            # gets judged now - previously this scan's verdict silently used
            # `runtime.default_trust_tier` instead, regardless of what `tier`
            # resolved to.
            #
            # 2026-07-29 (follow-up C1): the caller-supplied `trust_tier` form
            # field no longer always wins, which narrows the gap coding spec
            # §4.1's closing note tracks. For a RESUBMISSION of an
            # already-registered `skill_id`, `tier` has been overwritten above
            # with the skill's RECORDED tier - see that block for why. The gap
            # remains open for a FIRST submission (new skill_id) and for an
            # anonymous one (no skill_id), where there is no recorded tier to
            # defer to and the form field is still the only input.
            trust_tier=tier,
            # 里程碑 F Task 12: this handler IS the console channel - the fact
            # is known here and nowhere else afterwards, so it is recorded on
            # the `scan_submitter` row now rather than reconstructed at read
            # time from the submitter's name. This module's own docstring is
            # the authority for the constant: the console surface is closed to
            # machine identities (`require_human_role`), so every submission
            # reaching this line arrived through the console, by construction.
            source=SubmissionChannel.CONSOLE,
            # 里程碑 F Task 14: what THIS caller asked for, recorded on their
            # own `scan_submitter` row even when single-flight dedup hands
            # them a scan_job someone else's earlier submission created and a
            # verdict adjudicated at that person's tier. `trust_tier` above
            # only reaches `ScanJob` on the fresh-scan path; this reaches the
            # association row on both, which is the whole point.
            #
            # `tier`, the RESOLVED tier - deliberately not the raw `trust_tier`
            # form field. For a resubmission of a registered skill the block
            # above has already overridden the form field with the skill's
            # recorded tier (finding I2), and that override is the tier this
            # submission would genuinely have been judged at. Recording the
            # discarded form value instead would report the override itself as
            # a divergence and hand an input we just decided not to trust a
            # place in the response.
            requested_trust_tier=tier,
            deadline_s=runtime.scan_deadline_s,
        )

    if skill_id:
        # Re-checked rather than asserted: the pre-flight above already 503s on
        # this, so in practice it cannot fire here - but an `assert` is removed
        # under `python -O`, which would turn a misconfigured deployment into an
        # AttributeError 500 instead of the honest 503. Cheap, explicit, and it
        # narrows the Optional for mypy either way.
        if runtime.inventory_session_factory is None:
            raise HTTPException(status_code=503, detail="inventory module is not configured")
        # `c_hash` is computed once, above the pre-flight - the "already
        # registered to another skill" check needs it BEFORE `submit_scan`
        # runs, and hashing the same bytes twice per submission to keep the
        # computation next to its second use would be pure waste.
        t_digest = compute_toolchain_digest(enabled_engine_metadatas, runtime.policy.version)
        # FR-PAR-013: record the Skill's declared permissions so the gate and
        # human reviewers can see them. skill_version.declared_perms has existed
        # since the initial schema but every caller passed None until 2026-07-27.
        #
        # SECURITY/CORRECTNESS: root path ONLY, never basename-anywhere. This
        # is persisted to skill_version.declared_perms and consumed downstream
        # by the gate and human reviewers - it must reflect the ONE
        # declaration the Agent actually reads (the package-root SKILL.md), or
        # the gate ends up judging a permission profile the package doesn't
        # really have, permanently recorded. A bundled example
        # (examples/SKILL.md) must never populate this field.
        #
        # 2026-07-27 (final review, F-5): "root" is not the literal string
        # "SKILL.md" - a conventionally packed `tar czf skill.tgz my-skill/`
        # puts everything under a wrapper directory the normalizer does not
        # strip, and this used to record declared_perms=None for every such
        # package. `common.skill_package.root_skill_md_path` is the one shared
        # implementation (also used by the permissions detector and by
        # orchestration's skill-name parser) - do not add a fourth spelling.
        declared: dict[str, Any] | None = None
        root_skill_md = root_skill_md_path(f_path for f_path, _mode, _data in files)
        for f_path, _mode, f_data in files:
            if f_path == root_skill_md:
                fm = parse_frontmatter(f_data)
                if fm is not None:
                    declared = {"tools": declared_tools(fm)}
                break
        async with runtime.inventory_session_factory() as inv_session, inv_session.begin():
            # 2026-07-29 (milestone F Task 11 follow-up I1): NO "is this
            # content already known?" gate wraps this block any more. It used
            # to skip BOTH `register_skill_version` and the `-> scanning`
            # transition whenever `content_hash` was already a recorded
            # version, which silently turned the policy-fix case (same bytes,
            # new ruleset, skill sitting at `blocked`) into a 202 that wrote
            # nothing: no lifecycle event, so `worker.sync_lifecycle_tick` -
            # which only ever looks at `scanning`/`review_pending` - never
            # touched the skill again and it stayed `blocked` forever. A 202
            # that changes nothing is worse than an error, because the caller
            # is told it worked.
            #
            # `register_skill_version` owns the whole decision now: it skips
            # the duplicate `skill_version` row (`content_hash` is its PK, and
            # that keying is what single-flight dedup and the verdict cache
            # rest on) while still running ownership, the lifecycle re-entry
            # and the cross-skill refusal below. One chokepoint, rather than a
            # partial copy of its rules out here.
            try:
                await register_skill_version(
                    inv_session,
                    skill_id=skill_id,
                    source="web-upload",
                    trust_tier=tier.value,
                    content_hash=c_hash,
                    toolchain_digest=t_digest,
                    declared_perms=declared,
                    operator=session.subject,
                    # SECURITY: the authoritative ownership check runs
                    # INSIDE this call's transaction (the pre-flight above
                    # races anything that registers `skill_id` in between).
                    # Required keyword, no default - see
                    # `register_skill_version`'s docstring.
                    actor_is_admin=caller_is_admin,
                )
                await transition_skill(
                    inv_session,
                    skill_id=skill_id,
                    to_state="scanning",
                    reason=f"scan {scan_id} submitted",
                    actor=session.subject,
                    content_hash=c_hash,
                    # SECURITY (2026-07-29, milestones E+F review finding C1):
                    # the scan THIS submission created, recorded as a typed
                    # column and not only interpolated into `reason` above.
                    # `worker.sync_lifecycle_tick` resolves this event by it -
                    # previously it took the newest verdict for `c_hash`, which
                    # for a resubmission of unchanged bytes under a new
                    # toolchain is the PREVIOUS toolchain's verdict, published
                    # (or re-blocked) within a tick while the scan being
                    # submitted right here was still running.
                    scan_id=scan_id,
                )
            except SkillOwnershipError as exc:
                # SECURITY (milestone F Task 11 follow-up C1): the pre-flight
                # above answers this for every ordinary request. Reaching
                # HERE means `skill_id` was registered by someone else in
                # the window between that read and this transaction - the
                # TOCTOU race the in-transaction check exists to lose
                # safely. Same 403, so the race resolves to "the registrant
                # who got there first owns it" rather than to a 500 or, far
                # worse, a silent write.
                raise HTTPException(status_code=403, detail=str(exc)) from exc
            except ContentRegisteredToAnotherSkillError as exc:
                # SECURITY: the same content is already registered under a
                # DIFFERENT skill_id - never silently re-attribute it. This
                # runs INSIDE the writing transaction, so a concurrent
                # registration of these bytes cannot slip between the read and
                # the write.
                #
                # 2026-07-29 (milestones E+F review): like the 403 above, this
                # is now the TOCTOU-loser path rather than the ordinary one.
                # The pre-flight answers it for every ordinary request, and it
                # has to, because `submit_scan` has already COMMITTED by the
                # time we get here - a caller refused at this line still leaves
                # a scan_job, an artifact blob and a `scan_submitter` row
                # behind, the last of which attaches them to another skill's
                # existing scan as an authorized reader via dedup. Reaching
                # here means those bytes were registered elsewhere in the
                # window between the pre-flight read and this transaction.
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            except InvalidTransitionError as exc:
                # SECURITY (found live 2026-07-24 via a real clawhub.ai
                # re-import batch): re-submitting new content for a
                # skill_id that already has lifecycle history is a real,
                # expected caller scenario (a duplicate or re-run
                # submission), not a system fault - it must not crash as
                # an unhandled 500. Same FR-API-060 posture as the
                # sibling 409 above: this message only describes
                # skill_id's OWN lifecycle state, never internal system
                # state, so it's safe to return verbatim.
                #
                # 2026-07-29 (milestone F Task 11): settled states
                # (published/review_pending/blocked) now re-enter at
                # `submitted` and reach the 202 below - a v2 release and a
                # fixed BLOCKed skill used to land here forever. This
                # branch is still reached, and must stay, for `scanning`
                # (racing the in-flight verdict), `retired` (terminal),
                # and `quarantined` (a deliberate gate - an admin restores
                # to `published` first; see lifecycle.VALID_TRANSITIONS).
                #
                # I1: it now covers a resubmission of UNCHANGED bytes into
                # those same three states too - which is the point. An
                # honest 409 naming the state, instead of the silent 202
                # that case used to get.
                #
                # 2026-07-29 (milestones E+F review): the pre-flight runs the
                # SAME `validate_transition` before `submit_scan` commits, so
                # the ordinary case no longer reaches this line at all. What
                # still does is the race - most realistically the caller's own
                # concurrent duplicate submission, which moves the skill to
                # `scanning` in between. Kept, and kept identical in wording:
                # a check that only exists in the pre-flight would be a check
                # that a concurrent writer can walk straight past.
                raise HTTPException(
                    status_code=409,
                    detail=f"cannot submit a new scan for skill {skill_id!r}: {exc}",
                ) from exc
    return {"scan_id": scan_id}


@router.get("/scans/{scan_id}")
async def get_scan(
    scan_id: str,
    session: SessionContext = Depends(_submitter_or_above),
    runtime: ScanRuntime = Depends(get_scan_runtime),
) -> dict[str, Any]:
    async with runtime.orchestration_session_factory() as db_session:
        job = (
            await db_session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
        ).scalar_one_or_none()
        if job is None:
            raise HTTPException(status_code=404, detail="scan not found")
        # SECURITY: object-level authz (IDOR defense) - a plain submitter may
        # only read their own scans; approver/auditor/admin may read any. A
        # 404 (not 403) so existence of another user's scan_id isn't leaked.
        #
        # C2: membership in `scan_submitter`, not `job.submitter == subject`.
        # Single-flight dedup means the scan a user just submitted may be a
        # scan_job someone else's earlier submission created, and the column
        # still names them - so the person who submitted it was refused their
        # own scan. Fixing only the marketplace side would have produced the
        # mirror-image bug here: marketplace can read it, the console user who
        # submitted the same bytes cannot.
        if not await is_scan_submitter(
            db_session, scan_id=scan_id, subject=session.subject
        ) and not session.has_role(*_REVIEWER_ROLES):
            raise HTTPException(status_code=404, detail="scan not found")

        result_row = (
            await db_session.execute(select(ScanResultRow).where(ScanResultRow.scan_id == scan_id))
        ).scalar_one_or_none()

        # 里程碑 F Task 2: every authorized reader (see `is_scan_submitter`
        # above), not just `job.submitter` (the FIRST submitter only - see
        # `ScanSubmitterRow`'s docstring). A deduped scan legitimately has N
        # rightful submitters, and the console must show all of them rather
        # than the one stranger's name the column happens to carry.
        #
        # Always a list, even for a single submitter - a response whose SHAPE
        # changes with the data (list vs bare string) is exactly the kind of
        # thing a consumer silently mis-parses.
        #
        # 里程碑 F Task 12 added `source`, Task 14 `requested_trust_tier`; both
        # are real columns on that row, recorded at INSERT by whichever handler
        # took the submission. 里程碑 F Task 16 moved the whole shape into
        # `orchestration.service.submitter_attribution` so `GET /v1/scans` and
        # `GET /v1/reviews` serve the IDENTICAL shape rather than three
        # hand-rolled selects that drift apart - which is exactly what had
        # happened: this endpoint had full attribution while both lists still
        # showed the scalar first-submitter.
        attribution = (await submitter_attribution(db_session, scan_ids=[scan_id])).get(
            scan_id, _EMPTY_ATTRIBUTION
        )
        submitter_sources = attribution["submitter_sources"]
        # 里程碑 F Task 14: the tier THIS caller asked for, off their OWN
        # association row. `None` when they have no row (a reviewer reading
        # someone else's scan - they made no request) or when their row records
        # none (written before the column existed).
        requested_by_caller = next(
            (
                entry["requested_trust_tier"]
                for entry in submitter_sources
                if entry["submitter"] == session.subject
                and entry["requested_trust_tier"] is not None
            ),
            None,
        )

    async with runtime.gate_session_factory() as gate_session:
        verdict_row = (
            await gate_session.execute(select(VerdictRow).where(VerdictRow.scan_id == scan_id))
        ).scalar_one_or_none()

    # `signed_policy_version` comes off the VERDICT, not off `runtime.policy`:
    # the question this answers is whether the direction below describes the
    # adjudication that happened or only today's thresholds. `None` (no verdict
    # yet) is honestly "current policy" - nothing has been signed at all.
    divergence = tier_divergence(
        runtime.policy,
        requested=requested_by_caller,
        judged=job.trust_tier,
        signed_policy_version=verdict_row.policy_version if verdict_row is not None else None,
    )
    return {
        "scan_id": scan_id,
        "state": job.state,
        "submitter": job.submitter,
        "verdict": verdict_row.verdict if verdict_row is not None else None,
        "severity": result_row.severity if result_row is not None else None,
        "score": verdict_row.score if verdict_row is not None else None,
        "is_safe": (verdict_row.verdict == "PASS") if verdict_row is not None else None,
        "findings": result_row.findings if result_row is not None else [],
        "provenance": result_row.provenance if result_row is not None else [],
        "required_ok": result_row.required_ok if result_row is not None else None,
        "hard_gate_hits": result_row.hard_gate_hits if result_row is not None else [],
        "reasons": verdict_row.reasons if verdict_row is not None else [],
        "sarif_ref": f"/v1/scans/{scan_id}/sarif",
        # 里程碑 F Task 14: these are two DIFFERENT facts now, and Task 2's
        # note that they could only ever be the same column no longer holds.
        #
        # `judged_at_tier` is unchanged - `ScanJob.trust_tier`, the tier the
        # verdict was actually adjudicated at, the same column
        # `orchestration.service.get_scan_state_and_tier` serves to
        # `marketplace_api.views.project_scan`. `trust_tier` is now what THIS
        # caller asked for, read from their own `scan_submitter` row.
        #
        # They diverge exactly when single-flight dedup hands a later submitter
        # someone else's verdict: `submit_scan` deliberately does not re-tier
        # an existing adjudication, so a caller asking for `public` (the
        # STRICTEST tier - `policies/gate/v1.yaml` blocks it at HIGH) can be
        # handed a verdict reached at `internal` (blocks only at CRITICAL).
        # `tier_direction` below says which way it cuts.
        #
        # The FALLBACK when this caller has no recorded request - a reviewer
        # reading someone else's scan, or a row written before the column
        # existed - is `job.trust_tier`, i.e. exactly what this field returned
        # before this change. It is not a guess dressed up as a record: it
        # makes the two fields equal, which suppresses the divergence warning
        # rather than inventing one, and the per-row truth (including `null`
        # for "no request recorded") stays visible in `submitter_sources`.
        # `tier_direction` is `null` in that case for the same reason.
        "trust_tier": requested_by_caller if requested_by_caller is not None else job.trust_tier,
        "judged_at_tier": job.trust_tier,
        # "looser" | "stricter" | "equivalent" | null - see
        # `gate.policy.tier_direction`. "looser" is the case that matters: a
        # verdict reached under a more permissive ruleset than this caller
        # asked for. Task 18 moved that function out of this file and into
        # `gate.policy` so the marketplace surface can disclose the same
        # divergence without importing this router.
        "tier_direction": divergence.direction,
        # WHICH policy that direction was computed under (2026-07-29 residual
        # triage). Strictness lives in `tier_block_overrides`, so a policy
        # approved between signing and viewing can relabel a historical
        # verdict. The verdict's own `policy_version` is recorded, so "same
        # version or not" is answerable; the historical policy CONTENT is not
        # reconstructible, and is therefore not invented - the console caveats
        # the label instead. See `gate.policy.tier_divergence`.
        "tier_direction_basis": divergence.basis,
        # 里程碑 F Task 12 (Task 2 reported this BLOCKED - no column existed).
        # `source` is the set of channels this scan arrived through and
        # `submitter_sources` is the per-submitter attribution behind it: which
        # NAME came through which door and asked for which tier, which is what
        # the console needs to label a deduplicated scan's submitter list rather
        # than showing a stranger's name with no explanation. Both are read
        # straight off `ScanSubmitterRow`; neither is inferred from the submitter
        # string. `null` in `submitter_sources` means that row records no such
        # fact and is passed through verbatim, the same never-guess posture as
        # `trust_tier` above.
        #
        # 里程碑 F Task 16: identical keys, identical shape, produced by the same
        # `submitter_attribution` call the two LIST endpoints use.
        **attribution,
    }


@router.get("/scans/{scan_id}/sarif")
async def get_scan_sarif(
    scan_id: str,
    session: SessionContext = Depends(_submitter_or_above),
    runtime: ScanRuntime = Depends(get_scan_runtime),
) -> dict[str, Any]:
    # SECURITY: same object-level authz (IDOR defense) as GET /v1/scans/{scan_id}
    # above - a 404 (not 403) so existence of another user's scan_id isn't leaked.
    # This lookup happens against orchestration's own ScanJob table rather than
    # trusting reporting.export_sarif_for_scans (which has no notion of
    # ownership - it just returns an empty SARIF document for any scan_id with
    # no matching row, decided or not, own or not).
    async with runtime.orchestration_session_factory() as db_session:
        job = (
            await db_session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
        ).scalar_one_or_none()
        if job is None:
            raise HTTPException(status_code=404, detail="scan not found")
        # C2: same association-table check as `get_scan` above - a fix applied
        # to only one of the two identical checks leaves the same hole one path
        # segment away.
        if not await is_scan_submitter(
            db_session, scan_id=scan_id, subject=session.subject
        ) and not session.has_role(*_REVIEWER_ROLES):
            raise HTTPException(status_code=404, detail="scan not found")

    if runtime.reporting_session_factory is None:
        # SECURITY: fail-closed - a misconfigured deployment (reporting module
        # not wired) must never look like "no data", it must be an explicit 500.
        raise HTTPException(status_code=500, detail="reporting module is not configured")
    async with runtime.reporting_session_factory() as reporting_session:
        return await reporting_service.export_sarif_for_scans(reporting_session, [scan_id])


@router.get("/scans")
async def list_scans(
    state: str | None = None,
    limit: int = 50,
    offset: int = 0,
    session: SessionContext = Depends(_submitter_or_above),
    runtime: ScanRuntime = Depends(get_scan_runtime),
) -> dict[str, Any]:
    """`limit` (clamped to 200) + `offset`. **Returns no total, on purpose**
    (里程碑 F Task 16 evaluated adding one and decided against it).

    A total means `SELECT COUNT(*) FROM scan_job` on every request, and for the
    reviewer roles - who see every scan, i.e. the console's primary users -
    there is no `submitter` predicate to narrow it. InnoDB keeps no cached row
    count, so that is a full index scan. `scan_job` is the highest-volume table
    in this system (one row per scan, forever), and **this endpoint is POLLED**:
    `web/src/pages/Scans.tsx` refetches on a 3s -> 5s -> 10s -> 20s backoff for
    as long as any scan on the page is non-terminal, resetting to 3s whenever
    the tab regains focus. A whole-table count on that cadence, per open tab, is
    a cost the console does not currently pay and does not need to.

    The submitter-scoped case would be cheap (`idx_submitter` on
    `scan_submitter` serves it), so this is not a blanket claim that counting is
    expensive - it is that the expensive case is the common one here.

    Honest in the other direction too: the list query already sorts by
    `created_at`, which has no index, so it is not free either. That is an
    argument for indexing the sort, not for adding a second full scan beside it.

    The frontend's degradation is the supported answer: it asks for
    `limit = PAGE_SIZE + 1`, renders `PAGE_SIZE` rows, and uses the extra row
    only to decide whether a "next" control exists - so it says "page N" and
    never invents a page count it cannot know. Documented in
    docs/USAGE_GUIDE.md as well, so consumers do not each guess.
    """
    bounded_limit = max(1, min(limit, 200))
    stmt = select(ScanJob)
    # SECURITY: object-level authz - a plain submitter only ever sees their own
    # scans in the list; approver/auditor/admin see all.
    #
    # C2: driven by `scan_submitter`, the same association the per-scan checks
    # above use. Filtering on `ScanJob.submitter` here would leave a submitter
    # able to open a deduplicated scan by id but unable to find it in their own
    # list - i.e. no way to reach it at all through the UI.
    if not session.has_role(*_REVIEWER_ROLES):
        stmt = stmt.where(
            ScanJob.scan_id.in_(
                select(ScanSubmitterRow.scan_id).where(
                    ScanSubmitterRow.submitter == session.subject
                )
            )
        )
    if state is not None:
        stmt = stmt.where(ScanJob.state == state)
    stmt = stmt.order_by(ScanJob.created_at.desc()).limit(bounded_limit).offset(max(0, offset))

    async with runtime.orchestration_session_factory() as db_session:
        jobs = (await db_session.execute(stmt)).scalars().all()
        # 里程碑 F Task 16: full attribution on the LIST, in the same shape the
        # detail response uses (same function produces both). Until now this
        # endpoint returned only the scalar `ScanJob.submitter` - the FIRST
        # submitter - so a deduplicated scan showed a stranger's name on the
        # list page and the right names one click away in the drawer. Task 8
        # fixed the detail view and deliberately left the lists alone to avoid
        # racing another agent in this file; this is that debt.
        #
        # SECURITY: no new disclosure. The rows are scoped to exactly the
        # scan_ids the object-level filter above already authorized, and any
        # reader of one of those scans can already see its full submitter list
        # through `GET /v1/scans/{scan_id}`. ONE extra query for the whole page,
        # not one per row.
        attribution = await submitter_attribution(db_session, scan_ids=[j.scan_id for j in jobs])

    scan_ids = [j.scan_id for j in jobs]
    content_hashes = [j.content_hash for j in jobs]

    # SECURITY (object-level authz already applied above, via `jobs`): these
    # two lookups are scoped to exactly the scan_ids/content_hashes already
    # authorized - never a broader query. Separate sessions because verdict
    # and inventory are separate modules with their own least-privilege DB
    # grants (same reason GET /v1/scans/{scan_id} above does two queries
    # instead of one JOIN - gate and inventory aren't in the same schema/user).
    verdicts_by_scan: dict[str, tuple[str, int]] = {}
    if scan_ids:
        async with runtime.gate_session_factory() as gate_session:
            rows = (
                await gate_session.execute(
                    select(VerdictRow.scan_id, VerdictRow.verdict, VerdictRow.score).where(
                        VerdictRow.scan_id.in_(scan_ids)
                    )
                )
            ).all()
        verdicts_by_scan = {scan_id: (verdict, score) for scan_id, verdict, score in rows}

    skill_ids_by_hash: dict[str, str] = {}
    if content_hashes and runtime.inventory_session_factory is not None:
        async with runtime.inventory_session_factory() as inv_session:
            hash_result = await inv_session.execute(
                select(SkillVersionRow.content_hash, SkillVersionRow.skill_id).where(
                    SkillVersionRow.content_hash.in_(content_hashes)
                )
            )
            hash_rows = hash_result.tuples().all()
        skill_ids_by_hash = dict(hash_rows)

    # NO `total`, deliberately - see this endpoint's docstring above and
    # docs/USAGE_GUIDE.md, which state the same thing so consumers do not each
    # have to rediscover it. The frontend's over-fetch-one-row probe
    # (`web/src/pages/Scans.tsx`) and its honest "page N" display are the
    # supported way to paginate here.
    return {
        "items": [
            {
                "scan_id": j.scan_id,
                "state": j.state,
                # The FIRST submitter, kept for compatibility. `submitters` below
                # is the authoritative list - see `ScanSubmitterRow`'s docstring
                # for why this column is not the answer to "whose scan is this".
                "submitter": j.submitter,
                "content_hash": j.content_hash,
                "verdict": verdicts_by_scan[j.scan_id][0]
                if j.scan_id in verdicts_by_scan
                else None,
                "score": verdicts_by_scan[j.scan_id][1] if j.scan_id in verdicts_by_scan else None,
                "is_safe": (
                    verdicts_by_scan[j.scan_id][0] == "PASS"
                    if j.scan_id in verdicts_by_scan
                    else None
                ),
                "skill_id": skill_ids_by_hash.get(j.content_hash),
                "skill_name": j.skill_name,
                # 里程碑 F Task 16: `submitters` / `submitter_sources` / `source`,
                # byte-for-byte the shape `GET /v1/scans/{scan_id}` returns.
                **attribution.get(j.scan_id, _EMPTY_ATTRIBUTION),
            }
            for j in jobs
        ]
    }


@router.post("/marketplace/webhook", status_code=202)
async def marketplace_push_webhook(
    request: Request,
    runtime: ScanRuntime = Depends(get_scan_runtime),
) -> dict[str, str]:
    """coding spec §11.6/SAD §4.3 push reconciliation. SECURITY: this endpoint
    is authenticated by the signed-event HMAC below, NOT `require_role()` -
    the caller is an external marketplace system, not one of our own IdP-
    authenticated users/services (mTLS is the OTHER strong-auth option SAD
    §4.3 allows; that's an ingress/network-layer control, out of this
    handler's scope). Verification happens over the RAW request body bytes,
    before any JSON parsing, since HMAC must cover exactly what the sender
    signed - a re-serialized copy could differ byte-for-byte even with
    identical field values.
    """
    if runtime.push_hmac_secret is None:
        # SECURITY: push disabled entirely - behave as if the route doesn't
        # exist rather than confirming/denying based on signature validity.
        raise HTTPException(status_code=404, detail="not found")

    signature_header = request.headers.get("X-Marketplace-Signature")
    timestamp_header = request.headers.get("X-Marketplace-Timestamp")
    if not signature_header or not timestamp_header:
        raise HTTPException(status_code=401, detail="missing signature/timestamp header")
    try:
        timestamp = int(timestamp_header)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="invalid timestamp header") from exc

    body = await request.body()
    try:
        verify_push_event_signature(
            body=body,
            signature_header=signature_header,
            timestamp=timestamp,
            hmac_secret=runtime.push_hmac_secret,
            replay_window_s=runtime.push_replay_window_s,
            now=time.time(),
        )
    except PushEventVerificationError as exc:
        raise HTTPException(status_code=401, detail="signature verification failed") from exc

    try:
        payload = json.loads(body)
        entry = MarketplacePublishedEntry(
            content_hash=str(payload["content_hash"]), skill_id=str(payload["skill_id"])
        )
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        # SECURITY: signature verified but the body itself doesn't match the
        # expected shape - this is a caller-input problem (safe to describe),
        # not a forged/replayed event (already ruled out above).
        raise HTTPException(status_code=400, detail=f"invalid webhook payload: {exc}") from exc

    if runtime.marketplace is None or runtime.reeval_session_factory is None:
        # SECURITY: signature verified but no marketplace/reeval wiring is
        # configured in this deployment - accept (the event WAS authentic)
        # but there is nothing to act on yet; fail-visible via the response
        # body, not a fabricated "processed" result.
        return {"status": "accepted_but_not_configured"}

    async with (
        runtime.gate_session_factory() as gate_session,
        runtime.reeval_session_factory() as reeval_session,
        reeval_session.begin(),
    ):
        outcome = await apply_push_event(
            entry,
            gate_session=gate_session,
            reeval_session=reeval_session,
            marketplace=runtime.marketplace,
            push_auto_quarantine_enabled=runtime.push_auto_quarantine_enabled,
        )
    return {"status": "processed", "result": outcome.result.value}


@router.get("/me")
async def get_current_session(
    session: SessionContext = Depends(_submitter_or_above),
) -> dict[str, Any]:
    """SECURITY: UX-only ("frontend隐藏仅UX", coding spec §9) - the frontend
    uses this to decide what nav/actions to SHOW, never as an authorization
    decision itself (every route independently re-checks via require_role)."""
    return {
        "subject": session.subject,
        "roles": sorted(session.roles),
        "tier": session.tier.value,
    }
