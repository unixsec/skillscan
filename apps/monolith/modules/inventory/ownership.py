"""Who may write a new VERSION of an already-registered skill (milestone F
Task 11 follow-up C1).

Pure logic only - no DB/network I/O, same posture as `lifecycle.py` next door.
`lifecycle.py` answers "is this transition STRUCTURALLY legal"; this module
answers "is this ACTOR allowed to drive it for this skill". They are
deliberately separate questions and both must pass.

WHY THIS EXISTS. Until 2026-07-29 `"submitted"` appeared zero times as a target
in `lifecycle.VALID_TRANSITIONS`, so `register_skill_version`'s validated
`current_state -> "submitted"` re-entry could never succeed and EVERY second
submission for a known `skill_id` was refused with a 409. That defect was
doing unintended double duty: it also meant a submission naming SOMEONE ELSE's
`skill_id` changed nothing. Fixing the lockout (which had to happen - no skill
could ever ship a v2) removed the accidental control, and nothing else on the
submission path had ever checked who owns the named skill:

  * `skill` has no owner column at all (had none before this task's migration);
  * `skill_id` AND `trust_tier` are both caller-supplied form fields on
    `POST /v1/scans`.

So any caller holding submit rights could name any existing skill, knock it out
of `published`, write their own `skill_version` row, have it judged at a trust
tier THEY chose, and on PASS leave that `skill_id` published with their content
as the latest version. This module is the missing check. It is an omission
being closed, not a trust model being changed - the codebase already enforces
object-level authorization elsewhere (IDOR-404 on `GET /v1/scans`, separation
of duties on reviews).

OWNER = THE IDENTITY THAT FIRST REGISTERED THE SKILL, recorded on
`skill.owner` at genesis by `service.register_skill_version` and never
rewritten on any SUBMISSION path. A resubmission does not transfer ownership,
and neither does an admin acting on someone's behalf - see
`authorize_skill_write`.

EXACTLY ONE path rewrites it (added 2026-07-29, milestone F Task 15): the
dedicated admin route `POST /v1/inventory/{skill_id}/owner`, whose decision
logic is `validate_owner_assignment` below. That is not a softening of the
sentence above, it is the other half of it - see that function's docstring for
why an explicit, audited, admin-only assignment is a different act from an
implicit rewrite riding along on a submission, and why the system is unusable
without it.
"""

from __future__ import annotations

# `skill.owner` is `String(255)` (models.SkillRow). Validated here rather than
# left to MySQL: a too-long value would otherwise either be silently TRUNCATED
# (a non-strict server would then record an owner nobody can ever match, i.e. a
# permanent lockout that looks like a success) or surface as a 500 from a
# DataError. Neither is an honest answer to "that name is too long".
MAX_OWNER_LENGTH = 255


class SkillOwnershipError(PermissionError):
    """SECURITY: the caller is authenticated but is not authorized to write
    this skill.

    Callers surface this as **403**, never 409. The pre-2026-07-29 behaviour
    answered 409 ("conflict/duplicate") to this situation, which was wrong on
    both counts: nothing is duplicated, and "you may not modify this object" is
    exactly what 403 means. A client that reads 409 as "retry with different
    content" would loop forever against a wall that is about identity.
    """


def authorize_skill_write(
    *,
    skill_id: str,
    recorded_owner: str | None,
    actor: str,
    actor_is_admin: bool,
) -> None:
    """Raises `SkillOwnershipError` unless `actor` may submit a new version of
    an ALREADY-REGISTERED `skill_id`. A brand-new `skill_id` never reaches
    here - registering one is what makes the caller its owner.

    ADMIN OVERRIDE: **yes, deliberately.** An admin may resubmit on any
    skill's behalf, and the decision is made explicit here rather than left to
    a reader to infer from its absence. Three reasons: (1) an admin already
    holds strictly STRONGER powers over this same object - `inventory/
    router.py` lets them quarantine, retire and re-baseline any skill - so
    refusing them the weaker "submit a new version, which still gets fully
    scanned and gated" would be incoherent, not safer; (2) it is the ONLY
    recovery path for the legacy rows below, which would otherwise be
    permanently unversionable by anyone; (3) it is fully audited - the
    resulting `skill_lifecycle_event.actor` and `audit_intent.operator` both
    record the admin's own subject, so an override is visible after the fact
    rather than indistinguishable from the owner acting.

    An admin override does NOT transfer ownership: `register_skill_version`
    writes `skill.owner` once, at genesis, and never updates it. An admin
    helping someone ship a release must not silently become the owner of their
    skill, and a takeover must not be reachable by laundering it through an
    admin action either.

    UNOWNED LEGACY ROWS (`recorded_owner is None`) FAIL CLOSED. The column is
    new and is deliberately NOT backfilled, so every row registered before this
    migration reads NULL. NULL means "this system holds no record of who owns
    this skill" - and the honest answer to "may this caller modify it" when the
    owner is unknown is no, not yes. Defaulting to permissive would leave the
    exact hole this module exists to close wide open for precisely the rows an
    attacker would most want (every skill that existed before the fix).

    A backfill was considered and REJECTED, and the reasoning is worth keeping
    because the value looks available: `skill_lifecycle_event` does record an
    `actor` on each skill's genesis (`from_state IS NULL`) event, and that
    actor IS by construction the identity that first registered the skill. So a
    backfill would not have been a guess. It was rejected on blast radius: that
    column was written as an AUDIT field and promoting it to an AUTHORIZATION
    field retroactively would grant real ownership - over ~481 bulk-imported
    real-world skills in the deployed database, among others - on the strength
    of a field nobody chose with authorization in mind. The two failure modes
    are not symmetric. A wrong backfill silently hands someone authority they
    should not have; fail-closed NULL produces a loud 403 that an admin can
    resolve deliberately, one skill at a time. Loud and recoverable beats
    silent and permanent. If the operator later decides that genesis actors ARE
    the rightful owners, that backfill remains available as its own reviewed
    migration - the reverse is not.

    NOTE ON EXISTENCE DISCLOSURE (accepted tradeoff): answering 403 rather than
    202 tells the caller that this `skill_id` is taken by someone else, the
    same class of disclosure as a "username already registered" signup error.
    Accepted deliberately. The alternative - a 202 that silently scans nothing
    into the caller's own namespace - would make the API lie about what it did,
    and a submitter attempting this already had to know the exact `skill_id` to
    type it. The 403 body never names the OWNER, only the skill: who owns a
    skill is not the requester's business, and echoing it back would turn every
    submission attempt into an identity-harvesting probe.
    """
    if actor_is_admin:
        return
    if recorded_owner is None:
        raise SkillOwnershipError(
            f"skill {skill_id!r} has no recorded owner, so a new version of it cannot be "
            "authorized; an admin must submit it"
        )
    if recorded_owner != actor:
        raise SkillOwnershipError(
            f"skill {skill_id!r} is registered to another identity; you may not submit a "
            "new version of it"
        )


class InvalidOwnerError(ValueError):
    """The proposed owner is not a usable identity string (blank, or longer
    than the column). Callers surface this as **400** - it is a malformed
    request, not an authorization failure and not a conflict."""


class OwnerAssignmentConflictError(ValueError):
    """SECURITY: the caller asked to assign an owner to a skill it believed was
    UNOWNED, and that skill already has one.

    Callers surface this as **409**. It is a genuine conflict with the
    resource's current state - unlike `SkillOwnershipError`, the caller (an
    admin) IS authorized to act here; the object simply is not in the state
    they described. Retrying verbatim would be wrong, which is exactly what a
    409 tells a client and a 403 does not.
    """


def normalize_owner(new_owner: str) -> str:
    """Shape-checks a proposed owner and returns the string to store. Raises
    `InvalidOwnerError` (400) for anything unusable.

    Split out from `validate_owner_assignment` so a BULK caller can reject a
    malformed owner ONCE, before it starts committing per-skill transactions,
    instead of reporting the same request-level mistake as N identical
    per-skill failures. It is called again inside the assignment path - this
    one is for fail-fast, that one is authoritative.
    """
    normalized = new_owner.strip()
    if not normalized:
        raise InvalidOwnerError("owner must be a non-empty identity")
    if len(normalized) > MAX_OWNER_LENGTH:
        raise InvalidOwnerError(f"owner must be at most {MAX_OWNER_LENGTH} characters")
    return normalized


def validate_owner_assignment(
    *,
    skill_id: str,
    recorded_owner: str | None,
    new_owner: str,
    expect_unowned: bool,
) -> str:
    """Decides whether an ADMIN may write `new_owner` onto `skill_id`, and
    returns the normalized owner string to store. Pure logic, no I/O -
    authorization itself (admin) is the router's `require_role("admin")`, the
    same split `transition_skill` documents.

    WHY THIS EXISTS AT ALL, given `authorize_skill_write` says ownership is
    "written once at genesis and never rewritten": that sentence describes
    every SUBMISSION path and still does. It left the deployment in a state
    with no way out. `skill.owner` was added NULLABLE and deliberately not
    backfilled, so every skill registered before it existed - roughly 481
    bulk-imported real-world skills on the deployed VM - reads NULL, fails
    closed, and is now admin-only forever, with no route back to whoever
    actually owns it. Symmetrically, an owner who leaves the organisation
    strands every skill in their name permanently. Fail-closed is the right
    DEFAULT precisely because an admin can resolve it deliberately; a
    fail-closed default with no resolution path is just a dead end.

    So the recovery path exists, and its shape is the whole point:

      * ADMIN ONLY, and never a side effect. `register_skill_version` still
        never writes `owner` for an existing skill, so no submission can move
        ownership; you have to ask for this, on its own endpoint, and say why.
      * AUDITED as a privilege change. `service.assign_skill_owner` writes an
        `audit_intent` row in the SAME transaction as the UPDATE (INV-12),
        recording the PREVIOUS owner as well as the new one - "alice now owns
        it" is not an answerable record of what changed.
      * EVIDENCE, NOT A BACKFILL. The console shows each unowned skill's
        genesis `actor` from `skill_lifecycle_event` next to it, because that
        is real evidence an admin should see before deciding. It is not
        promoted to the decision: there is no "adopt every genesis actor"
        button and no migration that writes them, because "who submitted this
        once" and "who may modify it now" are different questions. An admin
        types the identity they are granting authority to, having seen the
        evidence, one deliberate act per assignment.

    `expect_unowned` IS A COMPARE-AND-SET GUARD, and it defaults to True at
    the API. Assigning an owner to an unowned skill and TAKING a skill from
    its current owner are the same UPDATE and very different acts. The bulk
    console flow always means the first one, and its row set was rendered from
    a list read earlier - so an admin bulk-assigning 481 rows must not silently
    clobber an owner that appeared in between (a first registration, or a
    second admin working the same list). With the guard on, that row conflicts
    (409) and is reported instead of being overwritten. A real transfer sets
    it False, which reads as what it is: "yes, I know someone owns this, and I
    am moving it".

    NO IDENTITY VALIDATION on purpose, only shape. There is no complete
    registry to validate against - identities arrive from local accounts AND
    from OIDC/SAML, so rejecting anything not already in `local_account` would
    refuse every legitimate SSO owner. The failure mode of a typo is the safe
    one: `authorize_skill_write` compares `recorded_owner` to `session.subject`
    verbatim, so a misspelled owner matches nobody and the skill stays
    admin-only - the same fail-closed state it was already in, visible in the
    audit trail, and fixable by assigning again.
    """
    normalized = normalize_owner(new_owner)
    if expect_unowned and recorded_owner is not None:
        # SECURITY: the message names the CURRENT owner. Unlike the 403 on the
        # submission path - which must not turn a submit attempt into an
        # identity-harvesting probe - this endpoint is admin-only, and an admin
        # deciding a transfer needs to know what they would be overwriting.
        raise OwnerAssignmentConflictError(
            f"skill {skill_id!r} is already owned by {recorded_owner!r}; assign it explicitly "
            "as a transfer if you intend to take it over"
        )
    return normalized
