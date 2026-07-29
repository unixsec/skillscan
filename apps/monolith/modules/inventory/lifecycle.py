"""Skill lifecycle state machine (coding spec §16.2, FR-INV):

    submitted -> scanning -> (review_pending) -> published -> [quarantined <-> published] -> retired

A skill_id lives longer than one version: a settled skill (published /
review_pending / blocked) re-enters at "submitted" when a new VERSION
arrives, so the spec's line above is one lap, not the whole life. See
VALID_TRANSITIONS' own comment for which source states may re-enter and why
"scanning", "retired" and "quarantined" may not.

Pure logic only - no DB/network I/O. SECURITY: every transition goes through
this module's `transition()` - never mutate `to_state` directly without
validating against `VALID_TRANSITIONS` first (coding spec: "状态迁移经门禁/
审批" - transitions happen only through gate/approval, not arbitrarily).
Authorization for WHO may trigger a given transition (e.g. "quarantine/retire
需 admin" - quarantine/retire require admin) is enforced by the caller (the
admin API router's `require_role("admin")`), not here - this module only
knows whether a transition is STRUCTURALLY valid, not who's allowed to
request it.
"""

from __future__ import annotations

from dataclasses import dataclass

# SECURITY: "quarantined" is reachable from BOTH "published" (drift/intel-
# triggered per coding spec §16.2, or an admin manual action) and can return
# to "published" (admin restores after investigation) or terminate at
# "retired" - the only cycle in an otherwise linear progression.
#
# RE-ENTRY ("X -> submitted"): a skill_id's second and later VERSIONS re-enter
# the machine here. Coding spec §16.2 draws only one version's journey and is
# silent on re-entry, so the source set below is this project's inference
# (2026-07-29), argued per state at each edge. Before it existed, "submitted"
# appeared 0 times as a target, and since `inventory.service.
# register_skill_version` deliberately routes an already-known skill_id
# through a validated `current_state -> "submitted"` transition rather than
# faking a second genesis event, NO skill could ever have a second version
# submitted - every publisher of a v2, and every developer resubmitting a
# fixed BLOCKed skill, got a 409.
VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    "submitted": frozenset({"scanning"}),
    # SECURITY: NO "submitted" here. A scan is in flight and its verdict is
    # about to be written; accepting a resubmission would race `worker`'s
    # scanning -> published/blocked/review_pending reconcile against the new
    # submission's own submitted -> scanning, and the losing write would land
    # on the wrong content. Callers get a 409 and retry once the scan settles.
    "scanning": frozenset({"published", "review_pending", "retired", "blocked"}),
    "review_pending": frozenset({"published", "retired", "submitted"}),
    "published": frozenset({"quarantined", "retired", "submitted"}),
    # SECURITY: NO "submitted" here, and its absence is a DELIBERATE GATE, not
    # an oversight - do not "complete the set" by adding it back.
    #
    # A skill reaches `quarantined` precisely BECAUSE the automated scanner
    # already passed it once and something else (drift detection, threat
    # intel) caught it afterwards. A fresh PASS verdict from that same scanner
    # therefore cannot stand in for the human review the quarantine exists to
    # force. And since this module's own docstring records that
    # "quarantine/retire 需 admin", allowing quarantined -> submitted ->
    # scanning -> published would make the admin-only `quarantined ->
    # published` restore optional: nobody would wait for an admin when
    # resubmitting is faster. The gate would still be in the table and mean
    # nothing.
    #
    # Shipping a new version of a quarantined skill is possible - the path is
    # for an admin to restore it to `published` first, then iterate normally.
    # That keeps a human in the loop exactly once, where the quarantine put
    # them. That path is `POST /v1/inventory/{skill_id}/restore` (admin-only,
    # CSRF, audited) - built 2026-07-29 as follow-up C2, because until then
    # this justification named a route that existed in the table below and in
    # NO caller anywhere: `quarantined -> published` was structurally legal
    # and unreachable, which made `quarantined` a dead end with only
    # `retired` actually reachable from it.
    #
    # This is NOT symmetric with "blocked" below, despite the two states
    # looking alike: a BLOCKed skill never passed a scan at all, so its
    # resubmission runs the full scanning pipeline without bypassing any human
    # gate that was ever engaged.
    "quarantined": frozenset({"published", "retired"}),
    # SECURITY: "blocked" cannot go directly to "published" - lifting a block
    # must go back through scanning, so every release corresponds to a fresh,
    # newly-signed verdict rather than a state rewrite. "submitted" is the
    # remediation route the same rule implies: fix what the BLOCK flagged,
    # resubmit, get re-scanned. Safe here (unlike `quarantined` above) because
    # the skill was stopped BY the scanner and never cleared it - re-entry
    # bypasses no human decision, it just runs the pipeline again.
    "blocked": frozenset({"scanning", "retired", "submitted"}),
    "retired": frozenset(),  # terminal - no transitions out
}

ALL_STATES = frozenset(VALID_TRANSITIONS.keys())

# The ONLY state in which a queued REVIEW verdict is still worth a human's
# time. `worker.sync_lifecycle_tick` acts on exactly `scanning` and
# `review_pending`, and a review decision can only ever drive the latter - so
# outside this state the approver's answer is written to the verdict row and
# then dropped on the floor by the lifecycle.
REVIEW_ACTIONABLE_STATE = "review_pending"


@dataclass(frozen=True, slots=True)
class LifecyclePosition:
    """Where a skill's lifecycle currently stands: its latest recorded
    `to_state` and the `content_hash` that event was about (NULL for the
    admin quarantine/retire/restore routes, which record no content).

    Plain values, never the ORM row - the same "plain values cross the module
    boundary" rule `RegisteredSkill` documents in service.py. Lives here, in
    the pure-logic module, so `pending_review_is_superseded` below can be a
    real pure function rather than something only reachable through a DB
    session.
    """

    skill_id: str
    state: str
    content_hash: str | None


def pending_review_is_superseded(
    position: LifecyclePosition | None, *, review_content_hash: str
) -> bool:
    """Is a queued REVIEW verdict for `review_content_hash` still actionable?

    2026-07-29 (milestone F Task 11 follow-up I3). Task 11 made
    `review_pending -> submitted` legal so a skill awaiting review can ship a
    corrected version. What it left behind is the EARLIER REVIEW verdict,
    still sitting in the queue: `gate.service.list_pending_reviews` filters
    purely on `verdict == "REVIEW"` and knows nothing about lifecycle. An
    approver who picks it up is deciding a content hash the skill has already
    moved off, and `worker.sync_lifecycle_tick` then discards that decision
    (it only ever transitions skills whose latest state is `scanning` or
    `review_pending`) - the human's work is thrown away with no feedback.

    THE RULE, and why it is exactly this: a review is actionable only while
    the skill's CURRENT position is `review_pending` AT THIS content_hash.
    That is not a heuristic, it is the precise condition under which the
    worker will act on the answer. Anything else - a newer version submitted,
    an admin retirement, a quarantine, an already-completed publish - means
    the decision cannot reach the lifecycle, so presenting it as actionable
    is a lie.

    `position is None` (no lifecycle at all) is NOT superseded: an anonymous
    submission never registered a `skill_id`, so its REVIEW verdict is a pure
    gate-level decision with no lifecycle to contradict it. Those are ordinary
    queue entries and must stay decidable.
    """
    if position is None:
        return False
    return not (
        position.state == REVIEW_ACTIONABLE_STATE and position.content_hash == review_content_hash
    )


class InvalidTransitionError(ValueError):
    pass


def validate_transition(from_state: str | None, to_state: str) -> None:
    """`from_state=None` is only valid for a skill_id's very first event
    (the genesis "submitted" transition) - raises otherwise."""
    if to_state not in ALL_STATES:
        raise InvalidTransitionError(
            f"unknown target state {to_state!r}, expected one of {sorted(ALL_STATES)}"
        )
    if from_state is None:
        if to_state != "submitted":
            raise InvalidTransitionError(
                f"a skill's first lifecycle event must be 'submitted', got {to_state!r}"
            )
        return
    if from_state not in ALL_STATES:
        raise InvalidTransitionError(f"unknown source state {from_state!r}")
    if to_state not in VALID_TRANSITIONS[from_state]:
        raise InvalidTransitionError(
            f"cannot transition {from_state!r} -> {to_state!r}, "
            f"valid targets from {from_state!r}: {sorted(VALID_TRANSITIONS[from_state])}"
        )
