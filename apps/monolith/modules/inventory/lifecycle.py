"""Skill lifecycle state machine (coding spec §16.2, FR-INV):

    submitted -> scanning -> (review_pending) -> published -> [quarantined <-> published] -> retired

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

# SECURITY: "quarantined" is reachable from BOTH "published" (drift/intel-
# triggered per coding spec §16.2, or an admin manual action) and can return
# to "published" (admin restores after investigation) or terminate at
# "retired" - the only cycle in an otherwise linear progression.
VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    "submitted": frozenset({"scanning"}),
    "scanning": frozenset({"published", "review_pending", "retired"}),
    "review_pending": frozenset({"published", "retired"}),
    "published": frozenset({"quarantined", "retired"}),
    "quarantined": frozenset({"published", "retired"}),
    "retired": frozenset(),  # terminal - no transitions out
}

ALL_STATES = frozenset(VALID_TRANSITIONS.keys())


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
