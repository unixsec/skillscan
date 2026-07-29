"""Tests for `inventory.lifecycle` (coding spec §16.2 skill lifecycle state
machine). Pure logic, no DB/network needed.
"""

from __future__ import annotations

import pytest

from monolith.modules.inventory.lifecycle import (
    InvalidTransitionError,
    LifecyclePosition,
    pending_review_is_superseded,
    validate_transition,
)


class TestGenesisTransition:
    def test_submitted_from_none_is_valid(self) -> None:
        validate_transition(None, "submitted")  # must not raise

    def test_anything_other_than_submitted_from_none_is_invalid(self) -> None:
        with pytest.raises(InvalidTransitionError, match="first lifecycle event"):
            validate_transition(None, "published")


class TestLinearProgression:
    @pytest.mark.parametrize(
        ("from_state", "to_state"),
        [
            ("submitted", "scanning"),
            ("scanning", "published"),
            ("scanning", "review_pending"),
            ("scanning", "retired"),
            ("review_pending", "published"),
            ("review_pending", "retired"),
            ("published", "quarantined"),
            ("published", "retired"),
        ],
    )
    def test_valid_transitions_do_not_raise(self, from_state: str, to_state: str) -> None:
        validate_transition(from_state, to_state)


class TestQuarantineCycle:
    def test_quarantined_back_to_published(self) -> None:
        validate_transition("quarantined", "published")  # admin restores after investigation

    def test_quarantined_to_retired(self) -> None:
        validate_transition("quarantined", "retired")  # admin decides to permanently retire


class TestBlockedState:
    def test_block_verdict_moves_skill_to_blocked_state(self) -> None:
        validate_transition("scanning", "blocked")

    def test_blocked_cannot_publish_directly(self) -> None:
        with pytest.raises(InvalidTransitionError):
            validate_transition("blocked", "published")

    def test_blocked_can_rescan_or_retire(self) -> None:
        validate_transition("blocked", "scanning")
        validate_transition("blocked", "retired")


class TestResubmissionOfANewVersion:
    """A skill_id's SECOND (third, ...) version re-enters the state machine
    through `X -> submitted`, driven by `inventory.service.
    register_skill_version` off the skill's REAL current state (never a
    fabricated `None -> submitted` genesis event). Coding spec §16.2 draws
    only the single-version happy path and is silent on re-entry; the source
    set below is this project's inference, argued per state.
    """

    @pytest.mark.parametrize(
        "from_state",
        [
            # Publishing v2 of a healthy skill - the ordinary reason anyone
            # submits twice, and the case that made this a P0 journey break.
            "published",
            # A reviewer asked for changes; the developer uploads the fix
            # instead of waiting out a review of content they've abandoned.
            "review_pending",
            # The recovery path `blocked -> scanning` was always supposed to
            # serve: fix what the BLOCK verdict flagged, resubmit.
            "blocked",
        ],
    )
    def test_settled_states_accept_a_new_version(self, from_state: str) -> None:
        validate_transition(from_state, "submitted")

    def test_quarantined_cannot_be_resubmitted(self) -> None:
        # SECURITY: this absence is a DELIBERATE GATE, not a gap in the table.
        # If you are here because `quarantined` looks like the odd one out
        # among the settled states, read this before "completing the set".
        #
        # A skill is quarantined precisely BECAUSE the automated scanner
        # already passed it once and something else (drift detection, threat
        # intel) caught it afterwards. A new PASS verdict from that same
        # scanner cannot substitute for the human review the quarantine
        # exists to force. Allowing quarantined -> submitted -> scanning ->
        # published would also make the admin-only `quarantined -> published`
        # restore optional in practice, since resubmitting would be faster
        # than waiting for an admin - the gate would still be in the table and
        # mean nothing.
        #
        # The supported way to ship a new version of a quarantined skill is:
        # an admin restores it to `published` first, then normal versioning.
        #
        # Note this is NOT symmetric with `blocked` (see the accepted set
        # above), even though the two states look alike - a BLOCKed skill
        # never cleared a scan, so its re-entry bypasses no human decision.
        with pytest.raises(InvalidTransitionError, match="cannot transition"):
            validate_transition("quarantined", "submitted")

    def test_scanning_cannot_be_resubmitted(self) -> None:
        # SECURITY: the one genuinely dangerous source state. A scan is in
        # flight and a verdict is about to be written against it; accepting a
        # resubmission here races `worker`'s scanning -> published/blocked/
        # review_pending reconcile against the new submission's own
        # submitted -> scanning, and the losing write lands on the wrong
        # content. Fail closed - the caller gets a 409 and retries after the
        # in-flight scan settles.
        with pytest.raises(InvalidTransitionError, match="cannot transition"):
            validate_transition("scanning", "submitted")

    def test_retired_cannot_be_resubmitted(self) -> None:
        # `retired` is terminal by design (coding spec §16.2) - resurrecting a
        # retired skill_id is a new registration, not a new version.
        with pytest.raises(InvalidTransitionError, match="cannot transition"):
            validate_transition("retired", "submitted")

    def test_submitted_cannot_be_resubmitted(self) -> None:
        # Deliberately NOT widened: `submitted` never rests (the gateway
        # commits register_skill_version + the submitted -> scanning
        # transition in one transaction, and `worker`'s reconcile only ever
        # picks up `scanning`/`review_pending`), so a self-loop here would be
        # an unreachable edge in a security-relevant table.
        with pytest.raises(InvalidTransitionError, match="cannot transition"):
            validate_transition("submitted", "submitted")


class TestRetiredIsTerminal:
    @pytest.mark.parametrize(
        "to_state",
        ["submitted", "scanning", "review_pending", "published", "blocked", "quarantined"],
    )
    def test_no_transition_out_of_retired(self, to_state: str) -> None:
        with pytest.raises(InvalidTransitionError, match="cannot transition"):
            validate_transition("retired", to_state)


class TestInvalidTransitions:
    def test_cannot_skip_scanning(self) -> None:
        with pytest.raises(InvalidTransitionError):
            validate_transition("submitted", "published")

    def test_cannot_go_backwards(self) -> None:
        with pytest.raises(InvalidTransitionError):
            validate_transition("published", "scanning")

    def test_unknown_target_state_rejected(self) -> None:
        with pytest.raises(InvalidTransitionError, match="unknown target state"):
            validate_transition("submitted", "not-a-real-state")

    def test_unknown_source_state_rejected(self) -> None:
        with pytest.raises(InvalidTransitionError, match="unknown source state"):
            validate_transition("not-a-real-state", "scanning")

    def test_quarantined_cannot_go_directly_to_review_pending(self) -> None:
        with pytest.raises(InvalidTransitionError):
            validate_transition("quarantined", "review_pending")


class TestPendingReviewIsSuperseded:
    """I3 (2026-07-29): a queued REVIEW verdict is only worth a human's time
    while the skill is STILL `review_pending` at that exact content_hash.

    `review_pending -> submitted` became legal in Task 11 so a skill awaiting
    review can ship a corrected version - and it left the earlier REVIEW
    verdict in the queue, because `gate.service.list_pending_reviews` filters
    purely on `verdict == "REVIEW"`. An approver deciding one of those is
    acting on a superseded content hash, and `worker.sync_lifecycle_tick`
    then discards the answer (it transitions only `scanning`/`review_pending`
    skills), so the sign-off vanishes with no feedback.
    """

    _HASH = "a" * 64

    def test_still_review_pending_at_this_content_is_actionable(self) -> None:
        position = LifecyclePosition(
            skill_id="skill-1", state="review_pending", content_hash=self._HASH
        )
        assert pending_review_is_superseded(position, review_content_hash=self._HASH) is False

    def test_a_newer_version_supersedes_the_queued_review(self) -> None:
        # The exact I3 case: v2 was submitted while v1 sat in the queue.
        position = LifecyclePosition(skill_id="skill-1", state="submitted", content_hash="b" * 64)
        assert pending_review_is_superseded(position, review_content_hash=self._HASH) is True

    def test_review_pending_at_a_DIFFERENT_content_is_superseded(self) -> None:
        # State alone is not enough: a later version can be back at
        # `review_pending` under its OWN hash, which has its own queue entry.
        # Deciding the older one would still be discarded.
        position = LifecyclePosition(
            skill_id="skill-1", state="review_pending", content_hash="c" * 64
        )
        assert pending_review_is_superseded(position, review_content_hash=self._HASH) is True

    @pytest.mark.parametrize(
        "state", ["submitted", "scanning", "published", "blocked", "quarantined", "retired"]
    )
    def test_every_other_state_supersedes_it(self, state: str) -> None:
        # Not a list of special cases - `review_pending` is precisely the set
        # of positions from which a review decision can still reach the
        # lifecycle, so everything else is superseded by construction.
        position = LifecyclePosition(skill_id="skill-1", state=state, content_hash=self._HASH)
        assert pending_review_is_superseded(position, review_content_hash=self._HASH) is True

    def test_no_lifecycle_at_all_is_not_superseded(self) -> None:
        # SECURITY/UX: an anonymous submission never registered a skill_id, so
        # its REVIEW verdict is a pure gate-level decision with no lifecycle to
        # contradict it. Treating "no position" as superseded would silently
        # make every such entry undecidable - a far worse failure than the one
        # this predicate exists to fix.
        assert pending_review_is_superseded(None, review_content_hash=self._HASH) is False
