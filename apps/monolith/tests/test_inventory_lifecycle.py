"""Tests for `inventory.lifecycle` (coding spec §16.2 skill lifecycle state
machine). Pure logic, no DB/network needed.
"""

from __future__ import annotations

import pytest

from monolith.modules.inventory.lifecycle import InvalidTransitionError, validate_transition


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


class TestRetiredIsTerminal:
    @pytest.mark.parametrize(
        "to_state", ["submitted", "scanning", "review_pending", "published", "quarantined"]
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
