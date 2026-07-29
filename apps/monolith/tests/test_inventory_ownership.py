"""Tests for `inventory.ownership` - who may submit a new VERSION of an
already-registered skill (milestone F Task 11 follow-up C1).

PURE LOGIC, NO INFRASTRUCTURE. Everything in this file runs on the local
machine: no MySQL, no Redis, no container. That is deliberate and it is why the
authorization decision was factored into its own module instead of living
inline in `service.py` or `gateway/router.py` - the decision that answers "may
this identity overwrite that skill" is exactly the kind of thing that should be
exhaustively exercisable without any environment at all.

The end-to-end proof (a second identity submitting against a published
`skill_id` over the real HTTP path, and being refused with a 403) lives in
`test_router.py::TestSkillOwnership`. That one needs real MySQL + Redis and is
written but NOT run locally, per this project's VM-only rule.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from monolith.modules.inventory.lifecycle import InvalidTransitionError, validate_transition
from monolith.modules.inventory.ownership import (
    MAX_OWNER_LENGTH,
    InvalidOwnerError,
    OwnerAssignmentConflictError,
    SkillOwnershipError,
    authorize_skill_write,
    normalize_owner,
    validate_owner_assignment,
)

_SKILL = "skill-under-test"


class TestTheTakeoverThisModuleCloses:
    """The exploit, demonstrated as far as it can be without infrastructure.

    HONEST SCOPE. What is proven here is the MECHANISM: that before this
    module existed, the only gate a cross-identity resubmission had to pass
    was `lifecycle.validate_transition`, and that gate does not know identities
    exist. It cannot, by itself, prove the full HTTP takeover - that requires
    the database, and it is asserted in `test_router.py` instead.
    """

    def test_the_only_pre_fix_gate_lets_a_published_skill_re_enter(self) -> None:
        # This single call IS the whole pre-fix authorization story for a
        # resubmission. `register_skill_version` routes an already-known
        # skill_id through a validated `current_state -> "submitted"`
        # transition, and until 2026-07-29 that call raised for every source
        # state (`"submitted"` appeared 0 times as a target), which is what
        # accidentally refused strangers - and equally refused the legitimate
        # owner shipping a v2, which is why it had to be fixed.
        #
        # It now returns cleanly. Nothing about WHO is submitting is an input
        # to it, and nothing else on the submission path looked at identity
        # either, because `skill` had no owner column at all. That is the hole.
        validate_transition("published", "submitted")

    def test_the_state_machine_takes_no_identity_argument_at_all(self) -> None:
        # Stated as an assertion rather than as prose so it stays true: if
        # someone ever "fixes" ownership by threading an actor into the state
        # machine, this fails and points them at `ownership.py`, which is where
        # that decision belongs (structural legality and authorization are
        # separate questions - see both modules' docstrings).
        params = set(inspect.signature(validate_transition).parameters)
        assert params == {"from_state", "to_state"}

    def test_the_owner_and_a_stranger_are_now_distinguishable(self) -> None:
        # The same skill, the same lifecycle state, the same content - the ONLY
        # difference is who is asking. Pre-fix both of these were the same
        # answer (both 409 before Task 11; both 202 after it).
        authorize_skill_write(
            skill_id=_SKILL, recorded_owner="alice", actor="alice", actor_is_admin=False
        )
        with pytest.raises(SkillOwnershipError):
            authorize_skill_write(
                skill_id=_SKILL, recorded_owner="alice", actor="mallory", actor_is_admin=False
            )


class TestAuthorizeSkillWrite:
    def test_the_owner_may_submit_a_new_version(self) -> None:
        authorize_skill_write(
            skill_id=_SKILL, recorded_owner="alice", actor="alice", actor_is_admin=False
        )

    def test_a_different_identity_is_refused(self) -> None:
        with pytest.raises(SkillOwnershipError) as exc_info:
            authorize_skill_write(
                skill_id=_SKILL, recorded_owner="alice", actor="mallory", actor_is_admin=False
            )
        assert _SKILL in str(exc_info.value)

    def test_the_refusal_never_names_the_owner(self) -> None:
        # SECURITY: the 403 body is built from this message. Echoing the owner
        # back would turn every submission attempt into an identity-harvesting
        # probe - a stranger would learn who owns any skill_id they can guess.
        # Who owns a skill is not the requester's business; that the skill is
        # not theirs is.
        with pytest.raises(SkillOwnershipError) as exc_info:
            authorize_skill_write(
                skill_id=_SKILL,
                recorded_owner="alice@example.com",
                actor="mallory",
                actor_is_admin=False,
            )
        assert "alice" not in str(exc_info.value)

    def test_an_unowned_legacy_skill_fails_closed_for_a_non_admin(self) -> None:
        # SECURITY: `owner IS NULL` is every row registered before this
        # column existed, and it means "no owner is on record" - NOT "anyone
        # may write it". Defaulting to permissive here would leave the hole
        # open for precisely the rows an attacker would most want: every skill
        # that predates the fix. See `authorize_skill_write`'s docstring for
        # why the available-looking backfill from the genesis lifecycle event's
        # actor was rejected rather than overlooked.
        with pytest.raises(SkillOwnershipError):
            authorize_skill_write(
                skill_id=_SKILL, recorded_owner=None, actor="alice", actor_is_admin=False
            )

    def test_an_unowned_legacy_skill_is_still_reachable_by_an_admin(self) -> None:
        # The other half of the decision above: fail-closed must not mean
        # BRICKED. An admin is the recovery path for every legacy row, which is
        # a large part of why the override exists at all.
        authorize_skill_write(
            skill_id=_SKILL, recorded_owner=None, actor="root", actor_is_admin=True
        )

    def test_an_admin_may_submit_on_another_owners_behalf(self) -> None:
        # DECIDED, not defaulted: an admin already holds strictly stronger
        # powers over this same object (quarantine / retire / re-baseline, via
        # inventory/router.py), so refusing them the weaker "submit a version
        # that still gets fully scanned and gated" would be incoherent rather
        # than safer. It is audited - the lifecycle event and audit_intent both
        # record the admin's own subject.
        authorize_skill_write(
            skill_id=_SKILL, recorded_owner="alice", actor="root", actor_is_admin=True
        )

    def test_an_empty_string_owner_does_not_match_an_empty_string_actor_by_accident(
        self,
    ) -> None:
        # Degenerate but worth pinning: `""` is not NULL and must not be
        # treated as "unowned". An identity of `""` cannot be authenticated, so
        # the pairing should never occur - but if it did, the equality branch
        # (not the fail-closed branch) is the one that must handle it, and
        # neither may crash.
        authorize_skill_write(skill_id=_SKILL, recorded_owner="", actor="", actor_is_admin=False)
        with pytest.raises(SkillOwnershipError):
            authorize_skill_write(
                skill_id=_SKILL, recorded_owner="", actor="mallory", actor_is_admin=False
            )

    def test_ownership_and_lifecycle_failures_are_distinct_exception_types(self) -> None:
        # They map to DIFFERENT status codes (403 vs 409) and the router
        # distinguishes them by type alone. If one were ever made a subclass of
        # the other, the first matching `except` would silently swallow the
        # other and an authorization failure would start reporting as a
        # conflict - the exact confusion this task exists to undo.
        assert not issubclass(SkillOwnershipError, InvalidTransitionError)
        assert not issubclass(InvalidTransitionError, SkillOwnershipError)


class TestTheOwnershipPerimeter:
    """Which submission paths can reach inventory registration at all.

    A path this control does not cover is the whole hole, so the perimeter is
    asserted rather than remembered.
    """

    def test_the_marketplace_submit_endpoint_accepts_no_skill_id(self) -> None:
        # VERIFIED, not assumed: `register_skill_version` has exactly one
        # caller in the tree (`gateway.router.create_scan`), because the
        # marketplace's submit endpoint takes no `skill_id` and therefore has
        # no inventory-lifecycle side effects at all - it cannot be a
        # resubmission of a registered skill, so there is nothing there to
        # own.
        #
        # This is the guard on that reasoning. The day someone adds `skill_id`
        # to the marketplace surface, this fails and says why - rather than
        # that path quietly becoming a second, unguarded way to take a skill
        # over. It would need its own `authorize_skill_write` call, and its own
        # answer for what a machine identity owning a skill even means.
        from monolith.modules.marketplace_api.router import submit_marketplace_scan

        params = set(inspect.signature(submit_marketplace_scan).parameters)
        assert "skill_id" not in params

    def test_register_skill_version_requires_an_explicit_admin_decision(self) -> None:
        # The Task 12 technique, applied here: `actor_is_admin` is a REQUIRED
        # keyword with no default, so every present and future submission path
        # must state whether its caller is an admin. A missed call site becomes
        # a type error rather than a silently unauthorized write. A default of
        # False would quietly break admins; a default of True would quietly
        # reopen the hole.
        from monolith.modules.inventory.service import register_skill_version

        param = inspect.signature(register_skill_version).parameters["actor_is_admin"]
        assert param.default is inspect.Parameter.empty
        assert param.kind is inspect.Parameter.KEYWORD_ONLY


class TestNormalizeOwner:
    """Shape checks on the proposed owner (milestone F Task 15)."""

    def test_surrounding_whitespace_is_stripped(self) -> None:
        # A pasted identity carries whitespace far more often than not, and
        # `authorize_skill_write` compares `recorded_owner` to `session.subject`
        # VERBATIM - so `"alice "` stored is an owner nobody can ever be. That
        # is a silent permanent lockout dressed up as a successful assignment.
        assert normalize_owner("  alice  ") == "alice"

    @pytest.mark.parametrize("blank", ["", "   ", "\t", "\n"])
    def test_a_blank_owner_is_refused(self, blank: str) -> None:
        # An empty owner is NOT the same as NULL/unowned - it is a string no
        # identity equals, so it would fail closed forever while reading as
        # "owned" everywhere in the console. Refuse it as the malformed input
        # it is (400) rather than storing it.
        with pytest.raises(InvalidOwnerError):
            normalize_owner(blank)

    def test_the_column_width_is_the_limit_and_it_is_inclusive(self) -> None:
        # `skill.owner` is String(255). One over must be a 400, not a 500 from
        # a DataError and - worse, on a non-strict server - not a silent
        # TRUNCATION that records an owner nobody can match.
        assert normalize_owner("a" * MAX_OWNER_LENGTH) == "a" * MAX_OWNER_LENGTH
        with pytest.raises(InvalidOwnerError):
            normalize_owner("a" * (MAX_OWNER_LENGTH + 1))

    def test_length_is_measured_after_stripping(self) -> None:
        # Otherwise padding alone could push a perfectly storable identity over
        # the limit and get it rejected for no reason.
        padded = f"  {'a' * MAX_OWNER_LENGTH}  "
        assert normalize_owner(padded) == "a" * MAX_OWNER_LENGTH


class TestValidateOwnerAssignment:
    """The admin assignment/transfer decision - the recovery path that makes
    `authorize_skill_write`'s fail-closed NULL resolvable instead of terminal.
    """

    def test_assigning_an_owner_to_an_unowned_skill_is_the_ordinary_case(self) -> None:
        assert (
            validate_owner_assignment(
                skill_id=_SKILL, recorded_owner=None, new_owner="alice", expect_unowned=True
            )
            == "alice"
        )

    def test_an_assignment_that_finds_an_owner_conflicts_instead_of_overwriting(self) -> None:
        # THE COMPARE-AND-SET. An admin bulk-assigning the ~481 stranded rows
        # is acting on a list read some time ago; a row that acquired an owner
        # in between must not be silently taken from them. 409, reported, and
        # the rest of the batch still goes through.
        with pytest.raises(OwnerAssignmentConflictError):
            validate_owner_assignment(
                skill_id=_SKILL, recorded_owner="alice", new_owner="mallory", expect_unowned=True
            )

    def test_the_conflict_names_the_current_owner(self) -> None:
        # Opposite call from `authorize_skill_write`'s deliberate silence, and
        # deliberately so: that message is shown to a SUBMITTER who must not be
        # able to harvest identities. This one is admin-only, and an admin
        # deciding whether to transfer needs to know whose authority they would
        # be revoking.
        with pytest.raises(OwnerAssignmentConflictError) as exc_info:
            validate_owner_assignment(
                skill_id=_SKILL, recorded_owner="alice", new_owner="mallory", expect_unowned=True
            )
        assert "alice" in str(exc_info.value)

    def test_a_transfer_is_possible_but_has_to_say_so(self) -> None:
        # The departing-owner case. It is not refused - refusing it strands
        # every skill in a leaver's name permanently - but it cannot happen by
        # accident either: the request has to carry `expect_unowned=False`,
        # which reads as "I know someone owns this and I am moving it".
        assert (
            validate_owner_assignment(
                skill_id=_SKILL, recorded_owner="alice", new_owner="bob", expect_unowned=False
            )
            == "bob"
        )

    def test_a_transfer_still_normalizes_and_still_refuses_a_blank_owner(self) -> None:
        assert (
            validate_owner_assignment(
                skill_id=_SKILL, recorded_owner="alice", new_owner=" bob ", expect_unowned=False
            )
            == "bob"
        )
        with pytest.raises(InvalidOwnerError):
            validate_owner_assignment(
                skill_id=_SKILL, recorded_owner="alice", new_owner="   ", expect_unowned=False
            )

    def test_shape_is_checked_before_the_conflict(self) -> None:
        # Ordering matters for the status code: a blank owner against an owned
        # skill is a 400 (fix your request), not a 409 (the world moved). If
        # the conflict won, an admin would be told to retry as a transfer and
        # would then get the SAME failure with an even more dangerous flag set.
        with pytest.raises(InvalidOwnerError):
            validate_owner_assignment(
                skill_id=_SKILL, recorded_owner="alice", new_owner="", expect_unowned=True
            )

    def test_reassigning_the_same_owner_to_an_unowned_skill_is_not_special(self) -> None:
        # No "already correct" shortcut: the row is unowned, so this is a real
        # first assignment and must produce a real audit record.
        assert (
            validate_owner_assignment(
                skill_id=_SKILL, recorded_owner=None, new_owner="alice", expect_unowned=True
            )
            == "alice"
        )

    def test_the_three_failure_types_stay_distinct(self) -> None:
        # The router maps them to 400 / 409 / 403 by type alone, and two of the
        # three are ValueErrors. If one ever became a subclass of another, the
        # first matching `except` would swallow it and an admin would be told
        # the wrong thing about why their assignment failed.
        assert not issubclass(InvalidOwnerError, OwnerAssignmentConflictError)
        assert not issubclass(OwnerAssignmentConflictError, InvalidOwnerError)
        assert not issubclass(InvalidOwnerError, SkillOwnershipError)
        assert not issubclass(OwnerAssignmentConflictError, SkillOwnershipError)
        # Both ARE ValueErrors, which is what lets the router's final
        # `except ValueError` (unknown skill_id -> 404) sit below them - so the
        # narrow clauses MUST come first. That ordering is asserted over the
        # real router source in `TestOnlyOneWriterOfOwner` below.
        assert issubclass(InvalidOwnerError, ValueError)
        assert issubclass(OwnerAssignmentConflictError, ValueError)


class TestOnlyOneWriterOfOwner:
    """`skill.owner` decides who may write a skill at all, so a SECOND writer
    appearing anywhere is the whole control quietly coming undone.

    Asserted against the real source text rather than remembered, because this
    is precisely the "new path added, invariant stated only in a docstring"
    shape that a diff review does not catch.
    """

    @staticmethod
    def _functions_assigning_owner_attribute(module_path: Path) -> set[str]:
        tree = ast.parse(module_path.read_text(encoding="utf-8"))
        found: set[str] = set()
        for func in ast.walk(tree):
            if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for node in ast.walk(func):
                if not isinstance(node, ast.Assign):
                    continue
                for target in node.targets:
                    if isinstance(target, ast.Attribute) and target.attr == "owner":
                        found.add(func.name)
        return found

    def test_exactly_one_function_assigns_skill_owner_after_genesis(self) -> None:
        from monolith.modules.inventory import service

        assert self._functions_assigning_owner_attribute(Path(service.__file__)) == {
            "assign_skill_owner"
        }

    def test_the_new_owner_is_always_supplied_explicitly(self) -> None:
        # The Task 12 technique again. `new_owner` is a required keyword with
        # no default, so no caller can invoke this and have an owner DERIVED
        # for it - which is the shape an "adopt the genesis actor" convenience
        # would take. The genesis actor is evidence shown to an admin; it is
        # never the value that gets written. A default here would be the
        # rejected backfill sneaking back in through a call site.
        from monolith.modules.inventory.service import assign_skill_owner

        param = inspect.signature(assign_skill_owner).parameters["new_owner"]
        assert param.default is inspect.Parameter.empty
        assert param.kind is inspect.Parameter.KEYWORD_ONLY

    def test_nothing_copies_the_genesis_actor_into_the_owner_field(self) -> None:
        # The rejected backfill, guarded rather than trusted. `genesis_actor`
        # may be READ (it is returned to the console as advisory evidence), but
        # no function may assign it to anything called `owner`.
        from monolith.modules.inventory import router, service

        for module in (service, router):
            module_file = module.__file__
            assert module_file is not None
            tree = ast.parse(Path(module_file).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.keyword) and node.arg in {"owner", "new_owner"}:
                    rendered = ast.unparse(node.value)
                    assert "genesis" not in rendered, f"{module.__name__}: {rendered}"
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Attribute) and target.attr == "owner":
                            assert "genesis" not in ast.unparse(node.value)

    def test_the_assignment_route_orders_its_handlers_narrowest_first(self) -> None:
        # `InvalidOwnerError` and `OwnerAssignmentConflictError` are both
        # ValueErrors, and the handler ends with a broad `except ValueError`
        # for "unknown skill_id -> 404". Get the order wrong and a malformed
        # owner answers 404 while the admin re-checks a skill_id that was fine.
        from monolith.modules.inventory import router

        tree = ast.parse(Path(router.__file__).read_text(encoding="utf-8"))
        handler = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "set_skill_owner"
        )
        try_node = next(node for node in ast.walk(handler) if isinstance(node, ast.Try))
        caught = [ast.unparse(h.type) for h in try_node.handlers if h.type is not None]
        assert caught == [
            "InvalidOwnerError",
            "OwnerAssignmentConflictError",
            "ValueError",
        ]
