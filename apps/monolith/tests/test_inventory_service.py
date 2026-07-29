"""Tests for `inventory.service` (coding spec §16.2, FR-INV, INV-12) against
the real local MySQL instance - `svc_inventory` genuinely owns skill/
skill_version/baseline/skill_lifecycle_event (ALL privilege) plus an
INSERT-only view onto audit_intent, mirroring gate.service's own pattern.
"""

from __future__ import annotations

import datetime
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError

from monolith.modules.audit.models import AuditIntent
from monolith.modules.inventory.lifecycle import InvalidTransitionError
from monolith.modules.inventory.models import (
    AuditIntentInsertOnly,
    BaselineRow,
    SkillLifecycleEventRow,
    SkillRow,
    SkillVersionRow,
)
from monolith.modules.inventory.ownership import OwnerAssignmentConflictError, SkillOwnershipError
from monolith.modules.inventory.service import (
    ContentRegisteredToAnotherSkillError,
    advance_baseline_on_publish,
    assign_skill_owner,
    count_unowned_skills,
    current_state,
    genesis_actors,
    get_registered_skill,
    list_unowned_skills,
    register_skill_version,
    set_baseline,
    transition_skill,
)
from monolith.tests.conftest import SessionmakerFixture


def _content_hash() -> str:
    return uuid.uuid4().hex + uuid.uuid4().hex


class TestRegisterSkillVersion:
    @pytest.mark.asyncio
    async def test_creates_skill_and_version_and_genesis_event(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        content_hash = _content_hash()
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="internal",
                content_hash=content_hash,
                toolchain_digest="digest-v1",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )

        async with inventory_sessionmaker() as session:
            skill = await session.get(SkillRow, skill_id)
            version = await session.get(SkillVersionRow, content_hash)
            state = await current_state(session, skill_id=skill_id)
        assert skill is not None
        assert skill.trust_tier == "internal"
        assert version is not None
        assert version.toolchain_digest == "digest-v1"
        assert state == "submitted"

    @pytest.mark.asyncio
    async def test_second_version_while_still_submitted_is_rejected_not_faked(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # SECURITY (regression, was BUG): a skill_id that is still sitting at
        # `submitted` (its first submission hasn't even reached `scanning`
        # yet) previously got a SECOND fabricated `None->submitted` genesis
        # event on a second register_skill_version call - silently accepted,
        # `skill_lifecycle_event` grew a bogus duplicate genesis row, and
        # `current_state()` kept reporting "submitted" as if nothing was
        # wrong. Rejected fail-closed via validate_transition() instead.
        #
        # 2026-07-29: settled states (published/review_pending/blocked) now DO
        # have an `X -> submitted` re-entry edge, but `submitted` deliberately
        # does not - see VALID_TRANSITIONS' comment.
        # Confirms neither the SkillVersionRow write nor a second lifecycle
        # event survive (the whole call is one transaction).
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        first_hash = _content_hash()
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="internal",
                content_hash=first_hash,
                toolchain_digest="digest-v1",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )

        second_hash = _content_hash()
        with pytest.raises(InvalidTransitionError):
            async with inventory_sessionmaker() as session, session.begin():
                await register_skill_version(
                    session,
                    skill_id=skill_id,
                    source="test-suite",
                    trust_tier="internal",
                    content_hash=second_hash,
                    toolchain_digest="digest-v2",
                    declared_perms=None,
                    operator="tester",
                    actor_is_admin=False,
                )

        async with inventory_sessionmaker() as session:
            versions = (
                (
                    await session.execute(
                        select(SkillVersionRow).where(SkillVersionRow.skill_id == skill_id)
                    )
                )
                .scalars()
                .all()
            )
            events = (
                (
                    await session.execute(
                        select(SkillLifecycleEventRow)
                        .where(SkillLifecycleEventRow.skill_id == skill_id)
                        .order_by(SkillLifecycleEventRow.id)
                    )
                )
                .scalars()
                .all()
            )
            state = await current_state(session, skill_id=skill_id)
        # Only the FIRST version/genesis event survived - the rejected second
        # call's SkillVersionRow insert rolled back with the rest of its
        # transaction, not left dangling without a matching lifecycle event.
        assert [v.content_hash for v in versions] == [first_hash]
        assert len(events) == 1
        assert events[0].from_state is None
        assert events[0].to_state == "submitted"
        assert state == "submitted"

    @pytest.mark.asyncio
    async def test_second_version_after_advancing_to_scanning_is_rejected_not_faked(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # SECURITY (regression, was BUG): same fabricated-genesis defect, but
        # for a skill_id that HAS progressed past `submitted` (here:
        # `scanning`) by the time new content shows up under the same
        # skill_id. Previously this fabricated a SECOND `None->submitted`
        # event regardless, which made current_state() report "submitted"
        # again even though the skill's real state was "scanning" -
        # exactly the detour the router's `transition_skill(to_state=
        # "scanning")` call would then read as legitimate prior state. Now
        # rejected fail-closed instead.
        #
        # 2026-07-29: `scanning` is the ONE source state deliberately left
        # without an `X -> submitted` re-entry edge when the others gained
        # one. A scan is in flight here and its verdict is about to be
        # written; accepting the resubmission would race `worker`'s
        # scanning -> published/blocked/review_pending reconcile against the
        # new submission's own submitted -> scanning.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        first_hash = _content_hash()
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="internal",
                content_hash=first_hash,
                toolchain_digest="digest-v1",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="scanning",
                reason="worker picked it up",
                actor="system:orchestration",
            )

        with pytest.raises(InvalidTransitionError):
            async with inventory_sessionmaker() as session, session.begin():
                await register_skill_version(
                    session,
                    skill_id=skill_id,
                    source="test-suite",
                    trust_tier="internal",
                    content_hash=_content_hash(),
                    toolchain_digest="digest-v2",
                    declared_perms=None,
                    operator="tester",
                    actor_is_admin=False,
                )

        async with inventory_sessionmaker() as session:
            state = await current_state(session, skill_id=skill_id)
        # Unchanged - the rejected call must not have moved, faked, or
        # otherwise disturbed the skill's real current state.
        assert state == "scanning"

    @pytest.mark.asyncio
    async def test_second_version_for_a_published_skill_re_enters_at_submitted(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # 2026-07-29 (milestone F Task 11, was BUG): publishing v2 of a
        # healthy skill is the single most ordinary reason to submit twice,
        # and it was impossible - `"submitted"` appeared 0 times as a TARGET
        # in VALID_TRANSITIONS, so register_skill_version's validated
        # `published -> submitted` transition was rejected for every source
        # state and every v2 came back 409. It now re-enters at `submitted`.
        #
        # SECURITY: it re-enters via a REAL, recorded `published ->
        # submitted` event, NOT a fabricated `None -> submitted` genesis. The
        # distinction is the whole point of register_skill_version's fail-
        # closed branch: a fake genesis would make current_state() lie about
        # this skill_id having no prior state, and the caller's immediately-
        # following transition_skill() would read the fake `submitted` as
        # legitimate - laundering a jump the state machine never approved.
        # Asserted below: exactly one genesis row ever, and the new event
        # carries the skill's true prior state.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        v1_hash = _content_hash()
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="internal",
                content_hash=v1_hash,
                toolchain_digest="digest-v1",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )
        for to_state, actor in [
            ("scanning", "system:orchestration"),
            ("published", "system:gate"),
        ]:
            async with inventory_sessionmaker() as session, session.begin():
                await transition_skill(
                    session, skill_id=skill_id, to_state=to_state, reason="test", actor=actor
                )

        v2_hash = _content_hash()
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="internal",
                content_hash=v2_hash,
                toolchain_digest="digest-v2",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )

        async with inventory_sessionmaker() as session:
            state = await current_state(session, skill_id=skill_id)
            events = (
                (
                    await session.execute(
                        select(SkillLifecycleEventRow)
                        .where(SkillLifecycleEventRow.skill_id == skill_id)
                        .order_by(SkillLifecycleEventRow.id)
                    )
                )
                .scalars()
                .all()
            )
            versions = (
                (
                    await session.execute(
                        select(SkillVersionRow).where(SkillVersionRow.skill_id == skill_id)
                    )
                )
                .scalars()
                .all()
            )
        assert state == "submitted"
        assert [e.to_state for e in events] == ["submitted", "scanning", "published", "submitted"]
        # The re-entry event records the REAL prior state, not None.
        assert events[-1].from_state == "published"
        assert events[-1].content_hash == v2_hash
        # SECURITY: still exactly ONE genesis event across the skill's whole
        # history - the fabricated-second-genesis attack stays blocked.
        assert sum(1 for e in events if e.from_state is None) == 1
        # Both versions are retained; v2 did not overwrite or orphan v1.
        assert {str(v.content_hash) for v in versions} == {v1_hash, v2_hash}

        # And the router's very next step off the re-entry is the ordinary
        # `submitted -> scanning`, so the new version gets a full fresh scan.
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="scanning",
                reason="scan submitted",
                actor="tester",
                content_hash=v2_hash,
            )
        async with inventory_sessionmaker() as session:
            assert await current_state(session, skill_id=skill_id) == "scanning"

    @pytest.mark.asyncio
    async def test_second_version_for_a_retired_skill_is_rejected_not_faked(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # SECURITY (2026-07-29, milestone F Task 11): the fabricated-genesis
        # attack described in register_skill_version's docstring must still
        # be blocked AFTER settled states gained an `X -> submitted` re-entry
        # edge - widening the table must not have quietly turned the fail-
        # closed branch into a fail-open one. `retired` is terminal and is
        # the sharpest remaining probe: if register_skill_version were ever
        # to fabricate a `None -> submitted` genesis instead of validating
        # off the REAL current state, a retired skill_id would come back to
        # life here, current_state() would report `submitted`, and the
        # caller's next transition_skill(to_state="scanning") would resurrect
        # a deliberately-terminated skill without any admin action.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        v1_hash = _content_hash()
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="internal",
                content_hash=v1_hash,
                toolchain_digest="digest-v1",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )
        for to_state, actor in [
            ("scanning", "system:orchestration"),
            ("retired", "admin-alice"),
        ]:
            async with inventory_sessionmaker() as session, session.begin():
                await transition_skill(
                    session, skill_id=skill_id, to_state=to_state, reason="test", actor=actor
                )

        with pytest.raises(InvalidTransitionError):
            async with inventory_sessionmaker() as session, session.begin():
                await register_skill_version(
                    session,
                    skill_id=skill_id,
                    source="test-suite",
                    trust_tier="internal",
                    content_hash=_content_hash(),
                    toolchain_digest="digest-rug-pull",
                    declared_perms=None,
                    # 2026-07-29 (follow-up C1): the OWNER ("tester"), not the
                    # stranger this line used to name. Ownership is now checked
                    # BEFORE the transition is validated, so a stranger would
                    # be refused with `SkillOwnershipError` and this test would
                    # silently stop probing the terminal-`retired` fail-closed
                    # branch it exists for - passing for the wrong reason. The
                    # stranger case is covered on its own in
                    # `TestOwnership::test_a_stranger_is_refused_before_the_
                    # lifecycle_check_runs` below.
                    operator="tester",
                    actor_is_admin=False,
                )

        async with inventory_sessionmaker() as session:
            state = await current_state(session, skill_id=skill_id)
            events = (
                (
                    await session.execute(
                        select(SkillLifecycleEventRow)
                        .where(SkillLifecycleEventRow.skill_id == skill_id)
                        .order_by(SkillLifecycleEventRow.id)
                    )
                )
                .scalars()
                .all()
            )
            versions = (
                (
                    await session.execute(
                        select(SkillVersionRow).where(SkillVersionRow.skill_id == skill_id)
                    )
                )
                .scalars()
                .all()
            )
        # Still retired: no fake genesis row, no resurrection, and the
        # rejected call's SkillVersionRow insert rolled back with the rest of
        # its transaction rather than dangling without a lifecycle event.
        assert state == "retired"
        assert [e.to_state for e in events] == ["submitted", "scanning", "retired"]
        assert sum(1 for e in events if e.from_state is None) == 1
        assert [str(v.content_hash) for v in versions] == [v1_hash]

    @pytest.mark.asyncio
    async def test_second_version_mid_scan_cannot_race_the_in_flight_verdict(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # SECURITY (2026-07-29, milestone F Task 11): companion to the test
        # above at the OTHER deliberately-excluded source state. `scanning`
        # is the one genuinely dangerous re-entry: a verdict for the in-
        # flight content is about to be written, and letting a resubmission
        # in here races `worker`'s scanning -> published/blocked/
        # review_pending reconcile against the new submission's own
        # submitted -> scanning. Proven directly at the service layer (the
        # sibling test above reaches the same edge through the "advancing to
        # scanning" narrative; this one asserts the race property itself,
        # including that the in-flight content_hash is left untouched).
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        in_flight_hash = _content_hash()
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="internal",
                content_hash=in_flight_hash,
                toolchain_digest="digest-v1",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="scanning",
                reason="scan started",
                actor="system:orchestration",
                content_hash=in_flight_hash,
            )

        with pytest.raises(InvalidTransitionError, match="cannot transition"):
            async with inventory_sessionmaker() as session, session.begin():
                await register_skill_version(
                    session,
                    skill_id=skill_id,
                    source="test-suite",
                    trust_tier="internal",
                    content_hash=_content_hash(),
                    toolchain_digest="digest-v2",
                    declared_perms=None,
                    operator="tester",
                    actor_is_admin=False,
                )

        async with inventory_sessionmaker() as session:
            state = await current_state(session, skill_id=skill_id)
            events = (
                (
                    await session.execute(
                        select(SkillLifecycleEventRow)
                        .where(SkillLifecycleEventRow.skill_id == skill_id)
                        .order_by(SkillLifecycleEventRow.id)
                    )
                )
                .scalars()
                .all()
            )
        assert state == "scanning"
        assert [e.to_state for e in events] == ["submitted", "scanning"]
        # The verdict about to be written still targets the content that is
        # actually being scanned.
        assert events[-1].content_hash == in_flight_hash

    @pytest.mark.asyncio
    async def test_a_blocked_skill_can_be_fixed_and_resubmitted(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # 2026-07-29 (milestone F Task 11): the recovery path `blocked ->
        # scanning` was always supposed to serve. A developer whose skill got
        # a BLOCK verdict fixes what was flagged and uploads new content;
        # that must re-enter the machine rather than 409 forever.
        #
        # SECURITY: `blocked -> published` remains impossible - the fixed
        # content goes blocked -> submitted -> scanning and has to earn its
        # own fresh, newly-signed PASS verdict. No state rewrite.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="internal",
                content_hash=_content_hash(),
                toolchain_digest="digest-v1",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )
        for to_state, actor in [
            ("scanning", "system:orchestration"),
            ("blocked", "system:gate"),
        ]:
            async with inventory_sessionmaker() as session, session.begin():
                await transition_skill(
                    session, skill_id=skill_id, to_state=to_state, reason="test", actor=actor
                )

        fixed_hash = _content_hash()
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="internal",
                content_hash=fixed_hash,
                toolchain_digest="digest-v2",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="scanning",
                reason="rescan after fix",
                actor="tester",
                content_hash=fixed_hash,
            )

        async with inventory_sessionmaker() as session:
            state = await current_state(session, skill_id=skill_id)
            events = (
                (
                    await session.execute(
                        select(SkillLifecycleEventRow)
                        .where(SkillLifecycleEventRow.skill_id == skill_id)
                        .order_by(SkillLifecycleEventRow.id)
                    )
                )
                .scalars()
                .all()
            )
        assert state == "scanning"
        assert [e.to_state for e in events] == [
            "submitted",
            "scanning",
            "blocked",
            "submitted",
            "scanning",
        ]
        assert events[3].from_state == "blocked"
        assert sum(1 for e in events if e.from_state is None) == 1

    @pytest.mark.asyncio
    async def test_resubmitting_identical_content_re_enters_without_a_duplicate_version(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # I1 (2026-07-29): the policy-fix / re-run case. The PACKAGE did not
        # change; the RULESET did, and the caller wants the current toolchain's
        # opinion on bytes that BLOCKed under the old one. Before this, the
        # gateway skipped `register_skill_version` entirely for already-known
        # content, so the resubmission wrote NO lifecycle event, the skill
        # stayed `blocked` forever (`worker.sync_lifecycle_tick` matches only
        # `scanning`/`review_pending`) and the caller still got a 202.
        #
        # Two things must both hold: exactly ONE `skill_version` row survives
        # (content_hash is its primary key, and that keying is what
        # single-flight dedup and the verdict cache rest on), AND the
        # lifecycle really re-enters at `submitted`.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        content_hash = _content_hash()
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="internal",
                content_hash=content_hash,
                toolchain_digest="digest-v1",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )
        for to_state in ("scanning", "blocked"):
            async with inventory_sessionmaker() as session, session.begin():
                await transition_skill(
                    session, skill_id=skill_id, to_state=to_state, reason="test", actor="system"
                )

        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="internal",
                content_hash=content_hash,  # IDENTICAL bytes
                toolchain_digest="digest-v2",  # the ruleset moved on
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )

        async with inventory_sessionmaker() as session:
            versions = (
                (
                    await session.execute(
                        select(SkillVersionRow).where(SkillVersionRow.skill_id == skill_id)
                    )
                )
                .scalars()
                .all()
            )
            events = (
                (
                    await session.execute(
                        select(SkillLifecycleEventRow)
                        .where(SkillLifecycleEventRow.skill_id == skill_id)
                        .order_by(SkillLifecycleEventRow.id)
                    )
                )
                .scalars()
                .all()
            )
        assert len(versions) == 1
        # NOT advanced to digest-v2: writing the current digest at SUBMISSION
        # time would claim "already scanned by the current toolchain" before
        # any verdict exists - a fail-open write to the very staleness signal
        # `reeval.controller` uses to decide what still needs rescanning.
        assert versions[0].toolchain_digest == "digest-v1"
        assert [e.to_state for e in events] == ["submitted", "scanning", "blocked", "submitted"]
        assert events[3].from_state == "blocked"
        assert events[3].content_hash == content_hash
        # The audit trail must not call unchanged bytes "new content" - this
        # row is the only durable trace that a resubmission happened at all.
        assert events[3].reason == "resubmission of existing content"

    @pytest.mark.asyncio
    async def test_resubmitting_identical_content_into_a_frozen_state_is_still_refused(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # I1's other half: making the identical-content path run the lifecycle
        # must not make it BYPASS the lifecycle. `quarantined` has no
        # `-> submitted` edge on purpose (an admin restores to `published`
        # first), and resubmitting the very bytes that got quarantined is
        # exactly the request that gate exists to refuse. The caller now gets
        # a real rejection instead of the silent 202 this used to return.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        content_hash = _content_hash()
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="internal",
                content_hash=content_hash,
                toolchain_digest="digest-v1",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )
        for to_state in ("scanning", "published", "quarantined"):
            async with inventory_sessionmaker() as session, session.begin():
                await transition_skill(
                    session, skill_id=skill_id, to_state=to_state, reason="test", actor="system"
                )

        with pytest.raises(InvalidTransitionError):
            async with inventory_sessionmaker() as session, session.begin():
                await register_skill_version(
                    session,
                    skill_id=skill_id,
                    source="test-suite",
                    trust_tier="internal",
                    content_hash=content_hash,
                    toolchain_digest="digest-v2",
                    declared_perms=None,
                    operator="tester",
                    actor_is_admin=False,
                )

        async with inventory_sessionmaker() as session:
            state = await current_state(session, skill_id=skill_id)
        assert state == "quarantined"

    @pytest.mark.asyncio
    async def test_content_belonging_to_another_skill_is_refused(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # The cross-skill guard the gateway used to run inline, moved INTO the
        # writing transaction (I1). `skill_version.content_hash` is the primary
        # key: one package's bytes belong to exactly one skill and must never
        # be silently re-attributed to a second one.
        owner_skill = f"skill-{uuid.uuid4().hex[:12]}"
        other_skill = f"skill-{uuid.uuid4().hex[:12]}"
        content_hash = _content_hash()
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=owner_skill,
                source="test-suite",
                trust_tier="internal",
                content_hash=content_hash,
                toolchain_digest="digest-v1",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )

        with pytest.raises(ContentRegisteredToAnotherSkillError) as excinfo:
            async with inventory_sessionmaker() as session, session.begin():
                await register_skill_version(
                    session,
                    skill_id=other_skill,
                    source="test-suite",
                    trust_tier="internal",
                    content_hash=content_hash,
                    toolchain_digest="digest-v1",
                    declared_perms=None,
                    operator="tester",
                    actor_is_admin=False,
                )
        assert owner_skill in str(excinfo.value)

        # The whole call is one transaction: the losing skill_id must be left
        # with no row and no lifecycle history at all.
        async with inventory_sessionmaker() as session:
            assert await session.get(SkillRow, other_skill) is None
            assert await current_state(session, skill_id=other_skill) is None

    @pytest.mark.asyncio
    async def test_first_version_for_a_genuinely_new_skill_still_gets_genesis_event(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # SECURITY: confirms the fix did NOT break the correct, common case -
        # a brand new skill_id (no history at all) must still get the real
        # None->submitted genesis event, unchanged, so that the router's
        # immediately-following transition_skill(to_state="scanning") call
        # (submitted -> scanning) continues to succeed exactly as before.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        content_hash = _content_hash()
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="internal",
                content_hash=content_hash,
                toolchain_digest="digest-v1",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )

        async with inventory_sessionmaker() as session:
            events = (
                (
                    await session.execute(
                        select(SkillLifecycleEventRow).where(
                            SkillLifecycleEventRow.skill_id == skill_id
                        )
                    )
                )
                .scalars()
                .all()
            )
            state = await current_state(session, skill_id=skill_id)

        assert len(events) == 1
        assert events[0].from_state is None
        assert events[0].to_state == "submitted"
        assert state == "submitted"

        # And the router's own next step (submitted -> scanning) must still
        # go through cleanly off this real genesis event.
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="scanning",
                reason="scan submitted",
                actor="tester",
                content_hash=content_hash,
            )
        async with inventory_sessionmaker() as session:
            state = await current_state(session, skill_id=skill_id)
        assert state == "scanning"

    @pytest.mark.asyncio
    async def test_writes_audit_intent_in_the_same_transaction(
        self,
        inventory_sessionmaker: SessionmakerFixture,
        audit_sessionmaker: SessionmakerFixture,
    ) -> None:
        # SECURITY: svc_inventory can only INSERT into audit_intent, never
        # SELECT it back (policies/grants/manifest.yaml) - verifying the row
        # actually landed requires svc_audit's own (SELECT-capable) session,
        # proving this isolation is real, not just assumed.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="public",
                content_hash=_content_hash(),
                toolchain_digest="digest-v1",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )

        async with audit_sessionmaker() as session:
            result = await session.execute(
                select(AuditIntent).where(AuditIntent.action == "skill_lifecycle_transition")
            )
            intents = [
                row for row in result.scalars().all() if row.payload.get("skill_id") == skill_id
            ]
        assert len(intents) == 1
        assert intents[0].payload["to_state"] == "submitted"

    @pytest.mark.asyncio
    async def test_inventory_session_cannot_read_audit_intent_back(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # SECURITY: proves the INSERT-only grant is real at the DB layer,
        # not just app-layer convention (same isolation property
        # test_grant_isolation.py proves for other cross-module seams) -
        # this is what the ABOVE test's audit_sessionmaker workaround exists
        # to route around.
        with pytest.raises(DBAPIError):
            async with inventory_sessionmaker() as session:
                await session.execute(select(AuditIntentInsertOnly))


class TestTransitionSkill:
    @pytest.mark.asyncio
    async def test_valid_transition_updates_current_state(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="internal",
                content_hash=_content_hash(),
                toolchain_digest="digest-v1",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="scanning",
                reason="worker picked it up",
                actor="system:orchestration",
            )
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="published",
                reason="PASS verdict",
                actor="system:gate",
            )

        async with inventory_sessionmaker() as session:
            state = await current_state(session, skill_id=skill_id)
        assert state == "published"

    @pytest.mark.asyncio
    async def test_invalid_transition_raises_and_does_not_change_state(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="internal",
                content_hash=_content_hash(),
                toolchain_digest="digest-v1",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )

        with pytest.raises(InvalidTransitionError):
            async with inventory_sessionmaker() as session, session.begin():
                # SECURITY: submitted -> published directly (skipping
                # scanning) must be rejected - the whole point of a state
                # machine is that gate/approval can't be bypassed.
                await transition_skill(
                    session,
                    skill_id=skill_id,
                    to_state="published",
                    reason="attempted skip",
                    actor="tester",
                )

        async with inventory_sessionmaker() as session:
            state = await current_state(session, skill_id=skill_id)
        assert state == "submitted"  # unchanged - the failed attempt rolled back

    @pytest.mark.asyncio
    async def test_transition_on_unregistered_skill_raises(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        with pytest.raises(ValueError, match="no recorded lifecycle events"):
            async with inventory_sessionmaker() as session, session.begin():
                await transition_skill(
                    session,
                    skill_id=f"never-registered-{uuid.uuid4().hex}",
                    to_state="scanning",
                    reason="x",
                    actor="tester",
                )

    @pytest.mark.asyncio
    async def test_full_quarantine_and_restore_cycle(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="public",
                content_hash=_content_hash(),
                toolchain_digest="digest-v1",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )
        for to_state, actor in [
            ("scanning", "system:orchestration"),
            ("published", "system:gate"),
            ("quarantined", "admin:alice"),
            ("published", "admin:alice"),
        ]:
            async with inventory_sessionmaker() as session, session.begin():
                await transition_skill(
                    session, skill_id=skill_id, to_state=to_state, reason="test", actor=actor
                )

        async with inventory_sessionmaker() as session:
            state = await current_state(session, skill_id=skill_id)
            result = await session.execute(
                select(SkillLifecycleEventRow)
                .where(SkillLifecycleEventRow.skill_id == skill_id)
                .order_by(SkillLifecycleEventRow.id)
            )
            history = [row.to_state for row in result.scalars().all()]
        assert state == "published"
        assert history == ["submitted", "scanning", "published", "quarantined", "published"]


class TestCurrentState:
    @pytest.mark.asyncio
    async def test_never_registered_skill_has_no_state(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        async with inventory_sessionmaker() as session:
            state = await current_state(session, skill_id=f"never-{uuid.uuid4().hex}")
        assert state is None


class TestSetBaseline:
    @pytest.mark.asyncio
    async def test_creates_baseline_when_absent(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        content_hash = _content_hash()
        async with inventory_sessionmaker() as session, session.begin():
            await set_baseline(
                session, skill_id=skill_id, content_hash=content_hash, actor="admin:alice"
            )

        async with inventory_sessionmaker() as session:
            baseline = await session.get(BaselineRow, skill_id)
        assert baseline is not None
        assert baseline.content_hash == content_hash

    @pytest.mark.asyncio
    async def test_updates_existing_baseline(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        first_hash = _content_hash()
        second_hash = _content_hash()
        async with inventory_sessionmaker() as session, session.begin():
            await set_baseline(session, skill_id=skill_id, content_hash=first_hash, actor="a")
        async with inventory_sessionmaker() as session, session.begin():
            await set_baseline(session, skill_id=skill_id, content_hash=second_hash, actor="a")

        async with inventory_sessionmaker() as session:
            baseline = await session.get(BaselineRow, skill_id)
        assert baseline is not None
        assert baseline.content_hash == second_hash


class TestAdvanceBaselineOnPublish:
    """SECURITY (milestone F Task 11 follow-up C3): the drift baseline follows
    the skill's OWN approved content. A version that came through the pipeline
    - submitted, scanned, fresh signed verdict - is the intended path, not the
    "rug-pull" `orchestration/drift.py` exists to catch, so publishing it
    advances the baseline instead of tripping the drift check on it.

    The end-to-end proof that this makes a real v2 stay published (rather than
    auto-quarantining one hop later) lives in test_worker.py's
    `test_second_version_of_a_published_skill_stays_published`; these are the
    per-rule unit tests underneath it.
    """

    @staticmethod
    async def _publish_v1(
        sessionmaker: SessionmakerFixture, *, skill_id: str, content_hash: str
    ) -> None:
        """submitted -> scanning -> published, with the baseline advanced the
        way `worker.sync_lifecycle_tick` does it (inside the publish
        transaction, BEFORE the transition is recorded)."""
        async with sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="internal",
                content_hash=content_hash,
                toolchain_digest="digest-v1",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="scanning",
                reason="scan started",
                actor="tester",
                content_hash=content_hash,
            )
        async with sessionmaker() as session, session.begin():
            await advance_baseline_on_publish(
                session, skill_id=skill_id, content_hash=content_hash, actor="system:worker"
            )
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="published",
                reason="verdict PASS",
                actor="system:worker",
                content_hash=content_hash,
            )

    @pytest.mark.asyncio
    async def test_first_publish_establishes_the_baseline(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        hash_a = _content_hash()
        await self._publish_v1(inventory_sessionmaker, skill_id=skill_id, content_hash=hash_a)

        async with inventory_sessionmaker() as session:
            baseline = await session.get(BaselineRow, skill_id)
        assert baseline is not None
        assert baseline.content_hash == hash_a

    @pytest.mark.asyncio
    async def test_next_version_advances_a_baseline_that_matches_the_last_publish(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        """The C3 regression itself: v2 has a different content_hash BY
        DEFINITION, so a baseline that is never re-established makes every
        second version drift."""
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        hash_a = _content_hash()
        hash_b = _content_hash()
        await self._publish_v1(inventory_sessionmaker, skill_id=skill_id, content_hash=hash_a)

        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="internal",
                content_hash=hash_b,
                toolchain_digest="digest-v1",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="scanning",
                reason="scan started",
                actor="tester",
                content_hash=hash_b,
            )
        async with inventory_sessionmaker() as session, session.begin():
            adopted = await advance_baseline_on_publish(
                session, skill_id=skill_id, content_hash=hash_b, actor="system:worker"
            )
        assert adopted is True

        async with inventory_sessionmaker() as session:
            baseline = await session.get(BaselineRow, skill_id)
        assert baseline is not None
        assert baseline.content_hash == hash_b

    @pytest.mark.asyncio
    async def test_admin_pinned_baseline_is_left_alone(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        """SECURITY: a baseline pointing at content this skill never published
        can only have come from an admin's out-of-band `POST /v1/inventory/
        {skill_id}/baseline`. A pipeline publish must not silently overwrite
        that human statement - it declines, and the caller's drift check then
        quarantines (which is what worker.py's
        `test_drifted_content_gets_quarantined_after_publishing` asserts end
        to end)."""
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        pinned = _content_hash()
        publishing = _content_hash()
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="internal",
                content_hash=publishing,
                toolchain_digest="digest-v1",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="scanning",
                reason="scan started",
                actor="tester",
                content_hash=publishing,
            )
            await set_baseline(session, skill_id=skill_id, content_hash=pinned, actor="admin:alice")
        async with inventory_sessionmaker() as session, session.begin():
            adopted = await advance_baseline_on_publish(
                session, skill_id=skill_id, content_hash=publishing, actor="system:worker"
            )
        assert adopted is False

        async with inventory_sessionmaker() as session:
            baseline = await session.get(BaselineRow, skill_id)
        assert baseline is not None
        assert baseline.content_hash == pinned

    @pytest.mark.asyncio
    async def test_republishing_the_same_content_is_a_no_op(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        hash_a = _content_hash()
        await self._publish_v1(inventory_sessionmaker, skill_id=skill_id, content_hash=hash_a)
        async with inventory_sessionmaker() as session, session.begin():
            adopted = await advance_baseline_on_publish(
                session, skill_id=skill_id, content_hash=hash_a, actor="system:worker"
            )
        assert adopted is True

    @pytest.mark.asyncio
    async def test_an_admin_restore_does_not_break_the_next_version(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        """The C2/C3 seam. `POST /v1/inventory/{skill_id}/restore` records a
        `-> published` event with NO content_hash (like its quarantine/retire
        siblings). If that NULL were read as "the last published content", the
        very next legitimate version would fail the comparison and quarantine
        - the same one-hop-further dead end this whole fix removes."""
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        hash_a = _content_hash()
        hash_b = _content_hash()
        await self._publish_v1(inventory_sessionmaker, skill_id=skill_id, content_hash=hash_a)

        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="quarantined",
                reason="investigating",
                actor="admin:alice",
            )
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="published",
                reason="investigated, false alarm",
                actor="admin:alice",
            )

        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="internal",
                content_hash=hash_b,
                toolchain_digest="digest-v1",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="scanning",
                reason="scan started",
                actor="tester",
                content_hash=hash_b,
            )
        async with inventory_sessionmaker() as session, session.begin():
            adopted = await advance_baseline_on_publish(
                session, skill_id=skill_id, content_hash=hash_b, actor="system:worker"
            )
        assert adopted is True

        async with inventory_sessionmaker() as session:
            baseline = await session.get(BaselineRow, skill_id)
        assert baseline is not None
        assert baseline.content_hash == hash_b


class TestOwnership:
    """SECURITY (milestone F Task 11 follow-up C1): `register_skill_version` is
    the chokepoint every submission path passes through, so the AUTHORITATIVE
    ownership check lives there - inside the writing transaction - not only in
    the router.

    `gateway/router.py` also checks before it calls `submit_scan`, so an
    unauthorized caller is refused without leaving a scan behind. That
    pre-flight runs in an EARLIER, SEPARATE session, which makes it a TOCTOU
    window by construction; these tests cover the check that closes it.

    The pure-logic decision itself is exhausted in test_inventory_ownership.py,
    which needs no infrastructure.
    """

    @staticmethod
    async def _register(
        session: object,
        *,
        skill_id: str,
        operator: str,
        actor_is_admin: bool = False,
        trust_tier: str = "internal",
    ) -> None:
        await register_skill_version(
            session,  # type: ignore[arg-type]
            skill_id=skill_id,
            source="test-suite",
            trust_tier=trust_tier,
            content_hash=_content_hash(),
            toolchain_digest=f"digest-{uuid.uuid4().hex[:8]}",
            declared_perms=None,
            operator=operator,
            actor_is_admin=actor_is_admin,
        )

    @pytest.mark.asyncio
    async def test_the_first_registrant_is_recorded_as_the_owner(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await self._register(session, skill_id=skill_id, operator="alice")

        async with inventory_sessionmaker() as session:
            skill = await session.get(SkillRow, skill_id)
        assert skill is not None
        assert skill.owner == "alice"

    @pytest.mark.asyncio
    async def test_a_stranger_is_refused_before_the_lifecycle_check_runs(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # SECURITY (ordering): the skill is left in `scanning`, a state that
        # may NOT re-enter at `submitted`. An authorized caller would get
        # `InvalidTransitionError` here. A stranger must get
        # `SkillOwnershipError` instead - i.e. authorization is decided BEFORE
        # the state machine is consulted, so the error a stranger receives
        # never doubles as an oracle for the skill's lifecycle state.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await self._register(session, skill_id=skill_id, operator="alice")

        with pytest.raises(SkillOwnershipError):
            async with inventory_sessionmaker() as session, session.begin():
                await self._register(session, skill_id=skill_id, operator="mallory")

    @pytest.mark.asyncio
    async def test_a_refused_write_leaves_no_version_row_behind(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # The SkillVersionRow is added to the session BEFORE the ownership
        # check is reached, so this asserts the whole call really is one
        # transaction that rolls back - not that the check happens to run
        # first.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await self._register(session, skill_id=skill_id, operator="alice")
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session, skill_id=skill_id, to_state="scanning", reason="t", actor="system"
            )
            await transition_skill(
                session, skill_id=skill_id, to_state="published", reason="t", actor="system"
            )

        with pytest.raises(SkillOwnershipError):
            async with inventory_sessionmaker() as session, session.begin():
                await self._register(session, skill_id=skill_id, operator="mallory")

        async with inventory_sessionmaker() as session:
            versions = (
                (
                    await session.execute(
                        select(SkillVersionRow).where(SkillVersionRow.skill_id == skill_id)
                    )
                )
                .scalars()
                .all()
            )
            events = (
                (
                    await session.execute(
                        select(SkillLifecycleEventRow)
                        .where(SkillLifecycleEventRow.skill_id == skill_id)
                        .order_by(SkillLifecycleEventRow.id)
                    )
                )
                .scalars()
                .all()
            )
        assert len(versions) == 1
        assert [e.to_state for e in events] == ["submitted", "scanning", "published"]

    @pytest.mark.asyncio
    async def test_the_owner_may_register_a_second_version(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await self._register(session, skill_id=skill_id, operator="alice")
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session, skill_id=skill_id, to_state="scanning", reason="t", actor="system"
            )
            await transition_skill(
                session, skill_id=skill_id, to_state="published", reason="t", actor="system"
            )

        async with inventory_sessionmaker() as session, session.begin():
            await self._register(session, skill_id=skill_id, operator="alice")

        async with inventory_sessionmaker() as session:
            assert await current_state(session, skill_id=skill_id) == "submitted"

    @pytest.mark.asyncio
    async def test_an_admin_may_register_but_does_not_become_the_owner(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await self._register(session, skill_id=skill_id, operator="alice")
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session, skill_id=skill_id, to_state="scanning", reason="t", actor="system"
            )
            await transition_skill(
                session, skill_id=skill_id, to_state="published", reason="t", actor="system"
            )

        async with inventory_sessionmaker() as session, session.begin():
            await self._register(session, skill_id=skill_id, operator="root", actor_is_admin=True)

        async with inventory_sessionmaker() as session:
            skill = await session.get(SkillRow, skill_id)
        assert skill is not None
        assert skill.owner == "alice"

    @pytest.mark.asyncio
    async def test_a_resubmission_never_rewrites_the_recorded_trust_tier(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # Finding I2's inventory half: the skill's tier is set once, at
        # registration. `gateway/router.py` reads it back via
        # `get_registered_skill` and judges the resubmission AT it, so the two
        # can no longer disagree.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await self._register(session, skill_id=skill_id, operator="alice", trust_tier="public")
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session, skill_id=skill_id, to_state="scanning", reason="t", actor="system"
            )
            await transition_skill(
                session, skill_id=skill_id, to_state="published", reason="t", actor="system"
            )

        async with inventory_sessionmaker() as session, session.begin():
            await self._register(
                session, skill_id=skill_id, operator="alice", trust_tier="internal"
            )

        async with inventory_sessionmaker() as session:
            skill = await session.get(SkillRow, skill_id)
        assert skill is not None
        assert skill.trust_tier == "public"


class TestGetRegisteredSkill:
    @pytest.mark.asyncio
    async def test_returns_none_for_an_unregistered_skill_id(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        async with inventory_sessionmaker() as session:
            assert await get_registered_skill(session, skill_id=f"nope-{uuid.uuid4().hex}") is None

    @pytest.mark.asyncio
    async def test_returns_the_recorded_owner_and_tier(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await TestOwnership._register(
                session, skill_id=skill_id, operator="alice", trust_tier="partner"
            )

        async with inventory_sessionmaker() as session:
            registered = await get_registered_skill(session, skill_id=skill_id)
        assert registered is not None
        assert registered.owner == "alice"
        assert registered.trust_tier == "partner"


class TestAssignSkillOwner:
    """milestone F Task 15: the ONE writer that may change `skill.owner` after
    genesis, and the only reason C1's fail-closed NULL is recoverable rather
    than a permanent lockout of every pre-existing skill.

    REAL MySQL. The pure decision (`validate_owner_assignment`) is exhausted
    without infrastructure in test_inventory_ownership.py; what needs the
    database is that the UPDATE and its audit row commit together, that the
    compare-and-set is evaluated against the row actually being written, and
    that an unowned skill really does become submittable by its new owner.
    """

    @pytest.mark.asyncio
    async def test_assigns_an_owner_to_an_unowned_legacy_skill(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # The ~481-row case: a skill whose `owner` is NULL because it was
        # registered before the column existed. Simulated by clearing the
        # column directly, which is exactly what those rows look like.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await TestOwnership._register(session, skill_id=skill_id, operator="alice")
            skill = await session.get(SkillRow, skill_id)
            assert skill is not None
            skill.owner = None

        async with inventory_sessionmaker() as session, session.begin():
            previous = await assign_skill_owner(
                session,
                skill_id=skill_id,
                new_owner="alice",
                reason="verified against the genesis actor",
                actor="admin-root",
                expect_unowned=True,
            )
        assert previous is None

        async with inventory_sessionmaker() as session:
            skill = await session.get(SkillRow, skill_id)
        assert skill is not None
        assert skill.owner == "alice"

    @pytest.mark.asyncio
    async def test_the_newly_assigned_owner_can_now_submit_a_new_version(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # THE POINT OF THE WHOLE TASK, asserted end to end at the service
        # layer: before the assignment the skill is admin-only (C1's
        # fail-closed NULL); after it, its owner ships a v2 like any other.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await TestOwnership._register(session, skill_id=skill_id, operator="alice")
            skill = await session.get(SkillRow, skill_id)
            assert skill is not None
            skill.owner = None
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session, skill_id=skill_id, to_state="scanning", reason="t", actor="system"
            )
            await transition_skill(
                session, skill_id=skill_id, to_state="published", reason="t", actor="system"
            )

        with pytest.raises(SkillOwnershipError):
            async with inventory_sessionmaker() as session, session.begin():
                await TestOwnership._register(session, skill_id=skill_id, operator="alice")

        async with inventory_sessionmaker() as session, session.begin():
            await assign_skill_owner(
                session,
                skill_id=skill_id,
                new_owner="alice",
                reason="legacy row, assigned by an admin",
                actor="admin-root",
                expect_unowned=True,
            )

        async with inventory_sessionmaker() as session, session.begin():
            await TestOwnership._register(session, skill_id=skill_id, operator="alice")

        async with inventory_sessionmaker() as session:
            assert await current_state(session, skill_id=skill_id) == "submitted"

    @pytest.mark.asyncio
    async def test_a_transfer_moves_the_skill_and_reports_the_previous_owner(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # The departing-owner case. Without this, every skill in a leaver's
        # name is stranded forever.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await TestOwnership._register(session, skill_id=skill_id, operator="alice")

        async with inventory_sessionmaker() as session, session.begin():
            previous = await assign_skill_owner(
                session,
                skill_id=skill_id,
                new_owner="bob",
                reason="alice left the team",
                actor="admin-root",
                expect_unowned=False,
            )
        assert previous == "alice"

        async with inventory_sessionmaker() as session:
            skill = await session.get(SkillRow, skill_id)
        assert skill is not None
        assert skill.owner == "bob"

    @pytest.mark.asyncio
    async def test_the_compare_and_set_refuses_to_overwrite_an_existing_owner(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # An admin working the unowned worklist is acting on a list read some
        # time ago. A row that acquired an owner in between must conflict, not
        # be silently taken from them.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await TestOwnership._register(session, skill_id=skill_id, operator="alice")

        with pytest.raises(OwnerAssignmentConflictError):
            async with inventory_sessionmaker() as session, session.begin():
                await assign_skill_owner(
                    session,
                    skill_id=skill_id,
                    new_owner="mallory",
                    reason="stale worklist",
                    actor="admin-root",
                    expect_unowned=True,
                )

        async with inventory_sessionmaker() as session:
            skill = await session.get(SkillRow, skill_id)
        assert skill is not None
        assert skill.owner == "alice"

    @pytest.mark.asyncio
    async def test_an_unregistered_skill_id_raises_value_error_not_a_silent_insert(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # The router turns this into a 404. It must never create the row: an
        # endpoint that conjures a skill nobody submitted would let an admin
        # pre-register (and therefore own) any skill_id they can type.
        skill_id = f"never-registered-{uuid.uuid4().hex[:12]}"
        with pytest.raises(ValueError):
            async with inventory_sessionmaker() as session, session.begin():
                await assign_skill_owner(
                    session,
                    skill_id=skill_id,
                    new_owner="alice",
                    reason="typo",
                    actor="admin-root",
                    expect_unowned=True,
                )

        async with inventory_sessionmaker() as session:
            assert await session.get(SkillRow, skill_id) is None

    @pytest.mark.asyncio
    async def test_the_assignment_and_its_audit_intent_commit_together(
        self, inventory_sessionmaker: SessionmakerFixture, audit_sessionmaker: SessionmakerFixture
    ) -> None:
        # INV-12, the same one-transaction rule every other writer in this
        # module follows. A privilege change whose audit record can be missing
        # is not an audited privilege change.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await TestOwnership._register(session, skill_id=skill_id, operator="alice")

        async with inventory_sessionmaker() as session, session.begin():
            await assign_skill_owner(
                session,
                skill_id=skill_id,
                new_owner="bob",
                reason="alice left the team",
                actor="admin-root",
                expect_unowned=False,
            )

        async with audit_sessionmaker() as session:
            rows = (
                (
                    await session.execute(
                        select(AuditIntent).where(AuditIntent.action == "skill_owner_assigned")
                    )
                )
                .scalars()
                .all()
            )
        matching = [r for r in rows if r.payload.get("skill_id") == skill_id]
        assert len(matching) == 1
        entry = matching[0]
        assert entry.operator == "admin-root"
        # THE PREVIOUS OWNER IS THE RECORD. "bob owns it" answers nothing after
        # the fact; "it was alice's, admin-root moved it to bob, for this
        # reason" is what makes the change reviewable.
        assert entry.payload["previous_owner"] == "alice"
        assert entry.payload["new_owner"] == "bob"
        assert entry.payload["reason"] == "alice left the team"

    @pytest.mark.asyncio
    async def test_a_refused_assignment_writes_no_audit_row(
        self, inventory_sessionmaker: SessionmakerFixture, audit_sessionmaker: SessionmakerFixture
    ) -> None:
        # The other half of one-transaction: a conflict must leave NOTHING
        # behind. An audit trail that records attempts as if they were changes
        # would make "who was given authority over this" unanswerable.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await TestOwnership._register(session, skill_id=skill_id, operator="alice")

        with pytest.raises(OwnerAssignmentConflictError):
            async with inventory_sessionmaker() as session, session.begin():
                await assign_skill_owner(
                    session,
                    skill_id=skill_id,
                    new_owner="mallory",
                    reason="stale worklist",
                    actor="admin-root",
                    expect_unowned=True,
                )

        async with audit_sessionmaker() as session:
            rows = (
                (
                    await session.execute(
                        select(AuditIntent).where(AuditIntent.action == "skill_owner_assigned")
                    )
                )
                .scalars()
                .all()
            )
        assert [r for r in rows if r.payload.get("skill_id") == skill_id] == []

    @pytest.mark.asyncio
    async def test_the_stored_owner_is_stripped(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # `authorize_skill_write` compares the stored owner to `session.subject`
        # verbatim, so a stray space stored here is a permanent lockout that
        # looks like a successful assignment.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await TestOwnership._register(session, skill_id=skill_id, operator="alice")
            skill = await session.get(SkillRow, skill_id)
            assert skill is not None
            skill.owner = None

        async with inventory_sessionmaker() as session, session.begin():
            await assign_skill_owner(
                session,
                skill_id=skill_id,
                new_owner="  alice  ",
                reason="pasted from the directory",
                actor="admin-root",
                expect_unowned=True,
            )

        async with inventory_sessionmaker() as session:
            skill = await session.get(SkillRow, skill_id)
        assert skill is not None
        assert skill.owner == "alice"


class TestUnownedWorklist:
    """The read side of Task 15: which skills are stranded, and what evidence
    an admin gets to see about each one."""

    @staticmethod
    async def _register_unowned(session: object, *, skill_id: str, genesis_actor: str) -> None:
        """A pre-`skill.owner` row: registered normally, then the column
        cleared - which is exactly the shape of the rows that predate the
        migration, genesis lifecycle event and all."""
        await TestOwnership._register(session, skill_id=skill_id, operator=genesis_actor)
        skill = await session.get(SkillRow, skill_id)  # type: ignore[attr-defined]
        assert skill is not None
        skill.owner = None

    @pytest.mark.asyncio
    async def test_lists_only_unowned_skills(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        unowned_id = f"skill-{uuid.uuid4().hex[:12]}"
        owned_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await self._register_unowned(session, skill_id=unowned_id, genesis_actor="alice")
            await TestOwnership._register(session, skill_id=owned_id, operator="bob")

        async with inventory_sessionmaker() as session:
            rows = await list_unowned_skills(session, limit=500, offset=0)
        listed = {row.skill_id for row in rows}
        assert unowned_id in listed
        assert owned_id not in listed

    @pytest.mark.asyncio
    async def test_carries_the_genesis_actor_as_evidence(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # ADVISORY ONLY. It is shown to an admin so the assignment is an
        # informed decision; nothing writes it to `skill.owner`. The
        # source-level guard against that is in test_inventory_ownership.py's
        # TestOnlyOneWriterOfOwner.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await self._register_unowned(session, skill_id=skill_id, genesis_actor="alice")

        async with inventory_sessionmaker() as session:
            rows = await list_unowned_skills(session, limit=500, offset=0)
        row = next(r for r in rows if r.skill_id == skill_id)
        assert row.genesis_actor == "alice"
        # Still unowned - reading the evidence changes nothing.
        async with inventory_sessionmaker() as session:
            skill = await session.get(SkillRow, skill_id)
        assert skill is not None
        assert skill.owner is None

    @pytest.mark.asyncio
    async def test_the_genesis_actor_is_the_first_event_not_the_latest(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # "Who registered this" must not drift to "who last touched it" - a
        # later transition by `system` or by an admin would otherwise present
        # itself as the evidence an assignment is based on.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await self._register_unowned(session, skill_id=skill_id, genesis_actor="alice")
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session, skill_id=skill_id, to_state="scanning", reason="t", actor="worker-system"
            )

        async with inventory_sessionmaker() as session:
            actors = await genesis_actors(session, skill_ids=[skill_id])
        assert actors[skill_id] == "alice"

    @pytest.mark.asyncio
    async def test_a_skill_with_no_lifecycle_events_reports_no_genesis_actor(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # Absence, never a guess. A row with no genesis event has no evidence
        # to offer, and inventing one would be worse than saying so.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            session.add(
                SkillRow(
                    skill_id=skill_id,
                    source="test-suite",
                    trust_tier="internal",
                    scope=None,
                    owner=None,
                    created_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                )
            )

        async with inventory_sessionmaker() as session:
            rows = await list_unowned_skills(session, limit=500, offset=0)
        row = next(r for r in rows if r.skill_id == skill_id)
        assert row.genesis_actor is None
        assert row.state is None

    @pytest.mark.asyncio
    async def test_reports_the_lifecycle_state_of_each_unowned_skill(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await self._register_unowned(session, skill_id=skill_id, genesis_actor="alice")
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session, skill_id=skill_id, to_state="scanning", reason="t", actor="system"
            )
            await transition_skill(
                session, skill_id=skill_id, to_state="published", reason="t", actor="system"
            )

        async with inventory_sessionmaker() as session:
            rows = await list_unowned_skills(session, limit=500, offset=0)
        row = next(r for r in rows if r.skill_id == skill_id)
        assert row.state == "published"

    @pytest.mark.asyncio
    async def test_the_count_covers_every_unowned_skill_not_just_the_page(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # An admin needs the size of the job before starting it. A page of N
        # that says nothing about the rest reads as "that is all of them" -
        # with ~481 stranded rows that is the difference between a plan and a
        # surprise.
        ids = [f"skill-{uuid.uuid4().hex[:12]}" for _ in range(3)]
        async with inventory_sessionmaker() as session, session.begin():
            before = await count_unowned_skills(session)
            for skill_id in ids:
                await self._register_unowned(session, skill_id=skill_id, genesis_actor="alice")

        async with inventory_sessionmaker() as session:
            after = await count_unowned_skills(session)
            page = await list_unowned_skills(session, limit=1, offset=0)
        assert after == before + 3
        assert len(page) == 1

    @pytest.mark.asyncio
    async def test_paging_is_stable_and_does_not_skip_or_repeat_a_row(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # Rows created in the same second are why the ORDER BY carries a
        # skill_id tiebreak: without a TOTAL order, two page requests can
        # return the same row twice and never show another one at all.
        ids = [f"skill-{uuid.uuid4().hex[:12]}" for _ in range(4)]
        async with inventory_sessionmaker() as session, session.begin():
            for skill_id in ids:
                await self._register_unowned(session, skill_id=skill_id, genesis_actor="alice")

        async with inventory_sessionmaker() as session:
            total = await count_unowned_skills(session)
            walked: list[str] = []
            for offset in range(0, total, 2):
                page = await list_unowned_skills(session, limit=2, offset=offset)
                walked.extend(row.skill_id for row in page)
        assert len(walked) == len(set(walked))
        assert set(ids).issubset(set(walked))

    @pytest.mark.asyncio
    async def test_an_assigned_skill_leaves_the_worklist(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        async with inventory_sessionmaker() as session, session.begin():
            await self._register_unowned(session, skill_id=skill_id, genesis_actor="alice")

        async with inventory_sessionmaker() as session, session.begin():
            await assign_skill_owner(
                session,
                skill_id=skill_id,
                new_owner="alice",
                reason="assigned",
                actor="admin-root",
                expect_unowned=True,
            )

        async with inventory_sessionmaker() as session:
            rows = await list_unowned_skills(session, limit=500, offset=0)
        assert skill_id not in {row.skill_id for row in rows}
