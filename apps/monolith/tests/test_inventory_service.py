"""Tests for `inventory.service` (coding spec §16.2, FR-INV, INV-12) against
the real local MySQL instance - `svc_inventory` genuinely owns skill/
skill_version/baseline/skill_lifecycle_event (ALL privilege) plus an
INSERT-only view onto audit_intent, mirroring gate.service's own pattern.
"""

from __future__ import annotations

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
from monolith.modules.inventory.service import (
    current_state,
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
        # wrong. There is no `X -> submitted` edge for ANY real state in
        # VALID_TRANSITIONS (only `None -> submitted` is legal) - so this
        # must now be rejected fail-closed via validate_transition(), not
        # silently faked. Confirms neither the SkillVersionRow write nor a
        # second lifecycle event survive (the whole call is one transaction).
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
        # rejected fail-closed instead: `scanning` has no valid transition
        # to `submitted` either (VALID_TRANSITIONS["scanning"] only allows
        # published/review_pending/retired).
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
                )

        async with inventory_sessionmaker() as session:
            state = await current_state(session, skill_id=skill_id)
        # Unchanged - the rejected call must not have moved, faked, or
        # otherwise disturbed the skill's real current state.
        assert state == "scanning"

    @pytest.mark.asyncio
    async def test_second_version_for_a_published_skill_is_rejected_not_faked(
        self, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # SECURITY (regression, was BUG - this is the scenario the bug report
        # named explicitly): a skill_id already `published` receiving new
        # content must NEVER get a fabricated `None->submitted` genesis event
        # - that fabrication is exactly what let a published skill's state
        # machine be bypassed (the router's very next `transition_skill(
        # to_state="scanning")` call would read the FAKE "submitted" state as
        # legitimate and sail through submitted->scanning, even though
        # VALID_TRANSITIONS["published"] does not permit "scanning" at all).
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
            )
        for to_state, actor in [
            ("scanning", "system:orchestration"),
            ("published", "system:gate"),
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
                    operator="attacker-or-confused-publisher",
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
        # Still published - no fake genesis event snuck in, no second
        # None->submitted row, history is exactly the real 3 events.
        assert state == "published"
        assert [e.to_state for e in events] == ["submitted", "scanning", "published"]
        assert sum(1 for e in events if e.from_state is None) == 1

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
