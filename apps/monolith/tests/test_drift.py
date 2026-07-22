"""Tests for `orchestration.drift` (coding spec §11.4 SUP-05) against the real
local MySQL instance - reading `baseline` via orchestration's SELECT-only
cross-module grant (policies/grants/manifest.yaml)."""

from __future__ import annotations

import datetime
import uuid

import pymysql
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from monolith.modules.orchestration.drift import check_drift, is_drift
from monolith.tests.conftest import SessionmakerFixture


async def _seed_baseline(
    orchestration_sessionmaker: SessionmakerFixture, *, skill_id: str, content_hash: str
) -> None:
    # NOTE: svc_orchestration only has SELECT on baseline (by design - see
    # BaselineReadOnly's docstring), so seeding test data via that session
    # would be rejected too. Use root/admin instead, matching how
    # migrations/setup_grants.py already operate with elevated access for
    # setup, not app-layer code.
    conn = pymysql.connect(host="localhost", user="root", database="skillscan")
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO baseline (skill_id, content_hash, approved_at) VALUES (%s, %s, %s)",
                (skill_id, content_hash, datetime.datetime.now(datetime.UTC).replace(tzinfo=None)),
            )
        conn.commit()
    finally:
        conn.close()


class TestIsDriftPure:
    def test_no_baseline_is_not_drift(self) -> None:
        assert is_drift(None, "a" * 64) is False

    def test_matching_hash_is_not_drift(self) -> None:
        assert is_drift("a" * 64, "a" * 64) is False

    def test_different_hash_is_drift(self) -> None:
        assert is_drift("a" * 64, "b" * 64) is True


class TestCheckDriftAgainstRealBaseline:
    @pytest.mark.asyncio
    async def test_no_baseline_yet_reports_not_drifted(
        self, orchestration_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"test-skill-{uuid.uuid4().hex[:12]}"
        async with orchestration_sessionmaker() as session:
            result = await check_drift(session, skill_id=skill_id, content_hash="a" * 64)
        assert result.has_baseline is False
        assert result.drifted is False

    @pytest.mark.asyncio
    async def test_matching_content_hash_is_not_drift(
        self, orchestration_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"test-skill-{uuid.uuid4().hex[:12]}"
        content_hash = "c" * 64
        await _seed_baseline(
            orchestration_sessionmaker, skill_id=skill_id, content_hash=content_hash
        )

        async with orchestration_sessionmaker() as session:
            result = await check_drift(session, skill_id=skill_id, content_hash=content_hash)
        assert result.has_baseline is True
        assert result.drifted is False

    @pytest.mark.asyncio
    async def test_different_content_hash_is_drift(
        self, orchestration_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"test-skill-{uuid.uuid4().hex[:12]}"
        await _seed_baseline(orchestration_sessionmaker, skill_id=skill_id, content_hash="d" * 64)

        async with orchestration_sessionmaker() as session:
            result = await check_drift(session, skill_id=skill_id, content_hash="e" * 64)
        assert result.has_baseline is True
        assert result.drifted is True
        assert result.baseline_content_hash == "d" * 64

    @pytest.mark.asyncio
    async def test_orchestration_session_cannot_write_baseline(
        self, orchestration_sessionmaker: SessionmakerFixture
    ) -> None:
        """SECURITY: SELECT-only grant, positive-and-negative control in one -
        proves the read path works (above) AND that orchestration genuinely
        cannot write this cross-module table, matching gate's INSERT-only
        view onto audit_intent."""
        async with orchestration_sessionmaker() as session, session.begin():
            with pytest.raises(DBAPIError, match=r"(?i)command denied"):
                await session.execute(
                    text(
                        "INSERT INTO baseline (skill_id, content_hash, approved_at) "
                        "VALUES (:sid, :ch, NOW())"
                    ),
                    {"sid": f"attacker-{uuid.uuid4().hex[:8]}", "ch": "f" * 64},
                )
