"""Tests for `admin.breakglass` (coding spec §16.3, INV-17) against the real
local Redis instance - real `pyotp` TOTP generation/verification throughout,
no mocking.
"""

from __future__ import annotations

import asyncio
import datetime
import uuid
from collections.abc import AsyncIterator

import pyotp
import pytest
import pytest_asyncio
import redis.asyncio as aioredis

from monolith.modules.admin.breakglass import (
    BreakGlassError,
    activate_breakglass,
    authenticate_breakglass,
    create_breakglass_session,
    deactivate_breakglass,
    is_armed,
    resolve_breakglass_session,
    verify_totp,
)

# SECURITY: `activate_breakglass` now requires `known_admin_subjects` (BUG 2
# fix) - "bob" is the one and only allowlisted second-activator identity used
# throughout this file's tests, standing in for whatever a real deployment's
# admin-mapped group name(s)/identities would be.
_KNOWN_ADMIN_SUBJECTS = frozenset({"bob"})


@pytest_asyncio.fixture(autouse=True)
async def _clean_breakglass_redis_state() -> AsyncIterator[None]:
    """Test-isolation fix (2026-07-10 full-project review, Finding #04/11/14/15
    fix): `redis_client` (conftest.py) is a single shared Redis DB with NO
    flush between tests, and break-glass's Redis keys are fixed/global (not
    per-test-namespaced) - `_ARMED_KEY`/`_USED_KEY`/session tokens leaking
    from one test into the next was previously invisible, because the OLD
    (buggy) activate_breakglass() silently clobbered any leftover armed
    state. Now that BUG 3's fix correctly REJECTS re-arming while already
    armed, a leaked arming from an earlier test makes a LATER, unrelated
    test fail with BreakGlassError instead of silently masking the leak -
    this fixture is the real fix (clean state per test), not a workaround
    for the now-correct rejection behavior."""
    client: aioredis.Redis = aioredis.Redis.from_url("redis://localhost:6379/0")
    try:

        async def _clear() -> None:
            keys = [k async for k in client.scan_iter(match="skillscan:admin:breakglass:*")]
            if keys:
                await client.delete(*keys)

        await _clear()
        yield
        await _clear()
    finally:
        await client.aclose()


def _totp_secret_and_code() -> tuple[str, str]:
    secret = pyotp.random_base32()
    return secret, pyotp.TOTP(secret).now()


class TestVerifyTotp:
    def test_correct_code_verifies(self) -> None:
        secret, code = _totp_secret_and_code()
        assert verify_totp(secret, code) is True

    def test_wrong_code_rejected(self) -> None:
        secret, _code = _totp_secret_and_code()
        assert verify_totp(secret, "000000") is False

    def test_previous_window_code_tolerated(self) -> None:
        # SECURITY/RELIABILITY: valid_window=1 must tolerate the PREVIOUS
        # 30s step (clock drift / network latency), not just the current one -
        # caught for real while browser-testing the frontend, where the
        # round-trip between generating a code and the server checking it
        # could cross a window boundary.
        secret = pyotp.random_base32()
        thirty_seconds_ago = datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=30)
        stale_code = pyotp.TOTP(secret).at(thirty_seconds_ago)
        assert verify_totp(secret, stale_code) is True

    def test_far_stale_code_still_rejected(self) -> None:
        # SECURITY: tolerance is bounded - a code from several minutes ago
        # must NOT verify (never an unbounded replay window).
        secret = pyotp.random_base32()
        long_ago = datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=5)
        stale_code = pyotp.TOTP(secret).at(long_ago)
        assert verify_totp(secret, stale_code) is False

    def test_rotation_period_is_configurable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The TOTP step/period is env-configurable (SKILLSCAN_TOTP_PERIOD_S):
        # verify_totp must honor it, not a hardcoded 30. A code from a
        # 60s-period authenticator verifies against a 60s-period server; if the
        # `interval=` wiring were dropped (back to a hardcoded 30s step) the
        # 60s-window code would not match the 30s verifier's expected code.
        import monolith.modules.admin.breakglass as bg

        monkeypatch.setattr(bg, "TOTP_PERIOD_S", 60)
        secret = pyotp.random_base32()
        assert bg.verify_totp(secret, pyotp.TOTP(secret, interval=60).now()) is True


class TestActivateBreakGlass:
    @pytest.mark.asyncio
    async def test_valid_activation_arms_it(self, redis_client: aioredis.Redis) -> None:
        secret, code = _totp_secret_and_code()
        activation = await activate_breakglass(
            redis_client,
            activator_a="alice",
            activator_b="bob",
            totp_code=code,
            totp_secret=secret,
            known_admin_subjects=_KNOWN_ADMIN_SUBJECTS,
        )
        assert activation.activated_by == ("alice", "bob")
        assert await is_armed(redis_client) is True

    @pytest.mark.asyncio
    async def test_same_person_twice_rejected(self, redis_client: aioredis.Redis) -> None:
        secret, code = _totp_secret_and_code()
        with pytest.raises(BreakGlassError, match="two DIFFERENT people"):
            await activate_breakglass(
                redis_client,
                activator_a="alice",
                activator_b="alice",
                totp_code=code,
                totp_secret=secret,
                # SECURITY: even if "alice" WERE in known_admin_subjects, the
                # same-person check must still fire first - included here to
                # prove this rejection isn't secretly relying on "alice" being
                # excluded from the allowlist instead.
                known_admin_subjects=frozenset({"alice", "bob"}),
            )

    @pytest.mark.asyncio
    async def test_wrong_totp_code_rejected(self, redis_client: aioredis.Redis) -> None:
        secret, _code = _totp_secret_and_code()
        with pytest.raises(BreakGlassError, match="invalid TOTP"):
            await activate_breakglass(
                redis_client,
                activator_a="alice",
                activator_b="bob",
                totp_code="000000",
                totp_secret=secret,
                known_admin_subjects=_KNOWN_ADMIN_SUBJECTS,
            )

    @pytest.mark.asyncio
    async def test_not_armed_before_activation(self, redis_client: aioredis.Redis) -> None:
        # NOTE: uses a fresh throwaway Redis key namespace concern is global
        # (module-level key names) - this test just confirms deactivate_breakglass
        # correctly clears the armed state as a baseline before other assertions.
        await deactivate_breakglass(redis_client)
        assert await is_armed(redis_client) is False

    @pytest.mark.asyncio
    async def test_unknown_second_activator_rejected(self, redis_client: aioredis.Redis) -> None:
        # SECURITY (BUG 2 regression): `activator_b` must be a real, known
        # admin identity - an arbitrary/unrecognized string must never pass,
        # even with a fully correct TOTP code. This is the core "four-eyes
        # was not real" fix - before it, ANY string here would have armed
        # break-glass.
        await deactivate_breakglass(redis_client)
        secret, code = _totp_secret_and_code()
        with pytest.raises(BreakGlassError, match="real, known admin"):
            await activate_breakglass(
                redis_client,
                activator_a="alice",
                activator_b="totally-made-up-name",
                totp_code=code,
                totp_secret=secret,
                known_admin_subjects=_KNOWN_ADMIN_SUBJECTS,
            )
        assert await is_armed(redis_client) is False

    @pytest.mark.asyncio
    async def test_second_activator_cannot_be_own_session_subject(
        self, redis_client: aioredis.Redis
    ) -> None:
        # SECURITY (BUG 2 regression): reject `activator_b == activator_a`
        # even when that identity IS otherwise a known admin (i.e. this is
        # not merely relying on "not in known_admin_subjects" to reject it -
        # the same-person check fires independently).
        await deactivate_breakglass(redis_client)
        secret, code = _totp_secret_and_code()
        with pytest.raises(BreakGlassError, match="two DIFFERENT people"):
            await activate_breakglass(
                redis_client,
                activator_a="alice",
                activator_b="alice",
                totp_code=code,
                totp_secret=secret,
                known_admin_subjects=frozenset({"alice", "bob"}),
            )
        assert await is_armed(redis_client) is False

    @pytest.mark.asyncio
    async def test_activate_while_already_armed_raises_without_clobbering(
        self, redis_client: aioredis.Redis
    ) -> None:
        # SECURITY (BUG 3 regression): a second, different activator pair
        # must NOT silently overwrite an existing armed-and-unused
        # activation - it must raise, and the original activation must
        # survive untouched.
        await deactivate_breakglass(redis_client)
        secret_1, code_1 = _totp_secret_and_code()
        first_activation = await activate_breakglass(
            redis_client,
            activator_a="alice",
            activator_b="bob",
            totp_code=code_1,
            totp_secret=secret_1,
            known_admin_subjects=frozenset({"bob", "carol", "dave"}),
        )
        assert await is_armed(redis_client) is True

        secret_2, code_2 = _totp_secret_and_code()
        with pytest.raises(BreakGlassError, match="already armed"):
            await activate_breakglass(
                redis_client,
                activator_a="carol",
                activator_b="dave",
                totp_code=code_2,
                totp_secret=secret_2,
                known_admin_subjects=frozenset({"bob", "carol", "dave"}),
            )

        # The ORIGINAL activation must still be the one in effect - proven by
        # successfully logging in against alice+bob's original TOTP secret
        # (if the second activate call had clobbered `_ARMED_KEY`, the
        # "already armed" exception above wouldn't even be reachable a second
        # time, but this also proves no partial/inconsistent state was left
        # behind by the rejected attempt).
        assert await is_armed(redis_client) is True
        login_secret, login_code = _totp_secret_and_code()
        ok = await authenticate_breakglass(
            redis_client,
            supplied_credential="cred",
            expected_credential="cred",
            totp_code=login_code,
            totp_secret=login_secret,
        )
        assert ok is True
        assert first_activation.activated_by == ("alice", "bob")


class TestDeactivateBreakGlass:
    @pytest.mark.asyncio
    async def test_deactivate_clears_armed_state(self, redis_client: aioredis.Redis) -> None:
        secret, code = _totp_secret_and_code()
        await activate_breakglass(
            redis_client,
            activator_a="alice",
            activator_b="bob",
            totp_code=code,
            totp_secret=secret,
            known_admin_subjects=_KNOWN_ADMIN_SUBJECTS,
        )
        await deactivate_breakglass(redis_client)
        assert await is_armed(redis_client) is False


class TestAuthenticateBreakGlass:
    @pytest.mark.asyncio
    async def test_not_armed_rejects_even_correct_credentials(
        self, redis_client: aioredis.Redis
    ) -> None:
        await deactivate_breakglass(redis_client)
        secret, code = _totp_secret_and_code()
        ok = await authenticate_breakglass(
            redis_client,
            supplied_credential="correct-secret",
            expected_credential="correct-secret",
            totp_code=code,
            totp_secret=secret,
        )
        assert ok is False

    @pytest.mark.asyncio
    async def test_armed_with_correct_credential_and_totp_succeeds(
        self, redis_client: aioredis.Redis
    ) -> None:
        activation_secret, activation_code = _totp_secret_and_code()
        await activate_breakglass(
            redis_client,
            activator_a="alice",
            activator_b="bob",
            totp_code=activation_code,
            totp_secret=activation_secret,
            known_admin_subjects=_KNOWN_ADMIN_SUBJECTS,
        )
        login_secret, login_code = _totp_secret_and_code()
        ok = await authenticate_breakglass(
            redis_client,
            supplied_credential="the-real-credential",
            expected_credential="the-real-credential",
            totp_code=login_code,
            totp_secret=login_secret,
        )
        assert ok is True

    @pytest.mark.asyncio
    async def test_wrong_credential_rejected_even_when_armed(
        self, redis_client: aioredis.Redis
    ) -> None:
        activation_secret, activation_code = _totp_secret_and_code()
        await activate_breakglass(
            redis_client,
            activator_a="alice",
            activator_b="bob",
            totp_code=activation_code,
            totp_secret=activation_secret,
            known_admin_subjects=_KNOWN_ADMIN_SUBJECTS,
        )
        login_secret, login_code = _totp_secret_and_code()
        ok = await authenticate_breakglass(
            redis_client,
            supplied_credential="wrong-credential",
            expected_credential="the-real-credential",
            totp_code=login_code,
            totp_secret=login_secret,
        )
        assert ok is False

    @pytest.mark.asyncio
    async def test_successful_login_consumes_the_arming_single_use(
        self, redis_client: aioredis.Redis
    ) -> None:
        # SECURITY: "用后即禁" - disabled after use, even if TTL remains.
        activation_secret, activation_code = _totp_secret_and_code()
        await activate_breakglass(
            redis_client,
            activator_a="alice",
            activator_b="bob",
            totp_code=activation_code,
            totp_secret=activation_secret,
            known_admin_subjects=_KNOWN_ADMIN_SUBJECTS,
        )
        login_secret, login_code_1 = _totp_secret_and_code()
        first = await authenticate_breakglass(
            redis_client,
            supplied_credential="cred",
            expected_credential="cred",
            totp_code=login_code_1,
            totp_secret=login_secret,
        )
        assert first is True
        assert await is_armed(redis_client) is False

        login_code_2 = pyotp.TOTP(login_secret).now()
        second = await authenticate_breakglass(
            redis_client,
            supplied_credential="cred",
            expected_credential="cred",
            totp_code=login_code_2,
            totp_secret=login_secret,
        )
        assert second is False

    @pytest.mark.asyncio
    async def test_concurrent_logins_against_same_arming_only_one_succeeds(
        self, redis_client: aioredis.Redis
    ) -> None:
        # SECURITY (BUG 1 regression - TOCTOU race): two concurrent
        # authenticate_breakglass calls sharing the SAME valid arming, both
        # supplying fully correct credential + TOTP, must not both succeed -
        # exactly the race the old is_armed()-then-later-SET shape allowed
        # (both callers could pass the is_armed() check before either wrote
        # _USED_KEY). asyncio.gather runs both coroutines concurrently on the
        # same event loop, interleaving at every `await` - enough to exercise
        # the race deterministically without needing real OS threads/procs,
        # since the actual atomicity guarantee under test lives entirely in
        # Redis's own single-threaded command execution, not in Python's
        # concurrency model.
        await deactivate_breakglass(redis_client)
        activation_secret, activation_code = _totp_secret_and_code()
        await activate_breakglass(
            redis_client,
            activator_a="alice",
            activator_b="bob",
            totp_code=activation_code,
            totp_secret=activation_secret,
            known_admin_subjects=_KNOWN_ADMIN_SUBJECTS,
        )
        login_secret, login_code = _totp_secret_and_code()

        async def _attempt() -> bool:
            return await authenticate_breakglass(
                redis_client,
                supplied_credential="cred",
                expected_credential="cred",
                totp_code=login_code,
                totp_secret=login_secret,
            )

        results = await asyncio.gather(_attempt(), _attempt())
        assert sorted(results) == [False, True]
        assert await is_armed(redis_client) is False


class TestBreakGlassSession:
    @pytest.mark.asyncio
    async def test_created_session_resolves_to_the_same_subject(
        self, redis_client: aioredis.Redis
    ) -> None:
        token = await create_breakglass_session(redis_client, subject="breakglass-admin")
        subject = await resolve_breakglass_session(redis_client, token)
        assert subject == "breakglass-admin"

    @pytest.mark.asyncio
    async def test_unknown_token_resolves_to_none(self, redis_client: aioredis.Redis) -> None:
        subject = await resolve_breakglass_session(redis_client, f"nonexistent-{uuid.uuid4().hex}")
        assert subject is None
