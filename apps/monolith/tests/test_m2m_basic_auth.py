"""Tests for `gateway.auth.m2m.authenticate_basic_service_account` against the
real local Redis instance - no mocking, mirrors test_local_auth.py's structure
and isolation-fixture pattern.

2026-07-31: a username/password path for machine callers, added so a
marketplace can reach `/v1/market` in a deployment that has no IdP to
introspect against. It is deliberately the WEAKEST of the three M2M paths (see
m2m.py's own docstring) and every test here exists to pin down a property that
keeps it from being weaker still.
"""

from __future__ import annotations

import base64
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from common.password import hash_password
from skillscan_core import TrustTier

from monolith.modules.gateway.auth.m2m import (
    M2MError,
    M2MGrant,
    authenticate_basic_service_account,
)

_PASSWORD = "correct horse battery staple"
_ACCOUNT = "marketplace-svc"


def _header(username: str, password: str) -> str:
    raw = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {raw}"


def _accounts() -> dict[str, str]:
    return {_ACCOUNT: hash_password(_PASSWORD)}


@pytest_asyncio.fixture(autouse=True)
async def _clean_m2m_basic_redis_state() -> AsyncIterator[None]:
    """Same rationale as test_local_auth.py's analogous fixture: the fail
    counters are keyed per service account, not per test, and `redis_client`
    is a single shared DB with no flush between tests."""
    client: aioredis.Redis = aioredis.Redis.from_url("redis://localhost:6379/0")
    try:

        async def _clear() -> None:
            keys = [k async for k in client.scan_iter(match="skillscan:m2m:basic:*")]
            if keys:
                await client.delete(*keys)

        await _clear()
        yield
        await _clear()
    finally:
        await client.aclose()


class TestAuthenticateBasicServiceAccount:
    @pytest.mark.asyncio
    async def test_valid_credentials_return_a_machine_session(
        self, redis_client: aioredis.Redis
    ) -> None:
        session = await authenticate_basic_service_account(
            _header(_ACCOUNT, _PASSWORD),
            redis=redis_client,
            accounts=_accounts(),
            allowed_service_accounts=frozenset({_ACCOUNT}),
            grants={},
        )
        assert session.subject == _ACCOUNT
        # SECURITY: the whole point of `is_machine` - the console surface
        # (`require_human_role`) refuses this identity, so a password-authenticated
        # marketplace cannot read the raw internal scan shape that
        # `marketplace_api.views` exists to withhold.
        assert session.is_machine is True

    @pytest.mark.asyncio
    async def test_scopes_and_tier_come_from_the_grant(self, redis_client: aioredis.Redis) -> None:
        """Authentication says WHO; the existing per-account grant says WHAT.

        Sharing `M2MGrant` with the client-credentials path is what stops this
        surface from growing its own parallel authorization model.
        """
        session = await authenticate_basic_service_account(
            _header(_ACCOUNT, _PASSWORD),
            redis=redis_client,
            accounts=_accounts(),
            allowed_service_accounts=frozenset({_ACCOUNT}),
            grants={
                _ACCOUNT: M2MGrant(
                    scopes=frozenset({"scan:submit", "scan:read"}), tier=TrustTier.PUBLIC
                )
            },
        )
        assert session.scopes == frozenset({"scan:submit", "scan:read"})
        assert session.tier is TrustTier.PUBLIC

    @pytest.mark.asyncio
    async def test_unconfigured_account_falls_back_to_the_strictest_default_grant(
        self, redis_client: aioredis.Redis
    ) -> None:
        """No grant entry must never mean "no restriction"."""
        session = await authenticate_basic_service_account(
            _header(_ACCOUNT, _PASSWORD),
            redis=redis_client,
            accounts=_accounts(),
            allowed_service_accounts=frozenset({_ACCOUNT}),
            grants={},
        )
        assert session.scopes == frozenset({"scan:submit"})
        assert session.tier is TrustTier.PUBLIC

    @pytest.mark.asyncio
    async def test_wrong_password_is_rejected(self, redis_client: aioredis.Redis) -> None:
        with pytest.raises(M2MError):
            await authenticate_basic_service_account(
                _header(_ACCOUNT, "wrong"),
                redis=redis_client,
                accounts=_accounts(),
                allowed_service_accounts=frozenset({_ACCOUNT}),
                grants={},
            )

    @pytest.mark.asyncio
    async def test_unknown_account_is_rejected(self, redis_client: aioredis.Redis) -> None:
        with pytest.raises(M2MError):
            await authenticate_basic_service_account(
                _header("nobody", _PASSWORD),
                redis=redis_client,
                accounts=_accounts(),
                allowed_service_accounts=frozenset({_ACCOUNT}),
                grants={},
            )

    @pytest.mark.asyncio
    async def test_account_not_on_the_allowlist_is_rejected(
        self, redis_client: aioredis.Redis
    ) -> None:
        """SECURITY: knowing the password is not sufficient - the same
        allowlist the client-credentials path enforces applies here too, so
        removing an account from it revokes access even if its hash is still
        configured."""
        with pytest.raises(M2MError):
            await authenticate_basic_service_account(
                _header(_ACCOUNT, _PASSWORD),
                redis=redis_client,
                accounts=_accounts(),
                allowed_service_accounts=frozenset(),
                grants={},
            )

    @pytest.mark.asyncio
    async def test_no_configured_accounts_rejects_everything(
        self, redis_client: aioredis.Redis
    ) -> None:
        """An unconfigured deployment must be closed, not open."""
        with pytest.raises(M2MError):
            await authenticate_basic_service_account(
                _header(_ACCOUNT, _PASSWORD),
                redis=redis_client,
                accounts={},
                allowed_service_accounts=frozenset({_ACCOUNT}),
                grants={},
            )

    @pytest.mark.asyncio
    async def test_malformed_header_is_rejected(self, redis_client: aioredis.Redis) -> None:
        for header in (
            None,
            "Basic",
            "Basic !!!not-base64!!!",
            "Basic " + base64.b64encode(b"nocolon").decode(),
        ):
            with pytest.raises(M2MError):
                await authenticate_basic_service_account(
                    header,
                    redis=redis_client,
                    accounts=_accounts(),
                    allowed_service_accounts=frozenset({_ACCOUNT}),
                    grants={},
                )

    @pytest.mark.asyncio
    async def test_repeated_failures_lock_the_account_out(
        self, redis_client: aioredis.Redis
    ) -> None:
        """SECURITY: a standing password on an internet-reachable API needs a
        brute-force bound; without one this path is strictly weaker than the
        token paths it sits beside."""
        for _ in range(5):
            with pytest.raises(M2MError):
                await authenticate_basic_service_account(
                    _header(_ACCOUNT, "wrong"),
                    redis=redis_client,
                    accounts=_accounts(),
                    allowed_service_accounts=frozenset({_ACCOUNT}),
                    grants={},
                )
        # Now even the CORRECT password is refused while the lockout stands.
        with pytest.raises(M2MError):
            await authenticate_basic_service_account(
                _header(_ACCOUNT, _PASSWORD),
                redis=redis_client,
                accounts=_accounts(),
                allowed_service_accounts=frozenset({_ACCOUNT}),
                grants={},
            )

    @pytest.mark.asyncio
    async def test_successful_auth_clears_the_failure_counter(
        self, redis_client: aioredis.Redis
    ) -> None:
        for _ in range(3):
            with pytest.raises(M2MError):
                await authenticate_basic_service_account(
                    _header(_ACCOUNT, "wrong"),
                    redis=redis_client,
                    accounts=_accounts(),
                    allowed_service_accounts=frozenset({_ACCOUNT}),
                    grants={},
                )
        session = await authenticate_basic_service_account(
            _header(_ACCOUNT, _PASSWORD),
            redis=redis_client,
            accounts=_accounts(),
            allowed_service_accounts=frozenset({_ACCOUNT}),
            grants={},
        )
        assert session.subject == _ACCOUNT
        # Counter reset: 3 more failures must still not reach the threshold.
        for _ in range(3):
            with pytest.raises(M2MError):
                await authenticate_basic_service_account(
                    _header(_ACCOUNT, "wrong"),
                    redis=redis_client,
                    accounts=_accounts(),
                    allowed_service_accounts=frozenset({_ACCOUNT}),
                    grants={},
                )
        again = await authenticate_basic_service_account(
            _header(_ACCOUNT, _PASSWORD),
            redis=redis_client,
            accounts=_accounts(),
            allowed_service_accounts=frozenset({_ACCOUNT}),
            grants={},
        )
        assert again.subject == _ACCOUNT
