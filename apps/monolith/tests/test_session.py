"""Tests for opaque-token session validation (coding spec §11.2, FR-SES).
Negative cases mirror SAD Appendix D: 'introspection 故障→拒(fail-closed)'."""

from __future__ import annotations

import time

import httpx
import pytest
from common.config import SessionSettings
from skillscan_core import TrustTier

from monolith.modules.gateway.auth.session import (
    IntrospectionCache,
    SessionError,
    authenticate,
    introspect_token,
)

GROUP_ROLE_MAP = {"skillscan-approvers": "approver"}


def _settings() -> SessionSettings:
    return SessionSettings(
        introspection_endpoint="https://localhost/introspect",
        introspection_client_id="gateway",
        introspection_client_secret="secret",
    )


class TestIntrospectionCache:
    def test_miss_then_hit(self) -> None:
        cache = IntrospectionCache(ttl_s=30)
        assert cache.get("token-a") is None
        cache.put("token-a", {"active": True})
        assert cache.get("token-a") == {"active": True}

    def test_keyed_by_hash_not_raw_token(self) -> None:
        cache = IntrospectionCache(ttl_s=30)
        cache.put("secret-token-value", {"active": True})
        assert "secret-token-value" not in cache._entries
        assert len(list(cache._entries.keys())[0]) == 64  # sha256 hex digest length

    def test_expires_after_ttl(self) -> None:
        cache = IntrospectionCache(ttl_s=30)
        cache.put("token-a", {"active": True})
        key = next(iter(cache._entries))
        payload, _cached_at = cache._entries[key]
        cache._entries[key] = (payload, time.time() - 31)  # force past the TTL
        assert cache.get("token-a") is None


class TestIntrospectToken:
    @pytest.mark.asyncio
    async def test_returns_cached_value_without_a_second_call(self) -> None:
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(
                200, json={"active": True, "sub": "alice", "exp": time.time() + 60}
            )

        cache = IntrospectionCache(ttl_s=30)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await introspect_token("tok", settings=_settings(), http_client=client, cache=cache)
            await introspect_token("tok", settings=_settings(), http_client=client, cache=cache)
        assert calls == 1

    @pytest.mark.asyncio
    async def test_introspection_endpoint_failure_is_fail_closed(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="internal error")

        cache = IntrospectionCache(ttl_s=30)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(SessionError):
                await introspect_token("tok", settings=_settings(), http_client=client, cache=cache)

    @pytest.mark.asyncio
    async def test_non_json_response_is_fail_closed(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="not json")

        cache = IntrospectionCache(ttl_s=30)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(SessionError):
                await introspect_token("tok", settings=_settings(), http_client=client, cache=cache)


class TestAuthenticate:
    @pytest.mark.asyncio
    async def test_no_token_rejected_without_network_call(self) -> None:
        async def unexpected(request: httpx.Request) -> httpx.Response:
            raise AssertionError("must not call introspection when there is no token")

        cache = IntrospectionCache(ttl_s=30)
        async with httpx.AsyncClient(transport=httpx.MockTransport(unexpected)) as client:
            with pytest.raises(SessionError):
                await authenticate(
                    None,
                    settings=_settings(),
                    http_client=client,
                    cache=cache,
                    group_role_map=GROUP_ROLE_MAP,
                )

    @pytest.mark.asyncio
    async def test_valid_session_resolves_roles_and_tier(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "active": True,
                    "sub": "alice",
                    "exp": time.time() + 300,
                    "groups": ["skillscan-approvers"],
                    "scope": "scan:read scan:write",
                },
            )

        cache = IntrospectionCache(ttl_s=30)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            ctx = await authenticate(
                "a-token",
                settings=_settings(),
                http_client=client,
                cache=cache,
                group_role_map=GROUP_ROLE_MAP,
            )
        assert ctx.subject == "alice"
        assert ctx.has_role("approver")
        assert ctx.has_role("submitter")
        assert ctx.scopes == frozenset({"scan:read", "scan:write"})
        assert ctx.tier == TrustTier.INTERNAL

    @pytest.mark.asyncio
    async def test_inactive_token_rejected(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"active": False})

        cache = IntrospectionCache(ttl_s=30)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(SessionError):
                await authenticate(
                    "a-token",
                    settings=_settings(),
                    http_client=client,
                    cache=cache,
                    group_role_map=GROUP_ROLE_MAP,
                )

    @pytest.mark.asyncio
    async def test_expired_exp_rejected(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, json={"active": True, "sub": "alice", "exp": time.time() - 10}
            )

        cache = IntrospectionCache(ttl_s=30)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(SessionError):
                await authenticate(
                    "a-token",
                    settings=_settings(),
                    http_client=client,
                    cache=cache,
                    group_role_map=GROUP_ROLE_MAP,
                )

    @pytest.mark.asyncio
    async def test_missing_sub_rejected(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"active": True, "exp": time.time() + 300})

        cache = IntrospectionCache(ttl_s=30)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(SessionError):
                await authenticate(
                    "a-token",
                    settings=_settings(),
                    http_client=client,
                    cache=cache,
                    group_role_map=GROUP_ROLE_MAP,
                )

    @pytest.mark.asyncio
    async def test_unknown_trust_tier_value_defaults_to_internal(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "active": True,
                    "sub": "alice",
                    "exp": time.time() + 300,
                    "trust_tier": "super-admin-tier",  # not a real TrustTier value
                },
            )

        cache = IntrospectionCache(ttl_s=30)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            ctx = await authenticate(
                "a-token",
                settings=_settings(),
                http_client=client,
                cache=cache,
                group_role_map=GROUP_ROLE_MAP,
            )
        assert ctx.tier == TrustTier.INTERNAL
