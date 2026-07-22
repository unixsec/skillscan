"""Tests for M2M authentication: client-credentials + mTLS (coding spec §11.2,
FR-API-080)."""

from __future__ import annotations

import time

import httpx
import pytest
from common.config import SessionSettings

from monolith.modules.gateway.auth.m2m import (
    M2MError,
    authenticate_client_credentials,
    authenticate_mtls,
)
from monolith.modules.gateway.auth.session import IntrospectionCache


def _settings() -> SessionSettings:
    return SessionSettings(
        introspection_endpoint="https://localhost/introspect",
        introspection_client_id="gateway",
        introspection_client_secret="secret",
    )


class TestClientCredentials:
    @pytest.mark.asyncio
    async def test_allowlisted_service_account_accepted(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, json={"active": True, "client_id": "ci-runner", "exp": time.time() + 60}
            )

        cache = IntrospectionCache(ttl_s=30)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            ctx = await authenticate_client_credentials(
                "m2m-token",
                settings=_settings(),
                http_client=client,
                cache=cache,
                allowed_service_accounts=frozenset({"ci-runner"}),
            )
        assert ctx.subject == "ci-runner"
        assert ctx.roles == frozenset({"submitter"})
        assert ctx.scopes == frozenset({"scan:submit"})

    @pytest.mark.asyncio
    async def test_non_allowlisted_service_account_rejected(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, json={"active": True, "client_id": "unknown-service", "exp": time.time() + 60}
            )

        cache = IntrospectionCache(ttl_s=30)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(M2MError):
                await authenticate_client_credentials(
                    "m2m-token",
                    settings=_settings(),
                    http_client=client,
                    cache=cache,
                    allowed_service_accounts=frozenset({"ci-runner"}),
                )

    @pytest.mark.asyncio
    async def test_inactive_token_rejected(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"active": False})

        cache = IntrospectionCache(ttl_s=30)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(M2MError):
                await authenticate_client_credentials(
                    "m2m-token",
                    settings=_settings(),
                    http_client=client,
                    cache=cache,
                    allowed_service_accounts=frozenset({"ci-runner"}),
                )

    @pytest.mark.asyncio
    async def test_no_token_rejected(self) -> None:
        cache = IntrospectionCache(ttl_s=30)
        transport = httpx.MockTransport(lambda r: httpx.Response(500))
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(M2MError):
                await authenticate_client_credentials(
                    None,
                    settings=_settings(),
                    http_client=client,
                    cache=cache,
                    allowed_service_accounts=frozenset(),
                )

    @pytest.mark.asyncio
    async def test_empty_allowlist_rejects_validly_introspected_token(self) -> None:
        """SECURITY regression: an empty/unset allowlist must fail CLOSED
        (deny every caller), not fail open (allow every validly-introspected
        caller) - see FR-API-080."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, json={"active": True, "client_id": "ci-runner", "exp": time.time() + 60}
            )

        cache = IntrospectionCache(ttl_s=30)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(M2MError):
                await authenticate_client_credentials(
                    "m2m-token",
                    settings=_settings(),
                    http_client=client,
                    cache=cache,
                    allowed_service_accounts=frozenset(),
                )

    @pytest.mark.asyncio
    async def test_expired_token_rejected_despite_active_true(self) -> None:
        """SECURITY regression: introspection exp must be checked the same way
        session.py's authenticate() checks it - active:true alone must not be
        sufficient if exp has already lapsed."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, json={"active": True, "client_id": "ci-runner", "exp": time.time() - 60}
            )

        cache = IntrospectionCache(ttl_s=30)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(M2MError):
                await authenticate_client_credentials(
                    "m2m-token",
                    settings=_settings(),
                    http_client=client,
                    cache=cache,
                    allowed_service_accounts=frozenset({"ci-runner"}),
                )


class TestMtls:
    def test_allowlisted_spiffe_identity_accepted(self) -> None:
        header = "URI=spiffe://cluster.local/ns/skillscan-workers/sa/engine-runner"
        ctx = authenticate_mtls(header, allowed_service_accounts=frozenset({"engine-runner"}))
        assert ctx.subject == "engine-runner"
        assert ctx.token_exp == float("inf")

    def test_missing_header_rejected(self) -> None:
        with pytest.raises(M2MError):
            authenticate_mtls(None, allowed_service_accounts=frozenset())

    def test_non_allowlisted_spiffe_identity_rejected(self) -> None:
        header = "URI=spiffe://cluster.local/ns/skillscan-workers/sa/some-other-service"
        with pytest.raises(M2MError):
            authenticate_mtls(header, allowed_service_accounts=frozenset({"engine-runner"}))

    def test_malformed_header_rejected(self) -> None:
        with pytest.raises(M2MError):
            authenticate_mtls("not-a-valid-header", allowed_service_accounts=frozenset())

    def test_empty_allowlist_rejects_valid_spiffe_identity(self) -> None:
        """SECURITY regression: an empty/unset allowlist must fail CLOSED
        (deny every caller), not fail open (allow every validly-presented
        mTLS identity) - see FR-API-080."""
        header = "URI=spiffe://cluster.local/ns/skillscan-workers/sa/engine-runner"
        with pytest.raises(M2MError):
            authenticate_mtls(header, allowed_service_accounts=frozenset())
