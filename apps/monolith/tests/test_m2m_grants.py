"""M2M grants are per-service-account, not global (里程碑 B' spec §6.1).

No infrastructure needed. The resolution/parsing tests are pure functions; the
wiring test at the bottom builds a real `create_app()` FastAPI app around a
`ScanRuntime` whose database and Redis handles are never used (both connect
lazily and this file issues no query), and fakes only the IdP.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import httpx
import pytest
import redis.asyncio as aioredis
from common.blobstore import LocalFilesystemBlobStore
from fastapi import FastAPI
from skillscan_core import GatePolicy
from skillscan_core.models import TrustTier
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from monolith.config import _parse_m2m_grants, load_settings
from monolith.main import create_app
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.gateway.auth import m2m
from monolith.modules.gateway.auth.dependencies import AuthRuntime, get_session_context
from monolith.modules.gateway.runtime import ScanRuntime


class TestDefaultGrant:
    def test_an_unconfigured_account_gets_submit_only(self) -> None:
        # Compatibility: no existing deployment may gain a new permission.
        grant = m2m.resolve_grant("legacy-ci", {})
        assert grant.scopes == frozenset({"scan:submit"})

    def test_an_unconfigured_account_gets_the_STRICTEST_tier(self) -> None:
        # SECURITY: m2m.py used to hardcode TrustTier.INTERNAL, the most
        # PERMISSIVE tier (BLOCK at CRITICAL). A caller submitting third-party
        # content was therefore judged as if it were internal. PUBLIC (BLOCK at
        # HIGH) is the correct default for a machine caller.
        grant = m2m.resolve_grant("legacy-ci", {})
        assert grant.tier is TrustTier.PUBLIC


class TestConfiguredGrant:
    def test_a_configured_account_gets_exactly_its_own_scopes(self) -> None:
        grants = {
            "marketplace": m2m.M2MGrant(
                scopes=frozenset({"scan:submit", "scan:read"}), tier=TrustTier.PUBLIC
            )
        }
        assert m2m.resolve_grant("marketplace", grants).scopes == frozenset(
            {"scan:submit", "scan:read"}
        )

    def test_one_accounts_grant_does_not_leak_to_another(self) -> None:
        grants = {
            "marketplace": m2m.M2MGrant(
                scopes=frozenset({"scan:submit", "scan:read"}), tier=TrustTier.PUBLIC
            )
        }
        assert m2m.resolve_grant("other-ci", grants).scopes == frozenset({"scan:submit"})


class TestParsingTheOperatorsConfiguration:
    """`config._parse_m2m_grants` is the ONLY thing that turns operator
    configuration into grants, and every one of its branches was untested
    (review 2026-07-28) - checked by hand during implementation and never
    captured.

    SECURITY: every malformed value must RAISE. Returning `{}` on bad input
    would be silently indistinguishable from "no grants configured", leaving an
    operator convinced their configuration took effect while every account
    stayed on `DEFAULT_M2M_GRANT` - the same class of silent downgrade this
    milestone's fail-closed posture exists to prevent.
    """

    def test_an_unset_value_is_no_grants(self) -> None:
        assert _parse_m2m_grants("") == {}

    def test_a_valid_entry_becomes_a_grant(self) -> None:
        grants = _parse_m2m_grants(
            json.dumps({"marketplace": {"scopes": ["scan:submit", "scan:read"], "tier": "partner"}})
        )
        assert set(grants) == {"marketplace"}
        assert grants["marketplace"].scopes == frozenset({"scan:submit", "scan:read"})
        assert grants["marketplace"].tier is TrustTier.PARTNER

    def test_each_account_gets_its_own_grant(self) -> None:
        grants = _parse_m2m_grants(
            json.dumps(
                {
                    "marketplace": {"scopes": ["scan:submit", "scan:read"], "tier": "partner"},
                    "legacy-ci": {"scopes": ["scan:submit"], "tier": "public"},
                }
            )
        )
        assert grants["legacy-ci"].scopes == frozenset({"scan:submit"})
        assert grants["legacy-ci"].tier is TrustTier.PUBLIC

    @pytest.mark.parametrize(
        ("raw", "expected_message"),
        [
            ("{not json at all", "not valid JSON"),
            ('["marketplace"]', "must be a JSON object"),
            ('{"marketplace": "scan:read"}', "must be a JSON object"),
            ('{"marketplace": {"tier": "public"}}', "missing required key"),
            ('{"marketplace": {"scopes": ["scan:read"]}}', "missing required key"),
            ('{"marketplace": {"scopes": "scan:read", "tier": "public"}}', "array of strings"),
            ('{"marketplace": {"scopes": ["scan:read", 7], "tier": "public"}}', "array of strings"),
            ('{"marketplace": {"scopes": ["scan:read"], "tier": "trusted"}}', "invalid tier"),
            ('{"marketplace": {"scopes": ["scan:read"], "tier": null}}', "invalid tier"),
        ],
    )
    def test_a_malformed_value_raises_rather_than_yielding_no_grants(
        self, raw: str, expected_message: str
    ) -> None:
        with pytest.raises(ValueError, match=expected_message):
            _parse_m2m_grants(raw)

    def test_the_error_names_the_offending_account(self) -> None:
        # An operator configuring several accounts needs to know WHICH entry is
        # wrong; "invalid JSON" alone sends them re-reading all of them.
        with pytest.raises(ValueError, match="typo-account"):
            _parse_m2m_grants(
                json.dumps(
                    {
                        "marketplace": {"scopes": ["scan:read"], "tier": "public"},
                        "typo-account": {"scopes": ["scan:read"], "tier": "pubic"},
                    }
                )
            )


class TestSettingsCarryTheGrants:
    def test_load_settings_parses_the_environment_variable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(
            "SKILLSCAN_M2M_GRANTS_JSON",
            json.dumps({"marketplace": {"scopes": ["scan:read"], "tier": "partner"}}),
        )
        settings = load_settings()
        assert settings.m2m_grants["marketplace"].tier is TrustTier.PARTNER

    def test_a_malformed_environment_variable_fails_startup(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Fail-closed at startup, exactly like `main._load_policy` - never a
        # silent fallback to the empty default.
        monkeypatch.setenv("SKILLSCAN_M2M_GRANTS_JSON", "{not json at all")
        with pytest.raises(ValueError, match="not valid JSON"):
            load_settings()


_WIRED_ACCOUNT = "marketplace-bot"


def _never_used_session() -> AsyncSession:
    raise AssertionError("this test must never open a database session")


def _fake_scan_runtime(tmp_path: Path) -> ScanRuntime:
    """Enough runtime for `create_app` to build the app. Nothing here connects:
    SQLAlchemy/redis handles are lazy and no request in this file reaches a
    query."""
    return ScanRuntime(
        redis=aioredis.Redis.from_url("redis://localhost:6379/0"),
        blobstore=LocalFilesystemBlobStore(tmp_path / "blobstore"),
        orchestration_session_factory=_never_used_session,
        gate_session_factory=_never_used_session,
        policy=GatePolicy(version="test-m2m-wiring", required_engines=frozenset()),
        engine_metadatas=(),
        allowlist=(),
        signer=LocalDevSigner(),
    )


def _introspection_transport(subject: str) -> httpx.MockTransport:
    def _handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"active": True, "sub": subject, "exp": time.time() + 300})

    return httpx.MockTransport(_handler)


def _bearer_request(app: FastAPI, token: str) -> Request:
    """The minimal ASGI scope `get_session_context` reads: the app (for
    `app.state.auth`) and an `Authorization: Bearer` header."""
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/v1/market/skills/any",
            "query_string": b"",
            "headers": [(b"authorization", f"Bearer {token}".encode())],
            "app": app,
        }
    )


class TestConfiguredGrantsReachTheAuthenticator:
    """The END of the settings -> AuthRuntime -> authenticator chain.

    SECURITY (review 2026-07-28): nothing asserted that `create_app` passes
    `worker_settings.m2m_grants` into the auth runtime, nor that the runtime's
    grants reach `authenticate_client_credentials` - the existing tests call
    that function directly with an explicit `grants=`. Deleting the kwarg at the
    wiring site silently drops every configured account back to
    `DEFAULT_M2M_GRANT` (scan:submit only, PUBLIC), which 403s the marketplace
    on every poll, with a green suite.

    So these assert the SessionContext that actually comes out the far end. Only
    the IdP is faked (there is none in this environment); every hop in between -
    `load_settings`, `_parse_m2m_grants`, `create_app`, `_build_auth_runtime`,
    `get_session_context`, `authenticate_client_credentials`, `resolve_grant` -
    is the production path.
    """

    @pytest.mark.asyncio
    async def test_a_configured_grant_reaches_the_authenticated_session(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv(
            "SKILLSCAN_M2M_GRANTS_JSON",
            json.dumps(
                {_WIRED_ACCOUNT: {"scopes": ["scan:submit", "scan:read"], "tier": "partner"}}
            ),
        )
        monkeypatch.setenv("SKILLSCAN_M2M_ALLOWED_SERVICE_ACCOUNTS", _WIRED_ACCOUNT)
        runtime = _fake_scan_runtime(tmp_path)
        app = create_app(scan_runtime=runtime)
        auth_runtime: AuthRuntime = app.state.auth
        await auth_runtime.http_client.aclose()
        auth_runtime.http_client = httpx.AsyncClient(
            transport=_introspection_transport(_WIRED_ACCOUNT)
        )
        try:
            session = await get_session_context(_bearer_request(app, "opaque-token"))
        finally:
            await auth_runtime.http_client.aclose()
            await runtime.redis.aclose()

        assert session.subject == _WIRED_ACCOUNT
        assert session.scopes == frozenset({"scan:submit", "scan:read"})
        # PARTNER is neither DEFAULT_M2M_GRANT's PUBLIC nor the deployment
        # default INTERNAL, so this cannot pass by coincidence.
        assert session.tier is TrustTier.PARTNER
        assert session.is_machine is True

    @pytest.mark.asyncio
    async def test_an_account_the_operator_did_not_configure_keeps_the_default_grant(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # The other half of the claim: the configured dict is consulted PER
        # ACCOUNT on the way through, not applied to whoever authenticates.
        monkeypatch.setenv(
            "SKILLSCAN_M2M_GRANTS_JSON",
            json.dumps(
                {_WIRED_ACCOUNT: {"scopes": ["scan:submit", "scan:read"], "tier": "partner"}}
            ),
        )
        monkeypatch.setenv(
            "SKILLSCAN_M2M_ALLOWED_SERVICE_ACCOUNTS", f"{_WIRED_ACCOUNT},unconfigured-ci"
        )
        runtime = _fake_scan_runtime(tmp_path)
        app = create_app(scan_runtime=runtime)
        auth_runtime: AuthRuntime = app.state.auth
        await auth_runtime.http_client.aclose()
        auth_runtime.http_client = httpx.AsyncClient(
            transport=_introspection_transport("unconfigured-ci")
        )
        try:
            session = await get_session_context(_bearer_request(app, "another-token"))
        finally:
            await auth_runtime.http_client.aclose()
            await runtime.redis.aclose()

        assert session.subject == "unconfigured-ci"
        assert session.scopes == m2m.DEFAULT_M2M_GRANT.scopes
        assert session.tier is m2m.DEFAULT_M2M_GRANT.tier
