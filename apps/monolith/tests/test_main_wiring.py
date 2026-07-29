"""Proves `monolith.main.create_app()`'s OWN wiring is correct end-to-end -
every other test builds its own test-scoped `ScanRuntime` directly, so none of
them actually exercise `_build_scan_runtime()`/`_load_policy()` themselves.
This test lets `create_app()` build its REAL scan runtime (real per-module
DSNs against local MySQL, real local Redis, the REAL versioned
`policies/gate/v1.yaml`, `LocalDevSigner`/no-marketplace dev-default fallback
since `SKILLSCAN_VAULT_ADDR`/`SKILLSCAN_MARKETPLACE_API_BASE_URL` aren't set
in this test environment), only overriding `auth_runtime` (no real IdP in
this environment) and `SKILLSCAN_BLOBSTORE_ROOT` (redirected to `tmp_path` so
this test doesn't leave files in the repo's own `var/` directory).
"""

from __future__ import annotations

import io
import tarfile
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from common.config import SessionSettings
from fastapi import FastAPI
from skillscan_core import TrustTier

from monolith.main import create_app
from monolith.modules.gateway.auth.dependencies import AuthRuntime, get_session_context
from monolith.modules.gateway.auth.session import IntrospectionCache, SessionContext
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.modules.orchestration.floor import floor_engine_names


def _fake_auth_runtime() -> AuthRuntime:
    settings = SessionSettings(
        introspection_endpoint="https://localhost/introspect",
        introspection_client_id="gateway",
        introspection_client_secret="unused",
    )
    return AuthRuntime(
        settings=settings,
        http_client=httpx.AsyncClient(),
        cache=IntrospectionCache(ttl_s=30),
        group_role_map={},
    )


@pytest_asyncio.fixture
async def real_app(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> AsyncIterator[FastAPI]:
    monkeypatch.setenv("SKILLSCAN_BLOBSTORE_ROOT", str(tmp_path / "blobstore"))
    app = create_app(auth_runtime=_fake_auth_runtime())
    scan_runtime: ScanRuntime = app.state.scan
    try:
        yield app
    finally:
        await scan_runtime.redis.aclose()


class TestRealScanRuntimeWiring:
    def test_default_policy_requires_the_full_floor_set(self, real_app: FastAPI) -> None:
        scan_runtime: ScanRuntime = real_app.state.scan
        assert scan_runtime.policy.required_engines == floor_engine_names()

    def test_default_trust_tier_is_internal(self, real_app: FastAPI) -> None:
        scan_runtime: ScanRuntime = real_app.state.scan
        assert scan_runtime.default_trust_tier == TrustTier.INTERNAL

    @pytest.mark.asyncio
    async def test_can_submit_and_fetch_a_scan_through_the_real_wiring(
        self, real_app: FastAPI
    ) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            content = f"print({uuid.uuid4().hex!r})\n".encode()
            info = tarfile.TarInfo(name="skill.py")
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))

        real_app.dependency_overrides[get_session_context] = lambda: SessionContext(
            subject="alice",
            roles=frozenset({"submitter"}),
            scopes=frozenset(),
            tier=TrustTier.INTERNAL,
            token_exp=9999999999.0,
            is_machine=False,
        )
        transport = httpx.ASGITransport(app=real_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post(
                "/v1/scans", files={"package": ("skill.tar", buf.getvalue(), "application/x-tar")}
            )
            assert response.status_code == 202
            scan_id = response.json()["scan_id"]

            get_response = await client.get(f"/v1/scans/{scan_id}")
            assert get_response.status_code == 200
            assert get_response.json()["state"] == "queued"


# SECURITY regression (2026-07-06 spec-compliance audit): SKILLSCAN_VAULT_ADDR
# used to be read via a raw os.environ.get(...) in
# _build_breakglass_credential_port specifically - bypassing the same
# internal-address validation _build_signer's VaultSettings path already
# applied. Both call sites now go through the single validated Settings
# object (monolith/config.py), so a non-internal address must fail BOTH paths
# identically, not just the signer one.
class TestVaultAddrInternalValidation:
    def test_non_internal_vault_addr_fails_closed_at_startup(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("SKILLSCAN_BLOBSTORE_ROOT", str(tmp_path / "blobstore"))
        # 8.8.8.8 (Google public DNS) - unambiguously public, no DNS lookup
        # needed (already a literal IP), so this is deterministic regardless
        # of test-environment network/DNS availability.
        monkeypatch.setenv("SKILLSCAN_VAULT_ADDR", "https://8.8.8.8/")
        monkeypatch.setenv("SKILLSCAN_VAULT_TOKEN", "unused")
        with pytest.raises(ValueError, match="internal/private"):
            create_app(auth_runtime=_fake_auth_runtime())

    def test_non_internal_vault_addr_fails_closed_even_when_only_breakglass_uses_it(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Break-glass is the specific path that was NOT validated before this
        # fix - confirm it's covered even independent of the signer path
        # (which was already correct) by enabling break-glass explicitly.
        monkeypatch.setenv("SKILLSCAN_BLOBSTORE_ROOT", str(tmp_path / "blobstore"))
        monkeypatch.setenv("SKILLSCAN_BREAKGLASS_ENABLED", "true")
        monkeypatch.setenv("SKILLSCAN_VAULT_ADDR", "https://8.8.8.8/")
        monkeypatch.setenv("SKILLSCAN_VAULT_TOKEN", "unused")
        with pytest.raises(ValueError, match="internal/private"):
            create_app(auth_runtime=_fake_auth_runtime())


# SECURITY regression (whole-branch review, 2026-07-29): `_build_marketplace()`
# reads `SKILLSCAN_MARKETPLACE_API_BASE_URL` via a raw `os.environ.get(...)` -
# the same shape as the `SKILLSCAN_VAULT_ADDR` bug `TestVaultAddrInternalValidation`
# above regression-tests. Unlike that bug, this read is NOT a bypass: the value
# flows straight into `MarketplaceSettings(api_base_url=...)`, whose own
# `require_internal_endpoint` model_validator fires regardless of source - but
# nothing proved that before this test (`monolith.config.Settings` also carried
# a same-shaped but DEAD `marketplace_api` field, bound to a different env var
# name that nothing set, until this review removed it). This locks in that the
# already-existing validation actually fires at startup.
class TestMarketplaceApiInternalValidation:
    def test_non_internal_marketplace_api_base_url_fails_closed_at_startup(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("SKILLSCAN_BLOBSTORE_ROOT", str(tmp_path / "blobstore"))
        # 8.8.8.8 (Google public DNS) - unambiguously public, no DNS lookup
        # needed (already a literal IP), so this is deterministic regardless
        # of test-environment network/DNS availability.
        monkeypatch.setenv("SKILLSCAN_MARKETPLACE_API_BASE_URL", "https://8.8.8.8/")
        monkeypatch.setenv("SKILLSCAN_MARKETPLACE_POLL_TOKEN", "poll-token-unused")
        monkeypatch.setenv("SKILLSCAN_MARKETPLACE_WRITE_TOKEN", "write-token-unused")
        with pytest.raises(ValueError, match="internal/private"):
            create_app(auth_runtime=_fake_auth_runtime())


class TestDynamicSandboxUnimplementedWarning:
    def test_enabling_dynamic_sandbox_warns_rather_than_silently_doing_nothing(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setenv("SKILLSCAN_BLOBSTORE_ROOT", str(tmp_path / "blobstore"))
        monkeypatch.setenv("SKILLSCAN_DYNAMIC_SANDBOX_ENABLED", "true")
        with caplog.at_level("WARNING", logger="skillscan.monolith.config"):
            create_app(auth_runtime=_fake_auth_runtime())
        assert any(
            "no dynamic-sandbox implementation exists" in r.getMessage() for r in caplog.records
        )
