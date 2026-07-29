"""Tests for `admin.breakglass_vault.VaultBreakGlassCredentialPort`.

Exercised against a fake hvac KV v2 client whose response SHAPE mirrors what
a real Vault KV v2 backend actually returns
(`{"data": {"data": {<key>: <value>}}}`) - same fake-hvac-over-real-behavior
approach as `test_gate_signer.py`'s `_FakeHvacTransit`, for the same reason:
no live Vault dev server is authorized for this automated suite.
"""

from __future__ import annotations

from typing import Any

import pytest

from monolith.modules.admin.breakglass_vault import (
    BreakGlassVaultReadError,
    VaultBreakGlassCredentialPort,
)


class _FakeHvacKvV2:
    def __init__(
        self, secret_data: dict[str, Any] | None, *, raise_error: Exception | None = None
    ) -> None:
        self._secret_data = secret_data
        self._raise_error = raise_error
        self.read_calls: list[dict[str, Any]] = []

    def read_secret_version(
        self, *, path: str, mount_point: str = "secret", raise_on_deleted_version: bool = True
    ) -> dict[str, Any]:
        self.read_calls.append({"path": path, "mount_point": mount_point})
        if self._raise_error is not None:
            raise self._raise_error
        return {"data": {"data": self._secret_data or {}}}


class _FakeHvacSecrets:
    def __init__(self, kv_v2: _FakeHvacKvV2) -> None:
        self.kv = type("_Kv", (), {"v2": kv_v2})()


class _FakeHvacClient:
    def __init__(self, kv_v2: _FakeHvacKvV2) -> None:
        self.secrets = _FakeHvacSecrets(kv_v2)


def _port(kv_v2: _FakeHvacKvV2) -> VaultBreakGlassCredentialPort:
    return VaultBreakGlassCredentialPort(
        client=_FakeHvacClient(kv_v2),
        secret_path="skillscan/breakglass",
        mount_point="secret",
    )


class TestFetchCredential:
    @pytest.mark.asyncio
    async def test_reads_the_credential_field(self) -> None:
        kv_v2 = _FakeHvacKvV2({"credential": "s3cr3t-value", "totp_secret": "BASE32SECRET"})
        credential = await _port(kv_v2).fetch_credential()
        assert credential == "s3cr3t-value"
        assert kv_v2.read_calls == [{"path": "skillscan/breakglass", "mount_point": "secret"}]

    @pytest.mark.asyncio
    async def test_missing_field_raises(self) -> None:
        kv_v2 = _FakeHvacKvV2({"totp_secret": "BASE32SECRET"})
        with pytest.raises(BreakGlassVaultReadError, match="credential"):
            await _port(kv_v2).fetch_credential()

    @pytest.mark.asyncio
    async def test_empty_string_field_raises(self) -> None:
        kv_v2 = _FakeHvacKvV2({"credential": "", "totp_secret": "BASE32SECRET"})
        with pytest.raises(BreakGlassVaultReadError, match="credential"):
            await _port(kv_v2).fetch_credential()

    @pytest.mark.asyncio
    async def test_vault_read_failure_fails_closed(self) -> None:
        kv_v2 = _FakeHvacKvV2(None, raise_error=RuntimeError("vault sealed"))
        with pytest.raises(BreakGlassVaultReadError, match="vault sealed"):
            await _port(kv_v2).fetch_credential()


class TestFetchTotpSecret:
    @pytest.mark.asyncio
    async def test_reads_the_totp_secret_field(self) -> None:
        kv_v2 = _FakeHvacKvV2({"credential": "s3cr3t-value", "totp_secret": "BASE32SECRET"})
        secret = await _port(kv_v2).fetch_totp_secret()
        assert secret == "BASE32SECRET"

    @pytest.mark.asyncio
    async def test_missing_field_raises(self) -> None:
        kv_v2 = _FakeHvacKvV2({"credential": "s3cr3t-value"})
        with pytest.raises(BreakGlassVaultReadError, match="totp_secret"):
            await _port(kv_v2).fetch_totp_secret()

    @pytest.mark.asyncio
    async def test_non_string_field_raises(self) -> None:
        kv_v2 = _FakeHvacKvV2({"credential": "s3cr3t-value", "totp_secret": 12345})
        with pytest.raises(BreakGlassVaultReadError, match="totp_secret"):
            await _port(kv_v2).fetch_totp_secret()
