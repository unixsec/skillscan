"""Vault-backed `BreakGlassCredentialPort` (coding spec §16.3: "凭据为强随机,
Vault 封存(不落库/不入配置明文)" - a strong-random credential, Vault-sealed,
never landing in this DB or config in plaintext).

SECURITY: this adapter only ever READS from Vault KV - it never provisions
or rotates the break-glass credential/TOTP secret itself (that's a deliberate
out-of-band operator action, "在 Vault 预置封存的 break-glass 凭据 + 绑定
TOTP" per coding spec §16.3's own bootstrap flow - step 2, optional, done by
whoever deploys this system, not by application code).

hvac is a synchronous client (no async support) - every Vault call here runs
via `asyncio.to_thread`, same pattern as gate.signer.VaultTransitSigner.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import hvac


class BreakGlassVaultReadError(RuntimeError):
    pass


class VaultBreakGlassCredentialPort:
    def __init__(
        self,
        *,
        client: hvac.Client,
        secret_path: str,
        mount_point: str = "secret",
        credential_key: str = "credential",
        totp_secret_key: str = "totp_secret",
    ) -> None:
        self._client = client
        self._secret_path = secret_path
        self._mount_point = mount_point
        self._credential_key = credential_key
        self._totp_secret_key = totp_secret_key

    async def fetch_credential(self) -> str:
        return await asyncio.to_thread(self._fetch_field, self._credential_key)

    async def fetch_totp_secret(self) -> str:
        return await asyncio.to_thread(self._fetch_field, self._totp_secret_key)

    def _fetch_field(self, key: str) -> str:
        try:
            response = self._client.secrets.kv.v2.read_secret_version(
                path=self._secret_path, mount_point=self._mount_point, raise_on_deleted_version=True
            )
        except Exception as exc:  # noqa: BLE001 - any Vault read failure fails closed, never falls back
            raise BreakGlassVaultReadError(
                f"failed to read break-glass secret at {self._secret_path!r}: {exc}"
            ) from exc
        data = response.get("data", {}).get("data", {})
        value = data.get(key)
        if not isinstance(value, str) or not value:
            raise BreakGlassVaultReadError(
                f"break-glass secret at {self._secret_path!r} is missing a non-empty {key!r} field"
            )
        return value
