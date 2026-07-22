"""SignerPort (coding spec §6/§10.6) - implemented via Vault Transit; the
private signing key never leaves Vault. Real implementations:
`monolith.modules.gate.signer.LocalDevSigner` (dev/test only) and
`VaultTransitSigner` (production)."""

from __future__ import annotations

from typing import Any, Protocol


class SignerPort(Protocol):
    async def sign_verdict(self, payload: dict[str, Any]) -> str: ...  # returns compact JWS
    async def jwks(self) -> dict[str, Any]: ...  # for marketplace signature verification
