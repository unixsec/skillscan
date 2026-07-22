"""MarketplacePort (coding spec §6). Real implementation:
`monolith.modules.integration_relay.marketplace.HttpMarketplaceAdapter`."""

from __future__ import annotations

from typing import Any, Protocol


class MarketplacePort(Protocol):
    async def write_verdict(self, jws: str, content_hash: str) -> None: ...  # idempotent writeback
    async def list_published(self) -> list[dict[str, Any]]: ...  # reconciliation poll, read-only
    async def quarantine(self, skill_id: str, reason: str) -> None: ...
