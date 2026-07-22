"""NotificationPort (coding spec §6) - SIEM/webhook delivery, driven from the
gate_outbox (coding spec §8/§11.3's transactional-outbox pattern).

HONEST STATUS: `monolith.modules.integration_relay.service` currently has
plain `drain_one`/`drain_pending_outbox` functions with no such abstraction -
they log-only (M3's placeholder) or write to the marketplace (M6's
`MarketplacePort`), but nothing implements a SIEM/webhook notification target
yet. This Protocol is defined here for a real SIEM adapter to implement
against."""

from __future__ import annotations

from typing import Any, Protocol


class NotificationPort(Protocol):
    async def emit(self, event: dict[str, Any]) -> None: ...
