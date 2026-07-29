"""MarketplacePort + HTTP adapter (coding spec §6/§11.6).

SECURITY (SAD §4.3): `list_published` (poll) uses an INDEPENDENT, read-only
marketplace credential, deliberately separate from `write_verdict`/
`quarantine`'s credential - two separate `httpx.AsyncClient` instances, each
carrying only its own bearer token, so poll's observations can never be
influenced by whatever the write path is doing (and a bug that accidentally
reused one client for the other's calls would be caught immediately by the
marketplace rejecting a wrong-scoped token, not silently "work").

HONESTY: this project has no real marketplace to integrate against in this
environment - the concrete REST shape below (`PUT /v1/verdicts/{content_hash}`,
`GET /v1/published`, `POST /v1/skills/{skill_id}/quarantine`) is a reasonable,
clearly-documented assumption, not a confirmed real contract (coding spec §6
gives precise PORT signatures but the underlying wire format is this
adapter's own implementation detail, same status as intel_sync.py's endpoint
assumptions in M4). Tested here via `httpx.MockTransport` - the REAL httpx
request/response code path, against a fake transport instead of a fake
network - not unit-mocked at the Python-object level.
"""

from __future__ import annotations

from typing import Any

import httpx
from common.config import require_internal_endpoint
from ports import MarketplacePort

# MarketplacePort now lives in libs/ports/marketplace.py (coding spec §6) -
# re-exported here so this used to be its home and every existing
# `from .marketplace import MarketplacePort` import site keeps working
# unchanged.
__all__ = ["HttpMarketplaceAdapter", "MarketplacePort"]


class HttpMarketplaceAdapter:
    def __init__(
        self,
        *,
        base_url: str,
        poll_token: str,
        write_token: str,
        timeout_s: float = 10.0,
        poll_transport: httpx.AsyncBaseTransport | None = None,
        write_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        require_internal_endpoint(base_url, field_name="marketplace.api_base_url")
        # SECURITY: poll_token != write_token is already enforced at the
        # MarketplaceSettings level (libs/common/config.py) - not re-checked
        # here, since this adapter may legitimately be constructed directly
        # from already-validated settings OR from test-only literal tokens.
        self._poll_client = httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {poll_token}"},
            timeout=timeout_s,
            transport=poll_transport,
        )
        self._write_client = httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {write_token}"},
            timeout=timeout_s,
            transport=write_transport,
        )

    async def write_verdict(self, jws: str, content_hash: str) -> None:
        # SECURITY: PUT (not POST) - idempotent per coding spec §11.6 "幂等回写"
        # (idempotent writeback); a retried outbox drain that already
        # succeeded once must be safe to send again.
        response = await self._write_client.put(f"/v1/verdicts/{content_hash}", json={"jws": jws})
        response.raise_for_status()

    async def list_published(self) -> list[dict[str, Any]]:
        response = await self._poll_client.get("/v1/published")
        response.raise_for_status()
        payload = response.json()
        # SECURITY: fail-closed on an unexpected response shape - never treat
        # "couldn't parse the published set" as "the published set is empty"
        # (that would blind poll reconciliation to every real ORPHAN).
        if not isinstance(payload, list):
            raise ValueError("marketplace GET /v1/published response must be a JSON array")
        return payload

    async def quarantine(self, skill_id: str, reason: str) -> None:
        response = await self._write_client.post(
            f"/v1/skills/{skill_id}/quarantine", json={"reason": reason}
        )
        response.raise_for_status()

    async def aclose(self) -> None:
        await self._poll_client.aclose()
        await self._write_client.aclose()
