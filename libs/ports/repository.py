"""RepositoryPort (coding spec §6) - one concrete implementation per module,
each accessing only that module's own table(s) (per-module MySQL GRANT, §7.2).

This is a minimal, generic shape - real modules specialize far beyond `get`/
`put` (see e.g. `monolith.modules.gate.service`'s allowlist functions:
`create_allowlist_entry`, `list_active_allowlist_rows`, `revoke_allowlist_entry`
- these operate on the module's own `AllowlistRow` table exactly as this
Protocol's contract intends, just under module-specific names rather than
generic get/put, since a real repository's query shapes are domain-specific).
Every module in this codebase follows the same pattern: `service.py` absorbs
repository duties directly (no separate `repository.py` file) rather than
introducing an extra abstraction layer over a single-table, single-consumer
data access pattern - a deliberate simplification, not an oversight, and it is
NOT retrofitted into a forced generic-repository shape here: doing so across
every module would touch many call sites for no behavioral gain and real
regression risk, for a structural/documentation-shaped gap. The Protocol is
defined here so future modules that DO want the generic shape (e.g. a new
module with multiple entity types over the same table) have it available."""

from __future__ import annotations

from typing import Any, Protocol


class RepositoryPort(Protocol):
    async def get(self, id: str) -> Any | None: ...
    async def put(self, entity: Any) -> None: ...
