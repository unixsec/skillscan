"""Engine enable/disable registry (coding spec §9 Admin·Engines, §11.7/§16.1:
"引擎启停(不能停 required floor 引擎)").

SECURITY (INV-1): a required (floor) engine can NEVER be disabled - the whole
point of the floor-engine backstop is that it stays immune to being switched
off, whether by a compromised admin session or an honest operator mistake.

Disable state lives in Redis (a SET of disabled engine names), shared across
every monolith replica - NOT per-process memory (which would make admin
actions apply inconsistently across a fleet), and deliberately NOT a new
MySQL table either, since this is simple, ephemeral toggle state where the
fail-safe default (everything enabled) is also the SAFE direction: if this
Redis key is ever lost, previously-disabled engines simply come back online,
which increases detection coverage rather than reducing it - the opposite of
a security regression.

The key name + read live in `common.engine_toggle` (not here) - the separate
engine-runner service (services/engine_runner/worker.py) must gate its own
sandbox-engine dispatch on the exact same key, so it can't be a monolith-only
private constant.
"""

from __future__ import annotations

from collections.abc import Sequence

import redis.asyncio as aioredis
from common.engine_toggle import DISABLED_ENGINES_KEY, list_disabled_engines
from skillscan_core import EngineMetadata

__all__ = [
    "EngineDisableError",
    "filter_enabled_engines",
    "is_disableable",
    "list_disabled_engines",
    "set_engine_enabled",
]


class EngineDisableError(ValueError):
    pass


def is_disableable(name: str, *, required_names: frozenset[str]) -> bool:
    return name not in required_names


async def set_engine_enabled(
    redis: aioredis.Redis, name: str, *, enabled: bool, required_names: frozenset[str]
) -> None:
    """SECURITY (INV-1): raises `EngineDisableError` (never silently ignores)
    if asked to disable a required floor engine - the caller (admin router)
    turns this into a 400/409, not a silent no-op."""
    if not enabled and not is_disableable(name, required_names=required_names):
        raise EngineDisableError(
            f"{name!r} is a required floor engine and cannot be disabled (INV-1)"
        )
    if enabled:
        await redis.srem(DISABLED_ENGINES_KEY, name)  # type: ignore[misc]
    else:
        await redis.sadd(DISABLED_ENGINES_KEY, name)  # type: ignore[misc]


async def filter_enabled_engines(
    redis: aioredis.Redis, engine_metadatas: Sequence[EngineMetadata]
) -> tuple[EngineMetadata, ...]:
    """Called at scan-submission time (gateway.router.create_scan) - the
    admin toggle takes effect on the NEXT submission, not retroactively on
    scans already in flight."""
    disabled = await list_disabled_engines(redis)
    return tuple(m for m in engine_metadatas if m.name not in disabled)
