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
from typing import Any

import redis.asyncio as aioredis
from common.engine_toggle import DISABLED_ENGINES_KEY, list_disabled_engines
from engine_runner.sandbox_engines import SANDBOX_ENGINE_NAMES
from skillscan_core import EngineMetadata

from monolith.modules.intel.matcher import (
    INTEL_ENGINE_CAPABILITIES,
    INTEL_ENGINE_NAME,
    INTEL_ENGINE_VERSION,
)

__all__ = [
    "EngineDisableError",
    "filter_enabled_engines",
    "is_disableable",
    "known_engine_names",
    "known_engine_rows",
    "list_disabled_engines",
    "set_engine_enabled",
]


class EngineDisableError(ValueError):
    pass


def known_engine_rows(
    engine_metadatas: Sequence[EngineMetadata],
    *,
    required: frozenset[str],
    disabled: frozenset[str],
) -> list[dict[str, Any]]:
    """Every engine this deployment knows about, across all THREE tiers, as the
    admin console renders them.

    THE BUG THIS EXISTS TO PREVENT (2026-07-29, milestone C Task 2): the admin
    router used to assemble the listing and the toggle's `known_names` guard
    independently, and both enumerated only two tiers - `runtime.engine_
    metadatas` (which `main.py` fills from `floor_engines()` alone) plus
    `SANDBOX_ENGINE_NAMES`. The intel matcher is a third tier, declared nowhere
    either of them looked, so `inhouse-intel-matcher` could not be listed AND
    PATCHing it returned 404 - an engine that runs on every scan and that an
    operator had no way to see or switch off. Deriving both from this one
    function makes "listable" and "toggleable" the same set by construction.

    Tiers, and why each is enumerated the way it is:

    - floor / in-process: real `EngineMetadata` is available, so version and
      capabilities are real.
    - sandbox: runs in the separate engine-runner service/image, so no metadata
      is reachable from the monolith at all (INV-15) - "sandboxed" is the
      meaningful capability tag, distinguishing these rows from the floor ones.
    - intel: in-process but not constructible without a DB-fetched IOC snapshot,
      so its identity is taken from the constants `intel.matcher` exports.
    """
    rows: list[dict[str, Any]] = [
        {
            "name": metadata.name,
            "version": metadata.version,
            "required": metadata.name in required,
            "enabled": metadata.name not in disabled,
            "capabilities": sorted(c.value for c in metadata.capabilities),
        }
        for metadata in engine_metadatas
    ]
    rows += [
        {
            "name": name,
            "version": None,
            "required": False,
            "enabled": name not in disabled,
            "capabilities": ["sandboxed"],
        }
        for name in SANDBOX_ENGINE_NAMES
    ]
    rows.append(
        {
            "name": INTEL_ENGINE_NAME,
            "version": INTEL_ENGINE_VERSION,
            # Advisory by design, never `required_engines`: an intel-DB hiccup
            # must degrade to floor-only findings, not fail-closed BLOCK every
            # scan (see worker._floor_engines_with_intel's docstring).
            "required": INTEL_ENGINE_NAME in required,
            "enabled": INTEL_ENGINE_NAME not in disabled,
            "capabilities": sorted(c.value for c in INTEL_ENGINE_CAPABILITIES),
        }
    )
    return rows


def known_engine_names(engine_metadatas: Sequence[EngineMetadata]) -> frozenset[str]:
    """The name universe the toggle validates against - read off `known_engine_
    rows` rather than re-assembled, so an engine can never be listable but not
    addressable (or the reverse)."""
    return frozenset(
        str(row["name"])
        for row in known_engine_rows(engine_metadatas, required=frozenset(), disabled=frozenset())
    )


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
