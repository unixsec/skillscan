"""Shared engine enable/disable state (coding spec §9 Admin·Engines, §11.7/
§16.1: "引擎启停"). One canonical home for the Redis key + read, same reason
airlock.py lives here rather than in apps/monolith: both the monolith (which
writes this state via its admin API) and the separate engine-runner service
(which must actually gate sandbox-engine dispatch on it) need the same key
name and the same read logic - see engine_runner/sandbox_engines.py's own
docstring for why a duplicated constant across services is exactly the bug
class this project has already been burned by once.
"""

from __future__ import annotations

import redis.asyncio as aioredis

DISABLED_ENGINES_KEY = "skillscan:admin:disabled_engines"


async def list_disabled_engines(redis: aioredis.Redis) -> frozenset[str]:
    members = await redis.smembers(DISABLED_ENGINES_KEY)  # type: ignore[misc]
    return frozenset(m.decode() if isinstance(m, bytes) else m for m in members)
