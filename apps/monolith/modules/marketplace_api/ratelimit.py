"""Per-service-account polling rate limit (里程碑 B' spec §6.3).

Reuses the counter shape `admin.local_auth` already uses for failed logins
(INCR + EXPIRE on first increment) rather than introducing a second mechanism.

The window is per service account, so one marketplace exhausting its budget
cannot affect another.
"""

from __future__ import annotations

import redis.asyncio as aioredis

_KEY_PREFIX = "skillscan:mkt:rate:"
_WINDOW_S = 60


async def check_rate_limit(
    redis: aioredis.Redis, *, service_account: str, limit_per_min: int
) -> int | None:
    """Return None to allow, or the Retry-After seconds to reject with 429."""
    key = f"{_KEY_PREFIX}{service_account}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, _WINDOW_S)
    if count > limit_per_min:
        ttl = await redis.ttl(key)
        return max(1, ttl) if ttl and ttl > 0 else _WINDOW_S
    return None
