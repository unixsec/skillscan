"""Per-service-account polling rate limit (里程碑 B' spec §6.3).

Shares one counter primitive with `admin.local_auth`'s failed-login lockout
(`common.redis_window_counter`) rather than introducing a second mechanism.

The window is per service account, so one marketplace exhausting its budget
cannot affect another.

2026-07-31: that primitive replaced a hand-written `INCR` + conditional
`EXPIRE` here. The two were separate round-trips, so a drop between them left
the counter with no expiry and rejected this service account PERMANENTLY -
while the 429's `Retry-After` kept promising a window that never rolled over.
See `common.redis_window_counter` for the full argument and the self-healing
property that recovers keys already stranded by the old version.
"""

from __future__ import annotations

import redis.asyncio as aioredis
from common.redis_window_counter import incr_in_window

_KEY_PREFIX = "skillscan:mkt:rate:"
_WINDOW_S = 60


async def check_rate_limit(
    redis: aioredis.Redis, *, service_account: str, limit_per_min: int
) -> int | None:
    """Return None to allow, or the Retry-After seconds to reject with 429."""
    key = f"{_KEY_PREFIX}{service_account}"
    count, ttl = await incr_in_window(redis, key, window_s=_WINDOW_S)
    if count > limit_per_min:
        # `ttl` is the real remaining window, guaranteed positive by the
        # primitive; the fallback stays only for a key that expired between the
        # increment and this read, where a full window is the honest answer.
        return max(1, ttl) if ttl > 0 else _WINDOW_S
    return None
