"""Fixed-window counters in Redis that CANNOT be stranded without an expiry.

Both call sites here (`marketplace_api.ratelimit`, `admin.local_auth`) used to
spell the same counter by hand:

    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, WINDOW)

Two round-trips. A connection drop, a failover or a process restart between
them leaves a live count with NO TTL, and neither call site can recover from
that state on its own:

  * the marketplace limiter then reads `count > limit` on every subsequent
    request forever - the service account is rejected permanently, and the 429
    it returns advertises a fresh window (`Retry-After`), so a well-behaved
    client retries on a loop that can never succeed;
  * the login lockout is worse, because `_is_locked_out` returns BEFORE
    `_record_failure` runs - no code on the authentication path touches the key
    again, so the account is locked out permanently, correct password included.

Both were only escapable by deleting the key by hand, and neither produced any
error in our own logs.

SECURITY / DESIGN - two properties, and the second is why this module exists at
all rather than just a pipeline:

1. ATOMIC. The whole read-modify-expire runs inside one Lua script, so Redis
   executes it as a single step. There is no window in which the counter exists
   without a bound.
2. SELF-HEALING. Every entry point re-checks the TTL and re-arms it when the key
   has none. That is what lets a deployment that ALREADY has stranded keys (from
   the two-round-trip version that shipped before this) recover by itself on the
   next request, instead of needing an operator to find and delete them.

`ttl < 0` covers both Redis answers that mean "no bound": -1 (key exists, no
expiry - the stranded case) and -2 (key is gone, which a concurrent expiry can
produce between our own two calls). Re-arming on -2 is harmless: EXPIRE on a
missing key is a no-op, and the count we return is then 0.
"""

from __future__ import annotations

import redis.asyncio as aioredis

# Returns {count, ttl}. The EXPIRE is unconditional on `ttl < 0` rather than on
# `count == 1`: keying it to the first increment is exactly the assumption that
# broke - it only ever arms the window for a counter that was created by THIS
# call, and a stranded key is by definition one that was not.
_INCR_IN_WINDOW = """
local count = redis.call('INCR', KEYS[1])
local ttl = redis.call('TTL', KEYS[1])
if ttl < 0 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
    ttl = tonumber(ARGV[1])
end
return {count, ttl}
"""

# The read-only counterpart, which still repairs. A pure GET would leave the
# lockout path unable to ever clear a stranded counter (see the module
# docstring): that path refuses the request before any write happens, so if the
# read does not re-arm the window, nothing does.
_READ_IN_WINDOW = """
local raw = redis.call('GET', KEYS[1])
if raw == false then
    return {0, -2}
end
local count = tonumber(raw)
if count == nil then
    count = 0
end
local ttl = redis.call('TTL', KEYS[1])
if ttl < 0 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
    ttl = tonumber(ARGV[1])
end
return {count, ttl}
"""


async def incr_in_window(redis: aioredis.Redis, key: str, *, window_s: int) -> tuple[int, int]:
    """Increment `key`'s counter and guarantee it carries an expiry.

    Returns `(count, ttl_s)`. `count` is the value AFTER this increment.
    """
    # `str(window_s)`: Lua script arguments cross the wire as strings, and the
    # script's own `tonumber(ARGV[1])` is what turns it back into one.
    # `type: ignore[misc]`: redis-py types `eval` as sync-or-async on the shared
    # command mixin - same annotation gap `common.engine_toggle` works around.
    count, ttl = await redis.eval(_INCR_IN_WINDOW, 1, key, str(window_s))  # type: ignore[misc]
    return int(count), int(ttl)


async def read_in_window(redis: aioredis.Redis, key: str, *, window_s: int) -> tuple[int, int]:
    """Read `key`'s counter, re-arming its expiry if it has none.

    Returns `(count, ttl_s)`; `count` is 0 when the key is absent. Not a plain
    GET on purpose - see `_READ_IN_WINDOW`.
    """
    count, ttl = await redis.eval(_READ_IN_WINDOW, 1, key, str(window_s))  # type: ignore[misc]
    return int(count), int(ttl)
