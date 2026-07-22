"""engine-runner entrypoint (coding spec §10/§11.7, INV-10).

The actual missing deployable: `deploy/helm/skillscan/templates/
engine-runner-deployment.yaml` has described a `skillscan/engine-runner`
image since M7, but nothing in this repo built or ran one - this is that
process. Reads config from `SKILLSCAN_`-prefixed env vars, matching
`apps/monolith/config.py`'s existing convention so the same ConfigMap keys
work for both deployables.

SECURITY (INV-10): no DB DSN, no Vault address, no IdP config is read here -
only `SKILLSCAN_REDIS_URL`, `SKILLSCAN_BLOBSTORE_ROOT` (or MinIO endpoint,
once that's wired), and `SKILLSCAN_VLLM_BASE_URL`/`SKILLSCAN_OSV_SOURCE` for
the two engines that need them. There is nothing in this process's
environment for a compromised parser to steal beyond what the airlock itself
already exposes (Redis control-plane access, blob store artifacts/findings
prefixes) - exactly the blast-radius boundary the coding spec's architecture
requires.
"""

from __future__ import annotations

import asyncio
import os
import signal
import uuid
from pathlib import Path

import redis.asyncio as aioredis
from common.blobstore import LocalFilesystemBlobStore
from common.log import get_logger

from engine_runner.sandbox_engines import sandbox_engines
from engine_runner.worker import ensure_sandbox_group, sandbox_engine_tick

_logger = get_logger("skillscan.engine_runner.main")


def _settings_from_env() -> dict[str, str]:
    return {
        "redis_url": os.environ.get("SKILLSCAN_REDIS_URL", "redis://localhost:6379/0"),
        "blobstore_root": os.environ.get("SKILLSCAN_BLOBSTORE_ROOT", "/var/lib/skillscan/blobstore"),
        "vllm_base_url": os.environ.get("SKILLSCAN_VLLM_BASE_URL", ""),
        "tick_interval_s": os.environ.get("SKILLSCAN_ENGINE_RUNNER_INTERVAL_S", "1.0"),
        # SKILLSCAN_VLLM_BASE_URL must resolve internally regardless (INV-14,
        # require_internal_endpoint - "internal" covers an enterprise's own
        # privatized model deployment, not just a literal vLLM process).
        # These two are for a privatized deployment that enforces its own
        # auth and/or serves a specific named model - both optional, empty
        # by default.
        "llm_api_key": os.environ.get("SKILLSCAN_LLM_API_KEY", ""),
        "llm_model": os.environ.get("SKILLSCAN_LLM_MODEL", ""),
        # aig-mcp-scan's own subprocess timeout (services/engine_runner/
        # adapters/aig.py) - default 240s assumes a reasonably fast backend;
        # override for a slower one (e.g. a local debug model with no
        # dedicated inference hardware). Raising this alone does nothing
        # unless SKILLSCAN_SCAN_DEADLINE_S (apps/monolith) is ALSO raised -
        # see aig.py's own make_adapter() docstring for why.
        "llm_engine_timeout_s": os.environ.get("SKILLSCAN_LLM_ENGINE_TIMEOUT_S", "240.0"),
    }


_STARTUP_RETRY_ATTEMPTS = 30
_STARTUP_RETRY_DELAY_S = 2.0


async def _ensure_sandbox_group_with_retry(redis: aioredis.Redis) -> None:
    """ROBUSTNESS: on first deploy, this process's very first action is a
    Redis call - unlike `apps.monolith.main.create_app()`, which does enough
    other startup work (building 8 separate DB engines, etc.) that pod
    networking has typically settled by the time it first touches Redis,
    this process has nothing to do first. A pod's DNS/network can briefly lag
    container start (observed live: CoreDNS itself resolved `redis` correctly
    from a fresh debug pod at the same moment this failed with "Temporary
    failure in name resolution") - retry with a bounded, generous window
    rather than crash-looping on what's usually just early-pod-lifecycle
    timing, not a real misconfiguration. If Redis is genuinely unreachable
    for the full window, this re-raises and the process exits - a real crash
    loop at that point correctly reflects a real problem."""
    last_exc: Exception | None = None
    for attempt in range(1, _STARTUP_RETRY_ATTEMPTS + 1):
        try:
            await ensure_sandbox_group(redis)
            return
        except Exception as exc:  # noqa: BLE001 - retry any connection-shaped failure
            last_exc = exc
            _logger.warning(
                "engine-runner startup: sandbox consumer group not ready yet, retrying",
                extra={"context": {"attempt": attempt, "max_attempts": _STARTUP_RETRY_ATTEMPTS, "error": str(exc)}},
            )
            await asyncio.sleep(_STARTUP_RETRY_DELAY_S)
    assert last_exc is not None
    raise last_exc


async def run() -> None:
    settings = _settings_from_env()
    redis = aioredis.Redis.from_url(settings["redis_url"])
    blobstore = LocalFilesystemBlobStore(root=Path(settings["blobstore_root"]))
    engines_by_name = sandbox_engines(
        vllm_base_url=settings["vllm_base_url"],
        llm_api_key=settings["llm_api_key"] or None,
        llm_model=settings["llm_model"] or None,
        llm_engine_timeout_s=float(settings["llm_engine_timeout_s"]),
    )
    consumer = f"engine-runner-{uuid.uuid4().hex[:8]}"
    interval_s = float(settings["tick_interval_s"])

    await _ensure_sandbox_group_with_retry(redis)
    _logger.info(
        "engine-runner starting",
        extra={
            "context": {
                "consumer": consumer,
                "engines": sorted(engines_by_name.keys()),
                "redis_url": settings["redis_url"],
                "blobstore_root": settings["blobstore_root"],
            }
        },
    )

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop_event.set)

    while not stop_event.is_set():
        try:
            processed = await sandbox_engine_tick(
                redis, blobstore, engines_by_name=engines_by_name, consumer=consumer
            )
            if processed:
                _logger.info("engine-runner tick processed jobs", extra={"context": {"count": processed}})
        except Exception:
            _logger.exception("engine-runner tick failed - continuing")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval_s)
        except TimeoutError:
            pass

    await redis.aclose()
    _logger.info("engine-runner stopped", extra={"context": {"consumer": consumer}})


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
