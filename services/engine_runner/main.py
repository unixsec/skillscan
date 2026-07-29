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
import json
import os
import signal
import socket
import threading
import time
import uuid
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import redis.asyncio as aioredis
from common.blobstore import (
    ENGINE_RUNNER_PROBE_ROLE,
    MONOLITH_PROBE_ROLE,
    SHARE_PROBE_GRACE_S,
    SHARE_PROBE_INTERVAL_S,
    LocalFilesystemBlobStore,
    ShareProbeMonitor,
    ShareStatus,
    log_share_status,
    probe_identity,
)
from common.log import get_logger

from engine_runner.sandbox_engines import sandbox_engines
from engine_runner.worker import ensure_sandbox_group, sandbox_engine_tick

_logger = get_logger("skillscan.engine_runner.main")


def _settings_from_env() -> dict[str, str]:
    return {
        "redis_url": os.environ.get("SKILLSCAN_REDIS_URL", "redis://localhost:6379/0"),
        "blobstore_root": os.environ.get(
            "SKILLSCAN_BLOBSTORE_ROOT", "/var/lib/skillscan/blobstore"
        ),
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
        # 里程碑 E spec §4.3 - shared-blobstore self-check.
        "share_check": os.environ.get("SKILLSCAN_BLOBSTORE_SHARE_CHECK", "1"),
        "share_grace_s": os.environ.get(
            "SKILLSCAN_BLOBSTORE_SHARE_GRACE_S", str(SHARE_PROBE_GRACE_S)
        ),
        "share_interval_s": os.environ.get(
            "SKILLSCAN_BLOBSTORE_SHARE_INTERVAL_S", str(SHARE_PROBE_INTERVAL_S)
        ),
        # Readiness endpoint. Unlike the monolith this process has no HTTP
        # surface of its own, and the self-check is worth nothing if kubelet
        # cannot ask about it - "0" disables the listener entirely.
        "ready_port": os.environ.get("SKILLSCAN_ENGINE_RUNNER_READY_PORT", "8080"),
        # SECURITY: binds all interfaces by default because a kubelet probe
        # reaches the pod on its pod IP, not on loopback. What is exposed is
        # two fixed JSON bodies ({"status": ...}) on GET /healthz and
        # GET /readyz - no request body is read, no path is used to touch the
        # filesystem, every other request gets a 404. Override to bind
        # narrower where the deployment allows it.
        "ready_bind": os.environ.get("SKILLSCAN_ENGINE_RUNNER_READY_BIND", "0.0.0.0"),
    }


def _float_setting(settings: dict[str, str], key: str, default: float) -> float:
    try:
        return float(settings[key])
    except ValueError:
        _logger.warning(
            "engine-runner: setting is not a number - using the default",
            extra={"context": {"setting": key, "value": settings[key], "default": default}},
        )
        return default


class _ReadinessState:
    """Hand-off between the asyncio loop (writer) and the readiness HTTP thread
    (reader). No lock: `ShareStatus` is frozen and rebinding one attribute is
    atomic under the GIL, so a reader sees either the previous status or the
    new one, never a half-written one."""

    def __init__(self, status: ShareStatus) -> None:
        self.status = status


def _make_readiness_handler(state: _ReadinessState) -> type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        # HTTP/1.0 semantics (the default): each probe gets its own connection
        # and no keep-alive bookkeeping is needed.
        server_version = "skillscan-engine-runner"
        sys_version = ""

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's API
            path = self.path.split("?", 1)[0]
            if path == "/healthz":
                # Liveness: this process is running. Deliberately independent
                # of the share check - a broken shared volume must not get the
                # pod killed and restarted, restarting cannot fix a volume.
                self._respond(200, {"status": "ok"})
            elif path == "/readyz":
                status = state.status
                self._respond(
                    200 if status.ready else 503,
                    {"status": "ok" if status.ready else "not_ready"},
                )
            else:
                self._respond(404, {"status": "not_found"})

        def _respond(self, code: int, payload: dict[str, str]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            # Default goes straight to stderr, unstructured, once per probe -
            # roughly every 10s forever. Route it through the project logger at
            # debug level instead of drowning the real logs.
            _logger.debug("engine-runner readiness request", extra={"context": {"args": args}})

    return _Handler


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
                extra={
                    "context": {
                        "attempt": attempt,
                        "max_attempts": _STARTUP_RETRY_ATTEMPTS,
                        "error": str(exc),
                    }
                },
            )
            await asyncio.sleep(_STARTUP_RETRY_DELAY_S)
    assert last_exc is not None
    raise last_exc


_ALWAYS_READY = ShareStatus(
    identity="",
    ready=True,
    peers=frozenset(),
    in_grace=False,
    checked_at=None,
    changed=False,
)


def _build_share_probe_monitor(
    blobstore: LocalFilesystemBlobStore, settings: dict[str, str], *, started_at: float
) -> ShareProbeMonitor | None:
    """The blobstore share self-check (里程碑 E spec §4.3), or None when off.

    CORRECTNESS: this process reads `artifacts/<hash>/pkg.tar` written by the
    monolith and writes `findings/<scan_id>/<engine>.json` back for it to read.
    If the two are not on the same store, nothing errors here - the dispatch
    message never arrives (or its artifact is missing) and the monolith's scans
    sit at RUNNING forever. Detecting it is the only way an operator finds out
    before someone notices the queue never drains.
    """
    if settings["share_check"].lower() not in {"1", "true", "yes", "on"}:
        _logger.warning(
            "blobstore share self-check DISABLED - if this process and the monolith "
            "end up on different volumes, scans will stay RUNNING forever with no error",
            extra={"context": {"metric": "blobstore_share_check_disabled"}},
        )
        return None
    instance = os.environ.get("HOSTNAME") or socket.gethostname()
    return ShareProbeMonitor(
        blobstore,
        identity=probe_identity(ENGINE_RUNNER_PROBE_ROLE, instance),
        peer_role=MONOLITH_PROBE_ROLE,
        started_at=started_at,
        grace_s=_float_setting(settings, "share_grace_s", SHARE_PROBE_GRACE_S),
    )


def _start_readiness_server(
    state: _ReadinessState, settings: dict[str, str]
) -> ThreadingHTTPServer | None:
    port = int(settings["ready_port"])
    if port == 0:
        _logger.warning(
            "engine-runner readiness endpoint disabled - kubelet cannot observe the "
            "blobstore share self-check in this process",
            extra={"context": {"metric": "engine_runner_readyz_disabled"}},
        )
        return None
    # A bind failure is deliberately fatal: a pod whose readiness endpoint
    # never came up would otherwise look fine to everyone except kubelet.
    server = ThreadingHTTPServer((settings["ready_bind"], port), _make_readiness_handler(state))
    thread = threading.Thread(target=server.serve_forever, name="readyz", daemon=True)
    thread.start()
    _logger.info(
        "engine-runner readiness endpoint listening",
        extra={"context": {"bind": settings["ready_bind"], "port": port}},
    )
    return server


async def _run_share_probe_loop(
    monitor: ShareProbeMonitor,
    state: _ReadinessState,
    *,
    interval_s: float,
    stop_event: asyncio.Event,
) -> None:
    """ROBUSTNESS: the probe's filesystem work runs in a thread - the shared
    store is an RWX volume (NFS in the reference deployment) and a hung server
    there must degrade readiness, not freeze this process's event loop."""
    while not stop_event.is_set():
        try:
            status = await asyncio.to_thread(monitor.check, time.time())
            state.status = status
            log_share_status(_logger, status, peer_role=monitor.peer_role)
        except Exception:  # noqa: BLE001 - a probe failure must never kill the loop
            _logger.exception("blobstore share probe failed - continuing")
        with suppress(TimeoutError):
            await asyncio.wait_for(stop_event.wait(), timeout=interval_s)


async def run() -> None:
    settings = _settings_from_env()
    started_at = time.time()
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

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop_event.set)

    # ORDERING: the share probe and the readiness listener start BEFORE the
    # Redis consumer-group retry below, which can block for a full minute on a
    # cold cluster. The monolith's own grace window is already counting down
    # while that happens, and it can only stay ready if it can see this
    # process's probe file - announcing ourselves after a 60s Redis wait would
    # make the monolith report a sharing failure that isn't one.
    share_monitor = _build_share_probe_monitor(blobstore, settings, started_at=started_at)
    ready_state = _ReadinessState(
        share_monitor.status if share_monitor is not None else _ALWAYS_READY
    )
    ready_server = _start_readiness_server(ready_state, settings)
    share_task: asyncio.Task[None] | None = None
    if share_monitor is not None:
        share_task = asyncio.create_task(
            _run_share_probe_loop(
                share_monitor,
                ready_state,
                interval_s=_float_setting(settings, "share_interval_s", SHARE_PROBE_INTERVAL_S),
                stop_event=stop_event,
            )
        )

    await _ensure_sandbox_group_with_retry(redis)
    _logger.info(
        "engine-runner starting",
        extra={
            "context": {
                "consumer": consumer,
                "engines": sorted(engines_by_name.keys()),
                "redis_url": settings["redis_url"],
                "blobstore_root": settings["blobstore_root"],
                "share_probe_identity": share_monitor.identity if share_monitor else None,
            }
        },
    )

    while not stop_event.is_set():
        try:
            processed = await sandbox_engine_tick(
                redis, blobstore, engines_by_name=engines_by_name, consumer=consumer
            )
            if processed:
                _logger.info(
                    "engine-runner tick processed jobs", extra={"context": {"count": processed}}
                )
        except Exception:
            _logger.exception("engine-runner tick failed - continuing")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval_s)
        except TimeoutError:
            pass

    if share_task is not None:
        share_task.cancel()
        with suppress(asyncio.CancelledError):
            await share_task
    if ready_server is not None:
        ready_server.shutdown()
        ready_server.server_close()
    await redis.aclose()
    _logger.info("engine-runner stopped", extra={"context": {"consumer": consumer}})


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
