"""`GET /.well-known/jwks.json`, `GET /healthz`, `GET /readyz` (coding spec §9)
- deliberately UNPREFIXED (not under `/v1`) and PUBLIC (no auth/CSRF), matching
the spec table exactly: these are consumed by the marketplace (JWKS, INV-13
signature verification) and by orchestration probes (health/ready), neither
of which holds a skillscan session.
"""

from __future__ import annotations

from typing import Any

from common.blobstore import ShareProbeMonitor
from common.log import get_logger
from fastapi import APIRouter, Request, Response
from sqlalchemy import text

from .runtime import ScanRuntime

router = APIRouter()

_logger = get_logger("skillscan.gateway.infra")


def _get_scan_runtime(request: Request) -> ScanRuntime:
    runtime: ScanRuntime = request.app.state.scan
    return runtime


@router.get("/.well-known/jwks.json")
async def get_jwks(request: Request) -> dict[str, Any]:
    runtime = _get_scan_runtime(request)
    return await runtime.signer.jwks()


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    # SECURITY: liveness only - "is this process alive", never checks a
    # dependency (that's /readyz's job). A liveness probe that depends on
    # Redis/MySQL would cause an otherwise-healthy process to be killed and
    # restarted for a downstream outage it can't fix by restarting.
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(request: Request, response: Response) -> dict[str, Any]:
    # SECURITY: fail-closed readiness - any dependency check failing takes
    # this instance out of load-balancer rotation (503), never reports ready
    # on a guess. Each check is independent so one failure doesn't mask which
    # dependency is actually down.
    runtime = _get_scan_runtime(request)
    checks: dict[str, bool] = {}

    try:
        checks["redis"] = bool(await runtime.redis.ping())
    except Exception:  # noqa: BLE001 - any Redis failure means not-ready, never a crash here
        checks["redis"] = False

    try:
        async with runtime.orchestration_session_factory() as session:
            await session.execute(text("SELECT 1"))
        checks["orchestration_db"] = True
    except Exception:  # noqa: BLE001 - any DB failure means not-ready, never a crash here
        checks["orchestration_db"] = False

    # 里程碑 E spec §4.3: the monolith and the engine-runner MUST see the same
    # blob store. When they don't, nothing errors - every pod is Running, this
    # endpoint's other two checks pass, and scans just sit at RUNNING forever.
    # `main.create_app` runs the probe in the background and parks the monitor
    # here; a `None` monitor means the check isn't running in this process
    # (e.g. a test-built app, or a non-filesystem store), which is not evidence
    # that sharing is broken - so it is left out of `checks` entirely rather
    # than reported as a passing check that never ran.
    share_monitor: ShareProbeMonitor | None = getattr(
        request.app.state, "blobstore_share_monitor", None
    )
    if share_monitor is not None:
        checks["blobstore_shared"] = share_monitor.status.ready

    ready = all(checks.values())
    response.status_code = 200 if ready else 503
    return {"status": "ok" if ready else "not_ready", "checks": checks}
