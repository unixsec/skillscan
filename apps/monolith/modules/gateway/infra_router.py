"""`GET /.well-known/jwks.json`, `GET /healthz`, `GET /readyz`, `GET /metrics`
(coding spec §9/§11.7) - deliberately UNPREFIXED (not under `/v1`) and PUBLIC
(no auth/CSRF), matching the spec table exactly: these are consumed by the
marketplace (JWKS, INV-13 signature verification), by orchestration probes
(health/ready), and by a Prometheus scraper (metrics), none of which holds a
skillscan session.

`GET /metrics` (Task 12, 2026-07-29 milestone C): unlike the other three
paths here, it is deliberately NOT added to `web/nginx.conf` or the Helm
chart's `templates/web.yaml` ConfigMap (INV-14 - a new endpoint must not
widen the browser-facing gateway's surface). `/healthz`/`/readyz` being
proxied there is harmless-but-redundant: `monolith-deployment.yaml`'s own
livenessProbe/readinessProbe hit this pod's `containerPort: 8000` directly
(kubelet, not nginx), and `default-deny.yaml` records that kubelet's probe
traffic is not blocked by NetworkPolicy on this cluster's CNI either.
Prometheus scraping has no such privileged bypass and no built-in auth, so
network-layer allow-listing is the only control - see
`deploy/networkpolicy/monolith-metrics-ingress.yaml`, additive to
`monolith-ingress.yaml` (which only names the web pod).
"""

from __future__ import annotations

from typing import Any

from common.blobstore import ShareProbeMonitor
from common.log import get_logger
from fastapi import APIRouter, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
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


@router.get("/metrics")
async def metrics(request: Request) -> Response:
    # SECURITY: Prometheus's exposition format carries no credential by
    # convention (coding spec §11.7) - no auth check here is deliberate, not
    # an oversight; see this module's docstring for why the network layer
    # (deploy/networkpolicy/monolith-metrics-ingress.yaml), not this handler,
    # is what actually gates who can reach this.
    #
    # SECURITY/OBSERVABILITY. Task 12 exposed this endpoint over a registry
    # with zero production writers; Task 13 (2026-07-29) wired eight of the
    # nine, each verified by constructing the condition and watching the value
    # move. What a 0 means is therefore PER-METRIC, not uniform - one is never
    # measured at all, one only rises on a path with no scheduler, and one
    # fires on a DNS outage as well as on the attack it is named for.
    #
    # Those caveats are NOT repeated here, on purpose (2026-07-29 honesty
    # review): they used to live in this comment only, where nobody holding
    # the scraped number could see them. Each now lives in its collector's
    # HELP string in `libs/common/observability.py`, which is the one field
    # that travels with the exposition below into a dashboard or an alert -
    # read them there, and add any new caveat there rather than here.
    #
    # This handler is a straight `generate_latest` and adds nothing: whatever
    # a metric means, it means it before this line runs. See task-13-report.md.
    runtime = _get_scan_runtime(request)
    payload = generate_latest(runtime.security_metrics.registry)
    return Response(content=payload, media_type=CONTENT_TYPE_LATEST)
