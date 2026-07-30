"""Self-defense metrics + OTel tracing (coding spec §11.7).

SECURITY: `external_egress_attempts_total` must be permanently 0 in a
correctly-configured deployment (coding spec: "对外出站尝试(须恒为 0,非 0 告警)")
- this module only RECORDS the metric; alerting on a nonzero value is an
ops-layer concern (a Prometheus alerting rule / Alertmanager), outside what a
single Python process can enforce on itself. Likewise `reconciliation_inactive`
only reflects configuration state recorded here - `reeval.reconciliation.
reconciliation_mode_warnings` is what actually judges whether a given poll/push
combination is degraded.

Zero-network by construction: `prometheus_client`/`opentelemetry-sdk` are
in-process instrumentation libraries - metrics accumulate in a
`CollectorRegistry` and spans go through whatever `SpanProcessor`/exporter is
configured (or nowhere, if none is - importing/using either library never
itself opens a network connection).

EXPOSED (Task 12, 2026-07-29 milestone C): `GET /metrics`
(`apps/monolith/modules/gateway/infra_router.py`) serves whichever registry
is parked on the live `ScanRuntime.security_metrics` (`gateway/runtime.py`) -
one instance for the process's lifetime, not a fresh one per request.
Before this, the registry these collectors live in was built and read by
nothing outside this module's own tests.

HELP TEXT IS PART OF THE MEASUREMENT (2026-07-29 honesty review). A HELP
string is the only description that travels with a scrape - it is what a
Grafana panel, an alert annotation and a `curl /metrics` all show, and a
caveat kept in a Python comment beside the exposition handler reaches nobody
who reads the number. So every caveat that changes what a value MEANS lives
in the HELP text here, not in a comment: which process a counter covers,
whether a `0` is a measurement or an absence of measurement, and which
condition other than the obvious one can move it. `test_observability.py`
pins the exact strings, and `test_infra_router.py` re-checks them in the real
exposition output - that guard exists because `worker_failures_total`
described "engine-runner worker task failures" for a whole milestone while
counting only the monolith's tick, and every test asserted metric NAMES.

THE ENGINE-RUNNER IS DELIBERATELY UNMEASURED, and that is the honest state
rather than an oversight. `services/engine_runner/` is a separate deployable
that imports no `prometheus_client`, exposes only a readiness HTTP handler
(`main._make_readiness_handler`, `/healthz` + `/readyz`), and is reachable by
nothing that scrapes. Giving it a failure counter means a second registry, a
`/metrics` route on that handler, a NetworkPolicy ingress rule for the
scraper and a scrape target - four changes, none of which this module can
make - and a half-done version of it (a registry nobody reads) is exactly the
"instrumentation that looks wired and reports nothing" failure Task 12/13
found twice. Until those exist, the engine-runner's own per-scan failure
handler (`services/engine_runner/worker.py`) counts nothing and says so in
place, and no metric here implies otherwise.

BOUNDARY vs. the per-engine health table (milestone C tasks 7-10, which
persists `EngineResultRow`-shaped data to MySQL): these nine collectors are
process-wide, unlabeled by scan_id or engine, in-memory only (reset on every
restart, no retention policy this codebase controls - a Prometheus TSDB's
scrape/retention config is the operator's, not this app's). They answer
"how is THIS PROCESS doing in aggregate right now" - alerting/dashboard
questions - never "how did engine X do on scan Y", which is the health
table's job and requires a queryable, retained, per-row answer this registry
structurally cannot give (a `scan_id`-labeled Prometheus series would be
unbounded cardinality over the process's lifetime). Do not add a per-engine
or per-scan label to anything in `SecurityMetrics` - extend the health table
instead; do not add a retention/query API in front of this registry - that
is what the health table is for.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from opentelemetry import trace
from opentelemetry.trace import Tracer
from prometheus_client import CollectorRegistry, Counter, Gauge

_NAMESPACE = "skillscan"


class SecurityMetrics:
    """coding spec §11.7's named self-defense metrics, each a real
    `prometheus_client` collector. `registry` defaults to a FRESH
    `CollectorRegistry` (never the global default registry) so multiple
    instances - notably in tests - never collide; production wires one
    instance's `.registry` into `GET /metrics`
    (`apps/monolith/modules/gateway/infra_router.py`, via
    `ScanRuntime.security_metrics` - see that field's own comment)."""

    def __init__(self, *, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry if registry is not None else CollectorRegistry()
        self.worker_failures_total = Counter(
            "worker_failures_total",
            # HONESTY (2026-07-29): this said "Engine-runner worker task
            # failures" and counted no such thing. Its only writers are
            # `apps/monolith/worker.py`'s tick loop; a dashboard built on the
            # old text read an untouched 0 as "the engine-runner is not
            # failing", when the engine-runner is not measured at all. See
            # this module's docstring for why it stays that way for now.
            "Monolith background worker tick failures - the separate "
            "engine-runner process is NOT counted here and is unmeasured",
            namespace=_NAMESPACE,
            registry=self.registry,
        )
        self.cross_scope_access_attempts_total = Counter(
            "cross_scope_access_attempts_total",
            "Object-level authorization denials (IDOR attempts)",
            namespace=_NAMESPACE,
            registry=self.registry,
        )
        self.introspection_failures_total = Counter(
            "introspection_failures_total",
            "OIDC/OAuth2 token introspection failures",
            namespace=_NAMESPACE,
            registry=self.registry,
        )
        self.allowlist_entries_total = Counter(
            "allowlist_entries_total",
            "Allowlist entries created (growth indicator)",
            namespace=_NAMESPACE,
            registry=self.registry,
        )
        self.audit_intent_unchained = Gauge(
            "audit_intent_unchained",
            "Current count of audit_intent rows not yet chained",
            namespace=_NAMESPACE,
            registry=self.registry,
        )
        self.reconciliation_inactive = Gauge(
            "reconciliation_inactive",
            "1 if poll reconciliation is disabled (degraded posture), else 0",
            namespace=_NAMESPACE,
            registry=self.registry,
        )
        self.reconciliation_orphan_total = Counter(
            "reconciliation_orphan_total",
            "ORPHAN reconciliation outcomes detected (published, no verdict on "
            "record) - PUSH PATH ONLY: the poll detector "
            "(reeval.service.run_poll_reconciliation) has no production caller, "
            "so this can only rise on an event the marketplace chooses to send",
            namespace=_NAMESPACE,
            registry=self.registry,
        )
        self.sandbox_egress_denied_total = Counter(
            "sandbox_egress_denied_total",
            "Sandbox network egress attempts denied by NetworkPolicy - NEVER "
            "WIRED: no process in this system observes a NetworkPolicy denial, "
            "so 0 means NOT MEASURED, never 'no denials happened'",
            namespace=_NAMESPACE,
            registry=self.registry,
        )
        # SECURITY: must be permanently 0 in a correctly-configured deployment.
        self.external_egress_attempts_total = Counter(
            "external_egress_attempts_total",
            "A hostname pinned as internal-only failed re-validation - an "
            "attempted egress to a non-internal address OR a DNS outage of that "
            "host (both are refused, and this counter cannot tell them apart) - "
            "must always be 0",
            namespace=_NAMESPACE,
            registry=self.registry,
        )

    def observe_reconciliation_mode(self, *, poll_enabled: bool) -> None:
        self.reconciliation_inactive.set(0.0 if poll_enabled else 1.0)

    def record_cross_scope_attempt(self) -> None:
        """One authoritative definition of what `cross_scope_access_attempts_
        total` counts, so the five call sites cannot drift apart (Task 13,
        2026-07-29).

        COUNTS: object-level authorization denials only - a principal asked to
        read or write a specific object that exists and belongs to a DIFFERENT
        principal. `GET /v1/scans/{id}` and `.../sarif` refusing a scan the
        caller is not in `scan_submitter` for; `GET /v1/market/skills/{id}`
        refusing another service account's skill; `POST /v1/scans` and
        `POST /v1/market/scans` refusing to write a `skill_id` someone else owns
        (pre-flight and the in-transaction TOCTOU re-check both). This is the IDOR signal: a
        nonzero rate means someone is naming objects that are not theirs.

        DOES NOT COUNT, deliberately:
        - Missing role/scope (`require_role`, `require_human_role`,
          marketplace's `_require_scope`). Those fire on a misconfigured
          client far more often than on an attacker, and they say nothing
          about WHICH object was named - folding them in would swamp the IDOR
          signal in an unlabeled counter that could no longer be decomposed.
        - Separation-of-duties refusals (`reviews.SodViolationError`). "You may
          not approve your own scan" is a refusal aimed at a principal who
          legitimately has access to that very object; it is a different
          control with a different meaning.
        - A plain "no such object" 404. The response deliberately makes that
          indistinguishable from a cross-scope denial, which is exactly why
          the distinction has to be recorded at the branch or lost.
        """
        self.cross_scope_access_attempts_total.inc()


def get_tracer(*, tracer_provider: trace.TracerProvider | None = None) -> Tracer:
    """Thin wrapper over `opentelemetry.trace.get_tracer` - returns a working
    no-op tracer if no provider was ever configured (`trace.set_tracer_provider`
    is an application-startup concern, not this module's), or a real SDK-backed
    tracer if `tracer_provider` is supplied (tests pass one backed by an
    `InMemorySpanExporter` to inspect emitted spans)."""
    return trace.get_tracer("skillscan", tracer_provider=tracer_provider)


@contextmanager
def scan_trace_span(
    scan_id: str, *, name: str = "scan", tracer: Tracer | None = None
) -> Iterator[trace.Span]:
    """OTel span correlated by scan_id (coding spec: "OTel trace(scan_id 关联)")."""
    active_tracer = tracer if tracer is not None else get_tracer()
    with active_tracer.start_as_current_span(name, attributes={"scan_id": scan_id}) as span:
        yield span
