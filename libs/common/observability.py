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
    instance's `.registry` into whatever exposes `GET /metrics` (outside this
    module's scope - see coding spec §9's `/healthz`/`/readyz` precedent for
    where such an endpoint would live)."""

    def __init__(self, *, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry if registry is not None else CollectorRegistry()
        self.worker_failures_total = Counter(
            "worker_failures_total",
            "Engine-runner worker task failures",
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
            "ORPHAN reconciliation outcomes detected (published, no verdict on record)",
            namespace=_NAMESPACE,
            registry=self.registry,
        )
        self.sandbox_egress_denied_total = Counter(
            "sandbox_egress_denied_total",
            "Sandbox network egress attempts denied by NetworkPolicy",
            namespace=_NAMESPACE,
            registry=self.registry,
        )
        # SECURITY: must be permanently 0 in a correctly-configured deployment.
        self.external_egress_attempts_total = Counter(
            "external_egress_attempts_total",
            "Attempted network egress to a non-internal address - must always be 0",
            namespace=_NAMESPACE,
            registry=self.registry,
        )

    def observe_reconciliation_mode(self, *, poll_enabled: bool) -> None:
        self.reconciliation_inactive.set(0.0 if poll_enabled else 1.0)


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
