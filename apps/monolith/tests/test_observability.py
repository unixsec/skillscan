"""Tests for `common.observability` (coding spec §11.7). Real
`prometheus_client`/`opentelemetry-sdk` objects throughout - no mocking - a
fresh `CollectorRegistry`/`InMemorySpanExporter` per test gives full
inspection without needing an actual Prometheus/OTel collector running.
"""

from __future__ import annotations

from common.observability import SecurityMetrics, get_tracer, scan_trace_span
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from prometheus_client import generate_latest

#: The EXACT `# HELP` text every collector must expose, hand-written here and
#: deliberately NOT read off `SecurityMetrics` - a table derived from the class
#: under test agrees with that class by construction and could never catch a
#: description that lies about what is counted.
#:
#: Imported by `test_infra_router.py` so the same strings are re-checked in the
#: real `GET /metrics` exposition, which is where they actually reach a reader.
#: Changing a string here is a deliberate act: the HELP text is the only
#: description that travels with a scrape, so editing one changes what every
#: dashboard and alert built on that metric claims.
EXPECTED_HELP: dict[str, str] = {
    "skillscan_worker_failures_total": (
        "Monolith background worker tick failures - the separate engine-runner "
        "process is NOT counted here and is unmeasured"
    ),
    "skillscan_cross_scope_access_attempts_total": (
        "Object-level authorization denials (IDOR attempts)"
    ),
    "skillscan_introspection_failures_total": "OIDC/OAuth2 token introspection failures",
    "skillscan_allowlist_entries_total": "Allowlist entries created (growth indicator)",
    "skillscan_audit_intent_unchained": "Current count of audit_intent rows not yet chained",
    "skillscan_reconciliation_inactive": (
        "1 if poll reconciliation is disabled (degraded posture), else 0"
    ),
    "skillscan_reconciliation_orphan_total": (
        "ORPHAN reconciliation outcomes detected (published, no verdict on record) - "
        "PUSH PATH ONLY: the poll detector (reeval.service.run_poll_reconciliation) "
        "has no production caller, so this can only rise on an event the marketplace "
        "chooses to send"
    ),
    "skillscan_sandbox_egress_denied_total": (
        "Sandbox network egress attempts denied by NetworkPolicy - NEVER WIRED: no "
        "process in this system observes a NetworkPolicy denial, so 0 means NOT "
        "MEASURED, never 'no denials happened'"
    ),
    "skillscan_external_egress_attempts_total": (
        "A hostname pinned as internal-only failed re-validation - an attempted egress "
        "to a non-internal address OR a DNS outage of that host (both are refused, and "
        "this counter cannot tell them apart) - must always be 0"
    ),
}


def help_lines_of(registry_owner: SecurityMetrics) -> dict[str, str]:
    """`{metric name: HELP text}` as a scraper would parse it, from the real
    exposition rather than from `Counter._documentation` - the exposition is
    what a dashboard reads, and it is the only place a HELP string can be
    checked as a reader receives it."""
    body = generate_latest(registry_owner.registry).decode("utf-8")
    lines = {}
    for line in body.splitlines():
        if not line.startswith("# HELP "):
            continue
        _hash, _help, name, documentation = line.split(" ", 3)
        lines[name] = documentation
    return lines


class TestSecurityMetrics:
    def test_fresh_instances_use_independent_registries(self) -> None:
        # SECURITY: two instances must never collide (e.g. across tests, or
        # multiple in-process components) - each gets its own registry unless
        # one is explicitly shared.
        a = SecurityMetrics()
        b = SecurityMetrics()
        a.worker_failures_total.inc()
        assert a.registry.get_sample_value("skillscan_worker_failures_total") == 1.0
        assert b.registry.get_sample_value("skillscan_worker_failures_total") == 0.0

    def test_worker_failures_counter_increments(self) -> None:
        metrics = SecurityMetrics()
        metrics.worker_failures_total.inc()
        metrics.worker_failures_total.inc()
        assert metrics.registry.get_sample_value("skillscan_worker_failures_total") == 2.0

    def test_cross_scope_access_attempts_counter_increments(self) -> None:
        metrics = SecurityMetrics()
        metrics.cross_scope_access_attempts_total.inc()
        assert (
            metrics.registry.get_sample_value("skillscan_cross_scope_access_attempts_total") == 1.0
        )

    def test_external_egress_attempts_starts_at_zero(self) -> None:
        # SECURITY: this is the metric that must be permanently 0 in a
        # correctly-configured deployment - confirm the honest baseline is
        # actually 0, not some nonzero default that would mask a real breach.
        metrics = SecurityMetrics()
        assert metrics.registry.get_sample_value("skillscan_external_egress_attempts_total") == 0.0

    def test_external_egress_attempt_recorded_if_it_ever_happens(self) -> None:
        metrics = SecurityMetrics()
        metrics.external_egress_attempts_total.inc()
        assert metrics.registry.get_sample_value("skillscan_external_egress_attempts_total") == 1.0

    def test_audit_intent_unchained_gauge_reflects_current_count(self) -> None:
        metrics = SecurityMetrics()
        metrics.audit_intent_unchained.set(5)
        assert metrics.registry.get_sample_value("skillscan_audit_intent_unchained") == 5.0
        metrics.audit_intent_unchained.set(0)
        assert metrics.registry.get_sample_value("skillscan_audit_intent_unchained") == 0.0

    def test_reconciliation_orphan_counter_increments(self) -> None:
        metrics = SecurityMetrics()
        metrics.reconciliation_orphan_total.inc()
        assert metrics.registry.get_sample_value("skillscan_reconciliation_orphan_total") == 1.0

    def test_sandbox_egress_denied_counter_increments(self) -> None:
        metrics = SecurityMetrics()
        metrics.sandbox_egress_denied_total.inc()
        assert metrics.registry.get_sample_value("skillscan_sandbox_egress_denied_total") == 1.0


class TestHelpTextDescribesWhatIsActuallyCounted:
    """2026-07-29 honesty review. `worker_failures_total` shipped documented as
    "Engine-runner worker task failures" while its only writers were the
    MONOLITH's tick loop (`apps/monolith/worker.py`) - the engine-runner imports
    no `prometheus_client` at all and its own per-scan failure handler counts
    nothing. A reader of that metric at 0 concluded the engine-runner was
    failure-free; the truth was that it is entirely unmeasured.

    Nothing caught it because nothing anywhere asserted a HELP string.
    `test_infra_router.TestMetrics` asserts metric NAMES, the tests above assert
    sample VALUES, and neither a name nor a value can contradict a description.
    HELP is also the ONE field that travels with a scrape into a Grafana panel
    or an alert annotation, so a caveat that lives anywhere else - a Python
    comment beside the exposition handler, a task report - reaches nobody
    holding the number.
    """

    def test_every_collector_exposes_the_documented_help_text(self) -> None:
        served = help_lines_of(SecurityMetrics())
        for name, expected in EXPECTED_HELP.items():
            assert served.get(name) == expected, (
                f"{name}'s HELP text does not match what this test documents. "
                "If the change is deliberate, update EXPECTED_HELP - but first "
                "check the new text against the metric's actual writers: this "
                "guard exists because one described a process it never counted."
            )

    def test_no_collector_escapes_the_table(self) -> None:
        # Coverage, in the derived direction on purpose: a collector added to
        # `SecurityMetrics` without a HELP entry above fails HERE rather than
        # shipping undescribed. `_created` samples repeat their parent's HELP
        # (prometheus_client emits one per Counter) and are not separate
        # collectors, so they are excluded rather than given their own row.
        served = {
            name for name in help_lines_of(SecurityMetrics()) if not name.endswith("_created")
        }
        assert served == set(EXPECTED_HELP)


class TestRecordCrossScopeAttempt:
    """Task 13 (2026-07-29): the helper exists so the five production call
    sites share ONE definition of what qualifies. These tests pin the
    behaviour; the docstring on `SecurityMetrics.record_cross_scope_attempt`
    is the authoritative statement of the boundary, and the sites that must
    NOT call it (role/scope denials, SoD refusals, plain not-founds) are
    asserted end-to-end in `test_router.py` / `test_marketplace_router.py`,
    since a "this code path does not increment" claim can only be made where
    the code path actually runs.
    """

    def test_each_call_records_one_attempt(self) -> None:
        metrics = SecurityMetrics()
        metrics.record_cross_scope_attempt()
        metrics.record_cross_scope_attempt()
        assert (
            metrics.registry.get_sample_value("skillscan_cross_scope_access_attempts_total") == 2.0
        )

    def test_it_touches_nothing_else(self) -> None:
        # An unlabeled registry gives no way to attribute a stray increment
        # after the fact, so confirm the helper writes exactly one series.
        metrics = SecurityMetrics()
        metrics.record_cross_scope_attempt()
        for other in (
            "skillscan_worker_failures_total",
            "skillscan_introspection_failures_total",
            "skillscan_allowlist_entries_total",
            "skillscan_reconciliation_orphan_total",
            "skillscan_sandbox_egress_denied_total",
            "skillscan_external_egress_attempts_total",
        ):
            assert metrics.registry.get_sample_value(other) == 0.0


class TestObserveReconciliationMode:
    def test_poll_enabled_sets_inactive_gauge_to_zero(self) -> None:
        metrics = SecurityMetrics()
        metrics.observe_reconciliation_mode(poll_enabled=True)
        assert metrics.registry.get_sample_value("skillscan_reconciliation_inactive") == 0.0

    def test_poll_disabled_sets_inactive_gauge_to_one(self) -> None:
        metrics = SecurityMetrics()
        metrics.observe_reconciliation_mode(poll_enabled=False)
        assert metrics.registry.get_sample_value("skillscan_reconciliation_inactive") == 1.0


class TestScanTraceSpan:
    def test_span_correlated_by_scan_id(self) -> None:
        provider = TracerProvider()
        exporter = InMemorySpanExporter()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        tracer = get_tracer(tracer_provider=provider)

        with scan_trace_span("scan-123", tracer=tracer):
            pass

        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].name == "scan"
        assert spans[0].attributes is not None
        assert spans[0].attributes["scan_id"] == "scan-123"

    def test_custom_span_name_used(self) -> None:
        provider = TracerProvider()
        exporter = InMemorySpanExporter()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        tracer = get_tracer(tracer_provider=provider)

        with scan_trace_span("scan-456", name="worker_tick", tracer=tracer):
            pass

        spans = exporter.get_finished_spans()
        assert spans[0].name == "worker_tick"

    def test_exception_inside_span_still_ends_it_and_records_it(self) -> None:
        provider = TracerProvider()
        exporter = InMemorySpanExporter()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        tracer = get_tracer(tracer_provider=provider)

        class _Boom(Exception):
            pass

        try:
            with scan_trace_span("scan-789", tracer=tracer):
                raise _Boom("failure inside the span")
        except _Boom:
            pass

        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].status.status_code.name == "ERROR"

    def test_default_tracer_is_a_working_no_op_without_a_configured_provider(self) -> None:
        # SECURITY/hygiene: this module must never require an application to
        # configure OTel just to call scan_trace_span - the default (global)
        # tracer provider is a harmless no-op that still lets the `with`
        # block run normally.
        with scan_trace_span("scan-default") as span:
            assert span is not None
