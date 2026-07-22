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
