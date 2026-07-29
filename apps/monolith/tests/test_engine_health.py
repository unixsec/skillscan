"""Per-engine health capture at read-back (milestone C Task 8, design §3).

No infra needed: every test here drives `orchestration.aggregate` against an
in-memory dict blob store. The DB side of this feature - the real
`scan_engine_health` rows written inside the scoring transaction - is exercised
by `test_orchestration_pipeline.py::TestEngineHealthRows` against real MySQL,
which cannot run on a developer machine (see CLAUDE.md).

The property under test throughout: the fail-closed collapse that
`unavailable_engine_result` performs for the GATE (a missing blob becomes
`EngineStatus.ERROR`) must not reach the HEALTH record. That collapse is
acceptance criterion 8's failure mode, and it is why the storage layer could
not previously tell a broken engine from an absent one.
"""

from __future__ import annotations

import json

import pytest
from common.blobstore import BlobNotFoundError, findings_key
from common.engine_names import ENGINE_NAME_BY_LOCK_KEY, LOCK_KEY_BY_ENGINE_NAME
from engine_runner.sandbox_engines import SANDBOX_ENGINE_NAMES
from schemas.findings import serialize_engine_result
from skillscan_core import (
    DetectionCategory,
    EngineCapability,
    EngineMetadata,
    EngineResult,
    EngineStatus,
    Finding,
    GatePolicy,
    ScanMode,
    Severity,
    Verdict,
)

from monolith.modules.orchestration.aggregate import (
    EngineHealthRecord,
    EngineReportState,
    load_and_aggregate,
)
from monolith.modules.orchestration.floor import floor_engine_names

_SCAN_ID = "11111111-1111-1111-1111-111111111111"
_CONTENT_HASH = "a" * 64


class _DictBlobStore:
    """Minimal `BlobStorePort` - the point of these tests is what
    `load_and_aggregate` records, not how bytes are stored."""

    def __init__(self) -> None:
        self.blobs: dict[str, bytes] = {}

    def put(self, key: str, data: bytes) -> None:
        self.blobs[key] = data

    def get(self, key: str) -> bytes:
        try:
            return self.blobs[key]
        except KeyError:
            raise BlobNotFoundError(key) from None

    def list_prefix(self, prefix: str) -> list[str]:
        return [k for k in self.blobs if k.startswith(prefix)]

    def exists(self, key: str) -> bool:
        return key in self.blobs


def _policy(*, required: frozenset[str]) -> GatePolicy:
    return GatePolicy(
        version="test-engine-health",
        required_engines=required,
        hard_gate_rules=frozenset(),
        fail_closed_verdict=Verdict.BLOCK,
    )


def _finding(rule_id: str, engine: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        test_item_id="CODE-01",
        category=DetectionCategory.CODE,
        title="t",
        severity=Severity.LOW,
        confidence=0.5,
        source_engine=engine,
        source_capability=EngineCapability.STATIC,
    )


def _result(
    engine: str,
    *,
    status: EngineStatus = EngineStatus.OK,
    error: str | None = None,
    findings: tuple[Finding, ...] = (),
) -> EngineResult:
    return EngineResult(
        engine=EngineMetadata(
            name=engine,
            version="1.0",
            ruleset_digest="d",
            capabilities=frozenset({EngineCapability.STATIC}),
        ),
        findings=findings,
        status=status,
        scan_mode=ScanMode.STATIC,
        llm_used=False,
        error=error,
    )


def _write(
    store: _DictBlobStore,
    engine: str,
    result: EngineResult,
    *,
    analyze_duration_ms: int | None = None,
) -> None:
    store.put(
        findings_key(_SCAN_ID, engine),
        json.dumps(serialize_engine_result(result, analyze_duration_ms=analyze_duration_ms)).encode(
            "utf-8"
        ),
    )


def _health(store: _DictBlobStore, engines: tuple[str, ...]) -> dict[str, EngineHealthRecord]:
    aggregated = load_and_aggregate(
        store,
        scan_id=_SCAN_ID,
        content_hash=_CONTENT_HASH,
        engine_names=engines,
        policy=_policy(required=frozenset(engines)),
    )
    return {h.engine_name: h for h in aggregated.engine_health}


class TestErrorVersusNeverReported:
    """Acceptance criterion 8, the whole reason this table exists."""

    def test_a_reported_error_and_a_missing_blob_are_not_the_same_record(self) -> None:
        store = _DictBlobStore()
        _write(store, "broken", _result("broken", status=EngineStatus.ERROR, error="boom"))
        health = _health(store, ("broken", "absent"))

        assert health["broken"].report_state is EngineReportState.REPORTED
        assert health["broken"].engine_status is EngineStatus.ERROR
        assert health["broken"].error == "boom"

        assert health["absent"].report_state is EngineReportState.NOT_REPORTED
        # NOT EngineStatus.ERROR. `unavailable_engine_result` fabricates that
        # for the gate so it fails closed; inheriting the fabrication here is
        # precisely the defect - it would report a never-constructed engine as
        # a permanently failing one.
        assert health["absent"].engine_status is None

    def test_the_gate_still_sees_both_as_a_fail_closed_error(self) -> None:
        """The health split must NOT have loosened adjudication: a missing blob
        is still an unusable engine as far as `required_ok` is concerned."""
        store = _DictBlobStore()
        _write(store, "ok-engine", _result("ok-engine"))
        aggregated = load_and_aggregate(
            store,
            scan_id=_SCAN_ID,
            content_hash=_CONTENT_HASH,
            engine_names=("ok-engine", "absent"),
            policy=_policy(required=frozenset({"ok-engine", "absent"})),
        )
        assert aggregated.scan_result.required_ok is False

    def test_a_timeout_is_a_report_not_an_absence(self) -> None:
        """The engine that reports 'I timed out' told us something; the engine
        the sweep gave up on did not. `sweep_sandbox_wait_timeouts` exists
        precisely to let the first win that race, so the two must not merge."""
        store = _DictBlobStore()
        _write(store, "slow", _result("slow", status=EngineStatus.TIMEOUT, error="deadline"))
        health = _health(store, ("slow", "never"))
        assert health["slow"].report_state is EngineReportState.REPORTED
        assert health["slow"].engine_status is EngineStatus.TIMEOUT
        assert health["never"].report_state is EngineReportState.NOT_REPORTED

    def test_an_unreadable_blob_is_neither_of_the_other_two(self) -> None:
        store = _DictBlobStore()
        store.put(findings_key(_SCAN_ID, "garbage"), b"{not json")
        health = _health(store, ("garbage",))
        assert health["garbage"].report_state is EngineReportState.UNREADABLE
        assert health["garbage"].engine_status is None
        assert "schema validation failed" in (health["garbage"].error or "")

    def test_a_misdirected_write_files_under_the_key_we_looked_up(self) -> None:
        """A blob claiming another engine's identity is rejected fail-closed,
        and its health record is keyed on the name WE asked for - never on the
        name the untrusted blob claimed, which would let one engine's telemetry
        be filed under another's."""
        store = _DictBlobStore()
        _write(store, "expected", _result("impostor"))
        health = _health(store, ("expected",))
        assert set(health) == {"expected"}
        assert health["expected"].report_state is EngineReportState.UNREADABLE
        assert "identity mismatch" in (health["expected"].error or "")


class TestDurationHasThreeStates:
    """Task 7's own concern, made a storage property: `0` is a measurement."""

    def test_zero_is_recorded_as_zero_not_as_unknown(self) -> None:
        store = _DictBlobStore()
        _write(store, "floor", _result("floor"), analyze_duration_ms=0)
        health = _health(store, ("floor",))
        assert health["floor"].analyze_duration_ms == 0
        assert health["floor"].analyze_duration_ms is not None

    def test_an_unmeasured_blob_is_none_not_zero(self) -> None:
        """A blob written by a pre-Task-7 engine-runner image omits the key
        entirely. Defaulting it to 0 would record 'every engine on the
        not-yet-upgraded pod finished instantly'."""
        store = _DictBlobStore()
        _write(store, "old", _result("old"))
        assert _health(store, ("old",))["old"].analyze_duration_ms is None

    def test_a_real_measurement_survives_unchanged(self) -> None:
        store = _DictBlobStore()
        _write(store, "sandboxed", _result("sandboxed"), analyze_duration_ms=1234)
        assert _health(store, ("sandboxed",))["sandboxed"].analyze_duration_ms == 1234

    def test_an_engine_that_never_reported_has_no_duration_at_all(self) -> None:
        health = _health(_DictBlobStore(), ("absent",))
        assert health["absent"].analyze_duration_ms is None
        assert health["absent"].report_state is EngineReportState.NOT_REPORTED


class TestRecordInvariants:
    """The pairing the DB CHECK also enforces - asserted here so a violation is
    caught before it reaches a database nobody can run locally."""

    def test_a_status_without_a_report_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="exactly when report_state is REPORTED"):
            EngineHealthRecord(
                engine_name="e",
                report_state=EngineReportState.NOT_REPORTED,
                engine_status=EngineStatus.ERROR,
                analyze_duration_ms=None,
                finding_count=None,
                error=None,
            )

    def test_a_report_without_a_status_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="exactly when report_state is REPORTED"):
            EngineHealthRecord(
                engine_name="e",
                report_state=EngineReportState.REPORTED,
                engine_status=None,
                analyze_duration_ms=None,
                finding_count=None,
                error=None,
            )

    def test_a_duration_without_a_report_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="cannot have a measured duration"):
            EngineHealthRecord(
                engine_name="e",
                report_state=EngineReportState.NOT_REPORTED,
                engine_status=None,
                analyze_duration_ms=0,
                finding_count=None,
                error=None,
            )


class TestErrorTextFitsTheColumn:
    def test_an_engines_own_multi_kilobyte_error_is_truncated_at_capture(self) -> None:
        """`ScanEngineHealthRow.error` is VARCHAR(1024) and MySQL runs strict:
        an over-length value is an ERROR, and this INSERT shares the scoring
        transaction, so an untruncated message would abort the decide and leave
        the scan stuck rather than lose a tail nobody reads. `EngineResultDTO.
        error` has no length bound - a subprocess adapter that stuffs a tool's
        whole stderr in there is untrusted input, not a hypothetical."""
        store = _DictBlobStore()
        _write(store, "loud", _result("loud", status=EngineStatus.ERROR, error="y" * 20000))
        error = _health(store, ("loud",))["loud"].error
        assert error is not None
        assert len(error) <= 1024
        assert error.endswith("... (truncated)")

    def test_a_multi_kilobyte_validation_error_is_truncated_too(self) -> None:
        """The other unbounded source: our own fail-closed reason embeds the
        pydantic `ValidationError`, which grows with the number of violations
        in the blob rather than with any single field."""
        store = _DictBlobStore()
        store.put(
            findings_key(_SCAN_ID, "huge"),
            json.dumps(
                {
                    "engine": {"name": "huge", "version": "1", "ruleset_digest": "d"},
                    "status": "ok",
                    "scan_mode": "static",
                    "findings": [{"rule_id": f"R{i}"} for i in range(200)],
                }
            ).encode(),
        )
        error = _health(store, ("huge",))["huge"].error
        assert error is not None
        assert len(error) <= 1024
        assert error.endswith("... (truncated)")

    def test_a_short_error_is_left_exactly_as_it_was(self) -> None:
        store = _DictBlobStore()
        _write(store, "e", _result("e", status=EngineStatus.ERROR, error="binary not found"))
        assert _health(store, ("e",))["e"].error == "binary not found"


class TestFindingCount:
    def test_it_is_the_engines_own_pre_aggregation_count(self) -> None:
        """Not derivable from `ScanResultRow.findings`, which is deduplicated
        and capped: 'ran fine and found nothing' and 'found things that all
        deduplicated away' are different operational facts."""
        store = _DictBlobStore()
        _write(store, "a", _result("a", findings=(_finding("R1", "a"), _finding("R2", "a"))))
        _write(store, "b", _result("b", findings=(_finding("R1", "b"),)))
        health = _health(store, ("a", "b"))
        assert health["a"].finding_count == 2
        assert health["b"].finding_count == 1

    def test_an_absent_engine_counts_nothing_rather_than_zero(self) -> None:
        assert _health(_DictBlobStore(), ("absent",))["absent"].finding_count is None


class TestOneRecordPerRequestedEngine:
    def test_every_engine_asked_about_produces_exactly_one_record(self) -> None:
        """The health set must cover the WHOLE aggregation set, in order -
        otherwise 'never reported' is indistinguishable from 'never asked'."""
        store = _DictBlobStore()
        _write(store, "present", _result("present"))
        aggregated = load_and_aggregate(
            store,
            scan_id=_SCAN_ID,
            content_hash=_CONTENT_HASH,
            engine_names=("present", "absent", "also-absent"),
            policy=_policy(required=frozenset({"present"})),
        )
        assert [h.engine_name for h in aggregated.engine_health] == [
            "present",
            "absent",
            "also-absent",
        ]


class TestEngineNameNamespace:
    """The health rows are keyed on RUNTIME engine names. A fourth spelling, or
    a lock-file key leaking in, would mis-join for `osv_scanner`/`aig` while
    looking correct for the three names that collide by accident - exactly how
    the engine-coverage dashboard's `disabled` flag stayed wrong for years."""

    def test_no_real_dispatch_set_carries_a_lock_key_only_spelling(self) -> None:
        # DERIVED from `common.engine_names`, not hand-listed: today this is
        # {"osv_scanner", "aig"}, and a future vendored engine whose two
        # spellings differ joins the set without editing this test.
        lock_key_only = set(ENGINE_NAME_BY_LOCK_KEY) - set(LOCK_KEY_BY_ENGINE_NAME)
        assert lock_key_only, "no namespace divergence left to guard - is the mapping still real?"
        dispatched = set(floor_engine_names()) | set(SANDBOX_ENGINE_NAMES)
        assert not (dispatched & lock_key_only), (
            "a lock-file key reached a dispatch set, so it would be written into "
            "scan_engine_health.engine_name - convert through common.engine_names instead"
        )

    def test_every_vendored_engine_stores_under_a_name_that_converts_back(self) -> None:
        """The stored name must round-trip to a lock key, so Task 10's read path
        can join health rows against `vendor/engines.lock.yaml` through the one
        sanctioned conversion rather than a fourth ad-hoc table."""
        for name in SANDBOX_ENGINE_NAMES:
            assert LOCK_KEY_BY_ENGINE_NAME[name]

    def test_the_recorded_name_survives_a_blob_that_claims_otherwise(self) -> None:
        store = _DictBlobStore()
        _write(store, "osv-scanner", _result("osv_scanner"))  # lock key inside the blob
        health = _health(store, ("osv-scanner",))
        assert set(health) == {"osv-scanner"}
        assert health["osv-scanner"].report_state is EngineReportState.UNREADABLE
