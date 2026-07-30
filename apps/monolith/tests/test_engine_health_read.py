"""Tests for the `scan_engine_health` READ path (milestone C Task 10).

PURE - no MySQL, no Redis, no network. Everything here exercises
`orchestration.engine_health.summarize_engine_health` (a fold over values) and
`admin.engine_registry`'s attribution helpers (a lookup against two frozensets),
which is why the aggregation rules were factored out of the SQL in the first
place: the tests that need a real database can only run on the dev VM, and the
rules that decide what an operator sees must be provable anywhere.

The DB-backed half - `load_recent_engine_health` against a real
`scan_engine_health` table, and `GET /v1/admin/engines/health` through a real
ScanRuntime - lives in `test_admin_router.py` and is in the VM checklist.
"""

from __future__ import annotations

import datetime

from engine_runner.sandbox_engines import llm_gated_engine_names
from skillscan_core import EngineCapability, EngineMetadata, EngineStatus, StaticKeywordEngine

from monolith.modules.admin.engine_registry import (
    ATTRIBUTION_BASIS_CURRENT_CONFIG,
    ATTRIBUTION_CURRENTLY_DISABLED,
    ATTRIBUTION_LLM_ENDPOINT_UNCONFIGURED,
    VERSION_UNAVAILABLE_SANDBOXED,
    known_engine_rows,
    llm_unconfigured_engine_names,
    not_reported_attribution,
    not_reported_attribution_basis,
    structurally_absent_engine_names,
)
from monolith.modules.orchestration.aggregate import EngineReportState
from monolith.modules.orchestration.engine_health import (
    MAX_WINDOW_SCANS,
    EngineCoverageClass,
    EngineHealthCounts,
    EngineHealthObservation,
    clamp_window_scans,
    classify_engine_coverage,
    summarize_engine_health,
    summarize_scan_coverage,
)

_T0 = datetime.datetime(2026, 7, 29, 12, 0, 0)


def _obs(
    *,
    scan: str,
    engine: str = "bandit",
    report_state: str = "reported",
    engine_status: str | None = "ok",
    duration: int | None = 12,
    findings: int | None = 0,
    error: str | None = None,
    at: datetime.datetime | None = None,
) -> EngineHealthObservation:
    return EngineHealthObservation(
        scan_id=scan,
        engine_name=engine,
        report_state=report_state,
        engine_status=engine_status,
        analyze_duration_ms=duration,
        finding_count=findings,
        error=error,
        recorded_at=at or _T0,
    )


class TestTheWindowIsCountedInScans:
    """Task 9 is choosing a retention window concurrently. Every assertion here
    is about the same thing: when history stops, the read path must say so
    rather than let it read as engines that stopped reporting."""

    def test_no_rows_reports_an_empty_window_and_no_engine_claims(self) -> None:
        report = summarize_engine_health((), requested_scans=50)
        assert report.window.observed_scans == 0
        assert report.window.requested_scans == 50
        assert report.window.started_at is None
        assert report.window.ended_at is None
        # THE POINT: not one engine is described. An empty retention window is
        # a statement about storage, never about an engine.
        assert report.engines == ()

    def test_observed_scans_counts_scans_not_rows(self) -> None:
        """Fifteen engines of one scan are one unit of history. Counting rows
        would make the window look 15x longer than it is and would make a
        retention sweep look like a much smaller loss than it was."""
        report = summarize_engine_health(
            [_obs(scan="s1", engine=f"e{i}") for i in range(15)], requested_scans=50
        )
        assert report.window.observed_scans == 1
        assert len(report.engines) == 15

    def test_the_window_reports_fewer_scans_than_requested_after_a_sweep(self) -> None:
        report = summarize_engine_health(
            [_obs(scan=f"s{i}", at=_T0 + datetime.timedelta(minutes=i)) for i in range(3)],
            requested_scans=50,
        )
        assert (report.window.requested_scans, report.window.observed_scans) == (50, 3)
        assert report.window.started_at == _T0
        assert report.window.ended_at == _T0 + datetime.timedelta(minutes=2)

    def test_requested_scans_is_clamped_to_a_ceiling(self) -> None:
        assert clamp_window_scans(10**9) == MAX_WINDOW_SCANS
        assert clamp_window_scans(0) == 1
        assert clamp_window_scans(25) == 25


class TestReturnedErrorIsNotNeverReported:
    """Acceptance criterion 8, at the layer that decides what the console is
    given. The two must arrive as different values, not as one collapsed
    status - `unavailable_engine_result` fabricates `EngineStatus.ERROR` for a
    missing blob, and it is precisely that fabrication the health table exists
    to keep out of the telemetry."""

    def test_an_engine_that_errored_and_one_that_never_reported_differ_in_every_field(
        self,
    ) -> None:
        report = summarize_engine_health(
            [
                _obs(scan="s1", engine="bandit", engine_status="error", error="boom", duration=90),
                _obs(
                    scan="s1",
                    engine="aig-mcp-scan",
                    report_state="not_reported",
                    engine_status=None,
                    duration=None,
                    findings=None,
                    error="no findings reported at findings/s1/aig-mcp-scan.json",
                ),
            ],
            requested_scans=50,
        )
        errored, never = report.engines[0], report.engines[1]
        assert errored.engine_name == "aig-mcp-scan" or never.engine_name == "bandit"
        by_name = {summary.engine_name: summary for summary in report.engines}
        errored, never = by_name["bandit"], by_name["aig-mcp-scan"]

        assert (errored.last_report_state, errored.last_engine_status) == ("reported", "error")
        assert (never.last_report_state, never.last_engine_status) == ("not_reported", None)
        assert (errored.counts.error, errored.counts.not_reported) == (1, 0)
        assert (never.counts.error, never.counts.not_reported) == (0, 1)

    def test_a_timeout_counts_as_a_failure_and_a_partial_does_not(self) -> None:
        """`PARTIAL` is a degraded success that still contributed findings.
        Folding it into the failure count would report breakage that did not
        happen; leaving `TIMEOUT` out of it would hide breakage that did."""
        report = summarize_engine_health(
            [
                _obs(scan="s1", engine="a", engine_status="timeout"),
                _obs(scan="s1", engine="b", engine_status="partial"),
            ],
            requested_scans=50,
        )
        by_name = {summary.engine_name: summary for summary in report.engines}
        assert (by_name["a"].counts.error, by_name["a"].counts.partial) == (1, 0)
        assert (by_name["b"].counts.error, by_name["b"].counts.partial) == (0, 1)

    def test_counts_are_exhaustive_over_every_state_pair(self) -> None:
        """The five counters must sum to `observed_scans`. A status this module
        has not been taught therefore breaks this test instead of quietly
        joining an existing bucket - `_count` has no `else` branch on purpose."""
        rows = [
            _obs(scan="s1", engine="e", engine_status="ok"),
            _obs(scan="s2", engine="e", engine_status="partial"),
            _obs(scan="s3", engine="e", engine_status="error"),
            _obs(scan="s4", engine="e", engine_status="timeout"),
            _obs(scan="s5", engine="e", report_state="not_reported", engine_status=None),
            _obs(scan="s6", engine="e", report_state="unreadable", engine_status=None),
        ]
        summary = summarize_engine_health(rows, requested_scans=50).engines[0]
        assert summary.observed_scans == 6
        assert summary.counts.total == summary.observed_scans
        assert (summary.counts.ok, summary.counts.partial, summary.counts.error) == (1, 1, 2)
        assert (summary.counts.not_reported, summary.counts.unreadable) == (1, 1)

    def test_an_unknown_report_state_is_counted_nowhere_and_breaks_the_sum(self) -> None:
        summary = summarize_engine_health(
            [_obs(scan="s1", engine="e", report_state="a_state_from_the_future")],
            requested_scans=50,
        ).engines[0]
        assert summary.counts.total == 0
        assert summary.observed_scans == 1


class TestTheThreeDurationStates:
    """Task 7 preserved `0` (measured, floor engines really are that fast) as
    distinct from `None` (not measured - a pre-Task-7 engine-runner image).
    Task 8 kept the column nullable for it. Nothing here may substitute a
    default."""

    def test_zero_is_kept_as_a_measurement_and_counted_as_one(self) -> None:
        summary = summarize_engine_health(
            [_obs(scan="s1", engine="static-keyword", duration=0)], requested_scans=50
        ).engines[0]
        assert summary.last_analyze_duration_ms == 0
        assert summary.measured_duration_count == 1
        assert summary.max_analyze_duration_ms == 0

    def test_none_is_kept_as_not_measured_and_counted_as_none(self) -> None:
        summary = summarize_engine_health(
            [_obs(scan="s1", engine="bandit", duration=None)], requested_scans=50
        ).engines[0]
        assert summary.last_analyze_duration_ms is None
        assert summary.measured_duration_count == 0
        assert summary.max_analyze_duration_ms is None

    def test_a_max_over_a_mixed_window_ignores_unmeasured_rows_without_zeroing_them(self) -> None:
        summary = summarize_engine_health(
            [
                _obs(scan="s1", engine="e", duration=None, at=_T0),
                _obs(scan="s2", engine="e", duration=0, at=_T0 + datetime.timedelta(minutes=1)),
                _obs(scan="s3", engine="e", duration=140, at=_T0 + datetime.timedelta(minutes=2)),
            ],
            requested_scans=50,
        ).engines[0]
        assert summary.max_analyze_duration_ms == 140
        assert summary.measured_duration_count == 2
        assert summary.observed_scans == 3


class TestTheLastRowIsTheLastRow:
    def test_the_most_recent_observation_wins_regardless_of_input_order(self) -> None:
        rows = [
            _obs(scan="old", engine="e", engine_status="ok", at=_T0),
            _obs(scan="new", engine="e", engine_status="error", at=_T0 + datetime.timedelta(1)),
        ]
        for ordering in (rows, list(reversed(rows))):
            summary = summarize_engine_health(ordering, requested_scans=50).engines[0]
            assert summary.last_scan_id == "new"
            assert summary.last_engine_status == "error"

    def test_ties_on_recorded_at_are_broken_deterministically_by_scan_id(self) -> None:
        """Every engine of one scan shares a single `recorded_at`, so two scans
        decided in the same clock tick would otherwise pick a winner by dict
        iteration order and two identical calls could disagree."""
        rows = [
            _obs(scan="aaa", engine="e", engine_status="ok", at=_T0),
            _obs(scan="zzz", engine="e", engine_status="error", at=_T0),
        ]
        for ordering in (rows, list(reversed(rows))):
            assert summarize_engine_health(ordering, requested_scans=50).engines[
                0
            ].last_scan_id == ("zzz")


class TestNotReportedAttribution:
    """Five causes, one bucket. Two have a source this process can read; three
    do not, and for those the honest answer is `None` - the console renders
    that as "cause not recorded" rather than inventing one."""

    def test_an_llm_gated_engine_is_attributed_from_this_services_own_config(self) -> None:
        unconfigured = llm_unconfigured_engine_names(sandbox_llm_configured=False)
        assert "aig-mcp-scan" in unconfigured, (
            "the engine-runner's LLM gate no longer names aig-mcp-scan; this is the standing "
            "never-reported case on an LLM-less deployment and the console's explanation for it"
        )
        assert (
            not_reported_attribution(
                "aig-mcp-scan", disabled=frozenset(), llm_unconfigured=unconfigured
            )
            == ATTRIBUTION_LLM_ENDPOINT_UNCONFIGURED
        )

    def test_nothing_is_llm_unconfigured_once_an_llm_endpoint_is_configured(self) -> None:
        assert llm_unconfigured_engine_names(sandbox_llm_configured=True) == frozenset()

    def test_a_currently_disabled_engine_is_attributed_from_the_redis_toggle_set(self) -> None:
        assert (
            not_reported_attribution(
                "bandit", disabled=frozenset({"bandit"}), llm_unconfigured=frozenset()
            )
            == ATTRIBUTION_CURRENTLY_DISABLED
        )

    def test_the_llm_cause_outranks_currently_disabled(self) -> None:
        """The stronger prediction wins: an engine the engine-runner does not
        build would not report even if the operator switched it back on, so
        offering the actionable-looking cause would send them down a dead end."""
        assert (
            not_reported_attribution(
                "aig-mcp-scan",
                disabled=frozenset({"aig-mcp-scan"}),
                llm_unconfigured=frozenset({"aig-mcp-scan"}),
            )
            == ATTRIBUTION_LLM_ENDPOINT_UNCONFIGURED
        )

    def test_the_other_three_causes_get_no_attribution_at_all(self) -> None:
        """Crashed before writing / still running past the wait / never
        dispatched. None is observable from here, and a guessed cause looks
        exactly like an observed one to whoever acts on it."""
        assert (
            not_reported_attribution("bandit", disabled=frozenset(), llm_unconfigured=frozenset())
            is None
        )


class TestAttributionBasisTravelsWithTheToken:
    """2026-07-29. The "this is today's config, not what happened" caveat lived
    only in the web console's translated hint strings. `GET /v1/admin/engines/
    health` is a public-ish JSON API with more possible consumers than one
    console, and a bare `currently_disabled` reads to any of them as a
    statement about the scan it is attached to."""

    def test_every_producible_token_carries_the_current_config_basis(self) -> None:
        for token in (ATTRIBUTION_LLM_ENDPOINT_UNCONFIGURED, ATTRIBUTION_CURRENTLY_DISABLED):
            assert not_reported_attribution_basis(token) == ATTRIBUTION_BASIS_CURRENT_CONFIG

    def test_no_attribution_means_no_basis_rather_than_a_default(self) -> None:
        # A basis on a null attribution would qualify nothing and read as a
        # claim in its own right.
        assert not_reported_attribution_basis(None) is None


class TestEvidenceOutranksInference:
    """MEASURED on the dev VM 2026-07-29. `SKILLSCAN_VLLM_BASE_URL` was set on
    the engine-runner Deployment and not on the monolith, so the engine-runner
    built and ran `aig-mcp-scan` on every scan while the monolith's
    `sandbox_llm_configured` said it did not exist. The health page then
    rendered 「本部署不构建该引擎」 on a row that also read `failed 2` - the
    console contradicting itself about one engine, in one table, at once.

    The LLM branch is the only claim on this page derived from configuration
    rather than from an authority. These pin that it yields to the
    engine-runner's own delivered results - and that it does not depend on
    getting them, since `TestTheOverruleIsNotTheWholeFix` below shows the same
    split brain in a shape that delivers none.
    """

    def test_a_single_delivered_result_withdraws_the_llm_config_claim(self) -> None:
        assert (
            not_reported_attribution(
                "aig-mcp-scan",
                disabled=frozenset(),
                llm_unconfigured=frozenset({"aig-mcp-scan"}),
                reported_in_window=1,
            )
            is None
        )

    def test_withdrawing_the_false_claim_uncovers_the_true_one_rather_than_silencing_both(
        self,
    ) -> None:
        """Only the unverifiable claim is withdrawn. `currently_disabled` is
        read from the Redis key this same process writes, so evidence that the
        engine WAS built does not undermine it - "it reported earlier in the
        window, then an operator switched it off" is a coherent history, and it
        is the one actionable cause on this page. Silencing it here to be
        cautious would hide a fact from the person who can act on it.

        Note the ordering this makes visible: the LLM cause outranks
        `currently_disabled` only while it is credible."""
        assert (
            not_reported_attribution(
                "aig-mcp-scan",
                disabled=frozenset({"aig-mcp-scan"}),
                llm_unconfigured=frozenset({"aig-mcp-scan"}),
                reported_in_window=3,
            )
            == ATTRIBUTION_CURRENTLY_DISABLED
        )

    def test_no_evidence_leaves_the_claim_intact(self) -> None:
        """The guard must not disarm the attribution on a genuinely LLM-less
        deployment, which is the case it was built for and the common one."""
        assert (
            not_reported_attribution(
                "aig-mcp-scan",
                disabled=frozenset(),
                llm_unconfigured=frozenset({"aig-mcp-scan"}),
                reported_in_window=0,
            )
            == ATTRIBUTION_LLM_ENDPOINT_UNCONFIGURED
        )

    def test_the_evidence_count_is_every_reported_bucket_not_just_the_healthy_one(self) -> None:
        """The VM's aig rows were `error`, not `ok` - a failing engine is still
        a constructed one, and an implementation that only counted successes
        would have left the false claim in place in exactly the situation that
        produced it. `partial` joins them (`osv-scanner`'s nothing-in-scope
        state, same day), which is why this reads a derived property rather
        than a hand-listed pair."""
        counts = EngineHealthCounts(ok=0, partial=0, error=2, not_reported=2, unreadable=0)
        assert counts.reported == 2
        assert EngineHealthCounts(partial=1).reported == 1
        assert EngineHealthCounts(not_reported=5, unreadable=1).reported == 0

    def test_reported_and_the_unreported_buckets_still_sum_to_total(self) -> None:
        """`reported` is a re-derivation, so it has to stay consistent with the
        exhaustiveness `total` already enforces - otherwise a future
        engine_status could be counted by one and not the other."""
        counts = EngineHealthCounts(ok=3, partial=1, error=2, not_reported=4, unreadable=1)
        assert counts.reported + counts.not_reported + counts.unreadable == counts.total


class TestTheOverruleIsNotTheWholeFix:
    """2026-07-29 honesty review. The evidence overrule above needs a DELIVERED
    result to fire, and the split brain it was written for has a second shape
    that produces none:

        the engine-runner has `SKILLSCAN_VLLM_BASE_URL` and the monolith does
        not -> the runner builds and dispatches `aig-mcp-scan` -> with the LLM
        endpoint actually UP it takes ~240 s -> the monolith, believing the
        engine does not exist, never waits for it -> EVERY row in the window is
        `not_reported`, `counts.reported` is 0, and nothing withdraws anything.

    On the VM the same misconfiguration was catchable only because the endpoint
    was refusing connections, so the engine exited in under a second and left
    `reported` rows behind. Correctness that depends on how the environment
    happened to be broken is not correctness.

    The fix a stronger claim would need - a per-scan record of the engines
    actually DISPATCHED, written by the process that dispatched them - does not
    exist and cannot be derived from what is stored. So the claim was weakened
    to what this process can observe, and these pin the weakened wording rather
    than a behaviour change: in the scenario above the returned token is still
    produced, and it must be one that stays TRUE there.
    """

    def test_the_unfalsifiable_split_brain_still_yields_a_token(self) -> None:
        # Exactly the state above, as data: LLM-gated per this process's env,
        # zero delivered results, engine in fact running in the other pod.
        assert (
            not_reported_attribution(
                "aig-mcp-scan",
                disabled=frozenset(),
                llm_unconfigured=frozenset({"aig-mcp-scan"}),
                reported_in_window=0,
            )
            == ATTRIBUTION_LLM_ENDPOINT_UNCONFIGURED
        )

    def test_that_token_names_this_services_config_not_the_other_processs_behaviour(self) -> None:
        """THE ASSERTION THIS CLASS EXISTS FOR. The token crosses the wire and
        is echoed verbatim by any consumer that has not been taught it
        (`engineHealth.notReportedAttributionLabel`), so it is itself a claim.
        `never_constructed` asserted something about the engine-runner that is
        FALSE in the scenario above; `llm_endpoint_unconfigured` states what
        this process read in its own environment, which is true in it."""
        assert ATTRIBUTION_LLM_ENDPOINT_UNCONFIGURED == "llm_endpoint_unconfigured"
        assert "constructed" not in ATTRIBUTION_LLM_ENDPOINT_UNCONFIGURED
        assert "built" not in ATTRIBUTION_LLM_ENDPOINT_UNCONFIGURED

    def test_the_source_of_the_set_is_this_process_alone(self) -> None:
        """`llm_unconfigured_engine_names` takes ONE input, and it is the
        monolith's own flag. Nothing in this signature reads the engine-runner,
        which is the whole reason the claim built on it had to be weakened."""
        assert (
            llm_unconfigured_engine_names(sandbox_llm_configured=False) == llm_gated_engine_names()
        )
        assert llm_unconfigured_engine_names(sandbox_llm_configured=True) == frozenset()


class TestVersionUnavailableIsExplained:
    def test_a_sandbox_engine_says_why_it_has_no_version_and_a_floor_engine_has_one(self) -> None:
        """`version: None` for a sandbox engine is a structural fact (INV-15 -
        the metadata lives in the other image), not a value that failed to
        load. The console rendered both as a bare "—"."""
        metadata = StaticKeywordEngine().metadata
        rows = {
            str(row["name"]): row
            for row in known_engine_rows([metadata], required=frozenset(), disabled=frozenset())
        }
        assert rows[metadata.name]["version"] == metadata.version
        assert rows[metadata.name]["version_unavailable_reason"] is None
        assert rows["bandit"]["version"] is None
        assert rows["bandit"]["version_unavailable_reason"] == VERSION_UNAVAILABLE_SANDBOXED

    def test_every_listed_row_carries_the_field(self) -> None:
        """So the console never has to branch on its absence - a row without it
        would fall back to the same uninformative dash this fixes."""
        metadata = EngineMetadata(
            name="probe",
            version="9.9",
            ruleset_digest="d",
            capabilities=frozenset({EngineCapability.STATIC}),
        )
        rows = known_engine_rows([metadata], required=frozenset(), disabled=frozenset())
        assert all("version_unavailable_reason" in row for row in rows)
        assert all(
            (row["version"] is None) == (row["version_unavailable_reason"] is not None)
            for row in rows
        )


# --------------------------------------------------------------------------- #
# PER-SCAN COVERAGE (2026-07-30)
# --------------------------------------------------------------------------- #


class TestCoverageSplitsOnDeliveryNotOnReportState:
    """THE measurement that produced this feature, turned into assertions.

    On the 290-scan run, every engine timeout was a `('reported', 'timeout')`
    row: the airlock times `analyze()` out and writes a valid findings blob
    carrying zero findings. So the obvious definition of coverage - "did we hear
    from the engine" - read 14.0 engines on the scans WITH timeouts and 14.0 on
    the scans without, while the findings those scans were judged on dropped
    from 12.7 to 4.3. If any of these tests can be made to pass with
    `report_state` alone, the field is measuring nothing.
    """

    def test_a_reported_timeout_is_missing_evidence(self) -> None:
        coverage = summarize_scan_coverage(
            [
                _obs(scan="s1", engine="static-keyword", engine_status="ok"),
                _obs(scan="s1", engine="skillspector", engine_status="timeout", duration=3218),
            ]
        )
        assert coverage.expected == 2
        assert coverage.reported == 1
        assert coverage.missing == 1
        assert coverage.complete is False
        assert [e.engine_name for e in coverage.entries] == ["skillspector"]
        # The state pair is preserved, NOT flattened: the console needs both to
        # tell "the engine told us it timed out" from "we never heard from it".
        assert coverage.entries[0].report_state == "reported"
        assert coverage.entries[0].engine_status == "timeout"
        # A timed-out engine has a REAL measured duration - the airlock timed the
        # run it cut short. Corpus range: 0 to 3218 ms.
        assert coverage.entries[0].analyze_duration_ms == 3218

    def test_a_reported_error_is_missing_evidence_too(self) -> None:
        """osv-scanner returned `error` on 21 of the 290 scans, all of them in
        the bucket the original analysis called "no timeouts". Those 21 are
        exactly as evidence-less as a timeout, and this definition catches them
        (162 complete / 128 incomplete, against the analysis' own 183 / 107)."""
        coverage = summarize_scan_coverage(
            [_obs(scan="s1", engine="osv-scanner", engine_status="error")]
        )
        assert coverage.complete is False
        assert coverage.entries[0].coverage is EngineCoverageClass.MISSING

    def test_partial_counts_as_delivered(self) -> None:
        """A degraded success that still contributed findings - the same call
        `FAILED_ENGINE_STATUSES` makes. Not a rounding decision: osv-scanner
        reports PARTIAL on 161 of 290 scans, so the other choice would mark more
        than half of all scans incomplete and make the flag meaningless."""
        coverage = summarize_scan_coverage(
            [_obs(scan="s1", engine="osv-scanner", engine_status="partial")]
        )
        assert coverage.complete is True
        assert coverage.reported == 1
        assert coverage.entries == ()

    def test_unreadable_is_missing_and_never_explained_away(self) -> None:
        """Something WROTE to that key, so the engine demonstrably ran. Config
        cannot explain it away even if the name is structurally absent."""
        coverage = summarize_scan_coverage(
            [_obs(scan="s1", engine="aig-mcp-scan", report_state="unreadable", engine_status=None)],
            structurally_absent=frozenset({"aig-mcp-scan"}),
        )
        assert coverage.entries[0].coverage is EngineCoverageClass.MISSING
        assert coverage.not_applicable == 0
        assert coverage.complete is False


class TestStructurallyAbsentIsNotAFault:
    """`aig-mcp-scan` has a `not_reported` row on 290 of 290 scans in the corpus
    - every deployment without an internal LLM endpoint looks like this, which is
    the honest default state, not a fault. Counting it as a gap would publish
    `complete: false` on every scan the system will ever run, and a warning that
    is always on teaches operators that coverage warnings mean nothing."""

    def test_it_is_excluded_from_expected_and_does_not_break_complete(self) -> None:
        coverage = summarize_scan_coverage(
            [
                _obs(scan="s1", engine="static-keyword", engine_status="ok"),
                _obs(
                    scan="s1",
                    engine="aig-mcp-scan",
                    report_state="not_reported",
                    engine_status=None,
                    duration=None,
                    findings=None,
                ),
            ],
            structurally_absent=frozenset({"aig-mcp-scan"}),
        )
        assert coverage.expected == 1
        assert coverage.reported == 1
        assert coverage.not_applicable == 1
        assert coverage.complete is True

    def test_it_is_still_LISTED_so_the_absence_is_visible(self) -> None:
        """Excluded from the count, NOT hidden. "This deployment does not run
        that engine" is a fact a reader is entitled to; silently shrinking
        `expected` from 15 to 14 with no accounting is how a coverage number
        becomes unfalsifiable."""
        coverage = summarize_scan_coverage(
            [
                _obs(
                    scan="s1",
                    engine="aig-mcp-scan",
                    report_state="not_reported",
                    engine_status=None,
                    duration=None,
                )
            ],
            structurally_absent=frozenset({"aig-mcp-scan"}),
        )
        assert [e.engine_name for e in coverage.entries] == ["aig-mcp-scan"]
        assert coverage.entries[0].coverage is EngineCoverageClass.NOT_APPLICABLE

    def test_an_expected_engine_that_did_not_arrive_is_a_gap(self) -> None:
        """The other half of the same distinction - the whole point of having
        two classes. Nothing in today's configuration explains this one, so no
        cause is claimed and it counts against `complete`."""
        coverage = summarize_scan_coverage(
            [
                _obs(
                    scan="s1",
                    engine="skillspector",
                    report_state="not_reported",
                    engine_status=None,
                    duration=None,
                )
            ],
            structurally_absent=frozenset({"aig-mcp-scan"}),
        )
        assert coverage.entries[0].coverage is EngineCoverageClass.MISSING
        assert coverage.complete is False

    def test_a_delivered_result_outranks_the_config_inference(self) -> None:
        """EVIDENCE OUTRANKS INFERENCE, the rule `not_reported_attribution` was
        rewritten to follow. `structurally_absent` is read NOW; a blob is proof
        about THIS scan. So an engine the config claims is absent, but which
        delivered here, is simply reported."""
        coverage = summarize_scan_coverage(
            [_obs(scan="s1", engine="aig-mcp-scan", engine_status="ok")],
            structurally_absent=frozenset({"aig-mcp-scan"}),
        )
        assert coverage.reported == 1
        assert coverage.not_applicable == 0
        assert coverage.entries == ()

    def test_a_reported_timeout_is_not_explained_away_by_a_disable(self) -> None:
        """An operator disabling an engine AFTER a scan must not retroactively
        erase that scan's real timeout. A `reported` row is proof it ran."""
        coverage = summarize_scan_coverage(
            [_obs(scan="s1", engine="yara", engine_status="timeout", duration=0)],
            structurally_absent=frozenset({"yara"}),
        )
        assert coverage.entries[0].coverage is EngineCoverageClass.MISSING
        assert coverage.complete is False


class TestNoRecordIsNotCompleteCoverage:
    """`complete is None`, never True. Three ordinary ways to have no rows:
    `_dead_letter_and_decide` never aggregates, Task 9's retention sweep deletes
    old rows, and scans scored before milestone C never had any.

    This is the field that had to be gotten right: hours before this feature,
    the marketplace's `fail_closed` was found to be a structural inference
    ("a verdict with no result row") that read `false` for 17 of 18 REAL
    fail-closed BLOCKs. "0 of 0 engines missing, therefore complete" is the same
    mistake with the same shape."""

    def test_no_rows_means_no_answer(self) -> None:
        coverage = summarize_scan_coverage([])
        assert coverage.observed is False
        assert coverage.complete is None
        assert coverage.expected == 0
        assert coverage.reported == 0
        assert coverage.entries == ()

    def test_rows_that_all_delivered_means_complete(self) -> None:
        coverage = summarize_scan_coverage([_obs(scan="s1", engine="static-keyword")])
        assert coverage.observed is True
        assert coverage.complete is True


class TestEveryEnumPairIsClassified:
    """The cross-registry assertion. Milestone D produced FIVE defects of the
    "new detector added, sibling registry not updated" shape, none findable by
    reading a diff - so this enumerates both enums rather than listing the pairs
    a human remembered. A new `EngineStatus` or `EngineReportState` member makes
    this test fail with the pair named, instead of sliding silently into
    `MISSING` and quietly widening what counts as a gap.
    """

    def _classify(self, report_state: str, engine_status: str | None) -> EngineCoverageClass:
        return classify_engine_coverage(
            _obs(scan="s1", report_state=report_state, engine_status=engine_status),
            structurally_absent=frozenset(),
        )

    def test_every_reported_status_is_deliberately_placed(self) -> None:
        expected = {
            EngineStatus.OK.value: EngineCoverageClass.REPORTED,
            EngineStatus.PARTIAL.value: EngineCoverageClass.REPORTED,
            EngineStatus.ERROR.value: EngineCoverageClass.MISSING,
            EngineStatus.TIMEOUT.value: EngineCoverageClass.MISSING,
        }
        assert {status.value for status in EngineStatus} == set(expected), (
            "EngineStatus grew a member - decide whether it means the engine's "
            "findings reached the verdict, and add it to DELIVERED_ENGINE_STATUSES "
            "or not. Do not leave it to the MISSING default."
        )
        for status, want in expected.items():
            assert self._classify(EngineReportState.REPORTED.value, status) is want

    def test_every_report_state_is_deliberately_placed(self) -> None:
        assert {state.value for state in EngineReportState} == {
            "reported",
            "not_reported",
            "unreadable",
        }, "EngineReportState grew a member - classify_engine_coverage must be taught it"
        assert (
            self._classify(EngineReportState.NOT_REPORTED.value, None)
            is EngineCoverageClass.MISSING
        )
        assert (
            self._classify(EngineReportState.UNREADABLE.value, None) is EngineCoverageClass.MISSING
        )

    def test_an_unrecognised_value_falls_to_missing_not_to_reported(self) -> None:
        """The conservative direction, and the opposite of what `_count` does
        above - see `classify_engine_coverage`'s docstring for why the two
        differ. A completeness claim may only ever be weakened by ignorance."""
        assert self._classify("reported", "some_future_status") is EngineCoverageClass.MISSING
        assert self._classify("some_future_state", None) is EngineCoverageClass.MISSING


class TestStructurallyAbsentSetIsTheSameOneTheConsoleExplains:
    """One definition, two consumers. If this union and
    `not_reported_attribution`'s two authorities ever diverged, a single scan
    would carry "this engine is disabled" beside "this engine is missing
    evidence" - two statements about one engine that cannot both be acted on."""

    def test_it_is_the_union_of_the_two_readable_authorities(self) -> None:
        absent = structurally_absent_engine_names(
            disabled=frozenset({"yara"}), llm_unconfigured=frozenset({"aig-mcp-scan"})
        )
        assert absent == frozenset({"yara", "aig-mcp-scan"})

    def test_every_member_has_an_attribution_the_console_can_print(self) -> None:
        """No member of this set may be excluded from `expected` without a cause
        the console can name. An engine silently subtracted with nothing to show
        for it is exactly the unaccounted shrink this feature exists to stop."""
        disabled = frozenset({"yara"})
        llm_unconfigured = llm_unconfigured_engine_names(sandbox_llm_configured=False)
        assert llm_unconfigured, "the LLM gate is empty - this test would be vacuous"
        for name in structurally_absent_engine_names(
            disabled=disabled, llm_unconfigured=llm_unconfigured
        ):
            attribution = not_reported_attribution(
                name, disabled=disabled, llm_unconfigured=llm_unconfigured
            )
            assert attribution is not None, name
            assert not_reported_attribution_basis(attribution) == ATTRIBUTION_BASIS_CURRENT_CONFIG
