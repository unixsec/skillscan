"""Tests for `marketplace_api.views` (里程碑 B' spec §5).

Pure functions, no infra needed - same as test_floor.py.

2026-07-30: the contract became skill-keyed and binary. `project_scan` is gone
(the scan-keyed endpoint it served was replaced outright), so every case here now
exercises `project_skill_verdict` and the `is_safe` / `unsafe_reason` derivation.
"""

from __future__ import annotations

import datetime
import json
from typing import Any

import pytest

from monolith.modules.marketplace_api import views
from monolith.modules.orchestration.engine_health import (
    EngineHealthObservation,
    summarize_scan_coverage,
)

_COVERAGE_AT = datetime.datetime(2026, 7, 30, 12, 0, 0)


def _coverage_obs(
    engine: str,
    *,
    report_state: str = "reported",
    engine_status: str | None = "ok",
) -> EngineHealthObservation:
    """A `scan_engine_health` row as the read path hands it over. Built through
    the real `summarize_scan_coverage` in the tests below rather than by
    constructing a `ScanEngineCoverage` by hand: the projection and the console
    must share ONE definition of "complete", and a hand-built object would let
    this file agree with a projection that had grown its own."""
    return EngineHealthObservation(
        scan_id="scan-1",
        engine_name=engine,
        report_state=report_state,
        engine_status=engine_status,
        analyze_duration_ms=None if report_state != "reported" else 5,
        finding_count=None if report_state != "reported" else 0,
        error=None,
        recorded_at=_COVERAGE_AT,
    )


class TestStatusProjection:
    @pytest.mark.parametrize(
        ("internal", "external"),
        [
            ("queued", "PENDING"),
            ("running", "RUNNING"),
            ("scored", "RUNNING"),
            ("decided", "COMPLETED"),
            ("failed", "COMPLETED"),
        ],
    )
    def test_each_internal_state_projects(self, internal: str, external: str) -> None:
        assert views.project_status(internal) == external

    def test_an_unknown_internal_state_raises_rather_than_guessing(self) -> None:
        # SECURITY: a new internal state must not silently project to something
        # plausible. Failing loudly here is what forces the projection to be
        # updated alongside the state machine.
        with pytest.raises(ValueError, match="unmapped"):
            views.project_status("teleported")


_SKILL_ID = "acme/data-helper"
_CONTENT_HASH = "c" * 64

_VERDICT_ROW: dict[str, Any] = {
    "verdict": "REVIEW",
    "score": 62,
    "policy_version": "v1",
    "issued_at": "2026-07-28T02:00:00Z",
    "jws_signature": "eyJhbGciOiJSUzI1NiJ9.stub.sig",
    # 2026-07-30: `gate.service.get_verdict_view` now carries the gate's own
    # recorded `VerdictRow.fail_closed` rather than leaving the projection to
    # infer it from which other rows exist.
    "fail_closed": False,
}

_RESULT_ROW: dict[str, Any] = {
    "findings_capped": False,
    "findings_total": 1,
    "hard_gate_hits": [],
    "findings": [
        {
            "rule_id": "static.eval_call",
            "test_item_id": "CODE-02",
            "category": "code",
            "title": "检测到 eval() 调用",
            "severity": 3,
            "confidence": 0.5,
            "source_engine": "static-keyword",
            "source_capability": "static",
            "trifecta_signals": [],
            "file_path": "scripts/helper.py",
            "start_line": 25,
            "evidence_redacted": "eval() call (redacted)",
            "snippet_hash": "a" * 64,
        }
    ],
}


def _project(**overrides: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "skill_id": _SKILL_ID,
        "content_hash": _CONTENT_HASH,
        "internal_state": "decided",
        "verdict_row": _VERDICT_ROW,
        "result_row": _RESULT_ROW,
    }
    kwargs.update(overrides)
    return views.project_skill_verdict(**kwargs)


class TestBinarySafetyClassification:
    """The one bit the marketplace acts on, and the code that explains it."""

    def test_pass_on_a_completed_scan_is_the_only_safe_answer(self) -> None:
        out = _project(verdict_row={**_VERDICT_ROW, "verdict": "PASS", "score": 100})
        assert out["is_safe"] is True
        assert out["unsafe_reason"] is None

    @pytest.mark.parametrize("verdict", ["REVIEW", "BLOCK"])
    def test_everything_that_did_not_pass_is_unsafe(self, verdict: str) -> None:
        # The owner's requirement, stated as a test: only two outcomes exist for
        # the marketplace, and REVIEW is on the unsafe side of the line.
        out = _project(verdict_row={**_VERDICT_ROW, "verdict": verdict})
        assert out["is_safe"] is False
        assert out["unsafe_reason"] in views.UNSAFE_REASONS

    def test_review_maps_to_pending_review_not_to_a_findings_code(self) -> None:
        out = _project(verdict_row={**_VERDICT_ROW, "verdict": "REVIEW"})
        assert out["unsafe_reason"] == "pending_review"

    def test_a_block_with_findings_maps_to_content_findings(self) -> None:
        out = _project(verdict_row={**_VERDICT_ROW, "verdict": "BLOCK", "score": 20})
        assert out["unsafe_reason"] == "content_findings"
        assert out["findings"] != []

    def test_a_fail_closed_block_maps_to_scan_incomplete_not_content_findings(self) -> None:
        """The distinction the whole change exists to make.

        A fail-closed BLOCK carries NO findings - the scan never completed - so
        under a binary contract, labelling it `content_findings` hands the
        marketplace "unsafe, no findings, no explanation". On a real 226-package
        run, 17 of 18 BLOCKs were exactly this.

        Note the result row is PRESENT and non-empty of nothing but hard_gate_hits:
        that is what the collector path really writes, and it is why the old
        structural inference (`result_row is None`) got this case wrong.
        """
        out = _project(
            verdict_row={**_VERDICT_ROW, "verdict": "BLOCK", "score": 0, "fail_closed": True},
            result_row={
                "findings_capped": False,
                "findings_total": 0,
                "hard_gate_hits": [],
                "findings": [],
            },
        )
        assert out["is_safe"] is False
        assert out["unsafe_reason"] == "scan_incomplete"
        assert out["findings"] == []

    def test_a_hard_gate_block_maps_to_hard_gate(self) -> None:
        # INV-3: an unwaivable rule fired. Materially different from findings
        # merely accumulating - no allowlist can move it - so it gets its own code.
        out = _project(
            verdict_row={**_VERDICT_ROW, "verdict": "BLOCK", "score": 0},
            result_row={**_RESULT_ROW, "hard_gate_hits": ["net.exfil_to_pastebin"]},
        )
        assert out["unsafe_reason"] == "hard_gate"
        assert out["hard_gate_hits"] == ["net.exfil_to_pastebin"]

    def test_scan_incomplete_outranks_hard_gate(self) -> None:
        # Both flags set is not a real state (a fail-closed decision is made on an
        # incomplete finding set, so its recorded hits mean nothing) - assert the
        # order anyway, so the resolution is a decision rather than an accident.
        out = _project(
            verdict_row={**_VERDICT_ROW, "verdict": "BLOCK", "fail_closed": True},
            result_row={**_RESULT_ROW, "hard_gate_hits": ["some.rule"]},
        )
        assert out["unsafe_reason"] == "scan_incomplete"

    @pytest.mark.parametrize("state", ["queued", "running", "scored"])
    def test_a_scan_still_in_flight_is_unsafe_and_not_yet_scanned(self, state: str) -> None:
        # Owner decision 3: `is_safe: false` while PENDING/RUNNING, reading "not
        # passed is unsafe" strictly.
        out = _project(internal_state=state, verdict_row=None, result_row=None)
        assert out["is_safe"] is False
        assert out["unsafe_reason"] == "not_yet_scanned"
        assert out["status"] in {"PENDING", "RUNNING"}

    def test_a_pass_verdict_before_the_scan_is_terminal_is_still_unsafe(self) -> None:
        # The gate commits its verdict before `scan_job` is marked decided, so a
        # poll can land on PASS + `scored`. Answering "safe" inside that window
        # would publish on a scan the system does not consider finished.
        out = _project(
            internal_state="scored",
            verdict_row={**_VERDICT_ROW, "verdict": "PASS", "score": 100},
        )
        assert out["status"] == "RUNNING"
        assert out["is_safe"] is False
        assert out["unsafe_reason"] == "not_yet_scanned"

    def test_a_skill_with_no_scan_at_all_is_pending_and_unsafe(self) -> None:
        # A registered skill whose latest version has never been scanned. Answered
        # rather than 404'd by the router; the projection must not call it safe.
        out = _project(internal_state=None, verdict_row=None, result_row=None)
        assert out["status"] == "PENDING"
        assert out["poll_after_ms"] == 5_000
        assert out["is_safe"] is False
        assert out["unsafe_reason"] == "not_yet_scanned"

    def test_is_safe_and_unsafe_reason_are_never_both_informative(self) -> None:
        # Exactly one of the two carries information, in every combination the
        # classifier can be handed. A response with both set (or neither) would let
        # a client branch on one field and act on the other.
        for status in ("PENDING", "RUNNING", "COMPLETED"):
            for verdict in (None, "PASS", "REVIEW", "BLOCK"):
                for fail_closed in (False, True):
                    for hits in ([], ["r"]):
                        is_safe, reason = views.classify_safety(
                            status=status,
                            verdict=verdict,
                            fail_closed=fail_closed,
                            hard_gate_hits=hits,
                        )
                        assert is_safe is (reason is None), (status, verdict, fail_closed, hits)
                        if reason is not None:
                            assert reason in views.UNSAFE_REASONS


class TestScanProjection:
    def test_top_level_field_set_is_exactly_the_whitelist(self) -> None:
        assert set(_project()) == views.EXTERNAL_TOP_LEVEL_FIELDS

    def test_finding_field_set_is_exactly_the_whitelist(self) -> None:
        assert set(_project()["findings"][0]) == views.EXTERNAL_FINDING_FIELDS

    def test_snippet_hash_is_never_exposed(self) -> None:
        # SECURITY (INV-9, spec §5.3): a hash of a low-entropy secret can be
        # brute-forced offline. The marketplace has no use for it. Re-examined when
        # `hard_gate_hits` was admitted to the contract (2026-07-30) and kept out:
        # the exclusions were never a package deal.
        assert "snippet_hash" not in _project()["findings"][0]

    def test_the_answer_names_the_version_it_is_about(self) -> None:
        # Owner decision 1: latest-version semantics, and the response says which
        # version. "skill X is safe" with no content_hash is unfalsifiable.
        out = _project()
        assert out["skill_id"] == _SKILL_ID
        assert out["content_hash"] == _CONTENT_HASH

    def test_scan_id_never_appears_in_the_response(self) -> None:
        # The scan-keyed contract was REPLACED (owner decision 4). Leaving scan_id
        # in would let integrators rebuild the retired contract on top of this one.
        assert "scan_id" not in _project()

    def test_confidence_is_raw_and_not_rounded(self) -> None:
        # Deliberately unrounded: rounding would hide the difference between 0.69
        # and 0.70 at exactly the threshold that decides REVIEW
        # (`GatePolicy.review_confidence`).
        finding = {**_RESULT_ROW["findings"][0], "confidence": 0.695}
        out = _project(result_row={**_RESULT_ROW, "findings": [finding]})
        assert out["findings"][0]["confidence"] == 0.695

    def test_policy_version_and_decided_at_carry_the_verdicts_own_values(self) -> None:
        """spec §7 non-repudiation: WHICH policy decided this, and WHEN.

        Both fields went entirely unasserted until 2026-07-28 - hardcoding
        `"policy_version": None` and `"decided_at": None` in the projection passed
        this whole file plus the router suite. Without them a caller cannot bind a
        verdict to the policy that produced it, and a signed verdict with no
        decision time is not evidence of anything.

        `decided_at` is a cross-layer RENAME: `gate.service.get_verdict_view`
        emits `issued_at`, this projection reads that key and republishes it as
        `decided_at`. Note `_VERDICT_ROW` carries NO `decided_at` key of its
        own, so this passes only if the rename actually happens - which is the
        exact shape that silently goes null when either side is renamed alone.
        """
        out = _project()
        assert "decided_at" not in _VERDICT_ROW  # the premise of the rename claim
        assert out["policy_version"] == "v1"
        assert out["decided_at"] == "2026-07-28T02:00:00Z"

    def test_a_fail_closed_verdict_still_reports_its_policy_and_decision_time(self) -> None:
        # The fail-closed BLOCK (spec §5.1) is the verdict most likely to be
        # disputed, so it is the one that can least afford to lose the two
        # fields that anchor it to a policy version and a moment in time.
        out = _project(
            internal_state="failed",
            verdict_row={**_VERDICT_ROW, "verdict": "BLOCK", "score": 0, "fail_closed": True},
            result_row=None,
        )
        assert out["unsafe_reason"] == "scan_incomplete"
        assert out["policy_version"] == "v1"
        assert out["decided_at"] == "2026-07-28T02:00:00Z"
        assert out["poll_after_ms"] == 0

    def test_judged_at_tier_reports_the_tier_the_verdict_was_decided_at(self) -> None:
        # SECURITY (C2): submissions are single-flight on content + toolchain, so
        # a caller can be handed a verdict decided at ANOTHER submitter's tier -
        # and the tier is the BLOCK threshold (public: HIGH, everything else:
        # CRITICAL). PARTNER here is neither the deployment default nor the
        # default M2M grant, so this cannot pass by coincidence.
        assert _project(judged_at_tier="partner")["judged_at_tier"] == "partner"

    def test_an_unrecorded_tier_is_null_rather_than_a_guess(self) -> None:
        # A scan with no recorded tier fell back to the deployment default at
        # decide time - runtime configuration this pure function cannot see.
        # Reporting the likely value would misstate the basis of a real
        # decision; null says "not recorded", which is what is actually known.
        out = _project(internal_state="queued", verdict_row=None, result_row=None)
        assert out["judged_at_tier"] is None

    def test_a_looser_judgment_than_requested_is_disclosed(self) -> None:
        # SECURITY (Task 18) - the case this pair of fields exists for, and the
        # commonest one on this surface. A marketplace service account defaults
        # to PUBLIC, the STRICTEST tier (policies/gate/v1.yaml blocks it at
        # HIGH); its submission deduplicates onto a console submission judged at
        # `internal` (blocks only at CRITICAL); so the verdict it is handed was
        # reached under a MORE PERMISSIVE ruleset than it asked for, and a
        # finding that should have blocked for it can read PASS.
        #
        # Deliberately retained through the 2026-07-30 binary re-key: the
        # reference draft `docs/skill安全扫描接口规范v2.2.md` has no place for this
        # disclosure, and dropping it to match that shape would be a regression.
        out = _project(
            judged_at_tier="internal",
            requested_tier="public",
            tier_direction="looser",
            tier_direction_basis="signing_policy",
        )
        assert out["judged_at_tier"] == "internal"
        assert out["requested_tier"] == "public"
        assert out["tier_direction"] == "looser"
        assert out["tier_direction_basis"] == "signing_policy"

    def test_an_unrecorded_request_is_null_and_not_the_judged_tier(self) -> None:
        # A `scan_submitter` row written before `requested_trust_tier` existed
        # records no request. Defaulting to `judged_at_tier` (which is what the
        # CONSOLE's equivalent field does, to preserve a pre-existing field's
        # meaning) would assert agreement nobody recorded - and agreement is
        # exactly the claim these fields exist to stop making silently. This
        # field is new here, so it has no prior meaning to preserve.
        out = _project(judged_at_tier="internal")
        assert out["judged_at_tier"] == "internal"
        assert out["requested_tier"] is None
        assert out["tier_direction"] is None
        assert out["tier_direction_basis"] is None

    def test_summary_counts_by_severity(self) -> None:
        result = {
            "findings_capped": False,
            "findings_total": 5,
            "hard_gate_hits": [],
            "findings": [{**_RESULT_ROW["findings"][0], "severity": s} for s in (1, 2, 3, 3, 4)],
        }
        out = _project(result_row=result)
        assert out["summary"] == {
            "total": 5,
            "critical": 1,
            "high": 2,
            "medium": 1,
            "low": 1,
            "truncated": False,
        }

    def test_truncated_keeps_total_truthful(self) -> None:
        # spec §5.3 CRITICAL (review 2026-07-28): `total` must be the real pre-cap
        # count, NOT `len(findings)` - once `findings` is the post-cap list, its
        # length IS the cap (5000), not the truth. `findings_total` is the only
        # thing carrying the real number, so this asserts an ACTUAL value that
        # differs from `len(findings)` - a test that only checked `truncated is
        # True` could not have caught `total` silently degrading to the cap.
        result = {
            "findings_capped": True,
            "findings_total": 12_345,
            "hard_gate_hits": [],
            "findings": _RESULT_ROW["findings"],  # len 1: the post-cap page returned
        }
        out = _project(result_row=result)
        assert out["summary"]["truncated"] is True
        assert out["summary"]["total"] == 12_345
        assert out["summary"]["total"] != len(result["findings"])

    def test_truncated_with_no_findings_total_falls_back_honestly(self) -> None:
        # A row written before the findings_total column existed has no way to
        # recover the true pre-cap count - the truncated findings are gone. Falling
        # back to `len(findings)` (the cap) is a DEGRADED answer for an
        # already-capped historical row, but it is honest: it reports what is
        # actually known rather than inventing a number.
        result = {
            "findings_capped": True,
            "findings_total": None,
            "hard_gate_hits": [],
            "findings": _RESULT_ROW["findings"],
        }
        out = _project(result_row=result)
        assert out["summary"]["truncated"] is True
        assert out["summary"]["total"] == len(result["findings"])

    def test_a_capped_scan_cannot_read_safe(self) -> None:
        # SECURITY (INV-5, and the objection design spec §5.2 recorded against
        # collapsing to two values): the flood cap forces REVIEW, so an attacker
        # who buries the scan in findings must not thereby get a publishable
        # answer. Under this mapping REVIEW is UNSAFE, which closes that channel
        # rather than opening it - the recorded objection was about REVIEW mapping
        # to SAFE, and this asserts the direction actually taken.
        out = _project(
            verdict_row={**_VERDICT_ROW, "verdict": "REVIEW"},
            result_row={
                "findings_capped": True,
                "findings_total": 12_345,
                "hard_gate_hits": [],
                "findings": _RESULT_ROW["findings"],
            },
        )
        assert out["is_safe"] is False
        assert out["unsafe_reason"] == "pending_review"
        assert out["summary"]["truncated"] is True


class TestProjectionGuard:
    def test_no_internal_finding_field_leaks_into_the_projection(self) -> None:
        """A new field on the internal finding shape must NOT appear externally.

        spec §3.2: the projection is a whitelist precisely so that adding an
        internal field is a no-op here. This asserts it, so the property is
        checked rather than merely intended.
        """
        polluted = {
            **_RESULT_ROW["findings"][0],
            "some_future_internal_field": "must not escape",
            "another_one": {"nested": "secret"},
        }
        out = _project(result_row={"findings_capped": False, "findings": [polluted]})
        assert set(out["findings"][0]) == views.EXTERNAL_FINDING_FIELDS

    def test_no_internal_result_row_field_leaks_into_the_top_level(self) -> None:
        # Same property one level up. `get_scan_result_view` deliberately still
        # withholds `provenance` and `required_ok`; if it ever stopped, the
        # whitelist - not that accessor - is what has to keep them out.
        out = _project(
            result_row={
                **_RESULT_ROW,
                "provenance": [["static-keyword", "ok"]],
                "required_ok": False,
            }
        )
        assert set(out) == views.EXTERNAL_TOP_LEVEL_FIELDS

    def test_every_internal_state_in_the_state_machine_is_mapped(self) -> None:
        """The projection must cover the real state machine, not a remembered one.

        Reads `orchestration.service.SCAN_STATES` - the constant that module's
        own writers use - so a state added there and left unmapped here fails.

        The previous version of this guard regex-matched the module DOCSTRING
        for `(queued|running|scored|decided|failed)`, i.e. it enumerated exactly
        the five states it claimed to discover: adding a sixth state produced
        the same five-element set and this test still passed, while
        `project_status` on that new state raised ValueError and 500'd every
        marketplace poll of such a scan (review 2026-07-28). Prose is not a
        source of truth; the constant the state machine itself writes is.
        """
        from monolith.modules.orchestration.service import SCAN_STATES

        assert SCAN_STATES, "orchestration.service.SCAN_STATES is empty"
        unmapped: list[str] = []
        for state in sorted(SCAN_STATES):
            try:
                views.project_status(state)
            except ValueError:
                unmapped.append(state)
        assert not unmapped, (
            f"internal scan states with no marketplace projection: {unmapped} - "
            "add them to views._STATUS_PROJECTION (a poll of such a scan 500s)"
        )


# The contract, written out literally. NOT `views.EXTERNAL_*_FIELDS` - asserting
# the implementation against the constant the implementation itself reads is a
# tautology: delete a field and both sides shrink together, still equal. That
# hole was real and shipped (2026-07-28); it is why these two frozensets are
# duplicated here by hand and must be edited deliberately when the contract
# genuinely changes. Source of truth: design spec 5.3.
#
# 2026-07-30 - EDITED BY HAND for the skill-keyed binary contract. Removed:
# `scan_id` (the key was replaced outright), `verdict` (three-valued),
# `fail_closed` (now `unsafe_reason == "scan_incomplete"`), `requires_review` (now
# `unsafe_reason == "pending_review"`). Added: `skill_id`, `content_hash`,
# `is_safe`, `unsafe_reason`, `hard_gate_hits`.
_SPEC_TOP_LEVEL_FIELDS = frozenset(
    {
        "skill_id",
        "content_hash",
        "status",
        "poll_after_ms",
        "is_safe",
        "unsafe_reason",
        # Reverses a deliberate exclusion ("internal adjudication detail; exposing
        # them makes them part of the contract"), added by hand on both sides. A
        # binary answer with no `verdict` cannot otherwise say WHY it is unsafe,
        # and "an unwaivable rule fired" (INV-3) is not the same problem as
        # "findings accumulated". It is a rule_id list, never evidence.
        "hard_gate_hits",
        "score",
        "policy_version",
        "decided_at",
        "verdict_jws",
        "judged_at_tier",
        # 里程碑 F Task 18: added to the contract deliberately, by hand, on both
        # sides. `judged_at_tier` alone reported a tier and let the caller
        # assume it was the one they asked for - which on this surface it
        # usually is not (a service account defaults to PUBLIC, the strictest
        # tier; the console commonly submits at `internal`, and dedup hands the
        # marketplace that verdict).
        "requested_tier",
        "tier_direction",
        # 2026-07-29 residual triage, added by hand on both sides for the same
        # reason. `tier_direction` is computed from the policy loaded NOW, so a
        # policy approved between signing and polling can relabel a verdict the
        # caller already holds. This says which policy the label came from.
        "tier_direction_basis",
        # 2026-07-30 PER-SCAN ENGINE COVERAGE, added by hand on both sides.
        # `required_engines` fails closed and every other engine fails open: an
        # advisory engine that does not deliver has its findings discarded and the
        # verdict is computed as though it found nothing. On a 290-scan run,
        # complete-evidence scans were 38% PASS / 60% REVIEW and incomplete ones
        # 57% PASS / 29% REVIEW - `is_safe: true` is measurably EASIER to obtain
        # under load, and nothing in the contract said so. Counts plus a boolean,
        # because a machine consumer branches on this rather than reading it.
        "engines_expected",
        "engines_reported",
        "engines_not_applicable",
        "evidence_complete",
        "engine_coverage_basis",
        "summary",
        "findings",
    }
)

# Unchanged by the 2026-07-30 re-key: research confirmed these twelve already cover
# every field the console's own 「发现明细」 table renders
# (`web/src/pages/ScanDetail.tsx`), so the binary contract needed no widening here
# to carry "the specific unsafe reasons".
_SPEC_FINDING_FIELDS = frozenset(
    {
        "rule_id",
        "test_item_id",
        "category",
        "title",
        "severity",
        "confidence",
        "source_engine",
        "source_capability",
        "trifecta_signals",
        "file_path",
        "start_line",
        "evidence_redacted",
    }
)

# The unsafe-reason vocabulary, also written out literally and for the same reason:
# it is a machine-readable enum an integrator branches on, so silently gaining or
# losing a member is a contract change.
_SPEC_UNSAFE_REASONS = frozenset(
    {
        "content_findings",
        "pending_review",
        "hard_gate",
        "scan_incomplete",
        "not_yet_scanned",
    }
)


class TestEngineCoverageDisclosure:
    """2026-07-30. The verdict is unchanged by all of this; what changes is that
    a caller can see the evidence was incomplete.

    `is_safe` is asserted alongside the counts in the first test on purpose: the
    owner's decision was explicitly NOT to change verdict semantics, and a
    regression that started letting coverage move the bit would be the single
    worst outcome of this feature."""

    def test_the_counts_and_the_boolean_come_from_the_coverage_object(self) -> None:
        coverage = summarize_scan_coverage(
            [
                _coverage_obs("static-keyword", engine_status="ok"),
                _coverage_obs("skillspector", engine_status="timeout"),
                _coverage_obs("aig-mcp-scan", report_state="not_reported", engine_status=None),
            ],
            structurally_absent=frozenset({"aig-mcp-scan"}),
        )
        out = _project(verdict_row={**_VERDICT_ROW, "verdict": "PASS"}, coverage=coverage)
        assert out["engines_expected"] == 2
        assert out["engines_reported"] == 1
        assert out["engines_not_applicable"] == 1
        assert out["evidence_complete"] is False
        assert out["engine_coverage_basis"] == "current_config"
        # THE INVARIANT OF THIS WHOLE FEATURE: incomplete evidence does not move
        # the bit. A PASS on partial evidence is still reported as safe; the
        # caller is told the evidence was partial and decides for itself.
        assert out["is_safe"] is True
        assert out["unsafe_reason"] is None

    def test_complete_evidence_reads_complete(self) -> None:
        coverage = summarize_scan_coverage([_coverage_obs("static-keyword", engine_status="ok")])
        out = _project(coverage=coverage)
        assert (out["engines_expected"], out["engines_reported"]) == (1, 1)
        assert out["evidence_complete"] is True

    def test_no_coverage_read_is_null_and_never_true(self) -> None:
        """No scan exists yet, so no coverage was read. Zeroed counts with a
        `null` boolean: `true` would be a completeness claim backed by nothing,
        which is the shape of the `fail_closed` defect this same contract shipped
        and reverted hours earlier."""
        out = _project(internal_state=None, verdict_row=None, result_row=None)
        assert out["engines_expected"] == 0
        assert out["engines_reported"] == 0
        assert out["evidence_complete"] is None
        assert out["engine_coverage_basis"] is None

    def test_a_scan_with_no_retained_health_rows_is_also_null(self) -> None:
        """Indistinguishable from the above by design - a dead-lettered scan, one
        older than the retention window, or one scored before the health table
        existed. From the caller's side they ARE the same fact: nobody can say
        what the coverage was."""
        out = _project(coverage=summarize_scan_coverage([]))
        assert out["evidence_complete"] is None
        assert out["engine_coverage_basis"] is None

    def test_a_structurally_absent_engine_does_not_make_every_scan_incomplete(self) -> None:
        """`aig-mcp-scan` is `not_reported` on 290 of 290 scans of any deployment
        without an LLM endpoint. If this test fails, the contract publishes
        `evidence_complete: false` on every scan forever and integrators learn to
        ignore the field entirely - strictly worse than not having it."""
        coverage = summarize_scan_coverage(
            [
                _coverage_obs("static-keyword", engine_status="ok"),
                _coverage_obs("aig-mcp-scan", report_state="not_reported", engine_status=None),
            ],
            structurally_absent=frozenset({"aig-mcp-scan"}),
        )
        out = _project(coverage=coverage)
        assert out["evidence_complete"] is True
        # Still ACCOUNTED FOR, not silently subtracted: `expected` dropping from
        # 2 to 1 has a published reason.
        assert out["engines_not_applicable"] == 1

    def test_the_projection_publishes_no_engine_names(self) -> None:
        """SECURITY / minimal surface: the marketplace gets counts, the console
        gets names. A machine consumer branches on numbers, and `entries` carries
        per-engine operational detail this surface has no use for."""
        coverage = summarize_scan_coverage([_coverage_obs("skillspector", engine_status="timeout")])
        out = _project(coverage=coverage)
        assert "skillspector" not in json.dumps(
            {k: v for k, v in out.items() if k != "findings"}, default=str
        )


class TestContractIsWhatTheSpecSays:
    """Catches a field being REMOVED from the contract.

    The whitelist tests elsewhere in this file catch the opposite direction - an
    internal field leaking out past the projection. Both directions need their
    own assertion, and only this one can be written without reading the
    implementation's own constants.
    """

    def test_top_level_contract_matches_the_spec_literally(self) -> None:
        assert views.EXTERNAL_TOP_LEVEL_FIELDS == _SPEC_TOP_LEVEL_FIELDS

    def test_finding_contract_matches_the_spec_literally(self) -> None:
        assert views.EXTERNAL_FINDING_FIELDS == _SPEC_FINDING_FIELDS

    def test_unsafe_reason_vocabulary_matches_the_spec_literally(self) -> None:
        assert views.UNSAFE_REASONS == _SPEC_UNSAFE_REASONS

    def test_snippet_hash_is_absent_from_the_spec_field_set(self) -> None:
        # INV-9, stated independently of the implementation: a hash of a
        # low-entropy secret is brute-forceable offline.
        assert "snippet_hash" not in _SPEC_FINDING_FIELDS

    def test_the_retired_scan_keyed_fields_are_absent_from_the_spec_field_set(self) -> None:
        # Stated independently of the implementation, so a well-meaning "restore
        # verdict for compatibility" has to change this literal too. The contract
        # is binary; a three-valued `verdict` alongside `is_safe` would give it two
        # sources of truth, and `fail_closed`/`requires_review` are each already
        # spelled as an `unsafe_reason` code.
        for retired in ("scan_id", "verdict", "fail_closed", "requires_review"):
            assert retired not in _SPEC_TOP_LEVEL_FIELDS
