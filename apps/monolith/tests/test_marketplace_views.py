"""Tests for `marketplace_api.views` (里程碑 B' spec §5).

Pure functions, no infra needed - same as test_floor.py.
"""

from __future__ import annotations

from typing import Any

import pytest

from monolith.modules.marketplace_api import views


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


_VERDICT_ROW: dict[str, Any] = {
    "verdict": "REVIEW",
    "score": 62,
    "policy_version": "v1",
    "issued_at": "2026-07-28T02:00:00Z",
    "jws_signature": "eyJhbGciOiJSUzI1NiJ9.stub.sig",
}

_RESULT_ROW: dict[str, Any] = {
    "findings_capped": False,
    "findings_total": 1,
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


class TestScanProjection:
    def test_top_level_field_set_is_exactly_the_whitelist(self) -> None:
        out = views.project_scan(
            scan_id="s1",
            internal_state="decided",
            verdict_row=_VERDICT_ROW,
            result_row=_RESULT_ROW,
        )
        assert set(out) == views.EXTERNAL_TOP_LEVEL_FIELDS

    def test_finding_field_set_is_exactly_the_whitelist(self) -> None:
        out = views.project_scan(
            scan_id="s1",
            internal_state="decided",
            verdict_row=_VERDICT_ROW,
            result_row=_RESULT_ROW,
        )
        assert set(out["findings"][0]) == views.EXTERNAL_FINDING_FIELDS

    def test_snippet_hash_is_never_exposed(self) -> None:
        # SECURITY (INV-9, spec §5.3): a hash of a low-entropy secret can be
        # brute-forced offline. The marketplace has no use for it.
        out = views.project_scan(
            scan_id="s1",
            internal_state="decided",
            verdict_row=_VERDICT_ROW,
            result_row=_RESULT_ROW,
        )
        assert "snippet_hash" not in out["findings"][0]

    def test_a_pending_scan_reports_no_verdict(self) -> None:
        out = views.project_scan(
            scan_id="s1", internal_state="queued", verdict_row=None, result_row=None
        )
        assert out["status"] == "PENDING"
        assert out["verdict"] is None
        assert out["score"] is None
        assert out["policy_version"] is None
        assert out["decided_at"] is None
        assert out["findings"] == []
        assert out["poll_after_ms"] == 5_000

    def test_a_failed_scan_is_completed_block_with_no_findings(self) -> None:
        # spec §5.1: fail-closed produces a real signed BLOCK. There is no
        # ScanResultRow, so findings are empty - but the decision stands.
        out = views.project_scan(
            scan_id="s1",
            internal_state="failed",
            verdict_row={**_VERDICT_ROW, "verdict": "BLOCK", "score": 0},
            result_row=None,
        )
        assert out["status"] == "COMPLETED"
        assert out["verdict"] == "BLOCK"
        assert out["fail_closed"] is True
        assert out["findings"] == []
        assert out["poll_after_ms"] == 0

    def test_policy_version_and_decided_at_carry_the_verdicts_own_values(self) -> None:
        """spec §7 non-repudiation: WHICH policy decided this, and WHEN.

        Both fields went entirely unasserted until 2026-07-28 - hardcoding
        `"policy_version": None` and `"decided_at": None` in `project_scan`
        passed this whole file plus the router suite. Without them a caller
        cannot bind a verdict to the policy that produced it, and a signed
        verdict with no decision time is not evidence of anything.

        `decided_at` is a cross-layer RENAME: `gate.service.get_verdict_view`
        emits `issued_at`, this projection reads that key and republishes it as
        `decided_at`. Note `_VERDICT_ROW` carries NO `decided_at` key of its
        own, so this passes only if the rename actually happens - which is the
        exact shape that silently goes null when either side is renamed alone.
        """
        out = views.project_scan(
            scan_id="s1",
            internal_state="decided",
            verdict_row=_VERDICT_ROW,
            result_row=_RESULT_ROW,
        )
        assert "decided_at" not in _VERDICT_ROW  # the premise of the rename claim
        assert out["policy_version"] == "v1"
        assert out["decided_at"] == "2026-07-28T02:00:00Z"

    def test_a_fail_closed_verdict_still_reports_its_policy_and_decision_time(self) -> None:
        # The fail-closed BLOCK (spec §5.1) is the verdict most likely to be
        # disputed, so it is the one that can least afford to lose the two
        # fields that anchor it to a policy version and a moment in time.
        out = views.project_scan(
            scan_id="s1",
            internal_state="failed",
            verdict_row={**_VERDICT_ROW, "verdict": "BLOCK", "score": 0},
            result_row=None,
        )
        assert out["fail_closed"] is True
        assert out["policy_version"] == "v1"
        assert out["decided_at"] == "2026-07-28T02:00:00Z"

    def test_requires_review_is_true_only_for_review(self) -> None:
        for verdict, expected in (("PASS", False), ("REVIEW", True), ("BLOCK", False)):
            out = views.project_scan(
                scan_id="s1",
                internal_state="decided",
                verdict_row={**_VERDICT_ROW, "verdict": verdict},
                result_row=_RESULT_ROW,
            )
            assert out["requires_review"] is expected, verdict

    def test_judged_at_tier_reports_the_tier_the_verdict_was_decided_at(self) -> None:
        # SECURITY (C2): submissions are single-flight on content + toolchain, so
        # a caller can be handed a verdict decided at ANOTHER submitter's tier -
        # and the tier is the BLOCK threshold (public: HIGH, everything else:
        # CRITICAL). PARTNER here is neither the deployment default nor the
        # default M2M grant, so this cannot pass by coincidence.
        out = views.project_scan(
            scan_id="s1",
            internal_state="decided",
            verdict_row=_VERDICT_ROW,
            result_row=_RESULT_ROW,
            judged_at_tier="partner",
        )
        assert out["judged_at_tier"] == "partner"

    def test_an_unrecorded_tier_is_null_rather_than_a_guess(self) -> None:
        # A scan with no recorded tier fell back to the deployment default at
        # decide time - runtime configuration this pure function cannot see.
        # Reporting the likely value would misstate the basis of a real
        # decision; null says "not recorded", which is what is actually known.
        out = views.project_scan(
            scan_id="s1", internal_state="queued", verdict_row=None, result_row=None
        )
        assert out["judged_at_tier"] is None

    def test_a_looser_judgment_than_requested_is_disclosed(self) -> None:
        # SECURITY (Task 18) - the case this pair of fields exists for, and the
        # commonest one on this surface. A marketplace service account defaults
        # to PUBLIC, the STRICTEST tier (policies/gate/v1.yaml blocks it at
        # HIGH); its submission deduplicates onto a console submission judged at
        # `internal` (blocks only at CRITICAL); so the verdict it is handed was
        # reached under a MORE PERMISSIVE ruleset than it asked for, and a
        # finding that should have blocked for it can read PASS.
        out = views.project_scan(
            scan_id="s1",
            internal_state="decided",
            verdict_row=_VERDICT_ROW,
            result_row=_RESULT_ROW,
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
        out = views.project_scan(
            scan_id="s1",
            internal_state="decided",
            verdict_row=_VERDICT_ROW,
            result_row=_RESULT_ROW,
            judged_at_tier="internal",
        )
        assert out["judged_at_tier"] == "internal"
        assert out["requested_tier"] is None
        assert out["tier_direction"] is None
        assert out["tier_direction_basis"] is None

    def test_summary_counts_by_severity(self) -> None:
        result = {
            "findings_capped": False,
            "findings_total": 5,
            "findings": [{**_RESULT_ROW["findings"][0], "severity": s} for s in (1, 2, 3, 3, 4)],
        }
        out = views.project_scan(
            scan_id="s1", internal_state="decided", verdict_row=_VERDICT_ROW, result_row=result
        )
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
            "findings": _RESULT_ROW["findings"],  # len 1: the post-cap page returned
        }
        out = views.project_scan(
            scan_id="s1", internal_state="decided", verdict_row=_VERDICT_ROW, result_row=result
        )
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
            "findings": _RESULT_ROW["findings"],
        }
        out = views.project_scan(
            scan_id="s1", internal_state="decided", verdict_row=_VERDICT_ROW, result_row=result
        )
        assert out["summary"]["truncated"] is True
        assert out["summary"]["total"] == len(result["findings"])


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
        out = views.project_scan(
            scan_id="s1",
            internal_state="decided",
            verdict_row=_VERDICT_ROW,
            result_row={"findings_capped": False, "findings": [polluted]},
        )
        assert set(out["findings"][0]) == views.EXTERNAL_FINDING_FIELDS

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
_SPEC_TOP_LEVEL_FIELDS = frozenset(
    {
        "scan_id",
        "status",
        "verdict",
        "score",
        "policy_version",
        "decided_at",
        "verdict_jws",
        "fail_closed",
        "requires_review",
        "poll_after_ms",
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
        "summary",
        "findings",
    }
)

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

    def test_snippet_hash_is_absent_from_the_spec_field_set(self) -> None:
        # INV-9, stated independently of the implementation: a hash of a
        # low-entropy secret is brute-forceable offline.
        assert "snippet_hash" not in _SPEC_FINDING_FIELDS
