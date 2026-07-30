"""Unit tests for skillscan_core.models (coding spec M1, §5.1)."""

from __future__ import annotations

import dataclasses
import unittest

from skillscan_core import (
    MAX_CATEGORY_WEIGHT,
    AllowlistEntry,
    CategoryWeights,
    DetectionCategory,
    EngineCapability,
    EngineMetadata,
    EngineResult,
    EngineStatus,
    Finding,
    GatePolicy,
    ScanMode,
    Severity,
    TrifectaSignal,
    TrustTier,
    Verdict,
    VerdictResult,
)
from skillscan_core.models import _canonical_policy_term


class TestSeverityAndVerdictOrdering(unittest.TestCase):
    def test_severity_max_picks_most_severe(self) -> None:
        self.assertEqual(max(Severity.LOW, Severity.CRITICAL), Severity.CRITICAL)

    def test_verdict_max_picks_stricter(self) -> None:
        self.assertEqual(max(Verdict.PASS, Verdict.BLOCK), Verdict.BLOCK)
        self.assertEqual(max(Verdict.REVIEW, Verdict.PASS), Verdict.REVIEW)


class TestFinding(unittest.TestCase):
    def _base_kwargs(self, **overrides: object) -> dict:
        kwargs: dict = dict(
            rule_id="rule.1",
            test_item_id="CODE-01",
            category=DetectionCategory.CODE,
            title="t",
            severity=Severity.MEDIUM,
            confidence=0.5,
            source_engine="eng",
            source_capability=EngineCapability.STATIC,
        )
        kwargs.update(overrides)
        return kwargs

    def test_valid_finding_constructs(self) -> None:
        f = Finding(**self._base_kwargs())
        self.assertEqual(f.trifecta_signals, frozenset())

    def test_rejects_empty_rule_id(self) -> None:
        with self.assertRaises(ValueError):
            Finding(**self._base_kwargs(rule_id=""))

    def test_rejects_confidence_out_of_range(self) -> None:
        with self.assertRaises(ValueError):
            Finding(**self._base_kwargs(confidence=1.5))
        with self.assertRaises(ValueError):
            Finding(**self._base_kwargs(confidence=-0.1))

    def test_rejects_none_severity(self) -> None:
        with self.assertRaises(ValueError):
            Finding(**self._base_kwargs(severity=Severity.NONE))

    def test_rejects_plaintext_snippet_hash(self) -> None:
        with self.assertRaises(ValueError):
            Finding(**self._base_kwargs(snippet_hash="os.environ['SECRET']"))

    def test_accepts_hex_snippet_hash(self) -> None:
        f = Finding(**self._base_kwargs(snippet_hash="deadbeef"))
        self.assertEqual(f.snippet_hash, "deadbeef")

    def test_trifecta_signals_normalized_to_frozenset(self) -> None:
        f = Finding(**self._base_kwargs(trifecta_signals=[TrifectaSignal.EXTERNAL_EGRESS]))
        self.assertIsInstance(f.trifecta_signals, frozenset)

    def test_is_llm_sourced(self) -> None:
        det = Finding(**self._base_kwargs(source_capability=EngineCapability.STATIC))
        llm = Finding(**self._base_kwargs(source_capability=EngineCapability.SEMANTIC_LLM))
        self.assertFalse(det.is_llm_sourced)
        self.assertTrue(llm.is_llm_sourced)

    def test_dedup_key(self) -> None:
        f = Finding(**self._base_kwargs(file_path="a.py", start_line=3))
        self.assertEqual(f.dedup_key, ("rule.1", "a.py", 3, DetectionCategory.CODE))


class TestEngineMetadata(unittest.TestCase):
    def test_rejects_empty_name_or_version(self) -> None:
        with self.assertRaises(ValueError):
            EngineMetadata(name="", version="1", ruleset_digest="d", capabilities=frozenset())
        with self.assertRaises(ValueError):
            EngineMetadata(name="n", version="", ruleset_digest="d", capabilities=frozenset())

    def test_rejects_requires_network(self) -> None:
        with self.assertRaises(ValueError):
            EngineMetadata(
                name="n",
                version="1",
                ruleset_digest="d",
                capabilities=frozenset(),
                requires_network=True,
            )


class TestEngineResult(unittest.TestCase):
    def _metadata(self) -> EngineMetadata:
        return EngineMetadata(name="n", version="1", ruleset_digest="d", capabilities=frozenset())

    def test_usable_statuses(self) -> None:
        for status, expected in (
            (EngineStatus.OK, True),
            (EngineStatus.PARTIAL, True),
            (EngineStatus.ERROR, False),
            (EngineStatus.TIMEOUT, False),
        ):
            with self.subTest(status=status):
                result = EngineResult(
                    engine=self._metadata(),
                    findings=(),
                    status=status,
                    scan_mode=ScanMode.STATIC,
                )
                self.assertEqual(result.usable, expected)


class TestGatePolicy(unittest.TestCase):
    def test_rejects_empty_version(self) -> None:
        with self.assertRaises(ValueError):
            GatePolicy(version="", required_engines=frozenset())

    def test_rejects_fail_closed_pass(self) -> None:
        with self.assertRaises(ValueError):
            GatePolicy(version="v1", required_engines=frozenset(), fail_closed_verdict=Verdict.PASS)

    def test_rejects_looser_tier_override(self) -> None:
        with self.assertRaises(ValueError):
            GatePolicy(
                version="v1",
                required_engines=frozenset(),
                block_on_severity=Severity.HIGH,
                tier_block_overrides=((TrustTier.PUBLIC, Severity.CRITICAL),),
            )

    def test_accepts_stricter_tier_override(self) -> None:
        policy = GatePolicy(
            version="v1",
            required_engines=frozenset(),
            block_on_severity=Severity.HIGH,
            tier_block_overrides=((TrustTier.PUBLIC, Severity.MEDIUM),),
        )
        self.assertEqual(policy.block_threshold(TrustTier.PUBLIC), Severity.MEDIUM)
        self.assertEqual(policy.block_threshold(TrustTier.INTERNAL), Severity.HIGH)

    def test_block_threshold_takes_strictest_of_multiple_overrides(self) -> None:
        policy = GatePolicy(
            version="v1",
            required_engines=frozenset(),
            block_on_severity=Severity.CRITICAL,
            tier_block_overrides=(
                (TrustTier.PUBLIC, Severity.HIGH),
                (TrustTier.PUBLIC, Severity.MEDIUM),
            ),
        )
        self.assertEqual(policy.block_threshold(TrustTier.PUBLIC), Severity.MEDIUM)


class TestAllowlistEntry(unittest.TestCase):
    def _base_kwargs(self, **overrides: object) -> dict:
        kwargs: dict = dict(
            scope_type="content_hash",
            scope_value="abc123",
            rule_id="rule.1",
            expires_at=1000.0,
            approved_by="approver",
            requested_by="requester",
        )
        kwargs.update(overrides)
        return kwargs

    def test_rejects_same_approver_and_requester(self) -> None:
        with self.assertRaises(ValueError):
            AllowlistEntry(**self._base_kwargs(approved_by="same", requested_by="same"))

    def test_rejects_empty_approver_or_requester(self) -> None:
        with self.assertRaises(ValueError):
            AllowlistEntry(**self._base_kwargs(approved_by=""))

    def test_rejects_non_positive_expiry(self) -> None:
        with self.assertRaises(ValueError):
            AllowlistEntry(**self._base_kwargs(expires_at=0.0))
        with self.assertRaises(ValueError):
            AllowlistEntry(**self._base_kwargs(expires_at=-5.0))

    def test_rejects_invalid_scope_type(self) -> None:
        with self.assertRaises(ValueError):
            AllowlistEntry(**self._base_kwargs(scope_type="bogus"))

    def test_rejects_empty_scope_value_for_non_global_scope(self) -> None:
        with self.assertRaises(ValueError):
            AllowlistEntry(**self._base_kwargs(scope_type="content_hash", scope_value=""))
        with self.assertRaises(ValueError):
            AllowlistEntry(**self._base_kwargs(scope_type="skill_id", scope_value=""))

    def test_allows_empty_scope_value_for_rule_global(self) -> None:
        # scope_value is meaningless for rule_global (is_active() never reads
        # it) - the web UI submits it empty for this scope type, so this must
        # succeed rather than raise (previously untested combination that
        # made every rule_global waiver a guaranteed 400 in the live UI).
        entry = AllowlistEntry(**self._base_kwargs(scope_type="rule_global", scope_value=""))
        self.assertTrue(entry.is_active(0.0, "anything"))

    def test_is_active_expiry(self) -> None:
        entry = AllowlistEntry(**self._base_kwargs(expires_at=100.0))
        self.assertTrue(entry.is_active(50.0, "abc123"))
        self.assertFalse(entry.is_active(100.0, "abc123"))  # strict: now>=expires_at -> expired
        self.assertFalse(entry.is_active(150.0, "abc123"))

    def test_is_active_scope_matching(self) -> None:
        by_hash = AllowlistEntry(**self._base_kwargs(scope_type="content_hash", scope_value="H1"))
        self.assertTrue(by_hash.is_active(0.0, "H1"))
        self.assertFalse(by_hash.is_active(0.0, "H2"))

        by_skill = AllowlistEntry(**self._base_kwargs(scope_type="skill_id", scope_value="S1"))
        self.assertTrue(by_skill.is_active(0.0, "H1", "S1"))
        self.assertFalse(by_skill.is_active(0.0, "H1", "S2"))
        self.assertFalse(by_skill.is_active(0.0, "H1", None))

        global_entry = AllowlistEntry(**self._base_kwargs(scope_type="rule_global"))
        self.assertTrue(global_entry.is_active(0.0, "anything"))

    def test_waives_matches_by_rule_id(self) -> None:
        entry = AllowlistEntry(**self._base_kwargs(rule_id="rule.1"))
        finding = Finding(
            rule_id="rule.1",
            test_item_id="x",
            category=DetectionCategory.CODE,
            title="t",
            severity=Severity.LOW,
            confidence=1.0,
            source_engine="e",
            source_capability=EngineCapability.STATIC,
        )
        other = Finding(
            rule_id="rule.2",
            test_item_id="x",
            category=DetectionCategory.CODE,
            title="t",
            severity=Severity.LOW,
            confidence=1.0,
            source_engine="e",
            source_capability=EngineCapability.STATIC,
        )
        self.assertTrue(entry.waives(finding))
        self.assertFalse(entry.waives(other))


class TestCategoryWeights(unittest.TestCase):
    def test_defaults_are_all_neutral(self) -> None:
        weights = CategoryWeights()
        for category in DetectionCategory:
            self.assertEqual(weights.for_category(category), 1.0)

    def test_for_category_reads_the_matching_field(self) -> None:
        weights = CategoryWeights(data_credential=2.5)
        self.assertEqual(weights.for_category(DetectionCategory.DATA_CREDENTIAL), 2.5)
        self.assertEqual(weights.for_category(DetectionCategory.CODE), 1.0)

    def test_every_detection_category_has_a_weight_field(self) -> None:
        # Field-discovering, not a hardcoded list: a DetectionCategory added
        # without a matching weight field would otherwise only fail the first
        # time a finding in that category was scored.
        fields = {spec.name for spec in dataclasses.fields(CategoryWeights)}
        self.assertEqual(fields, {c.value for c in DetectionCategory})

    def test_negative_weight_rejected_at_construction(self) -> None:
        # SECURITY: a negative weight inverts security_score's penalty term -
        # a finding in that category would RAISE the score.
        with self.assertRaises(ValueError) as ctx:
            CategoryWeights(permission=-0.1)
        self.assertIn("permission", str(ctx.exception))

    def test_absurd_weight_rejected_at_construction(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            CategoryWeights(supply_chain=MAX_CATEGORY_WEIGHT + 0.1)
        self.assertIn("supply_chain", str(ctx.exception))

    def test_bounds_themselves_are_accepted(self) -> None:
        self.assertEqual(CategoryWeights(code=0.0).code, 0.0)
        self.assertEqual(CategoryWeights(code=MAX_CATEGORY_WEIGHT).code, float(MAX_CATEGORY_WEIGHT))

    def test_non_finite_weight_rejected(self) -> None:
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                CategoryWeights(code=bad)

    def test_non_numeric_weight_rejected(self) -> None:
        with self.assertRaises(ValueError):
            CategoryWeights(code="2.0")  # type: ignore[arg-type]
        # bool is an int subclass and must not read as 1.0/0.0.
        with self.assertRaises(ValueError):
            CategoryWeights(code=True)  # type: ignore[arg-type]

    def test_int_is_normalized_to_float(self) -> None:
        # So a YAML `2` and a YAML `2.0` are the same policy - equal values,
        # and therefore the same cache_policy_version.
        self.assertEqual(CategoryWeights(code=2), CategoryWeights(code=2.0))  # type: ignore[arg-type]
        self.assertEqual(CategoryWeights(code=1), CategoryWeights())  # type: ignore[arg-type]

    def test_non_default_items_reports_only_divergent_fields(self) -> None:
        self.assertEqual(CategoryWeights().non_default_items(), ())
        self.assertEqual(
            CategoryWeights(code=2.0, supply_chain=0.5).non_default_items(),
            (("code", 2.0), ("supply_chain", 0.5)),
        )


class TestGatePolicyCachePolicyVersion(unittest.TestCase):
    """INV-7 (milestone C Tasks 5 and 11): the policy identity the toolchain
    digest binds, as opposed to the one a verdict records."""

    def _policy(self, **overrides: object) -> GatePolicy:
        params: dict[str, object] = {"version": "v7", "required_engines": frozenset({"e"})}
        params.update(overrides)
        return GatePolicy(**params)  # type: ignore[arg-type]

    def test_the_version_is_the_prefix_and_the_semantics_the_suffix(self) -> None:
        # Task 11 gave up Task 5's identity element on purpose (no threshold is
        # "neutral" the way an all-1.0 weight is), so EVERY policy now carries a
        # suffix. The version must still be readable off the front of it - it is
        # the only handle a human has when comparing two digests.
        policy = self._policy()
        self.assertTrue(policy.cache_policy_version.startswith("v7+p1:"))
        self.assertNotEqual(policy.cache_policy_version, "v7")

    def test_every_gate_policy_field_reaches_the_cache_policy_version(self) -> None:
        """FIELD-DISCOVERING, deliberately: the milestone's recurring defect is
        "new field added, second registry not updated", and a policy field that
        silently drops out of this digest is exactly that defect in its most
        expensive form - the cache would keep serving verdicts adjudicated
        under the old value of it.

        Each entry is a value that MUST produce a different digest. Adding a
        field to `GatePolicy` without adding one here fails on the coverage
        assertion, which is the point: whoever adds the field has to state
        whether it reaches an adjudication.
        """
        different: dict[str, object] = {
            "required_engines": frozenset({"e", "other"}),
            "hard_gate_rules": frozenset({"pii.us_ssn"}),
            "review_confidence": 0.9,
            "block_on_severity": Severity.HIGH,
            "review_on_severity": Severity.MEDIUM,
            "tier_block_overrides": ((TrustTier.PUBLIC, Severity.HIGH),),
            "allowlistable_max_severity": Severity.MEDIUM,
            "fail_closed_verdict": Verdict.REVIEW,
            "category_weights": CategoryWeights(code=2.0),
        }
        covered = {spec.name for spec in dataclasses.fields(GatePolicy)} - {"version"}
        self.assertEqual(
            set(different),
            covered,
            "a GatePolicy field is not covered here - decide whether it reaches "
            "an adjudication (it almost certainly does; see "
            "GatePolicy.adjudication_semantics) and add a differing value",
        )

        baseline = self._policy().cache_policy_version
        for name, value in different.items():
            with self.subTest(field=name):
                self.assertNotEqual(baseline, self._policy(**{name: value}).cache_policy_version)

    def test_the_semantics_string_is_stable_across_equal_policies(self) -> None:
        # Two processes must derive the same digest from the same policy, or
        # every published skill reads as permanently stale and every cache miss
        # is a rescan. frozenset iteration order is the concrete hazard.
        a = self._policy(required_engines=frozenset({"z", "a", "m"}))
        b = self._policy(required_engines=frozenset({"m", "z", "a"}))
        self.assertEqual(a.adjudication_semantics(), b.adjudication_semantics())
        self.assertEqual(a.cache_policy_version, b.cache_policy_version)

    def test_the_semantics_string_names_the_scheme_version(self) -> None:
        self.assertTrue(
            self._policy()
            .adjudication_semantics()
            .startswith("skillscan.gate_policy.adjudication_semantics.v1\n")
        )

    def test_an_uncanonicalisable_value_raises_rather_than_falling_back(self) -> None:
        # The guard on the guard: a fallback to repr() would be silently wrong
        # for set-like values (unstable order) and silently inert for a type
        # whose repr does not move with its content.
        with self.assertRaises(TypeError) as ctx:
            _canonical_policy_term(object())
        self.assertIn("canonicalise", str(ctx.exception))

    def test_bool_and_int_do_not_collide(self) -> None:
        self.assertNotEqual(_canonical_policy_term(True), _canonical_policy_term(1))

    def test_a_weighted_policy_diverges_from_its_version(self) -> None:
        weighted = self._policy(category_weights=CategoryWeights(code=2.0))
        self.assertEqual(weighted.version, "v7")
        self.assertNotEqual(weighted.cache_policy_version, "v7")

    def test_different_weights_give_different_cache_policy_versions(self) -> None:
        a = self._policy(category_weights=CategoryWeights(code=2.0))
        b = self._policy(category_weights=CategoryWeights(code=3.0))
        self.assertNotEqual(a.cache_policy_version, b.cache_policy_version)

    def test_same_weights_reached_differently_agree(self) -> None:
        # Determinism: the digest input must not depend on kwarg order or on
        # int-vs-float spelling, or an unchanged policy would look changed and
        # trigger a rescan of everything on every restart.
        a = self._policy(category_weights=CategoryWeights(code=2.0, permission=0.5))
        b = self._policy(category_weights=CategoryWeights(permission=0.5, code=2))  # type: ignore[arg-type]
        self.assertEqual(a.cache_policy_version, b.cache_policy_version)

    def test_a_weighted_policy_still_records_the_bare_version(self) -> None:
        # `VerdictRow.policy_version` and `tier_divergence` compare against
        # `.version`; only the digest uses the derived form.
        weighted = self._policy(category_weights=CategoryWeights(code=2.0))
        self.assertEqual(weighted.version, "v7")


class TestVerdictResultScore(unittest.TestCase):
    def test_score_field_round_trips(self) -> None:
        result = VerdictResult(
            verdict=Verdict.PASS,
            reasons=(),
            policy_version="v1",
            effective_severity=Severity.NONE,
            trifecta_present=False,
            hard_gate_hits=(),
            fail_closed=False,
            score=100,
        )
        self.assertEqual(result.score, 100)

    def test_fail_closed_has_no_default_and_must_be_stated(self) -> None:
        # SECURITY: a default of False would let a new construction site silently
        # assert "this verdict was reached on a COMPLETE scan", which is the exact
        # wrong answer the field exists to stop being inferred.
        with self.assertRaises(TypeError):
            VerdictResult(  # type: ignore[call-arg]
                verdict=Verdict.PASS,
                reasons=(),
                policy_version="v1",
                effective_severity=Severity.NONE,
                trifecta_present=False,
                hard_gate_hits=(),
                score=100,
            )


if __name__ == "__main__":
    unittest.main()
