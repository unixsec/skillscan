"""Tests for `gate.policy` (coding spec §11.6: versioned GatePolicy loading).

`TestLoadRealPolicyFile` loads the REAL `policies/gate/v1.yaml` shipped in
this repo, not a synthetic fixture - proving the actual file this project
ships parses into a valid GatePolicy, not just that the parser handles some
hypothetical shape.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from skillscan_core import Severity, TrustTier, Verdict

from monolith.modules.gate.policy import (
    GatePolicyLoadError,
    load_gate_policy,
    parse_gate_policy,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_REAL_POLICY_PATH = _REPO_ROOT / "policies" / "gate" / "v1.yaml"


def _minimal_raw(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "version": "v1",
        "required_engines": ["static-keyword"],
    }
    base.update(overrides)
    return base


class TestLoadRealPolicyFile:
    def test_real_v1_yaml_loads(self) -> None:
        policy = load_gate_policy(_REAL_POLICY_PATH)
        assert policy.version == "v1"

    def test_real_v1_yaml_required_engines_includes_all_floor_engines(self) -> None:
        from monolith.modules.orchestration.floor import floor_engine_names

        policy = load_gate_policy(_REAL_POLICY_PATH)
        assert floor_engine_names() <= policy.required_engines

    def test_real_v1_yaml_hard_gate_rules_non_empty(self) -> None:
        policy = load_gate_policy(_REAL_POLICY_PATH)
        assert len(policy.hard_gate_rules) > 0

    def test_real_v1_yaml_tier_override_tightens_public(self) -> None:
        policy = load_gate_policy(_REAL_POLICY_PATH)
        assert policy.block_threshold(TrustTier.PUBLIC) <= policy.block_on_severity


class TestLoadGatePolicyErrors:
    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(GatePolicyLoadError, match="cannot read"):
            load_gate_policy(tmp_path / "does-not-exist.yaml")

    def test_invalid_yaml_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("version: [unterminated\n")
        with pytest.raises(GatePolicyLoadError, match="not valid YAML"):
            load_gate_policy(bad)

    def test_non_mapping_top_level_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("- just\n- a\n- list\n")
        with pytest.raises(GatePolicyLoadError, match="YAML mapping"):
            load_gate_policy(bad)


class TestParseGatePolicy:
    def test_minimal_valid_payload(self) -> None:
        policy = parse_gate_policy(_minimal_raw())
        assert policy.version == "v1"
        assert policy.required_engines == frozenset({"static-keyword"})
        assert policy.hard_gate_rules == frozenset()

    def test_missing_version_raises(self) -> None:
        raw = _minimal_raw()
        del raw["version"]
        with pytest.raises(GatePolicyLoadError, match="version"):
            parse_gate_policy(raw)

    def test_empty_version_raises(self) -> None:
        with pytest.raises(GatePolicyLoadError, match="version"):
            parse_gate_policy(_minimal_raw(version=""))

    def test_missing_required_engines_raises(self) -> None:
        with pytest.raises(GatePolicyLoadError, match="required_engines"):
            parse_gate_policy({"version": "v1"})

    def test_required_engines_wrong_type_raises(self) -> None:
        with pytest.raises(GatePolicyLoadError, match="required_engines"):
            parse_gate_policy(_minimal_raw(required_engines="not-a-list"))

    def test_required_engines_with_non_string_item_raises(self) -> None:
        with pytest.raises(GatePolicyLoadError, match="required_engines"):
            parse_gate_policy(_minimal_raw(required_engines=["ok", 123]))

    def test_unknown_severity_string_raises(self) -> None:
        with pytest.raises(GatePolicyLoadError, match="unknown severity"):
            parse_gate_policy(_minimal_raw(block_on_severity="SUPER_CRITICAL"))

    def test_unknown_verdict_string_raises(self) -> None:
        with pytest.raises(GatePolicyLoadError, match="unknown verdict"):
            parse_gate_policy(_minimal_raw(fail_closed_verdict="MAYBE"))

    def test_fail_closed_verdict_pass_rejected_by_gate_policy_itself(self) -> None:
        # SECURITY: GatePolicy.__post_init__'s own invariant (fail_closed_verdict
        # != PASS) must surface as a GatePolicyLoadError, not an unhandled ValueError.
        with pytest.raises(GatePolicyLoadError, match="GatePolicy validation"):
            parse_gate_policy(_minimal_raw(fail_closed_verdict="PASS"))

    def test_tier_override_severity_looser_than_base_rejected(self) -> None:
        # SECURITY: GatePolicy itself enforces overrides may only tighten -
        # a LOOSER override (base=HIGH, override=CRITICAL i.e. weaker) must
        # still surface as a load error, not silently accepted.
        with pytest.raises(GatePolicyLoadError, match="GatePolicy validation"):
            parse_gate_policy(
                _minimal_raw(
                    block_on_severity="HIGH",
                    tier_block_overrides=[{"tier": "public", "severity": "CRITICAL"}],
                )
            )

    def test_valid_tier_override_parsed(self) -> None:
        policy = parse_gate_policy(
            _minimal_raw(
                block_on_severity="CRITICAL",
                tier_block_overrides=[{"tier": "public", "severity": "HIGH"}],
            )
        )
        assert policy.block_threshold(TrustTier.PUBLIC) == Severity.HIGH
        assert policy.block_threshold(TrustTier.INTERNAL) == Severity.CRITICAL

    def test_tier_override_missing_key_raises(self) -> None:
        with pytest.raises(GatePolicyLoadError, match="tier_block_overrides"):
            parse_gate_policy(_minimal_raw(tier_block_overrides=[{"tier": "public"}]))

    def test_review_confidence_wrong_type_raises(self) -> None:
        with pytest.raises(GatePolicyLoadError, match="review_confidence"):
            parse_gate_policy(_minimal_raw(review_confidence="high"))

    def test_all_optional_fields_parsed(self) -> None:
        policy = parse_gate_policy(
            _minimal_raw(
                hard_gate_rules=["rule.a", "rule.b"],
                review_confidence=0.75,
                block_on_severity="HIGH",
                review_on_severity="MEDIUM",
                allowlistable_max_severity="MEDIUM",
                fail_closed_verdict="BLOCK",
            )
        )
        assert policy.hard_gate_rules == frozenset({"rule.a", "rule.b"})
        assert policy.review_confidence == 0.75
        assert policy.block_on_severity is Severity.HIGH
        assert policy.review_on_severity is Severity.MEDIUM
        assert policy.allowlistable_max_severity is Severity.MEDIUM
        assert policy.fail_closed_verdict is Verdict.BLOCK
