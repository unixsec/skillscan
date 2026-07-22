"""Unit tests for skillscan_core.engines (coding spec M1, §5.5 - INV-7)."""

from __future__ import annotations

import copy
import unittest

from skillscan_core.engines import (
    _STATIC_KEYWORD_PATTERNS,
    StaticKeywordEngine,
    _static_keyword_ruleset_digest,
)
from skillscan_core.models import DetectionCategory, Severity, TrifectaSignal


class TestStaticKeywordRulesetDigest(unittest.TestCase):
    # INV-7 regression (2026-07-06 spec-compliance audit): the digest must
    # change if a rule's severity/category/trifecta_signal changes, not just
    # its rule_id/pattern - otherwise toolchain_digest/cache_key stay the same
    # and a stale cached PASS survives a rule severity upgrade.
    def test_digest_changes_when_severity_changes_for_same_rule_id_and_pattern(self) -> None:
        original_digest = _static_keyword_ruleset_digest()

        import skillscan_core.engines as engines_module

        patched = list(copy.deepcopy(_STATIC_KEYWORD_PATTERNS))
        pattern, rule_id, category, severity, trifecta_signal, title = patched[0]
        self.assertNotEqual(severity, Severity.CRITICAL, "test needs a real severity change")
        patched[0] = (pattern, rule_id, category, Severity.CRITICAL, trifecta_signal, title)

        original_patterns = engines_module._STATIC_KEYWORD_PATTERNS
        try:
            engines_module._STATIC_KEYWORD_PATTERNS = tuple(patched)
            changed_digest = engines_module._static_keyword_ruleset_digest()
        finally:
            engines_module._STATIC_KEYWORD_PATTERNS = original_patterns

        self.assertNotEqual(
            original_digest,
            changed_digest,
            "changing an existing rule's severity must change the ruleset digest",
        )

    def test_digest_changes_when_category_changes(self) -> None:
        import skillscan_core.engines as engines_module

        patched = list(copy.deepcopy(_STATIC_KEYWORD_PATTERNS))
        pattern, rule_id, category, severity, trifecta_signal, title = patched[0]
        new_category = (
            DetectionCategory.SUPPLY_CHAIN
            if category is not DetectionCategory.SUPPLY_CHAIN
            else DetectionCategory.PERMISSION
        )
        patched[0] = (pattern, rule_id, new_category, severity, trifecta_signal, title)

        original_patterns = engines_module._STATIC_KEYWORD_PATTERNS
        try:
            original_digest = engines_module._static_keyword_ruleset_digest()
            engines_module._STATIC_KEYWORD_PATTERNS = tuple(patched)
            changed_digest = engines_module._static_keyword_ruleset_digest()
        finally:
            engines_module._STATIC_KEYWORD_PATTERNS = original_patterns

        self.assertNotEqual(original_digest, changed_digest)

    def test_digest_changes_when_trifecta_signal_changes(self) -> None:
        import skillscan_core.engines as engines_module

        patched = list(copy.deepcopy(_STATIC_KEYWORD_PATTERNS))
        pattern, rule_id, category, severity, trifecta_signal, title = patched[0]
        new_signal = None if trifecta_signal is not None else TrifectaSignal.EXTERNAL_EGRESS
        patched[0] = (pattern, rule_id, category, severity, new_signal, title)

        original_patterns = engines_module._STATIC_KEYWORD_PATTERNS
        try:
            original_digest = engines_module._static_keyword_ruleset_digest()
            engines_module._STATIC_KEYWORD_PATTERNS = tuple(patched)
            changed_digest = engines_module._static_keyword_ruleset_digest()
        finally:
            engines_module._STATIC_KEYWORD_PATTERNS = original_patterns

        self.assertNotEqual(original_digest, changed_digest)

    def test_digest_stable_when_nothing_changes(self) -> None:
        self.assertEqual(_static_keyword_ruleset_digest(), _static_keyword_ruleset_digest())

    def test_engine_metadata_exposes_current_digest(self) -> None:
        engine = StaticKeywordEngine()
        self.assertEqual(engine.metadata.ruleset_digest, _static_keyword_ruleset_digest())


if __name__ == "__main__":
    unittest.main()
