"""Tests for `orchestration.floor` (coding spec §11.4 O-1, INV-1 backstop).
Pure, no infra needed."""

from __future__ import annotations

import re
from pathlib import Path

from monolith.modules.orchestration.floor import floor_engine_names, floor_engines

_TRANSLATIONS_TS = Path(__file__).resolve().parents[3] / "web" / "src" / "i18n" / "translations.ts"


class TestFloorEngines:
    def test_includes_static_keyword_engine(self) -> None:
        assert "static-keyword" in floor_engine_names()

    def test_includes_all_four_inhouse_detectors(self) -> None:
        # inhouse-provenance was removed 2026-07-24 (see
        # detectors/__init__.py's module docstring for why).
        names = floor_engine_names()
        assert {
            "inhouse-crypto-weak",
            "inhouse-file-type",
            "inhouse-pii",
            "inhouse-toctou",
        } <= names

    def test_includes_the_two_chinese_prompt_defense_detectors(self) -> None:
        names = floor_engine_names()
        assert {
            "inhouse-prompt-injection-zh",
            "inhouse-jailbreak-inducement-zh",
        } <= names

    def test_every_floor_engine_requires_no_network(self) -> None:
        for engine in floor_engines().values():
            assert engine.metadata.requires_network is False

    def test_every_floor_engine_has_a_display_name_in_both_locales(self) -> None:
        """Every floor engine needs an `engine.<name>` key in the web bundle, or
        the console falls back to printing the raw engine id.

        Found 2026-07-27 by looking at a real scan-detail page: Task 3/4 added
        `inhouse-mcp-config` and `inhouse-skill-permissions` but never registered
        their display names, so those two rows read "inhouse-mcp-config" while
        every neighbouring row read "Weak cryptography detection". Same shape as
        `test_real_v1_yaml_required_engines_includes_all_floor_engines` in
        test_gate_policy.py: adding a detector means updating several registries,
        and only a cross-registry assertion catches the one that was forgotten.

        Deliberately checks BOTH locale blocks - a key present in only one still
        shows the raw id to half the users.
        """
        source = _TRANSLATIONS_TS.read_text(encoding="utf-8")
        # Two locale objects in one module; count occurrences per key rather than
        # parsing TS - a key registered in only one locale appears exactly once.
        missing: dict[str, int] = {}
        for name in sorted(floor_engine_names()):
            hits = len(re.findall(rf"^\s*'engine\.{re.escape(name)}':", source, re.MULTILINE))
            if hits < 2:
                missing[name] = hits
        assert not missing, (
            "floor engines missing an 'engine.<name>' translation in one or both "
            f"locales (name -> locales found): {missing}"
        )

    def test_floor_still_detects_when_treated_as_the_only_available_engines(self) -> None:
        """SECURITY (M4 acceptance bar): 'floor 引擎在 mock sandbox 引擎返回空时
        仍命中字节模式(抗压制)' - byte-pattern detection must still fire even
        when every sandboxed OSS engine is degraded/suppressed and only the
        floor set is actually consulted."""
        engines = floor_engines()
        # NOTE: "eval(user_input)"/"hashlib.md5(x)" are inert scanned-content
        # bytes the floor engines are expected to flag - nothing here executes
        # or hashes anything itself.
        files = {"skill.py": b"eval(user_input)\nhashlib.md5(x)\n"}
        all_findings = [f for engine in engines.values() for f in engine.analyze(files).findings]
        assert len(all_findings) >= 2  # at least the eval() and md5() patterns fire
