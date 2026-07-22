"""Tests for `orchestration.floor` (coding spec §11.4 O-1, INV-1 backstop).
Pure, no infra needed."""

from __future__ import annotations

from monolith.modules.orchestration.floor import floor_engine_names, floor_engines


class TestFloorEngines:
    def test_includes_static_keyword_engine(self) -> None:
        assert "static-keyword" in floor_engine_names()

    def test_includes_all_five_inhouse_detectors(self) -> None:
        names = floor_engine_names()
        assert {
            "inhouse-crypto-weak",
            "inhouse-file-type",
            "inhouse-pii",
            "inhouse-toctou",
            "inhouse-provenance",
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
