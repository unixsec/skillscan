"""Tests for `engine_runner.adapters.bandit` (coding spec §10) → CODE-10,
FILE-06, CODE-01, CODE-08, CODE-02, CODE-07 (2026-07-27: corrected/expanded
from the previously mislabelled CODE-12/FILE-04 - see bandit.py's module
docstring).

`TestParseOutput` exercises the parsing logic against representative JSON
payloads shaped like the real schema (confirmed by reading
`vendor/bandit/bandit/formatters/json.py` - and by actually running the
installed `bandit` CLI, see `TestRealEndToEnd` below, which is what caught
the B303-vs-B324 test-ID mismatch fixed in bandit.py's `_CODE_10_TEST_IDS`).

`TestRealEndToEnd` runs the REAL `bandit` CLI (a lightweight, pure-Python dev
dependency - `pyproject.toml`'s `[dependency-groups] dev`) through the full
`SubprocessEngineAdapter.analyze()` pipeline against an on-disk vulnerable
sample - genuine proof this adapter works against the real tool, not just
against a hand-shaped JSON fixture, matching this project's established
preference for real-infra verification over mocks wherever feasible.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path

import pytest
from engine_runner.adapters import bandit
from skillscan_core import DetectionCategory, EngineStatus, Severity


def _completed(
    payload: Mapping[str, object], returncode: int = 1
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(
        args=["bandit"], returncode=returncode, stdout=json.dumps(payload).encode(), stderr=b""
    )


def _result(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "filename": "skill.py",
        "test_id": "B105",
        "test_name": "hardcoded_password_string",
        "issue_severity": "MEDIUM",
        "issue_confidence": "HIGH",
        "issue_text": "Possible hardcoded password.",
        "line_number": 12,
        "code": "password = 'hunter2'\n",
    }
    base.update(overrides)
    return base


class TestParseOutput:
    def test_weak_hash_test_id_maps_to_code_10(self) -> None:
        # 2026-07-27: corrected from CODE-12 ("进程创建"/process creation in the
        # catalog, not weak crypto) to CODE-10 ("弱加密"/weak encryption), the
        # actual catalog entry for bandit's weak-hash/cipher/random test IDs.
        payload = {"results": [_result(test_id="B324")], "errors": [], "metrics": {}}
        findings = bandit.parse_output(_completed(payload), Path("."), {})
        assert len(findings) == 1
        assert findings[0].test_item_id == "CODE-10"
        assert findings[0].category is DetectionCategory.CODE

    def test_hardcoded_tmp_dir_maps_to_file_06(self) -> None:
        # 2026-07-27: corrected from FILE-04 ("任意文件读取"/arbitrary file read
        # in the catalog, not TOCTOU) to FILE-06 ("临时文件与符号链接风险"), the
        # actual catalog entry for B108 (hardcoded_tmp_directory).
        payload = {"results": [_result(test_id="B108")], "errors": [], "metrics": {}}
        findings = bandit.parse_output(_completed(payload), Path("."), {})
        assert findings[0].test_item_id == "FILE-06"
        assert findings[0].category is DetectionCategory.FILE_PACKAGE

    @pytest.mark.parametrize(
        ("test_id", "expected_item"),
        [
            # command injection / system command execution family.
            ("B602", "CODE-01"),
            ("B603", "CODE-01"),
            ("B605", "CODE-01"),
            ("B607", "CODE-01"),
            # hardcoded SQL string construction - SQL injection.
            ("B608", "CODE-08"),
            # eval() on a possibly-untrusted string - dynamic code execution.
            ("B307", "CODE-02"),
            # pickle/dill/shelve of untrusted data - insecure deserialization,
            # a DISTINCT catalog item from CODE-02 (see bandit.py's own
            # _CODE_07_TEST_IDS comment for why these aren't lumped together).
            ("B301", "CODE-07"),
        ],
    )
    def test_2026_07_27_added_mappings(self, test_id: str, expected_item: str) -> None:
        payload = {"results": [_result(test_id=test_id)], "errors": [], "metrics": {}}
        findings = bandit.parse_output(_completed(payload), Path("."), {})
        assert findings[0].test_item_id == expected_item
        assert findings[0].category is DetectionCategory.CODE

    def test_unmapped_test_id_falls_back_to_gen_01_not_the_raw_id(self) -> None:
        # 2026-07-27: the fallback used to pass bandit's own raw test_id
        # straight through to test_item_id - that never matches a catalog
        # entry, so a report keyed on the catalog silently counted it as
        # UNCOVERED. B101 (assert_used) has no specific catalog mapping and
        # never will (it's a code-quality lint, not a security-catalog item);
        # the fallback must now be the catalog's own explicit "detected but
        # unclassified" marker, GEN-01 - never the raw engine id again.
        payload = {"results": [_result(test_id="B101")], "errors": [], "metrics": {}}
        findings = bandit.parse_output(_completed(payload), Path("."), {})
        assert findings[0].test_item_id == "GEN-01"
        assert findings[0].category is DetectionCategory.CODE

    def test_severity_and_confidence_mapped(self) -> None:
        payload = {
            "results": [_result(issue_severity="HIGH", issue_confidence="LOW")],
            "errors": [],
            "metrics": {},
        }
        findings = bandit.parse_output(_completed(payload), Path("."), {})
        assert findings[0].severity is Severity.HIGH
        assert findings[0].confidence == pytest.approx(0.3)

    def test_undefined_severity_fails_toward_stricter_medium(self) -> None:
        payload = {
            "results": [_result(issue_severity="UNDEFINED")],
            "errors": [],
            "metrics": {},
        }
        findings = bandit.parse_output(_completed(payload), Path("."), {})
        assert findings[0].severity is Severity.MEDIUM

    def test_snippet_hash_set_when_code_present(self) -> None:
        payload = {"results": [_result(code="secret = 1\n")], "errors": [], "metrics": {}}
        findings = bandit.parse_output(_completed(payload), Path("."), {})
        assert findings[0].snippet_hash is not None
        assert len(findings[0].snippet_hash) == 64

    def test_snippet_hash_none_when_code_absent(self) -> None:
        payload = {"results": [_result(code="")], "errors": [], "metrics": {}}
        findings = bandit.parse_output(_completed(payload), Path("."), {})
        assert findings[0].snippet_hash is None

    def test_evidence_redacted_never_contains_raw_code_snippet(self) -> None:
        # SECURITY (INV-9): the raw `code` field is a plaintext snippet from
        # the scanned file - it must only ever reach snippet_hash, never
        # evidence_redacted (which carries bandit's own issue_text instead).
        raw_secret = "AKIAABCDEFGHIJKLMNOP"
        payload = {
            "results": [_result(code=f"key = '{raw_secret}'\n", issue_text="Possible secret")],
            "errors": [],
            "metrics": {},
        }
        findings = bandit.parse_output(_completed(payload), Path("."), {})
        assert raw_secret not in findings[0].evidence_redacted

    def test_multiple_results_all_parsed(self) -> None:
        payload = {
            "results": [_result(test_id="B105"), _result(test_id="B324", line_number=20)],
            "errors": [],
            "metrics": {},
        }
        findings = bandit.parse_output(_completed(payload), Path("."), {})
        assert len(findings) == 2

    def test_missing_results_key_raises(self) -> None:
        with pytest.raises(ValueError, match="results"):
            bandit.parse_output(_completed({"errors": []}), Path("."), {})

    def test_source_engine_and_capability_set(self) -> None:
        payload = {"results": [_result()], "errors": [], "metrics": {}}
        findings = bandit.parse_output(_completed(payload), Path("."), {})
        assert findings[0].source_engine == "bandit"
        assert findings[0].rule_id.startswith("bandit.")


class TestMakeAdapter:
    def test_wires_metadata_and_nonzero_exit_tolerance(self) -> None:
        adapter = bandit.make_adapter(ruleset_digest="abc123", version="1.9.4")
        assert adapter.metadata.name == "bandit"
        assert adapter.metadata.version == "1.9.4"
        assert adapter.metadata.ruleset_digest == "abc123"
        # SECURITY: bandit exits 1 on findings-present, not a crash - the
        # adapter must not treat that as ERROR (see module docstring).
        assert adapter._treat_nonzero_exit_as_error is False  # noqa: SLF001


@pytest.mark.skipif(shutil.which("bandit") is None, reason="bandit CLI not installed")
class TestRealEndToEnd:
    """Genuine subprocess proof against the actual installed bandit binary -
    not a hand-shaped JSON fixture. This is what caught the real B303-vs-B324
    test-ID mismatch (see module docstring and bandit.py's _CODE_10_TEST_IDS
    comment)."""

    def test_real_bandit_finds_weak_hash_and_shell_true(self, tmp_path: Path) -> None:
        vulnerable = tmp_path / "sample.py"
        vulnerable.write_text(
            "import hashlib\n"
            "import subprocess\n"
            "\n"
            "def weak_hash(data):\n"
            "    return hashlib.md5(data).hexdigest()\n"
            "\n"
            "def run_cmd(user_input):\n"
            "    subprocess.call(user_input, shell=True)\n"
        )
        adapter = bandit.make_adapter(ruleset_digest="live-cli-probe", version="1.9.4")
        result = adapter.analyze({"sample.py": vulnerable.read_bytes()})

        assert result.status is EngineStatus.OK
        assert result.usable
        rule_ids = {f.rule_id for f in result.findings}
        assert "bandit.B324" in rule_ids  # hashlib weak-hash plugin
        assert any(f.test_item_id == "CODE-10" for f in result.findings)
        assert any("shell" in f.evidence_redacted.lower() for f in result.findings)

    def test_real_bandit_clean_file_yields_zero_findings(self, tmp_path: Path) -> None:
        clean = tmp_path / "clean.py"
        clean.write_text("def add(a, b):\n    return a + b\n")
        adapter = bandit.make_adapter(ruleset_digest="live-cli-probe", version="1.9.4")
        result = adapter.analyze({"clean.py": clean.read_bytes()})
        assert result.status is EngineStatus.OK
        assert result.findings == ()
