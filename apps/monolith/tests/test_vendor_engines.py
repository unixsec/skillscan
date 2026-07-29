"""Tests for `scripts/vendor_engines.py` (coding spec §10A vendoring pipeline
helper). `scripts/` is a standalone operational tool, not part of the
installed package surface - loaded here directly by file path rather than
via a package import.

Exercised against the REAL `vendor/engines.lock.yaml` and the REAL vendored
engine source committed in this repo (no mocking) wherever a test's whole
point is to catch real drift/license regressions against actual vendored
state (`verify-pins`/`license-scan` below) - a test against fake fixtures
would prove nothing there. `TestVendoredEngines`'s
TBD-repo/missing-commit exclusion tests are the one exception: they exercise
`vendored_engines()`'s pure filter logic itself, not any real vendor state,
so a synthetic in-memory fixture is the more direct test.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from typing import cast

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT_PATH = _REPO_ROOT / "scripts" / "vendor_engines.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("vendor_engines", _SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vendor_engines = _load_module()


@pytest.fixture(scope="module")
def real_engines() -> dict[str, dict[str, object]]:
    return cast(dict[str, dict[str, object]], vendor_engines.load_lock())


class TestLoadLock:
    def test_loads_real_lock_file(self, real_engines: dict[str, dict[str, object]]) -> None:
        assert "bandit" in real_engines
        assert "aig" in real_engines

    def test_missing_engines_key_raises(self, tmp_path: Path) -> None:
        bad_lock = tmp_path / "bad.yaml"
        bad_lock.write_text("not_engines: {}\n")
        with pytest.raises(ValueError, match="engines"):
            vendor_engines.load_lock(bad_lock)


class TestVendoredEngines:
    def test_tbd_repo_excluded(self) -> None:
        # SECURITY: repo: TBD (official repo unconfirmed) must never be
        # treated as vendored - synthetic fixture, not the real lock file,
        # since cisco_skill_scanner (this project's only historical TBD
        # example) was removed once confirmed dead - never vendored; see
        # `vendor/VENDOR.md`'s entry for it, and the two in-house Chinese
        # floor detectors under services/engine_runner/detectors/ that cover
        # the capability gap it was a candidate for. This keeps the exclusion
        # logic itself under real test coverage even with no live TBD entry.
        engines = {
            "confirmed_engine": {"repo": "https://github.com/example/tool", "commit": "abc123"},
            # commit is set here so this isolates the repo == "TBD" branch
            # specifically, independent of the missing-commit branch below.
            "unconfirmed_engine": {"repo": "TBD", "commit": "abc123"},
        }
        vendored = vendor_engines.vendored_engines(engines)
        assert "unconfirmed_engine" not in vendored

    def test_missing_commit_excluded(self) -> None:
        # SECURITY: a repo without a pinned commit is equally unvendored -
        # `vendored_engines` requires BOTH a real repo AND a commit.
        engines = {"no_commit_yet": {"repo": "https://github.com/example/tool", "commit": None}}
        vendored = vendor_engines.vendored_engines(engines)
        assert "no_commit_yet" not in vendored

    def test_real_vendored_engines_included(
        self, real_engines: dict[str, dict[str, object]]
    ) -> None:
        vendored = vendor_engines.vendored_engines(real_engines)
        assert {"skillspector", "aig", "bandit", "osv_scanner", "yara"} <= set(vendored)


class TestVerifyPinsAgainstRealVendoredSource:
    def test_real_vendored_source_matches_its_recorded_pin(
        self, real_engines: dict[str, dict[str, object]]
    ) -> None:
        failures = vendor_engines.verify_pins(real_engines)
        assert failures == []

    def test_missing_vendor_directory_reported(
        self, real_engines: dict[str, dict[str, object]], tmp_path: Path
    ) -> None:
        failures = vendor_engines.verify_pins(real_engines, vendor_dir=tmp_path)
        assert len(failures) == len(vendor_engines.vendored_engines(real_engines))
        assert all("does not exist" in f for f in failures)

    def test_drifted_tree_detected(
        self, real_engines: dict[str, dict[str, object]], tmp_path: Path
    ) -> None:
        import subprocess

        # A real, self-contained git repo whose committed vendor/bandit/ holds
        # CONTENT DIFFERENT from the tree recorded in engines.lock.yaml -
        # proves drift detection fires on a genuine content mismatch, not just
        # on a missing directory.
        #
        # Deliberately built from scratch here rather than pointed at the outer
        # checkout: this test then needs nothing from its environment and keeps
        # passing where the repo arrives without `.git` (the dev VM's rsync).
        bandit_dir = tmp_path / "vendor" / "bandit"
        bandit_dir.mkdir(parents=True)
        (bandit_dir / "placeholder.txt").write_text("not the real bandit source")
        for argv in (
            ["git", "init", "-q"],
            ["git", "config", "user.email", "test@example.com"],
            ["git", "config", "user.name", "test"],
            ["git", "add", "."],
            ["git", "commit", "-q", "-m", "placeholder"],
        ):
            subprocess.run(argv, cwd=tmp_path, check=True)

        single_engine = {"bandit": real_engines["bandit"]}
        failures = vendor_engines.verify_pins(
            single_engine, vendor_dir=tmp_path / "vendor", repo_root=tmp_path
        )
        assert len(failures) == 1
        assert "DRIFT" in failures[0]

    def test_missing_tree_pin_reported(
        self, real_engines: dict[str, dict[str, object]], tmp_path: Path
    ) -> None:
        # An engine recorded WITHOUT a `tree:` must be reported, never silently
        # treated as verified - the whole point of the pin is fail-closed.
        bandit_dir = tmp_path / "vendor" / "bandit"
        bandit_dir.mkdir(parents=True)
        spec = dict(real_engines["bandit"])
        spec.pop("tree", None)
        failures = vendor_engines.verify_pins(
            {"bandit": spec}, vendor_dir=tmp_path / "vendor", repo_root=tmp_path
        )
        assert len(failures) == 1
        assert "no `tree:` recorded" in failures[0]


class TestLicenseScanAgainstRealVendoredSource:
    def test_real_vendored_engines_pass_license_scan(
        self, real_engines: dict[str, dict[str, object]]
    ) -> None:
        failures = vendor_engines.license_scan(real_engines)
        assert failures == []

    def test_disallowed_recorded_license_rejected(
        self, real_engines: dict[str, dict[str, object]]
    ) -> None:
        tampered = {
            "bandit": {**real_engines["bandit"], "license": "GPL-3.0"},
        }
        failures = vendor_engines.license_scan(tampered)
        assert len(failures) == 1
        assert "not on the permissive allowlist" in failures[0]

    def test_missing_license_file_reported(
        self, real_engines: dict[str, dict[str, object]], tmp_path: Path
    ) -> None:
        engine_dir = tmp_path / "bandit"
        engine_dir.mkdir()
        single_engine = {"bandit": real_engines["bandit"]}
        failures = vendor_engines.license_scan(single_engine, vendor_dir=tmp_path)
        assert len(failures) == 1
        assert "no LICENSE/COPYING file found" in failures[0]

    def test_gpl_marker_in_license_text_fails_closed_even_if_recorded_license_is_permissive(
        self, real_engines: dict[str, dict[str, object]], tmp_path: Path
    ) -> None:
        # SECURITY: even if engines.lock.yaml's own `license:` field were
        # wrong/stale, the actual LICENSE file content is the ground truth -
        # a real GPL marker must still fail closed.
        engine_dir = tmp_path / "bandit"
        engine_dir.mkdir()
        (engine_dir / "LICENSE").write_text("GNU GENERAL PUBLIC LICENSE\nVersion 3\n")
        single_engine = {"bandit": {**real_engines["bandit"], "license": "Apache-2.0"}}
        failures = vendor_engines.license_scan(single_engine, vendor_dir=tmp_path)
        assert len(failures) == 1
        assert "fail-closed on copyleft" in failures[0]


class TestCliCommands:
    def test_status_command_runs_against_real_lock_file(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        exit_code = vendor_engines.main(["status"])
        assert exit_code == 0
        out = capsys.readouterr().out
        # PRE-EXISTING FAILURE, fixed 2026-07-29: this asserted
        # "adapter_status=not_built" for aig, true only until 2026-07-09, when
        # the mcp-scan subsystem got a real adapter and engines.lock.yaml moved
        # aig to `built` (VENDOR.md's "Adapter status" section records the same
        # correction). The assertion has been wrong ever since and nobody saw
        # it: deploy_and_test_vm.sh filters out EVERY test_vendor_engines.py
        # failure, because the pin checks can never pass on a VM checkout that
        # arrives without `.git`. A blanket per-file filter hides unrelated
        # regressions in that file too - that is the real lesson here.
        assert "aig" in out
        for engine in ("skillspector", "aig", "bandit", "osv_scanner", "yara"):
            assert f"{engine:<12}  role=mandatory   adapter_status=built" in out

    def test_verify_pins_command_succeeds_against_real_repo_state(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        exit_code = vendor_engines.main(["verify-pins"])
        assert exit_code == 0
        assert "OK" in capsys.readouterr().out

    def test_license_scan_command_succeeds_against_real_repo_state(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        exit_code = vendor_engines.main(["license-scan"])
        assert exit_code == 0
        assert "OK" in capsys.readouterr().out

    def test_no_command_is_a_usage_error(self) -> None:
        with pytest.raises(SystemExit):
            vendor_engines.main([])
