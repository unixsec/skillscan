"""Tests for `engine_runner.adapters.osv` (coding spec §10) → SUP-01.

Exercises `parse_output` against representative JSON payloads shaped like the
real schema (confirmed by reading `vendor/osv-scanner/pkg/models/results.go`
directly).

CONFIRMED against a real `osv-scanner 2.4.0` binary on a dev VM (2026-07-09):
run with `--offline` but no local vulnerability database present, it exits
127 and prints the real reason ("could not load db for PyPI ecosystem...")
to STDERR only - STDOUT is still syntactically valid JSON
(`{"results": [], ...}`). Before the fix in `TestParseOutput`'s
`test_general_error_returncode_raises_even_with_well_formed_stdout` below,
`parse_output` would have parsed that as a genuine clean scan (0 findings,
`EngineStatus.OK`) - a real false-negative, indistinguishable from a package
with no known vulnerabilities. Fixed by checking `completed.returncode`
against osv-scanner's own documented Return Codes table
(`vendor/osv-scanner/docs/output.md`) before trusting stdout at all.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from engine_runner.adapters import osv
from skillscan_core import DetectionCategory, Severity


def _completed(payload: dict[str, object]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(
        args=["osv-scanner"], returncode=1, stdout=json.dumps(payload).encode(), stderr=b""
    )


def _vuln(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "summary": "Example vulnerability in requests",
    }
    base.update(overrides)
    return base


def _package_result(
    *,
    name: str = "requests",
    version: str = "2.25.0",
    vulns: list[dict[str, object]] | None = None,
    max_severity: str = "9.8",
) -> dict[str, object]:
    vulns = vulns if vulns is not None else [_vuln()]
    return {
        "package": {"name": name, "version": version, "ecosystem": "PyPI"},
        "vulnerabilities": vulns,
        "groups": [{"ids": [v["id"] for v in vulns], "max_severity": max_severity}],
    }


def _payload(
    *, path: str = "requirements.txt", packages: list[dict[str, object]] | None = None
) -> dict[str, object]:
    packages = packages if packages is not None else [_package_result()]
    return {"results": [{"source": {"path": path, "type": "lockfile"}, "packages": packages}]}


class TestParseOutput:
    def test_empty_stdout_yields_no_findings(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["osv-scanner"], returncode=0, stdout=b"", stderr=b""
        )
        assert osv.parse_output(completed, Path("."), {}) == ()

    def test_finding_extracted_with_package_and_version(self) -> None:
        findings = osv.parse_output(_completed(_payload()), Path("."), {})
        assert len(findings) == 1
        assert "requests@2.25.0" in findings[0].title
        assert findings[0].test_item_id == "SUP-01"
        assert findings[0].category is DetectionCategory.SUPPLY_CHAIN

    def test_source_path_set_as_file_path(self) -> None:
        findings = osv.parse_output(_completed(_payload(path="poetry.lock")), Path("."), {})
        assert findings[0].file_path == "poetry.lock"

    def test_no_vulnerabilities_yields_no_findings(self) -> None:
        payload = _payload(packages=[_package_result(vulns=[])])
        findings = osv.parse_output(_completed(payload), Path("."), {})
        assert findings == ()

    def test_multiple_packages_all_parsed(self) -> None:
        payload = _payload(
            packages=[
                _package_result(name="requests", version="2.25.0"),
                _package_result(name="pyyaml", version="5.3"),
            ]
        )
        findings = osv.parse_output(_completed(payload), Path("."), {})
        assert len(findings) == 2

    def test_missing_results_key_raises(self) -> None:
        with pytest.raises(ValueError, match="results"):
            osv.parse_output(_completed({"unexpected": []}), Path("."), {})

    def test_general_error_returncode_raises_even_with_well_formed_stdout(self) -> None:
        # SECURITY: reproduces the real live failure mode exactly - valid
        # JSON on stdout, the actual failure reason only on stderr, exit 127
        # ("General Error" per osv-scanner's own docs). Must raise (->
        # EngineStatus.ERROR upstream in base.py), never silently return
        # a clean-looking empty findings tuple.
        completed = subprocess.CompletedProcess(
            args=["osv-scanner"],
            returncode=127,
            stdout=json.dumps({"results": []}).encode(),
            stderr=b"could not load db for PyPI ecosystem: unable to fetch OSV database",
        )
        with pytest.raises(ValueError, match="127"):
            osv.parse_output(completed, Path("."), {})

    def test_no_packages_found_returncode_128_also_raises(self) -> None:
        # 128 = "No packages found" per osv-scanner's Return Codes table -
        # distinct from "0 vulnerabilities in packages that WERE scanned"
        # (returncode 0) and must not be conflated with a clean result.
        completed = subprocess.CompletedProcess(
            args=["osv-scanner"],
            returncode=128,
            stdout=json.dumps({"results": []}).encode(),
            stderr=b"",
        )
        with pytest.raises(ValueError, match="128"):
            osv.parse_output(completed, Path("."), {})

    def test_snippet_hash_derived_from_package_identity(self) -> None:
        findings = osv.parse_output(_completed(_payload()), Path("."), {})
        assert findings[0].snippet_hash is not None
        assert len(findings[0].snippet_hash) == 64


class TestSeverityFromMaxSeverity:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            ("9.8", Severity.CRITICAL),
            ("9.0", Severity.CRITICAL),
            ("7.5", Severity.HIGH),
            ("7.0", Severity.HIGH),
            ("5.0", Severity.MEDIUM),
            ("4.0", Severity.MEDIUM),
            ("2.0", Severity.LOW),
            ("0.0", Severity.LOW),
        ],
    )
    def test_cvss_threshold_mapping(self, score: str, expected: Severity) -> None:
        payload = _payload(packages=[_package_result(max_severity=score)])
        findings = osv.parse_output(_completed(payload), Path("."), {})
        assert findings[0].severity is expected

    def test_unparseable_severity_fails_toward_medium_not_low(self) -> None:
        # SECURITY: unparseable/missing severity must fail toward stricter
        # (MEDIUM), never toward laxer (LOW) - an unknown score is not "safe".
        payload = _payload(packages=[_package_result(max_severity="not-a-number")])
        findings = osv.parse_output(_completed(payload), Path("."), {})
        assert findings[0].severity is Severity.MEDIUM

    def test_missing_group_falls_back_to_medium_default(self) -> None:
        package = _package_result()
        package["groups"] = []
        payload = _payload(packages=[package])
        findings = osv.parse_output(_completed(payload), Path("."), {})
        assert findings[0].severity is Severity.MEDIUM


class TestMakeAdapter:
    def test_wires_metadata_and_argv_offline_flag(self) -> None:
        adapter = osv.make_adapter(ruleset_digest="db-snapshot-123", version="1.8.0")
        assert adapter.metadata.name == "osv-scanner"
        assert adapter.metadata.ruleset_digest == "db-snapshot-123"
        assert adapter._treat_nonzero_exit_as_error is False  # noqa: SLF001
        # SECURITY (INV-14): --offline is non-negotiable - verify the wired
        # build_argv actually includes it rather than trusting the docstring.
        argv = adapter._build_argv(Path("/tmp/probe"))  # noqa: SLF001
        assert "--offline" in argv
        assert "api.osv.dev" not in " ".join(argv)
