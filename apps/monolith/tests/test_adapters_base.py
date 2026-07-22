"""Tests for `engine_runner.adapters.base.SubprocessEngineAdapter` (coding
spec §10, INV-15). Pure - no real OSS engine binary needed; a small
`python3 -c` script stands in as the "subprocess engine" so these tests are
portable and depend on nothing beyond the interpreter already running them.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest
from engine_runner.adapters.base import SubprocessEngineAdapter
from skillscan_core import (
    DetectionCategory,
    EngineCapability,
    EngineMetadata,
    EngineStatus,
    Finding,
    Severity,
)


def _metadata(**overrides: object) -> EngineMetadata:
    defaults: dict[str, object] = {
        "name": "fake-engine",
        "version": "1.0.0",
        "ruleset_digest": "deadbeef",
        "capabilities": frozenset({EngineCapability.STATIC}),
    }
    defaults.update(overrides)
    return EngineMetadata(**defaults)  # type: ignore[arg-type]


def _fixed_findings(
    _completed: subprocess.CompletedProcess[bytes], _target_dir: Path, _files: dict[str, bytes]
) -> tuple[Finding, ...]:
    return (
        Finding(
            rule_id="fake.rule",
            test_item_id="TEST-01",
            category=DetectionCategory.CODE,
            title="fake finding",
            severity=Severity.LOW,
            confidence=0.5,
            source_engine="fake-engine",
            source_capability=EngineCapability.STATIC,
        ),
    )


def _never_called_argv(_target_dir: Path) -> list[str]:
    raise AssertionError("build_argv must not be invoked for this scenario")


def _never_called_parse(
    _completed: subprocess.CompletedProcess[bytes], _target_dir: Path, _files: dict[str, bytes]
) -> tuple[Finding, ...]:
    raise AssertionError("parse_output must not be invoked for this scenario")


class TestMetadataProperty:
    def test_metadata_returns_constructor_value(self) -> None:
        meta = _metadata(name="probe")
        adapter = SubprocessEngineAdapter(
            metadata=meta,
            build_argv=lambda _target_dir: [sys.executable, "-c", "pass"],
            parse_output=_fixed_findings,
        )
        assert adapter.metadata is meta
        assert adapter.metadata.name == "probe"


class TestHappyPath:
    def test_zero_exit_parses_findings(self) -> None:
        adapter = SubprocessEngineAdapter(
            metadata=_metadata(),
            build_argv=lambda _target_dir: [sys.executable, "-c", "print('ok')"],
            parse_output=_fixed_findings,
        )
        result = adapter.analyze({})
        assert result.status is EngineStatus.OK
        assert result.usable
        assert len(result.findings) == 1
        assert result.findings[0].rule_id == "fake.rule"

    def test_llm_used_reflects_metadata_requires_llm(self) -> None:
        adapter = SubprocessEngineAdapter(
            metadata=_metadata(
                requires_llm=True, capabilities=frozenset({EngineCapability.SEMANTIC_LLM})
            ),
            build_argv=lambda _target_dir: [sys.executable, "-c", "pass"],
            parse_output=_fixed_findings,
        )
        result = adapter.analyze({})
        assert result.llm_used is True

    def test_files_materialized_into_target_dir_with_correct_bytes(self) -> None:
        # SECURITY: proves the adapter actually writes the ORIGINAL scanned
        # bytes into the temp dir the engine subprocess sees - not some
        # re-encoded or truncated copy.
        captured: dict[str, str] = {}

        def build_argv(target_dir: Path) -> list[str]:
            script = (
                "import pathlib, sys; "
                f"sys.stdout.write(pathlib.Path({str(target_dir / 'skill.py')!r}).read_text())"
            )
            return [sys.executable, "-c", script]

        def parse_output(
            completed: subprocess.CompletedProcess[bytes],
            _target_dir: Path,
            _files: dict[str, bytes],
        ) -> tuple[Finding, ...]:
            captured["stdout"] = completed.stdout.decode()
            return ()

        adapter = SubprocessEngineAdapter(
            metadata=_metadata(), build_argv=build_argv, parse_output=parse_output
        )
        result = adapter.analyze({"skill.py": b"print('hello')\n"})
        assert result.status is EngineStatus.OK
        assert captured["stdout"] == "print('hello')\n"

    def test_parse_output_receives_original_files_dict(self) -> None:
        seen: dict[str, dict[str, bytes]] = {}

        def parse_output(
            _completed: subprocess.CompletedProcess[bytes],
            _target_dir: Path,
            files: dict[str, bytes],
        ) -> tuple[Finding, ...]:
            seen["files"] = files
            return ()

        adapter = SubprocessEngineAdapter(
            metadata=_metadata(),
            build_argv=lambda _target_dir: [sys.executable, "-c", "pass"],
            parse_output=parse_output,
        )
        original = {"a.py": b"one", "b.py": b"two"}
        adapter.analyze(original)
        assert seen["files"] == original


class TestCallableEnv:
    """SECURITY regression (2026-07-10 full-project review, Finding #16): `env`
    may be a callable, re-invoked immediately before EVERY subprocess spawn
    (not just once at adapter construction) - lets an adapter embedding a
    validated-internal-endpoint URL (skillspector.py/aig.py's LLM base_url)
    re-run its DNS-rebinding-sensitive validation fresh each time, since
    make_adapter() itself only runs once per process at startup."""

    def test_callable_env_is_invoked_and_used_for_subprocess(self) -> None:
        calls = 0

        def build_env() -> dict[str, str]:
            nonlocal calls
            calls += 1
            return {"PROBE_MARKER": f"call-{calls}"}

        adapter = SubprocessEngineAdapter(
            metadata=_metadata(),
            build_argv=lambda _target_dir: [
                sys.executable,
                "-c",
                "import os, sys; sys.stdout.write(os.environ.get('PROBE_MARKER', 'MISSING'))",
            ],
            parse_output=lambda completed, _t, _f: (
                Finding(
                    rule_id="probe",
                    test_item_id="TEST-01",
                    category=DetectionCategory.CODE,
                    title=completed.stdout.decode(),
                    severity=Severity.LOW,
                    confidence=1.0,
                    source_engine="fake-engine",
                    source_capability=EngineCapability.STATIC,
                ),
            ),
            env=build_env,
        )
        first = adapter.analyze({})
        second = adapter.analyze({})
        assert calls == 2, "a callable env must be re-invoked on every analyze() call"
        assert first.findings[0].title == "call-1"
        assert second.findings[0].title == "call-2"

    def test_callable_env_raising_value_error_fails_closed_not_crashes(self) -> None:
        # SECURITY: a callable env raising ValueError (e.g.
        # require_internal_endpoint rejecting a since-rebound hostname) must
        # become a fail-closed EngineStatus.ERROR, never propagate out of
        # analyze() and never fall back to spawning with a stale/unvalidated
        # environment.
        def raising_env() -> dict[str, str]:
            raise ValueError("endpoint no longer resolves internally")

        adapter = SubprocessEngineAdapter(
            metadata=_metadata(),
            # build_argv/parse_output are harmless no-ops here - argv is built
            # (pure string construction, no side effects) before env is
            # resolved, but the subprocess itself must never actually launch,
            # which _never_called_parse would catch if it somehow did.
            build_argv=lambda _target_dir: [sys.executable, "-c", "pass"],
            parse_output=_never_called_parse,
            env=raising_env,
        )
        result = adapter.analyze({})
        assert result.status is EngineStatus.ERROR
        assert not result.usable
        assert result.error is not None
        assert "endpoint re-validation failed" in result.error

    def test_plain_dict_env_still_works_unchanged(self) -> None:
        # Non-regression: bandit/yara/osv's adapters all still pass a plain
        # dict (or None) - must keep working exactly as before.
        adapter = SubprocessEngineAdapter(
            metadata=_metadata(),
            build_argv=lambda _target_dir: [
                sys.executable,
                "-c",
                "import os, sys; sys.stdout.write(os.environ.get('PROBE_MARKER', 'MISSING'))",
            ],
            parse_output=lambda completed, _t, _f: (
                Finding(
                    rule_id="probe",
                    test_item_id="TEST-01",
                    category=DetectionCategory.CODE,
                    title=completed.stdout.decode(),
                    severity=Severity.LOW,
                    confidence=1.0,
                    source_engine="fake-engine",
                    source_capability=EngineCapability.STATIC,
                ),
            ),
            env={"PROBE_MARKER": "static-value"},
        )
        result = adapter.analyze({})
        assert result.findings[0].title == "static-value"


class TestTimeout:
    def test_slow_engine_times_out(self) -> None:
        adapter = SubprocessEngineAdapter(
            metadata=_metadata(),
            build_argv=lambda _target_dir: [sys.executable, "-c", "import time; time.sleep(5)"],
            parse_output=_never_called_parse,
            timeout_s=0.2,
        )
        result = adapter.analyze({})
        assert result.status is EngineStatus.TIMEOUT
        assert not result.usable
        assert result.findings == ()

    def test_deadline_already_passed_short_circuits_before_any_work(self) -> None:
        # SECURITY: an already-expired absolute deadline must fail-closed
        # immediately - never materialize files or spawn a process first.
        # `deadline` is a wall-clock epoch value (time.time()-based) - see
        # `analyze()`'s own comment - matching every real caller
        # (airlock.now_epoch() + N, itself time.time()-based), not
        # time.monotonic() (an arbitrary-origin uptime counter no real caller
        # ever passes here).
        adapter = SubprocessEngineAdapter(
            metadata=_metadata(), build_argv=_never_called_argv, parse_output=_never_called_parse
        )
        result = adapter.analyze({"a.py": b"x"}, deadline=time.time() - 10)
        assert result.status is EngineStatus.TIMEOUT

    def test_deadline_shorter_than_timeout_s_wins(self) -> None:
        # SECURITY: the per-scan absolute deadline must be able to cut a
        # long-configured timeout_s short, not the other way around.
        # `deadline` is wall-clock epoch (time.time()-based), matching every
        # real caller - see `analyze()`'s own comment.
        adapter = SubprocessEngineAdapter(
            metadata=_metadata(),
            build_argv=lambda _target_dir: [sys.executable, "-c", "import time; time.sleep(5)"],
            parse_output=_never_called_parse,
            timeout_s=60.0,
        )
        started = time.monotonic()
        result = adapter.analyze({}, deadline=time.time() + 0.2)
        elapsed = time.monotonic() - started
        assert result.status is EngineStatus.TIMEOUT
        assert elapsed < 5.0

    def test_realistic_wall_clock_deadline_epoch_actually_bounds_the_engine(self) -> None:
        # SECURITY REGRESSION: every real caller (services/engine_runner/
        # worker.py, orchestration/service.py) threads a wall-clock
        # `deadline_epoch` shaped exactly like `airlock.now_epoch() + N`
        # (airlock.now_epoch() = time.time()) - never a monotonic-clock
        # value. Before the fix, `analyze()` computed
        # `remaining = deadline - time.monotonic()`: subtracting a small,
        # arbitrary-origin uptime counter from a ~1.7-billion-second epoch
        # value produced a "remaining" of tens of years, so
        # `min(relative_timeout, remaining)` always resolved to the
        # adapter's own fixed `timeout_s` - the real shared scan budget
        # never actually constrained anything. Here `timeout_s` is
        # deliberately large (60s) and the realistic deadline_epoch is
        # small (0.3s): under the bug this would run the full 5s sleep
        # uninterrupted (bounded only by timeout_s, nowhere near 60s); under
        # the fix it must time out close to the small deadline instead.
        adapter = SubprocessEngineAdapter(
            metadata=_metadata(),
            build_argv=lambda _target_dir: [sys.executable, "-c", "import time; time.sleep(5)"],
            parse_output=_never_called_parse,
            timeout_s=60.0,
        )
        deadline_epoch = time.time() + 0.3  # realistic caller shape: now_epoch() + N
        started = time.monotonic()
        result = adapter.analyze({}, deadline=deadline_epoch)
        elapsed = time.monotonic() - started
        assert result.status is EngineStatus.TIMEOUT
        assert not result.usable
        # Bounded by the small deadline (~0.3s), not by timeout_s (60s) and
        # not by the sleep(5) - proves `remaining` was computed from the
        # correct (wall-clock) origin, not a monotonic/epoch mismatch that
        # would have let the full 60s timeout_s or the full 5s sleep win.
        assert elapsed < 5.0


class TestNonzeroExit:
    def test_nonzero_exit_is_error_by_default(self) -> None:
        adapter = SubprocessEngineAdapter(
            metadata=_metadata(),
            build_argv=lambda _target_dir: [sys.executable, "-c", "import sys; sys.exit(3)"],
            parse_output=_never_called_parse,
        )
        result = adapter.analyze({})
        assert result.status is EngineStatus.ERROR
        assert result.error is not None and "exited 3" in result.error

    def test_nonzero_exit_still_parsed_when_flag_disabled(self) -> None:
        # SECURITY: bandit/osv-scanner/skillspector use nonzero exit to mean
        # "findings reported", not "crashed" - opting out must still parse.
        adapter = SubprocessEngineAdapter(
            metadata=_metadata(),
            build_argv=lambda _target_dir: [sys.executable, "-c", "import sys; sys.exit(1)"],
            parse_output=_fixed_findings,
            treat_nonzero_exit_as_error=False,
        )
        result = adapter.analyze({})
        assert result.status is EngineStatus.OK
        assert len(result.findings) == 1


class TestFailClosedOnUnusableOutput:
    def test_missing_binary_is_error_not_exception(self) -> None:
        adapter = SubprocessEngineAdapter(
            metadata=_metadata(),
            build_argv=lambda _target_dir: ["this-binary-does-not-exist-xyz-123"],
            parse_output=_never_called_parse,
        )
        result = adapter.analyze({})
        assert result.status is EngineStatus.ERROR
        assert not result.usable

    def test_parse_output_exception_is_error_not_propagated(self) -> None:
        def exploding_parse(
            _completed: subprocess.CompletedProcess[bytes],
            _target_dir: Path,
            _files: dict[str, bytes],
        ) -> tuple[Finding, ...]:
            raise ValueError("malformed output")

        adapter = SubprocessEngineAdapter(
            metadata=_metadata(),
            build_argv=lambda _target_dir: [sys.executable, "-c", "print('ok')"],
            parse_output=exploding_parse,
        )
        result = adapter.analyze({})
        assert result.status is EngineStatus.ERROR
        assert result.error is not None and "malformed output" in result.error

    def test_empty_findings_is_still_ok_not_indistinguishable_error(self) -> None:
        # A genuinely clean scan (zero findings) must remain OK, distinct
        # from ERROR/TIMEOUT - callers rely on `.usable` to tell them apart.
        adapter = SubprocessEngineAdapter(
            metadata=_metadata(),
            build_argv=lambda _target_dir: [sys.executable, "-c", "pass"],
            parse_output=lambda _c, _t, _f: (),
        )
        result = adapter.analyze({})
        assert result.status is EngineStatus.OK
        assert result.usable
        assert result.findings == ()


class TestPathEscapeDefenseInDepth:
    @pytest.mark.parametrize("escaping_path", ["../evil.txt", "../../etc/passwd"])
    def test_escaping_relative_path_rejected_before_subprocess_spawn(
        self, escaping_path: str
    ) -> None:
        # SECURITY: `engine_runner.normalizer.unpack_hardened` is the primary
        # control against traversal paths ever reaching here - this proves
        # the adapter's OWN defense-in-depth check also holds on its own,
        # independent of that upstream guarantee.
        adapter = SubprocessEngineAdapter(
            metadata=_metadata(), build_argv=_never_called_argv, parse_output=_never_called_parse
        )
        result = adapter.analyze({escaping_path: b"pwned"})
        assert result.status is EngineStatus.ERROR
        assert result.error is not None and "escaping path" in result.error
