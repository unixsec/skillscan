"""Subprocess-invoked OSS engine adapter base class (coding spec §10, INV-15).

LICENSE (INV-15 copyleft isolation): every subclass calls its engine ONLY via
`subprocess` CLI invocation - never `import`s the vendored engine's source,
never links against it. Arm's-length invocation + mere aggregation of the
engine's own stdout does not create a derivative work under any license,
which is what makes it safe to run these adapters against permissively- AND
copyleft-licensed engines alike (this project only vendors permissive-licensed
engines by policy - see vendor/engines.lock.yaml's license scan - but the
subprocess boundary is enforced uniformly regardless, per this project's own
supply-chain posture).

SECURITY: `subprocess.run(...)` is called with an explicit argv list and
`shell=False` (the default, but never overridden) - never a shell-interpreted
command string, so there is no shell metacharacter injection surface even
though some argv elements are derived from scanned-content file paths.
Deadline handling converts the `DetectionEngine.analyze()` Protocol's
wall-clock (`time.time()`-based) absolute epoch deadline into subprocess.run's
relative `timeout=` seconds. A timeout, a nonzero exit with no parseable
findings, or an unparseable/malformed output are all EngineStatus.ERROR/TIMEOUT
(unusable, fail-closed per INV-1) - never silently treated as "zero findings",
which would be indistinguishable from a real clean scan.
"""

from __future__ import annotations

import subprocess
import tempfile
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from common.log import get_logger
from skillscan_core import EngineMetadata, EngineResult, EngineStatus, Finding, ScanMode

from engine_runner.timeouts import DEFAULT_ENGINE_TIMEOUT_S

_logger = get_logger("skillscan.engine_runner.adapter")

# The former `_DEFAULT_TIMEOUT_S = 60.0` now lives in `engine_runner.timeouts`
# as `DEFAULT_ENGINE_TIMEOUT_S` (milestone C Task 4), with the same value: the
# fallback for an engine that has neither a deployment override nor a built-in
# per-engine default. It moved so that "what timeout does this engine get" has
# exactly one answer, instead of a constant here plus a single-engine
# environment variable read in main.py.

# `parse_output(completed, target_dir, files)` - the full CompletedProcess
# (stdout/stderr/returncode), the temp dir the scanned files were materialized
# into (so a parser for a file-output engine like skillspector can read its
# report file back from there), and the original in-memory files dict (so a
# parser can compute snippet_hash from the ORIGINAL bytes rather than
# re-reading from disk). Any parse failure must raise, not return an empty
# list (empty is indistinguishable from "no findings"; a raised exception
# correctly becomes EngineStatus.ERROR below).
ParseOutput = Callable[
    [subprocess.CompletedProcess[bytes], Path, dict[str, bytes]], tuple[Finding, ...]
]


class EngineHadNothingInScope(Exception):
    """The engine ran to completion and correctly found nothing it could
    examine - NOT a failure, and NOT a clean scan either.

    The third answer this class previously could not express. `parse_output`
    had exactly two outcomes: return findings (-> `EngineStatus.OK`, "I
    examined this package") or raise (-> `EngineStatus.ERROR`, "I could not
    complete"). An engine handed input outside its own domain fits neither,
    and forcing it into one of them is a lie in whichever direction it is
    forced: OK-with-zero-findings claims a check that never happened (exactly
    the false negative this module's docstring exists to prevent), and ERROR
    reports a broken engine that is in fact working perfectly.

    Maps to `EngineStatus.PARTIAL` - "degraded success" - which
    `EngineResult.usable` already accepts and which
    `orchestration.engine_health.FAILED_ENGINE_STATUSES` already, deliberately,
    excludes from the failure count. The console has rendered `partial` since
    Task 10. Nothing downstream needed teaching; the state was always there and
    nothing raised it.

    RAISE THIS ONLY for "this input has nothing for me", never for "I could not
    read the input" - the second is an error and must stay one.
    """


class SubprocessEngineAdapter:
    """`DetectionEngine` Protocol implementation (skillscan_core.DetectionEngine)
    wrapping one subprocess-invoked OSS engine binary.

    `build_argv(target_dir)` returns the full argv (binary path + flags) given
    the temp directory the scanned files were materialized into - the SAME
    directory `parse_output` receives, so an engine that writes its report to
    a file inside that directory (rather than stdout) can be supported too.
    """

    def __init__(
        self,
        *,
        metadata: EngineMetadata,
        build_argv: Callable[[Path], Sequence[str]],
        parse_output: ParseOutput,
        env: dict[str, str] | Callable[[], dict[str, str]] | None = None,
        timeout_s: float = DEFAULT_ENGINE_TIMEOUT_S,
        treat_nonzero_exit_as_error: bool = True,
        run_in_target_dir: bool = False,
    ) -> None:
        self._metadata = metadata
        self._build_argv = build_argv
        self._parse_output = parse_output
        self._env = env
        self._timeout_s = timeout_s
        self._treat_nonzero_exit_as_error = treat_nonzero_exit_as_error
        # SECURITY/CORRECTNESS: default False preserves the exact prior
        # behavior (subprocess inherits this process's own CWD) for every
        # existing adapter - added for aig.py, whose subprocess writes a
        # CWD-relative log file at import time (before argument parsing),
        # which would crash outright under this deployment's
        # `readOnlyRootFilesystem: true` unless run somewhere guaranteed
        # writable. `target_dir` (the per-scan tempdir this class already
        # creates under /tmp) is that guaranteed-writable place - every
        # other adapter has no such requirement and stays on the default.
        self._run_in_target_dir = run_in_target_dir

    @property
    def metadata(self) -> EngineMetadata:
        return self._metadata

    def analyze(self, files: dict[str, bytes], *, deadline: float | None = None) -> EngineResult:
        # `deadline` is a wall-clock epoch value (time.time()-based, e.g.
        # airlock.now_epoch() + N), never a monotonic-clock value - every real
        # caller (services/engine_runner/worker.py, orchestration/service.py)
        # threads a `deadline_epoch` computed from `airlock.now_epoch()`
        # (= time.time()). Must be compared against time.time() here, not
        # time.monotonic() (a small, arbitrary-origin uptime counter) - that
        # mismatch previously made `remaining` come out to (epoch - uptime),
        # tens of years, so the shared scan-budget deadline never actually
        # constrained anything and every engine silently fell back to its own
        # fixed `timeout_s` regardless of the real remaining budget.
        relative_timeout = self._timeout_s
        if deadline is not None:
            remaining = deadline - time.time()
            if remaining <= 0:
                return self._unusable(EngineStatus.TIMEOUT, "deadline already passed")
            relative_timeout = min(relative_timeout, remaining)

        with tempfile.TemporaryDirectory(prefix="skillscan-engine-") as tmp_name:
            target_dir = Path(tmp_name)
            for path, data in files.items():
                # SECURITY: files here are already hardened-unpacked
                # (engine_runner.normalizer.unpack_hardened rejects traversal/
                # absolute/symlink paths before this point) - resolve()+
                # relative_to() below is defense in depth, not the primary
                # control, against a path somehow escaping that upstream check.
                dest = (target_dir / path).resolve()
                if not dest.is_relative_to(target_dir.resolve()):
                    return self._unusable(
                        EngineStatus.ERROR, f"refusing to materialize escaping path: {path!r}"
                    )
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)

            argv = list(self._build_argv(target_dir))
            # SECURITY (Finding #16): a plain dict is captured once at adapter
            # construction (process startup) and would otherwise be reused
            # unchanged for the process's entire lifetime; a callable lets an
            # adapter that embeds a validated-internal-endpoint URL (e.g.
            # skillspector.py/aig.py's LLM base_url) re-run
            # require_internal_endpoint() fresh before EVERY subprocess spawn
            # instead of trusting a startup-time-only validation - narrowing
            # (though, unlike the in-process pinned_dns.py fix, not fully
            # eliminating) the DNS-rebinding TOCTOU window for tools that do
            # their own OS-level resolution outside this process's control.
            try:
                # SECURITY: env resolution (which may re-run
                # require_internal_endpoint) must be INSIDE this try - it can
                # raise ValueError, and that must fail closed exactly like a
                # subprocess-launch failure, never propagate out of
                # analyze() uncaught.
                env = self._env() if callable(self._env) else self._env
                completed = subprocess.run(  # noqa: S603 - argv list, shell=False (default), no injection surface
                    argv,
                    timeout=relative_timeout,
                    capture_output=True,
                    shell=False,
                    env=env,
                    check=False,
                    cwd=target_dir if self._run_in_target_dir else None,
                )
            except subprocess.TimeoutExpired:
                return self._unusable(
                    EngineStatus.TIMEOUT, f"{argv[0]} exceeded {relative_timeout}s"
                )
            except OSError as exc:
                return self._unusable(EngineStatus.ERROR, f"failed to start {argv[0]}: {exc}")
            except ValueError as exc:
                # SECURITY: raised by require_internal_endpoint inside a
                # callable env - a hostname that was internal at startup but
                # is no longer resolving internally now (rebinding, or a
                # legitimate re-point to an external host) must fail closed,
                # never fall back to spawning with a stale/unvalidated env.
                return self._unusable(EngineStatus.ERROR, f"endpoint re-validation failed: {exc}")

            if completed.returncode != 0 and self._treat_nonzero_exit_as_error:
                # SECURITY: some engines (bandit, osv-scanner) use nonzero exit
                # to mean "findings were reported" (not "the engine crashed") -
                # `treat_nonzero_exit_as_error=False` lets a caller opt out of
                # this default for those engines specifically; still attempts
                # to parse stdout below in that case.
                _logger.warning(
                    "engine exited nonzero",
                    extra={
                        "context": {
                            "engine": self._metadata.name,
                            "returncode": completed.returncode,
                            "stderr_len": len(completed.stderr or b""),
                        }
                    },
                )
                return self._unusable(
                    EngineStatus.ERROR, f"{argv[0]} exited {completed.returncode}"
                )

            try:
                findings = self._parse_output(completed, target_dir, files)
            except EngineHadNothingInScope as exc:
                # Deliberately BEFORE the blanket handler below - this is the
                # one exception that is not a failure, and it must not be
                # swallowed into ERROR by the `except Exception` that follows.
                _logger.info(
                    "engine had nothing in scope",
                    extra={"context": {"engine": self._metadata.name, "reason": str(exc)}},
                )
                return self._nothing_in_scope(str(exc))
            except Exception as exc:  # noqa: BLE001 - any parse failure must fail-closed, not propagate
                _logger.exception(
                    "engine output failed to parse",
                    extra={"context": {"engine": self._metadata.name}},
                )
                return self._unusable(EngineStatus.ERROR, f"output parse failed: {exc}")

        return EngineResult(
            engine=self._metadata,
            findings=findings,
            status=EngineStatus.OK,
            scan_mode=ScanMode.STATIC,
            llm_used=self._metadata.requires_llm,
        )

    def _unusable(self, status: EngineStatus, reason: str) -> EngineResult:
        return EngineResult(
            engine=self._metadata,
            findings=(),
            status=status,
            scan_mode=ScanMode.STATIC,
            llm_used=False,
            error=reason,
        )

    def _nothing_in_scope(self, reason: str) -> EngineResult:
        # Same empty findings tuple as `_unusable`, deliberately a DIFFERENT
        # status: `PARTIAL` is usable, so this result counts as the engine
        # having answered. `error` still carries the reason - the column is the
        # only place the console can show WHY zero findings is not the same
        # claim as a clean scan, and nothing constrains it to failures.
        return EngineResult(
            engine=self._metadata,
            findings=(),
            status=EngineStatus.PARTIAL,
            scan_mode=ScanMode.STATIC,
            llm_used=False,
            error=reason,
        )
