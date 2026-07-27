"""Shared plumbing for the in-house floor detectors.

Every floor detector has the same shape: a module-level `scan(files)` pure
function plus a thin `DetectionEngine` Protocol class. The only logic in that
class is deadline handling, and before 2026-07-27 six of them simply omitted
it - they accepted `deadline` and ignored it, so a scan whose shared budget was
already spent still reported OK, which is indistinguishable from "scanned it,
found nothing". That is precisely what fail-closed exists to prevent.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from skillscan_core import (
    EngineMetadata,
    EngineResult,
    EngineStatus,
    Finding,
    ScanMode,
)


def run_with_deadline(
    metadata: EngineMetadata,
    scan_fn: Callable[[dict[str, bytes]], tuple[Finding, ...]],
    files: dict[str, bytes],
    deadline: float | None,
) -> EngineResult:
    """Run `scan_fn` unless the shared scan budget is already spent.

    `deadline` is a wall-clock epoch (`airlock.now_epoch()` = `time.time()`),
    never a monotonic value - comparing against `time.monotonic()` is the bug
    this helper exists to stop anyone from reintroducing (see
    `skillscan_core.engines.StaticKeywordEngine.analyze` and
    `adapters/base.py:96-105`).

    Checked once at entry rather than per file: these detectors are pure
    in-memory regex with no IO, so the meaningful case is a budget spent before
    they were reached, not one exhausted midway.
    """
    if deadline is not None and time.time() > deadline:
        return EngineResult(
            engine=metadata,
            findings=(),
            status=EngineStatus.TIMEOUT,
            scan_mode=ScanMode.STATIC,
            llm_used=False,
            error="deadline exceeded",
        )
    return EngineResult(
        engine=metadata,
        findings=scan_fn(files),
        status=EngineStatus.OK,
        scan_mode=ScanMode.STATIC,
        llm_used=False,
    )
