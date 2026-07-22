"""IntelPort (coding spec §6) - IOC matcher reading a local threat-indicator
table (synced by intel-sync, see services/intel_sync/sync.py); read-only.

HONEST STATUS: `monolith.modules.intel.matcher.IntelMatcher` does the real
IOC-matching work in production, but implements `skillscan_core.DetectionEngine`
(metadata + `analyze(files: dict[str, bytes], ...) -> EngineResult`), not this
Protocol's `match(indicators: dict[str, list[str]]) -> list[Finding]` shape -
because it is plugged into the pipeline via the engine registry (alongside the
OSS/floor engines) rather than called ad-hoc from elsewhere in the codebase.
That is a deliberate, low-risk choice: `IntelMatcher` already has real test
coverage and a real production call site as a `DetectionEngine`; retrofitting
a second, differently-shaped `match()` method onto it would duplicate the same
IOC-extraction logic under two interfaces for no consumer that needs the
`IntelPort` shape today. This Protocol is defined here per spec so a future
caller that wants direct indicator-list matching (bypassing the file-scanning
engine-registry path) has a real contract to implement against."""

from __future__ import annotations

from typing import Protocol

from skillscan_core import Finding


class IntelPort(Protocol):
    async def match(self, indicators: dict[str, list[str]]) -> list[Finding]: ...
