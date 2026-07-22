"""DetectionEnginePort (coding spec §6). Same contract as `skillscan_core.
engines.DetectionEngine` (coding spec §5.5) - the spec names it once per
section, this module re-exports rather than re-declaring the Protocol body,
since skillscan_core is the more foundational, stdlib-only layer and ports
importing from it (one direction only - skillscan_core never imports from
ports) introduces no new dependency for either package."""

from __future__ import annotations

from skillscan_core.engines import DetectionEngine as DetectionEnginePort

__all__ = ["DetectionEnginePort"]
