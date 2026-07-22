"""Content-hash baseline drift detection (coding spec §11.4 SUP-05, SRS Cat-7
"更新漂移/拔地毯" - update-drift / rug-pull).

SECURITY: an approved skill_id's *approved* content_hash is its baseline. If a
later scan of the same skill_id presents a DIFFERENT content_hash without a
new baseline having been explicitly (re-)approved, that is exactly the
rug-pull pattern this check exists to catch: a previously-vetted Skill quietly
swapped for different content post-approval. Detecting drift is this module's
whole job; the resulting action (auto-quarantine, poll/push trust asymmetry)
is `modules/reeval/quarantine.py`'s job (coding spec §11.6, M6) - this module
only answers "did it drift", it does not itself change any lifecycle state.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import BaselineReadOnly


@dataclass(frozen=True, slots=True)
class DriftResult:
    has_baseline: bool
    drifted: bool
    baseline_content_hash: str | None


def is_drift(baseline_content_hash: str | None, current_content_hash: str) -> bool:
    """Pure comparison - no I/O. `None` (no baseline yet) is never drift: a
    skill_id with nothing approved yet has nothing to have drifted FROM."""
    if baseline_content_hash is None:
        return False
    return baseline_content_hash != current_content_hash


async def check_drift(session: AsyncSession, *, skill_id: str, content_hash: str) -> DriftResult:
    """SECURITY: caller must supply a session authorized to SELECT `baseline`
    (svc_orchestration's grant, policies/grants/manifest.yaml) - this function
    never writes anything, matching its read-only GRANT."""
    baseline = (
        await session.execute(select(BaselineReadOnly).where(BaselineReadOnly.skill_id == skill_id))
    ).scalar_one_or_none()
    baseline_hash = baseline.content_hash if baseline is not None else None
    return DriftResult(
        has_baseline=baseline is not None,
        drifted=is_drift(baseline_hash, content_hash),
        baseline_content_hash=baseline_hash,
    )
