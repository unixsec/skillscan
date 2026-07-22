"""EngineResult read-back + aggregation (coding spec §11.3, INV-11).

SECURITY: `load_and_aggregate` is the only path from blob-store bytes into
`skillscan_core.aggregate()`. Every findings blob is untrusted (INV-11) - schema
validation happens in `schemas.findings`, and this module additionally treats a
*missing* blob (engine never reported) identically to a validation failure: both
become an ERROR placeholder result, never a silent gap that `aggregate()` might
mistake for "this engine had zero findings."
"""

from __future__ import annotations

from collections.abc import Sequence

from common.blobstore import BlobNotFoundError, BlobStorePort, findings_key
from schemas.findings import UntrustedFindingsError, parse_engine_result
from skillscan_core import (
    EngineMetadata,
    EngineResult,
    EngineStatus,
    GatePolicy,
    ScanMode,
    ScanResult,
)
from skillscan_core import (
    aggregate as core_aggregate,
)


def unavailable_engine_result(engine_name: str, *, reason: str) -> EngineResult:
    """SECURITY (INV-11 fail-closed): built from the *expected* engine name (our
    own dispatch list), never from anything read out of an untrusted/missing
    blob - a corrupted or absent findings blob must not be able to spoof a
    different engine's identity into the provenance record."""
    metadata = EngineMetadata(
        name=engine_name,
        version="unknown",
        ruleset_digest="unknown",
        capabilities=frozenset(),
        requires_network=False,
        requires_llm=False,
        deterministic=True,
    )
    return EngineResult(
        engine=metadata,
        findings=(),
        status=EngineStatus.ERROR,
        scan_mode=ScanMode.STATIC,
        llm_used=False,
        error=reason,
    )


def load_engine_result(blobstore: BlobStorePort, *, scan_id: str, engine_name: str) -> EngineResult:
    """SECURITY: any schema violation OR an engine-identity mismatch between the
    key we looked up and the identity claimed inside the blob is treated as
    unusable (fail-closed) - defense in depth against a misdirected or spoofed
    write landing at the wrong findings/<scan_id>/<engine>.json key."""
    key = findings_key(scan_id, engine_name)
    try:
        raw = blobstore.get(key)
    except BlobNotFoundError:
        return unavailable_engine_result(
            engine_name, reason=f"no findings reported at {key} (fail-closed, INV-11)"
        )
    try:
        result = parse_engine_result(raw)
    except UntrustedFindingsError as exc:
        return unavailable_engine_result(
            engine_name, reason=f"schema validation failed (fail-closed, INV-11): {exc}"
        )
    if result.engine.name != engine_name:
        return unavailable_engine_result(
            engine_name,
            reason=(
                f"engine identity mismatch: key={engine_name!r} but blob claimed "
                f"{result.engine.name!r} (fail-closed, INV-11)"
            ),
        )
    return result


def load_and_aggregate(
    blobstore: BlobStorePort,
    *,
    scan_id: str,
    content_hash: str,
    engine_names: Sequence[str],
    policy: GatePolicy,
    min_confidence: float = 0.0,
    max_findings: int = 5000,
) -> ScanResult:
    results = [
        load_engine_result(blobstore, scan_id=scan_id, engine_name=name) for name in engine_names
    ]
    return core_aggregate(
        content_hash, results, policy, min_confidence=min_confidence, max_findings=max_findings
    )
