"""skillscan_core - stdlib-only detection kernel (coding spec M1, §5).

Zero runtime dependencies by design: domain models, content-addressed hashing,
deterministic scoring, and fail-closed gate decision, all pure functions/frozen
value objects. Everything downstream (API, DB, sandboxing, real OSS engines)
depends on this; this depends on nothing but the stdlib.
"""

from skillscan_core.canonical import cache_key, content_hash, toolchain_digest
from skillscan_core.engines import (
    DetectionEngine,
    FailingEngine,
    MockLLMEngine,
    StaticKeywordEngine,
)
from skillscan_core.gate import decide
from skillscan_core.models import (
    ALL_TRIFECTA_SIGNALS,
    AllowlistEntry,
    DetectionCategory,
    EngineCapability,
    EngineMetadata,
    EngineResult,
    EngineStatus,
    Finding,
    GatePolicy,
    ScanMode,
    ScanResult,
    Severity,
    TrifectaSignal,
    TrustTier,
    Verdict,
    VerdictResult,
)
from skillscan_core.scoring import aggregate, evaluate_findings

__all__ = [
    "ALL_TRIFECTA_SIGNALS",
    "AllowlistEntry",
    "DetectionCategory",
    "DetectionEngine",
    "EngineCapability",
    "EngineMetadata",
    "EngineResult",
    "EngineStatus",
    "FailingEngine",
    "Finding",
    "GatePolicy",
    "MockLLMEngine",
    "ScanMode",
    "ScanResult",
    "Severity",
    "StaticKeywordEngine",
    "TrifectaSignal",
    "TrustTier",
    "Verdict",
    "VerdictResult",
    "aggregate",
    "cache_key",
    "content_hash",
    "decide",
    "evaluate_findings",
    "toolchain_digest",
]
