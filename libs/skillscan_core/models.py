"""Domain models for the skillscan detection kernel.

Pure stdlib, zero runtime dependencies (coding spec M1, §5.1). Every security
invariant here is enforced at construction time (fail fast), not deferred to
gate-decision time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum


class Severity(IntEnum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Verdict(IntEnum):
    """Larger = stricter, so max(verdict_a, verdict_b) picks the stricter one."""

    PASS = 0
    REVIEW = 1
    BLOCK = 2


class TrustTier(StrEnum):
    INTERNAL = "internal"
    PARTNER = "partner"
    PUBLIC = "public"


class DetectionCategory(StrEnum):
    """The 8 detection catalog categories (SRS §3.3, FR-DET-010..080)."""

    INSTRUCTION = "instruction"
    CODE = "code"
    DATA_CREDENTIAL = "data_credential"
    NETWORK_INTEL = "network_intel"
    PERMISSION = "permission"
    FILE_PACKAGE = "file_package"
    SUPPLY_CHAIN = "supply_chain"
    BUNDLED_COMPONENT = "bundled_component"


class EngineCapability(StrEnum):
    STATIC = "static"
    SEMANTIC_LLM = "semantic_llm"
    THREAT_INTEL = "threat_intel"
    DYNAMIC_SANDBOX = "dynamic_sandbox"
    SCA = "sca"
    FILE_COMPLIANCE = "file_compliance"


class EngineStatus(StrEnum):
    OK = "ok"
    PARTIAL = "partial"
    ERROR = "error"
    TIMEOUT = "timeout"


class ScanMode(StrEnum):
    STATIC = "static"
    DYNAMIC = "dynamic"


class TrifectaSignal(StrEnum):
    """The fatal-trifecta signals (INV-4): co-occurrence forces severity >= CRITICAL."""

    PRIVATE_DATA_ACCESS = "private_data_access"
    UNTRUSTED_INPUT = "untrusted_input"
    EXTERNAL_EGRESS = "external_egress"


ALL_TRIFECTA_SIGNALS: frozenset[TrifectaSignal] = frozenset(TrifectaSignal)

_VALID_ALLOWLIST_SCOPE_TYPES = ("content_hash", "skill_id", "rule_global")


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    test_item_id: str
    category: DetectionCategory
    title: str
    severity: Severity
    confidence: float
    source_engine: str
    source_capability: EngineCapability
    trifecta_signals: frozenset[TrifectaSignal] = field(default_factory=frozenset)
    file_path: str | None = None
    start_line: int | None = None
    snippet_hash: str | None = None
    evidence_redacted: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "trifecta_signals", frozenset(self.trifecta_signals))
        if not self.rule_id:
            raise ValueError("Finding.rule_id must be non-empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Finding.confidence must be in [0,1], got {self.confidence!r}")
        # SECURITY: no NONE-severity findings - that would create a "safe" signal
        # channel that bypasses scoring entirely.
        if self.severity < Severity.LOW:
            raise ValueError("Finding.severity must be >= LOW (no NONE-severity findings)")
        # SECURITY (INV-9): snippet_hash must be a digest, never plaintext evidence.
        if self.snippet_hash is not None and not (
            self.snippet_hash and all(c in "0123456789abcdef" for c in self.snippet_hash)
        ):
            raise ValueError("Finding.snippet_hash must be a lowercase hex digest, not plaintext")

    @property
    def is_llm_sourced(self) -> bool:
        return self.source_capability is EngineCapability.SEMANTIC_LLM

    @property
    def dedup_key(self) -> tuple[str, str | None, int | None, DetectionCategory]:
        return (self.rule_id, self.file_path, self.start_line, self.category)


@dataclass(frozen=True, slots=True)
class EngineMetadata:
    name: str
    version: str
    ruleset_digest: str
    capabilities: frozenset[EngineCapability]
    requires_network: bool = False
    requires_llm: bool = False
    deterministic: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "capabilities", frozenset(self.capabilities))
        if not self.name:
            raise ValueError("EngineMetadata.name must be non-empty")
        if not self.version:
            raise ValueError("EngineMetadata.version must be non-empty")
        # SECURITY: in-scan engines must never require direct network egress; any
        # intel egress goes through the dedicated, independently-controlled
        # intel-sync component instead.
        if self.requires_network:
            raise ValueError(
                f"EngineMetadata({self.name!r}): requires_network=True is forbidden for "
                "in-scan engines"
            )


@dataclass(frozen=True, slots=True)
class EngineResult:
    engine: EngineMetadata
    findings: tuple[Finding, ...]
    status: EngineStatus
    scan_mode: ScanMode
    llm_used: bool = False
    error: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", tuple(self.findings))

    @property
    def usable(self) -> bool:
        # SECURITY: ERROR/TIMEOUT results are never usable - fail-closed at the source.
        return self.status in (EngineStatus.OK, EngineStatus.PARTIAL)


@dataclass(frozen=True, slots=True)
class ScanResult:
    content_hash: str
    severity: Severity
    confidence_at_max: float
    trifecta_present: bool
    hard_gate_hits: tuple[str, ...]
    findings: tuple[Finding, ...]
    engine_provenance: tuple[tuple[str, str, str], ...]
    findings_capped: bool
    required_ok: bool
    missing_or_failed_required: tuple[str, ...]
    # SECURITY: the pre-cap count, i.e. `len(all_findings)` before `max_findings`
    # truncation (scoring.py aggregate()). Same rationale as the pre-cap hard-gate
    # and trifecta preservation below: a finding flood must not be able to make
    # the TRUE count unknowable, only the full findings list. Consumers (e.g.
    # marketplace_api.views's `summary.total`) need the real number even when
    # `findings` itself was capped.
    findings_total: int
    # SECURITY: rule_ids that lost at least one candidate to a _dedup() key
    # collision (scoring.py) - lets gate.decide() check whether the SPECIFIC
    # rule_id(s) behind a dedup-collision signal restoration are already
    # legitimately allowlist-waived, instead of restoring blindly against every
    # active waiver. Only rule_id survives the collision (not the full dropped
    # Finding), which is sufficient because AllowlistEntry.waives() itself only
    # compares rule_id.
    dedup_collision_rule_ids: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True, slots=True)
class GatePolicy:
    version: str
    required_engines: frozenset[str]
    hard_gate_rules: frozenset[str] = field(default_factory=frozenset)
    review_confidence: float = 0.6
    block_on_severity: Severity = Severity.CRITICAL
    review_on_severity: Severity = Severity.HIGH
    tier_block_overrides: tuple[tuple[TrustTier, Severity], ...] = ()
    allowlistable_max_severity: Severity = Severity.HIGH
    fail_closed_verdict: Verdict = Verdict.BLOCK

    def __post_init__(self) -> None:
        object.__setattr__(self, "required_engines", frozenset(self.required_engines))
        object.__setattr__(self, "hard_gate_rules", frozenset(self.hard_gate_rules))
        object.__setattr__(self, "tier_block_overrides", tuple(self.tier_block_overrides))
        if not self.version:
            raise ValueError("GatePolicy.version must be non-empty")
        if not 0.0 <= self.review_confidence <= 1.0:
            raise ValueError("GatePolicy.review_confidence must be in [0,1]")
        if self.block_on_severity < Severity.LOW or self.review_on_severity < Severity.LOW:
            raise ValueError("GatePolicy severity thresholds must be >= LOW")
        # SECURITY: a fail-closed policy that resolves to PASS is a contradiction in terms.
        if self.fail_closed_verdict == Verdict.PASS:
            raise ValueError("GatePolicy.fail_closed_verdict must never be PASS")
        # SECURITY: tier overrides may only tighten (severity <= base), never loosen it.
        for tier, sev in self.tier_block_overrides:
            if sev > self.block_on_severity:
                raise ValueError(
                    f"GatePolicy.tier_block_overrides for {tier}: override severity "
                    "must be <= block_on_severity (overrides may only tighten)"
                )

    def block_threshold(self, tier: TrustTier) -> Severity:
        matches = [sev for t, sev in self.tier_block_overrides if t == tier]
        if not matches:
            return self.block_on_severity
        return min(matches)  # strictest override wins = lowest severity threshold


@dataclass(frozen=True, slots=True)
class AllowlistEntry:
    scope_type: str  # 'content_hash' | 'skill_id' | 'rule_global'
    scope_value: str
    rule_id: str
    expires_at: float
    approved_by: str
    requested_by: str
    reason: str = ""

    def __post_init__(self) -> None:
        # SECURITY (INV-8): four-eyes - approver and requester must both be set and differ.
        if not self.approved_by or not self.requested_by:
            raise ValueError("AllowlistEntry requires non-empty approved_by and requested_by")
        if self.approved_by == self.requested_by:
            raise ValueError("AllowlistEntry.approved_by must differ from requested_by (four-eyes)")
        # SECURITY: mandatory, strictly-positive expiry - no permanent waivers.
        if self.expires_at <= 0:
            raise ValueError("AllowlistEntry.expires_at must be > 0")
        if self.scope_type not in _VALID_ALLOWLIST_SCOPE_TYPES:
            raise ValueError(f"AllowlistEntry.scope_type invalid: {self.scope_type!r}")
        # scope_value is meaningless for rule_global (is_active() below never
        # reads it for that branch) - the web UI correctly submits it empty
        # for this scope type, so requiring non-empty here made every
        # rule_global waiver a guaranteed 400, with zero test coverage ever
        # exercising that combination to catch it.
        if self.scope_type != "rule_global" and not self.scope_value:
            raise ValueError("AllowlistEntry.scope_value must be non-empty")
        if not self.rule_id:
            raise ValueError("AllowlistEntry.rule_id must be non-empty")

    def is_active(self, now: float, content_hash: str, skill_id: str | None = None) -> bool:
        if now >= self.expires_at:  # SECURITY: strict expiry, no grace period
            return False
        if self.scope_type == "content_hash":
            return self.scope_value == content_hash
        if self.scope_type == "skill_id":
            return skill_id is not None and self.scope_value == skill_id
        if self.scope_type == "rule_global":
            return True
        return False  # SECURITY: fail-closed on unknown scope

    def waives(self, finding: Finding) -> bool:
        return self.rule_id == finding.rule_id


@dataclass(frozen=True, slots=True)
class CategoryWeights:
    """Per-DetectionCategory multiplier for security_score()'s penalty term
    (2026-07-24 scoring design doc). All-1.0 default = every category counts
    equally; a caller (admin config, milestone C) can raise a category's
    weight to make its findings cost more score."""

    instruction: float = 1.0
    code: float = 1.0
    data_credential: float = 1.0
    network_intel: float = 1.0
    permission: float = 1.0
    file_package: float = 1.0
    supply_chain: float = 1.0
    bundled_component: float = 1.0

    def for_category(self, category: DetectionCategory) -> float:
        return float(getattr(self, category.value))


@dataclass(frozen=True, slots=True)
class VerdictResult:
    verdict: Verdict
    reasons: tuple[str, ...]
    policy_version: str
    effective_severity: Severity
    trifecta_present: bool
    hard_gate_hits: tuple[str, ...]
    # 0-100 advisory score, derived from (verdict, findings) - NEVER an input
    # to the verdict itself. See scoring.security_score().
    score: int
