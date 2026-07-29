"""Domain models for the skillscan detection kernel.

Pure stdlib, zero runtime dependencies (coding spec M1, §5.1). Every security
invariant here is enforced at construction time (fail fast), not deferred to
gate-decision time.
"""

from __future__ import annotations

import dataclasses
import hashlib
import math
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum

# Domain separator + SCHEME VERSION for `GatePolicy.adjudication_semantics`
# (milestone C Task 11). Bump the `.vN` when the canonical form itself changes
# shape: the point of the version is that two processes running different
# skillscan builds must not silently derive different digests from the same
# policy, they must derive VISIBLY different ones - a policy edit and a
# canonicaliser change are both "the digest moved", and both correctly mean
# "re-adjudicate", but only a version in the string makes the second one
# distinguishable from a corrupt read.
_POLICY_SEMANTICS_DOMAIN = "skillscan.gate_policy.adjudication_semantics.v1"

# Upper bound for a single `CategoryWeights` field. The scoring penalty
# saturates (scoring.security_score), so an absurd weight does not overflow -
# it just pins that band to its floor for any finding in the category, which is
# indistinguishable from a working configuration until someone compares scores.
# The cap exists to catch the shape of typo that produces it: a percentage
# (`100`) or a basis-point value written where a multiplier was meant.
MAX_CATEGORY_WEIGHT = 10.0


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
        #
        # PARTIAL IS ACCEPTED, and this property has a second reader that makes
        # that more than a findings-inclusion decision: `scoring.aggregate`
        # computes `required_ok` from the same set, so a REQUIRED engine
        # reporting "nothing in scope" (the only thing PARTIAL means today -
        # `SubprocessEngineAdapter._nothing_in_scope`) would satisfy INV-1's
        # floor backstop having examined nothing. Inert on two conditions that
        # hold today; see the comment at that call site before widening either
        # this status set or `required_engines`.
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
class CategoryWeights:
    """Per-DetectionCategory multiplier for security_score()'s penalty term
    (2026-07-24 scoring design doc). All-1.0 default = every category counts
    equally; raising a category's weight makes its findings cost more score.

    CONFIGURED THROUGH `GatePolicy.category_weights` AND NOWHERE ELSE
    (milestone C Task 5). These values change `VerdictResult.score`, which is a
    PERSISTED field, so they have to be covered by the same version term that
    invalidates the INV-7 cache - see `GatePolicy.cache_policy_version`. A
    weight reachable by any other route would be a scoring input the cache key
    cannot see.
    """

    instruction: float = 1.0
    code: float = 1.0
    data_credential: float = 1.0
    network_intel: float = 1.0
    permission: float = 1.0
    file_package: float = 1.0
    supply_chain: float = 1.0
    bundled_component: float = 1.0

    def __post_init__(self) -> None:
        for spec in dataclasses.fields(self):
            raw = getattr(self, spec.name)
            # bool is an int subclass; `True` as a weight is a config error.
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                raise ValueError(f"CategoryWeights.{spec.name} must be a number, got {raw!r}")
            value = float(raw)
            # SECURITY: a NEGATIVE weight inverts the penalty - a finding in
            # that category would RAISE the score, so the more credentials a
            # package leaked the cleaner it would look. Refused outright.
            if not math.isfinite(value) or not 0.0 <= value <= MAX_CATEGORY_WEIGHT:
                raise ValueError(
                    f"CategoryWeights.{spec.name} must be a finite number in "
                    f"[0.0, {MAX_CATEGORY_WEIGHT}], got {raw!r}"
                )
            # Normalize int -> float so `CategoryWeights(code=1)` compares equal
            # to the default (YAML writes `1`, not `1.0`) and so two policies
            # that mean the same thing produce the same cache_policy_version.
            object.__setattr__(self, spec.name, value)

    def for_category(self, category: DetectionCategory) -> float:
        return float(getattr(self, category.value))

    def non_default_items(self) -> tuple[tuple[str, float], ...]:
        """The fields that diverge from the all-1.0 default, in declaration
        order. Discovers the fields rather than listing them, so a new category
        added above cannot be silently omitted from `cache_policy_version`."""
        return tuple(
            (spec.name, float(getattr(self, spec.name)))
            for spec in dataclasses.fields(self)
            if getattr(self, spec.name) != spec.default
        )


def _canonical_policy_term(value: object) -> str:
    """One deterministic string for one `GatePolicy` field value (milestone C
    Task 11).

    DETERMINISM IS THE WHOLE JOB, and it is why this is a hand-written
    type-dispatch rather than `repr(value)`. `repr` of a `frozenset` is in
    ITERATION order, which python does not promise to be stable across
    processes - `required_engines` and `hard_gate_rules` are frozensets, so a
    repr-based digest would differ between the API pod and the worker pod for
    an identical policy, and every cached verdict would read as stale forever
    while every process disagreed about why. Sets are sorted here; sequences
    keep their order (an unnecessary invalidation is safe, a missed one is
    not).

    AN UNHANDLED TYPE RAISES rather than falling back to `repr`. The fallback
    is the dangerous direction: a future `GatePolicy` field whose type this
    does not understand would be canonicalised to something that either does
    not move when the field moves (a stale verdict served under a changed
    policy - the exact bug this function exists to prevent) or is unstable
    across processes. `tests/test_models.py` constructs a real policy and
    calls this on every field, so the raise lands in CI, not in production.
    """
    # Enum branches come first: Severity/Verdict are IntEnum and TrustTier is
    # StrEnum, so an int/str branch above them would swallow the name.
    if isinstance(value, (Severity, Verdict, TrustTier, DetectionCategory, EngineCapability)):
        return f"{type(value).__name__}.{value.name}"
    if isinstance(value, CategoryWeights):
        # Reuses Task 5's own canonical form: field-discovering, declaration
        # order, and normalised int->float, so an explicitly-declared all-1.0
        # section and an ABSENT one produce the same term.
        return "cw(" + ",".join(f"{n}={v!r}" for n, v in value.non_default_items()) + ")"
    # bool before int: bool is an int subclass and `True`/`1` must not collide.
    if isinstance(value, bool):
        return f"bool({value!r})"
    if isinstance(value, (int, float, str)):
        return repr(value)
    if isinstance(value, (frozenset, set)):
        return "{" + ",".join(sorted(_canonical_policy_term(item) for item in value)) + "}"
    if isinstance(value, (tuple, list)):
        return "[" + ",".join(_canonical_policy_term(item) for item in value) + "]"
    raise TypeError(
        f"GatePolicy carries a value of type {type(value).__name__!r} that "
        "cache_policy_version cannot canonicalise deterministically. Add an "
        "explicit branch to _canonical_policy_term - do NOT let it fall through "
        "to repr(), which is unstable across processes for set-like values and "
        "would make every cached verdict read as permanently stale."
    )


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
    # Loaded from the versioned policy file (gate.policy._parse_category_weights).
    # Optional: a policy file written before milestone C omits the section and
    # gets the all-1.0 default, i.e. exactly today's behaviour.
    category_weights: CategoryWeights = field(default_factory=CategoryWeights)

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

    def adjudication_semantics(self) -> str:
        """Every input this policy contributes to an adjudication, in one
        canonical string (milestone C Task 11). Feeds `cache_policy_version`;
        exposed on its own because "why did my digest move" is an operational
        question and a diff of two of these answers it.

        WHICH FIELDS, AND WHY IT IS ALL OF THEM. Each was checked against
        `gate.decide` rather than assumed: `required_engines` decides
        `required_ok` and therefore the INV-1 fail-closed branch;
        `fail_closed_verdict` is that branch's answer; `hard_gate_rules` forces
        the unwaivable INV-3 BLOCK and floors INV-8's waiver check;
        `block_on_severity`/`tier_block_overrides`/`review_on_severity`/
        `review_confidence` are `_classify` in its entirety;
        `allowlistable_max_severity` decides which findings survive waiving;
        `category_weights` moves the persisted score (Task 5). There is no
        `GatePolicy` field that does NOT reach a verdict or a score - so the
        honest scope is "the whole policy object", and the field loop below
        DISCOVERS them rather than naming them, which is what makes a field
        added later fail loudly (`_canonical_policy_term`) instead of quietly
        dropping out of the digest.

        DERIVED, NOT THE FILE'S BYTES - the same choice Task 5 made, for the
        same reason: a semantically-neutral edit must stay neutral. Hashing
        `policies/gate/v1.yaml` verbatim would make a mass rescan out of a
        comment (that file is majority comment), a reindent, or a key
        reordering. Reading the PARSED policy instead means all of those are
        free, and so are: `1` vs `1.0` in a weight (CategoryWeights normalises),
        reordering `required_engines`/`hard_gate_rules` (frozensets, sorted
        here), reordering or duplicating `tier_block_overrides` (resolved
        through `block_threshold` below), declaring `category_weights` at the
        all-1.0 default versus omitting the section, and any key
        `gate.policy.parse_gate_policy` ignores entirely.

        `tier_block_overrides` IS READ THROUGH `block_threshold`, not off the
        raw tuple, because `block_threshold` is the authority - it takes
        `min()` over the matching entries, so `[public:HIGH, public:HIGH]` and
        `[public:HIGH]` are the same policy and must produce the same digest.
        Enumerating every `TrustTier` also means a tier added to the enum is
        covered without touching this.

        That resolution also swallows `block_on_severity` (it is
        `block_threshold`'s fallback for an un-overridden tier), so the
        separate `block_on_severity=` term below is REDUNDANT TODAY - a
        mutation test confirms dropping it changes nothing. Kept anyway: the
        redundancy is the field loop doing its job, and it is what keeps the
        binding correct if `block_threshold` ever stops reading the field.
        """
        parts: list[str] = []
        for spec in dataclasses.fields(self):
            if spec.name == "version":
                # The version is the PREFIX of cache_policy_version, not part
                # of the semantics body - including it twice would say nothing.
                continue
            if spec.name == "tier_block_overrides":
                value: object = tuple(
                    sorted((tier.value, self.block_threshold(tier).name) for tier in TrustTier)
                )
            else:
                value = getattr(self, spec.name)
            parts.append(f"{spec.name}={_canonical_policy_term(value)}")
        return _POLICY_SEMANTICS_DOMAIN + "\n" + "\n".join(parts)

    @property
    def cache_policy_version(self) -> str:
        """The policy identity that INV-7's `toolchain_digest` must bind, as
        opposed to `version`, the identity a verdict RECORDS.

        WHY THE TWO DIFFER. `toolchain_digest` hashes `policy_version` and
        nothing else about the policy, and `cache_key` is derived from it - so
        whatever is NOT in that string is invisible to the cache. A policy file
        is edited by a human who can forget to bump `version:`, and the
        policy-proposal path (worker._parse_policy_candidate) changes policy at
        runtime with no file edit at all, where no bump-the-version convention
        exists to forget. Deriving the digest's version term from the policy's
        CONTENT removes the convention from the trust path.

        Task 5 bound `category_weights` this way, which move the persisted
        `score`. Task 11 extends it to the whole policy, which moves the
        persisted VERDICT: an operator who tightens `block_on_severity` in
        place and leaves `version:` alone was, until then, still served the
        adjudication computed under the OLD threshold - a package that should
        now BLOCK kept answering PASS for as long as the cache held. A score is
        advisory; a verdict is the gate.

        STILL ONE HASH TERM in `toolchain_digest`, and still one `version:`
        line in the file. The term just can no longer lag the content it names.

        THE COST, PAID DELIBERATELY (Task 11 measured it on the dev VM before
        choosing). There is no identity element any more: Task 5 could return
        the bare version for all-1.0 weights because "all-1.0" IS the behaviour
        that predates the feature, but no threshold is neutral in that sense,
        so EVERY policy's digest moves once when this ships and every cached
        verdict is invalidated. Measured rather than feared: on a 860-scan /
        760-skill corpus the cache had served 3 of 863 submissions (0.35%), the
        toolchain digest had already rotated 4 times in 7 days on ordinary
        engine changes, and 752 of 764 skill_versions already read as stale
        against the current digest. This adds one more rotation to a series the
        deployment already absorbs routinely; it does not create a novel event.

        DELIVERY IS `reeval`, BY CONSTRUCTION rather than by a new mechanism.
        `ScanRuntime.current_toolchain_digest` is this same expression, and
        `reeval` calls a published skill stale exactly when its recorded digest
        differs from it - so before this change a threshold tightening was
        invisible to re-evaluation too, and the already-published verdicts
        would never have been revisited at all. Binding the policy is what
        makes `GET /v1/reeval` surface them, where an admin drains them under
        control instead of the recompute landing on whoever submits next.
        """
        digest = hashlib.sha256(self.adjudication_semantics().encode("utf-8")).hexdigest()
        return f"{self.version}+p1:{digest}"


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
