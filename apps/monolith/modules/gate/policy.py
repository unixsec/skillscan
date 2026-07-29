"""Load a versioned `GatePolicy` from `policies/gate/*.yaml` (coding spec
§11.6: "GatePolicy 从版本化 yaml 加载;每判定记 policy_version;config-as-code,
PR 评审").

SECURITY: this is config-as-code, not a database row - the file itself IS the
audit trail (git history/PR review) for policy changes. Parsing is
deliberately fail-closed: any unknown enum string, wrong type, or missing
required field raises immediately rather than silently falling back to a
default - an operator typo in a hard-gate rule list must never be swallowed
into "policy loaded fine, just with fewer rules than intended".
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from skillscan_core import CategoryWeights, GatePolicy, Severity, TrustTier, Verdict


class GatePolicyLoadError(ValueError):
    pass


def _parse_severity(raw: object, *, field_name: str) -> Severity:
    if not isinstance(raw, str):
        raise GatePolicyLoadError(f"{field_name}: expected a string severity name, got {raw!r}")
    try:
        return Severity[raw]
    except KeyError as exc:
        valid = [s.name for s in Severity]
        raise GatePolicyLoadError(
            f"{field_name}: unknown severity {raw!r}, expected one of {valid}"
        ) from exc


def _parse_verdict(raw: object, *, field_name: str) -> Verdict:
    if not isinstance(raw, str):
        raise GatePolicyLoadError(f"{field_name}: expected a string verdict name, got {raw!r}")
    try:
        return Verdict[raw]
    except KeyError as exc:
        valid = [v.name for v in Verdict]
        raise GatePolicyLoadError(
            f"{field_name}: unknown verdict {raw!r}, expected one of {valid}"
        ) from exc


def _parse_trust_tier(raw: object, *, field_name: str) -> TrustTier:
    if not isinstance(raw, str):
        raise GatePolicyLoadError(f"{field_name}: expected a string trust tier, got {raw!r}")
    try:
        return TrustTier(raw)
    except ValueError as exc:
        valid = [t.value for t in TrustTier]
        raise GatePolicyLoadError(
            f"{field_name}: unknown trust tier {raw!r}, expected one of {valid}"
        ) from exc


def _parse_str_sequence(raw: object, *, field_name: str) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise GatePolicyLoadError(f"{field_name}: expected a list of strings, got {raw!r}")
    return tuple(raw)


def _parse_tier_overrides(raw: object) -> tuple[tuple[TrustTier, Severity], ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise GatePolicyLoadError(f"tier_block_overrides: expected a list, got {raw!r}")
    overrides: list[tuple[TrustTier, Severity]] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict) or "tier" not in entry or "severity" not in entry:
            raise GatePolicyLoadError(
                f"tier_block_overrides[{i}]: expected {{tier, severity}}, got {entry!r}"
            )
        tier = _parse_trust_tier(entry["tier"], field_name=f"tier_block_overrides[{i}].tier")
        severity = _parse_severity(
            entry["severity"], field_name=f"tier_block_overrides[{i}].severity"
        )
        overrides.append((tier, severity))
    return tuple(overrides)


def _parse_category_weights(raw: object) -> CategoryWeights:
    """`category_weights:` -> `CategoryWeights` (milestone C Task 5).

    ABSENT IS VALID and means the all-1.0 default: every policy file written
    before this section existed keeps loading, and behaves exactly as it did.
    Absent and all-1.0 are also indistinguishable downstream by construction -
    `GatePolicy.cache_policy_version` derives the same term for both (Task 11
    hashes the parsed policy, and `CategoryWeights.non_default_items()` is
    empty either way) - so an operator adding an explicit all-1.0 section does
    not invalidate a cache.

    An UNKNOWN KEY IS REFUSED, same fail-closed posture as the rest of this
    module: `data_credentials: 2.0` (plural, a plausible typo) would otherwise
    load as "weights configured" while weighting nothing, and the only symptom
    would be scores that never moved.
    """
    if raw is None:
        return CategoryWeights()
    if not isinstance(raw, dict):
        raise GatePolicyLoadError(f"category_weights: expected a mapping, got {raw!r}")

    valid = {spec.name for spec in dataclasses.fields(CategoryWeights)}
    kwargs: dict[str, float] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or key not in valid:
            raise GatePolicyLoadError(
                f"category_weights: unknown category {key!r}, expected one of {sorted(valid)}"
            )
        # bool is an int subclass - `code: true` must not read as 1.0.
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise GatePolicyLoadError(f"category_weights.{key}: expected a number, got {value!r}")
        kwargs[key] = float(value)

    # SECURITY: range/finiteness (negative weights invert the penalty) is
    # enforced by CategoryWeights.__post_init__, never duplicated here - same
    # posture as GatePolicy's own invariants below, so there is exactly one
    # place those rules can drift. Its message already names the field.
    try:
        return CategoryWeights(**kwargs)
    except ValueError as exc:
        raise GatePolicyLoadError(f"category_weights: {exc}") from exc


def parse_gate_policy(raw: dict[str, Any]) -> GatePolicy:
    """Pure parsing function (no file I/O) - `load_gate_policy` below is the
    thin file-reading wrapper. Split out so tests can exercise malformed
    payloads directly without writing temp files for every case."""
    if "version" not in raw or not isinstance(raw["version"], str) or not raw["version"]:
        raise GatePolicyLoadError("policy file missing non-empty string 'version'")
    if "required_engines" not in raw:
        raise GatePolicyLoadError("policy file missing required 'required_engines'")

    kwargs: dict[str, Any] = {
        "version": raw["version"],
        "required_engines": frozenset(
            _parse_str_sequence(raw["required_engines"], field_name="required_engines")
        ),
        "hard_gate_rules": frozenset(
            _parse_str_sequence(raw.get("hard_gate_rules"), field_name="hard_gate_rules")
        ),
        "tier_block_overrides": _parse_tier_overrides(raw.get("tier_block_overrides")),
        "category_weights": _parse_category_weights(raw.get("category_weights")),
    }
    if "review_confidence" in raw:
        if not isinstance(raw["review_confidence"], (int, float)):
            raise GatePolicyLoadError(
                f"review_confidence: expected a number, got {raw['review_confidence']!r}"
            )
        kwargs["review_confidence"] = float(raw["review_confidence"])
    if "block_on_severity" in raw:
        kwargs["block_on_severity"] = _parse_severity(
            raw["block_on_severity"], field_name="block_on_severity"
        )
    if "review_on_severity" in raw:
        kwargs["review_on_severity"] = _parse_severity(
            raw["review_on_severity"], field_name="review_on_severity"
        )
    if "allowlistable_max_severity" in raw:
        kwargs["allowlistable_max_severity"] = _parse_severity(
            raw["allowlistable_max_severity"], field_name="allowlistable_max_severity"
        )
    if "fail_closed_verdict" in raw:
        kwargs["fail_closed_verdict"] = _parse_verdict(
            raw["fail_closed_verdict"], field_name="fail_closed_verdict"
        )

    # SECURITY: GatePolicy.__post_init__ enforces the remaining invariants itself
    # (fail_closed_verdict != PASS, tier overrides may only tighten, etc.) - never
    # duplicated here, so there is exactly one place those rules can drift.
    try:
        return GatePolicy(**kwargs)
    except ValueError as exc:
        raise GatePolicyLoadError(f"policy file failed GatePolicy validation: {exc}") from exc


def load_gate_policy(yaml_path: Path) -> GatePolicy:
    try:
        text = yaml_path.read_text()
    except OSError as exc:
        raise GatePolicyLoadError(f"cannot read policy file {yaml_path}: {exc}") from exc
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise GatePolicyLoadError(f"policy file {yaml_path} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise GatePolicyLoadError(
            f"policy file {yaml_path} must contain a YAML mapping at the top level"
        )
    return parse_gate_policy(raw)


def tier_direction(policy: GatePolicy, *, requested: str | None, judged: str | None) -> str | None:
    """里程碑 F Task 14: which way a requested/judged tier divergence cuts.

    `"looser"` is the one that matters - the verdict was adjudicated under a
    MORE PERMISSIVE ruleset than this caller asked for, so a finding that
    should have blocked for them may read PASS. `"stricter"` is the safe side
    (possible over-blocking, still worth saying out loud). `"equivalent"` means
    the tier NAMES differ but the policy treats them identically, i.e. nothing
    about the verdict changes. `None` means the comparison cannot be made -
    either tier unrecorded, or a stored value that is not a `TrustTier`.

    Derived from `GatePolicy.block_threshold`, the authority, and NOT from
    `TrustTier`'s declaration order. That order happens to run loose-to-strict
    today, but strictness is a property of `tier_block_overrides` in the
    policy file: `public` blocks at HIGH and every other tier at CRITICAL, and
    a policy edit can change that without touching the enum. Reading the order
    instead would be a shape check standing in for a policy check - the exact
    substitution this codebase has already paid for once (see
    `SubmissionChannel`'s docstring on the SUP-01 catalog audit).

    A hint, not a claim about the past: it is computed from the policy loaded
    NOW, while the verdict was reached under whatever policy version was loaded
    then. Both tiers are always returned verbatim alongside it, so a consumer
    is never dependent on this field being the last word. `tier_divergence`
    below is what says WHICH policy a given answer was computed under - use it
    at any surface that shows this to a human.

    LIVES HERE, not in `gateway.router` where Task 14 first wrote it (Task 18):
    two surfaces now disclose the divergence - the console's
    `GET /v1/scans/{scan_id}` and the marketplace's `GET /v1/market/scans/
    {scan_id}` - and `marketplace_api` is a deliberate anti-corruption layer
    that must not import another surface's HTTP router to reach a private
    helper. `gate` is the module that owns applying `GatePolicy`, both callers
    already depend on it, and this function touches no ORM class, so it costs
    nothing at the module boundary (scripts/check_import_boundaries.py).

    Takes the STORED column shape (`str | None`) rather than `TrustTier`
    deliberately: both callers read these values straight out of
    `scan_job.trust_tier` / `scan_submitter.requested_trust_tier`, both of
    which are nullable and neither of which the database constrains to the
    enum. Coercing at the two call sites instead would duplicate exactly the
    "unrecorded vs. corrupt vs. valid" three-way that is the load-bearing part
    of this function.
    """
    if requested is None or judged is None or requested == judged:
        return None
    try:
        requested_threshold = policy.block_threshold(TrustTier(requested))
        judged_threshold = policy.block_threshold(TrustTier(judged))
    except ValueError:
        # A stored value that is not a valid TrustTier. Report "cannot say"
        # rather than picking a direction from a corrupt row.
        return None
    # LOWER block threshold = stricter (blocking at HIGH catches strictly more
    # than blocking at CRITICAL - Severity is an IntEnum, HIGH=3 < CRITICAL=4).
    if judged_threshold > requested_threshold:
        return "looser"
    if judged_threshold < requested_threshold:
        return "stricter"
    return "equivalent"


@dataclass(frozen=True, slots=True)
class TierDivergence:
    """`tier_direction` plus the one fact that makes it honest: which policy it
    was computed under.

    `basis` is `None` exactly when `direction` is - there is nothing to
    qualify. Otherwise:

      * `"signing_policy"` - the verdict's own `policy_version` is the version
        this process has loaded, so the direction describes the adjudication as
        it actually happened.
      * `"current_policy"` - it does not (or there is no verdict yet, so
        nothing has been signed at all). The direction is still computed and
        still useful, but it describes TODAY's thresholds, not the ones in
        force when the verdict was signed.
    """

    direction: str | None
    basis: str | None


def tier_divergence(
    policy: GatePolicy,
    *,
    requested: str | None,
    judged: str | None,
    signed_policy_version: str | None,
) -> TierDivergence:
    """`tier_direction`, qualified by whether it could be computed under the
    policy the verdict was actually signed under.

    THE PROBLEM (2026-07-29, milestones E+F residual triage). `tier_direction`
    reads `GatePolicy.block_threshold` off whatever policy this process has
    loaded right now. Strictness lives in `tier_block_overrides`, and an
    approved `policy_proposal` can change those between the moment a verdict is
    signed and the moment somebody looks at it - so a historical verdict could
    be relabelled: a divergence shown that did not exist when the adjudication
    happened, or a real one hidden.

    WHAT IS ACTUALLY RECOVERABLE, and what is therefore NOT invented here.
    `verdict.policy_version` is recorded on every verdict (gate.models.
    VerdictRow, written by `decide_and_record`), so "was this the same policy
    VERSION" is answerable. The policy CONTENT at that version is not
    reconstructible in the general case: `policy_proposal` holds the YAML of
    policies that arrived as proposals, but the bootstrap policy is a file on
    disk (policies/gate/v1.yaml) with no row anywhere, and svc_gate's own
    session is not a policy archive. So this function does NOT re-derive a
    historical threshold - it says which policy the number in front of you came
    from and lets the surface caveat it. An accurate caveat beats a confident
    wrong label.

    KNOWN LIMIT, stated rather than papered over: version equality is not
    content equality. `policies/gate/v1.yaml` can be edited in place without
    bumping `version`, and this would then report `"signing_policy"` for a
    policy whose thresholds have in fact moved. Version is the only handle the
    verdict row carries; the real fix is a content digest on the verdict, which
    is a schema change and not one to make silently as part of a display fix.

    `signed_policy_version is None` (no verdict yet) is `"current_policy"`: no
    adjudication has happened, so the direction describes what today's policy
    would do - which is exactly what the caveat says.
    """
    direction = tier_direction(policy, requested=requested, judged=judged)
    if direction is None:
        return TierDivergence(direction=None, basis=None)
    basis = "signing_policy" if signed_policy_version == policy.version else "current_policy"
    return TierDivergence(direction=direction, basis=basis)
