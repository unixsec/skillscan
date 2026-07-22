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

from pathlib import Path
from typing import Any

import yaml
from skillscan_core import GatePolicy, Severity, TrustTier, Verdict


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
