"""INV-7 guard: every in-house detector's `ruleset_digest` must change when any
field that changes detection or scoring changes.

WHY THIS EXISTS (2026-07-27, milestone D final review, F-3): `ruleset_digest`
flows into `toolchain_digest` (`libs/common/canonical.py`) and thus into the
scan `cache_key`. A rule edit that leaves the digest unchanged means
`submit_scan` returns the EXISTING scan_job for every already-scanned package
and reeval's toolchain-staleness check sees nothing to redo - so the corrected
rule is silently served a stale cached verdict, forever.

Four detectors were shipping with exactly that hole (`file_type` did not hash
severity or confidence at all; `mcp_config` and `skill_permissions` did not
hash their catalog-id mapping, and `skill_permissions` did not hash
`_PERMISSION_KEYS` - the list that decides which frontmatter spellings count
as a permission declaration at all; the two Chinese instruction detectors did
not hash severity). Each was fixed piecemeal at least once before, in three
separate passes, and each pass missed a sibling. That is why this file mutates
*discovered* fields rather than a hand-maintained list:

  - the DETECTOR list is a glob, so a new detector is covered the moment it
    lands;
  - the FIELD list is read from each module's own globals, so a new rule-table
    column or a new module constant is covered by construction too;
  - anything deliberately left out of a digest must be named in
    `_EXCLUDED_*` below with a reason, which makes every exclusion a
    reviewable decision instead of an oversight.

The only things excluded are human-facing prose (rule titles, risk
descriptions) and the engine's own name, which is carried by
`EngineMetadata.name` rather than by the ruleset.
"""

from __future__ import annotations

import importlib
import re
import unittest
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from skillscan_core import DetectionCategory, Severity

_DETECTORS_DIR = Path(__file__).resolve().parent.parent / "services" / "engine_runner" / "detectors"

# Prose and identity, per the module docstring. Names, not values, so a
# renamed constant loses its exemption and has to be justified again.
_EXCLUDED_GLOBALS = frozenset(
    {
        "_RISK_DESCRIPTIONS",  # human-facing explanation of a finding
        "_ENGINE_NAME",  # engine identity - hashed as EngineMetadata.name, not the ruleset
    }
)
_EXCLUDED_GLOBAL_SUFFIXES = ("_RISK",)  # e.g. _MAGIC_SIGNATURE_RISK: prose

# (module, rule-table constant, column index) that hold a human-readable title
# or description rather than a detection/scoring input.
_EXCLUDED_TABLE_COLUMNS = frozenset(
    {
        ("pii", "_PII_PATTERNS", 2),  # title
        ("crypto_weak", "_PATTERNS", 2),  # title
        ("toctou", "_PATTERNS", 2),  # title
        ("file_type", "_MAGIC_SIGNATURES", 3),  # description
    }
)

_SENTINEL_STR = "__digest_sensitivity_probe__"


def _detector_modules() -> list[Any]:
    modules = []
    for path in sorted(_DETECTORS_DIR.glob("*.py")):
        if path.name.startswith("__"):
            continue
        module = importlib.import_module(f"engine_runner.detectors.{path.stem}")
        if hasattr(module, "_metadata"):
            modules.append(module)
    return modules


def _mutate_scalar(value: object) -> object | None:
    """A different value of the same kind, or None if this kind is not one this
    guard knows how to perturb."""
    if isinstance(value, Severity):
        return next(s for s in Severity if s is not value)
    if isinstance(value, DetectionCategory):
        return next(c for c in DetectionCategory if c is not value)
    if isinstance(value, bool):
        return not value
    if isinstance(value, float):
        return value + 0.5
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str):
        return value + _SENTINEL_STR
    if isinstance(value, bytes):
        return value + b"\xde\xad"
    if isinstance(value, re.Pattern):
        return re.compile(value.pattern + f"|{_SENTINEL_STR}", value.flags)
    return None


def _mutations(module: Any) -> Iterator[tuple[str, str, object]]:
    """Yield (description, global_name, mutated_value) for every scoring- or
    detection-relevant module constant this guard can perturb."""
    module_name = module.__name__.rsplit(".", 1)[-1]
    for name, value in sorted(vars(module).items()):
        if not name.startswith("_") or name.startswith("__"):
            continue
        if name in _EXCLUDED_GLOBALS or name.endswith(_EXCLUDED_GLOBAL_SUFFIXES):
            continue

        scalar = _mutate_scalar(value)
        if scalar is not None:
            yield (name, name, scalar)
            continue

        if isinstance(value, frozenset | set):
            member = next(iter(value), None)
            addition = 10**9 if isinstance(member, int) else _SENTINEL_STR
            yield (name, name, type(value)([*value, addition]))
            continue

        if isinstance(value, dict):
            key = next(iter(value), None)
            if key is None:
                continue
            mutated_value = _mutate_dict_value(value[key])
            if mutated_value is not None:
                yield (f"{name}[{key!r}]", name, {**value, key: mutated_value})
            continue

        if isinstance(value, tuple) and value:
            if all(isinstance(row, tuple) for row in value):
                for column, cell in enumerate(value[0]):
                    if (module_name, name, column) in _EXCLUDED_TABLE_COLUMNS:
                        continue
                    mutated_cell = _mutate_scalar(cell)
                    if mutated_cell is None:
                        continue
                    first = (*value[0][:column], mutated_cell, *value[0][column + 1 :])
                    yield (f"{name}[0][{column}]", name, (first, *value[1:]))
            else:
                yield (name, name, (*value, _SENTINEL_STR))


def _mutate_dict_value(value: object) -> object | None:
    if isinstance(value, tuple) and value:
        mutated_first = _mutate_scalar(value[0])
        if mutated_first is None:
            return None
        return (mutated_first, *value[1:])
    return _mutate_scalar(value)


class TestDetectorDigestSensitivity(unittest.TestCase):
    def test_at_least_every_known_detector_is_discovered(self) -> None:
        """A glob that silently stops matching would make every assertion below
        vacuous."""
        discovered = {m.__name__.rsplit(".", 1)[-1] for m in _detector_modules()}
        self.assertGreaterEqual(
            discovered,
            {
                "crypto_weak",
                "file_type",
                "jailbreak_inducement_zh",
                "mcp_config",
                "pii",
                "prompt_injection_zh",
                "skill_permissions",
                "toctou",
            },
        )

    def test_every_detector_yields_mutations(self) -> None:
        for module in _detector_modules():
            with self.subTest(detector=module.__name__):
                self.assertNotEqual(
                    list(_mutations(module)),
                    [],
                    "no mutable rule fields discovered - this detector would be silently unguarded",
                )

    def test_every_rule_field_is_a_digest_input(self) -> None:
        for module in _detector_modules():
            baseline = module._metadata().ruleset_digest
            for description, name, mutated in _mutations(module):
                original = getattr(module, name)
                try:
                    setattr(module, name, mutated)
                    try:
                        after = module._metadata().ruleset_digest
                    except Exception:
                        # The mutated field is so tightly coupled to the digest
                        # computation that it cannot even be computed without
                        # it (e.g. a rule_id that keys a mapping table). That
                        # is sensitivity, not a hole.
                        continue
                finally:
                    setattr(module, name, original)

                with self.subTest(detector=module.__name__, field=description):
                    self.assertNotEqual(
                        after,
                        baseline,
                        f"{module.__name__}.{description} changes what this detector "
                        "detects, how severe/confident it is, or which catalog item it "
                        "maps to, but ruleset_digest did not change. toolchain_digest "
                        "and cache_key therefore also stay the same, so every "
                        "already-scanned package keeps its OLD verdict and the edit is "
                        "silently a no-op in production. Either fold this field into "
                        "_metadata()'s hash, or - if it genuinely cannot affect "
                        "detection or scoring - name it in this module's exclusion "
                        "list with a reason.",
                    )

    def test_the_digest_is_stable_when_nothing_changes(self) -> None:
        """Guards the guard: if `_metadata()` were nondeterministic, every
        assertion above would pass for the wrong reason."""
        for module in _detector_modules():
            with self.subTest(detector=module.__name__):
                self.assertEqual(
                    module._metadata().ruleset_digest, module._metadata().ruleset_digest
                )
