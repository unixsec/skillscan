"""Cross-namespace guard: every join between the vendored-engine LOCK-FILE key
namespace and the RUNTIME engine-name namespace must go through one explicit
conversion, and the "universe of engine names this deployment knows" must be
derived once, not re-assembled per call site.

WHY THIS EXISTS (2026-07-29, milestone C Task 2). Three namespaces coexist and
do not reconcile:

  lock-file keys      `osv_scanner`, `aig`        vendor/engines.lock.yaml
  runtime names       `osv-scanner`, `aig-mcp-scan`  adapters + floor.py
  catalog ids         `SUPPLY-02`, `CODE-02`      the .xlsx catalog

Three defects were live in production, all from joining across them by raw
string equality (measured against the real repo, 2026-07-29):

  D1  `reporting.service.build_engine_coverage`'s `disabled` flag tested a LOCK
      KEY for membership in the set of disabled RUNTIME names. `aig` and
      `osv_scanner` are not runtime names, so disabling `osv-scanner` never
      showed up on the dashboard for 2 of the 5 vendored engines.

  D2  the same function's `required` flag tested a LOCK KEY for membership in
      `floor_engine_names()`. No lock key is a floor name and none ever can be,
      so the comparison was structurally incapable of returning True. (The
      VALUE False happens to be correct for all five - sandbox engines are
      never `required_engines`, and `worker._parse_policy_candidate` refuses any
      policy that names one - so this was a broken computation producing a
      coincidentally-right answer, which is why it survived. Asserted below as
      a namespace property, not as an output value.)

  D3  `admin.router`'s `known_names` was floor names | SANDBOX_ENGINE_NAMES,
      built independently of the list the same module renders. It omitted
      `inhouse-intel-matcher` (declared only via `intel.matcher`), so that
      engine could neither be listed nor toggled - PATCH returned 404.

These tests are deliberately in the kernel suite (`uv run pytest tests/ -q`,
no MySQL/Redis): they read the REAL lock file and the REAL registries, so a
newly vendored engine whose lock key nobody mapped, or a new engine tier
nobody added to the admin universe, fails here rather than silently producing
a wrong dashboard flag for years.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = REPO_ROOT / "vendor" / "engines.lock.yaml"


def _lock_keys() -> frozenset[str]:
    payload = yaml.safe_load(LOCK_PATH.read_text(encoding="utf-8"))
    return frozenset(payload["engines"])


class TestLockKeyToRuntimeNameConversion(unittest.TestCase):
    """The conversion point itself - one table, total over the real lock file,
    and loud on anything it has not been told about."""

    def test_every_real_lock_key_resolves_to_a_real_runtime_engine_name(self) -> None:
        from common.engine_names import engine_name_for_lock_key
        from engine_runner.sandbox_engines import SANDBOX_ENGINE_NAMES

        resolved = {key: engine_name_for_lock_key(key) for key in _lock_keys()}
        unknown = {k: v for k, v in resolved.items() if v not in SANDBOX_ENGINE_NAMES}
        self.assertEqual(
            unknown,
            {},
            "a lock key resolved to a name no adapter produces - either the mapping in "
            "common.engine_names is wrong or an adapter's `name=` literal changed",
        )

    def test_the_conversion_covers_every_runtime_engine_name(self) -> None:
        """The other direction: an engine that exists at runtime but was never
        pinned (or was pinned under a key nobody mapped) is just as broken."""
        from common.engine_names import lock_key_for_engine_name
        from engine_runner.sandbox_engines import SANDBOX_ENGINE_NAMES

        self.assertEqual(
            {lock_key_for_engine_name(n) for n in SANDBOX_ENGINE_NAMES},
            set(_lock_keys()),
        )

    def test_an_unknown_lock_key_raises_rather_than_defaulting(self) -> None:
        """The whole point. A silent `return lock_key` fallback is how D1/D2
        stayed wrong for years instead of failing once, loudly."""
        from common.engine_names import UnknownEngineNameError, engine_name_for_lock_key

        with self.assertRaises(UnknownEngineNameError):
            engine_name_for_lock_key("osv-scanner")  # the RUNTIME name, not a lock key
        with self.assertRaises(UnknownEngineNameError):
            engine_name_for_lock_key("newly-vendored-engine")

    def test_an_unknown_runtime_name_raises_rather_than_defaulting(self) -> None:
        from common.engine_names import UnknownEngineNameError, lock_key_for_engine_name

        with self.assertRaises(UnknownEngineNameError):
            lock_key_for_engine_name("osv_scanner")  # the LOCK KEY, not a runtime name
        with self.assertRaises(UnknownEngineNameError):
            lock_key_for_engine_name("inhouse-pii")  # a floor engine is never vendored

    def test_the_two_directions_are_inverses(self) -> None:
        from common.engine_names import ENGINE_NAME_BY_LOCK_KEY, LOCK_KEY_BY_ENGINE_NAME

        self.assertEqual(len(ENGINE_NAME_BY_LOCK_KEY), len(LOCK_KEY_BY_ENGINE_NAME))
        for key, name in ENGINE_NAME_BY_LOCK_KEY.items():
            self.assertEqual(LOCK_KEY_BY_ENGINE_NAME[name], key)


class TestEngineCoverageRowsJoinInTheRuntimeNamespace(unittest.TestCase):
    """D1 + D2, at the row builder `build_engine_coverage` delegates to - pure,
    so it is provable here without the Redis the report function needs."""

    def _rows(self, disabled: frozenset[str] = frozenset()) -> dict[str, dict[str, object]]:
        from monolith.modules.orchestration.floor import floor_engine_names
        from monolith.modules.reporting.service import build_engine_coverage_rows

        payload = yaml.safe_load(LOCK_PATH.read_text(encoding="utf-8"))
        rows = build_engine_coverage_rows(
            payload["engines"], required=floor_engine_names(), disabled=disabled
        )
        return {str(r["lock_key"]): r for r in rows}

    def test_rows_are_identified_by_runtime_name_not_lock_key(self) -> None:
        rows = self._rows()
        self.assertEqual(rows["osv_scanner"]["name"], "osv-scanner")
        self.assertEqual(rows["aig"]["name"], "aig-mcp-scan")

    def test_disabled_flag_matches_a_disabled_runtime_engine(self) -> None:
        """D1: `osv-scanner` disabled by an admin must read as disabled on the
        row whose lock key is `osv_scanner`."""
        rows = self._rows(disabled=frozenset({"osv-scanner", "aig-mcp-scan"}))
        self.assertIs(rows["osv_scanner"]["disabled"], True)
        self.assertIs(rows["aig"]["disabled"], True)
        self.assertIs(rows["bandit"]["disabled"], False)

    def test_required_flag_is_computed_against_the_runtime_name(self) -> None:
        """D2: assert the JOIN, not the value. The value is False for all five
        (correctly - they are never `required_engines`); what was broken is that
        it was False because a lock key can never be a floor name. Feeding a
        required-set that contains the RUNTIME name must flip it."""
        from monolith.modules.reporting.service import build_engine_coverage_rows

        payload = yaml.safe_load(LOCK_PATH.read_text(encoding="utf-8"))
        rows = {
            str(r["lock_key"]): r
            for r in build_engine_coverage_rows(
                payload["engines"],
                required=frozenset({"osv-scanner"}),
                disabled=frozenset(),
            )
        }
        self.assertIs(rows["osv_scanner"]["required"], True)
        self.assertIs(rows["bandit"]["required"], False)

    def test_an_unmapped_lock_key_is_reported_as_unknown_never_as_false(self) -> None:
        """The report panel is fail-soft by deliberate design (a missing lock
        file must not 500 the dashboard), so it catches the conversion point's
        error rather than propagating it - but it must surface `None`
        ("unknown"), never `False` ("fine"), which is the exact shape of the
        bug being fixed."""
        from monolith.modules.reporting.service import build_engine_coverage_rows

        rows = build_engine_coverage_rows(
            {"a_brand_new_engine": {"role": "mandatory"}},
            required=frozenset(),
            disabled=frozenset(),
        )
        self.assertEqual(rows[0]["name"], "a_brand_new_engine")
        self.assertIsNone(rows[0]["required"])
        self.assertIsNone(rows[0]["disabled"])


class TestAdminEngineUniverse(unittest.TestCase):
    """D3: one derivation of "every engine name this deployment knows", used by
    both the listing and the toggle - so listable and toggleable cannot drift."""

    def test_the_intel_matcher_is_a_known_engine(self) -> None:
        from monolith.modules.admin.engine_registry import known_engine_names
        from monolith.modules.intel.matcher import INTEL_ENGINE_NAME
        from monolith.modules.orchestration.floor import floor_engines

        names = known_engine_names(tuple(e.metadata for e in floor_engines().values()))
        self.assertIn(INTEL_ENGINE_NAME, names)

    def test_the_universe_covers_all_three_engine_tiers(self) -> None:
        from engine_runner.sandbox_engines import SANDBOX_ENGINE_NAMES
        from monolith.modules.admin.engine_registry import known_engine_names
        from monolith.modules.intel.matcher import INTEL_ENGINE_NAME
        from monolith.modules.orchestration.floor import floor_engine_names, floor_engines

        names = known_engine_names(tuple(e.metadata for e in floor_engines().values()))
        self.assertEqual(
            names,
            floor_engine_names() | frozenset(SANDBOX_ENGINE_NAMES) | {INTEL_ENGINE_NAME},
        )

    def test_every_listed_engine_is_also_addressable_by_the_toggle(self) -> None:
        """The two used to be assembled independently; the listing is now the
        single derivation and the toggle's `known_names` reads off it."""
        from monolith.modules.admin.engine_registry import known_engine_names, known_engine_rows
        from monolith.modules.orchestration.floor import floor_engine_names, floor_engines

        metadatas = tuple(e.metadata for e in floor_engines().values())
        rows = known_engine_rows(metadatas, required=floor_engine_names(), disabled=frozenset())
        self.assertEqual({str(r["name"]) for r in rows}, set(known_engine_names(metadatas)))


if __name__ == "__main__":
    unittest.main()
