"""Cross-source pin for ENGINE TIER MEMBERSHIP (milestone C Task 3, 2026-07-29).

Which engines belong to the floor / sandbox / intel tier is asserted in SIX
places across three namespaces, and no two of them derive from each other:

    tier     source of truth this file trusts        derived declaration sites
    -------  --------------------------------------  ----------------------------------
    floor    `orchestration.floor.floor_engines()`   1. `policies/gate/v1.yaml`
                                                        `required_engines`
                                                     2. `main._build_scan_runtime`'s
                                                        `engine_metadatas=`
    sandbox  what `sandbox_engines()` really         3. `SANDBOX_ENGINE_NAMES`
             constructs with an LLM endpoint         4. `sandbox_engines()`'s config gate
             configured                              5. `worker.SANDBOX_ADVISORY_ENGINE_
                                                        NAMES` / `SANDBOX_WAITED_ENGINE_
                                                        NAMES`
    intel    `worker._floor_engines_with_intel`      6. `admin.engine_registry.
                                                        known_engine_rows`

WHY THIS FILE EXISTS. Milestone D shipped five separate defects of the form "a
new detector was registered in one place and its sibling registry was never
updated". Not one of them was findable by reading a diff, because the defining
symptom is a file that was *not* changed. Six declaration sites is that same
trap, larger.

This task deliberately does NOT merge the six into one. Merging would couple
runtime wiring (`main.py`) to the versioned policy file (`policies/gate/v1.yaml`),
which is a bigger change than milestone C wants and would put the INV-1 floor
backstop behind an extra layer of indirection. The goal here is narrower and
cheaper: make a MISSED site fail a test.

Shape, and why it needs no infrastructure: like `web/src/pages/Inventory.test.tsx`
(which parses the real `inventory/lifecycle.py` at test time) and
`web/src/lifecycleStateGuard.test.ts` (which scans real page source), this file
reads the REAL registries and the REAL source text. It touches no MySQL, no
Redis and no network, so it runs anywhere - which is most of why this shape
works at all: the same assertions inside `test_main_wiring.py` would only ever
run on the VM.

WHAT THIS DOES NOT REPLACE (all still needed, none of them covers the tier
registry end to end):
  - `test_gate_policy.py::test_real_v1_yaml_required_engines_includes_all_floor_
    engines` asserts a SUBSET, so a policy naming a non-floor engine passes there.
  - `test_sandbox_engines.py::TestSandboxEngineNamesSingleSourceOfTruth` covers
    the advisory alias against the real adapters, but nothing covers the WAITED
    set, and it is framed as one past bug's regression rather than as the
    registry.
  - `test_main_wiring.py` proves the real `create_app()` wiring, but needs real
    MySQL + Redis, so it cannot be the thing that catches a forgotten site
    during ordinary local work.
  - `tests/test_engine_name_namespaces.py` (Task 2) pins the lock-key <-> runtime
    -name conversion. Any name conversion here goes through `common.engine_names`
    rather than adding a fourth spelling; the tier sets below are all in the
    runtime namespace, so no conversion is needed.

DOCUMENTED OMISSIONS. One divergence between a tier and one of its declaration
sites is deliberate: `sandbox_engines()` omits `aig-mcp-scan` when no LLM
endpoint is configured. It is expressed below as a `DocumentedOmission` record
carrying the reason, the marker text that must still be present at the
declaring site, and the event that makes the omission expire - NOT as a filter
that hides it. That distinction is the whole point: an equality that has been
narrowed by a documented exception still breaks in BOTH directions, so the day
the divergence stops being legitimate the test goes red instead of staying
quiet. See `DocumentedOmission.disappears_when` for how the next person learns
the exception is over.

That is not hypothetical any more. A SECOND record lived here until 2026-07-29
(`SANDBOX_WAITED_ENGINE_NAMES` dropped `aig-mcp-scan`, because one global
subprocess timeout could not express that engine's budget). Milestone C Task 4
landed per-engine timeouts, this file went red exactly as designed, and the
record was deleted rather than widened. Note what did NOT change with it: the
engine can still be unwaitable on a deployment with no LLM endpoint, but that
is a runtime property, so it moved to a live filter
(`worker._active_sandbox_waited_engines`) instead of staying a hole in a
constant this test can see.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest
from engine_runner.sandbox_engines import (
    SANDBOX_ENGINE_NAMES,
    sandbox_engine_names,
    sandbox_engines,
)

from monolith.modules.admin.engine_registry import known_engine_names
from monolith.modules.gate.policy import load_gate_policy
from monolith.modules.intel.matcher import INTEL_ENGINE_NAME, IntelMatcher
from monolith.modules.orchestration.floor import floor_engine_names, floor_engines
from monolith.worker import SANDBOX_ADVISORY_ENGINE_NAMES, SANDBOX_WAITED_ENGINE_NAMES

_REPO_ROOT = Path(__file__).resolve().parents[3]
_REAL_POLICY_PATH = _REPO_ROOT / "policies" / "gate" / "v1.yaml"
_MAIN_PY = _REPO_ROOT / "apps" / "monolith" / "main.py"
_WORKER_PY = _REPO_ROOT / "apps" / "monolith" / "worker.py"
_SANDBOX_ENGINES_PY = _REPO_ROOT / "services" / "engine_runner" / "sandbox_engines.py"

# An internal endpoint (INV-14 rejects external ones unconditionally). Never
# dialed: `sandbox_engines()` only CONSTRUCTS adapters, it does not run them.
# Passing one is what makes the config-gated engines materialise, which is how
# this file gets at the full sandbox universe rather than one deployment's view.
_INTERNAL_LLM_URL = "http://localhost:11434/v1"


@dataclass(frozen=True)
class DocumentedOmission:
    """A tier member a specific declaration site deliberately leaves out.

    `reason` is the justification. `source_marker` is text that must still be
    present in `declared_in` - so the exclusion and its stated reason cannot
    drift apart silently (deleting the comment while keeping the exclusion is
    exactly how a reasoned divergence decays into an unexplained one).
    `disappears_when` names the event after which this record must be DELETED,
    not edited: once it is gone the plain equality applies again.
    """

    engine: str
    declared_in: Path
    reason: str
    source_marker: str
    disappears_when: str


# `sandbox_engines()` omits aig-mcp-scan entirely when no LLM endpoint is
# configured, rather than constructing it against a poison URL the way
# skillspector is. See that function's own docstring.
_AIG_HAS_NO_STATIC_MODE = DocumentedOmission(
    engine="aig-mcp-scan",
    declared_in=_SANDBOX_ENGINES_PY,
    reason=(
        "aig-mcp-scan has no static-only mode: vendor/aig/mcp-scan/main.py exits "
        "before touching the target if it cannot resolve an API key, so constructing "
        "it without a backend would report ERROR on every scan - indistinguishable "
        "from a genuinely broken engine."
    ),
    source_marker="static-only mode",
    disappears_when=(
        "aig-mcp-scan gains a real no-LLM mode upstream (it has none today), or the "
        "adapter stops being constructed conditionally"
    ),
)

# The second record that used to live here - `SANDBOX_WAITED_ENGINE_NAMES`
# dropping aig-mcp-scan - was DELETED by milestone C Task 4 (2026-07-29), the
# event its own `disappears_when` named. Per-engine timeouts landed
# (`engine_runner.timeouts`), the waited set became the whole tier, and the
# equality below now holds for that site with no omission at all. Deleting it
# rather than widening it is what the failure message asked for, and this note
# is here so the next reader knows the machinery has actually retired a record
# once - it is not decorative.


@dataclass(frozen=True)
class SandboxDeclarationSite:
    """One place the sandbox tier's membership is written down."""

    site: str
    names: Callable[[], frozenset[str]]
    omits: tuple[DocumentedOmission, ...]


_SANDBOX_SITES: tuple[SandboxDeclarationSite, ...] = (
    SandboxDeclarationSite(
        site="engine_runner/sandbox_engines.py:SANDBOX_ENGINE_NAMES",
        names=lambda: frozenset(SANDBOX_ENGINE_NAMES),
        omits=(),
    ),
    SandboxDeclarationSite(
        site="engine_runner/sandbox_engines.py:sandbox_engines() with no LLM endpoint",
        names=lambda: sandbox_engine_names(),
        omits=(_AIG_HAS_NO_STATIC_MODE,),
    ),
    SandboxDeclarationSite(
        site="apps/monolith/worker.py:SANDBOX_ADVISORY_ENGINE_NAMES",
        names=lambda: frozenset(SANDBOX_ADVISORY_ENGINE_NAMES),
        omits=(),
    ),
    SandboxDeclarationSite(
        site="apps/monolith/worker.py:SANDBOX_WAITED_ENGINE_NAMES",
        names=lambda: frozenset(SANDBOX_WAITED_ENGINE_NAMES),
        omits=(),
    ),
)


def _real_sandbox_tier() -> frozenset[str]:
    """The sandbox tier itself: whatever `sandbox_engines()` really builds when
    nothing is config-gated away. Deliberately not `SANDBOX_ENGINE_NAMES` - that
    is a hand-maintained literal and therefore one of the sites under test."""
    return frozenset(sandbox_engines(vllm_base_url=_INTERNAL_LLM_URL))


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _flattened_source(path: Path) -> str:
    """Source with every run of whitespace and comment `#` collapsed to one
    space, so a marker phrase still matches after a comment reflow - the reason
    for excluding aig-mcp-scan is currently written as `per-engine\\n# timeouts`,
    and a guard that a `ruff format` pass could break is not a guard."""
    return re.sub(r"[\s#]+", " ", path.read_text(encoding="utf-8"))


def _function_def(path: Path, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    for node in ast.walk(_parse(path)):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == name:
            return node
    raise AssertionError(
        f"{name}() no longer exists in {path.name} - this guard parses it to check a "
        f"tier declaration site. Point the test at whatever replaced it (and re-check "
        f"the tier membership by hand while doing so) rather than deleting the test."
    )


class TestFloorTierIsDeclaredIdenticallyInThreePlaces:
    """floor.py is the registry; the policy file and main.py restate it."""

    def test_the_shipped_gate_policy_requires_exactly_the_floor_set(self) -> None:
        """Site 1. Equality, not containment: `test_gate_policy.py` already
        asserts floor <= required, which catches a floor engine missing from the
        policy but NOT a policy entry that is no longer (or never was) a floor
        engine. The second direction matters just as much - INV-1 fail-closes a
        scan for every name in `required_engines`, so a stale name there blocks
        every scan for an engine that can never report."""
        floor = floor_engine_names()
        assert floor, "floor_engines() is empty - this assertion would be vacuous"
        assert load_gate_policy(_REAL_POLICY_PATH).required_engines == floor, (
            "policies/gate/v1.yaml's required_engines and orchestration/floor.py have "
            "diverged. A floor engine that is not in the policy is not enforced by "
            "INV-1; a policy name that is not a floor engine fail-closes every scan. "
            "Both files must be edited together."
        )

    def test_main_py_builds_engine_metadatas_from_the_floor_registry_unfiltered(self) -> None:
        """Site 2. `main._build_scan_runtime` needs real DB/Redis handles to
        run, so its wiring is checked by reading it, not by calling it (the
        executing version of this check is `test_main_wiring.py`, which is
        VM-only). What must hold is that `engine_metadatas` is a straight
        projection of `floor_engines()`: the moment it becomes a hand-written
        list, or grows a filter, adding a detector to floor.py silently stops
        reaching the runtime."""
        fn = _function_def(_MAIN_PY, "_build_scan_runtime")
        bound_to_floor = {
            target.id
            for stmt in ast.walk(fn)
            if isinstance(stmt, ast.Assign)
            and isinstance(stmt.value, ast.Call)
            and isinstance(stmt.value.func, ast.Name)
            and stmt.value.func.id == "floor_engines"
            for target in stmt.targets
            if isinstance(target, ast.Name)
        }
        keyword = next(
            (
                kw
                for node in ast.walk(fn)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "ScanRuntime"
                for kw in node.keywords
                if kw.arg == "engine_metadatas"
            ),
            None,
        )
        assert keyword is not None, (
            "_build_scan_runtime no longer passes engine_metadatas= to ScanRuntime(...) "
            "by keyword - update this parser rather than dropping the check."
        )
        referenced = {n.id for n in ast.walk(keyword.value) if isinstance(n, ast.Name)}
        assert referenced & bound_to_floor, (
            "main.py's engine_metadatas= no longer derives from floor_engines(). The "
            "floor tier would then be declared a third time, by hand, and adding a "
            "detector to orchestration/floor.py would not reach the running system."
        )
        narrowing = [
            node
            for node in ast.walk(keyword.value)
            if (isinstance(node, ast.comprehension) and node.ifs) or isinstance(node, ast.IfExp)
        ]
        assert not narrowing, (
            "main.py's engine_metadatas= now filters floor_engines(). A floor engine "
            "dropped here is silently not in `required_engines`' evidence path while "
            "policies/gate/v1.yaml still demands it - i.e. INV-1 fail-closes every "
            "scan. If a filter is genuinely wanted, it belongs in floor.py."
        )


class TestSandboxTierIsDeclaredIdenticallyInFourPlaces:
    """The real adapter registry is the tier; every constant restates it."""

    @pytest.mark.parametrize("site", _SANDBOX_SITES, ids=lambda s: s.site)
    def test_every_sandbox_declaration_site_covers_the_whole_tier(
        self, site: SandboxDeclarationSite
    ) -> None:
        """Sites 3-5 (and the config gate). Each site must equal the tier minus
        exactly its own documented omissions - so an accidental drop fails here,
        AND an omission that stops being legitimate also fails here, because the
        expected set is narrowed by the record rather than the comparison being
        skipped."""
        tier = _real_sandbox_tier()
        assert tier, "sandbox_engines() built nothing - this assertion would be vacuous"
        omitted = {omission.engine for omission in site.omits}
        expiries = (
            "; ".join(f"{o.engine} -> expires when {o.disappears_when}" for o in site.omits)
            or "none"
        )
        assert site.names() == tier - omitted, (
            f"{site.site} does not match the sandbox tier "
            f"(`sandbox_engines(vllm_base_url=...)`, which is what really runs). "
            f"Documented omissions at this site: {expiries}. If an engine was just added "
            f"or removed, every site in _SANDBOX_SITES needs the edit. If a documented "
            f"omission has just ENDED (its engine is back in this site's set), DELETE "
            f"that DocumentedOmission record - do not widen it and do not relax this "
            f"assertion. If a NEW omission has appeared, it needs a record with a reason "
            f"before this goes green again."
        )

    @pytest.mark.parametrize(
        "omission",
        [_AIG_HAS_NO_STATIC_MODE],
        ids=lambda o: f"{o.declared_in.name}:{o.engine}",
    )
    def test_each_documented_omission_still_states_its_reason_at_the_declaration_site(
        self, omission: DocumentedOmission
    ) -> None:
        """An omission recorded only here, with nothing left in the code it
        excuses, is indistinguishable from an unexplained one to the next reader
        of that file. Both directions of the pair must survive together."""
        assert omission.source_marker in _flattened_source(omission.declared_in), (
            f"{omission.declared_in.name} no longer contains {omission.source_marker!r}, "
            f"the stated reason for leaving {omission.engine!r} out. If the reason is "
            f"gone because the omission is over, delete the DocumentedOmission too "
            f"(it expires when: {omission.disappears_when}). If only the wording "
            f"changed, update source_marker."
        )

    def test_the_omitted_engine_is_still_a_real_member_of_the_tier(self) -> None:
        """Guards the omission machinery against becoming a rubber stamp: if
        `aig-mcp-scan` were deleted outright, subtracting it from the expected
        set would keep every site above green while the records claim to be
        excusing something that no longer exists."""
        for omission in (_AIG_HAS_NO_STATIC_MODE,):
            assert omission.engine in _real_sandbox_tier(), (
                f"{omission.engine!r} is documented as a deliberate omission but is no "
                f"longer a sandbox engine at all - delete the DocumentedOmission."
            )


class TestIntelTierIsDeclaredOnlyInTheWorkerAndMustReachTheAdminUniverse:
    """The intel matcher is declared in exactly one place - inside
    `worker._floor_engines_with_intel`. That is the single-declaration case, and
    it is precisely how milestone C Task 2's D3 happened: the admin console
    enumerated the two tiers it could see, so `inhouse-intel-matcher` could
    neither be listed nor toggled (PATCH returned 404) for an engine that runs
    on every scan."""

    def test_the_worker_tick_adds_exactly_one_engine_beyond_the_floor(self) -> None:
        """Site 6, first half. `_floor_engines_with_intel` needs a live DB
        session to add its engine, so its composition is read rather than run. A
        second entry appearing here is a new advisory tier, and every registry
        that enumerates tiers by hand - starting with
        `admin.engine_registry.known_engine_rows` - has to learn about it."""
        fn = _function_def(_WORKER_PY, "_floor_engines_with_intel")
        constructors = {
            target.id: stmt.value.func.id
            for stmt in ast.walk(fn)
            if isinstance(stmt, ast.Assign)
            and isinstance(stmt.value, ast.Call)
            and isinstance(stmt.value.func, ast.Name)
            for target in stmt.targets
            if isinstance(target, ast.Name)
        }
        added = [
            stmt.value.id
            for stmt in ast.walk(fn)
            if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Name)
            for target in stmt.targets
            if isinstance(target, ast.Subscript)
            and isinstance(target.value, ast.Name)
            and target.value.id == "engines"
        ]
        mutated = [
            node.func.attr
            for node in ast.walk(fn)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "engines"
        ]
        assert not mutated, (
            f"the worker tick's engine dict is now also written via {mutated} - this "
            f"parser only understands `engines[...] = <name>`, so it can no longer see "
            f"the whole tier. Teach it the new shape rather than deleting the check."
        )
        assert [constructors.get(name) for name in added] == ["IntelMatcher"], (
            "worker._floor_engines_with_intel no longer adds exactly one IntelMatcher "
            "beyond floor_engines(). A new engine here is a new TIER - it must also be "
            "added to admin.engine_registry.known_engine_rows (or the admin console "
            "will neither list nor toggle it, exactly as happened to the intel matcher) "
            "and to the expected list in this test."
        )

    def test_the_intel_engine_is_in_the_admin_universe(self) -> None:
        """Site 6, second half. `IntelMatcher` is constructed for real here (an
        empty IOC snapshot needs no DB - `load_known_iocs` is the part that
        does), so the name being checked is the one the running engine reports,
        not a constant that could itself be stale."""
        real_name = IntelMatcher(known_iocs=frozenset()).metadata.name
        assert real_name == INTEL_ENGINE_NAME, (
            "intel.matcher's exported INTEL_ENGINE_NAME no longer matches the name a "
            "real IntelMatcher reports - admin.engine_registry lists the constant, so "
            "the listed row would not be the running engine."
        )
        floor_metadatas = tuple(engine.metadata for engine in floor_engines().values())
        assert real_name in known_engine_names(floor_metadatas), (
            "the intel matcher is not in the admin engine universe. It runs on every "
            "scan; an engine missing from known_engine_names can be neither listed nor "
            "switched off (PATCH /v1/admin/engines/{name} returns 404)."
        )
