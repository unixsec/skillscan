"""The ONE conversion between the vendored-engine lock-file key namespace and
the runtime engine-name namespace.

Two namespaces name the same five OSS engines and they do not agree:

    lock-file key       runtime `EngineMetadata.name`
    -------------       ---------------------------
    skillspector        skillspector
    aig                 aig-mcp-scan
    bandit              bandit
    osv_scanner         osv-scanner
    yara                yara

Neither side is wrong on its own. The lock keys follow this repo's Python
naming (`vendor/engines.lock.yaml` says so explicitly for `osv_scanner`); the
runtime names are the real CLI/subsystem names each adapter reports and are
what every finding, provenance tuple, admin toggle and i18n label already
carries. Three of five collide by accident, which is exactly what made the
mismatch survive: any join across the two namespaces looks like it works.

WHY THIS MODULE, RATHER THAN RENAMING ONE SIDE (2026-07-29, milestone C Task
2): renaming until the strings happen to match leaves the next vendored engine
free to reintroduce the bug with nothing to warn anybody. A named conversion
that RAISES on an unknown name turns "someone added an engine and forgot" into
a loud, immediate failure instead of a dashboard flag that is quietly wrong for
years - which is precisely how `reporting.service.build_engine_coverage`'s
`disabled` flag came to be permanently False for `osv_scanner` and `aig`.

SECURITY/HONESTY: there is deliberately NO `.get(name, name)`-style fallback
anywhere in this module. A default here is indistinguishable from a correct
answer at the call site, and every consumer of these functions is deciding
something operationally meaningful (is this engine required? is it switched
off?). Callers that genuinely cannot fail - the engine-coverage dashboard
panel is fail-soft by a deliberate, incident-driven decision - must catch
`UnknownEngineNameError` and surface "unknown", never substitute "no".

The table is pinned to both real sources by `tests/test_engine_name_namespaces.py`
(kernel suite, no infrastructure): it asserts the mapping is total over the
real `vendor/engines.lock.yaml` keys and total over the real
`engine_runner.sandbox_engines.SANDBOX_ENGINE_NAMES`. Adding an engine to
either side without updating this table fails there.

This lives in `libs/common` for the same reason `engine_toggle.py` does: both
the monolith and the separate engine-runner service reason about these names,
so it cannot be a monolith-private constant.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

__all__ = [
    "ENGINE_NAME_BY_LOCK_KEY",
    "LOCK_KEY_BY_ENGINE_NAME",
    "UnknownEngineNameError",
    "engine_name_for_lock_key",
    "lock_key_for_engine_name",
]


class UnknownEngineNameError(LookupError):
    """Raised instead of returning a default for a name the mapping does not
    know. See this module's docstring for why a default is not acceptable."""


ENGINE_NAME_BY_LOCK_KEY: Final[Mapping[str, str]] = MappingProxyType(
    {
        # lock key -> the `name=` literal in services/engine_runner/adapters/*.py
        "aig": "aig-mcp-scan",  # vendor/aig, but only its mcp-scan/ subsystem is adapted
        "bandit": "bandit",
        "osv_scanner": "osv-scanner",  # underscore key, hyphen CLI - see the lock file's own note
        "skillspector": "skillspector",
        "yara": "yara",
    }
)

LOCK_KEY_BY_ENGINE_NAME: Final[Mapping[str, str]] = MappingProxyType(
    {name: key for key, name in ENGINE_NAME_BY_LOCK_KEY.items()}
)


def engine_name_for_lock_key(lock_key: str) -> str:
    """`vendor/engines.lock.yaml` key -> runtime `EngineMetadata.name`.

    Raises `UnknownEngineNameError` for anything not in the table - including a
    runtime name passed in by mistake, which is the single most likely error
    and the one a `.get(k, k)` fallback would swallow.
    """
    try:
        return ENGINE_NAME_BY_LOCK_KEY[lock_key]
    except KeyError:
        raise UnknownEngineNameError(
            f"no runtime engine name is mapped for lock-file key {lock_key!r}; "
            f"known lock keys: {sorted(ENGINE_NAME_BY_LOCK_KEY)}. If an engine was just "
            f"vendored, add it to common.engine_names.ENGINE_NAME_BY_LOCK_KEY."
        ) from None


def lock_key_for_engine_name(engine_name: str) -> str:
    """Runtime `EngineMetadata.name` -> `vendor/engines.lock.yaml` key.

    Raises `UnknownEngineNameError` for anything not in the table. Note that
    floor engines and the intel matcher are never vendored and therefore
    legitimately have no lock key - callers must not treat that as an error
    condition they can paper over, they must not ask.
    """
    try:
        return LOCK_KEY_BY_ENGINE_NAME[engine_name]
    except KeyError:
        raise UnknownEngineNameError(
            f"no lock-file key is mapped for runtime engine name {engine_name!r}; "
            f"known runtime names: {sorted(LOCK_KEY_BY_ENGINE_NAME)}. In-house floor "
            f"engines and the intel matcher are not vendored and have no lock key."
        ) from None
