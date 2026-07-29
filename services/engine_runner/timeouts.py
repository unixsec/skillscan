"""Per-engine subprocess timeouts (milestone C Task 4, design §4).

WHY THIS EXISTS. `adapters/base.py` had ONE timeout - `_DEFAULT_TIMEOUT_S =
60.0`, shared by every subprocess adapter - and exactly one engine escaped it,
through a single-engine environment variable (`SKILLSCAN_LLM_ENGINE_TIMEOUT_S`,
read in `main.py`, threaded to `adapters/aig.py` as `timeout_s=`). That is not
a configuration scheme, it is one special case, and `apps/monolith/worker.py`
was already paying for it: aig-mcp-scan had to be dropped from the set of
sandbox engines the gate waits for, with the comment naming the real fix as
"per-engine timeouts, not a bigger global one".

SHAPE. Two variables, read by the engine-runner process only:

    SKILLSCAN_ENGINE_TIMEOUT_S      the global default (60.0)
    SKILLSCAN_ENGINE_TIMEOUTS_JSON  {"<engine name>": <seconds>, ...} overrides

Keys are the engine's real `EngineMetadata.name` - the SAME namespace as
`SANDBOX_ENGINE_NAMES`, every finding's `engine` field, the admin toggle and
the lock-key conversion in `common.engine_names`. A JSON object was chosen over
per-engine env vars (`SKILLSCAN_ENGINE_TIMEOUT_AIG_MCP_SCAN`) precisely to
avoid that: an env-var spelling would be a FOURTH namespace for these five
names, needing its own name<->name conversion, which is the defect class
milestone C Task 2 just finished removing. It also follows this repo's own
precedent for a structured setting, `SKILLSCAN_M2M_GRANTS_JSON`
(`apps/monolith/config.py`), including its fail-closed parse.

PRECEDENCE. explicit per-engine override > built-in per-engine default >
global default. So raising the global default does not silently lower
aig-mcp-scan (whose built-in 240s exists for a stated reason - see
`BUILTIN_ENGINE_TIMEOUT_S` below), and an operator who wants one engine changed
does not have to restate the other four.

FAIL-CLOSED (this whole module raises rather than defaults). A timeout that
silently reverts to 60s is indistinguishable, from outside, from one that was
applied - the engine just reports TIMEOUT and the operator concludes the engine
is broken rather than that their configuration never took effect. So: a
non-numeric value, a non-positive/non-finite one, a JSON document that is not
an object, and a key that is not a real engine name are all
`EngineTimeoutConfigError` at process startup. Same posture as
`config._parse_m2m_grants`; the opposite of `main._float_setting`, which
log-and-defaults (fine for a poll interval, not for a value that decides
whether an engine can finish).
"""

from __future__ import annotations

import json
import math
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final

from common.log import get_logger

_logger = get_logger("skillscan.engine_runner.timeouts")

__all__ = [
    "BUILTIN_ENGINE_TIMEOUT_S",
    "DEFAULT_ENGINE_TIMEOUT_S",
    "GLOBAL_TIMEOUT_ENV",
    "LEGACY_LLM_TIMEOUT_ENV",
    "PER_ENGINE_TIMEOUT_ENV",
    "EngineTimeoutConfigError",
    "EngineTimeouts",
]

GLOBAL_TIMEOUT_ENV: Final = "SKILLSCAN_ENGINE_TIMEOUT_S"
PER_ENGINE_TIMEOUT_ENV: Final = "SKILLSCAN_ENGINE_TIMEOUTS_JSON"
# Superseded by the two above, still honoured - see `_apply_legacy_llm_timeout`.
LEGACY_LLM_TIMEOUT_ENV: Final = "SKILLSCAN_LLM_ENGINE_TIMEOUT_S"

# The value `adapters/base.py` has always used, unchanged: tuned for a single
# regex/AST pass (bandit, yara, osv-scanner) and now the fallback for any engine
# with neither an override nor a built-in default of its own.
DEFAULT_ENGINE_TIMEOUT_S: Final = 60.0

_AIG_ENGINE_NAME: Final = "aig-mcp-scan"

# Per-engine defaults that are a property of the ENGINE, not of a deployment,
# and therefore ship in code rather than in a ConfigMap. aig-mcp-scan runs a
# multi-turn LLM agent loop (tool calls, file reads, reasoning); 60s truncates a
# real run mid-reasoning on anything but a trivial target. 240s was already its
# effective default via `SKILLSCAN_LLM_ENGINE_TIMEOUT_S`'s own default value, so
# this table is not a behaviour change - it is that default moved somewhere a
# second engine can join it without a second environment variable.
BUILTIN_ENGINE_TIMEOUT_S: Final[Mapping[str, float]] = MappingProxyType({_AIG_ENGINE_NAME: 240.0})


class EngineTimeoutConfigError(ValueError):
    """A timeout setting that must stop the process rather than be defaulted."""


@dataclass(frozen=True)
class EngineTimeouts:
    """Resolved subprocess timeout per engine. Construct via `from_env`."""

    default_s: float = DEFAULT_ENGINE_TIMEOUT_S
    per_engine_s: Mapping[str, float] = field(default=BUILTIN_ENGINE_TIMEOUT_S)

    def for_engine(self, name: str) -> float:
        """Seconds this engine's subprocess gets. Deliberately NOT raising on an
        unknown name: this answers "how long may it run", and the fail-closed
        answer to that question for something we do not recognise is the default,
        not a crash inside a scan. Unknown names are rejected where they are
        CONFIGURED instead (`from_env`), which is the point where a typo is
        still an operator's mistake rather than a running engine's."""
        return self.per_engine_s.get(name, self.default_s)

    def total_budget_s(self, engine_names: Iterable[str]) -> float:
        """Worst-case wall clock for one scan job's engines.

        SUM, not max: `engine_runner.worker._dispatch_engines` runs the engines
        SEQUENTIALLY against one shared `deadline_epoch`, and `base.py` clamps
        each engine's timeout down to the budget REMAINING at the moment its
        turn comes up. So an early engine with a large timeout does not overrun
        the deadline - it silently takes the later engines' share, and the last
        one can get "deadline already passed" without ever spawning. Comparing
        this sum against the deployment's `SKILLSCAN_SCAN_DEADLINE_S` is the
        only way an operator sees that coming (`main.py` logs it at startup)."""
        return math.fsum(self.for_engine(name) for name in engine_names)

    @classmethod
    def from_env(cls, env: Mapping[str, str], *, known_engines: Collection[str]) -> EngineTimeouts:
        """Parse the two settings (plus the legacy one). Raises
        `EngineTimeoutConfigError` on anything it cannot apply exactly as
        written; see the module docstring for why nothing here defaults."""
        raw_default = _setting(env, GLOBAL_TIMEOUT_ENV)
        default_s = (
            DEFAULT_ENGINE_TIMEOUT_S
            if raw_default is None
            else _parse_seconds(raw_default, source=GLOBAL_TIMEOUT_ENV)
        )
        per_engine: dict[str, float] = dict(BUILTIN_ENGINE_TIMEOUT_S)
        overrides = _parse_overrides(_setting(env, PER_ENGINE_TIMEOUT_ENV), known_engines)
        per_engine.update(overrides)
        _apply_legacy_llm_timeout(env, per_engine=per_engine, overrides=overrides)
        return cls(default_s=default_s, per_engine_s=MappingProxyType(per_engine))


def _setting(env: Mapping[str, str], key: str) -> str | None:
    """An empty value means "unset", not "invalid".

    A Helm ConfigMap key with no value renders as `""` and a `secretKeyRef` with
    `optional: true` can too, so treating empty as a parse error would make the
    chart's own default rendering crash the pod - the exact failure the
    placeholder-FQDN incident in `values.yaml` is a comment about."""
    raw = env.get(key, "")
    stripped = raw.strip()
    return stripped or None


def _parse_seconds(raw: str, *, source: str) -> float:
    try:
        value = float(raw)
    except ValueError as exc:
        raise EngineTimeoutConfigError(f"{source}: {raw!r} is not a number") from exc
    return _checked_seconds(value, source=source)


def _checked_seconds(value: float, *, source: str) -> float:
    if not math.isfinite(value):
        raise EngineTimeoutConfigError(f"{source}: {value!r} is not a finite number of seconds")
    if value <= 0:
        # Zero or negative reaches `subprocess.run(timeout=...)` as an instant
        # expiry, i.e. every scan reports TIMEOUT with no work done - a way to
        # disable an engine that leaves no trace of having been configured. The
        # supported way to switch an engine off is the admin toggle
        # (`common.engine_toggle`), which is visible in the console.
        raise EngineTimeoutConfigError(f"{source}: timeout must be > 0, got {value!r}")
    return value


def _parse_overrides(raw: str | None, known_engines: Collection[str]) -> dict[str, float]:
    if raw is None:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise EngineTimeoutConfigError(
            f"{PER_ENGINE_TIMEOUT_ENV} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(parsed, dict):
        raise EngineTimeoutConfigError(
            f"{PER_ENGINE_TIMEOUT_ENV} must be a JSON object of engine name -> seconds, "
            f"got {type(parsed).__name__}"
        )
    overrides: dict[str, float] = {}
    for name, value in parsed.items():
        if name not in known_engines:
            # A misspelled key that was accepted would be a setting that reads
            # as applied and does nothing - the failure mode this module exists
            # to prevent. The names are exactly the ones findings, the admin
            # toggle and the dashboard already use.
            raise EngineTimeoutConfigError(
                f"{PER_ENGINE_TIMEOUT_ENV}: {name!r} is not an engine of this service. "
                f"Known engines: {', '.join(sorted(known_engines))}"
            )
        # `isinstance(True, int)` is True, so bools have to be excluded by hand;
        # `{"bandit": true}` is a configuration mistake, not a 1-second timeout.
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise EngineTimeoutConfigError(
                f"{PER_ENGINE_TIMEOUT_ENV}: {name!r} must be a number of seconds, got {value!r}"
            )
        overrides[name] = _checked_seconds(float(value), source=f"{PER_ENGINE_TIMEOUT_ENV}[{name}]")
    return overrides


def _apply_legacy_llm_timeout(
    env: Mapping[str, str], *, per_engine: dict[str, float], overrides: Mapping[str, float]
) -> None:
    """`SKILLSCAN_LLM_ENGINE_TIMEOUT_S` keeps working, loudly.

    DECISION (Task 4): honour it, do not ignore it, do not reject it. A
    deployment that set it did so to stop aig-mcp-scan being cut off mid-run;
    ignoring the variable would revert that deployment to 60s - a REGRESSION
    caused by a refactor, announced by nothing but engines timing out. Rejecting
    it at startup would be honest but turns an upgrade into an outage for a
    variable whose replacement is a strict superset of it. So it is applied and
    a deprecation warning names its replacement.

    The one case that IS refused is both variables naming aig-mcp-scan with
    DIFFERENT values: there is no reading of that which is not somebody's
    mistake, and silently picking a winner would hide it."""
    raw = _setting(env, LEGACY_LLM_TIMEOUT_ENV)
    if raw is None:
        return
    legacy_s = _parse_seconds(raw, source=LEGACY_LLM_TIMEOUT_ENV)
    explicit = overrides.get(_AIG_ENGINE_NAME)
    if explicit is not None and explicit != legacy_s:
        raise EngineTimeoutConfigError(
            f"{LEGACY_LLM_TIMEOUT_ENV}={legacy_s} conflicts with "
            f"{PER_ENGINE_TIMEOUT_ENV}[{_AIG_ENGINE_NAME!r}]={explicit}. Remove the deprecated "
            f"{LEGACY_LLM_TIMEOUT_ENV} - {PER_ENGINE_TIMEOUT_ENV} replaces it for every engine."
        )
    per_engine[_AIG_ENGINE_NAME] = legacy_s
    _logger.warning(
        f"{LEGACY_LLM_TIMEOUT_ENV} is deprecated and still applied - "
        f"{PER_ENGINE_TIMEOUT_ENV} replaces it and can set any engine's timeout",
        extra={
            "context": {
                "metric": "engine_timeout_legacy_env_used",
                "engine": _AIG_ENGINE_NAME,
                "timeout_s": legacy_s,
                "replacement": f'{PER_ENGINE_TIMEOUT_ENV}={{"{_AIG_ENGINE_NAME}": {legacy_s}}}',
            }
        },
    )
