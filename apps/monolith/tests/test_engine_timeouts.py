"""Per-engine subprocess timeouts (milestone C Task 4, design §4).

Covers three things that used to be one hardcoded number plus one
single-engine environment variable:

  1. `engine_runner.timeouts.EngineTimeouts.from_env` - the config shape, its
     precedence, and the values it REFUSES rather than silently defaults.
  2. that a configured timeout actually reaches `subprocess.run(timeout=...)`
     for EVERY engine in the real registry - parametrized over
     `SANDBOX_ENGINE_NAMES`, so an engine added later without a timeout wired
     through `sandbox_engines()` fails here rather than quietly running on the
     60s default.
  3. `monolith.worker._active_sandbox_waited_engines` - which of the waited
     tier a given deployment can actually wait for, now that `aig-mcp-scan` is
     a full member of `SANDBOX_WAITED_ENGINE_NAMES` instead of being excluded
     by name.

PURE: no MySQL, no Redis, no network, no engine binary. `sandbox_engines()`
only constructs adapters, and the one place a subprocess would be spawned is
monkeypatched here to record its `timeout=` and return. Uses none of
`conftest.py`'s (opt-in) infrastructure fixtures.
"""

from __future__ import annotations

import logging
import subprocess
from typing import Any

import pytest
from engine_runner.sandbox_engines import (
    SANDBOX_ENGINE_NAMES,
    llm_gated_engine_names,
    sandbox_engines,
)
from engine_runner.timeouts import (
    BUILTIN_ENGINE_TIMEOUT_S,
    DEFAULT_ENGINE_TIMEOUT_S,
    GLOBAL_TIMEOUT_ENV,
    LEGACY_LLM_TIMEOUT_ENV,
    PER_ENGINE_TIMEOUT_ENV,
    EngineTimeoutConfigError,
    EngineTimeouts,
)

from monolith.worker import SANDBOX_WAITED_ENGINE_NAMES, _active_sandbox_waited_engines

# Internal by INV-14's rules and never dialed: constructing the LLM-gated
# adapters is what puts all five engines in the registry under test.
_INTERNAL_LLM_URL = "http://localhost:11434/v1"

_AIG = "aig-mcp-scan"


def _from_env(**env: str) -> EngineTimeouts:
    return EngineTimeouts.from_env(env, known_engines=SANDBOX_ENGINE_NAMES)


class TestDefaultsReproduceThePreviousBehaviour:
    """Nothing configured must mean exactly what the two hardcoded values meant
    before this feature existed - otherwise shipping it is a silent retune of
    every deployment."""

    def test_an_unconfigured_engine_gets_the_former_base_class_default(self) -> None:
        timeouts = _from_env()
        for name in ("bandit", "osv-scanner", "yara", "skillspector"):
            assert timeouts.for_engine(name) == 60.0
        assert DEFAULT_ENGINE_TIMEOUT_S == 60.0

    def test_aig_keeps_its_built_in_240s_without_any_environment_variable(self) -> None:
        # Previously this came from SKILLSCAN_LLM_ENGINE_TIMEOUT_S's own default
        # value, i.e. an engine's default lived in a deployment setting.
        assert _from_env().for_engine(_AIG) == 240.0

    def test_an_unknown_engine_falls_back_rather_than_raising(self) -> None:
        # for_engine() answers "how long may this run"; a crash there would be
        # inside a scan. Unknown NAMES are rejected at configuration time
        # instead - see the from_env tests below.
        assert _from_env().for_engine("not-an-engine") == 60.0


class TestPerEngineOverrides:
    def test_the_global_default_moves_every_engine_without_its_own_value(self) -> None:
        timeouts = _from_env(**{GLOBAL_TIMEOUT_ENV: "12.5"})
        assert timeouts.for_engine("bandit") == 12.5
        assert timeouts.for_engine("yara") == 12.5

    def test_a_built_in_per_engine_default_beats_the_global_default(self) -> None:
        # Raising the global value must not silently LOWER aig-mcp-scan to it.
        assert _from_env(**{GLOBAL_TIMEOUT_ENV: "90"}).for_engine(_AIG) == 240.0

    def test_an_explicit_override_beats_both(self) -> None:
        timeouts = _from_env(
            **{
                GLOBAL_TIMEOUT_ENV: "90",
                PER_ENGINE_TIMEOUT_ENV: '{"bandit": 5, "aig-mcp-scan": 600}',
            }
        )
        assert timeouts.for_engine("bandit") == 5.0
        assert timeouts.for_engine(_AIG) == 600.0
        assert timeouts.for_engine("yara") == 90.0

    def test_an_integer_json_value_is_accepted_as_seconds(self) -> None:
        assert _from_env(**{PER_ENGINE_TIMEOUT_ENV: '{"yara": 30}'}).for_engine("yara") == 30.0

    def test_empty_values_mean_unset_not_invalid(self) -> None:
        # A Helm ConfigMap key with no value renders as "". Treating that as a
        # parse error would crash the pod on the chart's own defaults.
        timeouts = _from_env(**{GLOBAL_TIMEOUT_ENV: "", PER_ENGINE_TIMEOUT_ENV: "  "})
        assert timeouts.for_engine("bandit") == 60.0
        assert timeouts.for_engine(_AIG) == 240.0

    def test_the_sum_of_the_configured_timeouts_is_reported(self) -> None:
        timeouts = _from_env(**{PER_ENGINE_TIMEOUT_ENV: '{"bandit": 10, "yara": 20}'})
        assert timeouts.total_budget_s(("bandit", "yara")) == 30.0


class TestInvalidConfigurationIsRefusedNotDefaulted:
    """Every case here would otherwise be a setting that reads as applied and
    is not. That is the failure this module exists to prevent, so each one must
    stop the process at startup."""

    @pytest.mark.parametrize(
        ("env", "expected_in_message"),
        [
            ({GLOBAL_TIMEOUT_ENV: "soon"}, GLOBAL_TIMEOUT_ENV),
            ({GLOBAL_TIMEOUT_ENV: "0"}, "must be > 0"),
            ({GLOBAL_TIMEOUT_ENV: "-1"}, "must be > 0"),
            ({GLOBAL_TIMEOUT_ENV: "nan"}, "finite"),
            ({GLOBAL_TIMEOUT_ENV: "inf"}, "finite"),
            ({PER_ENGINE_TIMEOUT_ENV: "not json"}, "not valid JSON"),
            ({PER_ENGINE_TIMEOUT_ENV: "[1, 2]"}, "must be a JSON object"),
            ({PER_ENGINE_TIMEOUT_ENV: '{"bandit": "30"}'}, "must be a number"),
            ({PER_ENGINE_TIMEOUT_ENV: '{"bandit": true}'}, "must be a number"),
            ({PER_ENGINE_TIMEOUT_ENV: '{"bandit": 0}'}, "must be > 0"),
            ({PER_ENGINE_TIMEOUT_ENV: '{"bandit": -30}'}, "must be > 0"),
        ],
    )
    def test_refused(self, env: dict[str, str], expected_in_message: str) -> None:
        with pytest.raises(EngineTimeoutConfigError) as excinfo:
            _from_env(**env)
        assert expected_in_message in str(excinfo.value)

    def test_a_misspelled_engine_name_is_refused_and_the_real_names_listed(self) -> None:
        # The whole point of keying by the runtime engine name: `{"osv_scanner":
        # 30}` (the LOCK-FILE spelling - milestone C Task 2's two namespaces)
        # must not be accepted and then apply to nothing.
        with pytest.raises(EngineTimeoutConfigError) as excinfo:
            _from_env(**{PER_ENGINE_TIMEOUT_ENV: '{"osv_scanner": 30}'})
        message = str(excinfo.value)
        assert "osv_scanner" in message
        assert "osv-scanner" in message  # the real name, offered back


class TestTheSupersededSingleEngineVariable:
    """`SKILLSCAN_LLM_ENGINE_TIMEOUT_S` keeps working. A deployment that set it
    did so to stop aig-mcp-scan being cut off mid-run; ignoring it would revert
    that deployment to 60s with nothing to say so."""

    def test_it_still_sets_the_engines_timeout(self) -> None:
        assert _from_env(**{LEGACY_LLM_TIMEOUT_ENV: "480"}).for_engine(_AIG) == 480.0

    def test_using_it_logs_a_deprecation_naming_the_replacement(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="skillscan.engine_runner.timeouts"):
            _from_env(**{LEGACY_LLM_TIMEOUT_ENV: "480"})
        assert any(
            LEGACY_LLM_TIMEOUT_ENV in record.getMessage()
            and PER_ENGINE_TIMEOUT_ENV in record.getMessage()
            for record in caplog.records
        ), "a superseded setting that still works must say so, or it never gets migrated"

    def test_it_is_still_validated_like_any_other_timeout(self) -> None:
        with pytest.raises(EngineTimeoutConfigError):
            _from_env(**{LEGACY_LLM_TIMEOUT_ENV: "-5"})

    def test_agreeing_with_the_new_variable_is_fine(self) -> None:
        timeouts = _from_env(
            **{
                LEGACY_LLM_TIMEOUT_ENV: "480",
                PER_ENGINE_TIMEOUT_ENV: '{"aig-mcp-scan": 480}',
            }
        )
        assert timeouts.for_engine(_AIG) == 480.0

    def test_contradicting_the_new_variable_is_refused(self) -> None:
        # Picking a winner silently would leave one of the two settings inert
        # while both are visibly present in the ConfigMap.
        with pytest.raises(EngineTimeoutConfigError) as excinfo:
            _from_env(
                **{
                    LEGACY_LLM_TIMEOUT_ENV: "480",
                    PER_ENGINE_TIMEOUT_ENV: '{"aig-mcp-scan": 240}',
                }
            )
        assert LEGACY_LLM_TIMEOUT_ENV in str(excinfo.value)
        assert PER_ENGINE_TIMEOUT_ENV in str(excinfo.value)


class TestTheConfiguredTimeoutReachesTheSubprocess:
    """Parametrized over the REAL registry, not a hand-written list: an engine
    added to `SANDBOX_ENGINE_NAMES` whose `make_adapter` never gets a
    `timeout_s=` from `sandbox_engines()` shows up here as "still 60s"."""

    @staticmethod
    def _recorded_timeout(engine_name: str, monkeypatch: pytest.MonkeyPatch) -> float:
        distinct = {name: 100.0 + index for index, name in enumerate(SANDBOX_ENGINE_NAMES)}
        engines = sandbox_engines(
            vllm_base_url=_INTERNAL_LLM_URL,
            engine_timeouts=EngineTimeouts(per_engine_s=distinct),
        )
        assert engine_name in engines, (
            f"{engine_name!r} is in SANDBOX_ENGINE_NAMES but sandbox_engines() did not "
            f"construct it even with an LLM endpoint configured"
        )
        seen: list[float] = []

        def _fake_run(*_args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
            seen.append(kwargs["timeout"])
            return subprocess.CompletedProcess(args=["x"], returncode=0, stdout=b"", stderr=b"")

        # Patched on the module object `base.py` actually calls through, so
        # this measures what the adapter really passes to subprocess.run.
        monkeypatch.setattr(subprocess, "run", _fake_run)
        # No `deadline=`: the shared-budget clamp is base.py's own behaviour and
        # has its own tests; what is under test here is the CONFIGURED value.
        engines[engine_name].analyze({"skill.py": b"print(1)\n"})
        assert len(seen) == 1, f"{engine_name} did not spawn exactly one subprocess"
        return seen[0]

    @pytest.mark.parametrize("engine_name", SANDBOX_ENGINE_NAMES)
    def test_each_engine_runs_with_its_own_configured_timeout(
        self, engine_name: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        expected = 100.0 + SANDBOX_ENGINE_NAMES.index(engine_name)
        assert self._recorded_timeout(engine_name, monkeypatch) == expected, (
            f"{engine_name}'s configured timeout did not reach subprocess.run - check that "
            f"sandbox_engines() passes timeout_s=timeouts.for_engine({engine_name!r}) and that "
            f"the adapter's make_adapter() forwards it"
        )


class TestWhichEnginesThisDeploymentCanWaitFor:
    """`SANDBOX_WAITED_ENGINE_NAMES` is now the whole tier; what a deployment
    actually waits for is narrowed at runtime. Waiting for an engine that
    cannot report costs every scan the full `sandbox_wait_timeout_s` budget."""

    def test_the_waited_constant_is_now_the_whole_advisory_tier(self) -> None:
        # The equality itself is pinned across all six declaration sites by
        # test_engine_tier_registry.py; this states the Task 4 outcome locally,
        # because everything else in this class is about narrowing it again.
        assert _AIG in SANDBOX_WAITED_ENGINE_NAMES

    def test_an_llm_gated_engine_is_waited_for_when_the_endpoint_is_configured(self) -> None:
        active = _active_sandbox_waited_engines(
            disabled_engines=frozenset(), sandbox_llm_configured=True
        )
        assert set(active) == set(SANDBOX_ENGINE_NAMES)

    def test_it_is_dropped_when_no_llm_endpoint_is_configured(self) -> None:
        gated = llm_gated_engine_names()
        assert gated, "llm_gated_engine_names() is empty - this assertion would be vacuous"
        assert _AIG in gated, (
            "aig-mcp-scan is no longer config-gated in sandbox_engines(); if it gained a "
            "static-only mode, the gating filter and its DocumentedOmission both go away"
        )
        active = _active_sandbox_waited_engines(
            disabled_engines=frozenset(), sandbox_llm_configured=False
        )
        assert set(active) == set(SANDBOX_ENGINE_NAMES) - gated

    def test_an_admin_disabled_engine_is_dropped_too(self) -> None:
        active = _active_sandbox_waited_engines(
            disabled_engines=frozenset({"bandit"}), sandbox_llm_configured=True
        )
        assert "bandit" not in active
        assert _AIG in active

    def test_the_two_filters_compose(self) -> None:
        active = _active_sandbox_waited_engines(
            disabled_engines=frozenset({"yara"}), sandbox_llm_configured=False
        )
        assert set(active) == set(SANDBOX_ENGINE_NAMES) - llm_gated_engine_names() - {"yara"}


class TestTheStartupBudgetWarning:
    """The engine-runner runs its engines SEQUENTIALLY against one shared
    deadline, so the sum matters, not the max. Exceeding it does not overrun the
    deadline - it starves whichever engines run last, silently."""

    def test_no_warning_when_the_timeouts_fit(self) -> None:
        from engine_runner.main import _warn_if_timeouts_exceed_scan_budget

        shortfall = _warn_if_timeouts_exceed_scan_budget(
            _from_env(), engine_names=("bandit", "yara"), scan_deadline_s=300.0
        )
        assert shortfall == 0.0

    def test_the_shortfall_is_reported_when_they_do_not(self) -> None:
        from engine_runner.main import _warn_if_timeouts_exceed_scan_budget

        timeouts = _from_env(**{PER_ENGINE_TIMEOUT_ENV: '{"bandit": 280, "yara": 100}'})
        shortfall = _warn_if_timeouts_exceed_scan_budget(
            timeouts, engine_names=("bandit", "yara"), scan_deadline_s=300.0
        )
        assert shortfall == 80.0

    def test_the_shipped_defaults_already_overrun_the_default_deadline(self) -> None:
        # 60*4 + 240 = 480 > 300: the shipped defaults do NOT fit, and that is
        # the pre-existing state this task made visible rather than introduced.
        # Asserted so the number is a decision rather than a surprise - the
        # deadline clamp in base.py is what keeps it safe (each engine is cut
        # down to the remaining budget), and the warning is what tells an
        # operator that aig-mcp-scan, which runs last, is the one that pays.
        timeouts = _from_env()
        assert timeouts.total_budget_s(SANDBOX_ENGINE_NAMES) == 480.0
        assert BUILTIN_ENGINE_TIMEOUT_S[_AIG] == 240.0
