"""Tests for `engine_runner.sandbox_engines` (coding spec §10) - registration/
gating logic only, not any individual adapter's own behavior (see each
adapter's own test_*_adapter.py for that).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from engine_runner.adapters.base import SubprocessEngineAdapter
from engine_runner.sandbox_engines import (
    SANDBOX_ENGINE_NAMES,
    sandbox_engine_names,
    sandbox_engines,
)


class TestAigGating:
    def test_absent_when_no_vllm_base_url(self) -> None:
        # SECURITY: aig-mcp-scan has no static/offline mode (unlike
        # skillspector) - constructing it without a real backend would mean
        # EngineStatus.ERROR on every single scan, indistinguishable from a
        # genuinely broken engine. It must be OMITTED, not constructed-and-
        # erroring, when unconfigured - see sandbox_engines()'s own
        # docstring for the full reasoning.
        engines = sandbox_engines()
        assert "aig-mcp-scan" not in engines

    def test_present_when_vllm_base_url_configured(self) -> None:
        engines = sandbox_engines(vllm_base_url="http://localhost:11434/v1")
        assert "aig-mcp-scan" in engines
        assert engines["aig-mcp-scan"].metadata.requires_llm is True

    def test_name_helper_reflects_same_gating(self) -> None:
        assert "aig-mcp-scan" not in sandbox_engine_names()
        assert "aig-mcp-scan" in sandbox_engine_names(vllm_base_url="http://localhost:11434/v1")


class TestUnaffectedEnginesAlwaysPresent:
    def test_bandit_osv_yara_present_regardless_of_vllm(self) -> None:
        without = sandbox_engines()
        with_llm = sandbox_engines(vllm_base_url="http://localhost:11434/v1")
        for name in ("bandit", "osv-scanner", "yara"):
            assert name in without
            assert name in with_llm

    def test_skillspector_present_either_way_but_aig_is_not(self) -> None:
        # Documents the deliberate asymmetry this session introduced:
        # skillspector degrades gracefully (use_llm=False) without a
        # backend; aig-mcp-scan has no such mode and is omitted instead.
        without = sandbox_engines()
        assert "skillspector" in without
        assert "aig-mcp-scan" not in without


class TestPrivatizedModelThreading:
    """2026-07-09: confirms llm_api_key/llm_model reach both LLM-dependent
    adapters end to end through this function (for an enterprise's own
    internal/privatized model deployment - one that may serve a specific
    named model and/or enforce its own auth), not just that each adapter's
    OWN tests pass them correctly in isolation. INV-14 itself (external
    hosts unconditionally rejected, no allowlist/bypass of any kind) is
    covered by common.config's own tests and by each adapter's
    test_rejects_external_* - not duplicated here."""

    def test_external_vllm_base_url_still_unconditionally_rejected(self) -> None:
        # The single most important regression to guard after the
        # 2026-07-09 allowlist revert: there is no parameter combination
        # that makes an external vllm_base_url work any more.
        with pytest.raises(ValueError, match="INV-14"):
            sandbox_engines(
                vllm_base_url="https://api.deepseek.com/v1",
                llm_api_key="sk-test-not-a-real-key",
                llm_model="some-model",
            )

    def test_internal_vllm_base_url_with_key_and_model_works(self) -> None:
        engines = sandbox_engines(
            vllm_base_url="http://localhost:11434/v1",
            llm_api_key="sk-test-not-a-real-key",
            llm_model="enterprise-internal-model",
        )
        assert "skillspector" in engines
        assert "aig-mcp-scan" in engines

    def test_llm_model_reaches_aig_argv(self) -> None:
        engines = sandbox_engines(
            vllm_base_url="http://localhost:11434/v1",
            llm_api_key="sk-test-not-a-real-key",
            llm_model="enterprise-internal-model",
        )
        aig_engine = engines["aig-mcp-scan"]
        assert isinstance(
            aig_engine, SubprocessEngineAdapter
        )  # white-box test, see class docstring
        argv = aig_engine._build_argv(Path("/tmp/fake"))  # noqa: SLF001
        assert "enterprise-internal-model" in argv

    def test_llm_model_none_falls_back_to_generic_default(self) -> None:
        # Operator hasn't set a model name - aig.py's own default kicks in
        # rather than passing "None" as argv.
        engines = sandbox_engines(vllm_base_url="http://localhost:11434/v1")
        aig_engine = engines["aig-mcp-scan"]
        assert isinstance(aig_engine, SubprocessEngineAdapter)
        argv = aig_engine._build_argv(Path("/tmp/fake"))  # noqa: SLF001
        assert "None" not in argv

    def test_llm_api_key_reaches_skillspector_env(self) -> None:
        engines = sandbox_engines(
            vllm_base_url="http://localhost:11434/v1", llm_api_key="sk-test-not-a-real-key"
        )
        skillspector_engine = engines["skillspector"]
        assert isinstance(skillspector_engine, SubprocessEngineAdapter)
        # SECURITY (Finding #16): _env is now a callable, re-validated and
        # rebuilt on every subprocess spawn rather than a static dict fixed
        # at construction time - see skillspector.py's make_adapter().
        env_fn = skillspector_engine._env  # noqa: SLF001
        assert callable(env_fn)
        env = env_fn()
        assert env["OPENAI_API_KEY"] == "sk-test-not-a-real-key"


class TestSandboxEngineNamesSingleSourceOfTruth:
    """Regression coverage for the class of bug where `apps/monolith/worker.py`'s
    `SANDBOX_ADVISORY_ENGINE_NAMES` (aggregation-only: this process has no
    adapter instance for any of these, it only reads back finding blobs the
    engine-runner service already wrote) was a hand-maintained, independent
    copy of "every engine name engine-runner can produce" - it silently
    dropped aig-mcp-scan (the engine-runner's 5th adapter, added after that
    tuple was first written) until it was switched to import
    `SANDBOX_ENGINE_NAMES` directly from this module instead.

    These tests are deliberately DB/Redis-free (unlike
    `test_worker.py::test_sandbox_engine_finding_is_aggregated_but_never_
    dispatched_here`, which proves the SAME fix end-to-end through a real
    worker tick + real aggregation) so this specific invariant - "the
    monolith's aggregation allowlist has not drifted from engine-runner's
    real adapter registry" - can be checked fast, in any environment, without
    standing up local MySQL/Redis first."""

    def test_worker_constant_equals_the_source_of_truth(self) -> None:
        # apps/monolith is importable here (co-located in the same package,
        # `orchestration/service.py` and `orchestration/floor.py` already
        # import from `engine_runner` directly) - this is a direct identity
        # check, not a re-typed copy that could itself drift.
        from monolith.worker import SANDBOX_ADVISORY_ENGINE_NAMES

        assert SANDBOX_ADVISORY_ENGINE_NAMES == SANDBOX_ENGINE_NAMES

    def test_worker_constant_matches_every_real_adapter_name(self) -> None:
        # The strongest form of this check: compare against the REAL
        # registry's constructed adapter names (with an internal vllm_base_url
        # configured, so all 5 - including the otherwise config-gated
        # aig-mcp-scan - actually construct), not just against the other
        # hardcoded constant. If a 6th adapter is ever added to
        # services/engine_runner/adapters/ and wired into `sandbox_engines()`
        # but `SANDBOX_ENGINE_NAMES` above is forgotten, THIS assertion is the
        # one that fails loudly.
        from monolith.worker import SANDBOX_ADVISORY_ENGINE_NAMES

        real_names = frozenset(sandbox_engines(vllm_base_url="http://localhost:11434/v1").keys())
        assert frozenset(SANDBOX_ADVISORY_ENGINE_NAMES) == real_names

    def test_aig_mcp_scan_is_present(self) -> None:
        # The exact regression: aig-mcp-scan (services/engine_runner/adapters/
        # aig.py) must be in the aggregation allowlist. Prior to the fix this
        # assertion failed - aig-mcp-scan's findings were computed and
        # blob-written by engine-runner but never read back into any verdict.
        from monolith.worker import SANDBOX_ADVISORY_ENGINE_NAMES

        assert "aig-mcp-scan" in SANDBOX_ADVISORY_ENGINE_NAMES
