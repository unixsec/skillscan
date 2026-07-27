"""Tests for `engine_runner.adapters.aig` (coding spec §10) - MCP-01..04, PROMPT-05.

No real `mcp-scan` run is exercised here: unlike bandit/yara/osv-scanner,
there is no way to invoke it without a live, billed LLM API call (`main.py`
`sys.exit(1)`s before touching a target directory without one) - so
`TestParseStderr` below exercises `parse_stderr` against a REAL captured
example, not a constructed one: the exact `<vuln>...</vuln>` text embedded
in `vendor/aig/mcp-scan/utils/extract_vuln.py`'s own `if __name__ ==
"__main__":` block (that module's author's own worked example of their
tool's real output, including the surrounding loguru log lines and trailing
prose a real run also produces) - proving this adapter's independently
re-implemented regex parser (INV-15: never imports vendored source) agrees
with the vendored tool's own parser on the same real bytes.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from common.config import require_internal_endpoint
from engine_runner.adapters import aig
from skillscan_core import DetectionCategory, EngineCapability, Severity

# Verbatim from vendor/aig/mcp-scan/utils/extract_vuln.py's own __main__
# block (the tool author's worked example of real output) - two <vuln>
# blocks (Command Injection/High, Credential Theft/Medium) plus the
# surrounding loguru-style log lines and trailing risk-recalibration prose a
# real run also emits, confirming the parser tolerates realistic noise
# around the tags it actually cares about.
_REAL_CAPTURED_EXAMPLE = """
2
2025-11-12 18:52:19.481 | INFO     | agent.base_agent:run:132 - Agent execution completed
2025-11-12 18:52:19.481 | INFO     | __main__:main:36 - Agent completed successfully:

 <vuln>
  <title>命令注入漏洞 - executeCohoCommand函数</title>
  <desc>
  ## 漏洞详情
  **文件位置**: src/index.ts 第168-193行
  **漏洞类型**: Command Injection
  攻击者可通过以下工具注入恶意命令
  </desc>
  <risk_type>Command Injection</risk_type>
  <level>High</level>
  <suggestion>
  ## 修复建议
  使用execFile替代exec
  </suggestion>
</vuln>

<vuln>
  <title>认证令牌泄露风险</title>
  <desc>
  ## 漏洞详情
  **文件位置**: src/index.ts 第172行
  **漏洞类型**: Credential Theft
  adminToken作为命令行参数传递，可能被系统进程监控工具捕获
  </desc>
  <risk_type>Credential Theft</risk_type>
  <level>Medium</level>
  <suggestion>
  使用环境变量传递敏感凭据
  </suggestion>
</vuln>

## 漏洞复现验证结果
经过对Codehooks.io MCP服务器的代码审计和漏洞复现，确认以下关键发现：
Process finished with exit code 0
"""


class TestParseStderr:
    def test_extracts_both_real_captured_blocks(self) -> None:
        findings = aig.parse_stderr(_REAL_CAPTURED_EXAMPLE.encode("utf-8"))
        assert len(findings) == 2

    def test_command_injection_block_maps_to_code_01(self) -> None:
        findings = aig.parse_stderr(_REAL_CAPTURED_EXAMPLE.encode("utf-8"))
        cmd_inj = next(f for f in findings if "命令注入" in f.title)
        assert cmd_inj.test_item_id == "CODE-01"
        assert cmd_inj.category == DetectionCategory.CODE
        assert cmd_inj.severity == Severity.HIGH
        assert cmd_inj.source_engine == "aig-mcp-scan"
        assert cmd_inj.source_capability == EngineCapability.SEMANTIC_LLM
        assert cmd_inj.confidence < 0.7  # SECURITY: LLM-judgment findings stay below
        # this codebase's deterministic-detector confidence floor - see
        # aig.py's own comment on this.

    def test_credential_theft_block_maps_to_cred_04(self) -> None:
        findings = aig.parse_stderr(_REAL_CAPTURED_EXAMPLE.encode("utf-8"))
        cred = next(f for f in findings if "令牌" in f.title)
        assert cred.test_item_id == "CRED-04"
        assert cred.category == DetectionCategory.DATA_CREDENTIAL
        assert cred.severity == Severity.MEDIUM

    def test_no_vuln_blocks_yields_empty_tuple(self) -> None:
        assert aig.parse_stderr(b"2026-01-01 | INFO | nothing to see here") == ()

    def test_incomplete_block_is_skipped_not_fatal(self) -> None:
        text = "<vuln><title>only a title, no desc or risk_type</title></vuln>"
        assert aig.parse_stderr(text.encode("utf-8")) == ()

    def test_unrecognized_level_defaults_to_medium(self) -> None:
        text = (
            "<vuln><title>t</title><desc>d</desc>"
            "<risk_type>obscure category</risk_type><level>Unknown</level></vuln>"
        )
        findings = aig.parse_stderr(text.encode("utf-8"))
        assert findings[0].severity == Severity.MEDIUM

    def test_unmatched_risk_type_falls_back_to_gen_01(self) -> None:
        # SECURITY: GEN-01 is the checklist's own designated catch-all for
        # LLM-generalized findings (D10) - confirming the fallback actually
        # fires for genuinely uncategorizable content, not just documented.
        text = (
            "<vuln><title>something oddly specific</title>"
            "<desc>d</desc><risk_type>Bizarre Unprecedented Category</risk_type>"
            "<level>Low</level></vuln>"
        )
        findings = aig.parse_stderr(text.encode("utf-8"))
        assert findings[0].test_item_id == "GEN-01"


class TestClassify:
    @pytest.mark.parametrize(
        ("risk_type", "title", "expected_id"),
        [
            ("Tool Poisoning", "hidden instruction in tool description", "MCP-01"),
            ("", "服务器 impersonation of a popular MCP server", "MCP-02"),
            ("Cross-Server Escalation", "", "MCP-03"),
            ("Server Config", "missing TLS enforcement", "MCP-04"),
            ("", "行为与描述不符: claims read-only but writes files", "PROMPT-05"),
            ("Credential Theft", "", "CRED-04"),
            ("Command Injection", "", "CODE-01"),
            ("Insecure Deserialization", "", "CODE-07"),
            ("Path Traversal", "", "FILE-04"),
            ("SSRF", "", "NET-06"),
            ("Data Exfiltration", "", "NET-04"),
        ],
    )
    def test_keyword_mapping(self, risk_type: str, title: str, expected_id: str) -> None:
        test_item_id, _category = aig._classify(risk_type, title)
        assert test_item_id == expected_id

    def test_case_insensitive(self) -> None:
        test_item_id, _category = aig._classify("COMMAND INJECTION", "")
        assert test_item_id == "CODE-01"


class TestMakeAdapter:
    def test_metadata_marks_llm_required(self) -> None:
        adapter = aig.make_adapter(
            openai_base_url="http://localhost:11434/v1",
            ruleset_digest="test-digest",
            version="v4.1.15",
        )
        assert adapter.metadata.name == "aig-mcp-scan"
        assert adapter.metadata.requires_llm is True
        assert EngineCapability.SEMANTIC_LLM in adapter.metadata.capabilities

    def test_rejects_external_endpoint(self) -> None:
        # SECURITY (INV-14): mirrors skillspector.py's own enforcement -
        # confirming aig.py actually calls require_internal_endpoint, not
        # just documents that it should.
        with pytest.raises(ValueError, match="INV-14"):
            aig.make_adapter(
                openai_base_url="https://api.openai.com/v1",
                ruleset_digest="test-digest",
                version="v4.1.15",
            )

    def test_placeholder_api_key_used_when_none_provided(self) -> None:
        # SECURITY: the placeholder must still land in the subprocess env
        # (OPENROUTER_API_KEY) when no real api_key is supplied - same
        # no-auth-vLLM default behavior as before, just delivered via env
        # instead of argv now. See TestApiKeyEnv below for the full argv/env
        # regression coverage of this fix.
        adapter = aig.make_adapter(
            openai_base_url="http://localhost:11434/v1",
            ruleset_digest="test-digest",
            version="v4.1.15",
        )
        env_fn = adapter._env  # noqa: SLF001 - white-box test
        assert callable(env_fn)
        env = env_fn()
        assert env is not None
        assert env["OPENROUTER_API_KEY"] == aig._PLACEHOLDER_API_KEY
        argv = adapter._build_argv(Path("/tmp/fake-target"))  # noqa: SLF001 - white-box test
        assert "--api_key" not in argv

    def test_run_in_target_dir_enabled(self) -> None:
        # SECURITY: confirms the readOnlyRootFilesystem workaround (base.py's
        # `run_in_target_dir`) is actually wired for this adapter, not just
        # explained in a comment - see aig.py's own note on why.
        adapter = aig.make_adapter(
            openai_base_url="http://localhost:11434/v1",
            ruleset_digest="test-digest",
            version="v4.1.15",
        )
        assert adapter._run_in_target_dir is True  # noqa: SLF001 - white-box test


class TestApiKeyEnv:
    """SECURITY regression (2026-07-10): the LLM API key must reach the
    mcp-scan subprocess via `OPENROUTER_API_KEY` in `env`, never via
    `--api_key` in argv - argv is readable by any local process/user via
    `ps aux`/`/proc/<pid>/cmdline`, while `env` is not. Confirmed real target
    env var by reading `vendor/aig/mcp-scan/main.py`'s own arg handling
    (`api_key = args.api_key or os.environ.get("OPENROUTER_API_KEY")`) -
    mirrors skillspector.py's `test_api_key_sets_openai_api_key_env`/
    `test_no_api_key_env_when_none_provided`/
    `test_env_carries_path_so_the_binary_can_be_found` conventions.
    """

    def test_provided_api_key_lands_in_env_not_argv(self) -> None:
        adapter = aig.make_adapter(
            openai_base_url="http://localhost:11434/v1",
            ruleset_digest="test-digest",
            version="v4.1.15",
            api_key="sk-test-not-a-real-key",
        )
        env_fn = adapter._env  # noqa: SLF001 - white-box test
        assert callable(env_fn)
        env = env_fn()
        assert env is not None
        assert env["OPENROUTER_API_KEY"] == "sk-test-not-a-real-key"

        argv = adapter._build_argv(Path("/tmp/fake-target"))  # noqa: SLF001 - white-box test
        assert "--api_key" not in argv
        assert "sk-test-not-a-real-key" not in argv

    def test_no_api_key_falls_back_to_placeholder_in_env(self) -> None:
        # CORRECTNESS: `api_key: str | None = None` contract preserved - the
        # existing no-auth-vLLM placeholder default still applies, just
        # delivered via env instead of argv.
        adapter = aig.make_adapter(
            openai_base_url="http://localhost:11434/v1",
            ruleset_digest="test-digest",
            version="v4.1.15",
        )
        env_fn = adapter._env  # noqa: SLF001 - white-box test
        assert callable(env_fn)
        env = env_fn()
        assert env is not None
        assert env["OPENROUTER_API_KEY"] == aig._PLACEHOLDER_API_KEY

        argv = adapter._build_argv(Path("/tmp/fake-target"))  # noqa: SLF001 - white-box test
        assert "--api_key" not in argv
        assert aig._PLACEHOLDER_API_KEY not in argv

    def test_env_carries_path_so_the_binary_can_be_found(self) -> None:
        # CORRECTNESS: `subprocess.run(..., env=X)` REPLACES the child's
        # entire environment (see base.py's `analyze()` -> `env=self._env`)
        # - an env dict with no PATH key would break PATH-dependent behavior
        # inside mcp-scan's own dependencies even though the interpreter/
        # script paths here are absolute. Same PATH-loss bug class as
        # skillspector.py's own `test_env_carries_path_so_the_binary_can_be_found`
        # regression.
        import os

        adapter = aig.make_adapter(
            openai_base_url="http://localhost:11434/v1",
            ruleset_digest="test-digest",
            version="v4.1.15",
            api_key="sk-test-not-a-real-key",
        )
        env_fn = adapter._env  # noqa: SLF001 - white-box test
        assert callable(env_fn)
        env = env_fn()
        assert env is not None
        assert env["PATH"] == os.environ.get("PATH", "")
        assert env["PATH"]  # not empty - a blank PATH is just as unusable as a missing one


class TestSpecializedLlmRolesRoutedInternally:
    """SECURITY regression (INV-14, found live 2026-07-15): `--base_url`/
    `--model`/`OPENROUTER_API_KEY` only ever configured mcp-scan's "default"
    LLM role. `utils/llm_manager.py`'s "thinking"/"coding"/"fast" roles each
    fall back independently to their own `THINKING_*`/`CODING_*`/`FAST_*` env
    var (utils/config.py), defaulting to a real public OpenRouter model
    (google/gemini-2.5-pro, anthropic/claude-sonnet-4.5,
    google/gemini-2.0-flash-exp) when unset - confirmed live against a real
    deployed engine-runner pod: 3 of mcp-scan's 4 LLM roles silently targeted
    openrouter.ai regardless of the configured internal endpoint, blocked
    only incidentally by this deployment's NetworkPolicy egress-allowlist,
    not by the adapter itself."""

    def test_thinking_coding_fast_roles_use_same_internal_endpoint(self) -> None:
        adapter = aig.make_adapter(
            openai_base_url="http://localhost:11434/v1",
            ruleset_digest="test-digest",
            version="v4.1.15",
            model="internal-model-name",
            api_key="sk-test-not-a-real-key",
        )
        env_fn = adapter._env  # noqa: SLF001 - white-box test
        # `SubprocessEngineAdapter.env` accepts a static dict OR a callable; aig
        # deliberately passes the callable `_build_env` so the env is rebuilt on
        # every subprocess spawn. Assert that shape before calling it.
        assert callable(env_fn)
        env = env_fn()
        assert env is not None
        for role in ("THINKING", "CODING", "FAST"):
            assert env[f"{role}_BASE_URL"] == "http://localhost:11434/v1"
            assert env[f"{role}_MODEL"] == "internal-model-name"
            assert env[f"{role}_API_KEY"] == "sk-test-not-a-real-key"
        # BE-4 (2026-07-22 review): the master DEFAULT_* fallbacks must be
        # pinned too. config.py resolves any unset role BASE_URL to
        # DEFAULT_BASE_URL, which itself defaults to a real openrouter.ai URL
        # and would win in LLMManager.get_llm("default"); per INV-14 the
        # adapter must not leave that pointing outward.
        assert env["DEFAULT_BASE_URL"] == "http://localhost:11434/v1"
        assert env["DEFAULT_MODEL"] == "internal-model-name"

    def test_thinking_coding_fast_roles_get_placeholder_key_when_none_provided(self) -> None:
        adapter = aig.make_adapter(
            openai_base_url="http://localhost:11434/v1",
            ruleset_digest="test-digest",
            version="v4.1.15",
        )
        env_fn = adapter._env  # noqa: SLF001 - white-box test
        # `SubprocessEngineAdapter.env` accepts a static dict OR a callable; aig
        # deliberately passes the callable `_build_env` so the env is rebuilt on
        # every subprocess spawn. Assert that shape before calling it.
        assert callable(env_fn)
        env = env_fn()
        assert env is not None
        for role in ("THINKING", "CODING", "FAST"):
            assert env[f"{role}_API_KEY"] == aig._PLACEHOLDER_API_KEY


def test_require_internal_endpoint_still_enforced_directly() -> None:
    # Sanity check that this test file's assumption about require_internal_endpoint's
    # error message ("INV-14") hasn't drifted from common.config's real text.
    with pytest.raises(ValueError, match="INV-14"):
        require_internal_endpoint("https://example.com", field_name="test")
