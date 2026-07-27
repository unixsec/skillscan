"""Tests for `engine_runner.adapters.skillspector` (coding spec §10) → mostly
Cat-1..6.

Exercises `parse_sarif`/`parse_output` against a representative SARIF 2.1.0
payload (confirmed by reading `vendor/skillspector/sarif_models.py`/`cli.py`
directly) and `make_adapter`'s INV-14 internal-endpoint enforcement. No real
skillspector binary/LLM endpoint is available in this environment - this is a
schema-based parsing test only (same honest posture as the module's own
documented OSV-lookup gap).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from engine_runner.adapters import skillspector
from skillscan_core import DetectionCategory, EngineCapability, Severity


def _sarif_result(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "ruleId": "prompt-injection-detected",
        "level": "error",
        "message": {"text": "possible prompt injection in SKILL.md"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "SKILL.md"},
                    "region": {"startLine": 7},
                }
            }
        ],
    }
    base.update(overrides)
    return base


def _sarif(*, results: list[dict[str, object]] | None = None) -> bytes:
    results = results if results is not None else [_sarif_result()]
    payload = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "skillspector", "version": "0.1.0", "rules": []}},
                "results": results,
            }
        ],
    }
    return json.dumps(payload).encode()


class TestParseSarif:
    def test_single_result_parsed(self) -> None:
        findings = skillspector.parse_sarif(_sarif())
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "skillspector.prompt-injection-detected"
        assert f.category is DetectionCategory.INSTRUCTION
        assert f.severity is Severity.HIGH
        assert f.file_path == "SKILL.md"
        assert f.start_line == 7
        assert f.source_engine == "skillspector"

    def test_no_results_yields_no_findings(self) -> None:
        assert skillspector.parse_sarif(_sarif(results=[])) == ()

    def test_missing_runs_key_raises(self) -> None:
        with pytest.raises(ValueError, match="runs"):
            skillspector.parse_sarif(json.dumps({"version": "2.1.0"}).encode())

    def test_missing_locations_yields_none_file_path_and_line(self) -> None:
        result = _sarif_result()
        del result["locations"]
        findings = skillspector.parse_sarif(_sarif(results=[result]))
        assert findings[0].file_path is None
        assert findings[0].start_line is None

    def test_snippet_hash_none_when_message_empty(self) -> None:
        result = _sarif_result(message={"text": ""})
        findings = skillspector.parse_sarif(_sarif(results=[result]))
        assert findings[0].snippet_hash is None

    def test_snippet_hash_set_when_message_present(self) -> None:
        findings = skillspector.parse_sarif(_sarif())
        assert findings[0].snippet_hash is not None
        assert len(findings[0].snippet_hash) == 64

    @pytest.mark.parametrize(
        ("level", "expected"),
        [("error", Severity.HIGH), ("warning", Severity.MEDIUM), ("note", Severity.LOW)],
    )
    def test_level_to_severity_mapping(self, level: str, expected: Severity) -> None:
        findings = skillspector.parse_sarif(_sarif(results=[_sarif_result(level=level)]))
        assert findings[0].severity is expected

    def test_unmapped_level_defaults_to_medium(self) -> None:
        findings = skillspector.parse_sarif(_sarif(results=[_sarif_result(level="unknown")]))
        assert findings[0].severity is Severity.MEDIUM

    @pytest.mark.parametrize(
        ("rule_id", "expected"),
        [
            ("prompt-injection-detected", DetectionCategory.INSTRUCTION),
            ("hardcoded-credential", DetectionCategory.DATA_CREDENTIAL),
            ("secret-leak", DetectionCategory.DATA_CREDENTIAL),
            ("network-exfil-risk", DetectionCategory.NETWORK_INTEL),
            ("data-exfiltration", DetectionCategory.NETWORK_INTEL),
            ("excess-permission-request", DetectionCategory.PERMISSION),
            ("privilege-escalation", DetectionCategory.PERMISSION),
            ("sandbox-escape-attempt", DetectionCategory.PERMISSION),
            ("supply-chain-risk", DetectionCategory.SUPPLY_CHAIN),
            ("dependency-confusion", DetectionCategory.SUPPLY_CHAIN),
            ("some-unrelated-rule", DetectionCategory.INSTRUCTION),
        ],
    )
    def test_rule_id_keyword_category_inference(
        self, rule_id: str, expected: DetectionCategory
    ) -> None:
        findings = skillspector.parse_sarif(_sarif(results=[_sarif_result(ruleId=rule_id)]))
        assert findings[0].category is expected

    @pytest.mark.parametrize(
        ("rule_id", "expected_item"),
        [
            # 2026-07-27 (D7): a handful of skillspector's real, fixed ruleIds
            # spot-checking _TEST_ITEM_ID_BY_RULE_ID against the catalog.
            ("P1", "PROMPT-01"),  # 指令覆盖 - 直接提示词注入
            ("P2", "PROMPT-03"),  # 隐藏指令 - 隐藏/带外指令
            ("PE4", "PERM-03"),  # 访问 Docker Socket - 沙箱逃逸
            ("SSRF1", "NET-06"),  # 访问云元数据服务 - SSRF
            ("SC1", "SUPPLY-04"),  # 依赖未锁定版本 - 依赖锁定与混淆依赖
            # 2026-07-27 (review correction): E5 (cloud-storage exfil via
            # boto3/gsutil/Azure blob) is NET-04 "数据外传" (allowlist-exempt
            # enterprise storage calls), NOT NET-03 "数据外传给风险平台"
            # (untrusted platforms like free hosting/dnslog) - the original
            # mapping would have misreported normal cloud-storage calls as
            # Critical exfil to an untrusted platform.
            ("E5", "NET-04"),
        ],
    )
    def test_known_rule_id_maps_to_catalog_item(self, rule_id: str, expected_item: str) -> None:
        findings = skillspector.parse_sarif(_sarif(results=[_sarif_result(ruleId=rule_id)]))
        assert findings[0].test_item_id == expected_item

    @pytest.mark.parametrize("rule_id", ["TP1", "TP2", "TP3", "TP4"])
    def test_tool_poisoning_rule_ids_map_to_mcp_01(self, rule_id: str) -> None:
        # 2026-07-27 (review follow-up): TP1-4 had no mapping at all and were
        # silently falling to the GEN-01 fallback - unlike a raw-id
        # passthrough, GEN-01 doesn't even preserve which ruleId produced the
        # finding, so this was a real information loss, not just a label gap.
        # mcp_tool_poisoning.py confirms all four are tool-description-
        # poisoning checks (hidden instructions/Unicode deception/parameter
        # injection/LLM description-behavior mismatch) - MCP-01 in the xlsx,
        # whose detection means column explicitly lists both static_regex
        # (TP1-3) and semantic_llm (TP4) as in-scope mechanisms for this one
        # catalog item.
        findings = skillspector.parse_sarif(_sarif(results=[_sarif_result(ruleId=rule_id)]))
        assert findings[0].test_item_id == "MCP-01"

    @pytest.mark.parametrize(
        "rule_id",
        [
            # 2026-07-27 (review correction): both of these were originally
            # mapped to a syntactically-valid but semantically-mismatched
            # catalog item - RA2 (OS-level persistence: crontab/dotfiles/
            # systemd/launchd) is NOT PERM-07 (agent-specific hooks system);
            # TM3 (generic app config hygiene: TLS verification off,
            # permissive CORS, debug mode) is NOT MCP-04 (MCP-protocol-
            # specific server config). Neither has a clean catalog fit, so
            # both must fall through to GEN-01, same as RA1.
            "RA2",
            "TM3",
        ],
    )
    def test_semantically_mismatched_rule_ids_fall_back_to_gen_01(self, rule_id: str) -> None:
        findings = skillspector.parse_sarif(_sarif(results=[_sarif_result(ruleId=rule_id)]))
        assert findings[0].test_item_id == "GEN-01"

    def test_unmapped_rule_id_falls_back_to_gen_01_not_the_raw_id(self) -> None:
        # 2026-07-27: test_item_id used to be the raw SARIF ruleId whenever
        # unmapped - never matches a catalog entry, so it silently read as
        # uncovered in any report keyed on the catalog. The default fixture
        # ruleId ("prompt-injection-detected") is a schema-test placeholder,
        # not one of skillspector's real fixed ruleIds, so it must fall back
        # to GEN-01, not pass itself through.
        findings = skillspector.parse_sarif(_sarif())
        assert findings[0].test_item_id == "GEN-01"

    def test_multiple_runs_all_parsed(self) -> None:
        payload = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "skillspector"}},
                    "results": [_sarif_result(ruleId="a")],
                },
                {
                    "tool": {"driver": {"name": "skillspector"}},
                    "results": [_sarif_result(ruleId="b")],
                },
            ],
        }
        findings = skillspector.parse_sarif(json.dumps(payload).encode())
        assert len(findings) == 2


class TestParseOutput:
    def test_reads_sarif_file_from_target_dir(self, tmp_path: Path) -> None:
        (tmp_path / "report.sarif").write_bytes(_sarif())
        completed = subprocess.CompletedProcess(
            args=["skillspector"], returncode=0, stdout=b"", stderr=b""
        )
        findings = skillspector.parse_output(completed, tmp_path, {})
        assert len(findings) == 1

    def test_missing_sarif_file_raises(self, tmp_path: Path) -> None:
        completed = subprocess.CompletedProcess(
            args=["skillspector"], returncode=0, stdout=b"", stderr=b""
        )
        with pytest.raises(ValueError, match="did not write the expected SARIF file"):
            skillspector.parse_output(completed, tmp_path, {})


class TestMakeAdapter:
    def test_rejects_external_openai_base_url(self) -> None:
        with pytest.raises(ValueError, match="internal/private"):
            skillspector.make_adapter(
                openai_base_url="https://api.openai.com/v1",
                ruleset_digest="digest",
                version="0.1.0",
            )

    def test_accepts_loopback_openai_base_url(self) -> None:
        adapter = skillspector.make_adapter(
            openai_base_url="http://localhost:11434/v1", ruleset_digest="digest", version="0.1.0"
        )
        assert adapter.metadata.name == "skillspector"
        assert adapter.metadata.requires_llm is True
        assert EngineCapability.SEMANTIC_LLM in adapter.metadata.capabilities

    def test_api_key_sets_openai_api_key_env(self) -> None:
        # 2026-07-09: an enterprise privatized deployment may enforce its
        # own auth even on an internal network - api_key is independent of
        # the internal/external question (there is no external path at all
        # any more; require_internal_endpoint applies unconditionally).
        adapter = skillspector.make_adapter(
            openai_base_url="http://localhost:11434/v1",
            ruleset_digest="digest",
            version="0.1.0",
            api_key="sk-test-not-a-real-key",
        )
        env_fn = adapter._env  # noqa: SLF001 - white-box test
        assert callable(env_fn)
        env = env_fn()
        assert env is not None
        assert env["OPENAI_API_KEY"] == "sk-test-not-a-real-key"

    def test_no_api_key_env_when_none_provided(self) -> None:
        # No key needed against an unauthenticated internal vLLM - confirms
        # this stays true (no OPENAI_API_KEY at all, not even an empty one).
        adapter = skillspector.make_adapter(
            openai_base_url="http://localhost:11434/v1", ruleset_digest="digest", version="0.1.0"
        )
        env_fn = adapter._env  # noqa: SLF001 - white-box test
        assert callable(env_fn)
        env = env_fn()
        assert env is not None
        assert "OPENAI_API_KEY" not in env

    def test_env_carries_openai_base_url(self) -> None:
        adapter = skillspector.make_adapter(
            openai_base_url="http://localhost:11434/v1", ruleset_digest="digest", version="0.1.0"
        )
        env_fn = adapter._env  # noqa: SLF001
        assert callable(env_fn)
        env = env_fn()
        assert env["OPENAI_BASE_URL"] == "http://localhost:11434/v1"
        assert env["SKILLSPECTOR_PROVIDER"] == "openai"

    def test_env_carries_path_so_the_binary_can_be_found(self) -> None:
        # CORRECTNESS: confirmed live - `subprocess.run(..., env=X)` REPLACES
        # the child's entire environment; an env dict with no PATH key means
        # `subprocess.run(["skillspector", ...])` can never find the binary
        # via PATH search, even though it runs fine invoked directly in the
        # same container (which inherits the real PATH). Reproduced exactly:
        # FileNotFoundError: [Errno 2] No such file or directory: 'skillspector'.
        import os

        adapter = skillspector.make_adapter(
            openai_base_url="http://localhost:11434/v1", ruleset_digest="digest", version="0.1.0"
        )
        env_fn = adapter._env  # noqa: SLF001
        assert callable(env_fn)
        env = env_fn()
        assert env["PATH"] == os.environ.get("PATH", "")
        assert env["PATH"]  # not empty - a blank PATH is just as unusable as a missing one

    def test_no_llm_flag_present_when_use_llm_false(self) -> None:
        adapter = skillspector.make_adapter(
            openai_base_url="http://localhost:11434/v1",
            ruleset_digest="digest",
            version="0.1.0",
            use_llm=False,
        )
        argv = adapter._build_argv(Path("/tmp/scan-target"))  # noqa: SLF001
        assert "--no-llm" in argv

    def test_no_llm_flag_absent_when_use_llm_true(self) -> None:
        adapter = skillspector.make_adapter(
            openai_base_url="http://localhost:11434/v1",
            ruleset_digest="digest",
            version="0.1.0",
            use_llm=True,
        )
        argv = adapter._build_argv(Path("/tmp/scan-target"))  # noqa: SLF001
        assert "--no-llm" not in argv
        assert "--output" in argv
        assert str(Path("/tmp/scan-target") / "report.sarif") in argv

    # SECURITY regression (2026-07-06 spec-compliance audit, INV-14): the
    # vendored osv_client.py hits https://api.osv.dev directly with no
    # internal-mirror override of its own - osv_proxy_url lets make_adapter
    # route that call through an internal proxy via HTTPS_PROXY without
    # touching vendored code (httpx's default trust_env=True honors it).
    def test_no_osv_proxy_env_when_not_configured(self) -> None:
        adapter = skillspector.make_adapter(
            openai_base_url="http://localhost:11434/v1", ruleset_digest="digest", version="0.1.0"
        )
        env_fn = adapter._env  # noqa: SLF001
        assert callable(env_fn)
        env = env_fn()
        assert env is not None
        assert "HTTPS_PROXY" not in env
        assert "https_proxy" not in env

    def test_osv_proxy_url_injects_https_proxy_env(self) -> None:
        adapter = skillspector.make_adapter(
            openai_base_url="http://localhost:11434/v1",
            ruleset_digest="digest",
            version="0.1.0",
            osv_proxy_url="http://localhost:8080",
        )
        env_fn = adapter._env  # noqa: SLF001
        assert callable(env_fn)
        env = env_fn()
        assert env["OPENAI_BASE_URL"] == "http://localhost:11434/v1"
        assert env["SKILLSPECTOR_PROVIDER"] == "openai"
        assert env["HTTPS_PROXY"] == "http://localhost:8080"
        assert env["https_proxy"] == "http://localhost:8080"
        assert env["PATH"]  # still present alongside the proxy overrides

    def test_rejects_external_osv_proxy_url(self) -> None:
        with pytest.raises(ValueError, match="internal/private"):
            skillspector.make_adapter(
                openai_base_url="http://localhost:11434/v1",
                ruleset_digest="digest",
                version="0.1.0",
                osv_proxy_url="http://public-proxy.example.com:8080",
            )
