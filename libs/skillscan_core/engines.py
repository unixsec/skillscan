"""Reference and test-double detection engines (coding spec M1, §5.5).

Pure stdlib. These are NOT the real OSS adapters (those are sandboxed
subprocess wrappers built in a later milestone, coding spec §10) - they exist
so the kernel is fully testable without any infrastructure. StaticKeywordEngine
doubles as the basis for the O-1 "floor" engine referenced in §10/§11 M4.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Protocol

from skillscan_core.models import (
    DetectionCategory,
    EngineCapability,
    EngineMetadata,
    EngineResult,
    EngineStatus,
    Finding,
    ScanMode,
    Severity,
    TrifectaSignal,
)


class DetectionEngine(Protocol):
    # SECURITY/CORRECTNESS: a read-only property, not a plain attribute - every
    # real implementation below is a frozen dataclass, which can never satisfy
    # a Protocol member typed as a settable attribute (mypy strict rightly
    # rejects that as unsound: the Protocol would claim callers can reassign
    # `.metadata`, which would raise `FrozenInstanceError` at runtime). Nothing
    # in this codebase ever needs to reassign an engine's metadata after
    # construction anyway.
    @property
    def metadata(self) -> EngineMetadata: ...

    def analyze(
        self, files: dict[str, bytes], *, deadline: float | None = None
    ) -> EngineResult: ...


# (pattern, rule_id, category, severity, trifecta signal or None, title)
# NOTE: these are detection-pattern strings this engine searches FOR inside untrusted
# scanned content (e.g. "eval(" flags a call in the Skill being scanned) - nothing here
# is ever executed, imported, or eval'd by skillscan itself.
_STATIC_KEYWORD_PATTERNS: tuple[
    tuple[str, str, DetectionCategory, Severity, TrifectaSignal | None, str], ...
] = (
    (
        "eval(",
        "static.eval_call",
        DetectionCategory.CODE,
        Severity.HIGH,
        None,
        "检测到 eval() 调用",
    ),
    (
        "curl http",
        "static.curl_http",
        DetectionCategory.NETWORK_INTEL,
        Severity.MEDIUM,
        TrifectaSignal.EXTERNAL_EGRESS,
        "通过 curl 向 http(s) 端点发起出站请求",
    ),
    (
        "os.environ",
        "static.os_environ",
        DetectionCategory.DATA_CREDENTIAL,
        Severity.MEDIUM,
        TrifectaSignal.PRIVATE_DATA_ACCESS,
        "访问环境变量",
    ),
    (
        "input(",
        "static.input_call",
        DetectionCategory.INSTRUCTION,
        Severity.LOW,
        TrifectaSignal.UNTRUSTED_INPUT,
        "交互式 input() 调用",
    ),
)

# 安全风险描述（2026-07-24）：title 只标注命中的关键词，这里说明为什么这个
# 关键词在 Skill 代码里值得关注。
_RISK_DESCRIPTIONS: dict[str, str] = {
    "static.eval_call": (
        "eval() 会将字符串当作 Python 代码动态执行，如果该字符串包含任何"
        "用户输入或外部数据，攻击者可借此注入并执行任意代码；即使参数看似"
        "固定，也建议改用更安全的替代方案（如 ast.literal_eval 仅用于解析"
        "字面量）。"
    ),
    "static.curl_http": (
        "该行代码通过 curl 向外部 http(s) 端点发起出站网络请求，可能用于"
        "从远程下载并执行代码、向攻击者控制的服务器回传数据，或与命令与"
        "控制（C2）服务器通信；建议核实目标地址的可信度及请求的必要性。"
    ),
    "static.os_environ": (
        "该行代码读取了进程环境变量，环境变量中常常存放 API 密钥、数据库"
        "凭据、云服务账号等敏感信息；如果 Skill 将读取到的值回传/打印/写入"
        "日志，可能造成凭据泄露，建议核实读取的具体变量及其后续用途。"
    ),
    "static.input_call": (
        "该行代码通过 input() 接收交互式用户输入，如果后续未经校验就将其"
        "用于文件路径、shell 命令、SQL 查询等敏感操作，可能引入路径穿越、"
        "命令注入、SQL 注入等风险；建议核实输入后续的使用方式。"
    ),
}


def _static_keyword_ruleset_digest() -> str:
    # SECURITY (INV-7): must change if ANY field that affects scoring changes,
    # not just rule_id/pattern - otherwise toolchain_digest/cache_key stay the
    # same and a stale cached PASS survives a rule severity/category/trifecta
    # upgrade (a real gap found by the 2026-07-06 spec-compliance audit: this
    # previously hashed only rule_id:pattern).
    hasher = hashlib.sha256()
    for pattern, rule_id, category, severity, trifecta_signal, _title in _STATIC_KEYWORD_PATTERNS:
        trifecta_value = trifecta_signal.value if trifecta_signal is not None else ""
        hasher.update(
            f"{rule_id}:{pattern}:{category.value}:{severity.value}:{trifecta_value}\n".encode()
        )
    return hasher.hexdigest()


def _default_static_keyword_metadata() -> EngineMetadata:
    return EngineMetadata(
        name="static-keyword",
        version="1.0.0",
        ruleset_digest=_static_keyword_ruleset_digest(),
        capabilities=frozenset({EngineCapability.STATIC}),
        requires_network=False,
        requires_llm=False,
        deterministic=True,
    )


@dataclass(frozen=True, slots=True)
class StaticKeywordEngine:
    """Deterministic, dependency-free byte-matching engine.

    SECURITY: pure `pattern in line` matching on decoded text - never parses,
    imports, or executes the scanned content.
    """

    metadata: EngineMetadata = field(default_factory=_default_static_keyword_metadata)

    def analyze(self, files: dict[str, bytes], *, deadline: float | None = None) -> EngineResult:
        findings: list[Finding] = []
        timed_out = False
        for path, data in files.items():
            if deadline is not None and time.monotonic() > deadline:
                timed_out = True
                break
            text = data.decode("utf-8", errors="replace")
            for line_no, line in enumerate(text.splitlines(), start=1):
                for (
                    pattern,
                    rule_id,
                    category,
                    severity,
                    trifecta,
                    title,
                ) in _STATIC_KEYWORD_PATTERNS:
                    if pattern in line:
                        findings.append(
                            Finding(
                                rule_id=rule_id,
                                test_item_id=rule_id,
                                category=category,
                                title=title,
                                severity=severity,
                                confidence=1.0,
                                source_engine=self.metadata.name,
                                source_capability=EngineCapability.STATIC,
                                trifecta_signals=(
                                    frozenset({trifecta}) if trifecta else frozenset()
                                ),
                                file_path=path,
                                start_line=line_no,
                                # SECURITY (INV-9): store a digest, never the raw line.
                                snippet_hash=hashlib.sha256(line.encode("utf-8")).hexdigest(),
                                evidence_redacted=_RISK_DESCRIPTIONS[rule_id],
                            )
                        )

        status = EngineStatus.TIMEOUT if timed_out else EngineStatus.OK
        return EngineResult(
            engine=self.metadata,
            findings=tuple(findings),
            status=status,
            scan_mode=ScanMode.STATIC,
            llm_used=False,
            error="deadline exceeded" if timed_out else None,
        )


def _default_mock_llm_metadata() -> EngineMetadata:
    return EngineMetadata(
        name="mock-llm",
        version="0.0.0",
        ruleset_digest="n/a",
        capabilities=frozenset({EngineCapability.SEMANTIC_LLM}),
        requires_network=False,
        requires_llm=True,
        deterministic=False,
    )


@dataclass(frozen=True, slots=True)
class MockLLMEngine:
    """Test double for an LLM-backed engine: returns pre-set findings verbatim."""

    canned_findings: tuple[Finding, ...] = ()
    metadata: EngineMetadata = field(default_factory=_default_mock_llm_metadata)

    def analyze(self, files: dict[str, bytes], *, deadline: float | None = None) -> EngineResult:
        return EngineResult(
            engine=self.metadata,
            findings=self.canned_findings,
            status=EngineStatus.OK,
            scan_mode=ScanMode.STATIC,
            llm_used=True,
        )


@dataclass(frozen=True, slots=True)
class FailingEngine:
    """Test double that always fails - for exercising fail-closed behavior (INV-1)."""

    metadata: EngineMetadata
    failure_status: EngineStatus = EngineStatus.ERROR
    error_message: str = "engine failed"

    def analyze(self, files: dict[str, bytes], *, deadline: float | None = None) -> EngineResult:
        return EngineResult(
            engine=self.metadata,
            findings=(),
            status=self.failure_status,
            scan_mode=ScanMode.STATIC,
            llm_used=False,
            error=self.error_message,
        )
