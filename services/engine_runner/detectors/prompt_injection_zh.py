"""Chinese-language direct instruction-override detector (coding spec D5
PROMPT-01, floor tier). See docs/superpowers/specs/2026-07-22-chinese-
prompt-injection-detectors-design.md for the full design rationale.

SECURITY: SkillSpector's own static_patterns_prompt_injection.py (P1-P4)
covers this exact category, but every one of its regexes is English-only -
a Chinese-language instruction-override phrase passes through it completely
unflagged. This floor-tier detector closes that gap for Chinese specifically.

Co-occurrence, not whole-phrase templates: matching a bare override verb
(e.g. "忽略") or a bare instruction noun (e.g. "指令") alone is far too
common in ordinary benign technical writing ("脚本会忽略该指令并继续执行
下一条" - describing normal error-handling logic). Only when an override
verb, an instruction-class noun, AND a source/temporal qualifier (pointing
at "previous"/"system" instructions specifically, not instructions in
general) all appear on the SAME LINE is this reported.
"""

from __future__ import annotations

import hashlib
import re

from skillscan_core import (
    DetectionCategory,
    EngineCapability,
    EngineMetadata,
    EngineResult,
    EngineStatus,
    Finding,
    ScanMode,
    Severity,
)

from engine_runner.detectors._text_utils import looks_binary

_CATEGORY = DetectionCategory.INSTRUCTION
_TEST_ITEM_ID = "PROMPT-01"

# V1: override/negation verbs
_V1 = r"(?:忽略|无视|不(?:要|需)理会|别管|撇开)"
# N1: instruction-class nouns
_N1 = r"(?:指令|规则|限制|约束|要求)"
# Q1: source/temporal qualifiers - required alongside V1+N1 to avoid firing
# on ordinary technical prose that happens to contain both a verb and a noun
# without referring to PRIOR/SYSTEM instructions specifically.
_Q1 = r"(?:之前|以上|前面|上述|系统|所有)"

# P1: identity-declaration verb ("you (now) are/become")
_P1 = r"你(?:现在)?(?:是|处于|变成|切换(?:为|成))"
# A1: unrestricted/uncensored adjective
_A1 = r"(?:不受限制|无限制|越狱|无审查|无道德|没有(?:任何)?限制|无拘无束)"
# M1: mode/identity noun
_M1 = r"(?:模式|状态|AI|人工智能|助手|角色|身份)"


def _metadata() -> EngineMetadata:
    hasher = hashlib.sha256()
    for rule_id, pattern in (
        ("prompt_zh.instruction_override", _V1 + _N1 + _Q1),
        ("prompt_zh.unrestricted_persona", _P1 + _A1 + _M1),
    ):
        hasher.update(f"{rule_id}:{pattern}\n".encode())
    return EngineMetadata(
        name="inhouse-prompt-injection-zh",
        version="1.0.0",
        ruleset_digest=hasher.hexdigest(),
        capabilities=frozenset({EngineCapability.STATIC}),
    )


def _line_has_all(line: str, *patterns: str) -> bool:
    return all(re.search(p, line, re.IGNORECASE) for p in patterns)


def scan(files: dict[str, bytes]) -> tuple[Finding, ...]:
    """Pure detection function - the shape every in-house detector in this
    package shares: `dict[str, bytes] -> tuple[Finding, ...]`."""
    findings: list[Finding] = []
    for path, data in files.items():
        if looks_binary(data):
            continue
        text = data.decode("utf-8", errors="replace")
        for line_no, line in enumerate(text.splitlines(), start=1):
            snippet_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
            if _line_has_all(line, _V1, _N1, _Q1):
                findings.append(
                    Finding(
                        rule_id="prompt_zh.instruction_override",
                        test_item_id=_TEST_ITEM_ID,
                        category=_CATEGORY,
                        title="直接提示词注入：中文指令覆盖话术",
                        severity=Severity.HIGH,
                        confidence=0.7,
                        source_engine="inhouse-prompt-injection-zh",
                        source_capability=EngineCapability.STATIC,
                        file_path=path,
                        start_line=line_no,
                        snippet_hash=snippet_hash,
                        evidence_redacted="instruction-override phrase (redacted)",
                    )
                )
            if _line_has_all(line, _P1, _A1, _M1):
                findings.append(
                    Finding(
                        rule_id="prompt_zh.unrestricted_persona",
                        test_item_id=_TEST_ITEM_ID,
                        category=_CATEGORY,
                        title="直接提示词注入：中文无限制身份声明",
                        severity=Severity.HIGH,
                        confidence=0.7,
                        source_engine="inhouse-prompt-injection-zh",
                        source_capability=EngineCapability.STATIC,
                        file_path=path,
                        start_line=line_no,
                        snippet_hash=snippet_hash,
                        evidence_redacted="unrestricted-persona declaration (redacted)",
                    )
                )
    return tuple(findings)


class PromptInjectionZhDetector:
    """`DetectionEngine` Protocol implementation (skillscan_core.DetectionEngine)."""

    @property
    def metadata(self) -> EngineMetadata:
        return _metadata()

    def analyze(self, files: dict[str, bytes], *, deadline: float | None = None) -> EngineResult:
        return EngineResult(
            engine=self.metadata,
            findings=scan(files),
            status=EngineStatus.OK,
            scan_mode=ScanMode.STATIC,
            llm_used=False,
        )
