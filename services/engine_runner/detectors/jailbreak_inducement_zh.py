"""Chinese-language jailbreak/inducement phrase detector (coding spec D5
PROMPT-04, floor tier). See docs/superpowers/specs/2026-07-22-chinese-
prompt-injection-detectors-design.md for the full design rationale.

Distinct from prompt_injection_zh.py (PROMPT-01, direct instruction
override): this covers the checklist's PROMPT-04 category specifically -
"forget prior instructions" as a memory-erasure jailbreak technique,
"bypass security review" as an explicit evasion goal, and roleplay-style
persona jailbreaks (the classic "pretend you are an unrestricted AI"
pattern).

Co-occurrence, not whole-phrase templates. Two of the three rules require a
THIRD corroborating signal (a source/temporal qualifier, or the full
verb+adjective+noun roleplay structure) because their base verb+noun pairs
alone are too common in benign technical writing ("忘记训练数据里的错误" -
an ordinary ML/data-science sentence). `bypass_review` is the one exception:
"安全审查"/"安全检测"/"内容过滤" are specific enough four-character
compounds that they essentially never appear in ordinary benign writing, so
a bare two-way co-occurrence with a release/evasion verb is already
reliable.
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
_TEST_ITEM_ID = "PROMPT-04"

# V2: release/evasion verbs
_V2 = r"(?:忘记|绕过|跳过|规避|解除|取消|移除)"
# N2a: instruction/constraint-class nouns (broad - needs Q1 to avoid FPs like
# "忘记训练数据里的错误")
_N2A = r"(?:指令|限制|规则|设定|训练)"
# N2b: security-review-class nouns (narrow/specific enough on their own)
_N2B = r"(?:安全审查|安全检测|内容审查|内容过滤|安全检查)"
# Q1: source/temporal qualifier (same word list as prompt_injection_zh.py's
# private _Q1 constant, duplicated rather than imported - each floor
# detector in this package is deliberately self-contained with no
# cross-detector coupling, per the design doc).
_Q1 = r"(?:之前|以上|前面|上述|系统|所有)"

# P2: roleplay-inducement verb
_P2 = r"(?:扮演|假装(?:你)?是|你现在扮演|你将扮演|请扮演)"
# A2: unrestricted/uncensored adjective (same word list as
# prompt_injection_zh.py's _A1, duplicated for the same self-containment
# reason above)
_A2 = r"(?:不受限制|无限制|越狱|无审查|无道德|没有(?:任何)?限制|无拘无束)"
# M2: persona/role noun
_M2 = r"(?:AI|助手|角色|人工智能)"


def _metadata() -> EngineMetadata:
    hasher = hashlib.sha256()
    for rule_id, pattern in (
        ("jailbreak_zh.constraint_release", _V2 + _N2A + _Q1),
        ("jailbreak_zh.bypass_review", _V2 + _N2B),
        ("jailbreak_zh.roleplay_induction", _P2 + _A2 + _M2),
    ):
        hasher.update(f"{rule_id}:{pattern}\n".encode())
    return EngineMetadata(
        name="inhouse-jailbreak-inducement-zh",
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
            if _line_has_all(line, _V2, _N2A, _Q1):
                findings.append(
                    Finding(
                        rule_id="jailbreak_zh.constraint_release",
                        test_item_id=_TEST_ITEM_ID,
                        category=_CATEGORY,
                        title="诱导提示：中文约束解除话术",
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        source_engine="inhouse-jailbreak-inducement-zh",
                        source_capability=EngineCapability.STATIC,
                        file_path=path,
                        start_line=line_no,
                        snippet_hash=snippet_hash,
                        evidence_redacted="constraint-release (verb+noun+qualifier, redacted)",
                    )
                )
            if _line_has_all(line, _V2, _N2B):
                findings.append(
                    Finding(
                        rule_id="jailbreak_zh.bypass_review",
                        test_item_id=_TEST_ITEM_ID,
                        category=_CATEGORY,
                        title="诱导提示：中文绕过安全审查话术",
                        severity=Severity.HIGH,
                        confidence=0.7,
                        source_engine="inhouse-jailbreak-inducement-zh",
                        source_capability=EngineCapability.STATIC,
                        file_path=path,
                        start_line=line_no,
                        snippet_hash=snippet_hash,
                        evidence_redacted="bypass-security-review phrase (verb+noun, redacted)",
                    )
                )
            if _line_has_all(line, _P2, _A2, _M2):
                findings.append(
                    Finding(
                        rule_id="jailbreak_zh.roleplay_induction",
                        test_item_id=_TEST_ITEM_ID,
                        category=_CATEGORY,
                        title="诱导提示：中文角色扮演越狱话术",
                        severity=Severity.HIGH,
                        confidence=0.7,
                        source_engine="inhouse-jailbreak-inducement-zh",
                        source_capability=EngineCapability.STATIC,
                        file_path=path,
                        start_line=line_no,
                        snippet_hash=snippet_hash,
                        evidence_redacted="roleplay-jailbreak (verb+adjective+noun, redacted)",
                    )
                )
    return tuple(findings)


class JailbreakInducementZhDetector:
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
