"""TOCTOU / insecure temp-file detector (coding spec §11.4 FILE-04, SRS Cat-6
"临时文件/符号链接").

Self-built rules (bandit B108-equivalent: hardcoded /tmp paths) + symlink-
creation detection. NOTE: symlink *entries inside the scanned archive itself*
are already rejected outright by `normalizer.unpack_hardened` at unpack time -
this detector instead looks for CODE that creates symlinks or races on
predictable temp paths at runtime, which is a different risk (the Skill's own
behavior once executed, not the package's file listing).
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

_CATEGORY = DetectionCategory.FILE_PACKAGE

_PATTERNS: tuple[tuple[str, str, str, Severity], ...] = (
    (
        "toctou.hardcoded_tmp_path",
        r"""(?:["'])(?:/tmp/|/var/tmp/|/dev/shm/)[^"']*(?:["'])""",
        "硬编码的可预测临时目录路径",
        Severity.MEDIUM,
    ),
    (
        "toctou.insecure_mktemp",
        r"\btempfile\.mktemp\s*\(",
        "使用了不安全的 tempfile.mktemp()",
        Severity.HIGH,
    ),
    (
        "toctou.symlink_creation",
        r"\bos\.symlink\s*\(",
        "运行时创建符号链接",
        Severity.LOW,
    ),
)

# 安全风险描述（2026-07-24）：title 只标注命中的模式，这里说明为什么它是风险
# 及建议的规避方式（等同于 bandit B108 的检测口径）。
_RISK_DESCRIPTIONS: dict[str, str] = {
    "toctou.hardcoded_tmp_path": (
        "使用固定、可预测的临时文件路径时，攻击者可在文件被创建之前抢先在该路径"
        "放置符号链接或恶意文件，等 Skill 进程写入/读取时发生 TOCTOU（检查时间-使用"
        "时间）竞争，导致数据被劫持或覆盖到攻击者指定的位置；建议改用 tempfile."
        "mkstemp()/NamedTemporaryFile 生成不可预测且原子创建的临时文件。"
    ),
    "toctou.insecure_mktemp": (
        "tempfile.mktemp() 只返回一个当前不存在的文件名，不会原子性地创建文件，"
        "在“生成文件名”和“实际打开文件”之间存在竞争窗口，攻击者可抢先"
        "创建同名文件或符号链接，导致数据被劫持、覆盖或写入到非预期位置；应改用"
        "tempfile.mkstemp()/NamedTemporaryFile，由操作系统原子性地创建并返回已打开的文件。"
    ),
    "toctou.symlink_creation": (
        "运行时创建符号链接本身不一定是恶意行为，但如果目标路径可被攻击者控制"
        "或包含相对路径/上级目录引用，可能被用于目录穿越或将后续写入重定向到"
        "Skill 沙箱之外的敏感文件；建议人工核查符号链接的目标来源是否可信。"
    ),
}


def _metadata() -> EngineMetadata:
    hasher = hashlib.sha256()
    for rule_id, pattern, *_rest in _PATTERNS:
        hasher.update(f"{rule_id}:{pattern}\n".encode())
    return EngineMetadata(
        name="inhouse-toctou",
        version="1.0.0",
        ruleset_digest=hasher.hexdigest(),
        capabilities=frozenset({EngineCapability.STATIC}),
    )


def scan(files: dict[str, bytes]) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for path, data in files.items():
        text = data.decode("utf-8", errors="replace")
        for line_no, line in enumerate(text.splitlines(), start=1):
            for rule_id, pattern, title, severity in _PATTERNS:
                if re.search(pattern, line):
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            test_item_id="FILE-04",
                            category=_CATEGORY,
                            title=title,
                            severity=severity,
                            confidence=0.7,
                            source_engine="inhouse-toctou",
                            source_capability=EngineCapability.STATIC,
                            file_path=path,
                            start_line=line_no,
                            snippet_hash=hashlib.sha256(line.encode("utf-8")).hexdigest(),
                            evidence_redacted=_RISK_DESCRIPTIONS[rule_id],
                        )
                    )
    return tuple(findings)


class TocTouDetector:
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
