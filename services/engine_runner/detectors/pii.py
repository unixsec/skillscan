"""PII/PCI detector (coding spec §11.4 DATA-06, SRS Cat-3, INV-9).

SECURITY (INV-9): a PII/PCI match is, by definition, the exact kind of value
that must never appear in a finding's evidence. Every match is redacted to a
`snippet_hash` (sha256 of the raw matched text) before it ever leaves this
module - `evidence_redacted` carries only the pattern name and match length,
never a substring of the match itself, not even truncated (a truncated credit
card number is often still enough to be sensitive).
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

# NOTE: patterns match PII/PCI-SHAPED strings inside untrusted scanned content
# - nothing here parses, imports, or executes the scanned Skill.
_PII_PATTERNS: tuple[tuple[str, str, str, Severity], ...] = (
    (
        "pii.credit_card",
        r"\b(?:\d[ -]?){13,19}\b",
        "疑似信用卡号",
        Severity.HIGH,
    ),
    (
        "pii.us_ssn",
        r"\b\d{3}-\d{2}-\d{4}\b",
        "疑似美国社会安全号（SSN）",
        Severity.HIGH,
    ),
    (
        "pii.email",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "电子邮件地址",
        Severity.LOW,
    ),
    # SECURITY/FP-TUNING: require actual phone formatting (parens around the area
    # code or a separator between EVERY group) so a bare 10-digit run - the shape
    # of countless IDs, timestamps, and array offsets in normal source/data - is
    # NOT reported as a phone number. `4155551234` no longer matches;
    # `415-555-1234`, `(415) 555-1234`, `415.555.1234`, `+1 415 555 1234` do.
    (
        "pii.phone_number",
        r"(?<!\d)(?:\+?1[-. ])?(?:\(\d{3}\)[-. ]?|\d{3}[-. ])\d{3}[-. ]\d{4}(?!\d)",
        "疑似电话号码",
        Severity.LOW,
    ),
)

# 安全风险描述（2026-07-24）：与上面的 title 区分开——title 只说"找到了什么"，
# 这里说"为什么这是风险"。受 INV-9 约束不能展示匹配到的原文，所以这里是每类
# PII 固定的风险说明，不含任何具体命中内容。
_RISK_DESCRIPTIONS: dict[str, str] = {
    "pii.credit_card": (
        "Skill 包内硬编码了疑似真实的支付卡号，一旦随包分发或被日志/遥测意外记录，"
        "将造成持卡人数据泄露，违反 PCI-DSS 等合规要求；建议改用环境变量/密钥管理服务，"
        "并对已提交历史做清理。"
    ),
    "pii.us_ssn": (
        "Skill 包内硬编码了疑似美国社会安全号（SSN），属于高价值身份盗用素材，"
        "一旦泄露可用于冒名开户、税务欺诈等；不应出现在代码、配置或测试数据中，"
        "即使是示例数据也应使用明显不可用的占位值。"
    ),
    "pii.email": (
        "Skill 包内硬编码了真实邮箱地址，可能是开发者/用户的个人信息意外提交，"
        "存在被用于钓鱼、垃圾邮件定向投放或身份关联分析的风险；建议改用示例域名"
        "（如 example.com）或从配置/密钥管理中读取。"
    ),
    "pii.phone_number": (
        "Skill 包内硬编码了真实格式的电话号码，可能是意外提交的个人联系方式，"
        "存在被用于骚扰、社工钓鱼或身份关联分析的风险；建议改用明显的示例号码。"
    ),
}

_CATEGORY = DetectionCategory.DATA_CREDENTIAL

# Real payment-card PANs are 13, 14, 15, 16, or 19 digits (Visa/MC/Amex/UnionPay
# etc.). 17- and 18-digit runs are never valid card numbers, so requiring a
# real length on top of the Luhn check cuts false positives on long ID/serial
# digit strings that happen to satisfy Luhn.
_VALID_CARD_LENGTHS = frozenset({13, 14, 15, 16, 19})


def _metadata() -> EngineMetadata:
    hasher = hashlib.sha256()
    for rule_id, pattern, *_rest in _PII_PATTERNS:
        hasher.update(f"{rule_id}:{pattern}\n".encode())
    return EngineMetadata(
        name="inhouse-pii",
        version="1.0.0",
        ruleset_digest=hasher.hexdigest(),
        capabilities=frozenset({EngineCapability.STATIC}),
    )


def _luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def scan(files: dict[str, bytes]) -> tuple[Finding, ...]:
    """Pure detection function - the shape every in-house detector in this
    package shares: `dict[str, bytes] -> tuple[Finding, ...]`."""
    findings: list[Finding] = []
    for path, data in files.items():
        if looks_binary(data):
            continue  # FP-TUNING: text PII regexes have no meaning over binary bytes
        text = data.decode("utf-8", errors="replace")
        for line_no, line in enumerate(text.splitlines(), start=1):
            for rule_id, pattern, title, severity in _PII_PATTERNS:
                for match in re.finditer(pattern, line):
                    raw = match.group(0)
                    if rule_id == "pii.credit_card":
                        digits = re.sub(r"[ -]", "", raw)
                        # SECURITY: Luhn + real-card-length check to cut false
                        # positives on plain digit runs (schemas, IDs, serials).
                        if len(digits) not in _VALID_CARD_LENGTHS or not _luhn_valid(digits):
                            continue
                    # SECURITY (INV-9): sha256 of the RAW match, never stored
                    # or logged in plaintext form anywhere past this point.
                    snippet_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            test_item_id="DATA-06",
                            category=_CATEGORY,
                            title=f"检测到{title}",
                            severity=severity,
                            confidence=0.7,
                            source_engine="inhouse-pii",
                            source_capability=EngineCapability.STATIC,
                            file_path=path,
                            start_line=line_no,
                            snippet_hash=snippet_hash,
                            evidence_redacted=(
                                f"{_RISK_DESCRIPTIONS[rule_id]}"
                                f"（命中长度 {len(raw)} 字符，原文已脱敏不予展示）"
                            ),
                        )
                    )
    return tuple(findings)


class PiiDetector:
    """`DetectionEngine` Protocol implementation (skillscan_core.DetectionEngine)
    so this detector registers as a required/optional engine exactly like
    `StaticKeywordEngine`."""

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
