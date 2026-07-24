"""Weak-cryptography detector (coding spec §11.4 CODE-12, SRS Cat-2 "弱加密").

Self-built rules (coding spec explicitly allows "bandit B303/304/305/311 或
自研规则" - bandit's rule IDs OR self-built rules): the real subprocess-wrapped
bandit adapter is M5 scope (`services/engine_runner/adapters/bandit.py`,
coding spec §11.5) - this module gives a floor of coverage for the same
weakness classes without a subprocess dependency, following the same
byte/pattern-matching approach as `skillscan_core.StaticKeywordEngine`.
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

_CATEGORY = DetectionCategory.CODE

# (rule_id, pattern, title, severity, bandit-equivalent) - patterns match
# CONTENT being scanned for weak-crypto usage; nothing here is executed.
_PATTERNS: tuple[tuple[str, str, str, Severity], ...] = (
    (
        "crypto.weak_hash_md5",
        r"\bhashlib\.md5\s*\(",
        "使用了不安全的 MD5 哈希算法",
        Severity.MEDIUM,
    ),
    (
        "crypto.weak_hash_sha1",
        r"\bhashlib\.sha1\s*\(",
        "使用了不安全的 SHA1 哈希算法",
        Severity.MEDIUM,
    ),
    (
        "crypto.weak_cipher_des",
        r"\b(?:DES|TripleDES|Crypto\.Cipher\.DES)\.new\s*\(",
        "使用了不安全的 DES/3DES 加密算法",
        Severity.HIGH,
    ),
    (
        "crypto.weak_cipher_rc4",
        r"\b(?:ARC4|RC4|Crypto\.Cipher\.ARC4)\.new\s*\(",
        "使用了不安全的 RC4 流加密算法",
        Severity.HIGH,
    ),
    (
        "crypto.weak_cipher_mode_ecb",
        r"MODE_ECB\b",
        "使用了不安全的 ECB 加密模式",
        Severity.HIGH,
    ),
    (
        "crypto.non_cryptographic_random",
        r"\brandom\.(?:random|randint|choice|randrange|getrandbits)\s*\(",
        "在可能需要密码学安全随机数的场景使用了非密码学随机数 random()",
        Severity.LOW,
    ),
)

# 安全风险描述（2026-07-24）：与 bandit 对应规则（B303/B304/B305/B311）口径一致，
# 说明具体的攻击面而不只是重复"不安全"这个判断词。
_RISK_DESCRIPTIONS: dict[str, str] = {
    "crypto.weak_hash_md5": (
        "MD5 已被证实存在实用化的碰撞攻击，不应再用于密码存储、数字签名、完整性"
        "校验等安全场景（用于非安全用途的缓存 key/去重等则不构成风险，需结合"
        "调用位置判断）；建议改用 SHA-256 及以上，密码存储应使用 bcrypt/scrypt/"
        "Argon2 等专用算法。"
    ),
    "crypto.weak_hash_sha1": (
        "SHA1 已被证实存在实用化的碰撞攻击（如 SHAttered），不应再用于数字签名、"
        "证书指纹等安全场景；建议改用 SHA-256 及以上。"
    ),
    "crypto.weak_cipher_des": (
        "DES 密钥长度仅 56 位，3DES 也已被 NIST 弃用，在现代算力下可被暴力破解，"
        "无法提供有效的机密性保护；建议改用 AES-256（GCM/CBC 模式）等现代对称加密算法。"
    ),
    "crypto.weak_cipher_rc4": (
        "RC4 存在已知的密钥流偏差缺陷，可被统计分析恢复明文，多个安全标准"
        "（如 TLS 1.3）已将其禁用；建议改用 AES-GCM/ChaCha20-Poly1305 等现代加密算法。"
    ),
    "crypto.weak_cipher_mode_ecb": (
        "ECB 模式对相同的明文分组总是产生相同的密文分组，无法隐藏数据的结构性"
        "模式（经典例子是 ECB 模式加密图片仍能看出原图轮廓），存在明文特征泄露风险；"
        "建议改用 GCM/CBC（配合随机 IV）等模式。"
    ),
    "crypto.non_cryptographic_random": (
        "random 模块基于梅森旋转算法，是可预测的伪随机数生成器，如果被用于生成"
        "密码、令牌、会话 ID、密钥等安全相关的值，攻击者可能预测或还原后续输出；"
        "此类场景应改用 secrets 模块或 os.urandom()。若仅用于非安全场景（如抽样、"
        "游戏逻辑），则不构成安全缺陷，需结合调用位置判断。"
    ),
}


def _metadata() -> EngineMetadata:
    hasher = hashlib.sha256()
    for rule_id, pattern, *_rest in _PATTERNS:
        hasher.update(f"{rule_id}:{pattern}\n".encode())
    return EngineMetadata(
        name="inhouse-crypto-weak",
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
                            test_item_id="CODE-12",
                            category=_CATEGORY,
                            title=title,
                            severity=severity,
                            confidence=0.7,
                            source_engine="inhouse-crypto-weak",
                            source_capability=EngineCapability.STATIC,
                            file_path=path,
                            start_line=line_no,
                            snippet_hash=hashlib.sha256(line.encode("utf-8")).hexdigest(),
                            evidence_redacted=_RISK_DESCRIPTIONS[rule_id],
                        )
                    )
    return tuple(findings)


class CryptoWeakDetector:
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
