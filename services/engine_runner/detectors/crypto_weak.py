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
        "insecure MD5 hash (bandit B303-equivalent)",
        Severity.MEDIUM,
    ),
    (
        "crypto.weak_hash_sha1",
        r"\bhashlib\.sha1\s*\(",
        "insecure SHA1 hash (bandit B303-equivalent)",
        Severity.MEDIUM,
    ),
    (
        "crypto.weak_cipher_des",
        r"\b(?:DES|TripleDES|Crypto\.Cipher\.DES)\.new\s*\(",
        "insecure DES/3DES cipher (bandit B304-equivalent)",
        Severity.HIGH,
    ),
    (
        "crypto.weak_cipher_rc4",
        r"\b(?:ARC4|RC4|Crypto\.Cipher\.ARC4)\.new\s*\(",
        "insecure RC4 stream cipher (bandit B304-equivalent)",
        Severity.HIGH,
    ),
    (
        "crypto.weak_cipher_mode_ecb",
        r"MODE_ECB\b",
        "insecure ECB cipher mode (bandit B305-equivalent)",
        Severity.HIGH,
    ),
    (
        "crypto.non_cryptographic_random",
        r"\brandom\.(?:random|randint|choice|randrange|getrandbits)\s*\(",
        "non-cryptographic random() used where secrets may be needed "
        "(bandit B311-equivalent - review call site, not always a bug)",
        Severity.LOW,
    ),
)


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
                            evidence_redacted=f"pattern {rule_id!r} matched",
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
