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
        "credit-card-shaped number",
        Severity.HIGH,
    ),
    (
        "pii.us_ssn",
        r"\b\d{3}-\d{2}-\d{4}\b",
        "US SSN-shaped number",
        Severity.HIGH,
    ),
    (
        "pii.email",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "email address",
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
        "phone-number-shaped string",
        Severity.LOW,
    ),
)

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
                            title=f"possible {title} detected",
                            severity=severity,
                            confidence=0.7,
                            source_engine="inhouse-pii",
                            source_capability=EngineCapability.STATIC,
                            file_path=path,
                            start_line=line_no,
                            snippet_hash=snippet_hash,
                            evidence_redacted=f"{title} ({len(raw)} chars, redacted)",
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
