"""Shared text/binary sniffing helper for in-house floor detectors.

SECURITY/FP-TUNING: a Skill package legitimately ships binary assets (images,
fonts, compiled artifacts, PDFs). Running text regexes over their raw bytes
produces false positives (digit runs inside PDF object streams/font tables
matching PII shapes; random byte sequences matching prompt-injection phrase
shapes by sheer coincidence is far less likely but the same "text-only scope"
principle applies uniformly). Every in-house floor detector that does
line-based text regex matching shares this same pre-filter.
"""

from __future__ import annotations

_BINARY_SNIFF_BYTES = 8192
_TEXT_CONTROL_BYTES = frozenset({0x09, 0x0A, 0x0C, 0x0D})  # tab, LF, FF, CR


def looks_binary(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:_BINARY_SNIFF_BYTES]
    if b"\x00" in sample:
        return True  # a NUL byte is the classic, near-certain binary tell
    nontext = sum(1 for b in sample if b < 0x20 and b not in _TEXT_CONTROL_BYTES or b == 0x7F)
    return nontext / len(sample) > 0.30
