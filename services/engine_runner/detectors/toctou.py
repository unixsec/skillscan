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
        "hardcoded predictable temp-directory path (bandit B108-equivalent, TOCTOU race)",
        Severity.MEDIUM,
    ),
    (
        "toctou.insecure_mktemp",
        r"\btempfile\.mktemp\s*\(",
        "tempfile.mktemp() only predicts a name, does not atomically create it (TOCTOU race)",
        Severity.HIGH,
    ),
    (
        "toctou.symlink_creation",
        r"\bos\.symlink\s*\(",
        "creates a symlink at runtime - review target for traversal/escape risk",
        Severity.LOW,
    ),
)


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
                            evidence_redacted=f"pattern {rule_id!r} matched",
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
