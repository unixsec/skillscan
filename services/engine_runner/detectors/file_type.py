"""File-type allowlist + magic-byte detector (coding spec §11.4 FILE-06,
SRS Cat-6: "可执行文件存在"/"非常见文件类型").

SECURITY: extension checks alone are trivially spoofed (rename `payload.elf` to
`payload.txt`) - every file's actual leading bytes are checked against known
executable/archive magic signatures regardless of its claimed extension, so a
disguised binary is still caught.
"""

from __future__ import annotations

import hashlib

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

# SECURITY: a Skill package is source + docs + small config/assets - anything
# outside this allowlist is flagged as unexpected, regardless of its content.
_ALLOWED_EXTENSIONS = frozenset(
    {
        # source (interpreted + compiled languages a Skill may legitimately carry)
        ".py",
        ".pyi",
        ".js",
        ".cjs",
        ".mjs",
        ".jsx",
        ".ts",
        ".tsx",
        ".cts",
        ".mts",
        ".sh",
        ".bash",
        ".zsh",
        ".go",
        ".rs",
        ".rb",
        ".php",
        ".java",
        ".kt",
        ".swift",
        ".c",
        ".h",
        ".cc",
        ".cpp",
        ".hpp",
        ".cs",
        ".lua",
        ".pl",
        ".r",
        ".scala",
        ".sql",
        # docs
        ".md",
        ".mdx",
        ".txt",
        ".rst",
        ".adoc",
        ".pdf",
        # config / data
        ".json",
        ".jsonc",
        ".json5",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".env",
        ".properties",
        ".lock",
        ".csv",
        ".tsv",
        ".xml",
        ".xsd",
        ".dtd",
        ".html",
        ".htm",
        ".css",
        ".scss",
        ".less",
        ".map",
        # dotfile-style config (no "extension" per se, but common + benign)
        ".gitignore",
        ".gitattributes",
        ".dockerignore",
        ".editorconfig",
        ".npmrc",
        ".nvmrc",
        ".prettierrc",
        ".eslintrc",
        ".babelrc",
        # image / font / small binary assets
        ".png",
        ".jpg",
        ".jpeg",
        ".webp",
        ".svg",
        ".gif",
        ".ico",
        ".bmp",
        ".ttf",
        ".otf",
        ".woff",
        ".woff2",
        ".eot",
    }
)

# (rule_id, magic bytes, severity, description) - checked regardless of extension.
_MAGIC_SIGNATURES: tuple[tuple[str, bytes, Severity, str], ...] = (
    ("file.elf_binary", b"\x7fELF", Severity.CRITICAL, "ELF executable/library"),
    ("file.pe_binary", b"MZ", Severity.CRITICAL, "Windows PE executable"),
    ("file.macho_binary", b"\xfe\xed\xfa\xce", Severity.CRITICAL, "Mach-O executable (32-bit)"),
    ("file.macho_binary", b"\xfe\xed\xfa\xcf", Severity.CRITICAL, "Mach-O executable (64-bit)"),
    (
        "file.macho_binary",
        b"\xce\xfa\xed\xfe",
        Severity.CRITICAL,
        "Mach-O executable (32-bit, swapped)",
    ),
    (
        "file.macho_binary",
        b"\xcf\xfa\xed\xfe",
        Severity.CRITICAL,
        "Mach-O executable (64-bit, swapped)",
    ),
    (
        "file.macho_or_java_class",
        b"\xca\xfe\xba\xbe",
        Severity.HIGH,
        "Mach-O universal binary or Java .class file",
    ),
    ("file.shebang_script", b"#!", Severity.MEDIUM, "executable script (shebang)"),
)


def _metadata() -> EngineMetadata:
    hasher = hashlib.sha256()
    for rule_id, magic, _sev, _desc in _MAGIC_SIGNATURES:
        hasher.update(rule_id.encode() + b":" + magic + b"\n")
    hasher.update(",".join(sorted(_ALLOWED_EXTENSIONS)).encode())
    return EngineMetadata(
        name="inhouse-file-type",
        version="1.0.0",
        ruleset_digest=hasher.hexdigest(),
        capabilities=frozenset({EngineCapability.STATIC}),
    )


def _extension_of(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[-1].lower()


def scan(files: dict[str, bytes]) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for path, data in files.items():
        ext = _extension_of(path)
        if ext not in _ALLOWED_EXTENSIONS:
            findings.append(
                Finding(
                    rule_id="file.unexpected_extension",
                    test_item_id="FILE-06",
                    category=_CATEGORY,
                    title=f"unexpected file type: {ext or '(no extension)'}",
                    severity=Severity.LOW,
                    confidence=0.6,
                    source_engine="inhouse-file-type",
                    source_capability=EngineCapability.STATIC,
                    file_path=path,
                    snippet_hash=hashlib.sha256(data[:64]).hexdigest() if data else None,
                    evidence_redacted=f"extension {ext!r} not in Skill package allowlist",
                )
            )

        for rule_id, magic, severity, description in _MAGIC_SIGNATURES:
            if data.startswith(magic):
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        test_item_id="FILE-06",
                        category=_CATEGORY,
                        title=f"{description} detected by magic bytes",
                        severity=severity,
                        confidence=0.95,
                        source_engine="inhouse-file-type",
                        source_capability=EngineCapability.STATIC,
                        file_path=path,
                        snippet_hash=hashlib.sha256(data[:64]).hexdigest(),
                        evidence_redacted=f"{description}, claimed extension {ext or '(none)'!r}",
                    )
                )
                break  # SECURITY: first magic match wins - a file is one format, not several
    return tuple(findings)


class FileTypeDetector:
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
