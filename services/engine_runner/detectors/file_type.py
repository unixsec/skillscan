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

# 安全风险描述（2026-07-24）：Skill 包本应只包含源码/文档/小型配置资产，出现
# 可执行二进制或与声称扩展名不符的文件头，是最典型的"伪装成普通文件的恶意
# payload"手法（如把 payload.elf 改名为 readme.txt）。
_UNEXPECTED_EXTENSION_RISK = (
    "Skill 包内出现了不在允许清单内的文件类型。正常 Skill 应只包含源码、文档"
    "和少量配置/资源文件；未预期的扩展名可能是被恶意植入的可执行文件、脚本"
    "或数据外泄载荷，伪装成普通文件以规避审查，建议人工核查该文件的实际用途。"
)
_MAGIC_SIGNATURE_RISK = (
    "该文件的真实内容（按文件头魔数判断）与其声称的扩展名不一致，是攻击者"
    "常用的伪装手法——将可执行文件/二进制程序改名为看似无害的扩展名（如 .txt/"
    ".png）以规避基于扩展名的审查或诱导用户直接双击运行；一旦被执行可能导致"
    "任意代码执行、后门植入等严重后果，建议人工核查该文件的真实来源与用途。"
)

# (rule_id, magic bytes, severity, description) - checked regardless of extension.
_MAGIC_SIGNATURES: tuple[tuple[str, bytes, Severity, str], ...] = (
    ("file.elf_binary", b"\x7fELF", Severity.CRITICAL, "ELF 可执行文件/库"),
    ("file.pe_binary", b"MZ", Severity.CRITICAL, "Windows PE 可执行文件"),
    ("file.macho_binary", b"\xfe\xed\xfa\xce", Severity.CRITICAL, "Mach-O 可执行文件（32 位）"),
    ("file.macho_binary", b"\xfe\xed\xfa\xcf", Severity.CRITICAL, "Mach-O 可执行文件（64 位）"),
    (
        "file.macho_binary",
        b"\xce\xfa\xed\xfe",
        Severity.CRITICAL,
        "Mach-O 可执行文件（32 位，字节序反转）",
    ),
    (
        "file.macho_binary",
        b"\xcf\xfa\xed\xfe",
        Severity.CRITICAL,
        "Mach-O 可执行文件（64 位，字节序反转）",
    ),
    (
        "file.macho_or_java_class",
        b"\xca\xfe\xba\xbe",
        Severity.HIGH,
        "Mach-O 通用二进制文件或 Java .class 文件",
    ),
    ("file.shebang_script", b"#!", Severity.MEDIUM, "可执行脚本（含 shebang）"),
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
                    title=f"非预期的文件类型：{ext or '（无扩展名）'}",
                    severity=Severity.LOW,
                    confidence=0.6,
                    source_engine="inhouse-file-type",
                    source_capability=EngineCapability.STATIC,
                    file_path=path,
                    snippet_hash=hashlib.sha256(data[:64]).hexdigest() if data else None,
                    evidence_redacted=(
                        f"{_UNEXPECTED_EXTENSION_RISK}（实际扩展名：{ext or '（无扩展名）'}）"
                    ),
                )
            )

        for rule_id, magic, severity, description in _MAGIC_SIGNATURES:
            if data.startswith(magic):
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        test_item_id="FILE-06",
                        category=_CATEGORY,
                        title=f"通过文件头魔数识别出：{description}",
                        severity=severity,
                        confidence=0.95,
                        source_engine="inhouse-file-type",
                        source_capability=EngineCapability.STATIC,
                        file_path=path,
                        snippet_hash=hashlib.sha256(data[:64]).hexdigest(),
                        evidence_redacted=(
                            f"{_MAGIC_SIGNATURE_RISK}（文件头魔数识别为：{description}，"
                            f"声称的扩展名为 {ext or '（无）'!r}）"
                        ),
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
