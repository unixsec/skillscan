"""File-type allowlist + magic-byte detector (coding spec §11.4 FILE-01/FILE-02,
SRS Cat-6: "可执行文件存在"/"非常见文件类型").

SECURITY: extension checks alone are trivially spoofed (rename `payload.elf` to
`payload.txt`) - every file's actual leading bytes are checked against known
executable/archive magic signatures regardless of its claimed extension, so a
disguised binary is still caught.

2026-07-27：原标签统一是 FILE-06（临时文件与符号链接风险），与本检测器毫不相关，
现按检测目录（企业Skill安全评估测试维度清单 D7）拆分为两个正确的条目：
- FILE-01「存在可执行文件」（检测要点："包体内部含可执行文件"）→ 魔数签名规则
  （`_MAGIC_SIGNATURES`，按文件头字节判断是否为 ELF/PE/Mach-O 等可执行文件）。
- FILE-02「非常见SKILL文件类型」（检测要点："包体含非常见类型文件（pdf/office
  文档等）"）→ 扩展名不在允许清单规则（`file.unexpected_extension`）。
"""

from __future__ import annotations

import hashlib

from skillscan_core import (
    DetectionCategory,
    EngineCapability,
    EngineMetadata,
    EngineResult,
    Finding,
    Severity,
)

from engine_runner.detectors._engine_base import run_with_deadline

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

# Explicit rule_id -> detection-catalog id, same convention as the other
# in-house detectors: never derive a catalog id from the rule name. Hoisted
# out of `scan()` 2026-07-27 (final review, F-1/F-3) so that (a) the digest
# below can hash it and (b) tests/test_test_item_catalog.py can read the real
# values instead of a hardcoded copy.
_TEST_ITEM_IDS: dict[str, str] = {
    # 魔数签名规则 -> FILE-01「存在可执行文件」（检测要点："包体内部含可执行文件"）
    "file.elf_binary": "FILE-01",
    "file.pe_binary": "FILE-01",
    "file.macho_binary": "FILE-01",
    "file.macho_or_java_class": "FILE-01",
    "file.shebang_script": "FILE-01",
    # 扩展名不在允许清单 -> FILE-02「非常见SKILL文件类型」
    "file.unexpected_extension": "FILE-02",
}

# 每条规则的 severity/confidence（2026-07-27 最终评审 F-3）：此前这些值直接写死
# 在 scan() 的 Finding() 里，_metadata() 完全看不到它们，于是改一条规则的
# severity/confidence 不会改 ruleset_digest → toolchain_digest → cache_key 不变
# → 修正后的规则被旧的缓存判定悄悄覆盖。提到模块级常量而不是在 _metadata() 里
# 再抄一份，是为了保证 digest 输入与 Finding 实际记录的值永远是同一个值——重复
# 一份副本正是 prompt_injection_zh.py 的 _CONFIDENCE 注释里记下的那个坑。
_MAGIC_SIGNATURE_CONFIDENCE = 0.95
_UNEXPECTED_EXTENSION_SEVERITY = Severity.LOW
_UNEXPECTED_EXTENSION_CONFIDENCE = 0.6

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
    # SECURITY (INV-7, 2026-07-27 final review F-3): this hash must change if
    # ANY field that affects what is detected, how severe it is, how confident
    # we are, or which catalog item it maps to changes - not just
    # rule_id/magic. It previously discarded `severity` into `_sev` and never
    # saw `confidence`/`test_item_id` at all, so downgrading e.g.
    # file.shebang_script from MEDIUM to LOW left ruleset_digest ->
    # toolchain_digest -> cache_key completely unchanged and every
    # already-scanned package kept its old verdict. Same shape (and same
    # reason) as pii.py / crypto_weak.py / toctou.py, which Task 6's review
    # already fixed; this detector was simply outside that pass's scope.
    hasher = hashlib.sha256()
    # category is a real scoring input - scoring.py weights every finding by
    # `weights.for_category` - so it belongs in the digest too.
    hasher.update(f"category:{_CATEGORY.value}\n".encode())
    for rule_id, magic, severity, _desc in _MAGIC_SIGNATURES:
        suffix = (
            f":{severity.value}:{_MAGIC_SIGNATURE_CONFIDENCE}:{_TEST_ITEM_IDS[rule_id]}\n"
        ).encode()
        hasher.update(rule_id.encode() + b":" + magic + suffix)
    hasher.update(
        (
            f"file.unexpected_extension:{_UNEXPECTED_EXTENSION_SEVERITY.value}"
            f":{_UNEXPECTED_EXTENSION_CONFIDENCE}"
            f":{_TEST_ITEM_IDS['file.unexpected_extension']}\n"
        ).encode()
    )
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
                    # 2026-07-27：原标签 FILE-06 与检测目录不符，修正为 FILE-02
                    # （非常见SKILL文件类型 - 检测扩展名是否在允许清单内）。
                    # 三个值都来自模块级常量，_metadata() 用的是同一份 - 见其注释。
                    test_item_id=_TEST_ITEM_IDS["file.unexpected_extension"],
                    category=_CATEGORY,
                    title=f"非预期的文件类型：{ext or '（无扩展名）'}",
                    severity=_UNEXPECTED_EXTENSION_SEVERITY,
                    confidence=_UNEXPECTED_EXTENSION_CONFIDENCE,
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
                        # 2026-07-27：原标签 FILE-06 与检测目录不符，修正为 FILE-01
                        # （存在可执行文件 - 按文件头魔数判断是否为可执行文件）。
                        test_item_id=_TEST_ITEM_IDS[rule_id],
                        category=_CATEGORY,
                        title=f"通过文件头魔数识别出：{description}",
                        severity=severity,
                        confidence=_MAGIC_SIGNATURE_CONFIDENCE,
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
        return run_with_deadline(self.metadata, scan, files, deadline)
