"""SKILL.md permission-declaration detector (SRS Cat-5 PERM-*, FR-PAR-013,
FR-DET-050).

A Skill declares which tools it may use in its SKILL.md frontmatter. Until
2026-07-27 nothing read that declaration for security purposes - the only
parser took `name` for display. An over-broad declaration is the difference
between a Skill that can read files and one that can run arbitrary commands
and reach the network in the same breath.

SECURITY: in `required_engines`, so every path returns a Finding or nothing -
never an exception. Frontmatter parsing (including alias refusal) is delegated
to `common.frontmatter`, which has the same contract.

Catalog ids corrected 2026-07-27 (Task 8 SAD coverage-matrix review) from
PERM-03/PERM-01 to PERM-05 for two of the four rules - see `_TEST_ITEM_IDS`'
own comment for the full per-rule justification against
企业Skill安全评估测试维度清单.xlsx.
"""

from __future__ import annotations

import hashlib
from typing import Any

from common.frontmatter import parse_frontmatter
from common.skill_package import root_skill_md_path
from skillscan_core import (
    DetectionCategory,
    EngineCapability,
    EngineMetadata,
    EngineResult,
    Finding,
    Severity,
)

from engine_runner.detectors._engine_base import run_with_deadline

_ENGINE_NAME = "inhouse-skill-permissions"
_CATEGORY = DetectionCategory.PERMISSION

# Tools that let a Skill execute arbitrary commands on the host.
_EXECUTION_TOOLS = frozenset({"Bash", "Execute", "Shell", "Run"})
# Tools that let a Skill reach outside the host.
_NETWORK_TOOLS = frozenset({"WebFetch", "WebSearch", "Fetch", "HttpRequest"})

_PERMISSION_KEYS = ("allowed-tools", "allowed_tools", "tools", "permissions")

# Bumped whenever `common.skill_package`'s root-manifest resolution changes
# meaning. Which file counts as the package's manifest decides what this
# detector finds, so - exactly like mcp_config.py's
# `_HOST_CLASSIFICATION_VERSION` - it has to be a digest input even though
# there is no constant here to hash directly (the logic lives in a shared
# helper, not in a table).
_ROOT_MANIFEST_RESOLUTION_VERSION = (
    "skill_package.root_skill_md_path-v2:single-shared-wrapper"
    "+structural-dir-exclusion+root-metadata-tolerance"
)

# Explicit rule_id -> detection-catalog id, same reasoning as the .mcp.json
# detector: never derive a catalog id from the rule name.
#
# 2026-07-27 (Task 8 SAD coverage-matrix review, same pass as mcp_config.py's
# fix above): corrected against 企业Skill安全评估测试维度清单.xlsx directly.
#   - perm.dangerous_tool_combination was PERM-03 ("沙箱逃逸" - breaking out
#     of an isolation boundary via syscalls/cgroups/namespace/host socket) -
#     declaring both an execution tool and a network tool in SKILL.md
#     frontmatter has nothing to do with sandbox escape. -> PERM-05 (过度授权
#     /over-provisioning): "测试申请权限是否超出功能实际所需(最小权限原则)" -
#     a Skill genuinely needing only one of these two capabilities but
#     declaring both is requesting more than its function needs.
#   - perm.unrestricted_bash was PERM-01 ("权限提升" - missing/incorrect
#     authorization checks, bypassable role/resource boundaries, process
#     privilege higher than needed, setuid/chmod+x) - an unscoped Bash
#     declaration isn't a privilege-escalation MECHANISM, it's a permission
#     REQUEST wider than needed. -> PERM-05, same catalog item as above and
#     a more precise match: PERM-05's "超出功能实际所需" describes exactly
#     what an unconstrained (no per-command scoping) Bash grant is.
#   - perm.undeclared_permissions -> PERM-04 (权限manifest缺失) - unchanged,
#     exact match ("测试 skill 是否声明了 files/network/shell/tools 权限清
#     单；缺失则拒绝").
#   - perm.malformed_frontmatter -> PERM-04 - unchanged: an unparseable
#     frontmatter has the same practical effect as no declaration at all
#     (nothing to review), and unlike mcp_config.py's malformed_config there
#     IS an on-point item here (PERM-04 explicitly covers the missing-
#     manifest case this detector exists to catch).
_TEST_ITEM_IDS: dict[str, str] = {
    "perm.dangerous_tool_combination": "PERM-05",
    "perm.unrestricted_bash": "PERM-05",
    "perm.undeclared_permissions": "PERM-04",
    "perm.malformed_frontmatter": "PERM-04",
}

# Each rule's severity, one place (2026-07-27 final review, F-3) - previously
# a literal at each `_finding(...)` call site, invisible to `_metadata()`, so
# a severity change left ruleset_digest -> toolchain_digest -> cache_key
# unchanged and every already-scanned package kept its old verdict.
_SEVERITIES: dict[str, Severity] = {
    "perm.dangerous_tool_combination": Severity.HIGH,
    "perm.unrestricted_bash": Severity.MEDIUM,
    "perm.undeclared_permissions": Severity.LOW,
    "perm.malformed_frontmatter": Severity.LOW,
}

# Same single-source reasoning: confidence gates gate.py's review_confidence
# branch, so it is scoring-relevant and must be hashed.
_CONFIDENCE = 0.9

_RISK_DESCRIPTIONS: dict[str, str] = {
    "perm.dangerous_tool_combination": (
        "SKILL.md 同时声明了命令执行类工具与网络访问类工具。二者单独存在都可能是正当需求，"
        "但组合在一起构成完整的数据外泄链路：先在宿主机上读取或收集数据，再直接发往外部"
        "端点，全程不需要任何额外落地文件，因此也不会被针对文件写入的检测发现。"
    ),
    "perm.unrestricted_bash": (
        "SKILL.md 声明了不带任何参数约束的命令执行权限。Agent 据此可执行任意命令，"
        "该 Skill 的实际能力边界完全取决于其运行时提示词内容，静态审查无法界定。"
        "受约束的写法（如 `Bash(git status)`）能把权限收敛到具体命令。"
    ),
    "perm.undeclared_permissions": (
        "该 Skill 包含可执行脚本目录，但 SKILL.md 未声明任何权限。缺少声明意味着无法在"
        "准入阶段按最小权限原则审查它——审查者无从判断这些脚本预期需要什么能力，"
        "也无法在运行时对其做任何收敛（FR-PAR-013 要求记录声明的权限供门禁使用）。"
    ),
    "perm.malformed_frontmatter": (
        "SKILL.md 的 frontmatter 无法解析为合法映射。无法解析即无法审查其声明的权限，"
        "本系统对这部分内容不具备可见性，需人工确认该文件的来源与完整性。"
    ),
}


def _metadata() -> EngineMetadata:
    # SECURITY (INV-7, 2026-07-27 final review F-3): every field that changes
    # what is detected, how severe it is, how confident we are, or which
    # catalog item it maps to is hashed here.
    #
    # `_PERMISSION_KEYS` is the one that bites hardest. A real Skill declares
    # `allowedTools` (camelCase); the moment someone adds that spelling to the
    # tuple this detector starts FINDING declarations it previously missed -
    # a detection-behaviour change. Without it in the digest, `submit_scan`
    # returns the existing scan_job for every already-scanned package and
    # reeval's toolchain-staleness check sees nothing, so every prior package
    # keeps its old verdict permanently.
    #
    # `_TEST_ITEM_IDS` is hashed for the reason Task 9 already established
    # (a mapping-only correction must invalidate cached verdicts); this
    # detector was re-labelled inside this very milestone without it.
    hasher = hashlib.sha256()
    for rule_id in sorted(_RISK_DESCRIPTIONS):
        hasher.update(
            f"{rule_id}:{_TEST_ITEM_IDS[rule_id]}:{_CATEGORY.value}:"
            f"{_SEVERITIES[rule_id].value}:{_CONFIDENCE}\n".encode()
        )
    for tool in sorted(_EXECUTION_TOOLS | _NETWORK_TOOLS):
        hasher.update(f"{tool}\n".encode())
    for key in _PERMISSION_KEYS:
        hasher.update(f"permission_key:{key}\n".encode())
    hasher.update(f"{_ROOT_MANIFEST_RESOLUTION_VERSION}\n".encode())
    return EngineMetadata(
        name=_ENGINE_NAME,
        version="1.0.0",
        ruleset_digest=hasher.hexdigest(),
        capabilities=frozenset({EngineCapability.STATIC}),
    )


def _finding(rule_id: str, *, path: str, title: str, evidence: str) -> Finding:
    # severity/confidence/test_item_id all come from the module-level tables so
    # `_metadata()` hashes exactly the values recorded here - see `_SEVERITIES`.
    return Finding(
        rule_id=rule_id,
        test_item_id=_TEST_ITEM_IDS[rule_id],
        category=_CATEGORY,
        title=title,
        severity=_SEVERITIES[rule_id],
        confidence=_CONFIDENCE,
        source_engine=_ENGINE_NAME,
        source_capability=EngineCapability.STATIC,
        file_path=path,
        # SECURITY (INV-9): digest of the declaration, never the declaration.
        snippet_hash=hashlib.sha256(evidence.encode("utf-8")).hexdigest(),
        evidence_redacted=_RISK_DESCRIPTIONS[rule_id],
    )


def declared_tools(frontmatter: dict[str, Any]) -> list[str]:
    """The tool names a frontmatter declares, across the spellings seen in the
    wild. Non-string entries are dropped rather than rejected - a malformed
    entry should not hide the well-formed ones next to it."""
    for key in _PERMISSION_KEYS:
        value = frontmatter.get(key)
        if isinstance(value, list):
            return [v for v in value if isinstance(v, str)]
        if isinstance(value, str):
            return [value]
    return []


def _base_tool(entry: str) -> str:
    """`Bash(git status)` -> `Bash`. A parenthesised argument is what makes a
    declaration scoped rather than unrestricted."""
    return entry.split("(", 1)[0].strip()


def scan(files: dict[str, bytes]) -> tuple[Finding, ...]:
    # SECURITY: root path ONLY - never basename-anywhere. The Agent only ever
    # reads the package-root SKILL.md as its permission declaration; a
    # bundled example (`examples/SKILL.md`) is not consulted at runtime. If
    # this matched any SKILL.md by basename, a package with no root
    # declaration but a fully-declared examples/SKILL.md would read as
    # "permissions declared" and suppress perm.undeclared_permissions - a
    # false negative (undetected undeclared scripts), which is worse than the
    # false positive this narrower match risks.
    #
    # This is the OPPOSITE tradeoff from mcp_config.py's `_is_mcp_config`,
    # which deliberately matches `.mcp.json` by basename anywhere in the
    # package: an over-flagged non-root MCP config is a harmless false
    # positive a human can waive, and it never suppresses the root file's own
    # finding. Do not "unify" the two matchers - the asymmetry is intentional
    # and is about a different axis than the wrapper handling below.
    #
    # 2026-07-27 (final review, F-5): "root" is NOT the literal string
    # "SKILL.md". `tar czf skill.tgz my-skill/` - the conventional way to pack
    # a directory - puts every member under a `my-skill/` wrapper, and the
    # normalizer never strips it, so this used to conclude "no SKILL.md" for a
    # package that declares its permissions perfectly well and emit a false
    # `perm.undeclared_permissions`. `common.skill_package` recognises that
    # one shared wrapper (and nothing else - a nested `examples/SKILL.md`
    # still never counts); it is the single shared implementation for all
    # three places that need to find this file.
    skill_md_path = root_skill_md_path(files)
    root_data = files.get(skill_md_path)
    # Deliberately kept prefix-TOLERANT, unlike the manifest lookup above: this
    # only answers "is there anything here to declare permissions ABOUT", and
    # over-answering yes is the fail-safe direction (it can only add a finding,
    # never suppress one). The manifest lookup is the opposite - being too
    # tolerant there SUPPRESSES findings - which is why the two differ.
    has_scripts = any(p.startswith("scripts/") or "/scripts/" in p for p in files)

    if root_data is None:
        # No root manifest at all - not even a malformed one. Falls through to
        # the SAME has_scripts check as a malformed/undeclared root would: a
        # non-root SKILL.md elsewhere (e.g. examples/SKILL.md) must NOT
        # suppress this, since the Agent never reads it as a declaration.
        if not has_scripts:
            return ()
        return (
            _finding(
                "perm.undeclared_permissions",
                path=skill_md_path,
                title="缺少根目录 SKILL.md，含可执行脚本但未声明任何权限",
                evidence=skill_md_path,
            ),
        )

    frontmatter = parse_frontmatter(root_data)

    if frontmatter is None:
        # Only a finding when there was something to declare about: a docs-only
        # Skill with no frontmatter is ordinary, not suspicious.
        if not has_scripts:
            return ()
        return (
            _finding(
                "perm.malformed_frontmatter",
                path=skill_md_path,
                title="SKILL.md frontmatter 无法解析",
                evidence=skill_md_path,
            ),
        )

    entries = declared_tools(frontmatter)
    findings: list[Finding] = []

    if not entries:
        if has_scripts:
            findings.append(
                _finding(
                    "perm.undeclared_permissions",
                    path=skill_md_path,
                    title="含可执行脚本但未声明任何权限",
                    evidence=skill_md_path,
                )
            )
        return tuple(findings)

    bases = {_base_tool(e) for e in entries}
    if bases & _EXECUTION_TOOLS and bases & _NETWORK_TOOLS:
        findings.append(
            _finding(
                "perm.dangerous_tool_combination",
                path=skill_md_path,
                title="同时声明命令执行与网络访问权限",
                evidence=",".join(sorted(bases)),
            )
        )

    unscoped = sorted(e for e in entries if _base_tool(e) in _EXECUTION_TOOLS and "(" not in e)
    if unscoped:
        findings.append(
            _finding(
                "perm.unrestricted_bash",
                path=skill_md_path,
                title="声明了不带参数约束的命令执行权限",
                evidence=",".join(unscoped),
            )
        )

    return tuple(findings)


class SkillPermissionsDetector:
    """`DetectionEngine` Protocol implementation (skillscan_core.DetectionEngine)."""

    @property
    def metadata(self) -> EngineMetadata:
        return _metadata()

    def analyze(self, files: dict[str, bytes], *, deadline: float | None = None) -> EngineResult:
        # Deadline handling is shared with every other floor detector - see
        # _engine_base.run_with_deadline (added in Task 1).
        return run_with_deadline(self.metadata, scan, files, deadline)
