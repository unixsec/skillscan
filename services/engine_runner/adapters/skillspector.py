"""skillspector adapter (coding spec §10: SARIF output) → 大部分 Cat-1..6.

Real CLI/output confirmed by reading `vendor/skillspector/` directly (coding
spec's own instruction - read the real vendored source, don't guess the
interface):
  `skillspector scan <path> --format sarif --output report.sarif [--no-llm]
   [--yara-rules-dir DIR]` (cli.py) - exits 1 if risk_score exceeds its own
  threshold (findings present, not a crash) and 2 on a genuine error, so
  `treat_nonzero_exit_as_error=False` here too, matching bandit/osv-scanner.
  SARIF is written to `--output`, NOT printed to stdout - this adapter reads
  that file back from `target_dir` after the process exits (supported by
  `SubprocessEngineAdapter`'s `parse_output(completed, target_dir, files)`
  hook, which hands parsers the same temp dir the engine ran against).

Real SARIF 2.1.0 schema (sarif_models.py, Pydantic-modeled):
  {"version":"2.1.0","runs":[{"tool":{"driver":{"name","version","rules":
   [{"id","shortDescription":{"text"}}]}},"results":[{"ruleId",
   "level":"error"|"warning"|"note","message":{"text"},"locations":
   [{"physicalLocation":{"artifactLocation":{"uri"},"region":{"startLine"}}}],
   }]}]}

SECURITY (INV-14): `OPENAI_BASE_URL` must be set to an internal endpoint
(never a public OpenAI-compatible endpoint) - `make_adapter` requires
callers to pass this explicitly and validates it resolves internally via
`common.config.require_internal_endpoint`, matching every other internal-
endpoint check in this codebase (M2 OIDC/SAML/session settings, M4
intel_sync). "Internal" covers an enterprise's own privatized/on-prem model
deployment just as much as a literal `vLLM` process - the check is about the
network boundary (does this hostname resolve to a private/internal
address), not about which serving stack sits behind it. `api_key` (below)
exists for exactly that case: a privatized deployment that still enforces
its own auth, which is an orthogonal concern to the network boundary and
does not relax it. (2026-07-09 history: a scoped external-host-allowlist
exception briefly lived in `common.config` to point this at DeepSeek's
public cloud API; reverted the same day once the actual requirement turned
out to be an internal enterprise deployment - see that module's own note.)

OSV lookups (osv_client.py, vendored - never patched, per this project's
LICENSE policy) hit `https://api.osv.dev` directly via `httpx.Client(timeout=
...)` with no explicit `trust_env=False`/`proxies=` override - httpx's own
default (`trust_env=True`) means it DOES honor the standard `HTTPS_PROXY`/
`https_proxy` environment variables, confirmed by reading the vendored
source directly rather than assumed. `make_adapter`'s new `osv_proxy_url`
parameter uses exactly this: when provided (validated internal-only via the
same `require_internal_endpoint` check as `openai_base_url`), it's injected
as `HTTPS_PROXY`/`https_proxy` in the subprocess env, so the vendored code's
own OSV calls transparently route through an internal mirror/proxy without
this adapter ever touching `vendor/skillspector/`. `osv_proxy_url` is
OPTIONAL and defaults to `None` (no proxy injected) - if the deployment
doesn't have an internal OSV mirror/proxy to point at, this specific
mitigation stays unconfigured and INV-14 compliance for this one engine then
depends entirely on network-layer egress control (NetworkPolicy/firewall
routing or blocking api.osv.dev), same as before this fix - documented here
rather than silently assumed solved (matches the M4 intel_sync.py honesty
precedent on gaps this project's own code can't close alone). `--no-llm`
only ever avoided the LLM call, never the OSV one; this fix is specifically
about the OSV call.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

from common.config import require_internal_endpoint
from skillscan_core import (
    DetectionCategory,
    EngineCapability,
    EngineMetadata,
    Finding,
    Severity,
)

from .base import SubprocessEngineAdapter

_LEVEL_TO_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
}
_SARIF_OUTPUT_NAME = "report.sarif"

# i18n (2026-07-23): confirmed against the real vendored source (every
# static_patterns_*.py analyzer under vendor/skillspector/src/skillspector/
# nodes/analyzers/) - these are skillspector's own short, fixed `message`
# labels for its static-pattern rule_ids (NOT its LLM-driven semantic
# findings, which generate free English text at runtime with no fixed
# catalog to pre-translate - those fall back to skillspector's own message
# below, same honest-about-the-gap posture as bandit.py's mapping table).
_RULE_ID_TITLES: dict[str, str] = {
    "AS1": "访问 Agent 配置目录",
    "AS2": "访问 MCP 配置",
    "AS3": "枚举其它 Skill",
    "E1": "向外部传输数据",
    "E2": "收集环境变量",
    "E3": "枚举文件系统",
    "E4": "上下文信息泄露",
    "E5": "向云存储外泄数据",
    "EA1": "不受限制的工具访问权限",
    "EA2": "未经确认的自主决策行为",
    "EA3": "权限/职责范围蔓延",
    "EA4": "无边界的资源访问",
    "MP1": "持久化上下文注入",
    "MP2": "上下文窗口填塞攻击",
    "MP3": "记忆篡改",
    "OH1": "未经校验的输出注入",
    "OH2": "跨上下文输出",
    "OH3": "无边界输出",
    "P1": "指令覆盖",
    "P2": "隐藏指令（含 Unicode Tag / ASCII 走私变体）",
    "P3": "数据外泄指令",
    "P4": "行为操纵",
    "P5": "有害内容注入",
    "P6": "直接提取系统提示词",
    "P7": "间接提取系统提示词",
    "P8": "通过工具外泄提示词",
    "PE1": "权限过度",
    "PE2": "以 sudo/root 权限执行",
    "PE3": "访问凭据",
    "PE4": "访问 Docker Socket",
    "PE5": "特权容器/容器逃逸",
    "RA1": "自我修改",
    "RA2": "会话持久化",
    "SC1": "依赖未锁定版本",
    "SC2": "拉取外部脚本",
    "SC3": "混淆代码",
    "TM1": "工具参数滥用",
    "TM2": "工具链式调用滥用",
    "TM3": "不安全的默认配置",
    "TM4": "特权 Kubernetes 工作负载",
    "AR1": "反拒绝话术（诱导模型不要拒绝执行）",
    "AR2": "反拒绝话术（诱导模型不要拒绝执行）",
    "AR3": "反拒绝话术（诱导模型不要拒绝执行）",
    "SSRF1": "访问云元数据服务",
    "SSRF2": "发起内网请求",
    "SSRF3": "动态请求目标（可能被用于 SSRF）",
}
# These rule_ids' real `message` interpolates a package name/CVE/trigger
# word the reader actually needs (e.g. "Known Vulnerable Dependency: httpx
# (CVE-2026-...)") - unlike the fixed labels above, a straight replacement
# would throw away that specific, load-bearing detail. Prefix a Chinese
# category label onto skillspector's own message instead of replacing it.
_TEMPLATED_RULE_ID_PREFIXES: dict[str, str] = {
    "SC4": "已知存在漏洞的依赖",
    "SC5": "已废弃/无人维护的依赖",
    "SC6": "疑似域名抢注式仿冒包名",
    "TR1": "触发词范围过宽",
    "TR2": "触发词与内置命令冲突",
    "TR3": "诱导性关键词触发",
}


# 安全风险描述（2026-07-24）：title 只是短标签（对应 skillspector 静态规则
# 的固定标签），这里针对每个 rule_id 给出具体的攻击面/影响说明，覆盖同一组
# 在真实 vendored 源码中确认存在固定 message 的 rule_id（与 _RULE_ID_TITLES
# 一致）；模板化/LLM 驱动的 rule_id 走 parse_sarif 里的通用兜底，不在此处
# 编造内容。
_RISK_DESCRIPTIONS: dict[str, str] = {
    "AS1": (
        "该 Skill 代码访问了宿主 Agent 的配置目录，可能读取到其他 Skill 的配置、权限声明或敏感设置"
        "，存在越权读取宿主 Agent 内部状态的风险。"
    ),
    "AS2": (
        "该 Skill 代码访问了 MCP（Model Context Protocol）配置，可能获取到其他 MCP 服务器的连接信息"
        "、凭据或工具定义，存在横向越权访问的风险。"
    ),
    "AS3": (
        "该 Skill 代码枚举了宿主环境中安装的其他 Skill，可能被用于侦察攻击面、寻找可利用的其他 Skil"
        "l，或为后续针对性攻击收集情报。"
    ),
    "E1": (
        "该 Skill 代码向外部传输数据，如果传输内容包含用户对话、凭据或本地文件内容，存在数据外泄的"
        "风险；建议核实传输目标和传输内容的必要性。"
    ),
    "E2": (
        "该 Skill 代码收集了环境变量，环境变量中常存放 API 密钥、数据库凭据等敏感信息，收集行为本身"
        "可能是数据外泄链条的第一步。"
    ),
    "E3": (
        "该 Skill 代码枚举了文件系统，可能被用于定位敏感文件（凭据、配置、其他用户数据）作为后续外"
        "泄的前置侦察步骤。"
    ),
    "E4": (
        "该 Skill 代码存在上下文信息泄露：可能把宿主 Agent 的系统提示词、对话历史或其他 Skill 的上"
        "下文内容意外暴露给外部或非预期的接收方。"
    ),
    "E5": (
        "该 Skill 代码向云存储服务外泄数据，如果上传内容包含用户敏感信息，攻击者控制的云存储目标将"
        "持续获得数据外泄的能力。"
    ),
    "EA1": (
        "该 Skill 声明或实现了不受限制的工具访问权限，一旦被滥用或遭受提示注入攻击，可被诱导调用任"
        "意工具执行超出预期范围的操作。"
    ),
    "EA2": (
        "该 Skill 存在未经用户确认即执行自主决策行为的模式，缺乏人工把关环节，一旦决策逻辑被误导或"
        "攻击，后果无法被及时拦截。"
    ),
    "EA3": (
        "该 Skill 存在权限/职责范围蔓延（scope creep）：其实际行为超出了名义功能所需的最小权限范围"
        "，扩大了潜在的攻击面和误用空间。"
    ),
    "EA4": (
        "该 Skill 存在无边界的资源访问：对文件、网络、系统资源等的访问缺乏明确的范围限制，一旦被滥"
        "用可能波及预期范围之外的资源。"
    ),
    "MP1": (
        "该 Skill 涉嫌持久化上下文注入：试图将恶意指令写入会被跨会话/跨任务持续加载的记忆或上下文存"
        "储中，实现一次注入、长期生效的攻击。"
    ),
    "MP2": (
        "该 Skill 涉嫌上下文窗口填塞攻击：通过灌入大量无关或误导性内容占满上下文窗口，挤出真正的系"
        "统指令或安全约束，操纵模型后续行为。"
    ),
    "MP3": (
        "该 Skill 涉嫌记忆篡改：试图修改、覆盖或污染 Agent 已持久化的记忆内容，使其在未来的交互中基"
        "于被篡改的错误信息做出决策。"
    ),
    "OH1": (
        "该 Skill 存在未经校验的输出注入：把不可信的外部内容未经清理地混入模型输出或后续处理流程，"
        "可能夹带隐藏指令影响下游处理逻辑。"
    ),
    "OH2": (
        "该 Skill 存在跨上下文输出：把一个上下文/会话中的内容不加区分地带入另一个上下文，可能造成信"
        "息串扰或跨用户的数据泄露。"
    ),
    "OH3": (
        "该 Skill 存在无边界输出：对模型或工具的输出内容缺乏格式/范围校验，可能被用于绕过下游系统对"
        "输出内容的安全假设。"
    ),
    "P1": (
        "该 Skill 内容试图覆盖/替换宿主 Agent 此前的系统指令，属于直接提示词注入攻击的典型手法，可"
        "能劫持 Agent 的行为逻辑。"
    ),
    "P2": (
        "该 Skill 内容中检测到隐藏指令（含 Unicode Tag 或 ASCII 走私变体等隐写手法），这类指令对人"
        "类审查者不可见，但可能被模型正常解析执行，是极具隐蔽性的提示词注入手法。"
    ),
    "P3": (
        "该 Skill 内容包含试图诱导模型外泄数据的指令，可能诱使 Agent 把对话历史、系统提示词或其他敏"
        "感上下文回传给攻击者控制的位置。"
    ),
    "P4": (
        "该 Skill 内容包含试图操纵模型行为的指令，可能诱导 Agent 偏离用户真实意图，执行攻击者预设的"
        "行为。"
    ),
    "P5": (
        "该 Skill 内容包含有害内容注入，试图诱导模型生成违反使用政策、危害用户或第三方的输出内容。"
    ),
    "P6": (
        "该 Skill 内容包含试图直接提取宿主 Agent 系统提示词的指令，一旦得逞将暴露该 Agent 的内部配"
        "置、安全策略和业务逻辑细节。"
    ),
    "P7": (
        "该 Skill 内容包含试图间接提取宿主 Agent 系统提示词的指令（如诱导模型复述/总结/翻译其指令）"
        "，比直接提取更隐蔽，同样会暴露内部配置。"
    ),
    "P8": (
        "该 Skill 内容包含试图通过调用工具间接外泄系统提示词的指令，利用工具调用的副作用（如写入文"
        "件、发起请求）把提示词内容带出模型上下文。"
    ),
    "PE1": (
        "该 Skill 声明或请求了过度的权限，超出其实际功能所需的最小权限范围，一旦被滥用或攻破，影响"
        "面会远大于其本职功能所需。"
    ),
    "PE2": (
        "该 Skill 以 sudo/root 等特权身份执行，一旦其逻辑存在漏洞或被恶意利用，攻击者可直接获得系统"
        "级权限，后果远比普通用户权限严重。"
    ),
    "PE3": (
        "该 Skill 代码访问了凭据（密钥、令牌、密码等），如果访问行为超出其功能所需范围，存在凭据被"
        "滥用或进一步外泄的风险。"
    ),
    "PE4": (
        "该 Skill 代码访问了 Docker Socket，这等同于获得宿主机的完整控制权（可创建特权容器挂载宿主"
        "文件系统），是极高危的容器逃逸攻击面。"
    ),
    "PE5": (
        "该 Skill 涉及特权容器或容器逃逸手法，一旦得逞可突破容器隔离边界，直接威胁宿主机或整个集群"
        "的安全。"
    ),
    "RA1": (
        "该 Skill 存在自我修改行为：运行时修改自身或其他 Skill 的代码/配置，可能被用于持久化恶意逻"
        "辑或规避基于静态内容的安全检测。"
    ),
    "RA2": (
        "该 Skill 存在会话持久化行为：试图在正常会话结束后仍保持某种形式的存在或影响力（如后台任务"
        "、定时触发），扩大了潜在的持续性风险。"
    ),
    "SC1": (
        "该 Skill 依赖未锁定版本的第三方组件，实际安装的版本可能在发布后被替换为包含漏洞或恶意代码"
        "的新版本（依赖混淆/投毒风险），建议锁定精确版本并校验哈希。"
    ),
    "SC2": (
        "该 Skill 运行时从外部拉取脚本执行，脚本内容不受 Skill 包本身的审查覆盖，如果拉取源被劫持或"
        "本身恶意，等同于引入了未经审查的任意代码执行入口。"
    ),
    "SC3": (
        "该 Skill 代码经过混淆处理，混淆本身会显著增加安全审查和逆向分析的难度，是恶意软件常用的规"
        "避检测手法，即使功能本身无害也应人工核查混淆的必要性。"
    ),
    "TM1": (
        "该 Skill 存在工具参数滥用：向宿主 Agent 的工具传递了超出预期范围或语义异常的参数，可能被用"
        "于触发工具的非预期行为。"
    ),
    "TM2": (
        "该 Skill 存在工具链式调用滥用：通过组合多个工具的调用顺序绕过单个工具自身的安全限制，达成"
        "任一工具单独调用都无法完成的危险操作。"
    ),
    "TM3": (
        "该 Skill 使用了不安全的默认配置，在未显式加固的情况下暴露了不必要的功能或权限，扩大了攻击"
        "面。"
    ),
    "TM4": (
        "该 Skill 涉及特权 Kubernetes 工作负载配置，一旦被滥用可能突破 Pod 隔离边界，威胁整个集群的"
        "安全（等同于容器逃逸风险在编排层面的体现）。"
    ),
    "AR1": (
        "该 Skill 内容包含反拒绝话术，试图诱导模型不要拒绝执行请求（即使该请求违反安全策略），是绕"
        "过模型自身安全对齐机制的常见手法。"
    ),
    "AR2": (
        "该 Skill 内容包含反拒绝话术，试图诱导模型不要拒绝执行请求（即使该请求违反安全策略），是绕"
        "过模型自身安全对齐机制的常见手法。"
    ),
    "AR3": (
        "该 Skill 内容包含反拒绝话术，试图诱导模型不要拒绝执行请求（即使该请求违反安全策略），是绕"
        "过模型自身安全对齐机制的常见手法。"
    ),
    "SSRF1": (
        "该 Skill 代码访问了云元数据服务（如 169.254.169.254），这类端点常常无需额外认证即可返回云"
        "实例的临时凭据、角色权限等高度敏感信息，是云环境下最常见的 SSRF 利用目标之一。"
    ),
    "SSRF2": (
        "该 Skill 代码发起了指向内网地址的请求，如果请求目标可被外部输入控制，攻击者可借此探测或访"
        "问部署环境内网中原本不可直接从外部访问的服务（服务端请求伪造）。"
    ),
    "SSRF3": (
        "该 Skill 代码的请求目标地址是动态构造的，如果构造过程中包含未经校验的外部输入，可能被用于"
        "发起 SSRF 攻击，实际风险取决于目标地址的可控范围，需人工核查。"
    ),
}


def _title_for(rule_id: str, message: str) -> str:
    if rule_id in _RULE_ID_TITLES:
        return _RULE_ID_TITLES[rule_id]
    if rule_id in _TEMPLATED_RULE_ID_PREFIXES:
        return f"{_TEMPLATED_RULE_ID_PREFIXES[rule_id]}：{message}" if message else rule_id
    return message[:200] if message else rule_id


def _metadata(*, ruleset_digest: str, version: str) -> EngineMetadata:
    return EngineMetadata(
        name="skillspector",
        version=version,
        ruleset_digest=ruleset_digest,
        capabilities=frozenset({EngineCapability.STATIC, EngineCapability.SEMANTIC_LLM}),
        requires_llm=True,
    )


class _ArgvBuilder:
    def __init__(self, *, use_llm: bool) -> None:
        self._use_llm = use_llm

    def __call__(self, target_dir: Path) -> list[str]:
        argv = [
            "skillspector",
            "scan",
            str(target_dir),
            "--format",
            "sarif",
            "--output",
            str(target_dir / _SARIF_OUTPUT_NAME),
        ]
        if not self._use_llm:
            argv.append("--no-llm")
        return argv


def _category_for_rule_id(rule_id: str) -> DetectionCategory:
    # SECURITY: unmapped SARIF ruleId prefixes fall back to INSTRUCTION (Cat-1),
    # skillspector's primary focus per the coding spec ("大部分 Cat-1..6" -
    # mostly categories 1-6, with instruction-layer prompt-injection detection
    # as its hallmark capability).
    lowered = rule_id.lower()
    for keyword, category in (
        ("inject", DetectionCategory.INSTRUCTION),
        ("credential", DetectionCategory.DATA_CREDENTIAL),
        ("secret", DetectionCategory.DATA_CREDENTIAL),
        ("network", DetectionCategory.NETWORK_INTEL),
        ("exfil", DetectionCategory.NETWORK_INTEL),
        ("permission", DetectionCategory.PERMISSION),
        ("privilege", DetectionCategory.PERMISSION),
        ("sandbox", DetectionCategory.PERMISSION),
        ("supply", DetectionCategory.SUPPLY_CHAIN),
        ("depend", DetectionCategory.SUPPLY_CHAIN),
    ):
        if keyword in lowered:
            return category
    return DetectionCategory.INSTRUCTION


def parse_sarif(sarif_bytes: bytes) -> tuple[Finding, ...]:
    payload = json.loads(sarif_bytes)  # SECURITY: malformed SARIF -> raises -> caller fail-closes
    if not isinstance(payload, dict) or "runs" not in payload:
        raise ValueError("skillspector output missing SARIF 'runs' key")

    findings: list[Finding] = []
    for run in payload["runs"]:
        for result in run.get("results", []):
            rule_id = str(result.get("ruleId", "unknown"))
            level = str(result.get("level", "warning"))
            message = str(result.get("message", {}).get("text", ""))
            locations = result.get("locations", [])
            file_path: str | None = None
            start_line: int | None = None
            if locations:
                physical = locations[0].get("physicalLocation", {})
                file_path = physical.get("artifactLocation", {}).get("uri")
                start_line = physical.get("region", {}).get("startLine")

            findings.append(
                Finding(
                    rule_id=f"skillspector.{rule_id}",
                    test_item_id=rule_id,
                    category=_category_for_rule_id(rule_id),
                    title=_title_for(rule_id, message),
                    severity=_LEVEL_TO_SEVERITY.get(level, Severity.MEDIUM),
                    confidence=0.75,
                    source_engine="skillspector",
                    source_capability=EngineCapability.SEMANTIC_LLM,
                    file_path=file_path,
                    start_line=start_line,
                    snippet_hash=hashlib.sha256(message.encode("utf-8")).hexdigest()
                    if message
                    else None,
                    # 安全风险描述 (2026-07-24): `_RISK_DESCRIPTIONS` gives a
                    # genuine risk explanation for every rule_id with a fixed
                    # message (same set `_RULE_ID_TITLES` covers); templated/
                    # LLM-driven rule_ids fall back to skillspector's own raw
                    # message, same honest-about-the-gap posture as bandit.py.
                    evidence_redacted=_RISK_DESCRIPTIONS.get(rule_id) or message[:200],
                )
            )
    return tuple(findings)


def parse_output(
    _completed: subprocess.CompletedProcess[bytes], target_dir: Path, _files: dict[str, bytes]
) -> tuple[Finding, ...]:
    sarif_path = target_dir / _SARIF_OUTPUT_NAME
    if not sarif_path.is_file():
        raise ValueError(f"skillspector did not write the expected SARIF file at {sarif_path}")
    return parse_sarif(sarif_path.read_bytes())


def make_adapter(
    *,
    openai_base_url: str,
    ruleset_digest: str,
    version: str,
    use_llm: bool = True,
    osv_proxy_url: str | None = None,
    api_key: str | None = None,
) -> SubprocessEngineAdapter:
    # SECURITY (Finding #16): validated once here (fail fast on an obviously-
    # bad config at startup), but the REAL, load-bearing check is inside
    # _build_env() below, which re-runs on every subprocess spawn - this
    # subprocess is a separate OS process doing its own DNS resolution, so a
    # startup-time-only validation (like the rest of this file used to do)
    # leaves the endpoint trusted, unchecked, for the adapter's entire
    # lifetime (make_adapter() is called exactly once per process, at
    # services/engine_runner/main.py startup, not per-scan).
    require_internal_endpoint(openai_base_url, field_name="skillspector.openai_base_url")
    if osv_proxy_url is not None:
        require_internal_endpoint(osv_proxy_url, field_name="skillspector.osv_proxy_url")

    def _build_env() -> dict[str, str]:
        # SECURITY (Finding #16): re-validated on every call (i.e. immediately
        # before every subprocess spawn) rather than once at adapter
        # construction - raises ValueError (caught by base.py's analyze() and
        # turned into a fail-closed EngineStatus.ERROR) if the endpoint no
        # longer resolves internally, instead of trusting the startup-time
        # check forever.
        require_internal_endpoint(openai_base_url, field_name="skillspector.openai_base_url")
        # CORRECTNESS: confirmed live - `subprocess.run(..., env=X)` REPLACES
        # the child's entire environment with X, it does not merge/overlay X
        # onto the parent's environment (unlike `env=None`, which
        # bandit/osv/yara's adapters all use and which inherits the parent's
        # env, PATH included). This dict previously had no PATH at all, so
        # `subprocess.run(["skillspector", ...])` could never find the binary
        # via PATH search - it failed with `FileNotFoundError: [Errno 2] No
        # such file or directory: 'skillspector'`, identical to the
        # "genuinely missing binary" case, even though the exact same binary
        # ran fine when invoked directly via a shell (which inherits the
        # container's real PATH). Only PATH is carried over from the parent
        # (not a blanket `os.environ` spread).
        env = {
            "PATH": os.environ.get("PATH", ""),
            "OPENAI_BASE_URL": openai_base_url,
            "SKILLSPECTOR_PROVIDER": "openai",
        }
        if api_key is not None:
            # SECURITY (INV-10 NOTE, superseding the old "no secrets to leak"
            # claim this env dict used to carry): once `api_key` is set, this
            # process holds a real credential - added 2026-07-09 for
            # enterprise privatized-model deployments that enforce their own
            # auth even on an internal network (unauthenticated internal
            # vLLM, this codebase's original assumption, doesn't need this at
            # all - pass None and no OPENAI_API_KEY is set). Still a real, if
            # smaller, blast-radius consideration: engine-runner is
            # architecturally the only place that can make this call
            # (INV-11: the monolith never parses untrusted content), so any
            # credential the LLM call needs has to live here regardless.
            env["OPENAI_API_KEY"] = api_key
        if osv_proxy_url is not None:
            # SECURITY (INV-14): vendored osv_client.py's httpx.Client
            # defaults to trust_env=True (confirmed by reading the vendored
            # source - it never overrides this), so it honors HTTPS_PROXY -
            # this routes its api.osv.dev calls through an internal
            # mirror/proxy without ever touching vendored code. Both casings
            # set since proxy-env-var casing conventions vary by
            # library/platform and this must not silently no-op if httpx's
            # proxy resolution prefers one over the other.
            require_internal_endpoint(osv_proxy_url, field_name="skillspector.osv_proxy_url")
            env["HTTPS_PROXY"] = osv_proxy_url
            env["https_proxy"] = osv_proxy_url
        return env

    return SubprocessEngineAdapter(
        metadata=_metadata(ruleset_digest=ruleset_digest, version=version),
        build_argv=_ArgvBuilder(use_llm=use_llm),
        parse_output=parse_output,
        env=_build_env,
        treat_nonzero_exit_as_error=False,
    )
