"""IOC matcher (coding spec §11.4 INTEL-01/02/03, SRS Cat-4 "恶意域名/恶意IP/恶意
文件MD5").

2026-07-27：原标签 NET-06/07/08 与检测目录不符——NET-06/07/08 在检测目录里分别是
「SSRF」「下载并执行」「下载行为」，都不是威胁情报匹配；本模块实际对应的是
D1 威胁情报匹配 INTEL-01（恶意文件命中情报）/INTEL-02（恶意域名）/INTEL-03（恶意
IP），已修正。

SECURITY: matches Skill content against the LOCAL `threat_indicator` table
only - no outbound lookup, no live threat-intel API call (coding spec: "无出
站"). Indicators arrive via `services/intel_sync` (offline signed import) or
M6's marketplace sync; this module only ever reads.

`DetectionEngine.analyze()` is a synchronous Protocol method (coding spec
§5.5), but matching needs an async DB read - resolved the same way
`skillscan_core.MockLLMEngine` handles canned data: `IntelMatcher` is
constructed with an already-fetched `known_iocs` snapshot (see
`load_known_iocs`), so `analyze()` itself does pure in-memory matching with no
I/O. SECURITY: if `load_known_iocs` itself fails (table unreachable), the
caller must NOT construct an `IntelMatcher` and silently proceed with an
empty set - use `orchestration.aggregate.unavailable_engine_result` instead,
so a required-engine failure here fail-closes exactly like any other (INV-1),
rather than silently matching against nothing.
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
    TrifectaSignal,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import ThreatIndicator

_CATEGORY = DetectionCategory.NETWORK_INTEL

_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")

_EXTRACTORS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("domain", _DOMAIN_RE),
    ("ip", _IPV4_RE),
    ("md5", _MD5_RE),
)

# 2026-07-27：原标签与检测目录不符（NET-06/07/08 实际是 SSRF/下载并执行/下载行为），
# 修正为 D1 威胁情报匹配条目：domain→INTEL-02（恶意域名），ip→INTEL-03（恶意IP），
# md5→INTEL-01（恶意文件命中情报）。
_TEST_ITEM_ID_BY_IOC_TYPE = {"domain": "INTEL-02", "ip": "INTEL-03", "md5": "INTEL-01"}

# i18n + 安全风险描述（2026-07-24）：BUG 修复——这两处此前一直是未翻译的英文
# 占位文本（2026-07-23 的中文化提交遗漏了本文件）。IOC 具体值受 INV-9 约束不能
# 展示，这里按情报类型给出固定的风险说明。
_TITLE_BY_IOC_TYPE = {
    "domain": "命中已知恶意域名情报",
    "ip": "命中已知恶意 IP 情报",
    "md5": "命中已知恶意文件 MD5 情报",
}
_RISK_DESCRIPTION_BY_IOC_TYPE = {
    "domain": (
        "该 Skill 内容中出现的域名与本地维护的已知恶意域名情报库精确匹配，"
        "通常意味着存在与已知 C2（命令与控制）服务器、钓鱼站点或恶意软件"
        "分发站点的关联；这是高置信度的威胁情报命中，而非启发式猜测，"
        "建议按事件响应流程处理，而不仅仅是常规审查。"
    ),
    "ip": (
        "该 Skill 内容中出现的 IP 地址与本地维护的已知恶意 IP 情报库精确匹配，"
        "通常意味着存在与已知 C2 服务器、扫描/攻击源或恶意基础设施的关联；"
        "这是高置信度的威胁情报命中，而非启发式猜测，建议按事件响应流程处理。"
    ),
    "md5": (
        "该 Skill 内容中出现的文件 MD5 哈希与本地维护的已知恶意文件情报库精确"
        "匹配，通常意味着 Skill 包内捆绑或引用了已被确认的恶意软件样本；"
        "这是高置信度的威胁情报命中，而非启发式猜测，建议按事件响应流程处理。"
    ),
}


async def load_known_iocs(session: AsyncSession) -> frozenset[tuple[str, str]]:
    """SECURITY: caller must run this against a session authorized to SELECT
    `threat_indicator` (svc_intel's grant) - read-only, no I/O side effects."""
    rows = (await session.execute(select(ThreatIndicator))).scalars().all()
    return frozenset((row.ioc_type, row.ioc_value.lower()) for row in rows)


# The intel matcher's engine name, exported rather than left as a literal
# inside `_metadata` below: it is a THIRD engine tier (neither floor nor
# sandbox), and every consumer that needs "every engine name this deployment
# knows" - the admin listing and toggle above all - previously had no way to
# name it without constructing an `IntelMatcher`, which needs a DB-fetched IOC
# snapshot. That is exactly why `/v1/admin/engines` omitted it and PATCHing it
# 404'd (milestone C Task 2, 2026-07-29).
INTEL_ENGINE_NAME = "inhouse-intel-matcher"
INTEL_ENGINE_VERSION = "1.0.0"
INTEL_ENGINE_CAPABILITIES = frozenset({EngineCapability.STATIC, EngineCapability.THREAT_INTEL})


def _metadata(known_ioc_count: int) -> EngineMetadata:
    return EngineMetadata(
        name=INTEL_ENGINE_NAME,
        version=INTEL_ENGINE_VERSION,
        # SECURITY (INV-6/7 staleness): the digest binds the SIZE of the
        # loaded indicator snapshot, so a toolchain_digest computed with a
        # stale/empty snapshot is distinguishable from one with real coverage
        # - a scan re-run after new IOCs are imported gets a different digest
        # and is never served a stale cached verdict.
        ruleset_digest=hashlib.sha256(f"threat_indicator:{known_ioc_count}".encode()).hexdigest(),
        capabilities=INTEL_ENGINE_CAPABILITIES,
    )


class IntelMatcher:
    """`DetectionEngine` Protocol implementation (skillscan_core.DetectionEngine).
    See module docstring on why `known_iocs` is injected rather than fetched
    inside `analyze()`."""

    def __init__(self, *, known_iocs: frozenset[tuple[str, str]]) -> None:
        self._known_iocs = known_iocs

    @property
    def metadata(self) -> EngineMetadata:
        return _metadata(len(self._known_iocs))

    def analyze(self, files: dict[str, bytes], *, deadline: float | None = None) -> EngineResult:
        findings: list[Finding] = []
        for path, data in files.items():
            text = data.decode("utf-8", errors="replace")
            for line_no, line in enumerate(text.splitlines(), start=1):
                for ioc_type, pattern in _EXTRACTORS:
                    for match in pattern.finditer(line):
                        value = match.group(0).lower()
                        if (ioc_type, value) not in self._known_iocs:
                            continue
                        findings.append(
                            Finding(
                                rule_id=f"intel.ioc_match_{ioc_type}",
                                test_item_id=_TEST_ITEM_ID_BY_IOC_TYPE[ioc_type],
                                category=_CATEGORY,
                                title=_TITLE_BY_IOC_TYPE[ioc_type],
                                severity=Severity.CRITICAL,
                                confidence=0.9,
                                source_engine="inhouse-intel-matcher",
                                source_capability=EngineCapability.THREAT_INTEL,
                                trifecta_signals=frozenset({TrifectaSignal.EXTERNAL_EGRESS}),
                                file_path=path,
                                start_line=line_no,
                                snippet_hash=hashlib.sha256(match.group(0).encode()).hexdigest(),
                                evidence_redacted=_RISK_DESCRIPTION_BY_IOC_TYPE[ioc_type],
                            )
                        )
        return EngineResult(
            engine=self.metadata,
            findings=tuple(findings),
            status=EngineStatus.OK,
            scan_mode=ScanMode.STATIC,
            llm_used=False,
        )
