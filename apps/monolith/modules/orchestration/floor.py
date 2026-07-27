"""Floor-engine wiring (coding spec §11.4 O-1, INV-1 backstop).

SECURITY: every engine here is a pure byte/regex matcher with zero external
dependencies - no network, no subprocess, no LLM, no sandboxed OSS tool. They
exist so that even if every sandboxed engine (M5) is compromised, degraded, or
returns empty findings under adversarial pressure, the system still has a
byte-level detection floor that cannot itself be suppressed the same way.
`floor_engine_names()` is meant to be unioned into `GatePolicy.required_engines`
unconditionally by whoever builds a policy - this module does not enforce
that itself (policy construction is `main.py`'s/M6 policy-as-code's job), it
only defines what belongs in the floor set.

`IntelMatcher` (coding spec's INTEL-01/02/03, corrected 2026-07-27 from the
previously mislabelled NET-06/07/08) is deliberately NOT part of the floor:
unlike these, it needs a DB-fetched IOC snapshot at construction time (see
`modules.intel.matcher`), so it can't be built from zero arguments the way
every floor engine can.
"""

from __future__ import annotations

from engine_runner.detectors.crypto_weak import CryptoWeakDetector
from engine_runner.detectors.file_type import FileTypeDetector
from engine_runner.detectors.jailbreak_inducement_zh import JailbreakInducementZhDetector
from engine_runner.detectors.mcp_config import McpConfigDetector
from engine_runner.detectors.pii import PiiDetector
from engine_runner.detectors.prompt_injection_zh import PromptInjectionZhDetector
from engine_runner.detectors.skill_permissions import SkillPermissionsDetector
from engine_runner.detectors.toctou import TocTouDetector
from skillscan_core import DetectionEngine, StaticKeywordEngine


def floor_engines() -> dict[str, DetectionEngine]:
    """Fresh instances each call (all floor engines are stateless/frozen), keyed
    by `engine.metadata.name` - the same keying `GatePolicy.required_engines`
    and `orchestration.service.submit_scan`'s `engine_metadatas` use."""
    instances: tuple[DetectionEngine, ...] = (
        StaticKeywordEngine(),
        CryptoWeakDetector(),
        FileTypeDetector(),
        PiiDetector(),
        TocTouDetector(),
        PromptInjectionZhDetector(),  # PROMPT-01 中文直接提示词注入
        JailbreakInducementZhDetector(),  # PROMPT-04 中文诱导提示/越权话术
        # 随包 .mcp.json 检测(Cat-8)。注释曾写 "MCP-01/02" - 809c550(2026-07-27)
        # 校正后各规则实际归属 CODE-01/MCP-04/CRED-04/GEN-01(详见
        # mcp_config.py 自身的 _TEST_ITEM_IDS 与其模块文档字符串)。
        McpConfigDetector(),
        SkillPermissionsDetector(),  # Cat-5 PERM-* SKILL.md 权限声明
    )
    return {engine.metadata.name: engine for engine in instances}


def floor_engine_names() -> frozenset[str]:
    return frozenset(floor_engines().keys())
