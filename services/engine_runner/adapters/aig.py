"""Tencent AI-Infra-Guard `mcp-scan` adapter (vendor/aig, Apache-2.0).

Based on Tencent Zhuque Lab AI-Infra-Guard - https://github.com/Tencent/AI-Infra-Guard
(NOTICE file, Apache License 2.0 §4(d): mandatory attribution, satisfied by
this docstring + the credit in vendor/engines.lock.yaml).

Real CLI/output confirmed by reading `vendor/aig/mcp-scan/` directly, not
guessed:
  `python main.py --repo <dir> --base_url <url> --model <name> --language
   zh` (main.py's argparse) plus an `OPENROUTER_API_KEY` environment
  variable for the API key. There is NO `--no-llm`/static mode anywhere in
  this tool, unlike skillspector - `main.py` calls `sys.exit(1)` immediately
  if no API key is resolvable (env or --api_key), before touching the target
  directory at all. This is architecturally different from every other
  adapter in this package: skillspector/bandit/osv-scanner/yara all produce
  *some* real, deterministic findings with zero network access; AIG's
  mcp-scan produces zero findings without a live LLM call, full stop.
  `make_adapter` below still enforces INV-14 the same way skillspector.py
  does (`require_internal_endpoint` on `base_url`) - AIG's own `--base_url`
  flag defaults to OpenRouter's public API but is fully overridable
  (confirmed in `mcp-scan/utils/llm_manager.py`), so pointing it at an
  internal endpoint - including an enterprise's own privatized model
  deployment, not just a literal `vLLM` process - is a supported, not a
  forced, use. (2026-07-09 history: a scoped external-allowlist exception
  briefly lived here for DeepSeek's public API; reverted the same day once
  the actual requirement turned out to be an internal deployment - see
  `common.config`'s own note.)

The API key is a required non-empty string but vLLM deployments that don't
enforce authentication (the same trust model skillspector.py's adapter
already assumes - it sets no Authorization header at all) will accept any
non-empty value; `_PLACEHOLDER_API_KEY` documents that this is intentional,
not a stray secret. SECURITY (fixed 2026-07-10): this key is passed via the
`OPENROUTER_API_KEY` subprocess env var, NOT `--api_key` argv - confirmed by
reading main.py's own arg handling
(`api_key = args.api_key or os.environ.get("OPENROUTER_API_KEY")`, ~line
107), which natively supports the env-var path. Putting a real credential in
argv is readable by any local process/user via `ps aux`/`/proc/<pid>/cmdline`;
this adapter previously did exactly that (an argv `--api_key` flag) and has
been corrected to match skillspector.py's `OPENAI_API_KEY`-via-env precedent
for the exact same class of exposure.

Real output format confirmed by reading `mcp-scan/utils/extract_vuln.py`
(the tool's OWN parser for its OWN LLM output) and `utils/loging.py`:
  - the final result is logged via `logger.info(...)`, and `loging.py`
    configures loguru's console sink to `sys.stderr` (INFO level) - so this
    adapter parses `completed.stderr`, not `completed.stdout` (main.py never
    calls a bare `print()` for its actual findings, only for a
    KeyboardInterrupt/exception message).
  - findings are `<vuln>` blocks, each containing `<title>`, `<desc>`,
    `<risk_type>`, `<level>`, `<suggestion>` tags (parsed here with the same
    field set and same non-greedy-DOTALL regex approach as
    `extract_vuln.py`'s own `VulnerabilityExtractor` - re-implemented rather
    than imported, per INV-15's subprocess-only boundary: this adapter never
    imports vendored source).

i18n (2026-07-23, confirmed - no code change needed here): unlike bandit/
skillspector/osv-scanner, whose `title`/`evidence_redacted` needed an
in-adapter Chinese lookup table or template rewrite (those tools have no
concept of an output language), AIG's `<title>`/`<desc>` are LLM-generated
free text from mcp-scan's OWN process, which this adapter already invokes
with `--language zh` (`_ArgvBuilder.__call__` below, confirmed against
`vendor/aig/mcp-scan/main.py`'s `--language` flag - "Output language",
default "zh", threaded into the prompt the LLM itself receives) - so these
fields are already Chinese at the source, not something this parsing code
could retroactively translate even if it needed to. `_KEYWORD_RULES` below
already carries Chinese keywords alongside English ones for exactly this
reason.

test_item_id mapping (SECURITY/CORRECTNESS): unlike skillspector.py's
`test_item_id=rule_id` passthrough - confirmed this session to be the root
of a systemic compliance-reporting gap (real findings invisible to any
report keyed on the xlsx checklist's own IDs) - this adapter classifies each
`<vuln>` into a specific checklist test_item_id from day one, via keyword
matching against `risk_type`+`title` (mirroring skillspector.py's
`_category_for_rule_id` shape, but targeting a precise item id instead of a
coarse category). Falls back to GEN-01 - the checklist's own explicit
"LLM-generalization catch-all, specific items take precedence when matched"
role (企业Skill安全评估测试维度清单.xlsx, D10) - for anything that doesn't
match a more specific keyword, since mcp-scan's findings are themselves
free-text LLM judgment, not fixed rule IDs a lookup table could key on.
"""

from __future__ import annotations

import hashlib
import os
import re
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

# SECURITY: not a real credential - documented above (module docstring) as a
# deliberate placeholder for vLLM deployments that don't enforce auth, same
# trust model as skillspector.py's adapter (which sends no Authorization
# header at all). This constant is a hardcoded literal, never read FROM this
# process's own environment - if a deployment's internal endpoint DOES
# require a real key, that value must flow in via `make_adapter(api_key=...)`,
# not this constant. (It still ends up written INTO the child subprocess's
# `OPENROUTER_API_KEY` env var either way - see make_adapter - which is fine
# precisely because it isn't a real secret.)
_PLACEHOLDER_API_KEY = "internal-vllm-no-auth-enforced"

_VULN_BLOCK_RE = re.compile(r"<vuln>\s*(.*?)\s*</vuln>", re.DOTALL)


def _extract_tag(block: str, tag: str) -> str | None:
    match = re.search(rf"<{tag}>\s*(.*?)\s*</{tag}>", block, re.DOTALL)
    return match.group(1).strip() if match else None


_LEVEL_TO_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}

# (keywords checked against "risk_type title" lowercased, in priority order -
# first match wins) -> (test_item_id, DetectionCategory). Ordered most-
# specific-first so e.g. "mcp tool description" doesn't fall through to a
# generic "tool" match under a less precise id.
_KEYWORD_RULES: tuple[tuple[tuple[str, ...], str, DetectionCategory], ...] = (
    (
        ("tool poisoning", "tool description", "hidden instruction", "工具描述投毒", "隐藏指令"),
        "MCP-01",
        DetectionCategory.INSTRUCTION,
    ),
    (("impersonat", "typosquat", "冒充", "仿冒"), "MCP-02", DetectionCategory.SUPPLY_CHAIN),
    (
        ("cross-server", "cross server", "cross-domain", "跨域", "跨server"),
        "MCP-03",
        DetectionCategory.PERMISSION,
    ),
    (
        ("server config", "tls", "https", "unauthenticated", "server卫生", "配置卫生"),
        "MCP-04",
        DetectionCategory.PERMISSION,
    ),
    (
        ("behavior", "description mismatch", "行为与描述", "行为不符"),
        "PROMPT-05",
        DetectionCategory.INSTRUCTION,
    ),
    (
        ("credential", "token", "secret", "api key", "凭据", "令牌", "密钥泄露"),
        "CRED-04",
        DetectionCategory.DATA_CREDENTIAL,
    ),
    (
        ("command injection", "code injection", "rce", "命令注入", "代码注入"),
        "CODE-01",
        DetectionCategory.CODE,
    ),
    (("deserializ", "反序列化"), "CODE-07", DetectionCategory.CODE),
    (
        ("path traversal", "arbitrary file", "路径穿越", "任意文件"),
        "FILE-04",
        DetectionCategory.FILE_PACKAGE,
    ),
    (("ssrf", "server-side request forgery"), "NET-06", DetectionCategory.NETWORK_INTEL),
    (("exfil", "外传", "外泄"), "NET-04", DetectionCategory.NETWORK_INTEL),
)


def _classify(risk_type: str, title: str) -> tuple[str, DetectionCategory]:
    haystack = f"{risk_type} {title}".lower()
    for keywords, test_item_id, category in _KEYWORD_RULES:
        if any(kw in haystack for kw in keywords):
            return test_item_id, category
    # SECURITY: GEN-01 is the checklist's own designated fallback for
    # LLM-generalized findings that don't match a specific item (D10) - not
    # a made-up bucket. mcp-scan's output is ALWAYS free-text LLM judgment,
    # so an unmatched finding here is exactly what GEN-01 exists to hold.
    return "GEN-01", DetectionCategory.INSTRUCTION


def _metadata(*, ruleset_digest: str, version: str) -> EngineMetadata:
    return EngineMetadata(
        name="aig-mcp-scan",
        version=version,
        ruleset_digest=ruleset_digest,
        capabilities=frozenset({EngineCapability.SEMANTIC_LLM}),
        requires_llm=True,
    )


class _ArgvBuilder:
    def __init__(self, *, interpreter: str, script: str, base_url: str, model: str) -> None:
        self._interpreter = interpreter
        self._script = script
        self._base_url = base_url
        self._model = model

    def __call__(self, target_dir: Path) -> list[str]:
        return [
            self._interpreter,
            self._script,
            "--repo",
            str(target_dir),
            "--base_url",
            self._base_url,
            "--model",
            self._model,
            "--language",
            "zh",
        ]


def parse_stderr(stderr: bytes) -> tuple[Finding, ...]:
    text = stderr.decode("utf-8", errors="replace")
    findings: list[Finding] = []
    for block in _VULN_BLOCK_RE.findall(text):
        title = _extract_tag(block, "title")
        desc = _extract_tag(block, "desc")
        risk_type = _extract_tag(block, "risk_type")
        level = _extract_tag(block, "level") or "medium"
        if not title or not desc or not risk_type:
            # SECURITY: mirrors extract_vuln.py's own "skip incomplete block"
            # behavior - a partial/malformed <vuln> block is dropped, not
            # guessed at, but does NOT fail the whole parse (other blocks in
            # the same run may still be well-formed).
            continue

        test_item_id, category = _classify(risk_type, title)
        findings.append(
            Finding(
                rule_id=f"aig.{risk_type.lower().replace(' ', '_')}",
                test_item_id=test_item_id,
                category=category,
                title=title[:200],
                severity=_LEVEL_TO_SEVERITY.get(level.lower(), Severity.MEDIUM),
                confidence=0.6,  # SECURITY: LLM-judgment finding, deliberately below the
                # ~0.7-0.95 range used by this codebase's deterministic
                # pattern/AST detectors - lower confidence is the honest
                # signal that this came from free-text model reasoning, not
                # a fixed rule match.
                source_engine="aig-mcp-scan",
                source_capability=EngineCapability.SEMANTIC_LLM,
                evidence_redacted=desc[:200],
                snippet_hash=hashlib.sha256(desc.encode("utf-8")).hexdigest(),
            )
        )
    return tuple(findings)


def parse_output(
    completed: subprocess.CompletedProcess[bytes], _target_dir: Path, _files: dict[str, bytes]
) -> tuple[Finding, ...]:
    return parse_stderr(completed.stderr or b"")


def make_adapter(
    *,
    openai_base_url: str,
    ruleset_digest: str,
    version: str,
    model: str = "gpt-4o-mini",
    api_key: str | None = None,
    interpreter: str = "/app/.venv-aig/bin/python3",
    script: str = "/app/vendor-aig-mcp-scan/main.py",
    timeout_s: float = 240.0,
) -> SubprocessEngineAdapter:
    # SECURITY (Finding #16): validated once here (fail fast on an obviously-
    # bad config at startup), but the REAL, load-bearing check is inside
    # _build_env() below, which re-runs on every subprocess spawn - see the
    # matching note in skillspector.py's make_adapter() for why a
    # startup-time-only check (make_adapter() runs exactly once per process)
    # isn't enough on its own.
    require_internal_endpoint(openai_base_url, field_name="aig.openai_base_url")

    def _build_env() -> dict[str, str]:
        # SECURITY (Finding #16): re-validated on every call (i.e.
        # immediately before every subprocess spawn), not just once at
        # adapter construction - raises ValueError (caught by base.py's
        # analyze() and turned into a fail-closed EngineStatus.ERROR) if
        # openai_base_url no longer resolves internally.
        require_internal_endpoint(openai_base_url, field_name="aig.openai_base_url")
        # CORRECTNESS: same PATH-only-inherit rationale as skillspector.py -
        # this subprocess needs to resolve nothing via PATH search
        # (interpreter and script are both absolute paths), but PATH is
        # still carried over in case mcp-scan's own dependency imports shell
        # out to anything (e.g. `mcp` package internals) that expects a
        # normal PATH to exist.
        # SECURITY: the API key is passed via env, never argv - confirmed by
        # reading `vendor/aig/mcp-scan/main.py`'s own argument handling
        # (`api_key = args.api_key or os.environ.get("OPENROUTER_API_KEY")`,
        # main.py line ~107): the tool natively supports reading its key from
        # `OPENROUTER_API_KEY`, so putting it in argv instead (as this adapter
        # used to) needlessly exposed a real credential to any local process/user
        # that can read another process's argv (`ps aux`, `/proc/<pid>/cmdline`) -
        # the same class of exposure skillspector.py's adapter already avoids for
        # its own `OPENAI_API_KEY`. Mirrors that adapter's exact pattern: env
        # fully replaces (not merges into) the child's environment (see
        # `SubprocessEngineAdapter.analyze`'s `env=self._env`), so PATH must be
        # (and is) carried through explicitly below or the interpreter/script
        # invocation itself would still work (both paths are absolute) but any
        # PATH-dependent behavior inside mcp-scan's own dependencies would break.
        # SECURITY (INV-14, found live 2026-07-15): `--base_url`/`--model`
        # only wire the "default"/Main LLM role (main.py's own `LLM(...)`
        # construction above). `vendor/aig/mcp-scan/utils/llm_manager.py`'s
        # LLMManager ALSO instantiates "thinking"/"coding" (main.py calls
        # `get_specialized_llms(["thinking", "coding"])`) and, on any future
        # code path, "fast" - none of these are configured from `--base_url`/
        # `--model`/`OPENROUTER_API_KEY`; each falls back to its own
        # `THINKING_*`/`CODING_*`/`FAST_*` env var (utils/config.py), which
        # defaults to a REAL public OpenRouter model (google/gemini-2.5-pro,
        # anthropic/claude-sonnet-4.5, google/gemini-2.0-flash-exp) if unset.
        # Confirmed live: without this, 3 of mcp-scan's 4 LLM roles silently
        # target openrouter.ai regardless of `openai_base_url` - this
        # deployment's NetworkPolicy egress-allowlist happened to block that
        # traffic (no actual leak), but the adapter itself must not depend on
        # an external network control to enforce INV-14. Force every role
        # onto the same already-`require_internal_endpoint`-validated
        # endpoint/model/key used above.
        return {
            "PATH": os.environ.get("PATH", ""),
            "OPENROUTER_API_KEY": api_key or _PLACEHOLDER_API_KEY,
            # Pin the master DEFAULT_* fallbacks too, not just the three
            # specialized roles. mcp-scan's config.py resolves THINKING/CODING/
            # FAST BASE_URL to DEFAULT_BASE_URL when unset, and DEFAULT_BASE_URL
            # itself defaults to a real openrouter.ai URL that would WIN over
            # our internal endpoint in LLMManager.get_llm("default"). The
            # current scan path never hits that (main LLM is argv-driven), but
            # per INV-14 the adapter must not rely on that staying true - so
            # every knob that could egress is forced onto the validated
            # internal endpoint here. Harmless to the argv-driven main LLM.
            "DEFAULT_BASE_URL": openai_base_url,
            "DEFAULT_MODEL": model,
            "THINKING_BASE_URL": openai_base_url,
            "THINKING_MODEL": model,
            "THINKING_API_KEY": api_key or _PLACEHOLDER_API_KEY,
            "CODING_BASE_URL": openai_base_url,
            "CODING_MODEL": model,
            "CODING_API_KEY": api_key or _PLACEHOLDER_API_KEY,
            "FAST_BASE_URL": openai_base_url,
            "FAST_MODEL": model,
            "FAST_API_KEY": api_key or _PLACEHOLDER_API_KEY,
        }

    return SubprocessEngineAdapter(
        metadata=_metadata(ruleset_digest=ruleset_digest, version=version),
        build_argv=_ArgvBuilder(
            interpreter=interpreter,
            script=script,
            base_url=openai_base_url,
            model=model,
        ),
        parse_output=parse_output,
        env=_build_env,
        # mcp-scan's own error handling calls sys.exit(1) on a bad target
        # path or missing API key (main.py) - both are genuine adapter-
        # construction/config problems this codebase wants surfaced as
        # EngineStatus.ERROR (fail-closed, INV-1), not silently swallowed -
        # so this stays at the default True, unlike bandit/osv-scanner/
        # skillspector's False (which use nonzero exit to mean "findings
        # were reported", not "crashed" - mcp-scan has no such convention,
        # confirmed by reading main.py's only two sys.exit(1) call sites,
        # both genuine startup failures before any scanning happens).
        treat_nonzero_exit_as_error=True,
        # SEE base.py's own comment on this flag: mcp-scan's `utils/loging.py`
        # writes a CWD-relative `./logs/mcp-scan_<timestamp>.log` file via
        # loguru AT IMPORT TIME (before argument parsing) - under this
        # deployment's `readOnlyRootFilesystem: true`, a CWD anywhere other
        # than the per-scan tempdir (the one guaranteed-writable path this
        # process creates) would crash the subprocess before it ever reads
        # `--repo`/`OPENROUTER_API_KEY`, indistinguishable from a genuine
        # engine failure. NOT independently verified against the real k8s
        # deployment yet (same "not verified beyond the dev VM" posture as
        # this Dockerfile's own header comment) - flagging the reasoning
        # explicitly rather than either skipping the fix or claiming it's
        # confirmed working.
        run_in_target_dir=True,
        # SECURITY: LLM agent loops (multi-turn tool calls, file reads,
        # reasoning) take meaningfully longer than a single regex/AST pass -
        # 60s (the base class default, tuned for bandit/yara/osv-scanner)
        # would truncate a real mcp-scan run mid-reasoning on anything but a
        # trivial target. Defaults to 240s, comfortably under the shared
        # overall-job deadline (`ScanRuntime.scan_deadline_s`, itself
        # defaulting to 300s) with headroom left for file materialization and
        # other engines in the same job - but configurable (engine_runner/
        # main.py's `SKILLSCAN_LLM_ENGINE_TIMEOUT_S`) for a slower LLM backend
        # (e.g. a local debug model with no dedicated inference hardware).
        # Whatever this is set to, `SubprocessEngineAdapter.analyze()`'s own
        # `deadline` handling (base.py) still clamps it down to the actual
        # remaining shared-deadline budget per-call regardless - raising this
        # value alone does nothing unless the overall deadline is ALSO raised
        # to leave enough of that budget remaining by the time this engine's
        # turn comes up.
        timeout_s=timeout_s,
    )
