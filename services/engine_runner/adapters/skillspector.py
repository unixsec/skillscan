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
                    title=message[:200] if message else rule_id,
                    severity=_LEVEL_TO_SEVERITY.get(level, Severity.MEDIUM),
                    confidence=0.75,
                    source_engine="skillspector",
                    source_capability=EngineCapability.SEMANTIC_LLM,
                    file_path=file_path,
                    start_line=start_line,
                    snippet_hash=hashlib.sha256(message.encode("utf-8")).hexdigest()
                    if message
                    else None,
                    evidence_redacted=message[:200],
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
