"""Sandboxed OSS engine wiring (coding spec §10, INV-10/INV-15).

Counterpart to `orchestration.floor.floor_engines()`, but for the four
subprocess-invoked OSS adapters instead of the in-monolith byte-matchers.
These are NOT `required_engines` (see `services.engine_runner.worker` module
docstring for why) - they run as an independent, additive engine tier.

`version`/`ruleset_digest` are derived from `vendor/engines.lock.yaml`'s pin
(coding spec: "name@version#ruleset_digest 来自 pin 的镜像 digest"). A real
content-addressed ruleset digest per engine is a M5 follow-up (the pinned
vendor commit SHA is the actual provenance anchor today); "live-cli-probe"
matches the existing convention already used in
`apps/monolith/tests/test_bandit_adapter.py` for the same reason - honest
about not having built a full digest pipeline yet rather than inventing a
fake-precise hash.
"""

from __future__ import annotations

from functools import cache
from pathlib import Path

from skillscan_core import DetectionEngine

from engine_runner.adapters import aig, bandit, osv, skillspector, yara
from engine_runner.timeouts import EngineTimeouts

_RULESET_DIGEST = "live-cli-probe"

# SINGLE SOURCE OF TRUTH for "every engine name this service can ever produce
# a finding blob for" - the full universe of `metadata.name` values across
# services/engine_runner/adapters/*.py, regardless of today's runtime config
# (unlike `sandbox_engine_names()` below, which is config-gated: it omits
# aig-mcp-scan whenever `vllm_base_url` is unset, by design - see
# TestAigGating). Consumers that need "which engines are dispatched THIS
# tick" want `sandbox_engine_names()`; consumers that need "which engine
# names might this service have already written a findings blob for" (e.g.
# apps/monolith/worker.py's aggregation-only advisory tier, which has no
# adapter instance for any of these and only ever reads back blobs the
# engine-runner service already wrote) want this constant instead - it must
# stay independent of any single deployment's LLM configuration.
#
# Keep this in sync with each adapter's own `name=` literal
# (bandit.py/osv.py/yara.py/skillspector.py/aig.py's `_metadata()`) - there is
# no way to derive it from those functions without either fabricating fake
# ruleset_digest/version/rules_path/openai_base_url args for all five just to
# read `.name` back off the result, or satisfying aig.py's real INV-14
# internal-endpoint gate, so this is intentionally a plain literal tuple, not
# a computed one. A previous version of this exact class of bug (a hardcoded
# copy of this list in apps/monolith/worker.py, independently maintained and
# already missing aig-mcp-scan) is why this now lives in exactly one place.
SANDBOX_ENGINE_NAMES: tuple[str, ...] = (
    "bandit",
    "osv-scanner",
    "yara",
    "skillspector",
    "aig-mcp-scan",
)

# policies/yara/skillscan_rules.yar - project-authored rules (reverse-shell,
# webshell, cryptominer, curl-pipe-shell patterns), added alongside this
# service since none existed before. Path matches yara.py's own module
# docstring convention (`policies/yara/*.yar`) and this Dockerfile COPYs
# `policies/yara/` to `/app/policies/yara/` in the final image.
_DEFAULT_YARA_RULES_DIR = Path("/app/policies/yara")


def sandbox_engines(
    *,
    vllm_base_url: str = "",
    yara_rules_dir: Path = _DEFAULT_YARA_RULES_DIR,
    llm_api_key: str | None = None,
    llm_model: str | None = None,
    engine_timeouts: EngineTimeouts | None = None,
) -> dict[str, DetectionEngine]:
    """Fresh adapter instances each call. A binary that isn't installed on this
    host does not crash construction or the caller's loop - `SubprocessEngineAdapter.
    analyze()` already fail-closes a missing binary to `EngineStatus.ERROR`
    (base.py's `except OSError`), so an engine whose vendor build hasn't
    happened yet on a given deployment simply reports itself unusable rather
    than silently omitting itself from the returned dict - the caller and any
    downstream findings viewer can see exactly which engines ran vs. errored.

    skillspector is a partial exception: `make_adapter` requires a valid
    internal `openai_base_url` and rejects an empty/external one
    (`require_internal_endpoint`, INV-14 - "internal" covers an enterprise's
    own privatized model deployment just as much as a literal vLLM process,
    see that adapter's own module docstring), so it's constructed either way
    - with a poison URL and `use_llm=False` when `vllm_base_url` is empty
    (its SARIF static checks still run and produce real findings even
    without an LLM backend), or for real once one is configured.

    aig-mcp-scan is the true exception, and unlike skillspector has NO
    static-only mode at all: `vendor/aig/mcp-scan/main.py` calls
    `sys.exit(1)` before touching the target directory if it can't resolve
    an API key - there is no `--no-llm`-equivalent flag, so constructing it
    with a placeholder endpoint would mean it reports `EngineStatus.ERROR`
    on literally every scan until a real backend exists, which is
    indistinguishable from a genuinely broken engine. It is therefore
    omitted from the returned dict entirely when `vllm_base_url` is empty,
    and only added once a real internal endpoint is configured - the same
    gate as skillspector's live LLM path, reusing the same endpoint/key
    rather than introducing a second parallel set of variables for what is,
    operationally, one LLM backend serving both engines.

    `llm_api_key`/`llm_model` are `None` by default (skillspector needs no
    key against an unauthenticated internal deployment; aig-mcp-scan falls
    back to its own placeholder key and a generic default model in that
    case) - set them when the internal deployment enforces its own auth
    and/or serves a specific named model.

    `engine_timeouts` (milestone C Task 4) resolves each engine's subprocess
    timeout by its OWN name - `None` means the built-in table
    (`engine_runner.timeouts`), which reproduces the previous behaviour
    exactly: 60s everywhere, 240s for aig-mcp-scan. Every adapter is now
    passed one explicitly, so adding an engine without deciding its timeout
    is no longer possible by omission."""
    timeouts = engine_timeouts if engine_timeouts is not None else EngineTimeouts()
    instances: list[DetectionEngine] = [
        bandit.make_adapter(
            ruleset_digest=_RULESET_DIGEST,
            version="1.9.4",
            timeout_s=timeouts.for_engine("bandit"),
        ),
        osv.make_adapter(
            ruleset_digest=_RULESET_DIGEST,
            version="2.4.0",
            timeout_s=timeouts.for_engine("osv-scanner"),
        ),
        yara.make_adapter(
            rules_path=yara_rules_dir,
            ruleset_digest=_RULESET_DIGEST,
            version="4.5.7",
            timeout_s=timeouts.for_engine("yara"),
        ),
    ]
    if vllm_base_url:
        instances.append(
            skillspector.make_adapter(
                openai_base_url=vllm_base_url,
                ruleset_digest=_RULESET_DIGEST,
                # vendor/skillspector/pyproject.toml's own version; pinned commit is dde36f2
                version="2.3.9",
                use_llm=True,
                api_key=llm_api_key,
                timeout_s=timeouts.for_engine("skillspector"),
            )
        )
    else:
        instances.append(
            skillspector.make_adapter(
                openai_base_url="http://127.0.0.1:0",  # never dialed, use_llm=False
                ruleset_digest=_RULESET_DIGEST,
                # vendor/skillspector/pyproject.toml's own version; pinned commit is dde36f2
                version="2.3.9",
                use_llm=False,
                timeout_s=timeouts.for_engine("skillspector"),
            )
        )
    if vllm_base_url:
        # See this function's own docstring: aig-mcp-scan has no static
        # fallback mode, so it is only constructed (and only then does its
        # subprocess actually run) once a real internal endpoint exists -
        # never with a poison URL the way skillspector's `else` branch above
        # does, since there is no `use_llm=False` equivalent to fall back to.
        instances.append(
            aig.make_adapter(
                openai_base_url=vllm_base_url,
                ruleset_digest=_RULESET_DIGEST,
                version="v4.1.15",  # `git -C vendor/aig describe --tags` - pinned commit 31b2184
                model=llm_model or "gpt-4o-mini",
                api_key=llm_api_key,
                timeout_s=timeouts.for_engine("aig-mcp-scan"),
            )
        )
    return {engine.metadata.name: engine for engine in instances}


def sandbox_engine_names(
    *, vllm_base_url: str = "", llm_api_key: str | None = None, llm_model: str | None = None
) -> frozenset[str]:
    return frozenset(
        sandbox_engines(
            vllm_base_url=vllm_base_url, llm_api_key=llm_api_key, llm_model=llm_model
        ).keys()
    )


@cache
def llm_gated_engine_names() -> frozenset[str]:
    """The sandbox engines this service constructs ONLY when an LLM endpoint is
    configured - i.e. the ones that, on a deployment without one, never run,
    never write a findings blob and never produce a result message.

    DERIVED, not a literal: it is the difference between the full universe
    (`SANDBOX_ENGINE_NAMES`) and what `sandbox_engines()`'s own config gate
    builds with no endpoint. A future engine that joins (or leaves) that gate is
    therefore picked up here without a second edit - the class of miss milestone
    D produced five times over.

    WHO NEEDS IT: `apps/monolith/worker.py` decides how long the gate waits for
    the sandbox tier. Waiting on an engine that structurally cannot report costs
    every scan the full wait budget and delivers nothing, so the monolith
    subtracts these names unless its own `vllm_base_url` is configured - the
    same shape as the admin-disable filter already applied there, and the reason
    aig-mcp-scan can now be a full member of `SANDBOX_WAITED_ENGINE_NAMES`
    instead of being hardcoded out of it.

    Cached: the answer is a property of this module's source, not of any input,
    and it is consulted once per worker tick."""
    return frozenset(SANDBOX_ENGINE_NAMES) - sandbox_engine_names()
