"""Engine enable/disable registry (coding spec §9 Admin·Engines, §11.7/§16.1:
"引擎启停(不能停 required floor 引擎)").

SECURITY (INV-1): a required (floor) engine can NEVER be disabled - the whole
point of the floor-engine backstop is that it stays immune to being switched
off, whether by a compromised admin session or an honest operator mistake.

Disable state lives in Redis (a SET of disabled engine names), shared across
every monolith replica - NOT per-process memory (which would make admin
actions apply inconsistently across a fleet), and deliberately NOT a new
MySQL table either, since this is simple, ephemeral toggle state where the
fail-safe default (everything enabled) is also the SAFE direction: if this
Redis key is ever lost, previously-disabled engines simply come back online,
which increases detection coverage rather than reducing it - the opposite of
a security regression.

The key name + read live in `common.engine_toggle` (not here) - the separate
engine-runner service (services/engine_runner/worker.py) must gate its own
sandbox-engine dispatch on the exact same key, so it can't be a monolith-only
private constant.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import redis.asyncio as aioredis
from common.engine_toggle import DISABLED_ENGINES_KEY, list_disabled_engines
from engine_runner.sandbox_engines import SANDBOX_ENGINE_NAMES, llm_gated_engine_names
from skillscan_core import EngineMetadata

from monolith.modules.intel.matcher import (
    INTEL_ENGINE_CAPABILITIES,
    INTEL_ENGINE_NAME,
    INTEL_ENGINE_VERSION,
)

__all__ = [
    "ATTRIBUTION_BASIS_CURRENT_CONFIG",
    "ATTRIBUTION_CURRENTLY_DISABLED",
    "ATTRIBUTION_LLM_ENDPOINT_UNCONFIGURED",
    "EngineDisableError",
    "VERSION_UNAVAILABLE_SANDBOXED",
    "filter_enabled_engines",
    "is_disableable",
    "known_engine_names",
    "known_engine_rows",
    "list_disabled_engines",
    "llm_unconfigured_engine_names",
    "not_reported_attribution",
    "not_reported_attribution_basis",
    "set_engine_enabled",
]

#: Why a listed engine has no `version`. The monolith cannot reach a sandbox
#: engine's `EngineMetadata` at all - those engines live in the separate
#: engine-runner image (INV-15) - so `version: None` there is a STRUCTURAL fact
#: about this deployment's topology, not a value that failed to load. The
#: console rendered both as the same `—`, which told an operator nothing about
#: whether the engine was missing or merely un-introspectable; this field is
#: set at the one place that writes the `None`, so the two can never drift.
VERSION_UNAVAILABLE_SANDBOXED = "sandboxed_image"

#: `report_state = 'not_reported'` is one bucket for five causes (never
#: dispatched / still running past the wait / crashed before writing /
#: admin-disabled / never constructed). Exactly two have a source this process
#: can read at all, and these name them. The other three get NO attribution:
#: `aggregate.EngineReportState`'s docstring is explicit that a read path must
#: join an authority or say nothing, because a guessed cause is
#: indistinguishable from an observed one at the point where someone acts on it.
#:
#: HONESTY, and the console must repeat it: both of these are facts about the
#: CURRENT configuration, read now - not about the configuration in force when
#: those scans ran. An engine disabled this morning explains nothing about last
#: week's rows. They are offered as "here is what today's config would predict",
#: never as "this is why it did not report".
#:
#: `llm_endpoint_unconfigured` was called `never_constructed` until the
#: 2026-07-29 honesty review, and the rename is the fix rather than cosmetic -
#: see `not_reported_attribution` for the split-brain the old name asserted its
#: way through. It now states the thing this process actually observed (its own
#: missing LLM endpoint) instead of the conclusion it cannot check (what a
#: different pod builds).
ATTRIBUTION_LLM_ENDPOINT_UNCONFIGURED = "llm_endpoint_unconfigured"
ATTRIBUTION_CURRENTLY_DISABLED = "currently_disabled"

#: Sent beside whichever token above applies, so the caveat is ON THE WIRE
#: rather than only in the web console's translation strings (2026-07-29): the
#: console is not the only possible consumer of `GET /v1/admin/engines/health`,
#: and a bare `currently_disabled` reads to any other reader as a statement
#: about the scan it is attached to. It is not. Every attribution this module
#: produces is configuration READ AT REQUEST TIME, and the value that has to
#: travel with it is exactly that: "today's config would predict this", never
#: "this is what happened".
ATTRIBUTION_BASIS_CURRENT_CONFIG = "current_config"


class EngineDisableError(ValueError):
    pass


def known_engine_rows(
    engine_metadatas: Sequence[EngineMetadata],
    *,
    required: frozenset[str],
    disabled: frozenset[str],
) -> list[dict[str, Any]]:
    """Every engine this deployment knows about, across all THREE tiers, as the
    admin console renders them.

    THE BUG THIS EXISTS TO PREVENT (2026-07-29, milestone C Task 2): the admin
    router used to assemble the listing and the toggle's `known_names` guard
    independently, and both enumerated only two tiers - `runtime.engine_
    metadatas` (which `main.py` fills from `floor_engines()` alone) plus
    `SANDBOX_ENGINE_NAMES`. The intel matcher is a third tier, declared nowhere
    either of them looked, so `inhouse-intel-matcher` could not be listed AND
    PATCHing it returned 404 - an engine that runs on every scan and that an
    operator had no way to see or switch off. Deriving both from this one
    function makes "listable" and "toggleable" the same set by construction.

    Tiers, and why each is enumerated the way it is:

    - floor / in-process: real `EngineMetadata` is available, so version and
      capabilities are real.
    - sandbox: runs in the separate engine-runner service/image, so no metadata
      is reachable from the monolith at all (INV-15) - "sandboxed" is the
      meaningful capability tag, distinguishing these rows from the floor ones.
    - intel: in-process but not constructible without a DB-fetched IOC snapshot,
      so its identity is taken from the constants `intel.matcher` exports.
    """
    rows: list[dict[str, Any]] = [
        {
            "name": metadata.name,
            "version": metadata.version,
            "version_unavailable_reason": None,
            "required": metadata.name in required,
            "enabled": metadata.name not in disabled,
            "capabilities": sorted(c.value for c in metadata.capabilities),
        }
        for metadata in engine_metadatas
    ]
    rows += [
        {
            "name": name,
            "version": None,
            # Set HERE, beside the `None` it explains, rather than inferred
            # downstream from `capabilities == ["sandboxed"]`: an inference in
            # the console would silently revert to a bare "—" the day a sandbox
            # engine grows a second capability tag, which is the same
            # second-registry drift this module's own docstring exists to
            # describe.
            "version_unavailable_reason": VERSION_UNAVAILABLE_SANDBOXED,
            "required": False,
            "enabled": name not in disabled,
            "capabilities": ["sandboxed"],
        }
        for name in SANDBOX_ENGINE_NAMES
    ]
    rows.append(
        {
            "name": INTEL_ENGINE_NAME,
            "version": INTEL_ENGINE_VERSION,
            "version_unavailable_reason": None,
            # Advisory by design, never `required_engines`: an intel-DB hiccup
            # must degrade to floor-only findings, not fail-closed BLOCK every
            # scan (see worker._floor_engines_with_intel's docstring).
            "required": INTEL_ENGINE_NAME in required,
            "enabled": INTEL_ENGINE_NAME not in disabled,
            "capabilities": sorted(c.value for c in INTEL_ENGINE_CAPABILITIES),
        }
    )
    return rows


def known_engine_names(engine_metadatas: Sequence[EngineMetadata]) -> frozenset[str]:
    """The name universe the toggle validates against - read off `known_engine_
    rows` rather than re-assembled, so an engine can never be listable but not
    addressable (or the reverse)."""
    return frozenset(
        str(row["name"])
        for row in known_engine_rows(engine_metadatas, required=frozenset(), disabled=frozenset())
    )


def llm_unconfigured_engine_names(*, sandbox_llm_configured: bool) -> frozenset[str]:
    """The LLM-gated engines, when THIS PROCESS sees no internal LLM endpoint.

    Named for what it reads, not for what it implies (2026-07-29). It used to
    be `never_constructed_engine_names`, "engines the engine-runner does not
    build at all on THIS deployment" - a claim about a different process,
    computed entirely from this one's environment.

    DERIVED from the engine-runner's own gate (`llm_gated_engine_names()` is
    itself the difference between the full sandbox universe and what
    `sandbox_engines()` constructs with no endpoint), so an engine joining or
    leaving that gate is picked up without a second edit here. Milestone D
    produced five defects of the "new detector, sibling registry not updated"
    shape; a literal list of LLM-gated names would have been a sixth.

    `sandbox_llm_configured` is `ScanRuntime`'s copy of whether this deployment
    has an internal LLM endpoint - the same flag `worker._active_sandbox_
    waited_engines` uses to decide what the gate waits for, so the console's
    explanation and the gate's behaviour cannot disagree. What it is NOT is a
    reading of the engine-runner's environment; the two are supposed to come
    from one ConfigMap key and have already been observed disagreeing.
    """
    if sandbox_llm_configured:
        return frozenset()
    return llm_gated_engine_names()


def not_reported_attribution(
    engine_name: str,
    *,
    disabled: frozenset[str],
    llm_unconfigured: frozenset[str],
    reported_in_window: int = 0,
) -> str | None:
    """What TODAY'S configuration would predict about an engine that did not
    report - or `None`, which is the answer for three of the five causes.

    Order matters and is not arbitrary: `llm_endpoint_unconfigured` outranks
    `currently_disabled` because it is the stronger prediction (nothing an
    operator does to the toggle changes an engine the runner never builds), and
    an LLM-gated engine that is ALSO toggled off would otherwise be reported
    under the cause an operator can act on but which would not actually help.

    EVIDENCE OUTRANKS INFERENCE (2026-07-29). The LLM branch is the one claim
    here the monolith cannot verify: it is derived from `SKILLSCAN_VLLM_BASE_
    URL` as read by THIS process, and the thing it wants to say is about a
    DIFFERENT process. The two are supposed to receive that value from one
    ConfigMap key, and on the deployment where this table was first read they
    did not - the engine-runner had it, the monolith did not. The console then
    printed "this deployment does not build this engine" on a row that
    simultaneously showed `failed 2`, two statements about one engine that
    cannot both be true.

    `reported_in_window` is the engine-runner's own answer where it exists: a
    single delivered result proves the engine WAS built, so the prediction is
    withdrawn no matter what the local environment says. ONLY it is withdrawn -
    `currently_disabled` still applies if it applies, since "it reported, then
    an operator switched it off" is a coherent history and the one cause here
    anybody can act on. With neither, the row carries NO attribution, which is
    correct: an unexplained never-reported is exactly what a split-brain
    configuration looks like from this side, and saying nothing sends an
    operator to look instead of reassuring them with a false cause.

    WHAT THAT GUARD DOES NOT COVER, and why this branch no longer says "not
    built in this deployment" (the 2026-07-29 honesty review). The overrule
    needs a delivered result to fire, and the split-brain it was written for
    has a shape that produces none: with the LLM endpoint actually UP on the
    engine-runner, `aig-mcp-scan` takes ~240 s, and a monolith whose own
    `sandbox_llm_configured` is False does not wait for it - so every row in
    the window is `not_reported`, `counts.reported` is 0, and the withdrawal
    never triggers. It was falsifiable on the VM only because the endpoint was
    refusing connections and the engine exited in under a second. Correctness
    that holds only because the environment happened to be broken in a
    fail-fast way is not correctness.

    Fixing that properly needs a per-scan record of the set of engines actually
    DISPATCHED, written by the process that dispatched them - the engine-runner
    - so a read path can distinguish "never built" from "built, slow, decided
    without". That does not exist and cannot be inferred from what is stored.
    So the claim is weakened instead, to exactly what this process observed:
    THIS service has no internal LLM endpoint configured. That sentence stays
    true in the split-brain, and the console's wording states the conditional
    ("if the engine-runner shares this configuration...") rather than
    presenting the conclusion as an observation.

    `currently_disabled` needs no such treatment - it is read from the Redis
    key this same process writes, shared with the engine-runner, so it is
    authoritative about configuration rather than inferred. Only its TENSE is
    unproven (now, not at scan time), which is what
    `not_reported_attribution_basis` carries onto the wire.

    Returns a stable machine token, never a sentence: the console owns the
    wording in both locales, and a translated string crossing the wire is how
    this console previously ended up rendering raw backend values in one
    language on one page and translated labels on its sibling.
    """
    if engine_name in llm_unconfigured and reported_in_window == 0:
        return ATTRIBUTION_LLM_ENDPOINT_UNCONFIGURED
    if engine_name in disabled:
        return ATTRIBUTION_CURRENTLY_DISABLED
    return None


def not_reported_attribution_basis(attribution: str | None) -> str | None:
    """The qualifier that has to travel WITH an attribution, or `None` when
    there is no attribution to qualify.

    Every token `not_reported_attribution` can return is read from
    configuration at request time; none is an observation of the scan it is
    attached to. That caveat used to exist only in the web console's two
    translated hint strings, so the API served a bare `currently_disabled` and
    any second consumer - another dashboard, a script, an export - inherited an
    unqualified claim about a scan that ran under a configuration nobody
    recorded.

    Deliberately a separate function rather than a second return value: it is
    the same answer for both tokens today, and folding it into a tuple would
    invite a call site that keeps the token and drops the qualifier."""
    if attribution is None:
        return None
    return ATTRIBUTION_BASIS_CURRENT_CONFIG


def is_disableable(name: str, *, required_names: frozenset[str]) -> bool:
    return name not in required_names


async def set_engine_enabled(
    redis: aioredis.Redis, name: str, *, enabled: bool, required_names: frozenset[str]
) -> None:
    """SECURITY (INV-1): raises `EngineDisableError` (never silently ignores)
    if asked to disable a required floor engine - the caller (admin router)
    turns this into a 400/409, not a silent no-op."""
    if not enabled and not is_disableable(name, required_names=required_names):
        raise EngineDisableError(
            f"{name!r} is a required floor engine and cannot be disabled (INV-1)"
        )
    if enabled:
        await redis.srem(DISABLED_ENGINES_KEY, name)  # type: ignore[misc]
    else:
        await redis.sadd(DISABLED_ENGINES_KEY, name)  # type: ignore[misc]


async def filter_enabled_engines(
    redis: aioredis.Redis, engine_metadatas: Sequence[EngineMetadata]
) -> tuple[EngineMetadata, ...]:
    """Called at scan-submission time (gateway.router.create_scan) - the
    admin toggle takes effect on the NEXT submission, not retroactively on
    scans already in flight."""
    disabled = await list_disabled_engines(redis)
    return tuple(m for m in engine_metadatas if m.name not in disabled)
