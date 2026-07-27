# Vendored OSS Engine Source — Introduction Record

Per coding spec §10A: OSS detection engine source is pulled from official upstream
repositories **once, from a networked environment**, pinned to an exact commit,
and committed into this repository (as git submodules) so that enterprise deployment
is fully self-contained — zero internet access required at build or deploy time.

The authoritative pin data (repo, ref, commit SHA, license) lives in
[`engines.lock.yaml`](engines.lock.yaml). This file records the *introduction event*
itself: when each engine was vendored, and what was verified before doing so.

## Introduction log

| Engine | Date | Verified before vendoring |
|---|---|---|
| skillspector | 2026-07-05 | `git ls-remote` confirmed commit SHA exists on `main`; license file header confirms Apache-2.0 |
| aig | 2026-07-05 | `git ls-remote --tags` confirmed `v4.1.15` exists; license file header confirms Apache-2.0 |
| bandit | 2026-07-05 | `git ls-remote --tags` confirmed `1.9.4` exists; license file header confirms Apache-2.0 |
| osv_scanner | 2026-07-05 | `git ls-remote --tags` confirmed `v2.4.0` exists; license file header confirms Apache-2.0 |
| yara | 2026-07-05 | `git ls-remote --tags` confirmed `v4.5.7` exists; `COPYING` file confirms BSD-3-Clause |
| ~~cisco_skill_scanner~~ | never vendored; entry removed 2026-07-22 | the official repository was never confirmed across multiple research passes. Its one real capability gap — multilingual prompt-injection detection — is now covered by two in-house floor detectors instead (`services/engine_runner/detectors/prompt_injection_zh.py`, `jailbreak_inducement_zh.py`) |

**Reviewer note:** all five vendored repositories were explicitly named and confirmed
by the project owner before `git submodule add` ran, given the supply-chain
sensitivity of pulling external source into the repository.

## Third-party detection content (rules, not engine source)

Detection *content* adapted from third-party projects is a separate category from
the engine submodules above: it is not a submodule, carries no pin in
`engines.lock.yaml`, and — unlike engine source, which we invoke arm's-length via
subprocess and never import — it is copied into this repository and executed as our
own policy. It is therefore held to the **same owner-confirmation gate** as
vendoring an engine.

| Content | Date | Source | License | Authorized by | Verified before introduction |
|---|---|---|---|---|---|
| `policies/yara/vigil_adapted_rules.yar` (3 rules: PROMPT-01, PROMPT-03, NET-03) | 2026-07-22 | [deadbits/vigil-llm](https://github.com/deadbits/vigil-llm) — `data/yara/{instruction_bypass,system_instructions,mdexfil}.yar`, author Adam M. Swanda | Apache-2.0 | project owner, explicit (2026-07-22) | content fetched verbatim from raw.githubusercontent.com and diffed 2026-07-09; upstream license confirmed Apache-2.0; confirmed PROMPT-01/PROMPT-03 had zero prior rule coverage; confirmed none of the three enter `hard_gate_rules` |

Rules adapted this way keep upstream's `strings`/`condition` bodies **unmodified** —
only the `meta` block is rewritten to this project's `findings_json` convention, so
that upstream can be re-diffed against our copy at any time. Attribution, license,
upstream filenames, fetch date and any known coverage limitations are recorded in the
rule file's own header comment.

## What "vendored" means here

- Each `vendor/<engine>/` is a **git submodule** pinned to the exact commit/tag in
  `engines.lock.yaml` — not a live tracking branch. `git submodule update --init
  --recursive` reproduces exactly this content, needing no network access beyond the
  enterprise's own git mirror. (An earlier revision of this file also pointed at a
  `scripts/bundle_offline.sh`; no such script has ever existed in this repository.
  A single-archive offline bundle is not built yet — for a fully air-gapped target,
  mirror the submodule repositories, or transfer a clone made with
  `git clone --recurse-submodules`.)
- `# LICENSE:` (coding spec §10A.1/§10, INV-15): these engines are consumed **only**
  via `subprocess` CLI invocation by the adapters in `services/engine_runner/adapters/`
  — nothing in this repository ever `import`s engine code. This is deliberate:
  arm's-length subprocess invocation + mere aggregation does not create a derivative
  work under any of the vendored licenses (all permissive here regardless, but the
  isolation is enforced uniformly as the project's supply-chain posture).
- Upstream source is **never patched**. Any adapter-side workaround for engine
  behavior lives in the adapter, never as a diff against `vendor/<engine>/`.

## Adapter status

Vendored ≠ adapted — `engines.lock.yaml`'s `adapter_status` field tracks each engine
separately from its vendoring status. As of M5: `skillspector`/`bandit`/`osv_scanner`/
`yara` are `built` (see `services/engine_runner/adapters/`, tested in
`apps/monolith/tests/test_*_adapter.py`).

`aig` is **partially built**, `adapter_status: built` since 2026-07-09 (2026-07-27:
this section previously still said "deliberately `not_built`", stale against
`engines.lock.yaml` — corrected). Its top-level CLI (`ai-infra-guard scan`) is
genuinely unsuitable: a network-service scanner (`--target http://host:port` against
a running Ollama/vLLM/Dify endpoint), not a local file-bundle scanner, so it cannot
serve skillscan's actual need there — that original 2026-07-05 finding still stands
and `agent-scan/`/`AIG-PromptSecurity/`/`skills/` remain correctly un-adapted for it
(unparseable Python-repr logging). But `mcp-scan/main.py --repo <dir>` is a separate
subsystem the repo's own README calls out ("MCP Server & Agent Skills scan") that
genuinely takes a local directory and produces structured, parseable output — that
one did get an adapter (`services/engine_runner/adapters/aig.py`). It's constructed
only when an internal inference endpoint is configured (`SKILLSCAN_VLLM_BASE_URL`,
INV-14 internal-endpoint-only, same gating as skillspector's LLM path), since every
mcp-scan finding requires a real, live LLM API call and there is no `--no-llm`/static
mode in mcp-scan unlike skillspector. See `vendor/engines.lock.yaml`'s `aig` entry
and `services/engine_runner/adapters/aig.py`'s own module docstring for the full
writeup. `cisco_skill_scanner` was never vendored (repository unconfirmed across
multiple research passes) and so never had an adapter; its `engines.lock.yaml` entry
was removed 2026-07-22 once this was confirmed permanent, closing the "multilingual
prompt-injection detection" gap with two in-house floor detectors instead
(`services/engine_runner/detectors/prompt_injection_zh.py` and
`jailbreak_inducement_zh.py`, covering PROMPT-01 and PROMPT-04).

## Upgrading a pin

Bumping any engine's version is a deliberate, reviewed action, not automatic:

1. From a networked environment, resolve the new stable tag/commit for the engine.
2. `git -C vendor/<engine> fetch && git -C vendor/<engine> checkout <new-ref>`.
3. Review the diff between old and new commit (`git -C vendor/<engine> diff <old>..<new>`)
   for anything security-relevant, especially for `skillspector` which has no tags and
   is pinned to a bare commit.
4. Re-run the license scan (confirm no license change, no newly-introduced copyleft
   dependency).
5. Update `engines.lock.yaml` with the new pin and append a row to the introduction
   log above.
6. Re-run the M5 adapter test suite against the new engine version before merging.
