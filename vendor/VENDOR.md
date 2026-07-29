# Vendored OSS Engine Source — Introduction Record

Per coding spec §10A: OSS detection engine source is pulled from official upstream
repositories **once, from a networked environment**, pinned to an exact commit,
and committed into this repository so that enterprise deployment is fully
self-contained — zero internet access required at build or deploy time.

> **2026-07-29 — these were git submodules until this date.** They are not any more.
> The source of all five engines is committed directly into this repository, so a
> plain `git clone` carries it: no `git submodule update --init --recursive`, no
> reachable github.com. Nothing about the pins changed — the trees committed are
> exactly the trees of the commits `engines.lock.yaml` already recorded. See
> [What "vendored" means here](#what-vendored-means-here) below.

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
by the project owner before any source was pulled in, given the supply-chain
sensitivity of pulling external source into the repository. The 2026-07-29
submodule→committed-source conversion was likewise explicitly authorized by the
project owner; it introduced no new upstream and moved no pin.

## Third-party detection content (rules, not engine source)

Detection *content* adapted from third-party projects is a separate category from
the engine source above: it is not vendored engine source, carries no pin in
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

- Each `vendor/<engine>/` is **ordinary source committed into this repository**,
  pinned by the `commit` + `tree` pair in `engines.lock.yaml`. It is not a submodule
  and not a tracking branch. A plain `git clone` of this repository — with no
  submodule step and no access to github.com — carries every engine's source.
- **The pin is verifiable offline, and that is the point of keeping the SHAs.**
  `commit` is provenance: the upstream commit this source was taken from. `tree` is
  the git tree hash of what is committed here. Anyone can check both:

  ```bash
  # 1. this repository's copy is intact and unmodified (offline, no upstream needed)
  uv run python3 scripts/vendor_engines.py verify-pins

  # 2. it really is upstream's code (needs network, once, for an independent audit)
  git clone https://github.com/PyCQA/bandit /tmp/bandit
  git -C /tmp/bandit rev-parse 92ae8b82fb422a639f0ed8d99e96cea769594e08^{tree}
  git rev-parse HEAD:vendor/bandit        # must print the same tree hash
  ```

  A tree hash covers every path, mode and byte beneath the directory, so this
  detects any local edit to vendored source as well as an incomplete vendoring.
- **Offline deployment does not depend on this repository being cloneable.** The
  documented air-gapped path is the prebuilt image bundle:
  `scripts/build_offline_bundle.sh` (run on the networked side) produces
  `dist/skillscan-offline-<tag>-<arch>/` containing `images.tar`, `manifest.txt`,
  `SHA256SUMS` and `import_offline_bundle.sh`. Full procedure in
  `docs/DEPLOYMENT_GUIDE.md` §6. Committed vendor source and the image bundle solve
  **different** problems and neither replaces the other:
  - Committed source removes the *source-fetch* dependency on github.com, and is
    what makes this tree auditable and self-building.
  - It does **not** make `services/engine_runner/Dockerfile` buildable offline —
    that still needs base images, `go mod download`, `apt-get` and PyPI
    (`PIP_INDEX_URL`/`GOPROXY`/`NPM_CONFIG_REGISTRY` are parameterised for internal
    mirrors). The image bundle is what makes the isolated side need none of those,
    because it ships finished images instead of a build.

  (An earlier version of this file said "a single-archive offline bundle is not
  built yet … no such script has ever existed in this repository". That was already
  wrong when written: `scripts/build_offline_bundle.sh` was built in milestone E.
  The stale reference it was correcting was to a differently-named
  `scripts/bundle_offline.sh`, which indeed never existed.)
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

1. From a networked environment, resolve the new stable tag/commit for the engine, and
   get owner sign-off — same gate as introducing a new engine.
2. Clone upstream somewhere outside this repository and fetch the new ref:
   `git clone <repo> /tmp/<engine> && git -C /tmp/<engine> checkout <new-ref>`.
3. Review the diff between the old pin and the new one
   (`git -C /tmp/<engine> diff <old>..<new>`) for anything security-relevant —
   especially for `skillspector`, which has no upstream tags and is pinned to a bare
   commit.
4. Replace the tree in this repository. **Do this through git's object store, not by
   copying files:**

   ```bash
   git fetch /tmp/<engine> <new-ref>
   git rm -r --cached vendor/<engine>
   git read-tree --prefix=vendor/<engine>/ <new-sha>^{tree}
   git checkout -- vendor/<engine>          # materialise the new files on disk
   ```

   **Do not** `rsync`/`cp` the upstream working tree in and `git add` it. On a
   case-insensitive filesystem (any stock macOS) that silently drops files: aig alone
   has 466 paths differing only in case, and a working-tree `git add` commits 4085 of
   its 4551 files while looking completely successful. Reading the tree from the
   object store is immune to this, and to `.gitignore` — several vendored projects
   ship `.gitignore` files that match their own force-added content (16 files under
   `aig/AIG-PromptSecurity/tests/`, and yara's `docs/Makefile`, `m4/acx_pthread.m4`
   and three `tests/data/test-*` fixtures).
5. Re-run the license scan (confirm no license change, no newly-introduced copyleft
   dependency).
6. Update `engines.lock.yaml` with the new `commit` **and** the new `tree`
   (`git rev-parse HEAD:vendor/<engine>` after committing), and append a row to the
   introduction log above.
7. `uv run python3 scripts/vendor_engines.py verify-pins` must pass.
8. Re-run the M5 adapter test suite against the new engine version before merging.
   The adapters were written against the *pinned* sources — `adapters/bandit.py`
   records reading the pinned 1.9.4 `setup.cfg` and `blacklists/`, and
   `adapters/skillspector.py` records the SARIF schema and CLI read from the pinned
   tree — so a bump can invalidate them silently.
