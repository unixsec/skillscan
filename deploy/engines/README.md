# Engine Build Images

Per coding spec §10A: `deploy/engines/<name>/Dockerfile` builds a pin-digest
container image **locally from `vendor/<name>/`** — never `git clone`/public
package installs at build time. Each Dockerfile documents its own build
command (context = repo root) and its ARG-parametrized internal package
mirror where one is needed (`PIP_INDEX_URL` for Python engines, `GOPROXY` for
Go engines).

| Directory | Engine | Builds |
|---|---|---|
| `bandit/` | bandit 1.9.4 | `bandit` CLI (Python, pip) |
| `osv_scanner/` | osv-scanner v2.4.0 | `osv-scanner` CLI (Go) |
| `yara/` | yara v4.5.7 | `yara` CLI (C, autotools) |
| `skillspector/` | skillspector (commit `dde36f2`) | `skillspector` CLI (Python, pip) |

**No `aig/` directory here, deliberately:**

- `aig` is vendored (`vendor/aig/`, pinned commit, license-scanned) but has no
  `services/engine_runner/adapters/aig.py` — its real interface is a
  network-service scanner (`--target http://host:port` against a running
  inference endpoint), not a local file-bundle scanner, so it cannot serve
  skillscan's actual need. Its `mcp-scan` subsystem does accept a local
  directory and is adapted separately. See `vendor/VENDOR.md` and
  `services/engine_runner/adapters/aig.py`'s module docstring for the full
  reasoning. With no adapter to run it, there is no reason to build a runnable
  image for it here.

**No `cisco_skill_scanner/` directory, permanently:** it was never vendored
(official repo unconfirmed across multiple research passes); its
`vendor/engines.lock.yaml` entry was removed 2026-07-22 once this was
confirmed permanent. Its one real capability gap (multilingual/Chinese
prompt-injection detection) is now covered by two in-house floor detectors
instead (`inhouse-prompt-injection-zh`/`inhouse-jailbreak-inducement-zh`) —
see `services/engine_runner/detectors/prompt_injection_zh.py` and
`jailbreak_inducement_zh.py`, which cover PROMPT-01 and PROMPT-04.

## Relationship to `services/engine_runner/Dockerfile`

These are **per-engine** images (one engine, one image, used by
`.ci/pipeline.yml`'s `image-sign` job). `services/engine_runner/Dockerfile`
builds the **combined** image that skillscan actually deploys, and since
2026-07-29 it builds all five engines from `vendor/` too — its `osv-builder`
and `yara-builder` stages are adapted from `osv_scanner/` and `yara/` here.

**Two copies of one recipe is the standing hazard**, so the guard below is
duplicated into both rather than living in one of them: every Dockerfile that
produces an engine binary asserts, as a build step that exits non-zero on
disagreement, that the binary's own reported version equals the one
`vendor/engines.lock.yaml` pins (via `scripts/vendor_pinned_version.sh`). That
is a direct INV-7 concern — `toolchain_digest` and the `cache_key` beneath it
are derived from that lock file, so a build whose engines disagree with it
produces digests naming a toolchain that never ran.

`skillspector/` has no such guard: it is pinned to a bare upstream commit with
no release tag, so there is no version to assert.

**Verified 2026-07-29:** `bandit/` and `yara/` were built and run on the dev VM
(10.211.55.10). This directory previously said "no Docker daemon is available
in this development environment, so none of these Dockerfiles have been built
here" — and that gap was hiding a real defect: **`bandit/Dockerfile` did not
work.** `pip install .` on a vendored bandit tree fails with *"Versioning for
this project requires either an sdist tarball, or access to an upstream git
repository"*, because bandit's packaging is `pbr`-based and pbr reads the
version from git tags that a vendored subtree does not carry. It is fixed
(`PBR_VERSION`, sourced from `engines.lock.yaml`). `osv_scanner/` and
`skillspector/` remain built only in their adapted form inside
`services/engine_runner/Dockerfile`, which is exercised on every deploy.

Each Dockerfile is adapted from real reference material (the engine's own
upstream Dockerfile where one exists, or its real CI build recipe where it
doesn't — see each one's header comment for its source), not guessed from
scratch.
