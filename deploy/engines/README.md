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

**Not verified:** no Docker daemon is available in this development
environment, so none of these Dockerfiles have been built here — same
honestly-labeled gap as M7's IaC artifacts. Each one is adapted from real
reference material (the engine's own upstream Dockerfile where one exists, or
its real CI build recipe where it doesn't — see each Dockerfile's own header
comment for its source), not guessed from scratch.
