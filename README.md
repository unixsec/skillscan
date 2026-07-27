# skillscan

[中文](README.zh-CN.md)

Enterprise Skill security detection system — scans Agent Skill packages
(`SKILL.md` + `scripts/` + bundled `.mcp.json`/hooks) before marketplace admission
and produces a `PASS` / `REVIEW` / `BLOCK` verdict. Internal tool, on-prem, zero
external network connectivity.

The project is built against a layered spec set (requirements → architecture →
coding spec) and a milestone-by-milestone story backlog with per-story status
notes, both maintained separately from this repository's public snapshot. The
operational guides and the kernel threat model ship here, under `docs/`.

## Status

**M1-M8 all implemented.** A full requirement-by-requirement audit against the
coding spec (2026-07-06) found 18 real gaps — all 18 fixed, including a critical
kernel defect where a dedup collision in `gate.decide()` could silently drop a
trifecta-completing finding, a missing CSRF check on
`POST /v1/reeval/{skill_id}`, and a real OIDC/SAML login callback
(`/v1/auth/oidc/*`, `/v1/auth/saml/*`), so break-glass is no longer the only
working session path. The scan-decision worker loop — the biggest structural gap
that audit surfaced — was closed the same evening by `apps/monolith/worker.py`.

Since then:

- **Local accounts + RBAC** — a deployment can bootstrap an admin without an
  IdP, alongside the existing SSO path.
- **Chinese prompt-injection floor detectors** (PROMPT-01/04) — matching on
  same-line co-occurrence rather than single keywords. The upstream
  prompt-injection regexes are English-only, so this content passed cleanly
  before.
- **Per-rule security risk descriptions** across all 14 engines — every finding
  explains *why* it is a risk, rather than restating the rule name.
- **0-100 security score** alongside the PASS/REVIEW/BLOCK verdict, as a *pure
  downstream function* of an already-decided verdict: the verdict selects a band
  (BLOCK `[0,39]` / REVIEW `[40,74]` / PASS `[75,100]`) and findings modulate
  within it. The score is never an input to `decide()`, which is what makes
  "BLOCK with a high score" structurally impossible rather than merely
  tested-for.
- **Sandbox-tier engines now reach the verdict.** bandit / yara / skillspector /
  osv-scanner previously landed only if they happened to finish before the
  decision; the gate now waits for them, up to 300 seconds. The wait is
  advisory — a missing sandbox engine is recorded in `reasons` and the verdict
  proceeds, so one degraded engine cannot fail-close a whole batch. The
  trade-off is latency: a scan takes minutes rather than milliseconds, and the
  scan detail page does not yet auto-refresh.
- **Two new floor detectors**, taking `required_engines` from 7 to 9: bundled
  `.mcp.json` (command injection in a server definition, non-local endpoints,
  credential-shaped environment passthrough) and `SKILL.md` frontmatter
  permissions (over-broad tool declarations, undeclared permissions). Both are
  static-only — the `.mcp.json` detector never connects to the endpoints it
  reads about. Declared permissions are now persisted per skill version.
- **Per-rule confidence** replacing one constant per engine, graded by evidence
  strength: structurally validated matches ~0.9, distinctive API-call shapes
  0.7-0.8, bare substrings 0.4-0.5. This revived a gate policy branch that had
  been unreachable, since no floor engine had ever emitted below its threshold.
  Measured against 836 real historical verdicts, the change moves 2.3% of scans
  from PASS to REVIEW.
- **Catalog-id correctness.** Every finding carries a `test_item_id` from the
  detection catalog; several engines had been emitting their own internal rule
  ids or ids that did not exist in it, which made compliance reports read as
  uncovered for capabilities that were in fact running. A test now asserts that
  every id any engine can emit is a real catalog entry — a shape check cannot
  catch a wrong id that is shaped exactly like a right one.

**1103 backend tests** pass against real MySQL/Redis (no mocking of the systems
under test), plus **182 kernel tests** (`tests/`, pure `skillscan_core`, stdlib
only). `ruff check` / `ruff format --check` / `mypy --strict` are clean across
the tree, and `scripts/check_import_boundaries.py` guards the cross-module ORM
boundary — each module owns its own tables and its own least-privilege database
user, and this keeps the code side of that boundary from eroding. Frontend
(`web/`, React 19 + Vite SPA, 15 pages + login, Chinese/English i18n)
`tsc`/`vite build`/`oxlint` clean.

One-click deployment exists for local dev (`scripts/one_click_dev.sh`, verified
end-to-end including a real break-glass login) and as production-shaped Docker
Compose (`docker-compose.yml` + `scripts/one_click_deploy_docker.sh`). Note the
Compose path deliberately excludes `services/engine-runner`, so it runs the
floor engines only; see `docs/DEPLOYMENT_GUIDE.md` for the full topology.

## Development

Requires Python >= 3.12, [uv](https://docs.astral.sh/uv/), and (for the web UI)
Node/npm.

```bash
uv sync                    # install all deps (backend + dev tools) into .venv
uv run pytest -q           # backend suite against local MySQL/Redis (1103 tests)
uv run pytest tests/ -q    # kernel suite, no external dependencies (182 tests)
uv run mypy                # strict type-check
uv run ruff check .        # lint
uv run ruff format --check .
python3 scripts/check_import_boundaries.py   # cross-module ORM boundary

cd web && npm install && npm run build && npm run lint   # frontend
```

Or just run `./scripts/one_click_dev.sh` — brings up MySQL/Redis, migrates, builds
the frontend, and starts the backend with a working (dev-only) break-glass login in
one command, for local dev; a production-shaped Docker Compose path is also
available via `docker-compose.yml` + `scripts/one_click_deploy_docker.sh`.

The operational guides under `docs/` cover the rest: `BUILD_GUIDE.md` (toolchain,
container images, OSS engine vendoring), `DEPLOYMENT_GUIDE.md` (local, Compose,
Kubernetes, real OIDC/SAML setup), `USAGE_GUIDE.md` (full API list, per-role
workflows), `MAINTENANCE_GUIDE.md` (routine maintenance, **the honest list of
what remains open**, troubleshooting), and `THREAT_MODEL.md` (kernel threat
model).

`libs/skillscan_core` itself still has **zero runtime dependencies** by design
(coding spec §2) — it must remain testable with nothing but the stdlib, independent
of everything built on top of it since M2.
