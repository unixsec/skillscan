# skillscan

Enterprise Skill security detection system — scans Agent Skill packages
(`SKILL.md` + `scripts/` + bundled `.mcp.json`/hooks) before marketplace admission
and produces a `PASS` / `REVIEW` / `BLOCK` verdict. Internal tool, on-prem, zero
external network connectivity.

Specs (authoritative, in this order for implementation vs. architecture):

- `企业Skill安全检测系统-系统设计文档-编码规格v2.0.md` — coding spec (drives implementation)
- `企业Skill安全检测系统-架构设计说明书-SAD-v2.0.md` — architecture
- `企业Skill安全检测系统-需求规格说明书-SRS-v2.2.md` — requirements (FR-*/NFR-* IDs)
- `docs/stories/BACKLOG.md` — milestone-by-milestone story backlog, each with its own
  authoritative "Status:" note (most granular, most current source on "is X really done")
- `docs/BUILD_GUIDE.md` / `docs/DEPLOYMENT_GUIDE.md` / `docs/USAGE_GUIDE.md` /
  `docs/MAINTENANCE_GUIDE.md` — the 4 operational guides (Chinese), split by concern;
  `docs/USER_GUIDE.md` is now just an index pointing to these
- `docs/THREAT_MODEL.md` — kernel threat model (M1 deliverable)

## Status

**M1-M8 all implemented**, and a full requirement-by-requirement audit against the
coding spec (2026-07-06, 6 independent verification passes against live code/tests)
found 18 real gaps — **all 18 are now fixed**, including a critical kernel defect
where a dedup collision in `gate.decide()` could silently drop a trifecta-completing
finding (fixed with dedicated regression tests), a missing CSRF check on
`POST /v1/reeval/{skill_id}`, and — the most consequential structural gap — a real
OIDC/SAML login callback now exists (`/v1/auth/oidc/*`, `/v1/auth/saml/*`);
break-glass is no longer the only working session path. See
`docs/MAINTENANCE_GUIDE.md` §2 for the full fix list and §3 for what honestly
remains open (the scan-decision worker loop still isn't invoked by any live
process — the single biggest remaining gap, out of scope for that audit).

706 backend tests passing against real local MySQL/Redis (no mocking of systems
under test), `mypy --strict`/ruff/ruff-format all clean across 171 files; frontend
(`web/`, React 19 + Vite SPA, 13 pages + login, Chinese/English i18n) `tsc`/`vite
build`/`oxlint` clean. One-click deployment now exists both for local dev
(`scripts/one_click_dev.sh`, verified end-to-end including a real break-glass
login) and production-shaped Docker Compose (`docker-compose.yml` +
`scripts/one_click_deploy_docker.sh`, not build-verified here — no Docker daemon
in this environment, same posture as every other Dockerfile in this repo).

## Development

Requires Python >= 3.12, [uv](https://docs.astral.sh/uv/), and (for the web UI)
Node/npm.

```bash
uv sync                    # install all deps (backend + dev tools) into .venv
uv run pytest -q           # full backend suite against local MySQL/Redis (706 tests)
uv run mypy                # strict type-check
uv run ruff check .        # lint

cd web && npm install && npm run build && npm run lint   # frontend
```

Or just run `./scripts/one_click_dev.sh` — brings up MySQL/Redis, migrates, builds
the frontend, and starts the backend with a working (dev-only) break-glass login in
one command. See `docs/DEPLOYMENT_GUIDE.md` for that and the production-shaped
Docker Compose path; `docs/BUILD_GUIDE.md`/`docs/USAGE_GUIDE.md`/
`docs/MAINTENANCE_GUIDE.md` for everything else (local MySQL/Redis setup detail,
per-role usage, known footguns).

`libs/skillscan_core` itself still has **zero runtime dependencies** by design
(coding spec §2) — it must remain testable with nothing but the stdlib, independent
of everything built on top of it since M2.
