# skillscan web

React 19 + TypeScript + Vite SPA — the skillscan management console (coding spec
§11.8/§16): Dashboard, Scans (+ per-module scan status detail), Reviews, Allowlist,
Inventory, Reeval/Drift, Reconciliation, Reports, Audit, and Admin ·
{Engines, Policy, Users, Intel, BreakGlass}. Chinese/English via a hand-rolled
`src/i18n/` layer (default zh, no i18n library dependency).

Talks only to same-origin `/v1/*` on the backend monolith (`apps/monolith`) —
it's a BFF client, not a token holder: the browser only ever gets an HttpOnly
session cookie, never a bearer token in JS.

```bash
npm install
npm run dev      # http://localhost:5173, proxies /v1 to the backend on :8000
npm run build    # tsc -b && vite build
npm run lint     # oxlint
```

See [`../docs/DEPLOYMENT_GUIDE.md`](../docs/DEPLOYMENT_GUIDE.md) for running the
backend this needs — either `../scripts/one_click_dev.sh` (fastest path, local
dev-only break-glass login) or a real OIDC/SAML login (§4 there, no longer
break-glass-only) — and [`../docs/USAGE_GUIDE.md`](../docs/USAGE_GUIDE.md) for
the complete `/v1` API this calls and per-role usage of every page.
