#!/usr/bin/env python3
"""DEV/DEMO ONLY - local one-click launcher, invoked by scripts/one_click_dev.sh.

Builds the REAL `create_app()` (real per-module MySQL engines, real Redis,
real gate policy/RBAC map) but forces `breakglass_enabled=True` with
`DevBreakGlassCredentialPort` (this directory's own dev-only fixed
credential/TOTP secret) so a developer gets a working login without standing
up a real Vault server - the ONLY thing this script does differently from the
real production entrypoint (`uvicorn monolith.main:create_app --factory`,
per that command's own docstring in apps/monolith/main.py).

NOT the production entrypoint. Production always runs
`uvicorn monolith.main:create_app --factory` directly, with
SKILLSCAN_BREAKGLASS_ENABLED left false unless a real Vault-backed deployment
explicitly opts in (see docs/USER_GUIDE.md / docs/DEPLOYMENT_GUIDE.md).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# The dev/demo launcher wants a WORKING pipeline out of the box - submitted
# scans must actually get scored/decided, lifecycle must advance, report
# schedules must fire. Respect an explicit override, default on.
os.environ.setdefault("SKILLSCAN_WORKER_ENABLED", "true")

# SECURITY (dev-only): this launcher serves the app over plain HTTP on
# localhost (Vite proxy / uvicorn), so the production-default Secure +
# SameSite=Strict cookies would be silently dropped or withheld by the browser
# on reload / return-from-external-page - the session "vanishes the moment you
# leave the page". Relax to non-Secure + SameSite=Lax and extend the 15-min
# break-glass window to 8h for comfortable UI iteration. NEVER in production
# (production is HTTPS and keeps the strict defaults).
os.environ.setdefault("SKILLSCAN_COOKIE_SECURE", "false")
os.environ.setdefault("SKILLSCAN_COOKIE_SAMESITE", "lax")
os.environ.setdefault("SKILLSCAN_BREAKGLASS_SESSION_TTL_S", "28800")
# TOTP rotation period (seconds). RFC 6238 default is 30; set to 60 here so the
# break-glass code rotates every 60s. The generator (authenticator app / the
# dev helper scripts) MUST use the same period.
os.environ.setdefault("SKILLSCAN_TOTP_PERIOD_S", "60")

# SECURITY: dev-only path manipulation so this script can import both
# `monolith.*` (apps/monolith on sys.path) and its own sibling module
# (breakglass_dev_port.py) without needing this scripts/dev/ directory
# packaged as part of the real application - never done in main.py itself.
_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT / "apps" / "monolith"))
sys.path.insert(0, str(_REPO_ROOT / "scripts" / "dev"))

import uvicorn  # noqa: E402 - see sys.path setup above
from breakglass_dev_port import DevBreakGlassCredentialPort  # noqa: E402
from monolith.main import _build_auth_runtime, _build_scan_runtime, create_app  # noqa: E402


def main() -> None:
    # print banner before uvicorn's own log lines (stdout is line-buffered when
    # connected to a TTY already, but not when piped to a file/log collector)
    sys.stdout.reconfigure(line_buffering=True)  # type: ignore[union-attr]
    scan_runtime, _engines = _build_scan_runtime()
    scan_runtime.breakglass_enabled = True
    scan_runtime.breakglass_credentials = DevBreakGlassCredentialPort()
    auth_runtime = _build_auth_runtime(
        breakglass_redis=scan_runtime.redis,
        saml_redis=scan_runtime.redis,
        local_redis=scan_runtime.redis,
    )
    app = create_app(auth_runtime=auth_runtime, scan_runtime=scan_runtime)

    print("=" * 72)
    print("skillscan - LOCAL DEV/DEMO launcher (never use for production)")
    print("=" * 72)
    print("Backend:  http://127.0.0.1:8000")
    print("Login (break-glass, the only working session type without a real IdP):")
    print("  1. Add this secret to any TOTP app (Google Authenticator, 1Password, ...):")
    print("       JBSWY3DPEHPK3PXP")
    print("  2. Run this to arm break-glass for 1 hour (needs two DIFFERENT names):")
    print(
        '       uv run python3 -c "'
        "import asyncio,pyotp,redis.asyncio as r;"
        "from monolith.modules.admin.breakglass import activate_breakglass;"
        "asyncio.run(activate_breakglass(r.Redis.from_url('redis://localhost:6379/0'),"
        "activator_a='dev-a',activator_b='dev-b',"
        "totp_code=pyotp.TOTP('JBSWY3DPEHPK3PXP').now(),"
        "totp_secret='JBSWY3DPEHPK3PXP',ttl_s=3600))\""
    )
    print(
        "  3. Log in at the web UI with credential 'dev-breakglass-credential' + a fresh TOTP code."
    )
    print("=" * 72)
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")


if __name__ == "__main__":
    main()
