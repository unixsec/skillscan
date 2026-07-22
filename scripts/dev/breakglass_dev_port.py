"""DEV/TEST ONLY - fixed break-glass credential for local one-click deployment.

SECURITY: this is the LOCAL DEV/DEMO ANALOGUE of `LocalDevSigner`
(apps/monolith/modules/gate/signer.py) and `_LOCAL_DEV_DEFAULT_PASSWORD`
(apps/monolith/main.py) - the same "clearly-labeled, fixed, never-production"
posture, extended to break-glass specifically so `scripts/one_click_dev.sh`
can produce a working local login without a real Vault server. This module is
NEVER imported by `apps/monolith/main.py`'s real `create_app()`/
`_build_breakglass_credential_port()` path - only `scripts/dev/run_local.py`
(this same directory) uses it, and that script is itself clearly a dev-only
launcher, never the production entrypoint (`uvicorn monolith.main:create_app
--factory`, per that command's own docstring).

The fixed TOTP secret below is a real RFC 6238 base32 secret with no special
meaning (`JBSWY3DPEHPK3PXP` decodes to the ASCII bytes "Hello!\xde\x9a\xe6"
under RFC 4648 base32 - the same demo secret used throughout this project's
own manual browser-testing sessions) - it exists purely so a developer running
this script can point any TOTP app (Google Authenticator, 1Password, etc.) at
a fixed, reusable-across-restarts secret instead of a freshly random one every
run.
"""

from __future__ import annotations

from monolith.modules.admin.breakglass import BreakGlassCredentialPort

DEV_BREAKGLASS_CREDENTIAL = "dev-breakglass-credential"  # noqa: S105 - documented dev-only fixed value
DEV_BREAKGLASS_TOTP_SECRET = "JBSWY3DPEHPK3PXP"  # noqa: S105 - documented dev-only fixed value


class DevBreakGlassCredentialPort(BreakGlassCredentialPort):
    """DEV ONLY: returns the fixed values above instead of reading Vault."""

    async def fetch_credential(self) -> str:
        return DEV_BREAKGLASS_CREDENTIAL

    async def fetch_totp_secret(self) -> str:
        return DEV_BREAKGLASS_TOTP_SECRET
