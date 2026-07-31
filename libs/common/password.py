"""scrypt password hashing, shared by every credential path in this codebase.

Lives here rather than in any one module because two different authentication
surfaces need the identical primitive: `admin.local_auth` (human logins) and
`gateway.auth.m2m` (the username/password path for machine callers, added
2026-07-31). Putting it in `libs/common` is not only tidiness - `admin.
local_auth` imports `gateway.auth.redis_session`, so a direct
`gateway.auth.m2m -> admin.local_auth` import would close an import cycle
through `gateway.auth`'s own package.

SECURITY:
- Coding spec INV-17 ("无任何环节出现明文默认口令"): passwords are never stored
  or compared in plaintext, and there is no default/bootstrap hash here.
- scrypt (stdlib `hashlib.scrypt`, N=2**14/r=8/p=1 - OWASP's minimum
  recommended parameters as of this writing) with a random 16-byte salt per
  password, compared in constant time via `hmac.compare_digest`.
- `DUMMY_HASH` exists so an unknown username still costs one scrypt
  verification, keeping response timing from distinguishing "no such account"
  from "wrong password". It authenticates nobody and protects nothing.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SALT_BYTES = 16


def hash_password(password: str) -> str:
    """Returns "scrypt$<salt_hex>$<digest_hex>"."""
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time verification. A malformed or non-scrypt hash is False,
    never an exception - a corrupt stored value must fail closed, not 500."""
    try:
        scheme, salt_hex, digest_hex = password_hash.split("$")
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False
    if scheme != "scrypt":
        return False
    candidate = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=len(expected),
    )
    return hmac.compare_digest(candidate, expected)


# SECURITY: fixed at import time purely to give "unknown account" attempts the
# same scrypt-verification cost as a real one - this hash protects nothing and
# is never used to authenticate anyone.
DUMMY_HASH = hash_password(secrets.token_hex(16))
