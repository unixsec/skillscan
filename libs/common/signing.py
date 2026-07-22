"""Shared RSA-PSS/SHA256 signature verification for externally-authored signed
artifacts (offline IOC import packages, Skill provenance manifests).

SECURITY: this is verification-only (no private key material here) - used
wherever this project needs to check that a claim (a JSON payload) was really
signed by a trusted party's RSA key, matching the scheme
`apps.monolith.modules.gate.signer` already uses for outbound JWS signing (the
same RSA-PSS/SHA256 primitives, applied to verification instead of signing).
"""

from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


def canonical_claim_bytes(payload: dict[str, Any], *, exclude_keys: tuple[str, ...]) -> bytes:
    """Deterministic serialization of everything in `payload` except the
    excluded (signature-carrying) keys - must be identical between signer and
    verifier or every signature will (correctly) fail to verify."""
    claim = {k: v for k, v in payload.items() if k not in exclude_keys}
    return json.dumps(claim, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_rsa_pss_signature(
    *, public_keys: tuple[RSAPublicKey, ...], claim_bytes: bytes, signature_b64: str
) -> bool:
    """SECURITY: tries every supplied public key (supports rotation without
    the caller needing to know which key signed) - returns True only if AT
    LEAST ONE verifies; any base64/format error or a signature that verifies
    against none of the keys returns False (fail-closed), never raises."""
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, TypeError):
        return False

    for key in public_keys:
        try:
            key.verify(
                signature,
                claim_bytes,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            continue
    return False
