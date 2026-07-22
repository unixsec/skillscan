"""SignerPort implementations (coding spec §6/§11.3/§11.6).

SECURITY: M3 built a local dev RSA key as an explicit placeholder - the
coding spec is explicit that real Vault Transit signing is M6's job ("M3
签名:JWS 签名接口占位(本地 dev key);真实 Vault Transit 在 M6"). `LocalDevSigner`
must never be pointed at in production: the private key lives in process
memory, generated fresh per-process, with no HSM/Vault-backed protection. It
still exists for tests/local dev that don't need a running Vault.

`VaultTransitSigner` is the real M6 implementation: the RSA private key never
leaves Vault (INV-13) - this class only ever sends Vault a base64-encoded
digest input and receives a signature back, never a private key or plaintext
key material. It builds a standards-compliant RFC 7515 JWS Compact
Serialization by hand (header.claims.signature, each segment base64url) since
Vault Transit's `/transit/sign` endpoint returns a raw `vault:vN:<base64>`
wrapped signature, not a JWS - `signature_algorithm="pkcs1v15"` +
`hash_algorithm="sha2-256"` is exactly RS256 (RSASSA-PKCS1-v1_5 + SHA-256),
so the resulting compact JWS verifies with any standard RS256 JWT/JWS library
(e.g. PyJWT) against the public key `jwks()` exposes - proven by this
module's own tests round-tripping through PyJWT independently of Vault.

hvac is a synchronous client (no async support) - every Vault call here runs
via `asyncio.to_thread` so it never blocks the event loop.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
import uuid
from typing import TYPE_CHECKING, Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

if TYPE_CHECKING:
    import hvac


def _b64url_uint(value: int) -> str:
    byte_length = (value.bit_length() + 7) // 8
    raw = value.to_bytes(byte_length, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_encode_json(obj: dict[str, Any]) -> str:
    return _b64url_encode(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


class LocalDevSigner:
    """SECURITY: dev/test only - see module docstring. Real production signing
    goes through Vault Transit (`VaultTransitSigner` below) so the private
    key material never leaves Vault."""

    def __init__(self, *, ttl_s: int = 300) -> None:
        self._key: RSAPrivateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._ttl_s = ttl_s
        self._kid = "local-dev-key-1"

    async def sign_verdict(self, payload: dict[str, Any]) -> str:
        now = int(time.time())
        claims = {
            **payload,
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + self._ttl_s,  # SECURITY: short TTL, bound per coding spec §6 SignerPort
        }
        return jwt.encode(claims, self._key, algorithm="RS256", headers={"kid": self._kid})

    async def jwks(self) -> dict[str, Any]:
        public_numbers = self._key.public_key().public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": self._kid,
                    "n": _b64url_uint(public_numbers.n),
                    "e": _b64url_uint(public_numbers.e),
                }
            ]
        }


class VaultTransitSigner:
    """SECURITY (INV-13): the ONLY private-key-shaped material this class ever
    touches is Vault's response - it never holds, generates, or transmits raw
    key bytes. `client` is caller-constructed (auth method/token lifecycle is
    the caller's concern - Vault Agent, AppRole, K8s auth, etc. - this class
    only knows how to call Transit sign/read-key once already authenticated).
    """

    def __init__(
        self,
        *,
        client: hvac.Client,
        key_name: str,
        mount_point: str = "transit",
        ttl_s: int = 300,
    ) -> None:
        self._client = client
        self._key_name = key_name
        self._mount_point = mount_point
        self._ttl_s = ttl_s

    async def sign_verdict(self, payload: dict[str, Any]) -> str:
        # SECURITY: pin the exact key_version used for THIS signature up front
        # (rather than letting Vault silently pick "latest" at sign time) so
        # the `kid` embedded in the header is guaranteed to match the version
        # that actually produced the signature, even if the key rotates
        # between these two calls.
        key_version = await asyncio.to_thread(self._latest_key_version)
        now = int(time.time())
        claims = {
            **payload,
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + self._ttl_s,  # SECURITY: short TTL, bound per coding spec §6 SignerPort
        }
        header = {"alg": "RS256", "typ": "JWT", "kid": f"{self._key_name}:{key_version}"}
        header_b64 = _b64url_encode_json(header)
        claims_b64 = _b64url_encode_json(claims)
        signing_input = f"{header_b64}.{claims_b64}".encode("ascii")

        signature_b64url = await asyncio.to_thread(self._sign, signing_input, key_version)
        return f"{header_b64}.{claims_b64}.{signature_b64url}"

    def _latest_key_version(self) -> int:
        resp = self._client.secrets.transit.read_key(
            name=self._key_name, mount_point=self._mount_point
        )
        return int(resp["data"]["latest_version"])

    def _sign(self, signing_input: bytes, key_version: int) -> str:
        resp = self._client.secrets.transit.sign_data(
            name=self._key_name,
            hash_input=base64.b64encode(signing_input).decode("ascii"),
            key_version=key_version,
            hash_algorithm="sha2-256",
            signature_algorithm="pkcs1v15",  # RSASSA-PKCS1-v1_5 - matches JWS RS256 exactly
            mount_point=self._mount_point,
        )
        vault_signature = resp["data"]["signature"]
        # SECURITY: Vault wraps the raw signature as "vault:v<wrapper_version>:<base64>"
        # - `rsplit(":", 1)` strips whatever wrapper-format version prefix Vault used
        # (a Vault-internal versioning scheme, distinct from the Transit KEY version
        # above) rather than assuming a hardcoded "vault:v1:", so a future Vault
        # signature-wrapper bump doesn't silently break parsing.
        raw_signature = base64.b64decode(vault_signature.rsplit(":", 1)[-1])
        return _b64url_encode(raw_signature)

    async def jwks(self) -> dict[str, Any]:
        return await asyncio.to_thread(self._jwks_sync)

    def _jwks_sync(self) -> dict[str, Any]:
        resp = self._client.secrets.transit.read_key(
            name=self._key_name, mount_point=self._mount_point
        )
        keys_by_version: dict[str, dict[str, Any]] = resp["data"]["keys"]
        jwks_keys: list[dict[str, Any]] = []
        for version, key_info in keys_by_version.items():
            public_key = load_pem_public_key(key_info["public_key"].encode("ascii"))
            if not isinstance(public_key, rsa.RSAPublicKey):
                # SECURITY: this signer only ever produces RS256 JWS - an unexpected
                # non-RSA key version (shouldn't happen for an rsa-2048 Transit key)
                # is skipped rather than raising, so one odd version can't take the
                # whole jwks endpoint down; the marketplace simply won't have that
                # version's public key, matching "unknown kid -> reject" on its side.
                continue
            numbers = public_key.public_numbers()
            jwks_keys.append(
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": f"{self._key_name}:{version}",
                    "n": _b64url_uint(numbers.n),
                    "e": _b64url_uint(numbers.e),
                }
            )
        return {"keys": jwks_keys}
