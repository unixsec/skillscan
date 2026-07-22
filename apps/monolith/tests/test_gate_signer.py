"""Tests for `gate.signer` (coding spec §6/§11.3/§11.6).

`VaultTransitSigner` is exercised against a fake hvac Transit client backed by
a REAL in-process RSA key (not string fixtures) - `_FakeHvacTransit.sign_data`
performs a genuine `cryptography` PKCS1v15/SHA256 signature, and the fake's
response SHAPE mirrors what a real Vault Transit backend actually returns
(`{"data": {"key_version": int, "signature": "vault:v1:<base64>"}}` for sign,
`{"data": {"latest_version": int, "keys": {"<v>": {"public_key": PEM}}}}` for
read_key) - confirmed live against a real local Vault dev server (Transit
engine, rsa-2048 key) before that server was torn down per this project's
Homebrew-system-service-install policy (a fresh live Vault was not
re-authorized for the automated test suite; see docs/stories/BACKLOG.md's M6
status note). This proves VaultTransitSigner's OWN JWS-construction logic is
correct (RFC 7515 compact serialization, RS256) independent of whether a live
Vault is reachable in this environment - the produced JWS round-trips through
PyJWT, a completely independent standard library, which is what a real
marketplace verifier would also use.
"""

from __future__ import annotations

import base64
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from monolith.modules.gate.signer import LocalDevSigner, VaultTransitSigner


class _FakeHvacTransit:
    """Mimics hvac.Client().secrets.transit's sign_data/read_key just enough
    to exercise VaultTransitSigner - the `assert`s on call kwargs pin the
    exact Transit parameters VaultTransitSigner must send (sha2-256/pkcs1v15,
    the RS256-equivalent combination), turning a wrong-parameter regression
    into an immediate test failure rather than a silently-wrong signature."""

    def __init__(self, private_key: rsa.RSAPrivateKey, *, key_version: int = 1) -> None:
        self._private_key = private_key
        self.key_version = key_version
        self.sign_calls: list[dict[str, Any]] = []
        self.read_key_calls = 0

    def sign_data(
        self,
        *,
        name: str,
        hash_input: str,
        key_version: int | None = None,
        hash_algorithm: str | None = None,
        signature_algorithm: str | None = None,
        mount_point: str = "transit",
        **_kwargs: object,
    ) -> dict[str, Any]:
        assert hash_algorithm == "sha2-256"
        assert signature_algorithm == "pkcs1v15"
        assert key_version == self.key_version  # SECURITY: must pin the version it read
        self.sign_calls.append({"name": name, "mount_point": mount_point})
        data = base64.b64decode(hash_input)
        signature = self._private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        return {
            "data": {
                "key_version": key_version,
                "signature": f"vault:v1:{base64.b64encode(signature).decode('ascii')}",
            }
        }

    def read_key(self, *, name: str, mount_point: str = "transit") -> dict[str, Any]:
        self.read_key_calls += 1
        pem = (
            self._private_key.public_key()
            .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            .decode("ascii")
        )
        return {
            "data": {
                "name": name,
                "type": "rsa-2048",
                "latest_version": self.key_version,
                "keys": {str(self.key_version): {"name": "rsa-2048", "public_key": pem}},
            }
        }


class _FakeHvacSecrets:
    def __init__(self, transit: _FakeHvacTransit) -> None:
        self.transit = transit


class _FakeHvacClient:
    def __init__(self, transit: _FakeHvacTransit) -> None:
        self.secrets = _FakeHvacSecrets(transit)


@pytest.fixture
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def fake_transit(rsa_key: rsa.RSAPrivateKey) -> _FakeHvacTransit:
    return _FakeHvacTransit(rsa_key)


@pytest.fixture
def vault_signer(fake_transit: _FakeHvacTransit) -> VaultTransitSigner:
    return VaultTransitSigner(
        client=_FakeHvacClient(fake_transit),
        key_name="skillscan-gate-signing",
        ttl_s=120,
    )


class TestVaultTransitSigner:
    @pytest.mark.asyncio
    async def test_sign_verdict_produces_a_pyjwt_verifiable_rs256_jws(
        self, vault_signer: VaultTransitSigner, rsa_key: rsa.RSAPrivateKey
    ) -> None:
        jws = await vault_signer.sign_verdict({"content_hash": "a" * 64, "verdict": "PASS"})
        decoded = pyjwt.decode(jws, rsa_key.public_key(), algorithms=["RS256"])
        assert decoded["content_hash"] == "a" * 64
        assert decoded["verdict"] == "PASS"

    @pytest.mark.asyncio
    async def test_sign_verdict_adds_jti_iat_exp(self, vault_signer: VaultTransitSigner) -> None:
        jws = await vault_signer.sign_verdict({"content_hash": "b" * 64})
        unverified = pyjwt.decode(jws, options={"verify_signature": False})
        assert "jti" in unverified
        assert unverified["exp"] - unverified["iat"] == 120  # ttl_s passed to the fixture

    @pytest.mark.asyncio
    async def test_each_signature_gets_a_fresh_jti(self, vault_signer: VaultTransitSigner) -> None:
        jws_a = await vault_signer.sign_verdict({"content_hash": "c" * 64})
        jws_b = await vault_signer.sign_verdict({"content_hash": "c" * 64})
        jti_a = pyjwt.decode(jws_a, options={"verify_signature": False})["jti"]
        jti_b = pyjwt.decode(jws_b, options={"verify_signature": False})["jti"]
        assert jti_a != jti_b  # SECURITY (INV-13 anti-replay): jti must be unique per signature

    @pytest.mark.asyncio
    async def test_kid_header_encodes_key_name_and_pinned_version(
        self, vault_signer: VaultTransitSigner
    ) -> None:
        jws = await vault_signer.sign_verdict({"content_hash": "d" * 64})
        header = pyjwt.get_unverified_header(jws)
        assert header["kid"] == "skillscan-gate-signing:1"
        assert header["alg"] == "RS256"

    @pytest.mark.asyncio
    async def test_sign_data_called_with_correct_transit_algorithm_params(
        self, vault_signer: VaultTransitSigner, fake_transit: _FakeHvacTransit
    ) -> None:
        await vault_signer.sign_verdict({"content_hash": "e" * 64})
        assert len(fake_transit.sign_calls) == 1
        assert fake_transit.sign_calls[0]["name"] == "skillscan-gate-signing"

    @pytest.mark.asyncio
    async def test_wrong_public_key_fails_verification(
        self, vault_signer: VaultTransitSigner
    ) -> None:
        # SECURITY: proves this is a REAL signature check, not something that
        # would pass regardless of which key is used to verify.
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jws = await vault_signer.sign_verdict({"content_hash": "f" * 64})
        with pytest.raises(pyjwt.InvalidSignatureError):
            pyjwt.decode(jws, other_key.public_key(), algorithms=["RS256"])

    @pytest.mark.asyncio
    async def test_jwks_exposes_the_real_public_key(
        self, vault_signer: VaultTransitSigner, rsa_key: rsa.RSAPrivateKey
    ) -> None:
        jwks = await vault_signer.jwks()
        assert len(jwks["keys"]) == 1
        key = jwks["keys"][0]
        assert key["kid"] == "skillscan-gate-signing:1"
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"

        def _b64url_to_int(value: str) -> int:
            padded = value + "=" * (-len(value) % 4)
            return int.from_bytes(base64.urlsafe_b64decode(padded), "big")

        numbers = rsa_key.public_key().public_numbers()
        assert _b64url_to_int(key["n"]) == numbers.n
        assert _b64url_to_int(key["e"]) == numbers.e

    @pytest.mark.asyncio
    async def test_jwks_public_key_verifies_the_signature_end_to_end(
        self, vault_signer: VaultTransitSigner
    ) -> None:
        # SECURITY: the full loop a real marketplace performs - fetch jwks,
        # build a public key from n/e, verify a signature against it - proven
        # here with zero shortcuts (no reuse of the original rsa_key fixture).
        jws = await vault_signer.sign_verdict({"content_hash": "g" * 64})
        jwks = await vault_signer.jwks()
        key = jwks["keys"][0]

        def _b64url_to_int(value: str) -> int:
            padded = value + "=" * (-len(value) % 4)
            return int.from_bytes(base64.urlsafe_b64decode(padded), "big")

        public_numbers = rsa.RSAPublicNumbers(
            e=_b64url_to_int(key["e"]), n=_b64url_to_int(key["n"])
        )
        reconstructed_public_key = public_numbers.public_key()
        decoded = pyjwt.decode(jws, reconstructed_public_key, algorithms=["RS256"])
        assert decoded["content_hash"] == "g" * 64


class TestLocalDevSigner:
    @pytest.mark.asyncio
    async def test_sign_verdict_produces_a_verifiable_rs256_jws(self) -> None:
        signer = LocalDevSigner(ttl_s=60)
        jws = await signer.sign_verdict({"content_hash": "a" * 64})
        jwks = await signer.jwks()
        key = jwks["keys"][0]

        def _b64url_to_int(value: str) -> int:
            padded = value + "=" * (-len(value) % 4)
            return int.from_bytes(base64.urlsafe_b64decode(padded), "big")

        public_numbers = rsa.RSAPublicNumbers(
            e=_b64url_to_int(key["e"]), n=_b64url_to_int(key["n"])
        )
        decoded = pyjwt.decode(jws, public_numbers.public_key(), algorithms=["RS256"])
        assert decoded["content_hash"] == "a" * 64

    @pytest.mark.asyncio
    async def test_ttl_is_respected(self) -> None:
        signer = LocalDevSigner(ttl_s=42)
        jws = await signer.sign_verdict({"content_hash": "b" * 64})
        unverified = pyjwt.decode(jws, options={"verify_signature": False})
        assert unverified["exp"] - unverified["iat"] == 42
