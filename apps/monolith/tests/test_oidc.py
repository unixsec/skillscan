"""Tests for the OIDC RP (coding spec §11.2). Negative cases mirror SAD Appendix D:
'ID token 签名/aud/iss/exp 无效→拒;redirect_uri 非白名单→拒;无/错 PKCE→拒;
缺/错 state→拒;缺/错 nonce→拒'.

No live IdP is used - tokens are signed locally with a test RSA keypair, which
exercises the exact same authlib validation path a real IdP's tokens would go
through (issuer/audience/expiry/nonce are payload claims, not transport-level
concerns, so this is a faithful test of the validation logic itself).
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import httpx
import pytest
from authlib.jose import JsonWebKey, JsonWebToken
from common.config import OidcSettings
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from monolith.modules.gateway.auth.oidc import (
    AuthorizationRequestState,
    OidcError,
    begin_authorization,
    complete_authorization,
    validate_id_token,
)

ISSUER = "https://localhost/"
CLIENT_ID = "test-client"
NONCE = "expected-nonce-value"

# (private JWK, public JWKS document, raw cryptography private key)
RsaKeys = tuple[Any, dict[str, Any], Any]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.fixture(scope="module")
def rsa_keys() -> RsaKeys:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    jwk_priv = JsonWebKey.import_key(
        private_pem, {"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "test-key"}
    )
    jwk_pub = JsonWebKey.import_key(
        public_pem, {"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "test-key"}
    )
    jwks = {"keys": [json.loads(jwk_pub.as_json())]}
    return jwk_priv, jwks, private_key


def _make_claims(**overrides: object) -> dict[str, Any]:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "alice",
        "exp": now + 300,
        "iat": now,
        "nonce": NONCE,
    }
    claims.update(overrides)
    return claims


def _sign(rsa_keys: RsaKeys, claims: dict[str, Any]) -> str:
    jwk_priv, _jwks, _key = rsa_keys
    validator = JsonWebToken(algorithms=["RS256"])
    token = validator.encode({"alg": "RS256", "kid": "test-key"}, claims, jwk_priv)
    return token.decode() if isinstance(token, bytes) else token


class TestValidateIdToken:
    def test_valid_token_accepted(self, rsa_keys: RsaKeys) -> None:
        _jwk_priv, jwks, _key = rsa_keys
        token = _sign(rsa_keys, _make_claims())
        identity = validate_id_token(token, jwks, issuer=ISSUER, client_id=CLIENT_ID, nonce=NONCE)
        assert identity.subject == "alice"
        assert identity.issuer == ISSUER

    def test_wrong_issuer_rejected(self, rsa_keys: RsaKeys) -> None:
        _jwk_priv, jwks, _key = rsa_keys
        token = _sign(rsa_keys, _make_claims(iss="https://attacker.localhost/"))
        with pytest.raises(OidcError):
            validate_id_token(token, jwks, issuer=ISSUER, client_id=CLIENT_ID, nonce=NONCE)

    def test_wrong_audience_rejected(self, rsa_keys: RsaKeys) -> None:
        _jwk_priv, jwks, _key = rsa_keys
        token = _sign(rsa_keys, _make_claims(aud="some-other-client"))
        with pytest.raises(OidcError):
            validate_id_token(token, jwks, issuer=ISSUER, client_id=CLIENT_ID, nonce=NONCE)

    def test_expired_token_rejected(self, rsa_keys: RsaKeys) -> None:
        _jwk_priv, jwks, _key = rsa_keys
        token = _sign(rsa_keys, _make_claims(exp=int(time.time()) - 60))
        with pytest.raises(OidcError):
            validate_id_token(token, jwks, issuer=ISSUER, client_id=CLIENT_ID, nonce=NONCE)

    def test_missing_exp_rejected(self, rsa_keys: RsaKeys) -> None:
        _jwk_priv, jwks, _key = rsa_keys
        claims = _make_claims()
        del claims["exp"]
        token = _sign(rsa_keys, claims)
        with pytest.raises(OidcError):
            validate_id_token(token, jwks, issuer=ISSUER, client_id=CLIENT_ID, nonce=NONCE)

    def test_wrong_nonce_rejected(self, rsa_keys: RsaKeys) -> None:
        _jwk_priv, jwks, _key = rsa_keys
        token = _sign(rsa_keys, _make_claims(nonce="attacker-supplied-nonce"))
        with pytest.raises(OidcError):
            validate_id_token(token, jwks, issuer=ISSUER, client_id=CLIENT_ID, nonce=NONCE)

    def test_missing_nonce_rejected(self, rsa_keys: RsaKeys) -> None:
        _jwk_priv, jwks, _key = rsa_keys
        claims = _make_claims()
        del claims["nonce"]
        token = _sign(rsa_keys, claims)
        with pytest.raises(OidcError):
            validate_id_token(token, jwks, issuer=ISSUER, client_id=CLIENT_ID, nonce=NONCE)

    def test_missing_sub_rejected(self, rsa_keys: RsaKeys) -> None:
        _jwk_priv, jwks, _key = rsa_keys
        claims = _make_claims()
        del claims["sub"]
        token = _sign(rsa_keys, claims)
        with pytest.raises(OidcError):
            validate_id_token(token, jwks, issuer=ISSUER, client_id=CLIENT_ID, nonce=NONCE)

    def test_alg_none_rejected(self, rsa_keys: RsaKeys) -> None:
        _jwk_priv, jwks, _key = rsa_keys
        header = _b64url(json.dumps({"alg": "none"}).encode())
        payload = _b64url(json.dumps(_make_claims()).encode())
        token = f"{header}.{payload}."
        with pytest.raises(OidcError):
            validate_id_token(token, jwks, issuer=ISSUER, client_id=CLIENT_ID, nonce=NONCE)

    def test_tampered_signature_rejected(self, rsa_keys: RsaKeys) -> None:
        _jwk_priv, jwks, _key = rsa_keys
        token = _sign(rsa_keys, _make_claims())
        header_b64, payload_b64, sig_b64 = token.split(".")
        tampered_payload = _b64url(json.dumps(_make_claims(sub="mallory")).encode())
        tampered_token = f"{header_b64}.{tampered_payload}.{sig_b64}"
        with pytest.raises(OidcError):
            validate_id_token(tampered_token, jwks, issuer=ISSUER, client_id=CLIENT_ID, nonce=NONCE)

    def test_hs256_confusion_attack_rejected(self, rsa_keys: RsaKeys) -> None:
        # SECURITY: classic algorithm-confusion attack - attacker signs with HS256
        # using the RSA public key (PEM text) as the HMAC secret, hoping a naive
        # validator that trusts the token's own `alg` header will verify it.
        _jwk_priv, jwks, _key = rsa_keys
        public_pem_text = json.dumps(jwks)  # any public material stands in as the "guessed secret"
        header = _b64url(json.dumps({"alg": "HS256"}).encode())
        payload = _b64url(json.dumps(_make_claims()).encode())
        signing_input = f"{header}.{payload}".encode()
        import hashlib
        import hmac

        sig = _b64url(hmac.new(public_pem_text.encode(), signing_input, hashlib.sha256).digest())
        forged_token = f"{header}.{payload}.{sig}"
        with pytest.raises(OidcError):
            validate_id_token(forged_token, jwks, issuer=ISSUER, client_id=CLIENT_ID, nonce=NONCE)


class TestBeginAuthorization:
    def _settings(self) -> OidcSettings:
        return OidcSettings(
            issuer=ISSUER,
            client_id=CLIENT_ID,
            client_secret="test-secret",
            redirect_uri_allowlist=("https://localhost/callback",),
            authorization_endpoint="https://localhost/authorize",
            token_endpoint="https://localhost/token",
            jwks_uri="https://localhost/jwks",
        )

    def test_uses_s256_pkce_only(self) -> None:
        url, state = begin_authorization(self._settings())
        assert "code_challenge_method=S256" in url
        assert "code_challenge=" in url
        assert len(state.code_verifier) >= 43  # RFC 7636 minimum length

    def test_state_and_nonce_are_unpredictable(self) -> None:
        _url1, state1 = begin_authorization(self._settings())
        _url2, state2 = begin_authorization(self._settings())
        assert state1.state != state2.state
        assert state1.nonce != state2.nonce


class TestCompleteAuthorization:
    def _settings(self) -> OidcSettings:
        return OidcSettings(
            issuer=ISSUER,
            client_id=CLIENT_ID,
            client_secret="test-secret",
            redirect_uri_allowlist=("https://localhost/callback",),
            authorization_endpoint="https://localhost/authorize",
            token_endpoint="https://localhost/token",
            jwks_uri="https://localhost/jwks",
        )

    def _stored_state(self) -> AuthorizationRequestState:
        return AuthorizationRequestState(
            state="server-generated-state",
            nonce=NONCE,
            code_verifier="server-generated-verifier",
            redirect_uri="https://localhost/callback",
            created_at=time.time(),
        )

    @pytest.mark.asyncio
    async def test_state_mismatch_rejected_before_any_network_call(self) -> None:
        async def _unexpected(request: httpx.Request) -> httpx.Response:
            raise AssertionError("must not make network calls when state mismatches")

        async with httpx.AsyncClient(transport=httpx.MockTransport(_unexpected)) as client:
            with pytest.raises(OidcError, match="state mismatch"):
                await complete_authorization(
                    settings=self._settings(),
                    http_client=client,
                    stored=self._stored_state(),
                    received_state="attacker-supplied-state",
                    received_redirect_uri="https://localhost/callback",
                    code="irrelevant",
                )

    @pytest.mark.asyncio
    async def test_redirect_uri_not_in_allowlist_rejected(self) -> None:
        async def _unexpected(request: httpx.Request) -> httpx.Response:
            raise AssertionError("must not make network calls when redirect_uri is not allowlisted")

        async with httpx.AsyncClient(transport=httpx.MockTransport(_unexpected)) as client:
            with pytest.raises(OidcError, match="redirect_uri"):
                await complete_authorization(
                    settings=self._settings(),
                    http_client=client,
                    stored=self._stored_state(),
                    received_state="server-generated-state",
                    received_redirect_uri="https://attacker.localhost/callback",
                    code="irrelevant",
                )

    @pytest.mark.asyncio
    async def test_full_flow_with_mocked_idp(self, rsa_keys: RsaKeys) -> None:
        _jwk_priv, jwks, _key = rsa_keys
        id_token = _sign(rsa_keys, _make_claims())

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/token":
                return httpx.Response(
                    200,
                    json={
                        "id_token": id_token,
                        "access_token": "real-opaque-access-token",
                        "token_type": "Bearer",
                    },
                )
            if request.url.path == "/jwks":
                return httpx.Response(200, json=jwks)
            raise AssertionError(f"unexpected request to {request.url}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as client:
            identity = await complete_authorization(
                settings=self._settings(),
                http_client=client,
                stored=self._stored_state(),
                received_state="server-generated-state",
                received_redirect_uri="https://localhost/callback",
                code="valid-code",
            )
        assert identity.subject == "alice"
        # SECURITY (2026-07-06 login-callback fix): this is the opaque token a
        # real login callback hands to session.authenticate() as the session
        # cookie value - id_token alone can't serve that role (see OidcIdentity's
        # own docstring on the access_token field).
        assert identity.access_token == "real-opaque-access-token"

    @pytest.mark.asyncio
    async def test_missing_access_token_in_token_response_is_rejected(
        self, rsa_keys: RsaKeys
    ) -> None:
        # SECURITY: a token response missing access_token can't back a session
        # session.authenticate() will ever be able to introspect later - fail
        # closed at login time rather than minting a session doomed to 401 on
        # its very next request.
        _jwk_priv, jwks, _key = rsa_keys
        id_token = _sign(rsa_keys, _make_claims())

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/token":
                return httpx.Response(200, json={"id_token": id_token, "token_type": "Bearer"})
            if request.url.path == "/jwks":
                return httpx.Response(200, json=jwks)
            raise AssertionError(f"unexpected request to {request.url}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as client:
            with pytest.raises(OidcError, match="access_token"):
                await complete_authorization(
                    settings=self._settings(),
                    http_client=client,
                    stored=self._stored_state(),
                    received_state="server-generated-state",
                    received_redirect_uri="https://localhost/callback",
                    code="valid-code",
                )
