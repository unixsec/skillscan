"""Tests for libs/common: config validation, log redaction, error contract, mTLS parsing."""

from __future__ import annotations

import json
import logging

import pytest
from common.config import OidcSettings, SamlSettings, SessionSettings, is_internal_host
from common.errors import ApiError, AuthenticationError, AuthorizationError, ValidationError
from common.log import RedactionFilter, get_logger, redact_mapping, redact_text
from common.mtls import parse_spiffe_identity, service_account_from_spiffe
from pydantic import ValidationError as PydanticValidationError


class TestInternalEndpointValidation:
    def test_loopback_is_internal(self) -> None:
        assert is_internal_host("localhost")
        assert is_internal_host("127.0.0.1")

    def test_public_host_is_not_internal(self) -> None:
        # A well-known public resolver IP wrapped in a hostname-like check.
        assert not is_internal_host("8.8.8.8")

    def test_unresolvable_host_is_not_internal(self) -> None:
        assert not is_internal_host("this-host-should-not-resolve.invalid")

    def test_oidc_settings_rejects_public_issuer(self) -> None:
        with pytest.raises(PydanticValidationError):
            OidcSettings(
                issuer="https://8.8.8.8/",
                client_id="cid",
                client_secret="secret",
                redirect_uri_allowlist=("https://localhost/callback",),
                authorization_endpoint="https://localhost/auth",
                token_endpoint="https://localhost/token",
                jwks_uri="https://localhost/jwks",
            )

    def test_oidc_settings_accepts_internal_endpoints(self) -> None:
        settings = OidcSettings(
            issuer="https://localhost/",
            client_id="cid",
            client_secret="secret",
            redirect_uri_allowlist=("https://localhost/callback",),
            authorization_endpoint="https://localhost/auth",
            token_endpoint="https://localhost/token",
            jwks_uri="https://localhost/jwks",
        )
        assert settings.issuer == "https://localhost/"

    def test_saml_settings_rejects_public_idp(self) -> None:
        with pytest.raises(PydanticValidationError):
            SamlSettings(
                sp_entity_id="urn:skillscan:sp",
                sp_acs_url="https://localhost/saml/acs",
                idp_entity_id="urn:idp",
                idp_sso_url="https://8.8.8.8/sso",
                idp_x509_cert="MIIB...",
            )

    def test_session_settings_enforces_ttl_ceilings(self) -> None:
        with pytest.raises(PydanticValidationError):
            SessionSettings(
                introspection_endpoint="https://localhost/introspect",
                introspection_client_id="cid",
                introspection_client_secret="secret",
                introspection_cache_ttl_s=60,  # > 30s ceiling
            )
        with pytest.raises(PydanticValidationError):
            SessionSettings(
                introspection_endpoint="https://localhost/introspect",
                introspection_client_id="cid",
                introspection_client_secret="secret",
                access_token_ttl_s=3600,  # > 600s ceiling
            )


class TestRedaction:
    def test_redact_mapping_scrubs_sensitive_keys(self) -> None:
        result = redact_mapping(
            {"user": "alice", "password": "hunter2", "nested": {"token": "abc"}}
        )
        assert result["user"] == "alice"
        assert result["password"] == "***REDACTED***"
        assert result["nested"]["token"] == "***REDACTED***"

    def test_redact_text_scrubs_bearer_tokens(self) -> None:
        text = "calling introspection with Bearer abc123.def456.ghi789"
        redacted = redact_text(text)
        assert "abc123" not in redacted
        assert "Bearer ***REDACTED***" in redacted

    def test_redact_text_scrubs_authorization_header(self) -> None:
        text = "Authorization: Basic dXNlcjpwYXNz"
        redacted = redact_text(text)
        assert "dXNlcjpwYXNz" not in redacted

    def test_get_logger_redacts_context_and_emits_json(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        logger = get_logger("skillscan.test.redaction")
        logger.setLevel(logging.INFO)
        logger.info(
            "session issued", extra={"context": {"subject": "alice", "token": "secret-value"}}
        )
        captured = capsys.readouterr()
        payload = json.loads(captured.err.strip().splitlines()[-1])
        assert payload["context"]["subject"] == "alice"
        assert payload["context"]["token"] == "***REDACTED***"
        assert "secret-value" not in captured.err

    def test_redaction_filter_is_idempotent_to_attach(self) -> None:
        logger = logging.getLogger("skillscan.test.idempotent")
        logger.addFilter(RedactionFilter())
        before = len(logger.filters)
        get_logger("skillscan.test.idempotent")
        assert len(logger.filters) == before


class TestErrors:
    def test_api_error_carries_status_and_detail(self) -> None:
        err = ApiError(status_code=418, code="teapot", detail="I'm a teapot")
        assert err.status_code == 418
        assert str(err) == "I'm a teapot"

    def test_authentication_error_defaults(self) -> None:
        err = AuthenticationError()
        assert err.status_code == 401
        assert err.code == "authentication_required"

    def test_authorization_error_defaults(self) -> None:
        err = AuthorizationError()
        assert err.status_code == 403

    def test_validation_error_requires_detail(self) -> None:
        err = ValidationError(detail="missing field 'scan_id'")
        assert err.status_code == 400
        assert "scan_id" in err.detail


class TestMtls:
    def test_parses_valid_spiffe_id(self) -> None:
        header = "By=spiffe://cluster.local/ns/skillscan-system/sa/gateway;URI=spiffe://cluster.local/ns/skillscan-workers/sa/engine-runner"
        assert (
            parse_spiffe_identity(header)
            == "spiffe://cluster.local/ns/skillscan-workers/sa/engine-runner"
        )

    def test_none_on_missing_header(self) -> None:
        assert parse_spiffe_identity(None) is None
        assert parse_spiffe_identity("") is None

    def test_none_on_malformed_header(self) -> None:
        assert parse_spiffe_identity("not-a-spiffe-header") is None

    def test_service_account_extraction(self) -> None:
        sa = service_account_from_spiffe(
            "spiffe://cluster.local/ns/skillscan-workers/sa/engine-runner"
        )
        assert sa == "engine-runner"
