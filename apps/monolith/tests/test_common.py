"""Tests for libs/common: config validation, log redaction, error contract, mTLS parsing.

Needs NO MySQL and NO Redis - `conftest.py`'s infrastructure fixtures are all
opt-in (none are autouse), so this file is runnable on a developer machine
under the repo's VM-only rule for anything that touches real services.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Iterator

import pytest
from common.config import OidcSettings, SamlSettings, SessionSettings, is_internal_host
from common.errors import ApiError, AuthenticationError, AuthorizationError, ValidationError
from common.log import (
    RedactionFilter,
    get_logger,
    redact_mapping,
    redact_text,
    redact_url_credentials,
)
from common.mtls import parse_spiffe_identity, service_account_from_spiffe
from pydantic import ValidationError as PydanticValidationError


class _RecordingHandler(logging.Handler):
    """Records the LogRecords a logger actually hands to a handler.

    This is the whole point of `TestLoggerLevel` below. The 2026-07-29 defect
    was NOT "setLevel was never called" - that is only its cause. The symptom
    is "the handler never saw the record", and every assertion one could write
    about the shape of the configuration (a handler is installed, a formatter
    is set, a filter is attached, `propagate` is False) passed happily against
    the broken code. Only observing the record's arrival distinguishes them.
    """

    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def fresh_logger_name() -> Iterator[str]:
    """A logger name no other test has touched, torn down afterwards.

    `logging` caches loggers process-wide and `get_logger` only installs its
    StreamHandler once per name, so a shared name would make these tests depend
    on execution order - the exact class of accident that let the level defect
    survive.
    """
    name = f"skillscan.test.level.{uuid.uuid4().hex}"
    yield name
    logger = logging.getLogger(name)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    for log_filter in list(logger.filters):
        logger.removeFilter(log_filter)
    logger.setLevel(logging.NOTSET)
    logger.propagate = True
    logging.Logger.manager.loggerDict.pop(name, None)


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

    def test_redact_mapping_scrubs_the_jws_spelling_the_codebase_uses(self) -> None:
        # SECURITY (2026-07-29): `gate_outbox`'s verdict_issued payload keys the
        # signed verdict as `jws`, and integration_relay's log-only branch logs
        # that payload whole. `_SENSITIVE_KEYS` listed `jwt` - the spelling this
        # codebase never uses - so the only spelling that occurs in real data
        # was the one not covered.
        result = redact_mapping(
            {"scan_id": "s1", "jti": "j1", "jws": "eyJhbGciOiJSUzI1NiJ9.body.signature"}
        )
        assert result["scan_id"] == "s1"
        assert result["jti"] == "j1"  # the correlation id stays useful
        assert result["jws"] == "***REDACTED***"

    def test_redact_mapping_strips_url_credentials_and_keeps_the_host(self) -> None:
        # Not full redaction: "which Redis am I talking to?" is the reason the
        # field is logged at all, and a bare ***REDACTED*** answers nothing.
        result = redact_mapping({"redis_url": "redis://:hunter2@redis:6379/0"})
        assert result["redis_url"] == "redis://***REDACTED***@redis:6379/0"
        assert "hunter2" not in result["redis_url"]

    def test_credential_free_urls_and_paths_are_left_alone(self) -> None:
        assert redact_url_credentials("redis://redis:6379/0") == "redis://redis:6379/0"
        # The `@` sits in the PATH, not the authority - must not be mistaken for
        # userinfo and eat the hostname with it.
        assert redact_text("fetched https://idp.internal/u@x") == "fetched https://idp.internal/u@x"

    def test_redact_text_strips_credentials_from_a_free_form_message(self) -> None:
        redacted = redact_text("connect failed: mysql://svc_gate:pw@db.internal/skillscan")
        assert "pw@" not in redacted
        assert "db.internal/skillscan" in redacted

    def test_get_logger_redacts_context_and_emits_json(
        self, fresh_logger_name: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # NOTE (2026-07-29): this test used to call `logger.setLevel(INFO)`
        # itself. That one line is why the whole suite was green while every
        # INFO record in the product was being dropped - the test supplied the
        # configuration it was supposed to be verifying. It is deliberately not
        # here any more; `get_logger` must arrive already able to log at INFO.
        logger = get_logger(fresh_logger_name)
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


class TestLoggerLevel:
    """Regression tests for the 2026-07-29 silent-INFO defect.

    `get_logger` attached a RedactionFilter, attached a StreamHandler with the
    JSON formatter and set `propagate = False`, but never called `setLevel`.
    Effective level therefore resolved to the root logger's WARNING, so every
    `.info(...)` in the monolith and the engine-runner returned at
    `isEnabledFor` and the handler it had just been given was never reached.
    """

    def test_an_info_record_actually_reaches_a_handler(
        self, fresh_logger_name: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The one assertion that fails against the old code.

        Note the ORDER: `get_logger` first (so it installs its own handler on a
        name with none), the recorder second. That way this checks both routes -
        the record reaches a handler at all, AND the handler `get_logger`
        configured really wrote the JSON line to its stream.
        """
        logger = get_logger(fresh_logger_name)
        recorder = _RecordingHandler()
        logger.addHandler(recorder)

        logger.info("sandbox engine reported", extra={"context": {"engine": "osv-scanner"}})

        assert [record.getMessage() for record in recorder.records] == ["sandbox engine reported"]
        emitted = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
        assert emitted["level"] == "INFO"
        assert emitted["context"]["engine"] == "osv-scanner"

    def test_the_level_is_set_on_the_logger_not_inherited(self, fresh_logger_name: str) -> None:
        # `propagate = False` plus an unset level is the trap: the effective
        # level comes from an ancestor the records can never actually reach.
        logger = get_logger(fresh_logger_name)
        assert logger.level == logging.INFO
        assert logger.getEffectiveLevel() == logging.INFO

    def test_the_env_var_selects_the_level(
        self, fresh_logger_name: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SKILLSCAN_LOG_LEVEL", "warning")  # case-insensitive
        logger = get_logger(fresh_logger_name)
        recorder = _RecordingHandler()
        logger.addHandler(recorder)

        logger.info("below the configured level")
        logger.warning("at the configured level")

        assert [record.getMessage() for record in recorder.records] == ["at the configured level"]

    def test_an_invalid_level_falls_back_to_info_and_says_so_loudly(
        self,
        fresh_logger_name: str,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # The failure mode being designed against is the old one: a whole
        # severity vanishing with no signal. A typo must never be quieter than
        # the default, and must announce itself above the level it broke.
        monkeypatch.setattr("common.log._bad_level_reported", False)
        monkeypatch.setenv("SKILLSCAN_LOG_LEVEL", "INF0")
        logger = get_logger(fresh_logger_name)

        assert logger.level == logging.INFO
        emitted = [
            json.loads(line) for line in capsys.readouterr().err.strip().splitlines() if line
        ]
        complaints = [
            p for p in emitted if p.get("context", {}).get("metric") == "log_level_invalid"
        ]
        assert len(complaints) == 1
        assert complaints[0]["level"] == "WARNING"
        assert complaints[0]["context"]["rejected_value"] == "INF0"
        assert "INFO" in complaints[0]["context"]["valid_values"]

    def test_notset_is_rejected_rather_than_reinstating_the_defect(
        self,
        fresh_logger_name: str,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # `setLevel(NOTSET)` means "ask an ancestor", which under
        # `propagate = False` is exactly the original bug - reachable through a
        # config value that looks perfectly legitimate.
        monkeypatch.setattr("common.log._bad_level_reported", False)
        monkeypatch.setenv("SKILLSCAN_LOG_LEVEL", "NOTSET")
        logger = get_logger(fresh_logger_name)
        recorder = _RecordingHandler()
        logger.addHandler(recorder)

        logger.info("still emitted")

        assert logger.level == logging.INFO
        assert [record.getMessage() for record in recorder.records] == ["still emitted"]
        assert "log_level_invalid" in capsys.readouterr().err


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
