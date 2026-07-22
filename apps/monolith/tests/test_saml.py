"""Tests for the SAML SP (coding spec §11.2). Negative cases mirror SAD Appendix D:
'篡改断言不改签名→拒;签名排除→拒;XXE/实体炸弹→拒且不DoS;过期/未来NotBefore→拒;
错Audience/Recipient→拒;重放同断言→第二次拒'.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import redis.asyncio as aioredis
from common.config import SamlSettings

from monolith.modules.gateway.auth.saml import (
    _SAML_SESSION_KEY_PREFIX,
    SamlError,
    SamlIdentity,
    SamlRequestTracker,
    create_saml_session,
    process_saml_response,
    resolve_saml_session,
)
from monolith.tests._saml_fixtures import (
    ACS_URL,
    ISSUER,
    SP_ENTITY_ID,
    IdpFixture,
    build_saml_response,
    make_test_idp,
    to_request_data,
)


@pytest.fixture(scope="module")
def idp() -> IdpFixture:
    return make_test_idp()


@pytest.fixture
def settings(idp: IdpFixture) -> SamlSettings:
    return SamlSettings(
        sp_entity_id=SP_ENTITY_ID,
        sp_acs_url=ACS_URL,
        idp_entity_id="https://idp.localhost/",
        idp_sso_url="https://idp.localhost/sso",
        idp_x509_cert=idp.cert_pem_body,
    )


def _run(
    settings: SamlSettings,
    response_xml: str,
    request_id: str,
    *,
    tracker: SamlRequestTracker | None = None,
) -> SamlIdentity:
    tracker = tracker or SamlRequestTracker()
    tracker.register(request_id)
    return process_saml_response(
        settings, to_request_data(response_xml), tracker=tracker, expected_request_id=request_id
    )


class TestValidResponse:
    def test_valid_signed_response_accepted(self, idp: IdpFixture, settings: SamlSettings) -> None:
        response_xml, request_id = build_saml_response(idp)
        identity = _run(settings, response_xml, request_id)
        assert identity.name_id == "alice@example.com"
        assert identity.attributes["groups"] == ["skillscan-approvers"]


class TestSignatureEnforcement:
    def test_unsigned_assertion_rejected(self, idp: IdpFixture, settings: SamlSettings) -> None:
        response_xml, request_id = build_saml_response(idp, sign=False)
        with pytest.raises(SamlError):
            _run(settings, response_xml, request_id)

    def test_tampered_assertion_rejected(self, idp: IdpFixture, settings: SamlSettings) -> None:
        response_xml, request_id = build_saml_response(idp)
        tampered = response_xml.replace("alice@example.com", "mallory@example.com")
        with pytest.raises(SamlError):
            _run(settings, tampered, request_id)

    def test_signature_stripped_after_signing_rejected(
        self, idp: IdpFixture, settings: SamlSettings
    ) -> None:
        response_xml, request_id = build_saml_response(idp)
        # SECURITY: "signature exclusion" - remove the <ds:Signature> block entirely
        # while everything else stays intact, hoping a lax validator only checks
        # the signature IF one is present.
        stripped = re.sub(r"<ds:Signature.*?</ds:Signature>", "", response_xml, flags=re.DOTALL)
        with pytest.raises(SamlError):
            _run(settings, stripped, request_id)


class TestXmlSignatureWrapping:
    # SECURITY (coding spec §11.2 M2 acceptance: "XSW→拒", distinct from the
    # signature-stripped/tampered/unsigned cases in TestSignatureEnforcement
    # above): the classic XML Signature Wrapping attack clones the legitimately
    # signed assertion, then presents a SECOND, attacker-forged assertion
    # (different NameID/attributes, no valid signature of its own) in the
    # position business logic would naively read - e.g. first in document
    # order - while the original signed assertion is still present elsewhere
    # in the document so a signature verification step finds something valid
    # to check. A vulnerable implementation validates "a" signature is present
    # and correct, then extracts identity from whichever assertion sits in the
    # expected structural position rather than the one the signature actually
    # covers - authenticating as the forged identity. This test proves
    # process_saml_response does NOT do that: python3-saml resolves the
    # assertion it trusts by the Signature's own Reference URI (ID-based),
    # not by document position, so a forged sibling assertion must not grant
    # the attacker's identity.
    def test_forged_sibling_assertion_before_signed_original_is_rejected(
        self, idp: IdpFixture, settings: SamlSettings
    ) -> None:
        response_xml, request_id = build_saml_response(idp)
        match = re.search(r"<saml:Assertion\b.*</saml:Assertion>", response_xml, flags=re.DOTALL)
        assert match is not None, "test fixture didn't produce a parseable assertion block"
        signed_assertion = match.group(0)

        now = datetime.now(UTC)
        now_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        forged_id = "_" + uuid.uuid4().hex
        not_on_or_after = (now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        not_before = (now - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        password_protected_transport = (
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
        )
        emailaddress_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        # Attacker-forged assertion: no signature of its own, escalated identity
        # (admin group instead of the original approver group) - this is the
        # payload an XSW attack tries to smuggle past the app as authenticated.
        forged_assertion = f"""<saml:Assertion
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{forged_id}"
    Version="2.0" IssueInstant="{now_str}">
<saml:Issuer>{ISSUER}</saml:Issuer>
<saml:Subject>
<saml:NameID Format="{emailaddress_format}">mallory@evil.example.com</saml:NameID>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
<saml:SubjectConfirmationData
    NotOnOrAfter="{not_on_or_after}" Recipient="{ACS_URL}" InResponseTo="{request_id}"/>
</saml:SubjectConfirmation>
</saml:Subject>
<saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
<saml:AudienceRestriction><saml:Audience>{SP_ENTITY_ID}</saml:Audience></saml:AudienceRestriction>
</saml:Conditions>
<saml:AuthnStatement AuthnInstant="{now_str}" SessionIndex="_forged_session">
<saml:AuthnContext><saml:AuthnContextClassRef>{password_protected_transport}</saml:AuthnContextClassRef></saml:AuthnContext>
</saml:AuthnStatement>
<saml:AttributeStatement>
<saml:Attribute Name="groups">
<saml:AttributeValue>skillscan-admins</saml:AttributeValue>
</saml:Attribute>
</saml:AttributeStatement>
</saml:Assertion>"""

        # The forged assertion is placed FIRST (the position naive "first
        # assertion in document order" business logic would read); the
        # original, validly-signed assertion for alice follows it unchanged -
        # a real signature-verification pass over the document still finds a
        # valid signature, just not one that covers the forged content.
        wrapped_xml = response_xml.replace(signed_assertion, forged_assertion + signed_assertion)
        assert wrapped_xml.count("<saml:Assertion") == 2, "expected exactly two assertions"

        with pytest.raises(SamlError):
            identity = _run(settings, wrapped_xml, request_id)
            # If this line is ever reached, process_saml_response failed to
            # reject the wrapped response - fail loudly with which identity it
            # would have handed to the caller rather than let a bare
            # "expected SamlError, got none" obscure the actual severity.
            pytest.fail(
                f"XSW attack was NOT rejected - resolved identity: {identity.name_id!r}, "
                f"attributes: {identity.attributes!r}"
            )


class TestTemporalAndScopeValidation:
    def test_wrong_audience_rejected(self, idp: IdpFixture, settings: SamlSettings) -> None:
        response_xml, request_id = build_saml_response(idp, audience="urn:someone-else:sp")
        with pytest.raises(SamlError):
            _run(settings, response_xml, request_id)

    def test_wrong_recipient_rejected(self, idp: IdpFixture, settings: SamlSettings) -> None:
        response_xml, request_id = build_saml_response(
            idp, recipient="https://attacker.localhost/acs"
        )
        with pytest.raises(SamlError):
            _run(settings, response_xml, request_id)

    def test_expired_response_rejected(self, idp: IdpFixture, settings: SamlSettings) -> None:
        response_xml, request_id = build_saml_response(
            idp, not_on_or_after_delta=timedelta(minutes=-5)
        )
        with pytest.raises(SamlError):
            _run(settings, response_xml, request_id)


class TestReplayProtection:
    def test_unknown_request_id_rejected(self, idp: IdpFixture, settings: SamlSettings) -> None:
        response_xml, _request_id = build_saml_response(idp)
        tracker = SamlRequestTracker()  # never registered anything
        with pytest.raises(SamlError, match="replay"):
            process_saml_response(
                settings,
                to_request_data(response_xml),
                tracker=tracker,
                expected_request_id="_never_registered",
            )

    def test_second_use_of_same_request_id_rejected(
        self, idp: IdpFixture, settings: SamlSettings
    ) -> None:
        response_xml, request_id = build_saml_response(idp)
        tracker = SamlRequestTracker()
        tracker.register(request_id)
        # First use succeeds.
        identity = process_saml_response(
            settings, to_request_data(response_xml), tracker=tracker, expected_request_id=request_id
        )
        assert identity.name_id == "alice@example.com"
        # Replaying the exact same response a second time must be rejected,
        # even though the response itself is a legitimately-signed one.
        with pytest.raises(SamlError, match="replay"):
            process_saml_response(
                settings,
                to_request_data(response_xml),
                tracker=tracker,
                expected_request_id=request_id,
            )

    def test_mismatched_in_response_to_rejected(
        self, idp: IdpFixture, settings: SamlSettings
    ) -> None:
        response_xml, _request_id = build_saml_response(idp)
        tracker = SamlRequestTracker()
        tracker.register("_a_different_expected_id")
        with pytest.raises(SamlError):
            process_saml_response(
                settings,
                to_request_data(response_xml),
                tracker=tracker,
                expected_request_id="_a_different_expected_id",
            )


class TestXxeHardening:
    def test_xxe_payload_rejected_not_dos(self, settings: SamlSettings) -> None:
        xxe_payload = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" '
            'IssueInstant="2026-01-01T00:00:00Z" Destination="https://localhost/saml/acs" '
            'InResponseTo="_req1">'
            "<saml:Issuer>&xxe;</saml:Issuer>"
            "<samlp:Status><samlp:StatusCode "
            'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
            "</samlp:Response>"
        )
        b64 = base64.b64encode(xxe_payload.encode()).decode()
        request_data: dict[str, Any] = {
            "http_host": "localhost",
            "script_name": "/saml/acs",
            "https": "on",
            "post_data": {"SAMLResponse": b64},
        }
        tracker = SamlRequestTracker()
        tracker.register("_req1")
        # SECURITY: must raise our SamlError (fail-closed), not crash the process
        # and not return an authenticated identity with the entity's content.
        with pytest.raises(SamlError):
            process_saml_response(
                settings, request_data, tracker=tracker, expected_request_id="_req1"
            )


class TestRequestTracker:
    def test_expired_registration_cannot_be_consumed(self) -> None:
        tracker = SamlRequestTracker()
        tracker.register("_req")
        tracker._outstanding["_req"] = 0.0  # force-expire without waiting 300s in a test
        assert tracker.consume("_req") is False

    def test_consume_is_one_time_only(self) -> None:
        tracker = SamlRequestTracker()
        tracker.register("_req")
        assert tracker.consume("_req") is True
        assert tracker.consume("_req") is False


class TestResolveSamlSessionFailClosed:
    """SECURITY regression lock (2026-07-22 code review). resolve_saml_session
    coerces the stored `roles` to a frozenset. A JSON-valid record whose
    `roles` is non-iterable/non-hashable must fail closed to None, NEVER raise:
    get_session_context resolves the SAML session BEFORE its 401 try-block
    (dependencies.py), so a TypeError escaping here would surface as an
    unhandled 500 instead of falling through to bearer/cookie auth. The normal
    write path always stores `sorted(roles)` (a list), so this only triggers on
    an out-of-band / cross-version / corrupt Redis writer - exactly the
    defense-in-depth case fail-closed exists for."""

    @pytest.mark.asyncio
    async def test_valid_session_round_trips(self, redis_client: aioredis.Redis) -> None:
        token = await create_saml_session(
            redis_client, subject="alice", roles=frozenset({"admin", "approver"})
        )
        assert await resolve_saml_session(redis_client, token) == (
            "alice",
            frozenset({"admin", "approver"}),
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("bad_roles", [123, None, True, [["nested-unhashable"]]])
    async def test_non_iterable_or_unhashable_roles_fail_closed(
        self, redis_client: aioredis.Redis, bad_roles: object
    ) -> None:
        token = f"corrupt-{uuid.uuid4().hex}"
        key = _SAML_SESSION_KEY_PREFIX + hashlib.sha256(token.encode()).hexdigest()
        await redis_client.set(key, json.dumps({"subject": "x", "roles": bad_roles}), ex=60)
        # Must return None, not raise.
        assert await resolve_saml_session(redis_client, token) is None
