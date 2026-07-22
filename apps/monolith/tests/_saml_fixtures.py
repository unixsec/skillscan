"""Shared SAML test-fixture builders - not a test module (doesn't match test*.py).

Builds a self-signed test IdP certificate and hand-assembled SAML Response XML,
signed via python3-saml's own `add_sign` utility, so tests exercise the exact
signature-validation path a real IdP's response would go through.
"""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from onelogin.saml2.utils import OneLogin_Saml2_Utils

ISSUER = "https://idp.localhost/"
SP_ENTITY_ID = "urn:skillscan:sp"
ACS_URL = "https://localhost/saml/acs"


@dataclass(frozen=True)
class IdpFixture:
    key_pem: str
    cert_pem: str
    cert_pem_body: str  # header/footer stripped, as python3-saml settings expect


def make_test_idp() -> IdpFixture:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-idp")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    cert_pem_body = "".join(cert_pem.strip().splitlines()[1:-1])
    return IdpFixture(key_pem=key_pem, cert_pem=cert_pem, cert_pem_body=cert_pem_body)


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_saml_response(
    idp: IdpFixture,
    *,
    sign: bool = True,
    audience: str = SP_ENTITY_ID,
    recipient: str = ACS_URL,
    not_on_or_after_delta: timedelta = timedelta(minutes=5),
    request_id: str | None = None,
    subject: str = "alice@example.com",
    groups: tuple[str, ...] = ("skillscan-approvers",),
) -> tuple[str, str]:
    """Returns (response_xml, request_id_used_as_InResponseTo)."""
    now = datetime.now(UTC)
    req_id = request_id or ("_" + uuid.uuid4().hex)
    assertion_id = "_" + uuid.uuid4().hex
    response_id = "_" + uuid.uuid4().hex
    group_values = "".join(f"<saml:AttributeValue>{g}</saml:AttributeValue>" for g in groups)

    not_on_or_after = _fmt(now + not_on_or_after_delta)
    not_before = _fmt(now - timedelta(minutes=1))
    password_protected_transport = (
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    )
    # NOTE: newlines below are only ever placed inside a start-tag's attribute
    # list (XML allows whitespace, including newlines, between attributes) or
    # between sibling elements - never between a tag and its own text content,
    # which would otherwise leak stray whitespace into the parsed value.
    assertion_xml = f"""<saml:Assertion
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{assertion_id}"
    Version="2.0" IssueInstant="{_fmt(now)}">
<saml:Issuer>{ISSUER}</saml:Issuer>
<saml:Subject>
<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{subject}</saml:NameID>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
<saml:SubjectConfirmationData
    NotOnOrAfter="{not_on_or_after}" Recipient="{recipient}" InResponseTo="{req_id}"/>
</saml:SubjectConfirmation>
</saml:Subject>
<saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>
</saml:Conditions>
<saml:AuthnStatement AuthnInstant="{_fmt(now)}" SessionIndex="_session123">
<saml:AuthnContext><saml:AuthnContextClassRef>{password_protected_transport}</saml:AuthnContextClassRef></saml:AuthnContext>
</saml:AuthnStatement>
<saml:AttributeStatement>
<saml:Attribute Name="groups">{group_values}</saml:Attribute>
</saml:AttributeStatement>
</saml:Assertion>"""

    if sign:
        signed = OneLogin_Saml2_Utils.add_sign(assertion_xml, idp.key_pem, idp.cert_pem, False)
        assertion_final = signed.decode() if isinstance(signed, bytes) else signed
    else:
        assertion_final = assertion_xml

    response_xml = f"""<samlp:Response
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{response_id}" Version="2.0" IssueInstant="{_fmt(now)}"
    Destination="{ACS_URL}" InResponseTo="{req_id}">
<saml:Issuer>{ISSUER}</saml:Issuer>
<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
{assertion_final}
</samlp:Response>"""
    return response_xml, req_id


def to_request_data(response_xml: str) -> dict[str, Any]:
    b64 = base64.b64encode(response_xml.encode()).decode()
    return {
        "http_host": "localhost",
        "script_name": "/saml/acs",
        "https": "on",
        "post_data": {"SAMLResponse": b64},
    }
