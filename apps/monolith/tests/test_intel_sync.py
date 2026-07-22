"""Tests for `intel_sync.sync` (coding spec §11.4 SEC-UPD-010, INV-14) against
the real local MySQL instance (svc_intel's `threat_indicator` table)."""

from __future__ import annotations

import base64
import json
import uuid
from collections.abc import Mapping

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256
from intel_sync.sync import (
    IntelSyncError,
    import_offline_package,
    summarize_intel_status,
    sync_from_internal_source,
)

from monolith.modules.intel.matcher import load_known_iocs
from monolith.tests.conftest import SessionmakerFixture


def _sign(private_key: rsa.RSAPrivateKey, claim: Mapping[str, object]) -> str:
    claim_bytes = json.dumps(claim, sort_keys=True, separators=(",", ":")).encode()
    signature = private_key.sign(
        claim_bytes,
        padding.PSS(mgf=padding.MGF1(SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        SHA256(),
    )
    return base64.b64encode(signature).decode()


class TestSyncFromInternalSource:
    @pytest.mark.asyncio
    async def test_public_endpoint_rejected(self, intel_sessionmaker: SessionmakerFixture) -> None:
        client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
        async with intel_sessionmaker() as session:
            with pytest.raises(ValueError, match="internal/private"):
                await sync_from_internal_source(
                    client, endpoint_url="https://intel.example.com/feed", session=session
                )

    @pytest.mark.asyncio
    async def test_valid_internal_feed_applies_iocs(
        self, intel_sessionmaker: SessionmakerFixture
    ) -> None:
        domain = f"evil-{uuid.uuid4().hex[:12]}.example.com"

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=[{"ioc_type": "domain", "ioc_value": domain}])

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        async with intel_sessionmaker() as session, session.begin():
            count = await sync_from_internal_source(
                client, endpoint_url="https://localhost/feed", session=session
            )
        assert count == 1

        async with intel_sessionmaker() as session:
            known = await load_known_iocs(session)
        assert ("domain", domain) in known

    @pytest.mark.asyncio
    async def test_non_list_response_rejected(
        self, intel_sessionmaker: SessionmakerFixture
    ) -> None:
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"not": "a list"}))
        )
        async with intel_sessionmaker() as session:
            with pytest.raises(IntelSyncError, match="JSON list"):
                await sync_from_internal_source(
                    client, endpoint_url="https://localhost/feed", session=session
                )

    @pytest.mark.asyncio
    async def test_reapplying_same_ioc_is_idempotent(
        self, intel_sessionmaker: SessionmakerFixture
    ) -> None:
        domain = f"evil-{uuid.uuid4().hex[:12]}.example.com"

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=[{"ioc_type": "domain", "ioc_value": domain}])

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        async with intel_sessionmaker() as session, session.begin():
            await sync_from_internal_source(
                client, endpoint_url="https://localhost/feed", session=session
            )
        # SECURITY: re-syncing the SAME indicator must not raise (idempotent),
        # backed by the table's own UNIQUE(ioc_type, ioc_value) constraint.
        async with intel_sessionmaker() as session, session.begin():
            await sync_from_internal_source(
                client, endpoint_url="https://localhost/feed", session=session
            )


class TestImportOfflinePackage:
    @pytest.mark.asyncio
    async def test_rejects_with_no_trusted_keys(
        self, intel_sessionmaker: SessionmakerFixture
    ) -> None:
        package = json.dumps({"iocs": [], "signature": "irrelevant"}).encode()
        async with intel_sessionmaker() as session:
            with pytest.raises(IntelSyncError, match="no trusted public keys"):
                await import_offline_package(package, trusted_public_keys=(), session=session)

    @pytest.mark.asyncio
    async def test_valid_signed_package_applies_iocs(
        self, intel_sessionmaker: SessionmakerFixture
    ) -> None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        md5_hash = f"{uuid.uuid4().hex}{uuid.uuid4().hex}"[:32]
        claim = {"iocs": [{"ioc_type": "md5", "ioc_value": md5_hash}]}
        package: dict[str, object] = dict(claim)
        package["signature"] = _sign(private_key, claim)

        async with intel_sessionmaker() as session, session.begin():
            count = await import_offline_package(
                json.dumps(package).encode(),
                trusted_public_keys=(private_key.public_key(),),
                session=session,
            )
        assert count == 1

        async with intel_sessionmaker() as session:
            known = await load_known_iocs(session)
        assert ("md5", md5_hash.lower()) in known

    @pytest.mark.asyncio
    async def test_tampered_package_rejected_zero_applied(
        self, intel_sessionmaker: SessionmakerFixture
    ) -> None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        real_claim = {"iocs": [{"ioc_type": "domain", "ioc_value": "benign.example.com"}]}
        signature = _sign(private_key, real_claim)
        # SECURITY: attacker adds an extra malicious IOC after signing - the
        # signature was computed over `real_claim`, not this tampered claim.
        tampered = {
            "iocs": [
                {"ioc_type": "domain", "ioc_value": "benign.example.com"},
                {"ioc_type": "domain", "ioc_value": "attacker-injected.example.com"},
            ],
            "signature": signature,
        }
        async with intel_sessionmaker() as session:
            with pytest.raises(IntelSyncError, match="signature verification failed"):
                await import_offline_package(
                    json.dumps(tampered).encode(),
                    trusted_public_keys=(private_key.public_key(),),
                    session=session,
                )

    @pytest.mark.asyncio
    async def test_wrong_key_rejected(self, intel_sessionmaker: SessionmakerFixture) -> None:
        signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        claim = {"iocs": [{"ioc_type": "domain", "ioc_value": "benign.example.com"}]}
        package: dict[str, object] = dict(claim)
        package["signature"] = _sign(signing_key, claim)

        async with intel_sessionmaker() as session:
            with pytest.raises(IntelSyncError, match="signature verification failed"):
                await import_offline_package(
                    json.dumps(package).encode(),
                    trusted_public_keys=(other_key.public_key(),),
                    session=session,
                )

    @pytest.mark.asyncio
    async def test_malformed_json_rejected(self, intel_sessionmaker: SessionmakerFixture) -> None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        async with intel_sessionmaker() as session:
            with pytest.raises(IntelSyncError, match="not valid JSON"):
                await import_offline_package(
                    b"not json{{{",
                    trusted_public_keys=(private_key.public_key(),),
                    session=session,
                )


class TestSummarizeIntelStatus:
    @pytest.mark.asyncio
    async def test_groups_by_source_with_count_and_last_imported_at(
        self, intel_sessionmaker: SessionmakerFixture
    ) -> None:
        source = f"test-source-{uuid.uuid4().hex[:12]}"
        domain_a = f"a-{uuid.uuid4().hex[:12]}.example.com"
        domain_b = f"b-{uuid.uuid4().hex[:12]}.example.com"

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=[
                    {"ioc_type": "domain", "ioc_value": domain_a},
                    {"ioc_type": "domain", "ioc_value": domain_b},
                ],
            )

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        async with intel_sessionmaker() as session, session.begin():
            await sync_from_internal_source(
                client, endpoint_url=f"https://localhost/{source}", session=session
            )

        async with intel_sessionmaker() as session:
            summary = await summarize_intel_status(session)
        matching = [
            row for row in summary if row["source"] == f"internal:https://localhost/{source}"
        ]
        assert len(matching) == 1
        assert matching[0]["indicator_count"] == 2
        assert matching[0]["last_imported_at"] is not None
