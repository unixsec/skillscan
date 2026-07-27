"""Tests for `intel.matcher` (coding spec §11.4 INTEL-01/02/03, corrected
2026-07-27 from the previously mislabelled NET-06/07/08) against the real
local MySQL instance (`threat_indicator`, svc_intel's own table)."""

from __future__ import annotations

import datetime
import uuid

import pytest

from monolith.modules.intel.matcher import IntelMatcher, load_known_iocs
from monolith.modules.intel.models import ThreatIndicator
from monolith.tests.conftest import SessionmakerFixture


async def _seed_indicator(
    intel_sessionmaker: SessionmakerFixture, *, ioc_type: str, ioc_value: str
) -> None:
    async with intel_sessionmaker() as session, session.begin():
        session.add(
            ThreatIndicator(
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                source="test",
                imported_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
            )
        )


class TestLoadKnownIocs:
    @pytest.mark.asyncio
    async def test_loads_seeded_indicators(self, intel_sessionmaker: SessionmakerFixture) -> None:
        domain = f"evil-{uuid.uuid4().hex[:12]}.example.com"
        await _seed_indicator(intel_sessionmaker, ioc_type="domain", ioc_value=domain)

        async with intel_sessionmaker() as session:
            known = await load_known_iocs(session)
        assert ("domain", domain) in known


class TestIntelMatcher:
    @pytest.mark.asyncio
    async def test_matches_known_malicious_domain(
        self, intel_sessionmaker: SessionmakerFixture
    ) -> None:
        domain = f"evil-{uuid.uuid4().hex[:12]}.example.com"
        await _seed_indicator(intel_sessionmaker, ioc_type="domain", ioc_value=domain)

        async with intel_sessionmaker() as session:
            known = await load_known_iocs(session)
        matcher = IntelMatcher(known_iocs=known)
        result = matcher.analyze({"skill.py": f'requests.get("http://{domain}/beacon")\n'.encode()})

        assert any(f.rule_id == "intel.ioc_match_domain" for f in result.findings)
        match = next(f for f in result.findings if f.rule_id == "intel.ioc_match_domain")
        assert match.severity.name == "CRITICAL"
        assert "external_egress" in {s.value for s in match.trifecta_signals}
        assert domain not in match.evidence_redacted  # SECURITY: no raw IOC value leaked

    @pytest.mark.asyncio
    async def test_matches_known_malicious_ip(
        self, intel_sessionmaker: SessionmakerFixture
    ) -> None:
        # SECURITY/FLAKE (2026-07-06): randomizing only the last octet within
        # 203.0.113.0/24 (TEST-NET-3, RFC 5737) gives just 254 possible values -
        # nowhere near enough entropy against this shared, never-truncated local
        # dev DB after the hundreds of pytest invocations a real dev session
        # accumulates (see feedback_mysql_tail_append_locking), and this was
        # observed to intermittently collide with a stale row from an earlier
        # run and fail the UNIQUE(ioc_type, ioc_value) insert. All four octets
        # are now randomized (~4 billion combinations) - _IPV4_RE only requires
        # a valid dotted-quad shape, not that it fall in a specific reserved
        # block, so this is still correctly recognized as an "ip" IOC candidate.
        rand = uuid.uuid4().int
        ip = ".".join(str((rand >> (8 * i)) % 256) for i in range(4))
        await _seed_indicator(intel_sessionmaker, ioc_type="ip", ioc_value=ip)

        async with intel_sessionmaker() as session:
            known = await load_known_iocs(session)
        matcher = IntelMatcher(known_iocs=known)
        result = matcher.analyze({"skill.py": f'sock.connect(("{ip}", 4444))\n'.encode()})

        assert any(f.rule_id == "intel.ioc_match_ip" for f in result.findings)

    @pytest.mark.asyncio
    async def test_matches_known_malicious_md5(
        self, intel_sessionmaker: SessionmakerFixture
    ) -> None:
        # MD5-shaped (32 hex chars) but randomized per run - same collision
        # concern as the IP test above.
        md5_hash = (uuid.uuid4().hex + uuid.uuid4().hex)[:32]
        await _seed_indicator(intel_sessionmaker, ioc_type="md5", ioc_value=md5_hash)

        async with intel_sessionmaker() as session:
            known = await load_known_iocs(session)
        matcher = IntelMatcher(known_iocs=known)
        result = matcher.analyze({"manifest.txt": f"checksum: {md5_hash}\n".encode()})

        assert any(f.rule_id == "intel.ioc_match_md5" for f in result.findings)

    def test_unknown_domain_not_flagged(self) -> None:
        matcher = IntelMatcher(known_iocs=frozenset())
        result = matcher.analyze(
            {"skill.py": b'requests.get("http://totally-benign.example.com")\n'}
        )
        assert result.findings == ()

    def test_empty_known_iocs_never_matches_anything(self) -> None:
        matcher = IntelMatcher(known_iocs=frozenset())
        result = matcher.analyze(
            {"a.py": b"203.0.113.5 evil.example.com d41d8cd98f00b204e9800998ecf8427e"}
        )
        assert result.findings == ()
        assert result.status.value == "ok"

    # SECURITY (2026-07-27 review follow-up): the D7 catalog-id fix to
    # `_TEST_ITEM_ID_BY_IOC_TYPE` (matcher.py) had NO regression protection -
    # every existing matcher test asserted only `rule_id`, never
    # `test_item_id`, so a future accidental revert back to NET-06/07/08
    # would pass the entire suite. These three don't need a DB fixture at all
    # (unlike TestIntelMatcher's domain/ip/md5 tests above) - `known_iocs` is
    # just a plain frozenset `IntelMatcher.__init__` takes directly, so they
    # run locally without MySQL.
    @pytest.mark.parametrize(
        ("ioc_type", "ioc_value", "content", "expected_item"),
        [
            # INTEL-02「恶意域名」(企业Skill安全评估测试维度清单 D1).
            (
                "domain",
                "evil.example.com",
                b'requests.get("http://evil.example.com")\n',
                "INTEL-02",
            ),
            # INTEL-03「恶意IP」(D1).
            ("ip", "203.0.113.5", b'sock.connect(("203.0.113.5", 4444))\n', "INTEL-03"),
            # INTEL-01「恶意文件命中情报」(D1, MD5 hash hit).
            (
                "md5",
                "d41d8cd98f00b204e9800998ecf8427e",
                b"checksum: d41d8cd98f00b204e9800998ecf8427e\n",
                "INTEL-01",
            ),
        ],
    )
    def test_test_item_id_matches_the_catalog_entry_for_each_ioc_type(
        self, ioc_type: str, ioc_value: str, content: bytes, expected_item: str
    ) -> None:
        matcher = IntelMatcher(known_iocs=frozenset({(ioc_type, ioc_value)}))
        result = matcher.analyze({"skill.py": content})
        assert result.findings, f"fixture should have matched the seeded {ioc_type} IOC"
        assert all(f.test_item_id == expected_item for f in result.findings)
