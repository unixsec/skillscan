"""FastAPI router tests (coding spec §9 /v1 endpoints, M3 subset:
POST/GET /v1/scans) - real local MySQL/Redis via a real ScanRuntime; only auth
is faked via FastAPI dependency override (no real IdP in this environment),
matching the pattern `test_dependencies.py` already established for M2.

SECURITY: object-level authorization (a submitter may only read their OWN
scans; approver/auditor/admin may read any - FR-API defense against IDOR) is
exercised here at the full HTTP-request level, not just unit-tested in
isolation.

NOTE: uses `httpx.AsyncClient` + `ASGITransport` in async test functions
rather than the synchronous `fastapi.testclient.TestClient` - `TestClient`
drives the app from its own separately-created event loop, which is
incompatible with the real async SQLAlchemy/redis connections our pytest-
asyncio fixtures already opened on THIS test's loop (raises "Future attached
to a different loop"). Keeping requests on the same loop as the fixtures
avoids that entirely.
"""

from __future__ import annotations

import datetime
import io
import tarfile
import uuid
from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from common.blobstore import LocalFilesystemBlobStore
from fastapi import FastAPI
from skillscan_core import GatePolicy, StaticKeywordEngine, TrustTier, Verdict
from sqlalchemy import select

from monolith.main import create_app
from monolith.modules.gate.models import VerdictRow
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.gateway.auth.dependencies import get_session_context
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.modules.inventory.models import SkillVersionRow
from monolith.modules.inventory.service import register_skill_version, transition_skill
from monolith.modules.orchestration.models import ScanJob, ScanResultRow
from monolith.tests.conftest import SessionmakerFixture

_ENGINE = StaticKeywordEngine()


def _make_tar_bytes(content: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name="skill.py")
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _make_tar_bytes_with_skill_md(content: bytes, skill_md: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name="skill.py")
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
        md_info = tarfile.TarInfo(name="SKILL.md")
        md_info.size = len(skill_md)
        tar.addfile(md_info, io.BytesIO(skill_md))
    return buf.getvalue()


def _make_tar_bytes_with_skill_md_at(content: bytes, path: str, skill_md: bytes) -> bytes:
    """Like `_make_tar_bytes_with_skill_md`, but the SKILL.md lands at an
    arbitrary (non-root) path - used to prove a bundled example never
    supplies the package-root permission declaration."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name="skill.py")
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
        md_info = tarfile.TarInfo(name=path)
        md_info.size = len(skill_md)
        tar.addfile(md_info, io.BytesIO(skill_md))
    return buf.getvalue()


def _make_wrapped_tar_bytes(content: bytes, skill_md: bytes, *, wrapper: str) -> bytes:
    """A conventionally packed `tar czf skill.tgz my-skill/`: EVERY member sits
    under one wrapper directory. `normalizer._canonicalize_member_path` only
    strips `.` segments, never a leading directory, so the members really do
    arrive as `my-skill/SKILL.md` etc. - which is exactly why matching the
    literal string "SKILL.md" was wrong (final review, F-5)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in ((f"{wrapper}/skill.py", content), (f"{wrapper}/SKILL.md", skill_md)):
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _fake_session(subject: str, roles: frozenset[str]) -> SessionContext:
    return SessionContext(
        subject=subject,
        roles=roles,
        scopes=frozenset(),
        tier=TrustTier.INTERNAL,
        token_exp=9999999999.0,
    )


@pytest.fixture
def app(
    orchestration_sessionmaker: SessionmakerFixture,
    gate_sessionmaker: SessionmakerFixture,
    inventory_sessionmaker: SessionmakerFixture,
    redis_client: aioredis.Redis,
    blobstore: LocalFilesystemBlobStore,
) -> FastAPI:
    scan_runtime = ScanRuntime(
        redis=redis_client,
        blobstore=blobstore,
        orchestration_session_factory=orchestration_sessionmaker,
        gate_session_factory=gate_sessionmaker,
        policy=GatePolicy(
            version=f"test-router-{uuid.uuid4().hex[:8]}",
            required_engines=frozenset({_ENGINE.metadata.name}),
            hard_gate_rules=frozenset(),
            fail_closed_verdict=Verdict.BLOCK,
        ),
        engine_metadatas=(_ENGINE.metadata,),
        allowlist=(),
        signer=LocalDevSigner(),
        inventory_session_factory=inventory_sessionmaker,
    )
    return create_app(scan_runtime=scan_runtime)


@pytest_asyncio.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


class TestSubmitAndFetch:
    @pytest.mark.asyncio
    async def test_submit_then_fetch_returns_queued_scan(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        tar_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())
        response = await client.post(
            "/v1/scans", files={"package": ("skill.tar", tar_bytes, "application/x-tar")}
        )
        assert response.status_code == 202
        scan_id = response.json()["scan_id"]

        get_response = await client.get(f"/v1/scans/{scan_id}")
        assert get_response.status_code == 200
        body = get_response.json()
        assert body["scan_id"] == scan_id
        assert body["state"] == "queued"
        assert body["submitter"] == "alice"
        assert body["verdict"] is None  # not scored yet - no worker ran in this test

    @pytest.mark.asyncio
    async def test_scored_scan_exposes_required_ok(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        # SECURITY/BUG: required_ok (INV-1's "did every required engine
        # actually complete" signal) was computed and stored since M1/M3 but
        # never exposed by this endpoint - a real gap found while building
        # the frontend's per-module scan result view.
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        tar_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())
        response = await client.post(
            "/v1/scans", files={"package": ("skill.tar", tar_bytes, "application/x-tar")}
        )
        scan_id = response.json()["scan_id"]

        async with orchestration_sessionmaker() as session, session.begin():
            session.add(
                ScanResultRow(
                    scan_id=scan_id,
                    content_hash="a" * 64,
                    severity=1,
                    confidence_at_max=0.1,
                    trifecta_present=False,
                    findings_capped=False,
                    required_ok=False,
                    findings=[],
                    provenance=[],
                    hard_gate_hits=[],
                )
            )

        get_response = await client.get(f"/v1/scans/{scan_id}")
        assert get_response.json()["required_ok"] is False

    @pytest.mark.asyncio
    async def test_scored_scan_exposes_score_and_is_safe(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        tar_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())
        response = await client.post(
            "/v1/scans", files={"package": ("skill.tar", tar_bytes, "application/x-tar")}
        )
        scan_id = response.json()["scan_id"]

        async with gate_sessionmaker() as session, session.begin():
            session.add(
                VerdictRow(
                    scan_id=scan_id,
                    content_hash="a" * 64,
                    verdict="PASS",
                    policy_version="test-v1",
                    jti=str(uuid.uuid4()),
                    jws_signature="sig",
                    effective_severity=0,
                    score=97,
                    reasons=[],
                    issued_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                )
            )

        get_response = await client.get(f"/v1/scans/{scan_id}")
        body = get_response.json()
        assert body["score"] == 97
        assert body["is_safe"] is True

    @pytest.mark.asyncio
    async def test_unscored_scan_reports_null_score_and_is_safe(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        tar_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())
        response = await client.post(
            "/v1/scans", files={"package": ("skill.tar", tar_bytes, "application/x-tar")}
        )
        scan_id = response.json()["scan_id"]

        get_response = await client.get(f"/v1/scans/{scan_id}")
        body = get_response.json()
        assert body["score"] is None
        assert body["is_safe"] is None

    @pytest.mark.asyncio
    async def test_list_scans_includes_score_and_is_safe(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        tar_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())
        response = await client.post(
            "/v1/scans", files={"package": ("skill.tar", tar_bytes, "application/x-tar")}
        )
        scan_id = response.json()["scan_id"]

        async with gate_sessionmaker() as session, session.begin():
            session.add(
                VerdictRow(
                    scan_id=scan_id,
                    content_hash="b" * 64,
                    verdict="BLOCK",
                    policy_version="test-v1",
                    jti=str(uuid.uuid4()),
                    jws_signature="sig",
                    effective_severity=4,
                    score=12,
                    reasons=[],
                    issued_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                )
            )

        list_response = await client.get("/v1/scans")
        items = {item["scan_id"]: item for item in list_response.json()["items"]}
        assert items[scan_id]["score"] == 12
        assert items[scan_id]["is_safe"] is False

    @pytest.mark.asyncio
    async def test_list_scans_includes_skill_name_from_skill_md(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # 2026-07-14: distinguishes scan targets on the Scans list page even
        # when no skill_id was registered (most ad-hoc uploads never are).
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        tar_bytes = _make_tar_bytes_with_skill_md(
            f"print({uuid.uuid4().hex!r})\n".encode(),
            b"---\nname: my-cool-skill\n---\n",
        )
        response = await client.post(
            "/v1/scans", files={"package": ("skill.tar", tar_bytes, "application/x-tar")}
        )
        scan_id = response.json()["scan_id"]

        list_response = await client.get("/v1/scans")
        assert list_response.status_code == 200
        item = next(i for i in list_response.json()["items"] if i["scan_id"] == scan_id)
        assert item["skill_name"] == "my-cool-skill"

    @pytest.mark.asyncio
    async def test_list_scans_skill_name_is_none_without_skill_md(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        tar_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())
        response = await client.post(
            "/v1/scans", files={"package": ("skill.tar", tar_bytes, "application/x-tar")}
        )
        scan_id = response.json()["scan_id"]

        list_response = await client.get("/v1/scans")
        item = next(i for i in list_response.json()["items"] if i["scan_id"] == scan_id)
        assert item["skill_name"] is None

    @pytest.mark.asyncio
    async def test_empty_archive_is_rejected(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w"):
            pass  # a valid, but empty, tar archive
        response = await client.post(
            "/v1/scans", files={"package": ("empty.tar", buf.getvalue(), "application/x-tar")}
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_unauthenticated_request_is_401(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # No dependency override - the real get_session_context runs and
        # fail-closes on the missing cookie/bearer token without needing a
        # real IdP (see test_dependencies.py::test_no_cookie_is_401).
        response = await client.get(f"/v1/scans/{uuid.uuid4()}")
        assert response.status_code == 401


class TestSkillIdRegistration:
    """coding spec §7.1/§16.2: a scan submission that names `skill_id` also
    registers/advances that skill's inventory lifecycle. Found live
    2026-07-24 via a real clawhub.ai re-import batch: resubmitting new
    content for an already-published skill_id crashed as an unhandled 500
    (register_skill_version's `InvalidTransitionError`, uncaught) - a real,
    expected caller scenario (duplicate/re-run submission), not a system
    fault, so it must surface as a client error instead."""

    @pytest.mark.asyncio
    async def test_new_skill_id_is_registered_on_submission(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        tar_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())
        response = await client.post(
            "/v1/scans",
            files={"package": ("skill.tar", tar_bytes, "application/x-tar")},
            data={"skill_id": skill_id},
        )
        assert response.status_code == 202

    @pytest.mark.asyncio
    async def test_a_non_root_skill_md_does_not_populate_declared_perms(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
    ) -> None:
        """2026-07-27: FR-PAR-013's declared_perms is persisted to
        skill_version and consumed downstream by the gate and human
        reviewers - it must reflect the ONE declaration the Agent actually
        reads (the package-root SKILL.md). A bundled example
        (examples/SKILL.md) declaring allowed-tools must NOT populate this
        field when the package has no root SKILL.md at all - otherwise the
        gate would permanently judge a permission profile the package
        doesn't really have."""
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        tar_bytes = _make_tar_bytes_with_skill_md_at(
            f"print({uuid.uuid4().hex!r})\n".encode(),
            "examples/SKILL.md",
            b"---\nname: example-only\nallowed-tools: [Bash, WebFetch]\n---\n",
        )
        response = await client.post(
            "/v1/scans",
            files={"package": ("skill.tar", tar_bytes, "application/x-tar")},
            data={"skill_id": skill_id},
        )
        assert response.status_code == 202

        async with inventory_sessionmaker() as session:
            version = (
                await session.execute(
                    select(SkillVersionRow).where(SkillVersionRow.skill_id == skill_id)
                )
            ).scalar_one()
        assert version.declared_perms is None

    @pytest.mark.asyncio
    async def test_a_flat_packages_root_skill_md_populates_declared_perms(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
    ) -> None:
        """The baseline the wrapped case below must match: nothing about
        packaging shape may change what gets persisted."""
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        tar_bytes = _make_tar_bytes_with_skill_md(
            f"print({uuid.uuid4().hex!r})\n".encode(),
            b"---\nname: flat-skill\nallowed-tools: [Read, Grep]\n---\n",
        )
        response = await client.post(
            "/v1/scans",
            files={"package": ("skill.tar", tar_bytes, "application/x-tar")},
            data={"skill_id": skill_id},
        )
        assert response.status_code == 202

        async with inventory_sessionmaker() as session:
            version = (
                await session.execute(
                    select(SkillVersionRow).where(SkillVersionRow.skill_id == skill_id)
                )
            ).scalar_one()
        assert version.declared_perms == {"tools": ["Read", "Grep"]}

    @pytest.mark.asyncio
    async def test_a_directory_wrapped_packages_skill_md_populates_declared_perms(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        """2026-07-27 (final review, F-5): `tar czf skill.tgz my-skill/` - the
        conventional way to pack a directory - wraps every member in
        `my-skill/`, and the normalizer never strips it. This handler matched
        the literal string "SKILL.md", so it silently recorded
        `declared_perms=None` for a package that declares its permissions
        perfectly well - and `declared_perms` is consumed downstream by the
        gate and by human reviewers, so the gate ended up judging a permission
        profile the package does not actually have, permanently recorded.

        `ScanJob.skill_name` is asserted too: it is the third site that had the
        same literal-string bug, and it is what the scans list displays."""
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        tar_bytes = _make_wrapped_tar_bytes(
            f"print({uuid.uuid4().hex!r})\n".encode(),
            b"---\nname: wrapped-skill\nallowed-tools: [Read, Grep]\n---\n",
            wrapper="my-skill",
        )
        response = await client.post(
            "/v1/scans",
            files={"package": ("skill.tar", tar_bytes, "application/x-tar")},
            data={"skill_id": skill_id},
        )
        assert response.status_code == 202
        scan_id = response.json()["scan_id"]

        async with inventory_sessionmaker() as session:
            version = (
                await session.execute(
                    select(SkillVersionRow).where(SkillVersionRow.skill_id == skill_id)
                )
            ).scalar_one()
        assert version.declared_perms == {"tools": ["Read", "Grep"]}

        async with orchestration_sessionmaker() as session:
            job = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()
        assert job.skill_name == "wrapped-skill"

    @pytest.mark.asyncio
    async def test_resubmitting_a_published_skill_id_with_new_content_is_409(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        # submitted -> scanning -> published (a real, valid prior lifecycle -
        # exactly what clawhub re-import hit: a skill already fully published
        # from an earlier round)
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="public",
                content_hash=uuid.uuid4().hex + uuid.uuid4().hex,
                toolchain_digest="digest-v1",
                declared_perms=None,
                operator="tester",
            )
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="scanning",
                reason="scan started",
                actor="system",
            )
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="published",
                reason="passed gate",
                actor="system",
            )

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        tar_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())
        response = await client.post(
            "/v1/scans",
            files={"package": ("skill.tar", tar_bytes, "application/x-tar")},
            data={"skill_id": skill_id},
        )
        assert response.status_code == 409
        assert skill_id in response.json()["detail"]


class TestObjectLevelAuthorization:
    @pytest.mark.asyncio
    async def test_other_submitter_cannot_read_scan(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        tar_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())
        response = await client.post(
            "/v1/scans", files={"package": ("skill.tar", tar_bytes, "application/x-tar")}
        )
        scan_id = response.json()["scan_id"]

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "mallory", frozenset({"submitter"})
        )
        get_response = await client.get(f"/v1/scans/{scan_id}")
        # SECURITY: 404, not 403 - a submitter must not learn that a scan_id
        # belonging to someone else even exists (IDOR defense).
        assert get_response.status_code == 404

    @pytest.mark.asyncio
    async def test_approver_can_read_any_submitters_scan(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        tar_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())
        response = await client.post(
            "/v1/scans", files={"package": ("skill.tar", tar_bytes, "application/x-tar")}
        )
        scan_id = response.json()["scan_id"]

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "bob", frozenset({"approver"})
        )
        get_response = await client.get(f"/v1/scans/{scan_id}")
        assert get_response.status_code == 200
        assert get_response.json()["submitter"] == "alice"

    @pytest.mark.asyncio
    async def test_list_scans_scopes_to_own_submissions_for_plain_submitter(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "carol", frozenset({"submitter"})
        )
        tar_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())
        submit_response = await client.post(
            "/v1/scans", files={"package": ("skill.tar", tar_bytes, "application/x-tar")}
        )
        scan_id = submit_response.json()["scan_id"]

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "dave", frozenset({"submitter"})
        )
        list_response = await client.get("/v1/scans")
        assert list_response.status_code == 200
        listed_ids = {item["scan_id"] for item in list_response.json()["items"]}
        assert scan_id not in listed_ids  # carol's scan is invisible to dave

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "carol", frozenset({"submitter"})
        )
        own_list_response = await client.get("/v1/scans")
        own_ids = {item["scan_id"] for item in own_list_response.json()["items"]}
        assert scan_id in own_ids


class TestGetCurrentSession:
    @pytest.mark.asyncio
    async def test_returns_subject_and_roles(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "carol", frozenset({"approver", "auditor"})
        )
        response = await client.get("/v1/me")
        assert response.status_code == 200
        body = response.json()
        assert body["subject"] == "carol"
        assert body["roles"] == ["approver", "auditor"]


class TestPublicEndpoints:
    @pytest.mark.asyncio
    async def test_healthz(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/healthz")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_readyz(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/readyz")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_jwks(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/.well-known/jwks.json")
        assert response.status_code == 200
        assert response.json()["keys"][0]["kty"] == "RSA"


# GET /v1/scans/{scan_id}/sarif (2026-07-06 spec-compliance audit gap #11 - §9's
# explicit table row for this endpoint was never implemented; sarif_ref stayed
# null forever). Uses its own fixture (reporting_session_factory wired in,
# unlike the shared `app` fixture above) matching test_reports_router.py's
# established app/app_without_reporting split.
@pytest.fixture
def app_with_reporting(
    orchestration_sessionmaker: SessionmakerFixture,
    gate_sessionmaker: SessionmakerFixture,
    reporting_sessionmaker: SessionmakerFixture,
    redis_client: aioredis.Redis,
    blobstore: LocalFilesystemBlobStore,
) -> FastAPI:
    scan_runtime = ScanRuntime(
        redis=redis_client,
        blobstore=blobstore,
        orchestration_session_factory=orchestration_sessionmaker,
        gate_session_factory=gate_sessionmaker,
        policy=GatePolicy(
            version=f"test-router-sarif-{uuid.uuid4().hex[:8]}",
            required_engines=frozenset({_ENGINE.metadata.name}),
            hard_gate_rules=frozenset(),
            fail_closed_verdict=Verdict.BLOCK,
        ),
        engine_metadatas=(_ENGINE.metadata,),
        allowlist=(),
        signer=LocalDevSigner(),
        reporting_session_factory=reporting_sessionmaker,
    )
    return create_app(scan_runtime=scan_runtime)


@pytest_asyncio.fixture
async def client_with_reporting(app_with_reporting: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app_with_reporting)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


async def _submit_scan(client_instance: httpx.AsyncClient) -> str:
    tar_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())
    response = await client_instance.post(
        "/v1/scans", files={"package": ("skill.tar", tar_bytes, "application/x-tar")}
    )
    scan_id: str = response.json()["scan_id"]
    return scan_id


class TestScanSarif:
    @pytest.mark.asyncio
    async def test_own_scan_returns_sarif_with_seeded_finding(
        self,
        app_with_reporting: FastAPI,
        client_with_reporting: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        app_with_reporting.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        scan_id = await _submit_scan(client_with_reporting)

        async with orchestration_sessionmaker() as session, session.begin():
            session.add(
                ScanResultRow(
                    scan_id=scan_id,
                    content_hash="b" * 64,
                    severity=3,
                    confidence_at_max=0.9,
                    trifecta_present=False,
                    findings_capped=False,
                    required_ok=True,
                    findings=[
                        {
                            "rule_id": "bandit.hardcoded_password",
                            "test_item_id": "T-001",
                            "category": "data_credential",
                            "title": "Hardcoded password string",
                            "severity": 3,
                            "confidence": 0.9,
                            "source_engine": "bandit",
                            "source_capability": "static",
                            "trifecta_signals": [],
                            "file_path": "skill/auth.py",
                            "start_line": 12,
                            "snippet_hash": None,
                            "evidence_redacted": 'password = "<redacted>"',
                        }
                    ],
                    provenance=[],
                    hard_gate_hits=[],
                )
            )

        # detail response should point at this endpoint, not the old null.
        detail = await client_with_reporting.get(f"/v1/scans/{scan_id}")
        assert detail.json()["sarif_ref"] == f"/v1/scans/{scan_id}/sarif"

        response = await client_with_reporting.get(f"/v1/scans/{scan_id}/sarif")
        assert response.status_code == 200
        body = response.json()
        rule_ids = {result["ruleId"] for run in body["runs"] for result in run["results"]}
        assert "bandit.hardcoded_password" in rule_ids

    @pytest.mark.asyncio
    async def test_unknown_scan_id_is_404(
        self, app_with_reporting: FastAPI, client_with_reporting: httpx.AsyncClient
    ) -> None:
        app_with_reporting.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        response = await client_with_reporting.get(f"/v1/scans/{uuid.uuid4()}/sarif")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_other_submitter_cannot_read_sarif(
        self, app_with_reporting: FastAPI, client_with_reporting: httpx.AsyncClient
    ) -> None:
        app_with_reporting.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        scan_id = await _submit_scan(client_with_reporting)

        # SECURITY: same IDOR defense as GET /v1/scans/{scan_id} - a 404, not
        # 403, so existence of another submitter's scan_id isn't leaked.
        app_with_reporting.dependency_overrides[get_session_context] = lambda: _fake_session(
            "mallory", frozenset({"submitter"})
        )
        response = await client_with_reporting.get(f"/v1/scans/{scan_id}/sarif")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_approver_can_read_any_submitters_sarif(
        self, app_with_reporting: FastAPI, client_with_reporting: httpx.AsyncClient
    ) -> None:
        app_with_reporting.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        scan_id = await _submit_scan(client_with_reporting)

        app_with_reporting.dependency_overrides[get_session_context] = lambda: _fake_session(
            "bob", frozenset({"approver"})
        )
        response = await client_with_reporting.get(f"/v1/scans/{scan_id}/sarif")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_reporting_not_configured_is_500(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # the shared `app` fixture (module-level, above) has no
        # reporting_session_factory wired - fail-closed, not "empty".
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        scan_id = await _submit_scan(client)
        response = await client.get(f"/v1/scans/{scan_id}/sarif")
        assert response.status_code == 500
