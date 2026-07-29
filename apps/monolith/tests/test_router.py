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
from sqlalchemy import func, select, update

from monolith.main import create_app
from monolith.modules.gate.models import VerdictRow
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.gateway.auth.dependencies import get_session_context
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.modules.inventory.models import SkillLifecycleEventRow, SkillRow, SkillVersionRow
from monolith.modules.inventory.service import register_skill_version, transition_skill
from monolith.modules.orchestration.models import ScanJob, ScanResultRow, ScanSubmitterRow
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
        is_machine=False,  # a console/reviewer session is a person
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
    fault, so it must surface as a client error instead.

    2026-07-29 (milestone F Task 11): that 500 -> 409 fix treated the symptom.
    The cause was that `"submitted"` appeared 0 times as a TARGET state in
    VALID_TRANSITIONS, so NO skill of ANY state could ever have a second
    version submitted - a v2 of a healthy published skill and a fixed BLOCKed
    skill were both permanently 409. Settled states now re-enter at
    `submitted`; the 409 branch survives for the two states that must not
    (`scanning`, `retired`), covered below."""

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

    @staticmethod
    async def _seed_lifecycle(
        inventory_sessionmaker: SessionmakerFixture,
        *,
        skill_id: str,
        states: list[str],
        owner: str = "alice",
        trust_tier: str = "public",
    ) -> None:
        """Drives `skill_id` through a REAL prior lifecycle using the same
        service functions production uses - never by inserting lifecycle rows
        directly, which would let a test set up a state the machine forbids.

        `owner` defaults to "alice", the identity every test below submits as.

        2026-07-29 (follow-up C1): this used to hard-code `operator="tester"`
        while every caller submitted as "alice" - i.e. every "resubmission"
        test in this class was silently a CROSS-IDENTITY resubmission, and
        `test_resubmitting_a_published_skill_id_with_new_content_is_accepted`
        below asserted that a stranger overwriting alice's published skill
        returns 202. That was the takeover, written down as expected
        behaviour. It is now an explicit, refused case in `TestSkillOwnership`,
        and these tests seed the submitter as the owner so they keep testing
        the LIFECYCLE question they are about."""
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier=trust_tier,
                content_hash=uuid.uuid4().hex + uuid.uuid4().hex,
                toolchain_digest="digest-v1",
                declared_perms=None,
                operator=owner,
                actor_is_admin=False,
            )
        for to_state in states:
            async with inventory_sessionmaker() as session, session.begin():
                await transition_skill(
                    session,
                    skill_id=skill_id,
                    to_state=to_state,
                    reason="test",
                    actor="system",
                )

    @pytest.mark.asyncio
    async def test_resubmitting_a_published_skill_id_with_new_content_is_accepted(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
    ) -> None:
        # The end-to-end proof for milestone F Task 11: publishing v2 of a
        # healthy skill over the real HTTP submission path. This asserted 409
        # until 2026-07-29 - i.e. the product shipped with no way to release a
        # second version of anything.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await self._seed_lifecycle(
            inventory_sessionmaker, skill_id=skill_id, states=["scanning", "published"]
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
        assert response.status_code == 202

        async with inventory_sessionmaker() as session:
            events = (
                (
                    await session.execute(
                        select(SkillLifecycleEventRow)
                        .where(SkillLifecycleEventRow.skill_id == skill_id)
                        .order_by(SkillLifecycleEventRow.id)
                    )
                )
                .scalars()
                .all()
            )
        # SECURITY: the re-entry is a REAL `published -> submitted` event
        # followed by the ordinary `submitted -> scanning`, so v2 gets a full
        # fresh scan and its own verdict. Critically it is NOT a second
        # fabricated `None -> submitted` genesis - that fabrication is what
        # would let current_state() lie and launder a jump the state machine
        # never approved (see register_skill_version's docstring).
        assert [e.to_state for e in events] == [
            "submitted",
            "scanning",
            "published",
            "submitted",
            "scanning",
        ]
        assert events[3].from_state == "published"
        assert sum(1 for e in events if e.from_state is None) == 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "states",
        [
            # `scanning`: a verdict for the in-flight content is about to be
            # written and a resubmission here races it.
            ["scanning"],
            # `retired`: terminal by design - resurrecting a retired skill_id
            # is a new registration, not a new version.
            ["scanning", "retired"],
            # `quarantined`: a DELIBERATE GATE, and the reason this case is
            # asserted at the HTTP level and not just in the lifecycle table.
            # A quarantined skill already passed the automated scanner once
            # and was caught afterwards by drift/intel; a fresh PASS from that
            # same scanner is not a substitute for the human review the
            # quarantine forces. If re-entry were allowed, nobody would ever
            # wait for the admin-only `quarantined -> published` restore -
            # resubmitting would be faster - and the admin gate would be
            # decorative. The supported path is: admin restores to
            # `published`, then version normally.
            ["scanning", "published", "quarantined"],
        ],
        ids=["scanning", "retired", "quarantined"],
    )
    async def test_resubmitting_is_409_for_states_that_must_not_re_enter(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
        states: list[str],
    ) -> None:
        # SECURITY: the 409 branch in `gateway/router.py` must stay live for
        # every source state deliberately excluded from re-entry (see each
        # param above, and lifecycle.VALID_TRANSITIONS for the full argument).
        # A client error, never a 500 and never a 202.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await self._seed_lifecycle(inventory_sessionmaker, skill_id=skill_id, states=states)

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

        async with inventory_sessionmaker() as session:
            events = (
                (
                    await session.execute(
                        select(SkillLifecycleEventRow)
                        .where(SkillLifecycleEventRow.skill_id == skill_id)
                        .order_by(SkillLifecycleEventRow.id)
                    )
                )
                .scalars()
                .all()
            )
        # The refused submission left no trace: no fabricated genesis row, no
        # partial re-entry event, state unchanged.
        assert [e.to_state for e in events] == ["submitted", *states]
        assert sum(1 for e in events if e.from_state is None) == 1

    @pytest.mark.asyncio
    async def test_a_refused_resubmission_leaves_no_scan_job_or_submitter_row(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        """SECURITY (2026-07-29, milestones E+F review): a 409 must leave
        NOTHING behind, the same way the ownership 403 already did.

        `submit_scan` commits in its own transaction BEFORE the inventory
        transaction runs, so both 409 paths - `InvalidTransitionError` and
        `ContentRegisteredToAnotherSkillError` - used to tell the caller the
        submission had failed while a `scan_job`, an artifact blob and a
        `scan_submitter` row stayed committed. The `scan_submitter` row is the
        one that matters: via single-flight dedup it attaches the caller to
        an EXISTING scan of those bytes as an authorized reader, which for the
        content-conflict path means a scan belonging to the very skill they
        were just refused access to.

        Asserted on the ROW COUNT for the submitter, not on the response - the
        response was always a correct-looking 409, which is exactly why this
        went unnoticed. The pre-flight in `create_scan` is what makes it true;
        the in-transaction checks stay for the TOCTOU race.
        """

        async def rows_for(submitter: str) -> set[str]:
            async with orchestration_sessionmaker() as session:
                return set(
                    (
                        await session.execute(
                            select(ScanSubmitterRow.scan_id).where(
                                ScanSubmitterRow.submitter == submitter
                            )
                        )
                    )
                    .scalars()
                    .all()
                )

        async def total_scan_jobs() -> int:
            async with orchestration_sessionmaker() as session:
                return (
                    await session.execute(select(func.count()).select_from(ScanJob))
                ).scalar_one()

        # PATH 1 - InvalidTransitionError: a lifecycle state with no
        # `-> submitted` edge, with bytes that have never been scanned before,
        # so `submit_scan` would genuinely create a new scan_job here.
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        fresh_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())
        scanning_skill = f"skill-{uuid.uuid4().hex[:12]}"
        await self._seed_lifecycle(
            inventory_sessionmaker, skill_id=scanning_skill, states=["scanning"]
        )
        jobs_before, alice_before = await total_scan_jobs(), await rows_for("alice")
        response = await client.post(
            "/v1/scans",
            files={"package": ("skill.tar", fresh_bytes, "application/x-tar")},
            data={"skill_id": scanning_skill},
        )
        assert response.status_code == 409
        assert await total_scan_jobs() == jobs_before, (
            "a refused submission still committed a scan_job (and its artifact blob)"
        )
        assert await rows_for("alice") == alice_before

        # PATH 2 - ContentRegisteredToAnotherSkillError, and the sharper half:
        # BOB submits alice's already-registered bytes under his own skill_id.
        # Single-flight dedup hands him alice's existing scan, so the refused
        # request used to leave him a `scan_submitter` row on it - an
        # authorized reader of a scan belonging to the very skill he was just
        # refused. A different identity is essential here: a second submission
        # by alice would dedup onto a (scan_id, alice) row that already exists,
        # so the leak is invisible when the same person retries.
        shared_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())
        alice_skill = f"skill-{uuid.uuid4().hex[:12]}"
        accepted = await client.post(
            "/v1/scans",
            files={"package": ("skill.tar", shared_bytes, "application/x-tar")},
            data={"skill_id": alice_skill},
        )
        assert accepted.status_code == 202

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "bob", frozenset({"submitter"})
        )
        bob_before = await rows_for("bob")
        response = await client.post(
            "/v1/scans",
            files={"package": ("skill.tar", shared_bytes, "application/x-tar")},
            data={"skill_id": f"skill-{uuid.uuid4().hex[:12]}"},
        )
        assert response.status_code == 409
        assert "already registered to skill" in response.json()["detail"]
        assert await rows_for("bob") == bob_before, (
            "a refused submitter was attached to another skill's scan as an authorized reader"
        )
        # And the refusal really did name alice's skill - i.e. this is the
        # content-conflict path and not some other 409 arriving by accident.
        assert alice_skill in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_resubmitting_identical_content_for_a_blocked_skill_re_enters(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
    ) -> None:
        """I1 (2026-07-29): the policy-fix / re-run case, end to end.

        The package did not change; the RULESET did. Resubmitting the SAME
        bytes used to return 202 having written nothing at all - the gateway
        gated both `register_skill_version` and the `-> scanning` transition
        on `skill_version` being absent - so the skill stayed `blocked`
        forever and `sync_lifecycle_tick` never looked at it again (it matches
        only `scanning`/`review_pending`). A 202 that changes nothing is worse
        than an error: the submitter is told it worked.

        Seeded through the REAL submission path rather than `_seed_lifecycle`,
        because the point of this test is that the second POST carries the
        exact bytes the first one registered.
        """
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        tar_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())

        first = await client.post(
            "/v1/scans",
            files={"package": ("skill.tar", tar_bytes, "application/x-tar")},
            data={"skill_id": skill_id},
        )
        assert first.status_code == 202

        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="blocked",
                reason="verdict BLOCK",
                actor="system:gate",
            )

        second = await client.post(
            "/v1/scans",
            files={"package": ("skill.tar", tar_bytes, "application/x-tar")},
            data={"skill_id": skill_id},
        )
        assert second.status_code == 202

        async with inventory_sessionmaker() as session:
            events = (
                (
                    await session.execute(
                        select(SkillLifecycleEventRow)
                        .where(SkillLifecycleEventRow.skill_id == skill_id)
                        .order_by(SkillLifecycleEventRow.id)
                    )
                )
                .scalars()
                .all()
            )
            versions = (
                (
                    await session.execute(
                        select(SkillVersionRow).where(SkillVersionRow.skill_id == skill_id)
                    )
                )
                .scalars()
                .all()
            )
        # The re-entry actually happened, so the worker can pick it up again.
        assert [e.to_state for e in events] == [
            "submitted",
            "scanning",
            "blocked",
            "submitted",
            "scanning",
        ]
        assert events[3].from_state == "blocked"
        # ...and it did NOT cost a duplicate version row. `content_hash` is
        # `skill_version`'s primary key and the key single-flight dedup and the
        # verdict cache are built on; re-entry must not disturb it.
        assert len(versions) == 1


class TestSkillOwnership:
    """SECURITY (milestone F Task 11 follow-up C1): a caller may only submit a
    new version of a skill they OWN. Real HTTP path, real MySQL/Redis.

    THE HOLE THIS CLOSES. Task 11 fixed a genuine lockout - `"submitted"`
    appeared 0 times as a target in `VALID_TRANSITIONS`, so no skill could ever
    ship a v2 and every resubmission was a permanent 409. But that
    always-failing transition had been doing unintended double duty: a
    submission naming SOMEONE ELSE's `skill_id` also hit that 409 and changed
    nothing. Removing the lockout removed the accidental control, and nothing
    else on the submission path checked ownership - `skill` had no owner column
    at all, and `skill_id` AND `trust_tier` are both caller-supplied form
    fields. Any caller with submit rights could name any existing skill, knock
    it out of `published`, write their own `skill_version` row, have it judged
    at a tier THEY chose, and on PASS leave that skill published with their
    content as the latest version.

    Both properties are asserted here, because fixing either one alone is a
    bug: the owner CAN ship a v2 (`TestSkillIdRegistration` above, plus
    `test_the_owner_can_still_ship_v2` here), and nobody else can touch it.
    """

    @staticmethod
    async def _events(
        inventory_sessionmaker: SessionmakerFixture, skill_id: str
    ) -> list[SkillLifecycleEventRow]:
        async with inventory_sessionmaker() as session:
            return list(
                (
                    await session.execute(
                        select(SkillLifecycleEventRow)
                        .where(SkillLifecycleEventRow.skill_id == skill_id)
                        .order_by(SkillLifecycleEventRow.id)
                    )
                )
                .scalars()
                .all()
            )

    @pytest.mark.asyncio
    async def test_a_second_identity_cannot_take_over_a_published_skill(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
    ) -> None:
        """THE EXPLOIT. Alice registers and publishes a skill; Mallory submits
        her own content naming Alice's `skill_id`.

        Before this fix this returned **202**: Mallory's package was accepted,
        Alice's skill was driven `published -> submitted -> scanning` by
        Mallory, a `skill_version` row for Mallory's content was written under
        Alice's `skill_id`, and once the worker reconciled a PASS verdict the
        skill would sit `published` again with Mallory's content as its latest
        version. It is now a 403, and nothing is written."""
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await TestSkillIdRegistration._seed_lifecycle(
            inventory_sessionmaker,
            skill_id=skill_id,
            states=["scanning", "published"],
            owner="alice",
        )

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "mallory", frozenset({"submitter"})
        )
        tar_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())
        response = await client.post(
            "/v1/scans",
            files={"package": ("skill.tar", tar_bytes, "application/x-tar")},
            data={"skill_id": skill_id},
        )

        # 403, NOT the 409 this used to get by accident before Task 11. "You
        # may not modify this skill" is not a conflict, and a client told 409
        # would retry with different content forever.
        assert response.status_code == 403
        detail = response.json()["detail"]
        assert skill_id in detail
        # SECURITY: the refusal must not disclose WHO owns it - otherwise every
        # submission attempt doubles as an identity-harvesting probe.
        assert "alice" not in detail

        # Nothing moved: the skill is still published, on Alice's version only.
        events = await self._events(inventory_sessionmaker, skill_id)
        assert [e.to_state for e in events] == ["submitted", "scanning", "published"]
        async with inventory_sessionmaker() as session:
            versions = (
                (
                    await session.execute(
                        select(SkillVersionRow).where(SkillVersionRow.skill_id == skill_id)
                    )
                )
                .scalars()
                .all()
            )
            skill = await session.get(SkillRow, skill_id)
        assert len(versions) == 1, "Mallory's content must not be registered under alice's skill"
        assert skill is not None
        assert skill.owner == "alice", "a refused submission must never transfer ownership"

    @pytest.mark.asyncio
    async def test_no_scan_is_created_for_a_refused_submission(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
    ) -> None:
        """SECURITY: the ownership check runs BEFORE `submit_scan`, so a
        refused caller leaves no scan_job, no artifact blob and - the part that
        actually matters - no `scan_submitter` row. That association table is
        what every object-level authz check in the system reads, so creating
        one for a caller we are about to 403 would hand them a readable scan
        they should never have had."""
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await TestSkillIdRegistration._seed_lifecycle(
            inventory_sessionmaker,
            skill_id=skill_id,
            states=["scanning", "published"],
            owner="alice",
        )

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "mallory", frozenset({"submitter"})
        )
        marker = uuid.uuid4().hex
        tar_bytes = _make_tar_bytes(f"print({marker!r})\n".encode())
        response = await client.post(
            "/v1/scans",
            files={"package": ("skill.tar", tar_bytes, "application/x-tar")},
            data={"skill_id": skill_id},
        )
        assert response.status_code == 403

        # Mallory's list is empty - the refused submission created nothing she
        # can now read.
        list_response = await client.get("/v1/scans")
        assert list_response.status_code == 200
        assert list_response.json()["items"] == []

    @pytest.mark.asyncio
    async def test_the_owner_can_still_ship_v2(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
    ) -> None:
        """The other half. A fix that blocked Mallory by re-breaking Alice
        would just be Task 11's lockout again under a new name."""
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await TestSkillIdRegistration._seed_lifecycle(
            inventory_sessionmaker,
            skill_id=skill_id,
            states=["scanning", "published"],
            owner="alice",
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
        assert response.status_code == 202

        events = await self._events(inventory_sessionmaker, skill_id)
        assert [e.to_state for e in events] == [
            "submitted",
            "scanning",
            "published",
            "submitted",
            "scanning",
        ]

    @pytest.mark.asyncio
    async def test_an_admin_may_resubmit_on_an_owners_behalf_without_taking_ownership(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
    ) -> None:
        """The admin override, asserted rather than left implicit - and its
        limit asserted with it. An admin already holds strictly stronger
        powers over this object (quarantine/retire/baseline), so allowing the
        weaker "submit a version that still gets fully scanned" is coherent.
        But it must NOT silently make the admin the owner, or a takeover would
        just be one admin action away."""
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await TestSkillIdRegistration._seed_lifecycle(
            inventory_sessionmaker,
            skill_id=skill_id,
            states=["scanning", "published"],
            owner="alice",
        )

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "root", frozenset({"admin"})
        )
        tar_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())
        response = await client.post(
            "/v1/scans",
            files={"package": ("skill.tar", tar_bytes, "application/x-tar")},
            data={"skill_id": skill_id},
        )
        assert response.status_code == 202

        async with inventory_sessionmaker() as session:
            skill = await session.get(SkillRow, skill_id)
        assert skill is not None
        assert skill.owner == "alice", "an admin override must not transfer ownership"

    @pytest.mark.asyncio
    async def test_a_new_skill_id_makes_the_submitter_its_owner(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
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

        async with inventory_sessionmaker() as session:
            skill = await session.get(SkillRow, skill_id)
        assert skill is not None
        assert skill.owner == "alice"

    @pytest.mark.asyncio
    async def test_an_unowned_legacy_skill_refuses_a_non_admin_and_admits_an_admin(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
    ) -> None:
        """SECURITY: `owner IS NULL` - every row that predates the column,
        since the migration deliberately does not backfill - means "no owner is
        on record", and fails CLOSED. Defaulting to permissive would leave the
        hole open for exactly the rows an attacker would most want.

        The NULL is produced by nulling the column after a normal registration
        rather than by hand-building a row: that is precisely what a
        pre-migration row looks like, and it keeps the lifecycle history real.

        The admin half is asserted in the SAME test on purpose - fail-closed
        must not mean permanently bricked, and the admin is the recovery path
        for every legacy row."""
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await TestSkillIdRegistration._seed_lifecycle(
            inventory_sessionmaker,
            skill_id=skill_id,
            states=["scanning", "published"],
            owner="alice",
        )
        async with inventory_sessionmaker() as session, session.begin():
            await session.execute(
                update(SkillRow).where(SkillRow.skill_id == skill_id).values(owner=None)
            )

        # Even the identity that really did register it is refused: the system
        # has no record of that, and it must not guess.
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        response = await client.post(
            "/v1/scans",
            files={
                "package": (
                    "skill.tar",
                    _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode()),
                    "application/x-tar",
                )
            },
            data={"skill_id": skill_id},
        )
        assert response.status_code == 403

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "root", frozenset({"admin"})
        )
        admin_response = await client.post(
            "/v1/scans",
            files={
                "package": (
                    "skill.tar",
                    _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode()),
                    "application/x-tar",
                )
            },
            data={"skill_id": skill_id},
        )
        assert admin_response.status_code == 202

        # The admin's rescue did not invent an owner either - the column is
        # only ever written at genesis.
        async with inventory_sessionmaker() as session:
            skill = await session.get(SkillRow, skill_id)
        assert skill is not None
        assert skill.owner is None

    @pytest.mark.asyncio
    async def test_a_resubmission_is_judged_at_the_skills_recorded_tier(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        """SECURITY - the second half of the exploit, separately logged as
        finding I2. `trust_tier` is a caller-supplied form field and it decides
        the BLOCK threshold (`public` blocks at HIGH, every other tier only at
        CRITICAL - see test_trust_tier_plumbing.py). Meanwhile
        `register_skill_version` writes `skill.trust_tier` only when the skill
        is NEW, so the skill kept reporting `public` while the verdict was
        being made at whatever the submitter asked for.

        A resubmission is now judged at the skill's RECORDED tier. The caller's
        field is not honoured and not silently swallowed either: the resolved
        tier lands on `ScanJob.trust_tier` and is what `GET /v1/scans/{id}`
        reports as `trust_tier`/`judged_at_tier`."""
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await TestSkillIdRegistration._seed_lifecycle(
            inventory_sessionmaker,
            skill_id=skill_id,
            states=["scanning", "published"],
            owner="alice",
            trust_tier="public",
        )

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        tar_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())
        response = await client.post(
            "/v1/scans",
            files={"package": ("skill.tar", tar_bytes, "application/x-tar")},
            # The escalation attempt: `internal` blocks only at CRITICAL.
            data={"skill_id": skill_id, "trust_tier": "internal"},
        )
        assert response.status_code == 202
        scan_id = response.json()["scan_id"]

        async with orchestration_sessionmaker() as session:
            job = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()
        assert job.trust_tier == "public", "the caller's tier must not override the skill's"

        # And it is REPORTED, not silently substituted.
        detail = await client.get(f"/v1/scans/{scan_id}")
        assert detail.json()["judged_at_tier"] == "public"

    @pytest.mark.asyncio
    async def test_a_first_registration_still_honours_the_submitted_tier(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        """The limit of the rule above: a NEW skill has no recorded tier to
        defer to, so the submitted one is what registers it. Pinning this stops
        the override being widened into "the console can never set a tier",
        which would silently re-tier every first submission."""
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        tar_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())
        response = await client.post(
            "/v1/scans",
            files={"package": ("skill.tar", tar_bytes, "application/x-tar")},
            data={"skill_id": skill_id, "trust_tier": "internal"},
        )
        assert response.status_code == 202
        scan_id = response.json()["scan_id"]

        async with orchestration_sessionmaker() as session:
            job = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()
        assert job.trust_tier == "internal"

    @pytest.mark.asyncio
    async def test_a_stranger_is_refused_before_the_lifecycle_check_runs(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
    ) -> None:
        """Ordering, asserted deliberately. A stranger naming a QUARANTINED
        skill gets 403 (not authorized), never 409 (that skill is quarantined)
        - otherwise the error code itself becomes an oracle that leaks any
        skill's lifecycle state to anyone who can guess its id."""
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await TestSkillIdRegistration._seed_lifecycle(
            inventory_sessionmaker,
            skill_id=skill_id,
            states=["scanning", "published", "quarantined"],
            owner="alice",
        )

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "mallory", frozenset({"submitter"})
        )
        tar_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())
        response = await client.post(
            "/v1/scans",
            files={"package": ("skill.tar", tar_bytes, "application/x-tar")},
            data={"skill_id": skill_id},
        )
        assert response.status_code == 403
        assert "quarantin" not in response.json()["detail"].lower()


class TestCrossScopeAttemptsAreCounted:
    """Task 13 (2026-07-29): `cross_scope_access_attempts_total` (coding spec
    §11.7) - one of the two security-named signals Task 12 found had no
    production writer at all.

    Every assertion here goes through a REAL `/metrics` scrape of the same
    running app, not a direct read of the counter object: the failure mode
    being guarded against is an `.inc()` on a line that never executes, and a
    counter read in-process would not distinguish that from a working one any
    better than reading the source would. Needs real MySQL/Redis (the app
    fixture above) - VM only.
    """

    @staticmethod
    async def _scrape(client: httpx.AsyncClient) -> float:
        response = await client.get("/metrics")
        assert response.status_code == 200
        for line in response.text.splitlines():
            if line.startswith("skillscan_cross_scope_access_attempts_total "):
                return float(line.rsplit(" ", 1)[1])
        raise AssertionError("cross_scope_access_attempts_total missing from /metrics output")

    async def _submit_as_alice(self, app: FastAPI, client: httpx.AsyncClient) -> str:
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        tar_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())
        response = await client.post(
            "/v1/scans", files={"package": ("skill.tar", tar_bytes, "application/x-tar")}
        )
        return str(response.json()["scan_id"])

    @pytest.mark.asyncio
    async def test_reading_another_submitters_scan_moves_the_metric(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        scan_id = await self._submit_as_alice(app, client)
        before = await self._scrape(client)

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "mallory", frozenset({"submitter"})
        )
        assert (await client.get(f"/v1/scans/{scan_id}")).status_code == 404

        assert await self._scrape(client) == before + 1.0

    @pytest.mark.asyncio
    async def test_the_sarif_path_moves_it_too(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # The two IDOR checks are duplicated one path segment apart; an
        # instrumentation gap on one of them is the same shape of defect as
        # the authz gap the C2 fix closed.
        scan_id = await self._submit_as_alice(app, client)
        before = await self._scrape(client)

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "mallory", frozenset({"submitter"})
        )
        assert (await client.get(f"/v1/scans/{scan_id}/sarif")).status_code == 404

        assert await self._scrape(client) == before + 1.0

    @pytest.mark.asyncio
    async def test_an_unknown_scan_id_does_NOT_move_it(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # THE load-bearing negative. Both branches return an identical 404 by
        # design, so if the counter sat on the wrong one - or on both - every
        # stale bookmark and typo would read as an IDOR probe and the signal
        # would be worthless. Nothing distinguishes them but the branch.
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "mallory", frozenset({"submitter"})
        )
        before = await self._scrape(client)

        response = await client.get(f"/v1/scans/{uuid.uuid4()}")
        assert response.status_code == 404

        assert await self._scrape(client) == before

    @pytest.mark.asyncio
    async def test_an_authorized_read_does_NOT_move_it(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        scan_id = await self._submit_as_alice(app, client)
        before = await self._scrape(client)

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "bob", frozenset({"approver"})
        )
        assert (await client.get(f"/v1/scans/{scan_id}")).status_code == 200

        assert await self._scrape(client) == before

    @pytest.mark.asyncio
    async def test_a_plain_role_denial_does_NOT_move_it(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # A missing role is coarse RBAC, not an object-level attempt - see
        # `SecurityMetrics.record_cross_scope_attempt`'s docstring for why
        # folding it in would swamp the IDOR signal. Asserted here rather than
        # in test_observability.py because "this code path does not increment"
        # can only be shown where the code path actually runs.
        before = await self._scrape(client)

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "mallory", frozenset({"submitter"})
        )
        response = await client.get("/v1/allowlist")
        assert response.status_code == 403

        assert await self._scrape(client) == before


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
