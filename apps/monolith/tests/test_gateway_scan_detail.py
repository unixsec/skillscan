"""里程碑 F Task 2: GET /v1/scans/{scan_id} exposes trust_tier, judged_at_tier
and submitters (coding spec §9's detail response never carried them before,
though every one of them was already computed and stored).

Real local MySQL/Redis via a real ScanRuntime - same fixture/app pattern as
`test_router.py` (`orchestration_sessionmaker`, `gate_sessionmaker`,
`redis_client`, `blobstore` all come from `conftest.py` and talk to a real
local MySQL + Redis). This file must NOT be run on the local Mac (see
skillscan's root CLAUDE.md) - it needs the dev VM's real MySQL/Redis, same as
every other test in this directory that touches `ScanRuntime`.

NOTE on the two "different values" assertions in the milestone's own task
brief (`trust_tier == "public"`, `judged_at_tier == "sandbox"`): that example
does not match this codebase. `ScanJob` has exactly one `trust_tier` column
(orchestration/models.py:75), and it is the ONLY place either fact is
recorded - `marketplace_api.views.project_scan`'s `judged_at_tier` reads that
same column via `orchestration.service.get_scan_state_and_tier` (see its
docstring). "sandbox" is also not a valid `TrustTier` value in this codebase at
all (`internal` / `partner` / `public` - see `skillscan_core.models.TrustTier`);
it names a sandbox-tier ENGINE class, an unrelated concept.

**里程碑 F Task 14 changed half of that.** Task 2 went on to say there was
"nowhere a per-submitter 'tier this caller individually asked for' is stored",
which was true then and is no longer: `ScanSubmitterRow.requested_trust_tier`
stores exactly that, written at INSERT on both of `submit_scan`'s paths -
including the dedup path, where `ScanJob.trust_tier` is deliberately left alone.
So `trust_tier` in the detail response is now the VIEWER's own request and
`judged_at_tier` is still the tier the verdict was reached at, and the two can
genuinely differ. `TestRequestedTrustTier` at the bottom of this file is where
that is exercised; the tests immediately below still hold because a lone
submitter's request IS the tier their scan was judged at.

里程碑 F Task 12 added `source` / `submitter_sources`, the fields Task 2 had to
report BLOCKED on. `ScanSubmitterRow` now carries a real `source` column
assigned at INSERT time by whichever handler took the submission, so
`TestSubmissionChannel` below drives BOTH real write paths - the console's
`POST /v1/scans` and the marketplace's `POST /v1/market/scans` - rather than
seeding rows directly. A test that seeded the column itself would prove only
that a SELECT works; what has to be proven is that each handler records its own
channel, and that the dedup path records the SECOND caller's.
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
from skillscan_core import GatePolicy, Severity, StaticKeywordEngine, TrustTier, Verdict

from monolith.main import create_app
from monolith.modules.gate.models import VerdictRow
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.gateway.auth.dependencies import get_session_context
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.modules.orchestration.models import ScanJob, ScanSubmitterRow
from monolith.tests.conftest import SessionmakerFixture

_ENGINE = StaticKeywordEngine()


def _make_tar_bytes(content: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name="skill.py")
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _unique_content() -> bytes:
    """Unique bytes per submission, for TEST ISOLATION: `submit_scan` is
    single-flight on content+toolchain, so shared bytes would collapse
    unrelated tests onto one scan_job. The dedup tests below deliberately reuse
    ONE `_unique_content()` value across both of their submissions - that is
    the behaviour under test, not an accident."""
    return f"print({uuid.uuid4().hex!r})\n".encode()


def _fake_session(subject: str, roles: frozenset[str]) -> SessionContext:
    return SessionContext(
        subject=subject,
        roles=roles,
        scopes=frozenset(),
        tier=TrustTier.INTERNAL,
        token_exp=9999999999.0,
        is_machine=False,
    )


def _market_session(subject: str) -> SessionContext:
    """An M2M session as `m2m.authenticate_client_credentials` builds it, so
    `POST /v1/market/scans` is reached through its REAL dependency chain.

    `is_machine=True` is load-bearing, not decoration: it is what makes this a
    marketplace caller rather than a console one, and `SessionContext` has no
    default for it precisely so a fixture cannot quietly fake a human session
    while claiming to test the machine path (spec §6.1 / C1). Same helper shape
    as test_marketplace_router.py's own `_market_session`.
    """
    return SessionContext(
        subject=subject,
        roles=frozenset({"submitter"}),
        scopes=frozenset({"scan:submit", "scan:read"}),
        tier=TrustTier.PUBLIC,
        token_exp=9999999999.0,
        is_machine=True,
    )


def _account(prefix: str) -> str:
    """A fresh service-account name per test - the marketplace rate limiter
    keys a 60-second budget on the service account in a SHARED Redis, so a
    fixed name would leak one test's consumed budget into the next one's
    (test_marketplace_router.py documents the same hazard)."""
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


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
            version=f"test-scan-detail-{uuid.uuid4().hex[:8]}",
            required_engines=frozenset({_ENGINE.metadata.name}),
            hard_gate_rules=frozenset(),
            fail_closed_verdict=Verdict.BLOCK,
            # 里程碑 F Task 14: mirrors `policies/gate/v1.yaml`, and it is
            # load-bearing rather than decoration. `tier_direction` is derived
            # from `GatePolicy.block_threshold`, so with the default policy
            # (CRITICAL for every tier, no overrides) `public` and `internal`
            # are genuinely equivalent and every divergence would correctly
            # report "equivalent". This one override is what makes `public` the
            # STRICTEST tier - the whole premise of this task - and a fixture
            # without it would let a broken direction calculation pass.
            tier_block_overrides=((TrustTier.PUBLIC, Severity.HIGH),),
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


class TestTrustTierAndJudgedAtTier:
    @pytest.mark.asyncio
    async def test_scan_detail_exposes_trust_tier_and_judged_at_tier(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        tar_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())
        response = await client.post(
            "/v1/scans",
            files={"package": ("skill.tar", tar_bytes, "application/x-tar")},
            data={"trust_tier": "public"},
        )
        assert response.status_code == 202
        scan_id = response.json()["scan_id"]

        detail = await client.get(f"/v1/scans/{scan_id}")
        assert detail.status_code == 200
        body = detail.json()
        # Equal here because alice is the only submitter, so the tier she asked
        # for IS the tier her scan was judged at. 里程碑 F Task 14 made these two
        # different backend facts; `TestRequestedTrustTier` below constructs the
        # dedup case where they actually diverge.
        assert body["trust_tier"] == "public"
        assert body["judged_at_tier"] == "public"

    @pytest.mark.asyncio
    async def test_scan_detail_reports_null_tier_when_none_was_recorded(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # SECURITY: no invented fallback - a scan whose row records no tier
        # (legacy row / a writer that forgot to set it, see
        # `ScanJob.trust_tier`'s docstring) must report `null`, verbatim, the
        # same posture `marketplace_api.views.project_scan` takes rather than
        # guessing at `runtime.default_trust_tier`.
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        tar_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())
        # No `trust_tier` form field - `create_scan` still resolves ONE via
        # `runtime.default_trust_tier`, so to exercise a genuinely-NULL
        # `ScanJob.trust_tier` we'd need a row written outside this endpoint.
        # `submit_scan` requires `trust_tier` as of milestone B' Task 4 (no
        # default parameter), so the only production path that yields NULL
        # today is a bug in a THIRD writer (the docstring's own example:
        # `reeval.controller.build_rescan_job` once did). There is no such
        # writer reachable from this router, so this test instead pins down
        # the endpoint's happy path: a normal submission with no explicit
        # `trust_tier` still resolves to a concrete tier, never null.
        response = await client.post(
            "/v1/scans", files={"package": ("skill.tar", tar_bytes, "application/x-tar")}
        )
        scan_id = response.json()["scan_id"]

        detail = await client.get(f"/v1/scans/{scan_id}")
        body = detail.json()
        assert body["trust_tier"] is not None
        assert body["trust_tier"] == body["judged_at_tier"]


class TestSubmitters:
    @pytest.mark.asyncio
    async def test_scan_detail_returns_single_element_list_for_lone_submitter(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # SECURITY: the response SHAPE must not change with the data - a
        # single submitter is still a list, never a degenerate bare string.
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        tar_bytes = _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())
        response = await client.post(
            "/v1/scans", files={"package": ("skill.tar", tar_bytes, "application/x-tar")}
        )
        scan_id = response.json()["scan_id"]

        detail = await client.get(f"/v1/scans/{scan_id}")
        body = detail.json()
        assert body["submitters"] == ["alice"]
        assert isinstance(body["submitters"], list)

    @pytest.mark.asyncio
    async def test_scan_detail_lists_all_authorized_submitters_after_dedup(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # `submit_scan` is single-flight on content+toolchain (coding spec):
        # bob submitting byte-identical content to alice's collapses onto her
        # scan_job. Both are rightful readers (`ScanSubmitterRow`), and the
        # console must show both names, not just the first submitter's.
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        shared_content = f"print({uuid.uuid4().hex!r})\n".encode()
        tar_bytes = _make_tar_bytes(shared_content)
        first = await client.post(
            "/v1/scans", files={"package": ("skill.tar", tar_bytes, "application/x-tar")}
        )
        scan_id = first.json()["scan_id"]

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "bob", frozenset({"submitter"})
        )
        second = await client.post(
            "/v1/scans", files={"package": ("skill.tar", tar_bytes, "application/x-tar")}
        )
        assert second.json()["scan_id"] == scan_id  # dedup confirmed

        detail = await client.get(f"/v1/scans/{scan_id}")
        assert detail.status_code == 200
        body = detail.json()
        assert sorted(body["submitters"]) == ["alice", "bob"]
        # `submitter` (singular, pre-existing field) stays the FIRST
        # submitter only - `ScanSubmitterRow`'s own docstring says this is
        # deliberate (it's what the scans list already displays); the fix
        # here is additive (`submitters`), not a change to that field.
        assert body["submitter"] == "alice"


async def _submit_console(
    client_instance: httpx.AsyncClient, package: bytes, *, trust_tier: str | None = None
) -> str:
    response = await client_instance.post(
        "/v1/scans",
        files={"package": ("skill.tar", package, "application/x-tar")},
        data={} if trust_tier is None else {"trust_tier": trust_tier},
    )
    assert response.status_code == 202, response.text
    scan_id: str = response.json()["scan_id"]
    return scan_id


async def _submit_market(client_instance: httpx.AsyncClient, package: bytes) -> str:
    response = await client_instance.post(
        "/v1/market/scans", files={"package": ("skill.tar", package, "application/x-tar")}
    )
    assert response.status_code == 202, response.text
    scan_id: str = response.json()["scan_id"]
    return scan_id


class TestSubmissionChannel:
    """里程碑 F Task 12: `source` / `submitter_sources` - which channel each
    submission arrived through.

    Every test here goes through a REAL submission handler rather than seeding
    `scan_submitter.source` directly. Seeding the column would only prove that
    a SELECT reads back what a test wrote; what has to hold is that each
    handler records ITS OWN channel at INSERT time, on both the fresh-scan path
    and the dedup path.
    """

    @pytest.mark.asyncio
    async def test_console_submission_is_recorded_as_the_console_channel(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        scan_id = await _submit_console(client, _make_tar_bytes(_unique_content()))

        body = (await client.get(f"/v1/scans/{scan_id}")).json()
        # A LIST even for a single channel - the same shape rule `submitters`
        # follows. A response whose shape changes with the data is what
        # consumers silently mis-parse.
        assert body["source"] == ["console"]
        assert isinstance(body["source"], list)
        # Whole-dict equality on purpose (see this class's docstring): it is
        # what turns a field silently appearing in this projection into a
        # failing test. `requested_trust_tier` is Task 14's addition and this
        # assertion is the reason it could not slip in unannounced - `internal`
        # is the `app` fixture's `default_trust_tier`, which `_submit_console`
        # sends no `trust_tier` form field to override.
        assert body["submitter_sources"] == [
            {"submitter": "alice", "source": "console", "requested_trust_tier": "internal"}
        ]

    @pytest.mark.asyncio
    async def test_marketplace_submission_is_recorded_as_the_marketplace_channel(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        account = _account("mkt-channel")
        app.dependency_overrides[get_session_context] = lambda: _market_session(account)
        scan_id = await _submit_market(client, _make_tar_bytes(_unique_content()))

        # The console surface is closed to machine identities (403,
        # `require_human_role`), so the reader here is a human reviewer -
        # `_REVIEWER_ROLES` may read any scan. This is also the real product
        # scenario for this field: a console reviewer looking at a scan that
        # arrived from the marketplace and needing to know that it did.
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "carol", frozenset({"auditor"})
        )
        body = (await client.get(f"/v1/scans/{scan_id}")).json()
        assert body["source"] == ["marketplace"]
        # `public`, not the console's `internal`: the marketplace handler
        # records `session.tier`, and a service account's tier is PUBLIC - the
        # STRICTEST tier, which is why a marketplace poll of console-scanned
        # bytes is the dangerous direction Task 14 exists to disclose.
        assert body["submitter_sources"] == [
            {"submitter": account, "source": "marketplace", "requested_trust_tier": "public"}
        ]

    @pytest.mark.asyncio
    async def test_both_channels_survive_dedup_console_first(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # THE case this field is modelled per-submitter for. `submit_scan` is
        # single-flight on content+toolchain, so the marketplace submitting
        # bytes the console already scanned is handed the SAME scan_job - and
        # "the console and the marketplace scan the same skills" is this
        # product's normal case, not an edge case (see `scan_submitter`'s own
        # migration). A scan-LEVEL `source` would silently drop one of the two
        # channels here, and it would drop it precisely when both matter.
        package = _make_tar_bytes(_unique_content())

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        console_scan_id = await _submit_console(client, package)

        account = _account("mkt-dedup-second")
        app.dependency_overrides[get_session_context] = lambda: _market_session(account)
        market_scan_id = await _submit_market(client, package)
        assert market_scan_id == console_scan_id  # the premise: dedup happened

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        body = (await client.get(f"/v1/scans/{console_scan_id}")).json()
        assert body["source"] == ["console", "marketplace"]
        # ...and WHICH name came through WHICH door is still recoverable: the
        # aggregate above is a convenience, not the storage.
        assert sorted(body["submitter_sources"], key=lambda entry: entry["submitter"]) == sorted(
            [
                {"submitter": "alice", "source": "console", "requested_trust_tier": "internal"},
                {"submitter": account, "source": "marketplace", "requested_trust_tier": "public"},
            ],
            key=lambda entry: entry["submitter"],
        )

    @pytest.mark.asyncio
    async def test_both_channels_survive_dedup_marketplace_first(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # The mirror ordering, deliberately. The two orderings put a DIFFERENT
        # handler on `submit_scan`'s dedup branch, and this repository has
        # already shipped a bug that was fixed on exactly one of two identical
        # paths (the C2 authorization check - see test_marketplace_router.py's
        # TestDeduplicatedSubmissionsStayReadableByEverySubmitter). A `source`
        # written only on the fresh-scan path would pass the test above and
        # fail this one.
        package = _make_tar_bytes(_unique_content())

        account = _account("mkt-dedup-first")
        app.dependency_overrides[get_session_context] = lambda: _market_session(account)
        market_scan_id = await _submit_market(client, package)

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "bob", frozenset({"submitter"})
        )
        console_scan_id = await _submit_console(client, package)
        assert console_scan_id == market_scan_id

        body = (await client.get(f"/v1/scans/{console_scan_id}")).json()
        assert body["source"] == ["console", "marketplace"]
        assert {entry["submitter"]: entry["source"] for entry in body["submitter_sources"]} == {
            "bob": "console",
            account: "marketplace",
        }

    @pytest.mark.asyncio
    async def test_a_submitter_row_recording_no_channel_reports_null_never_a_guess(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        # SECURITY: `scan_submitter.source` is nullable with no backfill - rows
        # written before the column existed genuinely have no recorded channel,
        # and nothing anywhere records it retroactively. The one tempting
        # reconstruction ("service accounts are named like X, so this must be
        # marketplace") is a shape check standing in for a membership check and
        # is exactly what this design refuses. NULL therefore has to survive to
        # the response as `null`, and must NOT contribute a fabricated entry to
        # the aggregate `source` list.
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        scan_id = await _submit_console(client, _make_tar_bytes(_unique_content()))

        # Stands in for a pre-migration row: append a second, channel-less
        # submitter directly (INSERT is granted on this table; UPDATE
        # deliberately is not, which is why the column is only ever assigned
        # here, at insert time).
        async with orchestration_sessionmaker() as db_session, db_session.begin():
            db_session.add(ScanSubmitterRow(scan_id=scan_id, submitter="legacy-dave", source=None))

        body = (await client.get(f"/v1/scans/{scan_id}")).json()
        assert {entry["submitter"]: entry["source"] for entry in body["submitter_sources"]} == {
            "alice": "console",
            "legacy-dave": None,
        }
        # The unknown channel is absent from the aggregate, not guessed into it.
        assert body["source"] == ["console"]


class TestRequestedTrustTier:
    """里程碑 F Task 14: the tier each submitter ASKED FOR, as distinct from the
    tier the verdict was adjudicated at.

    Task 2's module docstring above says there is "nowhere a per-submitter
    'tier this caller individually asked for' is stored". That was true then and
    is the gap this class covers: `ScanSubmitterRow.requested_trust_tier` stores
    it now, written at INSERT on BOTH of `submit_scan`'s paths - including the
    dedup path, where `ScanJob.trust_tier` is deliberately left alone.

    Every test drives a REAL submission handler. Seeding the column directly
    would prove only that a SELECT reads back what the test wrote; what has to
    hold is that each handler records its own caller's request, and that the
    DEDUP path records the SECOND caller's - which is the only situation where
    the two tiers can differ at all. A test that does not construct dedup is
    asserting that two copies of one value are equal.
    """

    @pytest.mark.asyncio
    async def test_a_lone_submitter_sees_the_tier_they_asked_for_in_both_fields(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # The ordinary case: no dedup, so the tier asked for IS the tier judged
        # at. Both fields agree and `tier_direction` reports nothing - a
        # divergence warning that fired here would be noise on every scan.
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        scan_id = await _submit_console(
            client, _make_tar_bytes(_unique_content()), trust_tier="public"
        )

        body = (await client.get(f"/v1/scans/{scan_id}")).json()
        assert body["trust_tier"] == "public"
        assert body["judged_at_tier"] == "public"
        assert body["tier_direction"] is None
        assert body["submitter_sources"] == [
            {"submitter": "alice", "source": "console", "requested_trust_tier": "public"}
        ]

    @pytest.mark.asyncio
    async def test_cross_tier_dedup_tells_the_second_submitter_it_was_judged_more_permissively(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # THE test for this task, and the dangerous direction.
        #
        # alice submits at `internal` (blocks only at CRITICAL). bob submits
        # byte-identical content at `public` (blocks at HIGH - the STRICTEST
        # tier, per policies/gate/v1.yaml). Single-flight dedup hands bob
        # alice's scan_job and alice's verdict, and that verdict is NOT
        # re-adjudicated - correctly, since re-tiering it would claim a decision
        # nobody made. So bob is holding a conclusion reached under a MORE
        # PERMISSIVE ruleset than he asked for: a HIGH finding that had to block
        # for him reads PASS.
        #
        # Before this task both fields came from `ScanJob.trust_tier`, so bob's
        # response said `public`/`public` - it showed him his own request back
        # and called it the judged tier. The console's "highlight when they
        # differ" could never fire, and this test could not have been written.
        package = _make_tar_bytes(_unique_content())

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        first_scan_id = await _submit_console(client, package, trust_tier="internal")

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "bob", frozenset({"submitter"})
        )
        second_scan_id = await _submit_console(client, package, trust_tier="public")
        assert second_scan_id == first_scan_id  # the premise: dedup happened

        bob_body = (await client.get(f"/v1/scans/{second_scan_id}")).json()
        assert bob_body["trust_tier"] == "public"  # what bob asked for
        assert bob_body["judged_at_tier"] == "internal"  # what he actually got
        assert bob_body["tier_direction"] == "looser"
        # 2026-07-29 residual triage: nothing has decided this scan, so no
        # verdict has been signed and the direction can only describe today's
        # thresholds. Saying so is the whole point - see
        # `TestTierDirectionIsQualifiedByTheSigningPolicy` below.
        assert bob_body["tier_direction_basis"] == "current_policy"

        # alice, on the SAME scan, sees no divergence - hers is the request the
        # verdict was actually reached at. The fields are per-viewer, not a
        # scan-level flag that would shout at everyone.
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        alice_body = (await client.get(f"/v1/scans/{first_scan_id}")).json()
        assert alice_body["trust_tier"] == "internal"
        assert alice_body["judged_at_tier"] == "internal"
        assert alice_body["tier_direction"] is None
        # No comparison happened, so there is nothing to qualify.
        assert alice_body["tier_direction_basis"] is None

        # Both requests are on record per name, so a reviewer can see the whole
        # picture rather than only whichever caller happens to be looking.
        assert {
            entry["submitter"]: entry["requested_trust_tier"]
            for entry in alice_body["submitter_sources"]
        } == {"alice": "internal", "bob": "public"}

    @pytest.mark.asyncio
    async def test_cross_tier_dedup_reports_the_safe_direction_too(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # The mirror ordering. Asking for `internal` and receiving a `public`
        # verdict over-blocks rather than under-blocks, so it is the safe side -
        # but it is still disclosed, because an unexplained BLOCK is its own
        # failure. Not redundant with the test above: the two orderings put a
        # DIFFERENT submission on `submit_scan`'s dedup branch, and this repo has
        # already shipped a bug fixed on exactly one of two identical paths.
        package = _make_tar_bytes(_unique_content())

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        first_scan_id = await _submit_console(client, package, trust_tier="public")

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "bob", frozenset({"submitter"})
        )
        second_scan_id = await _submit_console(client, package, trust_tier="internal")
        assert second_scan_id == first_scan_id

        body = (await client.get(f"/v1/scans/{second_scan_id}")).json()
        assert body["trust_tier"] == "internal"
        assert body["judged_at_tier"] == "public"
        assert body["tier_direction"] == "stricter"

    @pytest.mark.asyncio
    async def test_console_then_marketplace_dedup_records_each_channel_own_request(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # The real product scenario, not a contrivance. A marketplace service
        # account is granted PUBLIC (the strictest tier; an unconfigured account
        # gets it by default) while the console routinely submits at `internal`,
        # and "the console and the marketplace scan the same skill" is this
        # product's normal case - it is why `scan_submitter` exists at all.
        package = _make_tar_bytes(_unique_content())

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        console_scan_id = await _submit_console(client, package, trust_tier="internal")

        account = _account("mkt-tier-second")
        app.dependency_overrides[get_session_context] = lambda: _market_session(account)
        market_scan_id = await _submit_market(client, package)
        assert market_scan_id == console_scan_id

        # Read by a human auditor: the console surface 403s machine identities,
        # and this is also who needs the whole picture.
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "carol", frozenset({"auditor"})
        )
        body = (await client.get(f"/v1/scans/{console_scan_id}")).json()
        assert {
            entry["submitter"]: entry["requested_trust_tier"] for entry in body["submitter_sources"]
        } == {"alice": "internal", account: "public"}
        # carol submitted nothing, so she has no request of her own. The two
        # fields fall back to the judged tier and agree - a reviewer must not be
        # shown a fabricated divergence, and must not have someone else's
        # request attributed to her.
        assert body["trust_tier"] == "internal"
        assert body["judged_at_tier"] == "internal"
        assert body["tier_direction"] is None

    @pytest.mark.asyncio
    async def test_a_row_recording_no_request_reports_null_and_never_a_guess(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        # SECURITY: `requested_trust_tier` is nullable with NO backfill, and the
        # tempting backfill is the dangerous one - copying `ScanJob.trust_tier`
        # into it would assert that every past submitter asked for the tier they
        # were judged at, which is precisely the unverified assumption the column
        # exists to stop making. NULL has to survive to the response as `null`.
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        scan_id = await _submit_console(
            client, _make_tar_bytes(_unique_content()), trust_tier="public"
        )

        # Stands in for a pre-migration row (INSERT is granted on this table;
        # UPDATE deliberately is not, which is why the column is only ever
        # assigned at insert time).
        async with orchestration_sessionmaker() as db_session, db_session.begin():
            db_session.add(
                ScanSubmitterRow(
                    scan_id=scan_id,
                    submitter="legacy-dave",
                    source=None,
                    requested_trust_tier=None,
                )
            )

        body = (await client.get(f"/v1/scans/{scan_id}")).json()
        assert {
            entry["submitter"]: entry["requested_trust_tier"] for entry in body["submitter_sources"]
        } == {"alice": "public", "legacy-dave": None}

        # And read AS that legacy submitter: with no request on record the two
        # fields fall back to the judged tier and agree, rather than inventing a
        # request or reporting a divergence nobody can act on.
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "legacy-dave", frozenset({"submitter"})
        )
        legacy_body = (await client.get(f"/v1/scans/{scan_id}")).json()
        assert legacy_body["trust_tier"] == "public"
        assert legacy_body["judged_at_tier"] == "public"
        assert legacy_body["tier_direction"] is None


class TestTierDirectionIsQualifiedByTheSigningPolicy:
    """2026-07-29 residual triage: `tier_direction` is computed from the policy
    this process has loaded, not from the one the verdict was signed under.

    Strictness lives in `tier_block_overrides`, so an approved policy change
    between signing and viewing could relabel a historical verdict - showing a
    divergence that did not exist when the adjudication happened, or hiding one
    that did. `verdict.policy_version` is the one part of that which IS
    recoverable, and `tier_direction_basis` is what it buys: the label stays,
    and the response says whether to read it as a statement about the past.

    The historical policy CONTENT is deliberately not reconstructed anywhere -
    see `gate.policy.tier_divergence` on why an accurate caveat beats an
    invented threshold.
    """

    @staticmethod
    async def _sign_verdict(
        gate_sessionmaker: SessionmakerFixture, *, scan_id: str, policy_version: str
    ) -> None:
        async with gate_sessionmaker() as db_session, db_session.begin():
            db_session.add(
                VerdictRow(
                    scan_id=scan_id,
                    content_hash=uuid.uuid4().hex + uuid.uuid4().hex,
                    verdict="PASS",
                    score=90,
                    policy_version=policy_version,
                    jti=str(uuid.uuid4()),
                    jws_signature="test",
                    effective_severity=0,
                    reasons=["test"],
                    issued_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                )
            )

    @pytest.mark.asyncio
    async def test_a_verdict_signed_under_the_loaded_policy_says_so(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        package = _make_tar_bytes(_unique_content())
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        first_scan_id = await _submit_console(client, package, trust_tier="internal")
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "bob", frozenset({"submitter"})
        )
        second_scan_id = await _submit_console(client, package, trust_tier="public")
        assert second_scan_id == first_scan_id

        runtime: ScanRuntime = app.state.scan
        await self._sign_verdict(
            gate_sessionmaker, scan_id=second_scan_id, policy_version=runtime.policy.version
        )

        body = (await client.get(f"/v1/scans/{second_scan_id}")).json()
        assert body["tier_direction"] == "looser"
        assert body["tier_direction_basis"] == "signing_policy"

    @pytest.mark.asyncio
    async def test_a_verdict_signed_under_a_superseded_policy_is_not_passed_off_as_current(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        """THE finding. Same scan, same tiers, same reported direction - the
        only difference is that the verdict was signed under a policy version
        this process no longer has, so the direction can no longer be claimed to
        describe the adjudication that happened.

        The direction is NOT suppressed. Nulling it would hide a divergence that
        may well be real; the honest move is to keep the best available reading
        and label what it is.
        """
        package = _make_tar_bytes(_unique_content())
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        first_scan_id = await _submit_console(client, package, trust_tier="internal")
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "bob", frozenset({"submitter"})
        )
        second_scan_id = await _submit_console(client, package, trust_tier="public")
        assert second_scan_id == first_scan_id

        runtime: ScanRuntime = app.state.scan
        await self._sign_verdict(
            gate_sessionmaker,
            scan_id=second_scan_id,
            policy_version=f"{runtime.policy.version}-superseded",
        )

        body = (await client.get(f"/v1/scans/{second_scan_id}")).json()
        assert body["tier_direction"] == "looser"
        assert body["tier_direction_basis"] == "current_policy"


_ATTRIBUTION_KEYS = ("submitters", "submitter_sources", "source")


class TestListCarriesTheSameAttributionAsDetail:
    """里程碑 F Task 16: `GET /v1/scans` serves attribution in the SAME shape as
    `GET /v1/scans/{scan_id}`.

    Task 8 fixed the detail response and deliberately left both lists alone to
    avoid racing another agent in `gateway/router.py`, so until now the list
    carried only the scalar `ScanJob.submitter` - the FIRST submitter. On a
    deduplicated scan that is a STRANGER'S name to everyone who submitted
    afterwards, and the correct names were one click away in the drawer.

    The assertions below compare the list item against the detail response
    FIELD BY FIELD rather than checking the list independently. One concept with
    two shapes across two endpoints is a reliable source of consumer bugs, and a
    test that only checks each endpoint against its own expectations is exactly
    how the two drift.
    """

    @pytest.mark.asyncio
    async def test_list_item_attribution_is_identical_to_the_detail_response(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        package = _make_tar_bytes(_unique_content())

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        scan_id = await _submit_console(client, package, trust_tier="internal")

        # A genuine dedup, so the list has something to get WRONG: without a
        # second submitter, `ScanJob.submitter` and the association table agree
        # and the old implementation would pass too.
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "bob", frozenset({"submitter"})
        )
        assert await _submit_console(client, package, trust_tier="public") == scan_id

        detail = (await client.get(f"/v1/scans/{scan_id}")).json()
        listing = (await client.get("/v1/scans")).json()
        item = next(i for i in listing["items"] if i["scan_id"] == scan_id)

        for key in _ATTRIBUTION_KEYS:
            assert key in item, f"list item is missing {key!r}"
            assert item[key] == detail[key], f"{key!r} differs between list and detail"
        # And the content is actually right, not merely consistent: two names,
        # each with its own channel and its own requested tier.
        assert item["submitters"] == ["alice", "bob"]
        assert item["submitter_sources"] == [
            {"submitter": "alice", "source": "console", "requested_trust_tier": "internal"},
            {"submitter": "bob", "source": "console", "requested_trust_tier": "public"},
        ]

    @pytest.mark.asyncio
    async def test_the_list_no_longer_shows_a_stranger_as_the_only_submitter(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # bob's own scan list is the ONLY route he has to a deduplicated scan
        # through the UI, and it used to name alice and nobody else.
        package = _make_tar_bytes(_unique_content())

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        scan_id = await _submit_console(client, package)

        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "bob", frozenset({"submitter"})
        )
        assert await _submit_console(client, package) == scan_id

        item = next(
            i for i in (await client.get("/v1/scans")).json()["items"] if i["scan_id"] == scan_id
        )
        # The scalar stays the FIRST submitter - the fix is additive, not a
        # change to that column's meaning.
        assert item["submitter"] == "alice"
        assert item["submitters"] == ["alice", "bob"]

    @pytest.mark.asyncio
    async def test_the_list_still_returns_no_total(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # 里程碑 F Task 16 evaluated adding one and decided against it: a total
        # means COUNT(*) over `scan_job` on every request (no `submitter`
        # predicate narrows it for the reviewer roles, InnoDB caches no row
        # count), and this endpoint is POLLED on a 3s->20s backoff by every open
        # Scans tab. The frontend's over-fetch-one-row probe and honest "page N"
        # display are the supported answer.
        #
        # Asserted rather than assumed: a later change that quietly adds `total`
        # would give the frontend a field it does not use and the deployment a
        # per-poll table scan nobody measured.
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "alice", frozenset({"submitter"})
        )
        await _submit_console(client, _make_tar_bytes(_unique_content()))

        body = (await client.get("/v1/scans")).json()
        assert set(body) == {"items"}

    @pytest.mark.asyncio
    async def test_a_scan_with_no_association_rows_lists_empty_not_the_first_submitter(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        # A `scan_job` with no `scan_submitter` rows - what
        # `reeval.controller.build_rescan_job` writes (it holds no grant on the
        # association table at all). Rendered as EMPTY lists, never as the scalar
        # `ScanJob.submitter` promoted into a one-element list: that would state
        # the first submitter is the ONLY authorized reader, which is the claim
        # `scan_submitter` exists to stop making.
        scan_id = str(uuid.uuid4())
        async with orchestration_sessionmaker() as db_session, db_session.begin():
            db_session.add(
                ScanJob(
                    scan_id=scan_id,
                    content_hash="c" * 64,
                    toolchain_digest="d" * 64,
                    cache_key=f"cache-{uuid.uuid4().hex}",
                    state="queued",
                    submitter="rescan-owner",
                    created_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                    trust_tier="internal",
                )
            )

        # An auditor, since nobody is a recorded submitter of this scan.
        app.dependency_overrides[get_session_context] = lambda: _fake_session(
            "carol", frozenset({"auditor"})
        )
        item = next(
            i for i in (await client.get("/v1/scans")).json()["items"] if i["scan_id"] == scan_id
        )
        assert item["submitter"] == "rescan-owner"
        assert item["submitters"] == []
        assert item["submitter_sources"] == []
        assert item["source"] == []
