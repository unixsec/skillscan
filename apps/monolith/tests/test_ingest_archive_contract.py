"""HTTP-level contract for `POST /v1/scans`'s archive rejection (the
`invalid package archive: ...` 400).

WHY THIS FILE EXISTS. Before 2026-07-30 that 400 had NO test at the HTTP layer
at all - grepping the suite for the string returned nothing - even though it is
the single most user-visible response this system produces for a bad upload,
and the reason a real skillhub.cloud.tencent.com zip was refused with "not a
valid tar archive". `test_normalizer.py` covers the unpacker; this covers the
CONTRACT: which status code, which detail prefix, and that a hostile archive can
never reach the 500 path.

NO INFRASTRUCTURE, BY CONSTRUCTION. `test_router.py`'s app fixture needs real
MySQL/Redis/blobstore, which this project only runs on the dev VM. Everything
asserted here happens strictly BEFORE the first infra call in `create_scan`, so
the runtime is wired with `_InfraSentinel`: any attempt to reach the database,
Redis or the blobstore raises `_InfraTouched` instead of connecting. That is not
a mock of behaviour - nothing here stubs a result - it is a tripwire, and it
doubles as the assertion that a REFUSED upload leaves no row, blob or Redis key
behind (the same "must not leave state behind on the way out" property
`create_scan`'s inventory pre-flight documents).
"""

from __future__ import annotations

import io
import stat
import struct
import tarfile
import uuid
import zipfile
from collections.abc import AsyncIterator
from typing import Any, cast

import httpx
import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from common.blobstore import BlobStorePort
from engine_runner.normalizer import MAX_ENTRY_COUNT
from fastapi import FastAPI
from skillscan_core import GatePolicy, StaticKeywordEngine, TrustTier, Verdict

from monolith.modules.gate.service import SignerPort
from monolith.modules.gateway.auth.dependencies import get_session_context
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.router import router as scan_router
from monolith.modules.gateway.runtime import ScanRuntime

_ENGINE = StaticKeywordEngine()

# Every route under test is reached with NO session cookie, which is exactly the
# case `require_csrf` exempts (bearer/API callers cannot be CSRF-forged), so the
# session override below is the only auth wiring needed.
_SUBJECT = "alice"


class _InfraTouched(RuntimeError):
    """Raised if the handler reaches Redis/MySQL/the blobstore. On the rejection
    paths under test that is a FAILURE; on the acceptance path it is the proof
    that the archive got through the ingest boundary."""


class _InfraSentinel:
    def __init__(self, what: str) -> None:
        self._what = what

    def __getattr__(self, name: str) -> Any:
        raise _InfraTouched(f"{self._what}.{name} was reached")

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        raise _InfraTouched(f"{self._what} was called")


def _fake_session() -> SessionContext:
    return SessionContext(
        subject=_SUBJECT,
        roles=frozenset({"submitter"}),
        scopes=frozenset(),
        tier=TrustTier.INTERNAL,
        token_exp=9999999999.0,
        is_machine=False,  # the console surface refuses machine identities
    )


@pytest.fixture
def app() -> FastAPI:
    runtime = ScanRuntime(
        redis=cast(aioredis.Redis, _InfraSentinel("redis")),
        blobstore=cast(BlobStorePort, _InfraSentinel("blobstore")),
        orchestration_session_factory=cast(Any, _InfraSentinel("orchestration_session")),
        gate_session_factory=cast(Any, _InfraSentinel("gate_session")),
        policy=GatePolicy(
            version=f"test-ingest-{uuid.uuid4().hex[:8]}",
            required_engines=frozenset({_ENGINE.metadata.name}),
            hard_gate_rules=frozenset(),
            fail_closed_verdict=Verdict.BLOCK,
        ),
        engine_metadatas=(_ENGINE.metadata,),
        allowlist=(),
        signer=cast(SignerPort, _InfraSentinel("signer")),
    )
    application = FastAPI()
    application.include_router(scan_router)
    application.state.scan = runtime
    application.dependency_overrides[get_session_context] = _fake_session
    return application


@pytest_asyncio.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


async def _submit(client: httpx.AsyncClient, payload: bytes, name: str) -> httpx.Response:
    return await client.post("/v1/scans", files={"package": (name, payload, "application/x-tar")})


def _tar(entries: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for entry_name, data in entries:
            info = tarfile.TarInfo(name=entry_name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _zip(entries: list[tuple[str, bytes]], *, compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compression) as zf:
        for entry_name, data in entries:
            zf.writestr(entry_name, data)
    return buf.getvalue()


class TestInvalidArchiveIsA400:
    @pytest.mark.asyncio
    async def test_garbage_bytes_are_a_400_with_the_documented_prefix(
        self, client: httpx.AsyncClient
    ) -> None:
        response = await _submit(client, b"not an archive of any kind", "skill.tar")
        assert response.status_code == 400
        # The prefix is the contract the frontend translates on (see
        # web/src/i18n/ingestErrors.ts); the tail is the caller's own diagnostic.
        assert response.json()["detail"].startswith("invalid package archive: ")
        assert "not a valid tar archive" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_an_empty_upload_is_a_400(self, client: httpx.AsyncClient) -> None:
        response = await _submit(client, b"", "empty.tar")
        assert response.status_code == 400
        assert "empty archive" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_a_tar_with_a_symlink_is_a_400(self, client: httpx.AsyncClient) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name="innocuous.txt")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tar.addfile(info)
        response = await _submit(client, buf.getvalue(), "skill.tar")
        assert response.status_code == 400
        assert "symlink" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_traversal_is_a_400(self, client: httpx.AsyncClient) -> None:
        response = await _submit(client, _tar([("../../etc/passwd", b"pwned")]), "skill.tar")
        assert response.status_code == 400
        assert "illegal path segment" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_a_rejected_upload_never_reaches_the_database_or_redis(
        self, client: httpx.AsyncClient
    ) -> None:
        # If this ever starts raising `_InfraTouched`, a refused submission has
        # begun leaving state behind on its way out.
        response = await _submit(client, b"PK\x03\x04 garbage", "skill.zip")
        assert response.status_code == 400


class TestZipUploadsAreAccepted:
    """The bug this closes: a real skillhub.cloud.tencent.com download is a zip,
    and this endpoint answered 400 "not a valid tar archive"."""

    @pytest.mark.asyncio
    async def test_a_zip_gets_past_the_ingest_boundary(self, client: httpx.AsyncClient) -> None:
        # Reaching Redis IS the pass condition: `filter_enabled_engines` is the
        # first thing `create_scan` does after unpacking, so `_InfraTouched`
        # proves the archive was accepted and the request moved on to
        # submission. What happens after that needs real MySQL/Redis and is
        # verified on the VM, not here.
        with pytest.raises(_InfraTouched, match="redis"):
            await _submit(client, _zip([("SKILL.md", b"# hi\n")]), "skill.zip")

    @pytest.mark.asyncio
    async def test_a_tar_still_gets_past_the_ingest_boundary(
        self, client: httpx.AsyncClient
    ) -> None:
        with pytest.raises(_InfraTouched, match="redis"):
            await _submit(client, _tar([("SKILL.md", b"# hi\n")]), "skill.tar")

    @pytest.mark.asyncio
    async def test_dispatch_ignores_the_filename_extension(self, client: httpx.AsyncClient) -> None:
        # A zip uploaded as ".tar" is still a zip: dispatch is on magic bytes,
        # because the filename is caller-supplied metadata.
        with pytest.raises(_InfraTouched, match="redis"):
            await _submit(client, _zip([("SKILL.md", b"# hi\n")]), "mislabelled.tar")


class TestHostileZipIsA400NotA500:
    """SECURITY: every one of these raises a bare `zipfile`/`zlib`/`RuntimeError`
    out of the stdlib if the transcode layer does not map it - i.e. a 500, an
    alarm, and a stack trace, for what is really "your upload is malformed"."""

    @pytest.mark.asyncio
    async def test_zip_magic_with_garbage_behind_it(self, client: httpx.AsyncClient) -> None:
        response = await _submit(client, b"PK\x03\x04" + b"\x00" * 64, "skill.zip")
        assert response.status_code == 400
        assert "not a valid zip archive" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_an_encrypted_entry(self, client: httpx.AsyncClient) -> None:
        raw = bytearray(_zip([("secret.txt", b"data")], compression=zipfile.ZIP_STORED))
        struct.pack_into("<H", raw, 6, 0x1)
        central = raw.find(b"PK\x01\x02")
        struct.pack_into("<H", raw, central + 8, 0x1)
        response = await _submit(client, bytes(raw), "skill.zip")
        assert response.status_code == 400
        assert "encrypted" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_a_decompression_bomb(self, client: httpx.AsyncClient) -> None:
        # 8 MiB of zeros in a few KB: rejected at the SHIPPED limits, no
        # monkeypatching, and rejected during transcode rather than after the
        # bomb has been expanded into a tar.
        response = await _submit(client, _zip([("z.bin", b"\x00" * (8 * 1024 * 1024))]), "b.zip")
        assert response.status_code == 400
        assert "compression ratio" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_entry_count_exhaustion(self, client: httpx.AsyncClient) -> None:
        # At the real limit: one entry past MAX_ENTRY_COUNT, each a single byte.
        payload = _zip([(f"f{i}.txt", b"x") for i in range(MAX_ENTRY_COUNT + 1)])
        response = await _submit(client, payload, "many.zip")
        assert response.status_code == 400
        assert "entry count" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_a_zip_carrying_a_symlink(self, client: httpx.AsyncClient) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            link = zipfile.ZipInfo(filename="passwd")
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(link, b"/etc/passwd")
        response = await _submit(client, buf.getvalue(), "links.zip")
        assert response.status_code == 400
        assert "non-regular zip entry rejected" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_a_symlink_hidden_among_real_files(self, client: httpx.AsyncClient) -> None:
        # THE 2026-07-30 REGRESSION LOCK, and the shape the test above does NOT
        # cover: with a real file beside it, the archive used to be ACCEPTED
        # (202) - the link was dropped and the rest scanned clean, so a package
        # carrying `passwd -> /etc/passwd` got a PASS with nothing recording the
        # attempt. Verified against a live k3s deployment before the fix.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            link = zipfile.ZipInfo(filename="passwd")
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(link, b"/etc/passwd")
            real = zipfile.ZipInfo(filename="SKILL.md")
            real.external_attr = (stat.S_IFREG | 0o644) << 16
            zf.writestr(real, b"# hi\n")
        response = await _submit(client, buf.getvalue(), "sneaky.zip")
        assert response.status_code == 400
        assert "non-regular zip entry rejected" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_the_clawhub_directory_marker_shape(self, client: httpx.AsyncClient) -> None:
        # The 2026-07-22 availability bug's original input, arriving as the zip
        # it really was: rejected at ingest instead of wedging every sandboxed
        # engine in an endless redelivery loop.
        payload = _zip([("agents", b""), ("agents/openai.yaml", b"key: value\n")])
        response = await _submit(client, payload, "marker.zip")
        assert response.status_code == 400
        assert "directory prefix" in response.json()["detail"]
