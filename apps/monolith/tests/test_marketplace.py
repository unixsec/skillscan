"""Tests for `integration_relay.marketplace.HttpMarketplaceAdapter` (coding
spec §6/§11.6). No real marketplace is available in this environment - these
tests exercise the REAL httpx request/response code path via
`httpx.MockTransport` (a fake transport, not a fake Python object), proving
URL construction, credential separation, and error handling are correct
independent of whether a real marketplace is reachable.
"""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx
import pytest

from monolith.modules.integration_relay.marketplace import HttpMarketplaceAdapter

_Handler = Callable[[httpx.Request], httpx.Response]


class _RequestLog:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def record(self, request: httpx.Request) -> None:
        self.requests.append(request)


def _make_adapter(
    handler: _Handler, *, poll_token: str = "poll-tok", write_token: str = "write-tok"
) -> tuple[HttpMarketplaceAdapter, _RequestLog]:
    log = _RequestLog()

    def logging_handler(request: httpx.Request) -> httpx.Response:
        log.record(request)
        return handler(request)

    transport = httpx.MockTransport(logging_handler)
    adapter = HttpMarketplaceAdapter(
        base_url="http://localhost:9000",
        poll_token=poll_token,
        write_token=write_token,
        poll_transport=transport,
        write_transport=transport,
    )
    return adapter, log


class TestWriteVerdict:
    @pytest.mark.asyncio
    async def test_sends_put_with_jws_body(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.method == "PUT"
            assert request.url.path == "/v1/verdicts/" + "a" * 64
            assert json.loads(request.content) == {"jws": "the-jws-token"}
            return httpx.Response(200)

        adapter, log = _make_adapter(handler)
        await adapter.write_verdict("the-jws-token", "a" * 64)
        assert len(log.requests) == 1

    @pytest.mark.asyncio
    async def test_uses_the_write_token_not_the_poll_token(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.headers["Authorization"] == "Bearer write-tok"
            return httpx.Response(200)

        adapter, _ = _make_adapter(handler, poll_token="poll-tok", write_token="write-tok")
        await adapter.write_verdict("jws", "a" * 64)

    @pytest.mark.asyncio
    async def test_non_2xx_response_raises(self) -> None:
        adapter, _ = _make_adapter(lambda _r: httpx.Response(500))
        with pytest.raises(httpx.HTTPStatusError):
            await adapter.write_verdict("jws", "a" * 64)


class TestListPublished:
    @pytest.mark.asyncio
    async def test_sends_get_and_parses_json_array(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.method == "GET"
            assert request.url.path == "/v1/published"
            return httpx.Response(200, json=[{"content_hash": "a" * 64, "skill_id": "s1"}])

        adapter, _ = _make_adapter(handler)
        result = await adapter.list_published()
        assert result == [{"content_hash": "a" * 64, "skill_id": "s1"}]

    @pytest.mark.asyncio
    async def test_uses_the_poll_token_not_the_write_token(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.headers["Authorization"] == "Bearer poll-tok"
            return httpx.Response(200, json=[])

        adapter, _ = _make_adapter(handler, poll_token="poll-tok", write_token="write-tok")
        await adapter.list_published()

    @pytest.mark.asyncio
    async def test_non_list_response_raises_value_error(self) -> None:
        # SECURITY: a malformed response must fail closed - never be treated
        # as "the published set happens to be empty", which would blind poll
        # reconciliation to every real ORPHAN.
        adapter, _ = _make_adapter(lambda _r: httpx.Response(200, json={"not": "a list"}))
        with pytest.raises(ValueError, match="JSON array"):
            await adapter.list_published()

    @pytest.mark.asyncio
    async def test_non_2xx_response_raises(self) -> None:
        adapter, _ = _make_adapter(lambda _r: httpx.Response(503))
        with pytest.raises(httpx.HTTPStatusError):
            await adapter.list_published()


class TestQuarantine:
    @pytest.mark.asyncio
    async def test_sends_post_with_reason_body(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.method == "POST"
            assert request.url.path == "/v1/skills/skill-1/quarantine"
            assert json.loads(request.content) == {"reason": "orphan detected"}
            return httpx.Response(200)

        adapter, _ = _make_adapter(handler)
        await adapter.quarantine("skill-1", "orphan detected")

    @pytest.mark.asyncio
    async def test_uses_the_write_token(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.headers["Authorization"] == "Bearer write-tok"
            return httpx.Response(200)

        adapter, _ = _make_adapter(handler, write_token="write-tok")
        await adapter.quarantine("skill-1", "reason")

    @pytest.mark.asyncio
    async def test_non_2xx_response_raises(self) -> None:
        adapter, _ = _make_adapter(lambda _r: httpx.Response(403))
        with pytest.raises(httpx.HTTPStatusError):
            await adapter.quarantine("skill-1", "reason")


class TestConstructionValidation:
    def test_rejects_external_base_url(self) -> None:
        with pytest.raises(ValueError, match="internal/private"):
            HttpMarketplaceAdapter(
                base_url="https://marketplace.example.com",
                poll_token="p",
                write_token="w",
            )

    def test_accepts_loopback_base_url(self) -> None:
        adapter = HttpMarketplaceAdapter(
            base_url="http://localhost:9000", poll_token="p", write_token="w"
        )
        assert adapter is not None
