"""Tests for `common.pinned_dns` (2026-07-10 full-project review, Finding
#16: DNS-rebinding TOCTOU on internal-endpoint validation).

SECURITY: this module monkeypatches `socket.getaddrinfo` process-wide, so
every test here resets that global state (`_reset_for_tests()`) both before
and after, to avoid leaking a patched resolver into unrelated tests that
happen to run later in the same pytest session.
"""

from __future__ import annotations

import socket
import time
from collections.abc import Iterator

import pytest
from common import pinned_dns
from common.config import require_internal_endpoint


@pytest.fixture(autouse=True)
def _reset_pinned_dns() -> Iterator[None]:
    pinned_dns._reset_for_tests()
    yield
    pinned_dns._reset_for_tests()


class TestPinInternalHost:
    def test_pinning_localhost_succeeds(self) -> None:
        pinned_dns.pin_internal_host("localhost")
        assert "localhost" in pinned_dns._pins

    def test_pinning_a_public_host_raises(self) -> None:
        # A hostname that resolves to a well-known public address must be
        # rejected exactly like config.is_internal_host already rejects it -
        # pin_internal_host must never pin something non-internal.
        def fake_getaddrinfo(host: str, port: object, *_a: object, **_kw: object) -> list:  # type: ignore[type-arg]
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]

        original = pinned_dns._real_getaddrinfo
        pinned_dns._real_getaddrinfo = fake_getaddrinfo  # type: ignore[assignment]
        try:
            with pytest.raises(ValueError, match="not internal/private"):
                pinned_dns.pin_internal_host("public.example.invalid")
        finally:
            pinned_dns._real_getaddrinfo = original

    def test_pinning_unresolvable_host_raises(self) -> None:
        with pytest.raises(ValueError, match="DNS resolution failed"):
            pinned_dns.pin_internal_host("this-host-should-not-resolve.invalid")


class TestPatchedResolutionUsesThePin:
    def test_getaddrinfo_for_pinned_host_returns_pinned_result_not_live_lookup(self) -> None:
        # Prove the patch is actually consulted, not just that pinning
        # records something inert: after pinning, redirect the REAL resolver
        # to something that would fail/differ, then confirm
        # socket.getaddrinfo still returns the originally-pinned (loopback)
        # result rather than re-resolving live.
        pinned_dns.pin_internal_host("localhost")

        def would_fail_if_called(*_a: object, **_kw: object) -> list:  # type: ignore[type-arg]
            raise AssertionError("must not re-resolve a pinned, unexpired hostname live")

        original = pinned_dns._real_getaddrinfo
        pinned_dns._real_getaddrinfo = would_fail_if_called
        try:
            infos = socket.getaddrinfo("localhost", 12345)
        finally:
            pinned_dns._real_getaddrinfo = original
        assert infos
        # Port substitution must reflect the REQUESTED port, not whatever
        # was resolved at pin-time (getaddrinfo(hostname, None) always
        # yields port 0).
        assert all(sockaddr[1] == 12345 for *_rest, sockaddr in infos)

    def test_getaddrinfo_for_unpinned_host_falls_through_to_real_resolver(self) -> None:
        # A hostname that was never pinned must resolve normally (the patch
        # only intercepts hostnames this process has actually validated).
        infos = socket.getaddrinfo("localhost", 80)
        assert infos
        assert all(sockaddr[1] == 80 for *_rest, sockaddr in infos)

    def test_expired_pin_is_transparently_revalidated_not_silently_trusted_forever(self) -> None:
        pinned_dns.pin_internal_host("localhost")
        # Simulate TTL expiry by rewriting the recorded pin time into the past.
        infos, _pinned_at = pinned_dns._pins["localhost"]
        pinned_dns._pins["localhost"] = (infos, time.monotonic() - pinned_dns._PIN_TTL_S - 1.0)

        # A revalidation must happen (calling the REAL resolver again) -
        # prove it by making the real resolver raise on this specific call
        # and confirming that failure surfaces, rather than the stale pin
        # being served forever.
        def fail_on_revalidate(*_a: object, **_kw: object) -> list:  # type: ignore[type-arg]
            raise OSError("simulated DNS failure on revalidation")

        original = pinned_dns._real_getaddrinfo
        pinned_dns._real_getaddrinfo = fail_on_revalidate
        try:
            with pytest.raises(ValueError, match="DNS resolution failed"):
                socket.getaddrinfo("localhost", 80)
        finally:
            pinned_dns._real_getaddrinfo = original


class TestRequireInternalEndpointPinsAsASideEffect:
    def test_require_internal_endpoint_pins_the_hostname(self) -> None:
        require_internal_endpoint("http://localhost:8080/v1", field_name="test")
        assert "localhost" in pinned_dns._pins

    def test_subsequent_socket_resolution_after_require_internal_endpoint_uses_the_pin(
        self,
    ) -> None:
        require_internal_endpoint("http://localhost:8080/v1", field_name="test")

        def would_fail_if_called(*_a: object, **_kw: object) -> list:  # type: ignore[type-arg]
            raise AssertionError("must not re-resolve live after require_internal_endpoint pinned")

        original = pinned_dns._real_getaddrinfo
        pinned_dns._real_getaddrinfo = would_fail_if_called
        try:
            infos = socket.getaddrinfo("localhost", 9999)
        finally:
            pinned_dns._real_getaddrinfo = original
        assert infos
