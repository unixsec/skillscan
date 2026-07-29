"""DNS-rebinding-resistant resolution for INV-14 internal-only endpoints
(2026-07-10 full-project review, Finding #16).

SECURITY: `config.require_internal_endpoint` validates that a hostname
resolves to an internal/private address at ONE point in time (process
startup, when a Settings class is constructed). The actual HTTP client that
later connects to that hostname (httpx, or whatever library `hvac`/authlib/
python3-saml use under the hood) performs its OWN, independent DNS
resolution at connect time - if an attacker controls that hostname's DNS
with a short TTL, they can present an internal address during validation and
a public, attacker-controlled address during every real connection for the
rest of the process's lifetime (DNS rebinding). `require_internal_endpoint`
closes this by calling `pin_internal_host()` immediately after a hostname
passes validation: this module then intercepts every in-process
`socket.getaddrinfo` call system-wide (which is what httpx, requests,
aiohttp, and the stdlib all eventually call to resolve a hostname,
regardless of which HTTP client library is on top) and, for any pinned
hostname, returns the SAME validated address(es) instead of a fresh, live
DNS answer - re-validated on a short TTL rather than trusted forever, but
never a single unvalidated lookup.

Scope: this covers every in-process Python network call (httpx-based
clients: OIDC/SAML/Vault/Marketplace/session-introspection/intel_sync). It
does NOT cover subprocess-spawned tools (skillspector, aig, osv-scanner),
which perform their own OS-level DNS resolution independent of this
process's `socket` module - those adapters instead re-resolve+re-validate
immediately before each subprocess launch and connect directly to the
resolved IP, narrowing (not eliminating) that separate window. See
`services/engine_runner/adapters/skillspector.py`/`aig.py`.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from collections.abc import Callable
from typing import Any

# What socket.getaddrinfo() actually returns: a list of 5-tuples, the last
# element being either a 2-tuple (IPv4: host, port) or 4-tuple (IPv6: host,
# port, flowinfo, scopeid) - Any keeps this module agnostic to that shape
# rather than modeling both variants explicitly.
_AddrInfo = tuple[Any, Any, Any, Any, tuple[Any, ...]]

# SECURITY: re-validate a pin periodically rather than trusting it for the
# entire process lifetime - bounds how stale a legitimately-changed internal
# address (e.g. a real failover) can get, while still being far tighter than
# an attacker's rebind-and-wait window, which needs to line up with a
# connection attempt to matter at all.
_PIN_TTL_S = 60.0

_lock = threading.Lock()
# hostname -> (getaddrinfo(hostname, None) results, pinned_at monotonic time)
_pins: dict[str, tuple[list[_AddrInfo], float]] = {}

_real_getaddrinfo = socket.getaddrinfo
_installed = False

# Task 13 (2026-07-29): an optional sink for "a hostname this process already
# committed to as internal-only now resolves to a public address" - i.e. a
# live DNS-rebinding attempt, caught at the moment a real connection was
# about to be made. That is the ONE condition in this codebase that is
# literally coding spec §11.7's `external_egress_attempts_total` ("对外出站
# 尝试(须恒为 0,非 0 告警)"): an attempted outbound connection to a
# non-internal address, observed in-process rather than inferred.
#
# A registered callback rather than an import of `SecurityMetrics`: this
# module is a process-wide `socket` monkeypatch with no request, no app and
# no `ScanRuntime` in scope, and it is imported by the engine-runner service
# too, which has no metrics registry at all. A callback keeps the ONE
# SecurityMetrics instance owned by `ScanRuntime` (Task 12) and merely points
# this module at it, instead of creating a second registry here that
# `GET /metrics` would never read - the failure mode that would look exactly
# like working instrumentation.
_ObservedRebinding = Callable[[str], None]
_rebinding_observer: _ObservedRebinding | None = None


def set_rebinding_observer(observer: _ObservedRebinding | None) -> None:
    """Register (or clear, with None) the callback invoked when a pinned host
    fails re-validation. Called once from `main.create_app`. Idempotent and
    last-writer-wins: re-registering replaces, so repeated `create_app()`
    calls in one process (tests) cannot accumulate observers and double-count."""
    global _rebinding_observer
    with _lock:
        _rebinding_observer = observer


def _notify_rebinding(hostname: str) -> None:
    """SECURITY: observing must never be able to break resolving. A raising or
    misbehaving observer is swallowed here - the ValueError that rejects the
    rebound address is raised by the caller regardless, so the SECURITY
    control holds even when its instrumentation does not."""
    with _lock:
        observer = _rebinding_observer
    if observer is None:
        return
    try:
        observer(hostname)
    except Exception:  # noqa: BLE001 - see docstring: the control outranks the metric
        pass


def _validate_and_resolve(hostname: str) -> list[_AddrInfo]:
    try:
        infos = _real_getaddrinfo(hostname, None)
    except OSError as exc:
        raise ValueError(f"cannot pin {hostname!r}: DNS resolution failed") from exc
    if not infos:
        raise ValueError(f"cannot pin {hostname!r}: DNS resolution returned no addresses")
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError as exc:
            raise ValueError(f"cannot pin {hostname!r}: unparseable address {addr!r}") from exc
        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
            raise ValueError(f"cannot pin {hostname!r}: {addr} is not internal/private")
    return list(infos)


def pin_internal_host(hostname: str) -> None:
    """Resolve `hostname` now, require every address to be internal (same
    floor as `config.is_internal_host`), and pin the validated result so
    subsequent in-process DNS lookups for this exact hostname return it
    instead of a fresh, unvalidated answer. Raises ValueError - matching
    `require_internal_endpoint`'s existing contract - if resolution fails or
    any address is public. Call this only immediately after a hostname has
    actually passed validation, never speculatively."""
    infos = _validate_and_resolve(hostname)
    with _lock:
        _pins[hostname] = (infos, time.monotonic())
    _install()


def _reshape_for_port(infos: list[_AddrInfo], port: Any) -> list[_AddrInfo]:
    reshaped: list[_AddrInfo] = []
    for fam, typ, prot, canon, sockaddr in infos:
        new_sockaddr = (sockaddr[0], port, *tuple(sockaddr)[2:])
        reshaped.append((fam, typ, prot, canon, new_sockaddr))
    return reshaped


def _patched_getaddrinfo(
    host: str | bytes | None,
    port: Any,
    family: int = 0,
    type: int = 0,  # noqa: A002 - matches socket.getaddrinfo's real parameter name
    proto: int = 0,
    flags: int = 0,
) -> list[_AddrInfo]:
    if isinstance(host, str):
        with _lock:
            pinned = _pins.get(host)
        if pinned is not None:
            infos, pinned_at = pinned
            if time.monotonic() - pinned_at >= _PIN_TTL_S:
                # SECURITY: pin expired - re-validate+re-pin transparently
                # (never silently fall through to a live, unvalidated lookup
                # for a hostname this process has already committed to
                # treating as internal-only).
                try:
                    infos = _validate_and_resolve(host)
                except ValueError:
                    # Task 13: THE external-egress attempt. This hostname
                    # passed internal-only validation when it was pinned and
                    # now does not - a caller is, right now, trying to open a
                    # connection that would leave the internal network. The
                    # raise below is what actually refuses it; this line is
                    # what makes the refusal countable.
                    #
                    # Note a DNS *outage* also lands here (ValueError covers
                    # "resolution failed"), so this counter is "attempted
                    # egress OR lost the ability to prove it is internal" -
                    # both of which must be zero on a healthy deployment, and
                    # neither of which this process may treat as internal.
                    _notify_rebinding(host)
                    raise
                with _lock:
                    _pins[host] = (infos, time.monotonic())
            return _reshape_for_port(infos, port)
    return list(_real_getaddrinfo(host, port, family, type, proto, flags))


def _install() -> None:
    global _installed
    with _lock:
        if _installed:
            return
        socket.getaddrinfo = _patched_getaddrinfo
        _installed = True


def _reset_for_tests() -> None:
    """Test-only: clear all pins and uninstall the patch, restoring the real
    resolver. Never called from production code."""
    global _installed, _rebinding_observer
    with _lock:
        _pins.clear()
        socket.getaddrinfo = _real_getaddrinfo
        _installed = False
        # Task 13: the observer is module-global too, so a test that registers
        # one and does not clear it would leak into every later test in the
        # same process - including counting into another test's registry.
        _rebinding_observer = None
