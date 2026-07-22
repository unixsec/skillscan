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
                infos = _validate_and_resolve(host)
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
    global _installed
    with _lock:
        _pins.clear()
        socket.getaddrinfo = _real_getaddrinfo
        _installed = False
