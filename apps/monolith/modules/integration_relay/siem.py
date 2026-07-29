"""SIEM integration (coding spec §13 `siem_endpoint` / §16.2 reporting-schedule
destination / SRS FR-INTG-020 "标准 syslog/CEF 输出安全事件") - real, working
CEF-over-syslog UDP emitter implementing `ports.NotificationPort`.

HONEST STATUS (2026-07-06 spec-compliance audit fix): before this file, no
SIEM-output code existed anywhere - two module docstrings mentioned "M6 will
wire real SIEM/marketplace" but M6 only ever wired marketplace. This closes
that specific gap: a real `NotificationPort` implementation, real CEF
formatting (parseable by Splunk/ArcSight/QRadar and any other CEF-compliant
SIEM), tested against a real UDP socket (no external network, no mocking of
the wire format itself).

WIRING STATUS: `apps/monolith/main.py`'s `_build_siem_notifier()` constructs
this when `SKILLSCAN_SIEM_ENDPOINT` is set and stores it on
`ScanRuntime.siem_notifier`; `integration_relay.service.drain_one`/
`drain_pending_outbox` accept it as an optional `notifier` parameter and call
`emit()` for `verdict_issued` rows alongside marketplace writeback. Both this
port and `ScanRuntime.marketplace` spent a long time as "real code, no live
caller"; that is over - `worker.worker_tick` runs `drain_pending_outbox` on
every tick, and `worker.run_due_report_schedules` emits scheduled-report
events through this notifier too.

DESIGN - endpoint shape: `Settings.siem_endpoint` (apps/monolith/config.py)
is validated through the SAME `require_internal_endpoint` every other
endpoint field uses, which requires an http(s)-scheme URL. The actual wire
protocol here is UDP syslog, not HTTP - the URL is used purely as a
validated, familiar `scheme://host:port` carrier (so this field gets the
exact same fail-closed internal-address check as every other endpoint
without needing a second, bespoke validator), not a literal HTTP request
target. `SyslogSiemAdapter` parses host/port out of it and never issues an
HTTP request.

DESIGN - why UDP send failure does NOT raise (unlike almost everything else
in this codebase's fail-closed posture): `NotificationPort.emit` is a
best-effort observability sink, not a security decision. The actual
gate/audit/allowlist pipeline this system exists to protect has ALREADY made
its (correctly fail-closed) decision by the time an event reaches here - a
down or unreachable SIEM must never be able to crash or block that pipeline,
because a failure here can't be verified or corrected by this process (unlike
e.g. `require_internal_endpoint` rejecting a genuinely misconfigured external
address, which prevents a real security bypass). Losing an observability
event to a SIEM outage is a real degradation an operator should notice
(logged at ERROR), but it is a strictly smaller failure than taking down scan
submission because a downstream log sink is unreachable.

DESIGN - event scope: this file handles DISCRETE security events with a real
payload shape - today that's exactly one thing, `gate_outbox`'s
`verdict_issued` rows (see `verdict_issued_event_to_cef`, mapping the exact
payload shape `gate/service.py`'s `decide_and_record` already writes:
`{scan_id, content_hash, verdict, jti, jws}`). `libs/common/observability.py`'s
named Prometheus counters/gauges (worker failures, cross-scope access
attempts, reconciliation ORPHAN hits, etc.) are a DIFFERENT kind of signal -
continuously-accumulating metrics, not discrete events - and are not mapped
to CEF here; a real deployment would typically feed those to a SIEM via
Prometheus remote-write or an Alertmanager webhook evaluating threshold
rules, not a per-increment `emit()` call. `format_cef` below is still general
enough that a future alerting layer could construct a CEF event from a
metric-threshold-crossing if that's ever built, but nothing in this codebase
does that today and this file does not pretend otherwise.
"""

from __future__ import annotations

import socket
from typing import Any
from urllib.parse import urlparse

from common.config import require_internal_endpoint
from common.log import get_logger

_logger = get_logger("skillscan.integration_relay.siem")

# RFC 3164 facility 4 = "security/authorization messages" - the standard
# syslog facility for exactly this kind of event, and what most SIEM CEF
# ingestion guides (Splunk/ArcSight/QRadar) default to for security tooling.
_DEFAULT_SYSLOG_FACILITY = 4


# CEF header fields (`|`-delimited) escape `\` and `|`; extension (space-
# delimited key=value pairs) escapes `\` and `=`. Both also escape embedded
# newlines so one event can never become two lines / corrupt the next event -
# order matters: backslash must be escaped FIRST, or the backslash inserted
# by escaping `|`/`=` would itself get re-escaped.
def _escape_cef_header(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "\\n").replace("\r", "")


def _escape_cef_extension_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "")


def format_cef(
    *,
    device_vendor: str,
    device_product: str,
    device_version: str,
    signature_id: str,
    name: str,
    severity: int,
    extension: dict[str, Any],
) -> str:
    """Real CEF (Common Event Format) - `CEF:Version|Device Vendor|Device
    Product|Device Version|Signature ID|Name|Severity|Extension`, the
    standard ingestion format for Splunk/ArcSight/QRadar and effectively
    every other SIEM. `severity` is CEF's own 0-10 scale (distinct from this
    project's `skillscan_core.Severity` 0-4 scale AND from syslog's PRI
    severity 0-7 - three different "severity" concepts collide in the CEF-
    over-syslog wire format, deliberately kept as three separate parameters/
    functions in this module rather than conflated into one)."""
    if not 0 <= severity <= 10:
        raise ValueError(f"CEF severity must be 0-10, got {severity}")
    header = "|".join(
        _escape_cef_header(str(part))
        for part in (
            "CEF:0",
            device_vendor,
            device_product,
            device_version,
            signature_id,
            name,
            severity,
        )
    )
    extension_str = " ".join(
        f"{key}={_escape_cef_extension_value(str(value))}" for key, value in extension.items()
    )
    return f"{header}|{extension_str}"


# verdict -> (CEF severity 0-10, syslog PRI severity 0-7) - BLOCK is the most
# actionable-for-a-SOC-analyst outcome (highest of both scales); PASS is
# informational only.
_VERDICT_SEVERITY: dict[str, tuple[int, int]] = {
    "BLOCK": (9, 3),  # syslog 3 = Error
    "REVIEW": (5, 5),  # syslog 5 = Notice
    "PASS": (1, 6),  # syslog 6 = Informational
}


def verdict_issued_event_to_cef(
    payload: dict[str, Any],
    *,
    device_vendor: str = "skillscan",
    device_product: str = "gate",
    device_version: str = "1.0",
) -> tuple[str, int]:
    """Maps a real `gate_outbox` `verdict_issued` row's payload (exact shape
    written by `gate.service.decide_and_record`: `{scan_id, content_hash,
    verdict, jti, jws}`) to a CEF string. Returns `(cef_string,
    syslog_pri_severity)` - the caller combines the latter with a facility to
    build the syslog PRI prefix, since PRI is a transport-framing concern
    `format_cef` itself (which only knows about CEF, not syslog) shouldn't
    own. `jws` is deliberately EXCLUDED from the extension - it's a bearer
    credential-shaped signed token, not something that belongs in a log sink
    with (typically) much broader read access than this system's own DB."""
    verdict = str(payload.get("verdict", "")).upper()
    cef_severity, syslog_severity = _VERDICT_SEVERITY.get(verdict, (5, 5))
    cef = format_cef(
        device_vendor=device_vendor,
        device_product=device_product,
        device_version=device_version,
        signature_id="verdict_issued",
        name=f"Skill scan verdict issued: {verdict or 'UNKNOWN'}",
        severity=cef_severity,
        extension={
            k: v for k, v in payload.items() if k in ("scan_id", "content_hash", "verdict", "jti")
        },
    )
    return cef, syslog_severity


class SyslogSiemAdapter:
    """`ports.NotificationPort` implementation - CEF-over-syslog-UDP. See
    module docstring for the endpoint-shape and fail-soft design rationale."""

    def __init__(
        self,
        *,
        endpoint: str,
        facility: int = _DEFAULT_SYSLOG_FACILITY,
        device_vendor: str = "skillscan",
        device_product: str = "gate",
        device_version: str = "1.0",
        timeout_s: float = 2.0,
    ) -> None:
        require_internal_endpoint(endpoint, field_name="siem_endpoint")
        parsed = urlparse(endpoint)
        if parsed.hostname is None or parsed.port is None:
            raise ValueError(f"siem_endpoint must include an explicit host and port: {endpoint!r}")
        if not 0 <= facility <= 23:
            raise ValueError(f"syslog facility must be 0-23, got {facility}")
        self._host = parsed.hostname
        self._port = parsed.port
        self._facility = facility
        self._device_vendor = device_vendor
        self._device_product = device_product
        self._device_version = device_version
        self._timeout_s = timeout_s

    async def emit(self, event: dict[str, Any]) -> None:
        # SECURITY: only verdict_issued has a real, honest CEF mapping today
        # (see module docstring) - any other event_type is dropped with a
        # loud warning rather than silently emitting a made-up/incomplete
        # CEF record, which would be worse than not sending anything (a SIEM
        # rule tuned against a real verdict_issued shape should never have to
        # also handle a fabricated shape from this adapter).
        event_type = event.get("event_type")
        if event_type != "verdict_issued":
            _logger.warning(
                "SyslogSiemAdapter has no CEF mapping for this event_type - dropped",
                extra={"context": {"event_type": event_type}},
            )
            return
        cef, syslog_severity = verdict_issued_event_to_cef(
            event.get("payload", {}),
            device_vendor=self._device_vendor,
            device_product=self._device_product,
            device_version=self._device_version,
        )
        pri = self._facility * 8 + syslog_severity
        message = f"<{pri}>{cef}"
        # SECURITY/DESIGN: intentionally NOT fail-closed - see module
        # docstring. A SIEM outage must never propagate into the caller
        # (which is draining the ALREADY-DECIDED gate_outbox, not making a
        # new security decision).
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self._timeout_s)
                sock.sendto(message.encode("utf-8"), (self._host, self._port))
        except OSError:
            _logger.exception(
                "SIEM UDP send failed - event dropped, scan/gate pipeline unaffected",
                extra={"context": {"siem_host": self._host, "siem_port": self._port}},
            )
