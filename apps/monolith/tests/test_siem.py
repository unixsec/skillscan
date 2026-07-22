"""Tests for the SIEM CEF-over-syslog integration (coding spec §13/§16.2,
SRS FR-INTG-020) - `apps/monolith/modules/integration_relay/siem.py`."""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass

import pytest

from monolith.modules.integration_relay.siem import (
    SyslogSiemAdapter,
    format_cef,
    verdict_issued_event_to_cef,
)


@dataclass(frozen=True, slots=True)
class _ParsedCef:
    vendor: str
    product: str
    version: str
    signature_id: str
    name: str
    severity: str
    extension: str


def _split_cef_header(cef: str) -> _ParsedCef:
    """Real CEF-aware split - unlike a naive `[^|]*` regex, this respects
    backslash-escaping (a `\\|` is an escaped literal pipe INSIDE a field,
    not a field delimiter) when finding the 7 unescaped `|` delimiters. Only
    unescaped delimiters end a field; a run of `\\`s is only "the pipe is
    escaped" when there's an ODD number of them immediately before it."""
    fields: list[str] = []
    current = []
    backslash_run = 0
    i = 0
    while i < len(cef) and len(fields) < 7:
        ch = cef[i]
        if ch == "\\":
            backslash_run += 1
            current.append(ch)
        elif ch == "|" and backslash_run % 2 == 0:
            fields.append("".join(current))
            current = []
            backslash_run = 0
        else:
            backslash_run = 0
            current.append(ch)
        i += 1
    assert len(fields) == 7, f"expected 7 CEF header delimiters, got {len(fields)}: {cef!r}"
    version_prefix, vendor = fields[0], fields[1]
    assert version_prefix == "CEF:0", f"not a CEF:0 record: {cef!r}"
    return _ParsedCef(
        vendor=vendor,
        product=fields[2],
        version=fields[3],
        signature_id=fields[4],
        name=fields[5],
        severity=fields[6],
        extension=cef[i:],
    )


# Used only by tests that deliberately DON'T contain header delimiters/
# backslashes in any field - a quick sanity check that _split_cef_header and
# a naive split agree on the easy case.
_CEF_RE = re.compile(
    r"^CEF:0\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<version>[^|]*)\|"
    r"(?P<sig>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|(?P<extension>.*)$"
)


class TestFormatCef:
    def test_produces_well_formed_cef_with_all_fields_recoverable(self) -> None:
        cef = format_cef(
            device_vendor="skillscan",
            device_product="gate",
            device_version="1.0",
            signature_id="verdict_issued",
            name="Skill scan verdict issued: BLOCK",
            severity=9,
            extension={"scan_id": "abc-123", "verdict": "BLOCK"},
        )
        match = _CEF_RE.match(cef)
        assert match is not None, f"not valid CEF shape: {cef!r}"
        assert match.group("vendor") == "skillscan"
        assert match.group("product") == "gate"
        assert match.group("sig") == "verdict_issued"
        assert match.group("severity") == "9"
        assert "scan_id=abc-123" in match.group("extension")
        assert "verdict=BLOCK" in match.group("extension")

    def test_rejects_out_of_range_severity(self) -> None:
        with pytest.raises(ValueError, match="0-10"):
            format_cef(
                device_vendor="v",
                device_product="p",
                device_version="1",
                signature_id="s",
                name="n",
                severity=11,
                extension={},
            )

    def test_escapes_pipe_and_backslash_in_header_fields(self) -> None:
        # A malicious/unexpected header field containing CEF's own delimiter
        # must not be able to inject extra fields or corrupt parsing - proven
        # here by ACTUALLY parsing the escaped output back with a real,
        # escape-aware CEF splitter (a naive `[^|]*` regex can't do this: an
        # escaped `\|` still contains a literal `|` character, so it isn't
        # itself a valid round-trip check for exactly the case under test).
        original_name = "evil|name\\with|pipes"
        cef = format_cef(
            device_vendor="skillscan",
            device_product="gate",
            device_version="1.0",
            signature_id="verdict_issued",
            name=original_name,
            severity=5,
            extension={},
        )
        parsed = _split_cef_header(cef)
        # The 7 fields correctly split despite embedded `|`/`\` - and
        # unescaping the recovered field reproduces the original exactly.
        unescaped = parsed.name.replace("\\|", "|").replace("\\\\", "\\")
        assert unescaped == original_name
        assert parsed.vendor == "skillscan"
        assert parsed.signature_id == "verdict_issued"

    def test_escapes_equals_and_backslash_in_extension_values(self) -> None:
        cef = format_cef(
            device_vendor="v",
            device_product="p",
            device_version="1",
            signature_id="s",
            name="n",
            severity=0,
            extension={"note": "a=b\\c"},
        )
        assert "note=a\\=b\\\\c" in cef


class TestVerdictIssuedEventToCef:
    def test_block_maps_to_high_severity(self) -> None:
        cef, syslog_severity = verdict_issued_event_to_cef(
            {"scan_id": "s1", "content_hash": "h1", "verdict": "BLOCK", "jti": "j1"}
        )
        match = _CEF_RE.match(cef)
        assert match is not None
        assert match.group("severity") == "9"
        assert syslog_severity == 3
        assert "verdict=BLOCK" in cef
        assert "scan_id=s1" in cef

    def test_pass_maps_to_low_severity(self) -> None:
        cef, syslog_severity = verdict_issued_event_to_cef(
            {"scan_id": "s2", "content_hash": "h2", "verdict": "PASS", "jti": "j2"}
        )
        match = _CEF_RE.match(cef)
        assert match is not None
        assert match.group("severity") == "1"
        assert syslog_severity == 6

    def test_jws_is_never_included_in_the_extension(self) -> None:
        # SECURITY: jws is a signed-credential-shaped token, not a log field -
        # must never reach a SIEM sink even though it's present in the real
        # gate_outbox payload shape.
        cef, _ = verdict_issued_event_to_cef(
            {
                "scan_id": "s3",
                "content_hash": "h3",
                "verdict": "REVIEW",
                "jti": "j3",
                "jws": "eyJhbGciOiJSUzI1NiJ9.super-secret-signed-token",
            }
        )
        assert "super-secret-signed-token" not in cef
        assert "jws=" not in cef


class TestSyslogSiemAdapterConstruction:
    def test_rejects_non_internal_endpoint(self) -> None:
        with pytest.raises(ValueError, match="internal/private"):
            SyslogSiemAdapter(endpoint="https://8.8.8.8:514/")

    def test_rejects_endpoint_without_explicit_port(self) -> None:
        with pytest.raises(ValueError, match="host and port"):
            SyslogSiemAdapter(endpoint="https://localhost/")

    def test_rejects_invalid_facility(self) -> None:
        with pytest.raises(ValueError, match="facility must be 0-23"):
            SyslogSiemAdapter(endpoint="https://localhost:514/", facility=99)

    def test_accepts_valid_internal_endpoint(self) -> None:
        SyslogSiemAdapter(endpoint="https://localhost:514/")


class TestSyslogSiemAdapterEmit:
    @pytest.mark.asyncio
    async def test_emits_real_udp_datagram_parseable_as_cef(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
            receiver.bind(("127.0.0.1", 0))
            receiver.settimeout(5.0)
            _, port = receiver.getsockname()

            adapter = SyslogSiemAdapter(endpoint=f"https://127.0.0.1:{port}/")
            await adapter.emit(
                {
                    "event_type": "verdict_issued",
                    "payload": {
                        "scan_id": "scan-xyz",
                        "content_hash": "hash-xyz",
                        "verdict": "BLOCK",
                        "jti": "jti-xyz",
                        "jws": "should-never-appear-on-the-wire",
                    },
                }
            )

            data, _addr = receiver.recvfrom(4096)
            message = data.decode("utf-8")

        # <PRI>CEF:0|... - PRI = facility(4)*8 + syslog_severity(3, BLOCK) = 35
        assert message.startswith("<35>CEF:0|")
        cef_body = message.split(">", 1)[1]
        match = _CEF_RE.match(cef_body)
        assert match is not None, f"received datagram is not valid CEF: {message!r}"
        assert "scan_id=scan-xyz" in match.group("extension")
        assert "should-never-appear-on-the-wire" not in message

    @pytest.mark.asyncio
    async def test_unknown_event_type_is_dropped_not_raised(self) -> None:
        adapter = SyslogSiemAdapter(endpoint="https://127.0.0.1:19999/")
        # No listener on this port at all - and an unmapped event_type should
        # be dropped before ever attempting a send. Must not raise either way.
        await adapter.emit({"event_type": "something_unmapped", "payload": {}})

    @pytest.mark.asyncio
    async def test_send_failure_is_caught_and_does_not_raise(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # SECURITY/DESIGN: a SIEM-sink failure must never propagate into the
        # caller (see module docstring) - force a real OSError from sendto
        # deterministically rather than relying on real network flakiness to
        # produce one.
        def _raise_oserror(self: socket.socket, *args: object, **kwargs: object) -> int:
            raise OSError("simulated network failure")

        monkeypatch.setattr(socket.socket, "sendto", _raise_oserror)
        adapter = SyslogSiemAdapter(endpoint="https://127.0.0.1:19999/")
        await adapter.emit(
            {
                "event_type": "verdict_issued",
                "payload": {"scan_id": "s", "content_hash": "h", "verdict": "BLOCK", "jti": "j"},
            }
        )  # must not raise
