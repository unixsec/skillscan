"""Per-engine timing on the results-stream wire format (milestone C Task 7).

Pure: no Redis, no MySQL, no blob store. `produce_result` is exercised against a
recording double that captures the exact field map it hands to `XADD`, and the
consumer side is exercised against the exact `(message_id, fields)` shapes
redis-py hands back - both `bytes` (real Redis) and `str` (decode_responses=True
clients), because `_decode_fields` is what makes those interchangeable and a
regression there would only show up on one of the two.

WHY THIS FILE EXISTS. `ResultMessage` / `produce_result` are the wire between
two INDEPENDENTLY DEPLOYED images (the monolith and services/engine_runner), so
every rollout has a window where one side writes a field the other has never
heard of. The compatibility decision recorded here is: **both directions
degrade, neither requires simultaneous deployment**, and the specific failure
being guarded against is not a crash - it is a plausible-looking `0`.

  old producer -> new consumer   no `analyze_duration_ms` field on the entry.
                                 Must parse to None. A `.get(k, 0)` here would
                                 record "every engine on the not-yet-upgraded
                                 image finished in 0ms", quietly corrupting the
                                 one dataset this task exists to create.
  new producer -> old consumer   a Redis Stream entry is a flat field map and
                                 the pre-Task-7 parse read four keys by name,
                                 so the extra field is ignored. Reproduced here
                                 by parsing with a frozen copy of the old code
                                 rather than by asserting that it would be.

The blob half of the same question lives in
`apps/monolith/tests/test_findings_schema.py` (also infra-free).
"""

from __future__ import annotations

from typing import Any, cast

import pytest
import redis.asyncio as aioredis
from common import airlock


class _RecordingRedis:
    """Captures what `produce_result` would XADD. Only `xadd` is reachable from
    the function under test, so a full fake would be dead weight."""

    def __init__(self) -> None:
        self.entries: list[tuple[str, dict[Any, Any]]] = []

    async def xadd(self, stream: str, fields: dict[Any, Any]) -> bytes:
        self.entries.append((stream, dict(fields)))
        return b"1700000000000-0"


def _as_redis(double: _RecordingRedis) -> aioredis.Redis:
    return cast(aioredis.Redis, double)


def _entry(fields: dict[str, str], *, message_id: str = "1-0", raw: bool = True) -> Any:
    """One redis-py stream entry. `raw=True` mimics a default client (bytes),
    `raw=False` a `decode_responses=True` one (str)."""
    if raw:
        return (
            message_id.encode(),
            {k.encode(): v.encode() for k, v in fields.items()},
        )
    return (message_id, dict(fields))


_OLD_FORMAT_FIELDS = {
    "scan_id": "scan-1",
    "findings_key": "findings/scan-1/bandit.json",
    "engine": "bandit",
    "status": "ok",
}


class TestProducerWritesTheField:
    async def test_duration_is_written_as_a_decimal_string(self) -> None:
        double = _RecordingRedis()
        await airlock.produce_result(
            _as_redis(double),
            scan_id="scan-1",
            findings_key="findings/scan-1/bandit.json",
            engine="bandit",
            status="ok",
            analyze_duration_ms=4321,
        )
        _stream, fields = double.entries[0]
        assert fields[airlock.ANALYZE_DURATION_MS_FIELD] == "4321"

    async def test_zero_is_written_because_zero_is_a_real_measurement(self) -> None:
        # A byte-matching floor engine really can finish inside a millisecond.
        # 0 must survive to the wire; only None is allowed to mean "absent".
        double = _RecordingRedis()
        await airlock.produce_result(
            _as_redis(double),
            scan_id="scan-1",
            findings_key="k",
            engine="static-keyword",
            status="ok",
            analyze_duration_ms=0,
        )
        _stream, fields = double.entries[0]
        assert fields[airlock.ANALYZE_DURATION_MS_FIELD] == "0"

    async def test_marker_messages_stay_byte_identical_to_the_old_format(self) -> None:
        # The poison-pill / unpack-rejected / unrunnable markers pass no
        # duration: no engine ran. Their entry must not grow an empty-string
        # field, which a pre-Task-7 consumer would have had no rule for.
        double = _RecordingRedis()
        await airlock.produce_result(
            _as_redis(double),
            scan_id="scan-1",
            findings_key="",
            engine="__poison_pill__",
            status="poison_pill",
        )
        _stream, fields = double.entries[0]
        assert fields == {
            "scan_id": "scan-1",
            "findings_key": "",
            "engine": "__poison_pill__",
            "status": "poison_pill",
        }


class TestOldFormatMessageReadByNewConsumer:
    """THE MUTATION-VERIFIED PATH: an entry produced by a pre-Task-7 image."""

    @pytest.mark.parametrize("raw", [True, False])
    def test_absent_duration_parses_to_none_not_zero(self, raw: bool) -> None:
        [message] = airlock._parse_results([_entry(_OLD_FORMAT_FIELDS, raw=raw)])
        # `is None`, not `== None` and not falsiness: 0 is falsy and 0 == False,
        # so a weaker assertion would pass against the very default this test
        # exists to forbid.
        assert message.analyze_duration_ms is None
        assert message.analyze_duration_ms != 0

    def test_every_load_bearing_field_still_parses(self) -> None:
        [message] = airlock._parse_results([_entry(_OLD_FORMAT_FIELDS)])
        assert (message.scan_id, message.engine, message.status) == ("scan-1", "bandit", "ok")
        assert message.findings_key == "findings/scan-1/bandit.json"
        assert message.message_id == "1-0"

    def test_a_missing_load_bearing_field_still_raises(self) -> None:
        # The asymmetry is deliberate and must not erode into "everything is
        # optional": a message with no scan_id cannot be acted on at all.
        missing = {k: v for k, v in _OLD_FORMAT_FIELDS.items() if k != "scan_id"}
        with pytest.raises(KeyError):
            airlock._parse_results([_entry(missing)])


class TestNewFormatMessageReadByOldConsumer:
    def test_the_pre_task_7_parse_ignores_the_added_field(self) -> None:
        # A frozen copy of the consumer as it stood before this task - four
        # keys read by name off the decoded map. Reproducing it is the point:
        # asserting "extra fields are ignored" against the CURRENT code would
        # prove nothing about the image still running in the other pod.
        fields = dict(_OLD_FORMAT_FIELDS) | {airlock.ANALYZE_DURATION_MS_FIELD: "873"}
        message_id, raw_fields = _entry(fields)
        decoded = airlock._decode_fields(raw_fields)
        old_shape = (
            airlock._decode(message_id),
            decoded["scan_id"],
            decoded["findings_key"],
            decoded["engine"],
            decoded["status"],
        )
        assert old_shape == ("1-0", "scan-1", "findings/scan-1/bandit.json", "bandit", "ok")


class TestNewFormatMessageReadByNewConsumer:
    @pytest.mark.parametrize("raw", [True, False])
    def test_duration_round_trips(self, raw: bool) -> None:
        fields = dict(_OLD_FORMAT_FIELDS) | {airlock.ANALYZE_DURATION_MS_FIELD: "873"}
        [message] = airlock._parse_results([_entry(fields, raw=raw)])
        assert message.analyze_duration_ms == 873

    def test_zero_survives_the_round_trip_distinct_from_absent(self) -> None:
        fields = dict(_OLD_FORMAT_FIELDS) | {airlock.ANALYZE_DURATION_MS_FIELD: "0"}
        [message] = airlock._parse_results([_entry(fields)])
        assert message.analyze_duration_ms == 0


class TestMalformedDurationDegradesInsteadOfStallingTheStream:
    """A corrupt telemetry field must not abort the parse of the whole batch -
    that would strand every OTHER scan in the same XREADGROUP, i.e. trade a
    fleet-wide fail-stuck for a number nobody scores on."""

    @pytest.mark.parametrize("bad", ["", "not-a-number", "12.5", "-1", "9e9"])
    def test_unusable_value_reads_as_none(self, bad: str) -> None:
        fields = dict(_OLD_FORMAT_FIELDS) | {airlock.ANALYZE_DURATION_MS_FIELD: bad}
        [message] = airlock._parse_results([_entry(fields)])
        assert message.analyze_duration_ms is None

    def test_one_corrupt_entry_does_not_drop_its_neighbours(self) -> None:
        good = dict(_OLD_FORMAT_FIELDS) | {airlock.ANALYZE_DURATION_MS_FIELD: "5"}
        bad = dict(_OLD_FORMAT_FIELDS) | {airlock.ANALYZE_DURATION_MS_FIELD: "??"}
        messages = airlock._parse_results(
            [_entry(good, message_id="1-0"), _entry(bad, message_id="1-1")]
        )
        assert [m.analyze_duration_ms for m in messages] == [5, None]


class TestDurationClock:
    def test_elapsed_ms_measures_forward_and_never_returns_negative(self) -> None:
        started = airlock.monotonic_now()
        assert airlock.elapsed_ms(started) >= 0
        # A reading from the future (only reachable via a bug or a doctored
        # start value) floors at 0 rather than emitting a negative that the
        # wire parser would then reject as corrupt.
        assert airlock.elapsed_ms(airlock.monotonic_now() + 10.0) == 0

    def test_monotonic_now_is_not_the_epoch_clock(self) -> None:
        # Guards the swap that adapters/base.py's post-mortem describes: if
        # this ever returned time.time(), durations would still look sane while
        # any deadline arithmetic built on it would be off by decades.
        assert airlock.monotonic_now() < airlock.now_epoch() / 2
