"""Marketplace reconciliation (coding spec §11.6, SAD §4.3, INV-13).

SECURITY: this is the compensating control for "complete arbitration" living
outside this system's trust boundary (SAD: "完整仲裁执行点在市场,信任边界外") -
the marketplace is the sole authority on what's actually published, and if
IT fails to verify a JWS (or is bypassed entirely), the gate can be
circumvented without this system ever knowing. `poll` independently
enumerates the marketplace's FULL published set and compares it against our
own issued-verdict ledger - this is what can actually detect an ORPHAN
(published with no verdict at all = the whole point of the gate defeated).
`push` is a low-latency accelerator only: structurally, a push event stream
can never prove the ABSENCE of an unauthorized publish, only report on
publishes the marketplace chose to announce - so push is only ever
meaningful on top of poll, never a substitute for it (SAD §4.3).

Pure comparison logic only - no DB/network I/O. Whoever orchestrates a
reconciliation pass (reeval.service) fetches `published` from
`MarketplacePort.list_published()` and `issued_verdicts` from
`gate.service.list_issued_verdicts` (using GATE's own session/credentials -
svc_reeval has no grant on `verdict`), then calls `reconcile()` here.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from monolith.modules.gate.service import IssuedVerdict

_PASS_VERDICT = "PASS"


class ReconciliationResult(StrEnum):
    MATCH = "MATCH"
    ORPHAN = "ORPHAN"  # published with no verdict at all - the gate was bypassed
    MISMATCH = "MISMATCH"  # published but our verdict was not PASS


class ReconciliationSource(StrEnum):
    POLL = "poll"  # our own authenticated, independent read - high confidence
    PUSH = "push"  # marketplace-originated event - forgeable/replayable, low confidence


@dataclass(frozen=True, slots=True)
class MarketplacePublishedEntry:
    """One row of `MarketplacePort.list_published()` - a Skill version the
    marketplace currently considers published."""

    content_hash: str
    skill_id: str


@dataclass(frozen=True, slots=True)
class ReconciliationOutcome:
    content_hash: str
    skill_id: str
    result: ReconciliationResult
    source: ReconciliationSource


def reconcile(
    published: Sequence[MarketplacePublishedEntry],
    issued_verdicts: Sequence[IssuedVerdict],
    *,
    source: ReconciliationSource,
) -> tuple[ReconciliationOutcome, ...]:
    verdict_by_hash = {v.content_hash: v.verdict for v in issued_verdicts}
    outcomes: list[ReconciliationOutcome] = []
    for entry in published:
        verdict = verdict_by_hash.get(entry.content_hash)
        if verdict is None:
            result = ReconciliationResult.ORPHAN
        elif verdict != _PASS_VERDICT:
            result = ReconciliationResult.MISMATCH
        else:
            result = ReconciliationResult.MATCH
        outcomes.append(
            ReconciliationOutcome(
                content_hash=entry.content_hash,
                skill_id=entry.skill_id,
                result=result,
                source=source,
            )
        )
    return tuple(outcomes)


def reconciliation_mode_warnings(*, poll_enabled: bool, push_enabled: bool) -> tuple[str, ...]:
    """coding spec §13 startup self-check: "reconciliation.poll=off → 启动告警
    + reconciliation_inactive 指标" and "配置矩阵 fail-fast(off/off→启动告警+
    降级指标;off/on→降覆盖告警)". Returns human-readable warning strings for the
    caller to log/alert on at startup - never raises, since a degraded
    reconciliation posture is a monitored, fail-visible condition, not a
    reason to refuse to start (unlike GatePolicy.fail_closed_verdict==PASS,
    which coding spec §13 DOES treat as a hard startup failure)."""
    if not poll_enabled and not push_enabled:
        return (
            "reconciliation fully disabled (poll=off, push=off): marketplace bypass "
            "(ORPHAN) cannot be detected at all - reconciliation_inactive metric should "
            "be raised",
        )
    if not poll_enabled and push_enabled:
        return (
            "reconciliation.poll=off with push=on: push-only coverage cannot detect "
            "ORPHAN (structurally requires an independent full-set scan) - this is a "
            "reduced-coverage mode, not a substitute for poll",
        )
    return ()


class PushEventVerificationError(ValueError):
    pass


def verify_push_event_signature(
    *,
    body: bytes,
    signature_header: str,
    timestamp: int,
    hmac_secret: str,
    replay_window_s: int,
    now: float,
) -> None:
    """SECURITY (SAD §4.3/TB14: "强认证(mTLS 或签名事件)+ 防重放"): implements
    the "signed event" half of that strong-auth requirement - mTLS is a
    network/ingress-layer control (M7's boundary, not this Python layer's).
    Raises `PushEventVerificationError` on ANY failure - wrong signature,
    or a timestamp outside the replay window - never silently accepts a
    push event as authentic.

    `signature_header` must equal `hex(HMAC-SHA256(hmac_secret,
    f"{timestamp}.".encode() + body))` - the timestamp is bound INTO the
    signed material (not merely checked separately) specifically so an
    attacker who captured one valid (timestamp, signature, body) tuple can't
    replay the same signature against a freshly-claimed, unsigned timestamp
    to slide the replay window forward.
    """
    if abs(now - timestamp) > replay_window_s:
        raise PushEventVerificationError(
            f"push event timestamp {timestamp} is outside the {replay_window_s}s replay window"
        )
    expected = hmac.new(
        hmac_secret.encode("utf-8"), f"{timestamp}.".encode("ascii") + body, hashlib.sha256
    ).hexdigest()
    # SECURITY: constant-time comparison - a timing side-channel here would let
    # an attacker recover the correct signature byte-by-byte.
    if not hmac.compare_digest(expected, signature_header):
        raise PushEventVerificationError("push event signature verification failed")
