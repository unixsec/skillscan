"""Threat-intel sync (coding spec §11.4 SEC-UPD-010, INV-14): two independent
modes - internal-network sync, OR offline signed IOC package import. Never a
live external feed ("SECURITY: 无外部网络").

SECURITY: this module only ever INSERTs into `threat_indicator` - it never
deletes/replaces existing indicators (a sync failure or partial/malicious feed
should not silently erase prior legitimate coverage). Duplicate
(ioc_type, ioc_value) pairs are silently skipped (idempotent re-sync), backed
by the table's own UNIQUE(ioc_type, ioc_value) constraint (defense in depth,
not just an application-layer INSERT...IGNORE convention).
"""

from __future__ import annotations

import datetime
import json
from collections.abc import Sequence
from typing import Any, cast

import httpx
from common.config import require_internal_endpoint
from common.signing import canonical_claim_bytes, verify_rsa_pss_signature
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from monolith.modules.intel.models import ThreatIndicator
from sqlalchemy import CursorResult, func, select
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.ext.asyncio import AsyncSession

_VALID_IOC_TYPES = frozenset({"domain", "ip", "md5"})


class IntelSyncError(Exception):
    """SECURITY: raised for any malformed/unverifiable/unreachable sync
    input - callers must treat the sync attempt as failed (no partial silent
    apply), not as "zero new indicators found"."""


def _naive_utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


def _validate_iocs(iocs: Sequence[dict[str, str]], *, source: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for entry in iocs:
        ioc_type = entry.get("ioc_type")
        ioc_value = entry.get("ioc_value")
        if ioc_type not in _VALID_IOC_TYPES or not ioc_value:
            raise IntelSyncError(f"invalid IOC entry: {entry!r}")
        rows.append(
            {
                "ioc_type": ioc_type,
                "ioc_value": str(ioc_value).lower(),
                "source": source,
                "imported_at": _naive_utcnow(),
            }
        )
    return rows


async def _apply_rows(session: AsyncSession, rows: list[dict[str, object]]) -> int:
    if not rows:
        return 0
    # SECURITY: INSERT ... ON DUPLICATE KEY UPDATE ioc_type=ioc_type (a no-op
    # update) is this project's idempotent-upsert-that-never-deletes idiom -
    # MySQL-specific because the UNIQUE(ioc_type, ioc_value) constraint is
    # what makes "already known" well-defined; a portable ORM `insert()`
    # would raise IntegrityError on the very re-syncs this is meant to allow.
    stmt = mysql_insert(ThreatIndicator).values(rows)
    stmt = stmt.on_duplicate_key_update(ioc_type=stmt.inserted.ioc_type)
    # NOTE: an INSERT statement's execute() always returns a CursorResult at
    # runtime (unlike the generic Result[Any] a SELECT would return) - cast
    # narrows to what .rowcount actually needs.
    result = cast(CursorResult[Any], await session.execute(stmt))
    await session.flush()
    return int(result.rowcount or 0)


async def sync_from_internal_source(
    http_client: httpx.AsyncClient, *, endpoint_url: str, session: AsyncSession
) -> int:
    """SECURITY (INV-14): `endpoint_url` must resolve to an internal/private
    address - `require_internal_endpoint` fail-closes on any public address or
    DNS failure, exactly like M2's OIDC/SAML/session settings validation."""
    require_internal_endpoint(endpoint_url, field_name="intel_sync.endpoint_url")

    response = await http_client.get(endpoint_url)
    response.raise_for_status()
    try:
        payload = response.json()
    except json.JSONDecodeError as exc:
        raise IntelSyncError(f"intel endpoint returned non-JSON response: {exc}") from exc
    if not isinstance(payload, list):
        raise IntelSyncError("intel endpoint response must be a JSON list of IOC entries")

    rows = _validate_iocs(payload, source=f"internal:{endpoint_url}")
    return await _apply_rows(session, rows)


async def import_offline_package(
    package_bytes: bytes,
    *,
    trusted_public_keys: tuple[RSAPublicKey, ...],
    session: AsyncSession,
    source_label: str = "offline_package",
) -> int:
    """SECURITY (SEC-UPD-010, "离线包验签承重" - offline-package signature
    verification is the load-bearing control here): the package is REJECTED
    outright - zero IOCs applied - unless it verifies against a supplied
    trusted key. There is no "unverifiable but apply anyway" path - unlike a
    scan-time detector, which can surface an unverifiable finding for a
    human/gate to weigh; an offline update package is code-adjacent trust
    material, not a scan
    result, so it fails closed with no partial credit.
    """
    if not trusted_public_keys:
        raise IntelSyncError("no trusted public keys configured - refusing to apply any package")

    try:
        payload = json.loads(package_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntelSyncError(f"offline package is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict) or "iocs" not in payload or "signature" not in payload:
        raise IntelSyncError("offline package missing required 'iocs'/'signature' fields")

    claim = canonical_claim_bytes(payload, exclude_keys=("signature", "signature_alg"))
    if not verify_rsa_pss_signature(
        public_keys=trusted_public_keys, claim_bytes=claim, signature_b64=str(payload["signature"])
    ):
        raise IntelSyncError("offline package signature verification failed - rejecting package")

    iocs = payload["iocs"]
    if not isinstance(iocs, list):
        raise IntelSyncError("offline package 'iocs' must be a list")

    rows = _validate_iocs(iocs, source=source_label)
    return await _apply_rows(session, rows)


__all__ = [
    "IntelSyncError",
    "import_offline_package",
    "summarize_intel_status",
    "sync_from_internal_source",
]


async def summarize_intel_status(session: AsyncSession) -> list[dict[str, object]]:
    """SECURITY (coding spec §9 `GET /v1/admin/intel`): per-source summary
    (count + most recent import) - read-only, no I/O side effects."""
    result = await session.execute(
        select(
            ThreatIndicator.source,
            func.count(ThreatIndicator.id),
            func.max(ThreatIndicator.imported_at),
        ).group_by(ThreatIndicator.source)
    )
    return [
        {"source": source, "indicator_count": count, "last_imported_at": last_imported_at}
        for source, count, last_imported_at in result.all()
    ]
