"""Publisher provenance + code-signing/commit-pin detector (coding spec §11.4
SUP-06, SRS Cat-7 "来源/签名验证").

Convention: a Skill package MAY include a `PROVENANCE.json` manifest at its
root declaring `publisher`, `commit_sha` (or `content_hash`), and a
`signature` (base64 RSA-PSS/SHA256 signature over the canonical claim bytes,
matching the RSA scheme this project's own JWS signer already uses -
`apps.monolith.modules.gate.signer`). Missing/malformed/unverifiable
provenance is itself the security-relevant signal (SUP-06 exists precisely to
catch Skills with no verifiable publisher attestation).

SECURITY (honest scope note): real trust-anchor distribution (an internal CA,
or a registry of known-publisher public keys) is not built anywhere in this
project yet - that's genuinely M6/M8-adjacent infrastructure (Vault, real
IdP), not something this detector can invent. `trusted_public_keys` is
injected by the caller; with none configured, this detector still checks
manifest presence/structure but cannot cryptographically verify a signature,
and says so explicitly in the finding rather than silently passing.
"""

from __future__ import annotations

import hashlib
import json

from common.signing import canonical_claim_bytes, verify_rsa_pss_signature
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from skillscan_core import (
    DetectionCategory,
    EngineCapability,
    EngineMetadata,
    EngineResult,
    EngineStatus,
    Finding,
    ScanMode,
    Severity,
)

_CATEGORY = DetectionCategory.SUPPLY_CHAIN
_MANIFEST_PATH = "PROVENANCE.json"
_REQUIRED_FIELDS = ("publisher", "signature")


def _metadata() -> EngineMetadata:
    return EngineMetadata(
        name="inhouse-provenance",
        version="1.0.0",
        ruleset_digest=hashlib.sha256(_MANIFEST_PATH.encode()).hexdigest(),
        capabilities=frozenset({EngineCapability.STATIC}),
    )


def _finding(rule_id: str, title: str, severity: Severity, confidence: float) -> Finding:
    return Finding(
        rule_id=rule_id,
        test_item_id="SUP-06",
        category=_CATEGORY,
        title=title,
        severity=severity,
        confidence=confidence,
        source_engine="inhouse-provenance",
        source_capability=EngineCapability.STATIC,
        file_path=_MANIFEST_PATH,
        evidence_redacted=title,
    )


def scan(
    files: dict[str, bytes], *, trusted_public_keys: tuple[RSAPublicKey, ...] = ()
) -> tuple[Finding, ...]:
    manifest_bytes = files.get(_MANIFEST_PATH)
    if manifest_bytes is None:
        # FP-TUNING (2026-07 ecosystem audit): a signed PROVENANCE.json is an
        # aspirational supply-chain control that essentially NO skill in the
        # real public ecosystem ships yet. Treating its mere absence as HIGH
        # forced 100% of real skills into REVIEW (or BLOCK on public-tier),
        # which made the whole verdict signal useless. Absence is still
        # surfaced - but as an informational LOW at full confidence, so it no
        # longer forces a verdict on its own while a PRESENT-but-broken or
        # PRESENT-but-unverifiable manifest (below) stays a stronger signal.
        return (
            _finding(
                "provenance.missing_manifest",
                f"no {_MANIFEST_PATH} publisher provenance attestation found",
                Severity.LOW,
                1.0,
            ),
        )

    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return (
            _finding(
                "provenance.malformed_manifest",
                f"{_MANIFEST_PATH} is not valid JSON",
                Severity.HIGH,
                1.0,
            ),
        )
    if not isinstance(manifest, dict):
        return (
            _finding(
                "provenance.malformed_manifest",
                f"{_MANIFEST_PATH} must be a JSON object",
                Severity.HIGH,
                1.0,
            ),
        )

    missing = [f for f in _REQUIRED_FIELDS if not manifest.get(f)]
    if missing:
        return (
            _finding(
                "provenance.incomplete_manifest",
                f"{_MANIFEST_PATH} missing required field(s): {', '.join(missing)}",
                Severity.MEDIUM,
                0.9,
            ),
        )

    if not trusted_public_keys:
        # SECURITY: honest about the gap - no trust anchor configured, so a
        # structurally valid manifest cannot be cryptographically verified.
        # This is a real, non-silent finding (fail-closed posture), not a pass.
        return (
            _finding(
                "provenance.unverifiable_no_trust_anchor",
                f"{_MANIFEST_PATH} present but no trusted publisher key configured to verify it",
                Severity.MEDIUM,
                0.6,
            ),
        )

    claim = canonical_claim_bytes(manifest, exclude_keys=("signature", "signature_alg"))
    verified = verify_rsa_pss_signature(
        public_keys=trusted_public_keys,
        claim_bytes=claim,
        signature_b64=str(manifest["signature"]),
    )
    if verified:
        return ()  # SECURITY: verified against a trusted key - no finding.

    return (
        _finding(
            "provenance.signature_verification_failed",
            f"{_MANIFEST_PATH} signature does not verify against any trusted publisher key",
            Severity.CRITICAL,
            1.0,
        ),
    )


class ProvenanceDetector:
    """`DetectionEngine` Protocol implementation (skillscan_core.DetectionEngine).
    `trusted_public_keys` is injected at construction - see module docstring on
    why this project has no built-in trust-anchor source yet."""

    def __init__(self, *, trusted_public_keys: tuple[RSAPublicKey, ...] = ()) -> None:
        self._trusted_public_keys = trusted_public_keys

    @property
    def metadata(self) -> EngineMetadata:
        return _metadata()

    def analyze(self, files: dict[str, bytes], *, deadline: float | None = None) -> EngineResult:
        return EngineResult(
            engine=self.metadata,
            findings=scan(files, trusted_public_keys=self._trusted_public_keys),
            status=EngineStatus.OK,
            scan_mode=ScanMode.STATIC,
            llm_used=False,
        )
