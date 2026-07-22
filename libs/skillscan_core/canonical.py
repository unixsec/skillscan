"""Content-addressed hashing (coding spec M1, §5.2 — INV-6/INV-7).

Pure stdlib, zero runtime dependencies.
"""

from __future__ import annotations

import hashlib
import struct
import unicodedata
from collections.abc import Iterable

from skillscan_core.models import EngineMetadata

_CONTENT_HASH_DOMAIN = b"skillscan.content_hash.v1\n"
_TOOLCHAIN_DIGEST_DOMAIN = b"skillscan.toolchain_digest.v1\n"
_CACHE_KEY_DOMAIN = b"skillscan.cache_key.v1\n"


def _encode_chunk(data: bytes) -> bytes:
    # SECURITY: length-prefix (big-endian, 8 bytes) so concatenating chunks is unambiguous.
    return struct.pack(">Q", len(data)) + data


def _validate_and_normalize_path(path: str) -> str:
    # SECURITY: reject NUL, absolute paths, drive letters, and '.'/'..'/empty segments -
    # these are exactly the shapes used for path-traversal/confusion attacks.
    if "\x00" in path:
        raise ValueError(f"content_hash: NUL byte in path {path!r}")
    normalized = unicodedata.normalize("NFC", path)
    if normalized.startswith("/"):
        raise ValueError(f"content_hash: absolute path rejected: {path!r}")
    if len(normalized) >= 2 and normalized[1] == ":":
        raise ValueError(f"content_hash: drive-letter path rejected: {path!r}")
    for segment in normalized.split("/"):
        if segment in ("", ".", ".."):
            raise ValueError(f"content_hash: illegal path segment in {path!r}")
        # SECURITY (INV-6, 2026-07-06 spec-compliance audit): the deployment
        # target is POSIX, where '\' is an ordinary filename character with no
        # separator meaning to the OS - but code elsewhere (archive extraction,
        # zip/tar members, engine adapters) may still treat it as one, so a
        # segment like '..\..\etc\passwd' must not slip through just because
        # it contains no literal '/'. Only reject a backslash-delimited
        # sub-piece that is itself '.'/'..'/empty - a real filename that
        # merely contains a literal backslash character (legal on POSIX) is
        # still allowed.
        for sub_segment in segment.split("\\"):
            if sub_segment in ("", ".", ".."):
                raise ValueError(f"content_hash: illegal path segment in {path!r}")
    return normalized


def content_hash(files: Iterable[tuple[str, int, bytes]]) -> str:
    entries = list(files)
    if not entries:
        raise ValueError("content_hash: empty file set rejected (refuses to authenticate nothing)")

    seen_paths: set[str] = set()
    normalized_entries: list[tuple[str, int, bytes]] = []
    for path, mode, data in entries:
        normalized_path = _validate_and_normalize_path(path)
        # SECURITY: reject duplicate paths post-NFC-normalization (homoglyph/normalization
        # collisions must not silently overwrite one entry with another).
        if normalized_path in seen_paths:
            raise ValueError(
                f"content_hash: duplicate path after NFC normalization: {normalized_path!r}"
            )
        seen_paths.add(normalized_path)
        normalized_entries.append((normalized_path, mode & 0o7777, data))

    # Order-independent: sort by normalized path before hashing.
    normalized_entries.sort(key=lambda entry: entry[0])

    hasher = hashlib.sha256()
    hasher.update(_CONTENT_HASH_DOMAIN)
    for path, mode, data in normalized_entries:
        hasher.update(_encode_chunk(path.encode("utf-8")))
        hasher.update(struct.pack(">I", mode))
        # SECURITY: hash raw bytes verbatim - no decoding/re-encoding that could drop
        # security-relevant bytes.
        hasher.update(_encode_chunk(data))
    return hasher.hexdigest()


def toolchain_digest(
    engine_metadatas: Iterable[EngineMetadata],
    policy_version: str,
    prompt_version: str = "none",
) -> str:
    # SECURITY: bind sorted engine identities + policy + prompt version, so any upgrade
    # to any of them changes the digest and invalidates stale cached verdicts.
    identities = sorted(f"{m.name}@{m.version}#{m.ruleset_digest}" for m in engine_metadatas)

    hasher = hashlib.sha256()
    hasher.update(_TOOLCHAIN_DIGEST_DOMAIN)
    for identity in identities:
        hasher.update(_encode_chunk(identity.encode("utf-8")))
    hasher.update(_encode_chunk(policy_version.encode("utf-8")))
    hasher.update(_encode_chunk(prompt_version.encode("utf-8")))
    return hasher.hexdigest()


def cache_key(content_hash_value: str, toolchain_digest_value: str) -> str:
    hasher = hashlib.sha256()
    hasher.update(_CACHE_KEY_DOMAIN)
    hasher.update(_encode_chunk(f"{content_hash_value}::{toolchain_digest_value}".encode()))
    return hasher.hexdigest()
