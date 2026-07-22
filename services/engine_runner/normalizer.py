"""Hardened archive unpacking (coding spec §11.4 M4, FR-DET catalog Cat-6).

SECURITY: this is the ONE place untrusted, potentially-adversarial archive
bytes get turned into a canonical file set - both at upload time (the API
layer must compute content_hash without itself becoming a decompression-bomb
target) and at worker time (unpacking the stored artifact for engine
analysis). Every limit here defends against a specific, named technique:
- decompression bombs: bounded archive size, bounded per-file size, bounded
  total uncompressed size, bounded compression ratio ("billion laughs"-style
  amplification, coding spec's own term for this class of attack).
- entry-count exhaustion: bounded member count.
- path traversal / NUL / excessive depth: rejected outright.
- symlink/hardlink escape: rejected outright (regular files only).

Any violation raises `UnpackRejected` - callers must treat the WHOLE archive
as unusable (fail-closed), never partially unpack it.

SECURITY (what this module does NOT provide): gVisor sandboxing (coding
spec §11.4: "全程在 gVisor sandbox 内") is a deployment-time concern (K8s
runtimeClassName, M7's IaC) - gVisor is Linux-only and unavailable on this
development machine (macOS), so it cannot be verified here. This module is
safe-by-construction independent of that (bounded memory/CPU, no filesystem
writes, no code execution), but running it inside a real sandbox in
production remains a required, separate defense-in-depth layer - the limits
below are not a substitute for it.
"""

from __future__ import annotations

import tarfile
from io import BytesIO

# SECURITY: all limits are deliberately generous for a legitimate Skill
# package (source + docs + small assets) while still bounding worst-case
# resource use to something a single request should tolerate.
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024  # 50 MiB compressed upload
MAX_SINGLE_FILE_BYTES = 20 * 1024 * 1024  # 20 MiB per file
MAX_TOTAL_UNCOMPRESSED_BYTES = 200 * 1024 * 1024  # 200 MiB decompressed
MAX_ENTRY_COUNT = 5_000
MAX_COMPRESSION_RATIO = 100  # decompressed / compressed - "billion laughs" defense
MAX_PATH_DEPTH = 20


class UnpackRejected(Exception):
    """SECURITY: raised for ANY hardening violation - callers must treat the
    originating archive as unusable (fail-closed), never partially unpack it."""


def _canonicalize_member_path(name: str) -> str:
    # SECURITY: reject NUL, absolute paths, and '..'/empty segments (path
    # traversal) - mirrors skillscan_core.canonical's own path validation so a
    # hardened-unpacked file set is always a valid content_hash() input. The
    # NUL check specifically is defense-in-depth: the tar format itself
    # NUL-terminates member names, so `tarfile` silently truncates at the NUL
    # before this function ever sees one via `unpack_hardened`'s normal path -
    # this guards this function's own contract if it's ever called directly.
    #
    # FP-TUNING (2026-07): a bare '.' segment means "current directory" - a
    # no-op, not traversal. GNU tar routinely prefixes members with './'
    # ('./skill.md'), which previously got the WHOLE archive rejected with
    # "illegal path segment in '.'". Such segments are now DROPPED (canonicalized
    # away) rather than treated as an attack; '..' / absolute / NUL / empty
    # stay hard rejections. The returned name is the cleaned path that gets
    # content-hashed, so canonical.py never sees a '.' segment either.
    if "\x00" in name:
        raise UnpackRejected(f"NUL byte in path: {name!r}")
    if name.startswith("/"):
        raise UnpackRejected(f"absolute path rejected: {name!r}")
    segments = name.split("/")
    if len(segments) > MAX_PATH_DEPTH:
        raise UnpackRejected(f"path depth exceeds max {MAX_PATH_DEPTH}: {name!r}")
    cleaned: list[str] = []
    for segment in segments:
        if segment == ".":
            continue  # current-directory no-op, safe to drop
        if segment in ("", ".."):
            raise UnpackRejected(f"illegal path segment in {name!r}")
        # SECURITY (2026-07-06 spec-compliance audit): mirrors canonical's own
        # backslash-traversal fix - '\' has no separator meaning on this
        # POSIX deployment target, but a member name like '..\..\etc\passwd'
        # must not slip through just because it contains no literal '/'. Only
        # a backslash-delimited sub-piece that is itself '.'/'..'/empty is
        # rejected - a real filename containing a literal backslash character
        # (legal on POSIX) is still allowed.
        for sub_segment in segment.split("\\"):
            if sub_segment in ("", ".", ".."):
                raise UnpackRejected(f"illegal path segment in {name!r}")
        cleaned.append(segment)
    if not cleaned:
        raise UnpackRejected(f"path reduces to nothing after canonicalization: {name!r}")
    return "/".join(cleaned)


def unpack_hardened(archive_bytes: bytes) -> list[tuple[str, int, bytes]]:
    """Returns canonical (path, mode, data) tuples - the same shape
    `skillscan_core.content_hash()` and `orchestration.service.submit_scan`
    already expect, so this is a drop-in replacement for the M3 skeleton's
    unhardened `orchestration.service.unpack_tar_with_modes`.
    """
    compressed_size = len(archive_bytes)
    if compressed_size == 0:
        raise UnpackRejected("empty archive")
    if compressed_size > MAX_ARCHIVE_BYTES:
        raise UnpackRejected(
            f"archive size {compressed_size} exceeds max {MAX_ARCHIVE_BYTES} bytes"
        )

    try:
        tar = tarfile.open(fileobj=BytesIO(archive_bytes), mode="r:*")
    except tarfile.TarError as exc:
        raise UnpackRejected(f"not a valid tar archive: {exc}") from exc

    files: list[tuple[str, int, bytes]] = []
    total_uncompressed = 0
    with tar:
        members = tar.getmembers()
        if len(members) > MAX_ENTRY_COUNT:
            raise UnpackRejected(f"entry count {len(members)} exceeds max {MAX_ENTRY_COUNT}")

        for member in members:
            canonical_name = _canonicalize_member_path(member.name)
            # SECURITY: symlinks/hardlinks are rejected outright rather than
            # followed or filtered - a link target is attacker-controlled and
            # has no legitimate place in a canonical content-hashed file set.
            if member.issym() or member.islnk():
                raise UnpackRejected(f"symlink/hardlink entries are rejected: {member.name!r}")
            if not member.isfile():
                continue  # dirs/devices/fifos: not data, silently skipped

            if member.size > MAX_SINGLE_FILE_BYTES:
                raise UnpackRejected(
                    f"member {member.name!r} declared size {member.size} "
                    f"exceeds max {MAX_SINGLE_FILE_BYTES}"
                )
            extracted = tar.extractfile(member)
            if extracted is None:
                continue

            # SECURITY: cap the ACTUAL bytes read (not just the header's
            # declared size) - a crafted archive's header can claim any size
            # it likes, so the running total below must be based on what was
            # really read, bounding worst-case work regardless of what the
            # header claims.
            data = extracted.read(MAX_SINGLE_FILE_BYTES + 1)
            if len(data) > MAX_SINGLE_FILE_BYTES:
                raise UnpackRejected(f"member {member.name!r} exceeded max size while reading")
            total_uncompressed += len(data)
            if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise UnpackRejected(
                    f"total uncompressed size exceeds max {MAX_TOTAL_UNCOMPRESSED_BYTES}"
                )
            files.append((canonical_name, member.mode & 0o7777, data))

    ratio = total_uncompressed / compressed_size
    if ratio > MAX_COMPRESSION_RATIO:
        raise UnpackRejected(
            f"compression ratio {ratio:.1f} exceeds max {MAX_COMPRESSION_RATIO} "
            "(decompression-bomb defense)"
        )
    if not files:
        raise UnpackRejected("archive contains no regular files")

    # SECURITY/BUG (found live, 2026-07-22, via a real clawhub.ai bulk-import
    # test): reject an archive where one entry's path is ALSO a directory
    # prefix of another entry - e.g. a regular-file entry at "agents" AND
    # another entry at "agents/foo.py". tarfile's own type system doesn't
    # catch this (both are ordinary REGTYPE members - nothing here is a
    # symlink or traversal, so every earlier check passes), and a real-world
    # skill hit exactly this shape (clawhub's zip had a zero-byte,
    # non-slash-terminated "directory marker" entry for "agents" alongside
    # "agents/openai.yaml" - a common zip-tooling quirk this project's own
    # zip->tar test conversion also didn't filter). A caller that later
    # materializes these files to a REAL filesystem (engine_runner.adapters.
    # base.SubprocessEngineAdapter.analyze, extracting into a temp dir for a
    # subprocess-based engine to scan) hits `mkdir()` on a path that already
    # exists as a plain file, which raises even with exist_ok=True -
    # permanently wedging every sandboxed engine for that scan in an endless
    # "leaves unacked for redelivery" retry loop that never succeeds and
    # never explicitly fails either. Since any submitter can construct a tar
    # with this exact structure directly (no zip conversion needed - tar
    # doesn't enforce hierarchical consistency between entries), this is a
    # submitter-triggerable availability gap, not merely a test-harness
    # artifact - reject it upfront, fail-closed, same posture as every other
    # structural check above.
    path_set = frozenset(path for path, _mode, _data in files)
    for path in path_set:
        parts = path.split("/")
        for depth in range(1, len(parts)):
            ancestor = "/".join(parts[:depth])
            if ancestor in path_set:
                raise UnpackRejected(
                    f"path {ancestor!r} is both a file and a directory prefix of {path!r}"
                )

    return files
