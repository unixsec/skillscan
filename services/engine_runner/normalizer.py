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

`unpack_hardened` accepts TAR ONLY. Zip uploads (both marketplaces ship zip)
are handled by the bounded transcode layer at the bottom of this module, which
sits in FRONT of `unpack_hardened` rather than inside it - see the long comment
above `ZIP_MAGIC_PREFIXES` for why that boundary is where it is.
`unpack_package_archive` is the entrypoint both submission doors call.

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

import stat
import struct
import tarfile
import time
import zipfile
import zlib
from collections import Counter
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
    # SECURITY (2026-07-30, added with the zip ingest path below): two entries
    # that canonicalize to the SAME path are rejected outright. Both containers
    # allow it - tar because it has no index at all (append twice, last one
    # wins on extraction), zip because two central-directory records may carry
    # the same name - and `_canonicalize_member_path` creates a third way in
    # ('./a.py' and 'a.py' are distinct member names and one canonical path).
    #
    # Why it is a defect and not a curiosity: the (path, mode, data) list this
    # function returns is consumed TWO ways. The in-process detectors iterate
    # the list and see BOTH copies; `engine_runner.adapters.base` materializes
    # it to a real filesystem for the subprocess engines, where the second
    # write overwrites the first and only the LAST copy exists. So "what was
    # scanned" and "what a sandboxed engine actually reads" diverge, while
    # `content_hash()` covers both copies and therefore describes neither file
    # set exactly. That is the same class of gap as the file/directory-prefix
    # collision below, and duplicate names have no legitimate meaning in a
    # Skill package.
    #
    # DELIBERATELY IN THE SHARED PATH, not in the zip transcoder: this is the
    # only place canonical paths exist (a zip-side name check would miss the
    # './a.py' + 'a.py' pair entirely), and a check that fired for zip uploads
    # but not tar uploads would be an undocumented asymmetry between two doors
    # into the same pipeline - worse than either answer chosen on purpose.
    paths = [path for path, _mode, _data in files]
    duplicated = sorted(name for name, count in Counter(paths).items() if count > 1)
    if duplicated:
        raise UnpackRejected(f"duplicate entry paths after canonicalization: {duplicated}")

    path_set = frozenset(paths)
    for path in path_set:
        parts = path.split("/")
        for depth in range(1, len(parts)):
            ancestor = "/".join(parts[:depth])
            if ancestor in path_set:
                raise UnpackRejected(
                    f"path {ancestor!r} is both a file and a directory prefix of {path!r}"
                )

    return files


# ---------------------------------------------------------------------------
# zip ingest (2026-07-30)
#
# WHY A TRANSCODER IN FRONT OF `unpack_hardened` RATHER THAN A ZIP BRANCH INSIDE
# IT. Both marketplaces this system integrates with ship zip - clawhub.ai and
# its China mirror skillhub.cloud.tencent.com (same `/api/v1/download?slug=`
# idiom, `api.skillhub.cn`) - so zip is the ecosystem's format, not one vendor's
# quirk, and the 2026-07-22 decision to stay tar-only (docs/stories/BACKLOG.md)
# rested on the premise that it was the latter.
#
# The safety argument for this shape is statable: a bug in this transcoder can
# only produce a STRANGE TAR, and that tar then faces every one of
# `unpack_hardened`'s checks unchanged - archive size, entry count, path depth,
# NUL/absolute/'..' (including backslash variants), symlink/hardlink refusal,
# per-file size, measured-vs-declared bytes, total uncompressed size,
# compression ratio, duplicate paths, file-that-is-also-a-directory-prefix. A
# zip branch INSIDE that parser could instead bypass one of them. The other half
# of the guarantee is already established by `orchestration.service._pack_tar`:
# packing an already-validated tuple list is not security-sensitive, "hardening
# lives entirely on the UNPACK side" - so the worker and the sandbox only ever
# see the canonical re-packed tar. No zip byte ever reaches an engine.
#
# WHAT THIS LAYER MUST DO THAT `unpack_hardened` CANNOT DO FOR IT: stop a
# decompression bomb DURING transcode. By the time a tar exists the bomb has
# already been expanded in memory, so every resource bound below is enforced
# here, at the same values the tar path uses (the same module constants, not
# copies).
#
# MEASURED BEHAVIOUR OF CPython's `zipfile` (verified on 3.14, 2026-07-30):
#   ZIP64            transparently SUPPORTED - `ZipFile` reads the ZIP64
#                    end-of-central-directory record and the per-entry ZIP64
#                    extra fields with no flag. Safe here because a ZIP64
#                    `file_size` is just a bigger number to bound, and the
#                    bounds below are enforced against the bytes actually read
#                    as well as against the declaration.
#   multi-disk       NOT refused by `zipfile` at all: it ignores the EOCD's
#   / spanned        disk-number fields (an archive doctored to say "disk 1 of
#                    3" parses and reads fine), and a real split archive's
#                    first segment simply fails somewhere later with
#                    `BadZipFile`/`ValueError`/`zlib.error`. Undefined
#                    behaviour is exactly what this layer must not have, so it
#                    is REFUSED explicitly below by reading those fields
#                    ourselves.
#   corrupt member   raises `zlib.error` (not `BadZipFile`) straight out of
#                    `read()`; a size field that lies raises `BadZipFile`
#                    ("Bad CRC-32") once the declared length is consumed; an
#                    unsupported/AES compression method raises
#                    `NotImplementedError`; a truncated local header raises a
#                    bare `ValueError`; an encrypted entry raises
#                    `RuntimeError`. All of those must become a clean 400, so
#                    `_ZIP_PARSE_ERRORS` catches them and re-raises
#                    `UnpackRejected`.
# ---------------------------------------------------------------------------

# The three zip-family signatures, per APPNOTE: a local file header (an ordinary
# archive), a bare end-of-central-directory record (an archive with no entries),
# and the spanning marker. Ingest dispatches on these MAGIC BYTES, never on a
# filename extension - the extension is caller-supplied metadata that has no
# bearing on what the bytes are.
ZIP_MAGIC_PREFIXES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")

_EOCD_SIGNATURE = b"PK\x05\x06"
_EOCD_SIZE = 22

# Every exception type CPython's `zipfile`/`zlib` can raise out of a malformed
# or hostile archive (each one measured, see the module comment above). Mapped
# to `UnpackRejected` so a bad upload is a 400 describing the caller's own
# bytes, never a 500.
_ZIP_PARSE_ERRORS = (
    zipfile.BadZipFile,
    zipfile.LargeZipFile,
    zlib.error,
    NotImplementedError,
    ValueError,
    EOFError,
    RuntimeError,
    struct.error,
    OSError,
)


def _read_zip_end_record(zip_bytes: bytes) -> tuple[int, int, int]:
    """Returns (this_disk, disk_with_central_directory, declared_entry_count)
    from the end-of-central-directory record, WITHOUT constructing a
    `zipfile.ZipFile` first.

    SECURITY: reading the entry count here is the only bound that lands before
    `ZipFile.__init__` parses the whole central directory into one `ZipInfo`
    object per entry - a 50 MiB archive can declare ~1.1M entries in 46 bytes
    each, so the authoritative `len(infolist())` check happens after that
    allocation has already been made. The declared count can lie (or be the
    0xFFFF ZIP64 placeholder); it is only ever used to refuse early, never to
    trust, and the measured check still runs afterwards.
    """
    index = zip_bytes.rfind(_EOCD_SIGNATURE)
    if index < 0 or len(zip_bytes) - index < _EOCD_SIZE:
        raise UnpackRejected("not a valid zip archive: no end-of-central-directory record")
    this_disk, cd_disk, _entries_here, total_entries = struct.unpack_from(
        "<HHHH", zip_bytes, index + 4
    )
    return this_disk, cd_disk, total_entries


def zip_to_tar_bytes(zip_bytes: bytes) -> bytes:
    """Transcode a zip archive into an uncompressed POSIX tar, bounded.

    Pure bytes-in/bytes-out with no marketplace coupling; the returned tar is
    meant to be handed straight to `unpack_hardened`, which stays the validator
    of paths, modes and structure.

    NON-REGULAR MEMBERS ARE REJECTED, NOT DROPPED - the identical policy
    `unpack_hardened` applies to a tar, so an upload faces one policy rather
    than two. (Directory entries are the exception, and are not an exception to
    the *file set*: a directory carries no content, `info.is_dir()` already
    skips the trailing-slash form, and skipping the S_IFDIR-with-no-slash form
    beside it keeps those two spellings of the same thing equivalent.)

    MEASURED 2026-07-30, and the reason this is a rejection rather than the
    drop it was for one day: across 364 real packages from both marketplaces
    (clawhub 200 + skillhub 124 + 40 others) there are ZERO non-regular zip
    members, and `symlinks_skipped_by_slug` is empty in every recorded import
    run. The earlier "dropping keeps real packages scannable" argument cited
    `scripts/import_clawhub_corpus.py`'s `symlinks_skipped` field as evidence
    that real packages carry symlinks; that field has never been non-empty.
    With the availability cost measured at zero, dropping bought nothing and
    cost the property that matters here: a dropped member makes the scanned
    file set differ from the submitted archive, silently, so a package
    containing `link -> /etc/passwd` earned a clean PASS with nothing anywhere
    recording that it had tried. A rejection is loud, submitter-fixable, and
    identical to what a tar carrying the same member already got.

    RAISES `UnpackRejected` for every bound violation and for every malformed
    archive - never a bare `zipfile`/`zlib` exception, so both ingest doors can
    keep their single "invalid package archive: ..." 400.
    """
    compressed_size = len(zip_bytes)
    if compressed_size == 0:
        raise UnpackRejected("empty archive")
    # SECURITY: the same 50 MiB ceiling the tar path applies to an upload, and
    # it has to be applied HERE: `unpack_hardened` will only ever see the
    # transcoded tar, whose size says nothing about the zip that produced it.
    if compressed_size > MAX_ARCHIVE_BYTES:
        raise UnpackRejected(
            f"archive size {compressed_size} exceeds max {MAX_ARCHIVE_BYTES} bytes"
        )

    this_disk, cd_disk, declared_entries = _read_zip_end_record(zip_bytes)
    # SECURITY: explicit refusal, because `zipfile` has no opinion here (see the
    # module comment). A segment of a split archive does not contain the members
    # its central directory describes, so "supporting" it would mean deciding
    # what a partially-readable archive hashes to - there is no honest answer.
    if this_disk != 0 or cd_disk != 0:
        raise UnpackRejected(
            f"spanned/multi-disk zip archives are not supported "
            f"(disk {this_disk}, central directory on disk {cd_disk})"
        )
    if declared_entries > MAX_ENTRY_COUNT:
        raise UnpackRejected(f"entry count {declared_entries} exceeds max {MAX_ENTRY_COUNT}")

    try:
        return _transcode_zip(zip_bytes)
    except _ZIP_PARSE_ERRORS as exc:
        raise UnpackRejected(f"not a valid zip archive: {type(exc).__name__}: {exc}") from exc


def _transcode_zip(zip_bytes: bytes) -> bytes:
    """The bounded transcode loop itself. Only ever called by
    `zip_to_tar_bytes`, which owns the pre-checks and the exception mapping."""
    compressed_size = len(zip_bytes)
    total_uncompressed = 0
    file_count = 0
    tar_buf = BytesIO()
    with (
        zipfile.ZipFile(BytesIO(zip_bytes)) as zf,
        tarfile.open(fileobj=tar_buf, mode="w") as tf,
    ):
        entries = zf.infolist()
        # The authoritative entry-count check: `_read_zip_end_record`'s is the
        # declared one, and a declaration is not evidence.
        if len(entries) > MAX_ENTRY_COUNT:
            raise UnpackRejected(f"entry count {len(entries)} exceeds max {MAX_ENTRY_COUNT}")

        for info in entries:
            # SECURITY: an encrypted member cannot be content-hashed or scanned,
            # and `zf.read()` on one raises `RuntimeError` - refuse the archive
            # instead of shipping a package whose payload nothing could read.
            if info.flag_bits & 0x1:
                raise UnpackRejected(f"encrypted zip entries are rejected: {info.filename!r}")
            if info.is_dir():
                continue
            # Unix mode recovery: zip stores it in the high 16 bits of
            # `external_attr` (0 for a DOS/Windows-produced archive).
            unix_mode = (info.external_attr >> 16) & 0xFFFF
            # MEASURED: the file-TYPE bits (S_IFMT) are frequently absent even
            # when permission bits are present - CPython's own `zipfile` writes
            # 0o600 with no type bits, and DOS/Windows writers store 0. So the
            # type is only consulted when it is actually declared; an entry with
            # permission bits alone is an ordinary file, and demanding S_ISREG
            # unconditionally would refuse every zip written by Python itself.
            #
            # NOTE: a zero-byte entry with NO mode at all ("agents" next to
            # "agents/x.yaml" - a real clawhub archive did this) therefore does
            # NOT reach the branch below, and must not: it is indistinguishable
            # from an empty regular file, so it is transcoded and
            # `unpack_hardened`'s file/directory-prefix check is what rejects
            # it. That check exists because of exactly this shape.
            if stat.S_IFMT(unix_mode) and not stat.S_ISREG(unix_mode):
                if stat.S_ISDIR(unix_mode):
                    # Same thing as the trailing-slash spelling `info.is_dir()`
                    # already skips; a directory is not part of the file set.
                    continue
                # SECURITY: symlinks, fifos, devices, sockets. Rejected, not
                # dropped - see `zip_to_tar_bytes`. Dropping made the scanned
                # file set silently differ from the submitted archive, which
                # let an escaping symlink earn a clean verdict unrecorded.
                raise UnpackRejected(
                    f"non-regular zip entry rejected (mode {oct(stat.S_IFMT(unix_mode))}): "
                    f"{info.filename!r}"
                )

            # The one path check that could not be delegated across this
            # boundary IF it were ever reachable: a tar header NUL-terminates
            # member names, so a NUL-bearing name would reach
            # `_canonicalize_member_path` already truncated ('bad\x00x.txt' ->
            # 'bad') and its NUL check would see a legal name.
            #
            # MEASURED 2026-07-30, and the reason this is defense-in-depth
            # rather than a fix: CPython's `zipfile` truncates at the first NUL
            # on BOTH write and read (its own source says why - "Null bytes in
            # file names are used as tricks by viruses in archives"), so a
            # hand-crafted archive carrying a NUL in the central directory
            # arrives here already truncated and this branch does not fire.
            # It is kept because it is one scan per member and it is the only
            # thing standing between a future reader that stops truncating and
            # a silently renamed member - see
            # `test_the_transcoded_tar_never_renames_a_member` for the property
            # that actually matters.
            if "\x00" in info.filename:
                raise UnpackRejected(f"NUL byte in path: {info.filename!r}")

            if info.file_size > MAX_SINGLE_FILE_BYTES:
                raise UnpackRejected(
                    f"member {info.filename!r} declared size {info.file_size} "
                    f"exceeds max {MAX_SINGLE_FILE_BYTES}"
                )
            with zf.open(info) as member:
                # SECURITY: read at most one byte past the limit, mirroring the
                # tar path - `ZipInfo.file_size` is a declaration and lies
                # exactly the way a tar header does. (`zipfile` happens to stop
                # at the declared length itself and then fail the CRC, which is
                # why a crafted archive cannot normally reach the check below;
                # it stays as the same defense-in-depth the tar path keeps, and
                # the running total is measured either way.)
                data = member.read(MAX_SINGLE_FILE_BYTES + 1)
            if len(data) > MAX_SINGLE_FILE_BYTES:
                raise UnpackRejected(f"member {info.filename!r} exceeded max size while reading")

            total_uncompressed += len(data)
            if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise UnpackRejected(
                    f"total uncompressed size exceeds max {MAX_TOTAL_UNCOMPRESSED_BYTES}"
                )
            # SECURITY ("billion laughs" amplification): checked INSIDE the loop,
            # unlike the tar path's single check after unpacking. The tar path
            # can afford to wait because its own total cap bounds the work
            # first; here the whole point is to kill the bomb before it is fully
            # expanded, and this layer is also the LAST place the ratio is
            # knowable at all - the tar handed onward is stored uncompressed, so
            # `unpack_hardened` would compute a ratio of ~1 for any zip and its
            # check would be structurally blind.
            ratio = total_uncompressed / compressed_size
            if ratio > MAX_COMPRESSION_RATIO:
                raise UnpackRejected(
                    f"compression ratio {ratio:.1f} exceeds max {MAX_COMPRESSION_RATIO} "
                    "(decompression-bomb defense)"
                )

            # Member names are copied through VERBATIM: path validation
            # (traversal, NUL, depth, backslash variants) belongs to
            # `_canonicalize_member_path` on the far side of the boundary, and
            # sanitizing here would mean two implementations of it.
            tarinfo = tarfile.TarInfo(name=info.filename)
            tarinfo.size = len(data)
            mode = unix_mode & 0o777
            tarinfo.mode = mode if mode else 0o644
            try:
                tarinfo.mtime = int(time.mktime((*info.date_time, 0, 0, -1)))
            except (OverflowError, ValueError):
                # A DOS zero timestamp ("00-00-1980"), which is what skillhub's
                # archives carry. mtime is not part of `content_hash()`, so 0 is
                # a lossless choice here.
                tarinfo.mtime = 0
            tf.addfile(tarinfo, BytesIO(data))
            file_count += 1

    if file_count == 0:
        # Would otherwise produce a structurally valid, empty tar that
        # `unpack_hardened` rejects with a less specific message.
        raise UnpackRejected("zip archive contains no regular files")
    return tar_buf.getvalue()


def unpack_package_archive(archive_bytes: bytes) -> list[tuple[str, int, bytes]]:
    """The ingest boundary both submission doors call (`gateway.router` for the
    console, `marketplace_api.router` for the marketplace).

    Dispatches on magic bytes: tar goes straight into `unpack_hardened`, zip is
    transcoded first by `zip_to_tar_bytes` and then goes through the identical
    `unpack_hardened` checks. Anything else reaches `unpack_hardened` unchanged
    and is refused there as "not a valid tar archive".

    NOTE (a deliberate asymmetry, not an oversight): the transcoded tar is
    stored uncompressed, so it must also pass `unpack_hardened`'s
    MAX_ARCHIVE_BYTES check - which makes 50 MiB the effective ceiling on a
    zip's TOTAL uncompressed payload, where a compressed tar may expand to
    MAX_TOTAL_UNCOMPRESSED_BYTES (200 MiB). Zip uploads are therefore bounded
    more tightly than tar uploads, never less; both are far above any real
    Skill package.
    """
    if archive_bytes.startswith(ZIP_MAGIC_PREFIXES):
        archive_bytes = zip_to_tar_bytes(archive_bytes)
    return unpack_hardened(archive_bytes)
