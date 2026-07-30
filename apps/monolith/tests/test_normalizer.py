"""Tests for `engine_runner.normalizer` (coding spec §11.4 M4 acceptance bar:
malicious corpus doesn't crash/DoS the unpacker). Pure, no infra needed.

NOTE: several tests monkeypatch the module's size/count constants down to
small values rather than constructing literal 200MB+ payloads - this exercises
the exact same code paths at a speed suitable for a unit test.
"""

from __future__ import annotations

import io
import stat
import struct
import tarfile
import zipfile
from typing import Literal

import pytest
from engine_runner import normalizer
from engine_runner.normalizer import (
    UnpackRejected,
    unpack_hardened,
    unpack_package_archive,
    zip_to_tar_bytes,
)


def _make_tar(entries: list[tuple[str, bytes]], *, mode: Literal["w", "w:gz"] = "w") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tar:
        for name, data in entries:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# A DOS "zero" timestamp - what skillhub.cloud.tencent.com's archives actually
# carry (00-00-1980), and the input that makes `time.mktime` raise.
DOS_ZERO_DATE_TIME = (1980, 0, 0, 0, 0, 0)


def _make_zip(
    entries: list[tuple[str, bytes]],
    *,
    compression: int = zipfile.ZIP_DEFLATED,
    external_attr: int | None = None,
    date_time: tuple[int, int, int, int, int, int] = (2026, 7, 30, 12, 0, 0),
) -> bytes:
    """A zip built entry-by-entry so each test controls `external_attr` (whose
    high 16 bits carry the Unix mode) and the DOS timestamp.

    NOTE: leaving `external_attr` at 0 does NOT produce a mode-less entry -
    `zipfile._open_to_write` substitutes 0o600 << 16 for a zero value, so a
    genuinely DOS-produced entry has to be spelled out (e.g. 0x20, the DOS
    "archive" attribute, with empty high bits)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compression) as zf:
        for name, data in entries:
            info = zipfile.ZipInfo(filename=name, date_time=date_time)
            info.compress_type = compression
            if external_attr is not None:
                info.external_attr = external_attr
            zf.writestr(info, data)
    return buf.getvalue()


def _eocd_offset(zip_bytes: bytes) -> int:
    index = zip_bytes.rfind(b"PK\x05\x06")
    assert index >= 0
    return index


def _patch_eocd(
    zip_bytes: bytes,
    *,
    this_disk: int | None = None,
    cd_disk: int | None = None,
    total_entries: int | None = None,
) -> bytes:
    """Rewrite end-of-central-directory fields in place - how a spanned archive
    and a lying entry count are constructed without a zip writer that can
    produce them."""
    raw = bytearray(zip_bytes)
    offset = _eocd_offset(zip_bytes)
    if this_disk is not None:
        struct.pack_into("<H", raw, offset + 4, this_disk)
    if cd_disk is not None:
        struct.pack_into("<H", raw, offset + 6, cd_disk)
    if total_entries is not None:
        struct.pack_into("<H", raw, offset + 10, total_entries)
    return bytes(raw)


class TestHappyPath:
    def test_unpacks_a_normal_archive(self) -> None:
        archive = _make_tar([("skill.py", b"print('hello')\n"), ("SKILL.md", b"# hi\n")])
        files = unpack_hardened(archive)
        assert {path for path, _mode, _data in files} == {"skill.py", "SKILL.md"}

    def test_preserves_mode_bits(self) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name="run.sh")
            data = b"#!/bin/sh\necho hi\n"
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))
        files = unpack_hardened(buf.getvalue())
        assert files[0][1] == 0o755


class TestRejectsEmptyOrGarbage:
    def test_empty_bytes_rejected(self) -> None:
        with pytest.raises(UnpackRejected, match="empty"):
            unpack_hardened(b"")

    def test_non_tar_garbage_rejected(self) -> None:
        # `unpack_hardened` itself stays TAR-ONLY by design (2026-07-30): zip
        # support is a bounded transcode in FRONT of it
        # (`unpack_package_archive`), never a second format branch inside the
        # hardened parser. This assertion is that design, not an accident - see
        # TestPackageArchiveDispatch for the boundary-level behaviour.
        with pytest.raises(UnpackRejected, match="not a valid tar"):
            unpack_hardened(b"this is not a tar archive at all, just junk bytes")

    def test_zip_bytes_rejected_by_the_hardened_tar_parser_itself(self) -> None:
        # The pre-2026-07-30 user-visible bug: a real skillhub/clawhub zip
        # reached `unpack_hardened` directly and got "not a valid tar archive".
        # That is still what this function does with zip bytes; what changed is
        # that ingest no longer calls it with them.
        with pytest.raises(UnpackRejected, match="not a valid tar"):
            unpack_hardened(_make_zip([("skill.py", b"print(1)\n")]))

    def test_archive_with_no_regular_files_rejected(self) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name="emptydir")
            info.type = tarfile.DIRTYPE
            tar.addfile(info)
        with pytest.raises(UnpackRejected, match="no regular files"):
            unpack_hardened(buf.getvalue())


class TestPathTraversal:
    def test_dotdot_segment_rejected(self) -> None:
        archive = _make_tar([("../../etc/passwd", b"pwned")])
        with pytest.raises(UnpackRejected, match="illegal path segment"):
            unpack_hardened(archive)

    def test_absolute_path_rejected(self) -> None:
        archive = _make_tar([("/etc/passwd", b"pwned")])
        with pytest.raises(UnpackRejected, match="absolute path"):
            unpack_hardened(archive)

    def test_nul_byte_in_path_rejected(self) -> None:
        # NOTE: exercises _canonicalize_member_path directly rather than round-
        # tripping through a real tar archive - the tar format itself
        # NUL-terminates member names, so a real archive can never actually
        # carry an embedded NUL through to unpack_hardened's member loop
        # (confirmed: tarfile silently truncates at the NUL on read-back).
        # This check is defense-in-depth for the validation function itself,
        # not a reachable-via-tar path. ZIP, however, CAN carry a NUL this far,
        # and that truncation-in-transit is exactly why the transcoder has to
        # check the name itself - see
        # `TestPackageArchiveDispatch::test_a_nul_byte_in_a_zip_member_name_is_rejected`.
        with pytest.raises(UnpackRejected, match="NUL byte"):
            normalizer._canonicalize_member_path("innocuous.txt\x00.py")

    def test_excessive_path_depth_rejected(self) -> None:
        deep_path = "/".join(["a"] * (normalizer.MAX_PATH_DEPTH + 5)) + "/file.txt"
        archive = _make_tar([(deep_path, b"data")])
        with pytest.raises(UnpackRejected, match="path depth"):
            unpack_hardened(archive)

    # INV-6 regression (2026-07-06 spec-compliance audit): mirrors
    # skillscan_core.canonical's own backslash-traversal fix - '\' has no
    # separator meaning on this POSIX deployment target, but a member name
    # like '..\..\etc\passwd' must not slip through just because it contains
    # no literal '/'.
    def test_dotdot_segment_hidden_behind_backslash_rejected(self) -> None:
        archive = _make_tar([("..\\..\\etc\\passwd", b"pwned")])
        with pytest.raises(UnpackRejected, match="illegal path segment"):
            unpack_hardened(archive)

    def test_mixed_slash_and_backslash_traversal_rejected(self) -> None:
        archive = _make_tar([("scripts/..\\..\\secret.py", b"pwned")])
        with pytest.raises(UnpackRejected, match="illegal path segment"):
            unpack_hardened(archive)

    def test_literal_backslash_character_in_a_real_filename_allowed(self) -> None:
        # A literal backslash inside a single path segment is a legal POSIX
        # filename character, not a traversal attempt.
        archive = _make_tar([("scripts/weird\\name.py", b"print(1)\n")])
        files = unpack_hardened(archive)
        assert {path for path, _mode, _data in files} == {"scripts/weird\\name.py"}


class TestDotSegmentCanonicalization:
    # FP-TUNING regression (2026-07): GNU tar routinely prefixes members with
    # './'. A '.' segment is "current directory" (a no-op), NOT traversal - it
    # must be canonicalized away, not cause the whole archive to be rejected.
    def test_leading_dot_slash_prefix_is_stripped_not_rejected(self) -> None:
        archive = _make_tar([("./skill.py", b"print(1)\n"), ("./docs/README.md", b"# hi\n")])
        files = unpack_hardened(archive)
        assert {path for path, _mode, _data in files} == {"skill.py", "docs/README.md"}

    def test_interior_dot_segment_is_collapsed(self) -> None:
        archive = _make_tar([("scripts/./run.py", b"print(1)\n")])
        files = unpack_hardened(archive)
        assert {path for path, _mode, _data in files} == {"scripts/run.py"}

    def test_dotdot_still_rejected_even_next_to_dot(self) -> None:
        # SECURITY: dropping '.' must NOT loosen '..' handling.
        archive = _make_tar([("./../etc/passwd", b"pwned")])
        with pytest.raises(UnpackRejected, match="illegal path segment"):
            unpack_hardened(archive)


class TestSymlinkRejection:
    def test_symlink_entry_rejected(self) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name="innocuous.txt")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tar.addfile(info)
        with pytest.raises(UnpackRejected, match="symlink"):
            unpack_hardened(buf.getvalue())

    def test_hardlink_entry_rejected(self) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            real = tarfile.TarInfo(name="real.txt")
            data = b"data"
            real.size = len(data)
            tar.addfile(real, io.BytesIO(data))
            link = tarfile.TarInfo(name="link.txt")
            link.type = tarfile.LNKTYPE
            link.linkname = "real.txt"
            tar.addfile(link)
        with pytest.raises(UnpackRejected, match="symlink/hardlink"):
            unpack_hardened(buf.getvalue())


class TestDecompressionBombDefense:
    def test_archive_over_max_size_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(normalizer, "MAX_ARCHIVE_BYTES", 100)
        archive = _make_tar([("big.txt", b"x" * 1000)])
        assert len(archive) > 100
        with pytest.raises(UnpackRejected, match="archive size"):
            unpack_hardened(archive)

    def test_entry_count_exhaustion_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(normalizer, "MAX_ENTRY_COUNT", 10)
        archive = _make_tar([(f"file_{i}.txt", b"x") for i in range(20)])
        with pytest.raises(UnpackRejected, match="entry count"):
            unpack_hardened(archive)

    def test_single_file_over_max_size_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(normalizer, "MAX_SINGLE_FILE_BYTES", 100)
        archive = _make_tar([("big.txt", b"x" * 1000)])
        with pytest.raises(UnpackRejected, match="declared size"):
            unpack_hardened(archive)

    def test_total_uncompressed_size_over_max_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(normalizer, "MAX_SINGLE_FILE_BYTES", 1000)
        monkeypatch.setattr(normalizer, "MAX_TOTAL_UNCOMPRESSED_BYTES", 1500)
        archive = _make_tar([(f"file_{i}.txt", b"x" * 800) for i in range(3)])
        with pytest.raises(UnpackRejected, match="total uncompressed size"):
            unpack_hardened(archive)

    def test_high_compression_ratio_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # SECURITY: "billion laughs"-style amplification defense - a small
        # compressed archive that expands to a disproportionately large
        # payload is rejected even though the absolute size might be under
        # MAX_TOTAL_UNCOMPRESSED_BYTES on its own.
        monkeypatch.setattr(normalizer, "MAX_COMPRESSION_RATIO", 50)
        archive = _make_tar([("zeros.bin", b"\x00" * (2 * 1024 * 1024))], mode="w:gz")
        with pytest.raises(UnpackRejected, match="compression ratio"):
            unpack_hardened(archive)


class TestFileDirectoryPathCollision:
    """SECURITY regression lock (found live, 2026-07-22): a real clawhub.ai
    skill's zip had a zero-byte, non-slash-terminated "directory marker" entry
    for "agents" alongside real files under "agents/" - a common zip-tooling
    quirk. Neither zip-tar conversion nor tarfile's own type system catches
    this (both are ordinary REGTYPE members), so it passed every earlier
    hardening check and materialized fine as a canonical (path, mode, data)
    list - but writing these files back out to a real filesystem (engine_
    runner.adapters.base's per-scan temp dir) hit mkdir() on a path that
    already existed as a plain file, permanently wedging every sandboxed
    engine for that scan in an endless unacked-redelivery retry loop. Any
    submitter can construct a tar with this exact shape directly (tar doesn't
    enforce hierarchical consistency between entries), so this is a
    submitter-triggerable availability gap, not merely a test-harness
    artifact."""

    def test_file_that_is_also_a_directory_prefix_rejected(self) -> None:
        archive = _make_tar([("agents", b""), ("agents/openai.yaml", b"key: value\n")])
        with pytest.raises(UnpackRejected, match="directory prefix"):
            unpack_hardened(archive)

    def test_collision_several_levels_deep_rejected(self) -> None:
        archive = _make_tar([("a/b", b"x"), ("a/b/c/d.txt", b"y")])
        with pytest.raises(UnpackRejected, match="directory prefix"):
            unpack_hardened(archive)

    def test_order_of_entries_does_not_matter(self) -> None:
        # The nested file appearing BEFORE the colliding leaf must still be
        # caught - this is a whole-archive structural check, not dependent on
        # which entry the tar happened to list first.
        archive = _make_tar([("agents/openai.yaml", b"key: value\n"), ("agents", b"")])
        with pytest.raises(UnpackRejected, match="directory prefix"):
            unpack_hardened(archive)

    def test_similarly_prefixed_but_distinct_paths_are_not_a_collision(self) -> None:
        # SECURITY/CORRECTNESS: "agents-extra" is not "agents" plus a "/"
        # separator, and "agentsx/y" doesn't collide with a file named
        # "agents" either - a naive substring-prefix check (rather than a
        # path-segment-aware one) would wrongly reject this legitimate shape.
        archive = _make_tar(
            [("agents", b"config"), ("agents-extra.txt", b"z"), ("agentsx/y.txt", b"w")]
        )
        files = unpack_hardened(archive)
        assert {path for path, _mode, _data in files} == {
            "agents",
            "agents-extra.txt",
            "agentsx/y.txt",
        }

    def test_normal_nested_directory_structure_still_allowed(self) -> None:
        # Regression guard: ordinary Skill packages (files nested under
        # directories with no colliding leaf-file) must be unaffected.
        archive = _make_tar(
            [("SKILL.md", b"# hi\n"), ("scripts/run.py", b"pass\n"), ("docs/img/a.png", b"\x89PNG")]
        )
        files = unpack_hardened(archive)
        assert {path for path, _mode, _data in files} == {
            "SKILL.md",
            "scripts/run.py",
            "docs/img/a.png",
        }


class TestDuplicateEntryPaths:
    """SECURITY (2026-07-30): two entries that canonicalize to one path are
    rejected. The in-process detectors iterate the returned list and see BOTH
    copies; `engine_runner.adapters.base` materializes it to a filesystem where
    the last write wins and only ONE exists - so "what was scanned" and "what a
    sandboxed engine reads" would diverge while `content_hash()` covers both.

    Enforced in `unpack_hardened`, i.e. for tar AND zip alike: only here do
    canonical paths exist, and a zip-only check would be an undocumented
    asymmetry between two doors into the same pipeline."""

    def test_duplicate_member_names_in_a_tar_rejected(self) -> None:
        # tar has no index at all - appending the same name twice is legal and
        # extraction is last-wins. Previously accepted silently.
        archive = _make_tar([("skill.py", b"benign\n"), ("skill.py", b"malicious\n")])
        with pytest.raises(UnpackRejected, match="duplicate entry paths"):
            unpack_hardened(archive)

    def test_duplicate_member_names_in_a_zip_rejected(self) -> None:
        # zip's central directory makes this trivially constructible, which is
        # why the check landed with the zip path.
        archive = _make_zip([("skill.py", b"benign\n"), ("skill.py", b"malicious\n")])
        with pytest.raises(UnpackRejected, match="duplicate entry paths"):
            unpack_package_archive(archive)

    def test_distinct_names_that_canonicalize_to_one_path_rejected(self) -> None:
        # The third way in, and the reason this check cannot live in the zip
        # transcoder: './skill.py' and 'skill.py' are two DIFFERENT member names
        # that `_canonicalize_member_path` collapses into one path. A name-level
        # check on either container would miss it entirely.
        archive = _make_tar([("./skill.py", b"benign\n"), ("skill.py", b"malicious\n")])
        with pytest.raises(UnpackRejected, match="duplicate entry paths"):
            unpack_hardened(archive)

    def test_the_duplicated_path_is_named_in_the_message(self) -> None:
        archive = _make_tar([("a.py", b"1"), ("a.py", b"2"), ("b.py", b"3")])
        with pytest.raises(UnpackRejected, match=r"duplicate entry paths.*a\.py"):
            unpack_hardened(archive)

    def test_distinct_paths_are_not_duplicates(self) -> None:
        archive = _make_tar([("a.py", b"1"), ("dir/a.py", b"2"), ("a.pyc", b"3")])
        files = unpack_hardened(archive)
        assert len(files) == 3


class TestPackageArchiveDispatch:
    """The ingest boundary both submission doors call. Dispatch is on MAGIC
    BYTES, never on a filename extension - the extension is caller-supplied
    metadata with no bearing on what the bytes are (and `UploadFile.filename`
    is not even consulted)."""

    def test_a_tar_still_goes_straight_through(self) -> None:
        archive = _make_tar([("skill.py", b"print(1)\n")])
        files = unpack_package_archive(archive)
        assert [path for path, _mode, _data in files] == ["skill.py"]

    def test_a_zip_is_accepted(self) -> None:
        # THE BUG THIS PART CLOSES: a real skillhub.cloud.tencent.com download
        # is a zip, and the console answered
        # "invalid package archive: not a valid tar archive".
        archive = _make_zip([("SKILL.md", b"# hi\n"), ("scripts/run.py", b"print(1)\n")])
        files = unpack_package_archive(archive)
        assert {path for path, _mode, _data in files} == {"SKILL.md", "scripts/run.py"}

    def test_neither_tar_nor_zip_still_reports_the_tar_failure(self) -> None:
        with pytest.raises(UnpackRejected, match="not a valid tar"):
            unpack_package_archive(b"just junk bytes, no PK, no ustar")

    def test_zip_magic_wins_over_a_tar_looking_name(self) -> None:
        # Dispatch cannot consult a name; this only records that the bytes are
        # what decide, using an entry name that looks like a tarball.
        archive = _make_zip([("bundle.tar", b"not really a tar\n")])
        files = unpack_package_archive(archive)
        assert [path for path, _mode, _data in files] == ["bundle.tar"]


class TestZipTranscode:
    def test_unix_mode_bits_are_recovered_from_external_attr(self) -> None:
        archive = _make_zip(
            [("run.sh", b"#!/bin/sh\n")], external_attr=(stat.S_IFREG | 0o755) << 16
        )
        files = unpack_package_archive(archive)
        assert files[0][1] == 0o755

    def test_permission_bits_without_file_type_bits_are_kept(self) -> None:
        # What CPython's own `zipfile` writes: 0o600 with NO S_IFMT bits. An
        # S_ISREG() test that did not first check whether a type was declared at
        # all would drop every member of such an archive.
        archive = _make_zip([("SKILL.md", b"# hi\n")], external_attr=0o600 << 16)
        files = unpack_package_archive(archive)
        assert files[0][1] == 0o600

    def test_a_dos_produced_zip_with_no_mode_bits_gets_0644(self) -> None:
        # No Unix mode at all (a Windows/DOS zip writer). Mode 0 would make the
        # file unreadable to the engines that materialize it.
        archive = _make_zip([("SKILL.md", b"# hi\n")], external_attr=0x20)
        files = unpack_package_archive(archive)
        assert files[0][1] == 0o644

    def test_dos_zero_timestamp_does_not_raise(self) -> None:
        # skillhub's real archives carry 00-00-1980, which reads back as
        # date_time (1980, 0, 0, 0, 0, 0) - month 0, day 0. `time.mktime` either
        # raises OverflowError/ValueError on it (the fallback to mtime=0 exists
        # for that) or normalizes it into late 1979, PLATFORM-DEPENDENTLY
        # (measured: macOS/glibc normalize). Either answer is fine - mtime is
        # not part of content_hash() - but the transcode must not blow up, which
        # is what an unguarded mktime would do.
        archive = _make_zip([("SKILL.md", b"# hi\n")], date_time=DOS_ZERO_DATE_TIME)
        tar_bytes = zip_to_tar_bytes(archive)
        with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
            member = tar.getmembers()[0]
            assert isinstance(member.mtime, int)
        files = unpack_package_archive(archive)
        assert [(path, data) for path, _mode, data in files] == [("SKILL.md", b"# hi\n")]

    def test_a_symlink_beside_real_files_rejects_the_whole_archive(self) -> None:
        # THE 2026-07-30 FIX. This shape previously returned 202 from a live
        # deployment: the link was dropped, "SKILL.md" alone was scanned, and a
        # package carrying `passwd -> /etc/passwd` earned a clean verdict with
        # nothing anywhere recording that it had tried. tar has always rejected
        # the whole archive here; zip now does the same, so there is one policy.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            link = zipfile.ZipInfo(filename="passwd")
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(link, b"/etc/passwd")
            real = zipfile.ZipInfo(filename="SKILL.md")
            real.external_attr = (stat.S_IFREG | 0o644) << 16
            zf.writestr(real, b"# hi\n")
        with pytest.raises(UnpackRejected, match="non-regular zip entry rejected"):
            unpack_package_archive(buf.getvalue())

    def test_a_zip_of_only_symlinks_is_rejected_cleanly(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            link = zipfile.ZipInfo(filename="passwd")
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(link, b"/etc/passwd")
        with pytest.raises(UnpackRejected, match="non-regular zip entry rejected"):
            unpack_package_archive(buf.getvalue())

    @pytest.mark.parametrize(
        "file_type",
        [stat.S_IFIFO, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFSOCK],
        ids=["fifo", "chardev", "blockdev", "socket"],
    )
    def test_every_other_non_regular_member_type_is_rejected(self, file_type: int) -> None:
        # Same policy for the rest of the S_IFMT space, not just symlinks - a
        # fifo or device member is content nothing can honestly scan.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            odd = zipfile.ZipInfo(filename="weird")
            odd.external_attr = (file_type | 0o644) << 16
            zf.writestr(odd, b"")
            real = zipfile.ZipInfo(filename="SKILL.md")
            real.external_attr = (stat.S_IFREG | 0o644) << 16
            zf.writestr(real, b"# hi\n")
        with pytest.raises(UnpackRejected, match="non-regular zip entry rejected"):
            unpack_package_archive(buf.getvalue())

    def test_cpython_zipfile_truncates_a_nul_name_before_we_see_it(self) -> None:
        # MEASURED, and the reason the transcoder's NUL check is unreachable
        # defense-in-depth rather than a live fix. A hand-crafted archive CAN
        # carry a NUL in the central directory (zip names are length-prefixed,
        # not NUL-terminated), but CPython's reader truncates there on the way
        # in - its own source explains why: "Null bytes in file names are used
        # as tricks by viruses in archives". This test exists so that if a
        # future CPython stops doing that, the surprise lands here with an
        # explanation rather than as a silently renamed member.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("SKILL.md", b"# hi\n")
            zf.writestr("badXname.txt", b"payload")
        raw = bytearray(buf.getvalue())
        patched = 0
        while (index := raw.find(b"badXname.txt")) >= 0:
            raw[index + 3] = 0  # the 'X' -> NUL, in local header AND directory
            patched += 1
        assert patched == 2, "expected the name in both the local header and the directory"
        with zipfile.ZipFile(io.BytesIO(bytes(raw))) as zf:
            assert [info.filename for info in zf.infolist()] == ["SKILL.md", "bad"]

    def test_a_nul_bearing_name_from_a_reader_is_rejected(self) -> None:
        # The branch the test above proves is currently unreachable, exercised
        # at the level it lives: if any zip reader ever hands the transcoder a
        # name with a NUL in it, the archive is refused rather than transcoded
        # into a tar that would store the truncated name.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("SKILL.md", b"# hi\n")
            zf.writestr("payload.txt", b"payload")
        real_infolist = zipfile.ZipFile.infolist

        def _lying_infolist(self: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
            infos = real_infolist(self)
            for info in infos:
                if info.filename == "payload.txt":
                    info.filename = "payload.txt\x00.py"
            return infos

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(zipfile.ZipFile, "infolist", _lying_infolist)
            with pytest.raises(UnpackRejected, match="NUL byte in path"):
                unpack_package_archive(buf.getvalue())

    def test_the_transcoded_tar_never_renames_a_member(self) -> None:
        # The property the NUL check protects, stated directly: whatever names
        # survive the transcode are the names the submitter sent. If this ever
        # fails, the content_hash no longer identifies the submitted archive.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name in ("SKILL.md", "scripts/run.py", "a-b_c.1.txt"):
                zf.writestr(name, b"x")
        tar_bytes = zip_to_tar_bytes(buf.getvalue())
        with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
            assert sorted(tar.getnames()) == ["SKILL.md", "a-b_c.1.txt", "scripts/run.py"]

    def test_a_zip_of_only_directories_is_rejected_cleanly(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(zipfile.ZipInfo(filename="docs/"), b"")
        with pytest.raises(UnpackRejected, match="no regular files"):
            unpack_package_archive(buf.getvalue())

    def test_an_empty_zip_is_rejected_cleanly(self) -> None:
        # A bare end-of-central-directory record: still zip magic
        # (PK\x05\x06), zero entries. Must be a 400, not a 500.
        empty = io.BytesIO()
        with zipfile.ZipFile(empty, "w"):
            pass
        assert empty.getvalue().startswith(b"PK\x05\x06")
        with pytest.raises(UnpackRejected, match="no regular files"):
            unpack_package_archive(empty.getvalue())

    def test_traversal_in_a_zip_member_name_is_still_rejected(self) -> None:
        # Path validation belongs to `_canonicalize_member_path` on the far side
        # of the boundary; the transcoder copies names through verbatim rather
        # than growing a second implementation of it.
        archive = _make_zip([("../../etc/passwd", b"pwned")])
        with pytest.raises(UnpackRejected, match="illegal path segment"):
            unpack_package_archive(archive)

    def test_absolute_path_in_a_zip_member_name_is_still_rejected(self) -> None:
        archive = _make_zip([("/etc/passwd", b"pwned")])
        with pytest.raises(UnpackRejected, match="absolute path"):
            unpack_package_archive(archive)

    def test_the_real_clawhub_directory_marker_still_trips_after_transcode(self) -> None:
        # THE 2026-07-22 REGRESSION LOCK, now exercised through its ORIGINAL
        # shape: a real clawhub zip carried a zero-byte, NON-slash-terminated
        # "agents" entry alongside "agents/openai.yaml", which wedged every
        # sandboxed engine for that scan in an endless redelivery loop. Such an
        # entry is indistinguishable from an empty regular file, so the
        # transcoder deliberately does NOT filter it - `unpack_hardened`'s
        # file/directory-prefix check is what must still catch it.
        archive = _make_zip([("agents", b""), ("agents/openai.yaml", b"key: value\n")])
        with pytest.raises(UnpackRejected, match="directory prefix"):
            unpack_package_archive(archive)

    def test_a_zip_directory_entry_with_a_unix_mode_is_skipped(self) -> None:
        # The other half of the same shape: an entry recorded WITH S_IFDIR but
        # no trailing slash is a directory. It is SKIPPED rather than rejected
        # with the other non-regular members, because a directory carries no
        # content and `info.is_dir()` already skips the trailing-slash
        # spelling of the identical thing - skipping both keeps the two
        # spellings equivalent instead of making one of them fatal.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            marker = zipfile.ZipInfo(filename="agents")
            marker.external_attr = (stat.S_IFDIR | 0o755) << 16
            zf.writestr(marker, b"")
            child = zipfile.ZipInfo(filename="agents/openai.yaml")
            child.external_attr = (stat.S_IFREG | 0o644) << 16
            zf.writestr(child, b"key: value\n")
        files = unpack_package_archive(buf.getvalue())
        assert [path for path, _mode, _data in files] == ["agents/openai.yaml"]

    def test_garbage_after_zip_magic_is_a_clean_rejection(self) -> None:
        # Dispatched to the zip path by its magic bytes, then unparseable. Must
        # be UnpackRejected (-> 400), never a bare BadZipFile (-> 500).
        with pytest.raises(UnpackRejected, match="not a valid zip archive"):
            unpack_package_archive(b"PK\x03\x04" + b"\x00" * 64)

    def test_a_corrupt_deflate_stream_is_a_clean_rejection(self) -> None:
        # Measured: this raises `zlib.error`, NOT BadZipFile - the reason
        # `_ZIP_PARSE_ERRORS` is a list of measured types rather than just
        # `BadZipFile`.
        archive = _make_zip([("a.txt", b"hello world" * 100)])
        local_payload_offset = 30 + len("a.txt")
        raw = bytearray(archive)
        raw[local_payload_offset : local_payload_offset + 8] = b"\xff" * 8
        with pytest.raises(UnpackRejected, match="not a valid zip archive"):
            unpack_package_archive(bytes(raw))

    def test_an_unsupported_compression_method_is_a_clean_rejection(self) -> None:
        # Method 99 is WinZip AES. Measured: `NotImplementedError`.
        archive = _make_zip([("a.txt", b"data")])
        raw = bytearray(archive)
        central = raw.find(b"PK\x01\x02")
        struct.pack_into("<H", raw, central + 10, 99)
        with pytest.raises(UnpackRejected, match="not a valid zip archive"):
            unpack_package_archive(bytes(raw))

    def test_an_archive_with_no_end_record_is_a_clean_rejection(self) -> None:
        with pytest.raises(UnpackRejected, match="end-of-central-directory"):
            unpack_package_archive(b"PK\x03\x04" + b"nothing resembling an end record")


class TestZipEncryptedEntries:
    def test_an_encrypted_entry_is_rejected(self) -> None:
        # `zf.read()` on one raises RuntimeError (measured), i.e. a 500 if this
        # were not checked. An encrypted member also cannot be scanned or
        # content-hashed, so accepting the archive would be dishonest anyway.
        archive = _make_zip([("secret.txt", b"data")], compression=zipfile.ZIP_STORED)
        raw = bytearray(archive)
        struct.pack_into("<H", raw, 6, 0x1)  # local header general-purpose flags
        central = raw.find(b"PK\x01\x02")
        struct.pack_into("<H", raw, central + 8, 0x1)  # central directory copy
        with pytest.raises(UnpackRejected, match="encrypted"):
            unpack_package_archive(bytes(raw))


class TestZipSpannedArchives:
    """MEASURED (CPython 3.14, 2026-07-30): `zipfile` does NOT refuse
    multi-disk/spanned archives - it ignores the end-of-central-directory disk
    fields entirely, so an archive claiming "disk 1 of 3" parses and reads like
    any other. Undefined behaviour at a hardened boundary is the thing to
    avoid, so this layer refuses them explicitly."""

    def test_a_nonzero_disk_number_is_refused(self) -> None:
        archive = _patch_eocd(_make_zip([("a.txt", b"data")]), this_disk=1, cd_disk=1)
        with pytest.raises(UnpackRejected, match="spanned/multi-disk"):
            unpack_package_archive(archive)

    def test_a_central_directory_on_another_disk_is_refused(self) -> None:
        archive = _patch_eocd(_make_zip([("a.txt", b"data")]), cd_disk=2)
        with pytest.raises(UnpackRejected, match="spanned/multi-disk"):
            unpack_package_archive(archive)

    def test_zipfile_itself_would_have_accepted_it(self) -> None:
        # The evidence for the class docstring's claim: if this ever starts
        # raising, `zipfile` grew its own refusal and the check above became
        # belt-and-braces rather than the only line of defense.
        archive = _patch_eocd(_make_zip([("a.txt", b"data")]), this_disk=1, cd_disk=1)
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            assert [info.filename for info in zf.infolist()] == ["a.txt"]

    def test_a_zip64_archive_is_supported(self) -> None:
        # The other half of the "explicit, never undefined" requirement: ZIP64
        # is read transparently by `zipfile` and is SUPPORTED here. Safe because
        # a ZIP64 size field is just a bigger declaration, and the bounds are
        # enforced against the bytes actually read as well.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", allowZip64=True) as zf:
            with zf.open("big.txt", "w", force_zip64=True) as member:
                member.write(b"y" * 4096)
        files = unpack_package_archive(buf.getvalue())
        assert [path for path, _mode, _data in files] == ["big.txt"]
        assert len(files[0][2]) == 4096


class TestZipResourceBounds:
    """SECURITY: the one piece of real new work in the zip path. A
    decompression bomb has to be stopped DURING transcode - by the time
    `unpack_hardened` sees a tar, the bomb has already been expanded in memory.
    Every bound below uses the SAME module constant as the tar path (monkey-
    patched down here, exactly as the tar bomb tests do) and every one of them
    is asserted to actually reject something."""

    def test_zip_over_max_archive_size_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Applied to the ZIP bytes: `unpack_hardened` will only ever see the
        # transcoded tar, whose size says nothing about the upload.
        monkeypatch.setattr(normalizer, "MAX_ARCHIVE_BYTES", 100)
        archive = _make_zip([("big.txt", b"x" * 4000)])
        assert len(archive) > 100
        with pytest.raises(UnpackRejected, match="archive size"):
            unpack_package_archive(archive)

    def test_declared_entry_count_over_max_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The early bound, read straight out of the end record BEFORE
        # `ZipFile.__init__` allocates one ZipInfo per entry.
        monkeypatch.setattr(normalizer, "MAX_ENTRY_COUNT", 10)
        archive = _make_zip([(f"file_{i}.txt", b"x") for i in range(20)])
        with pytest.raises(UnpackRejected, match="entry count 20 exceeds max 10"):
            unpack_package_archive(archive)

    def test_a_lying_entry_count_is_caught_by_the_measured_check(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The declared count is a declaration, not evidence: patched to 1 while
        # 20 entries really exist, so only the `len(infolist())` check can fire.
        monkeypatch.setattr(normalizer, "MAX_ENTRY_COUNT", 10)
        archive = _patch_eocd(
            _make_zip([(f"file_{i}.txt", b"x") for i in range(20)]), total_entries=1
        )
        with pytest.raises(UnpackRejected, match="entry count 20 exceeds max 10"):
            unpack_package_archive(archive)

    def test_single_file_over_max_declared_size_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(normalizer, "MAX_SINGLE_FILE_BYTES", 100)
        archive = _make_zip([("big.txt", b"x" * 4000)])
        with pytest.raises(UnpackRejected, match="declared size"):
            unpack_package_archive(archive)

    def test_total_uncompressed_size_over_max_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Accumulated from the bytes REALLY read, not from the declarations -
        # the same "measured bytes independent of the declared size" posture the
        # tar path takes.
        monkeypatch.setattr(normalizer, "MAX_SINGLE_FILE_BYTES", 1000)
        monkeypatch.setattr(normalizer, "MAX_TOTAL_UNCOMPRESSED_BYTES", 1500)
        monkeypatch.setattr(normalizer, "MAX_COMPRESSION_RATIO", 10_000)
        archive = _make_zip([(f"file_{i}.txt", b"x" * 800) for i in range(3)])
        with pytest.raises(UnpackRejected, match="total uncompressed size"):
            unpack_package_archive(archive)

    def test_a_decompression_bomb_is_rejected_at_the_real_limits(self) -> None:
        # NO monkeypatching: 8 MiB of zeros deflates to a few KB, i.e. a ratio
        # of ~1000 against a shipped MAX_COMPRESSION_RATIO of 100. This is the
        # case the tar path's own end-of-loop ratio check could not make for
        # zip: the tar handed onward is stored UNCOMPRESSED, so downstream the
        # ratio always looks like ~1 and the check is structurally blind.
        archive = _make_zip([("zeros.bin", b"\x00" * (8 * 1024 * 1024))])
        assert len(archive) < 64 * 1024
        with pytest.raises(UnpackRejected, match="compression ratio"):
            unpack_package_archive(archive)

    def test_the_ratio_is_checked_before_the_whole_bomb_is_expanded(self) -> None:
        # The check is inside the member loop, unlike the tar path's. With
        # entries far larger than the archive, the FIRST over-ratio member must
        # end it - nothing after it is read.
        monkeypatch_free = _make_zip([(f"z{i}.bin", b"\x00" * (1024 * 1024)) for i in range(8)])
        with pytest.raises(UnpackRejected, match="compression ratio"):
            unpack_package_archive(monkeypatch_free)

    def test_a_size_field_that_lies_is_rejected_not_silently_truncated(self) -> None:
        # A central-directory uncompressed-size field patched to 10 while the
        # member really holds 4000 bytes. Measured: `zipfile` stops at the
        # declared length and then fails the CRC, i.e. BadZipFile out of
        # `read()` - which must surface as a clean rejection rather than a
        # 4000-byte file silently becoming a 10-byte one.
        archive = _make_zip([("a.txt", b"x" * 4000)])
        raw = bytearray(archive)
        central = raw.find(b"PK\x01\x02")
        struct.pack_into("<I", raw, central + 24, 10)
        with pytest.raises(UnpackRejected, match="not a valid zip archive"):
            unpack_package_archive(bytes(raw))

    def test_the_transcoded_tar_must_itself_fit_the_archive_bound(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # THE DOCUMENTED ASYMMETRY: the transcoded tar is stored uncompressed
        # and still faces `unpack_hardened`'s MAX_ARCHIVE_BYTES, so 50 MiB is
        # the effective ceiling on a zip's TOTAL uncompressed payload where a
        # compressed tar may expand to 200 MiB. Zip is bounded more tightly
        # than tar, never less - deliberate, and this test is what would notice
        # if that ever silently inverted.
        monkeypatch.setattr(normalizer, "MAX_ARCHIVE_BYTES", 8192)
        # Incompressible payload, so the zip stays small while the tar (with its
        # 512-byte headers and 10 KiB record padding) does not.
        archive = _make_zip([("a.bin", bytes(range(256)) * 8)], compression=zipfile.ZIP_STORED)
        assert len(archive) < 8192
        tar_bytes = zip_to_tar_bytes(archive)
        assert len(tar_bytes) > 8192
        with pytest.raises(UnpackRejected, match="archive size"):
            unpack_package_archive(archive)

    def test_an_empty_upload_is_rejected(self) -> None:
        with pytest.raises(UnpackRejected, match="empty archive"):
            unpack_package_archive(b"")
