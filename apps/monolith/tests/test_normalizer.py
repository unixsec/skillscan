"""Tests for `engine_runner.normalizer` (coding spec §11.4 M4 acceptance bar:
malicious corpus doesn't crash/DoS the unpacker). Pure, no infra needed.

NOTE: several tests monkeypatch the module's size/count constants down to
small values rather than constructing literal 200MB+ payloads - this exercises
the exact same code paths at a speed suitable for a unit test.
"""

from __future__ import annotations

import io
import tarfile
from typing import Literal

import pytest
from engine_runner import normalizer
from engine_runner.normalizer import UnpackRejected, unpack_hardened


def _make_tar(entries: list[tuple[str, bytes]], *, mode: Literal["w", "w:gz"] = "w") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tar:
        for name, data in entries:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


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
        with pytest.raises(UnpackRejected, match="not a valid tar"):
            unpack_hardened(b"this is not a tar archive at all, just junk bytes")

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
        # not a reachable-via-tar path.
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
