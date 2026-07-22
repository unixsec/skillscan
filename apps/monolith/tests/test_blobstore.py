"""Tests for libs/common/blobstore.py's LocalFilesystemBlobStore.

Focus is the 2026-07-22 EACCES regression: a real 200-skill bulk-import test
found that on the k3s hostPath dev fallback, monolith and the sandboxed
engine-runner write into the same findings/<scan_id>/ directory as two
different uids, and fsGroup does not fix cross-uid write access for hostPath
volumes (a documented Kubernetes limitation - fsGroup only adjusts volume
types kubelet actually manages, not hostPath). 100% of scans in that test lost
all sandbox-engine (bandit/yara/osv-scanner/skillspector) coverage.

SECURITY: an earlier draft of the fix used a blanket 0o777 (world-writable) -
a review correctly flagged that as broader than necessary. The shipped fix
instead chgrp's to the fsGroup shared between the two processes and uses
0o2770 (group rwx + setgid, no access for anyone outside that group).

CORRECTNESS: a second draft only fixed the leaf `findings/<scan_id>/`
directory, missing that `mkdir(parents=True)` can create the `findings/`
PREFIX directory itself in the same call the first time the store is used -
whichever uid created that intermediate level then permanently locked the
other uid out of ever creating a NEW scan_id subdirectory under it (found via
a real redeploy + fresh bulk-import re-verification, not by inspection). The
shipped fix walks every newly created level, not just the deepest one.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from common.blobstore import BlobNotFoundError, LocalFilesystemBlobStore, _shared_group_gid


class TestSharedGroupGid:
    def test_returns_a_supplementary_group_when_present(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("os.getegid", lambda: 999)
        monkeypatch.setattr("os.getgroups", lambda: [999, 10000])
        assert _shared_group_gid() == 10000

    def test_returns_none_when_no_supplementary_group(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("os.getegid", lambda: 999)
        monkeypatch.setattr("os.getgroups", lambda: [999])
        assert _shared_group_gid() is None


class TestPutDirectoryPermissions:
    def test_never_world_writable(self, tmp_path: Path) -> None:
        # The security property that actually matters, regardless of which
        # branch (shared-group vs owner-only fallback) this test process
        # happens to take.
        store = LocalFilesystemBlobStore(tmp_path)
        store.put("findings/scan-1/bandit.json", b"{}")
        mode = stat.S_IMODE((tmp_path / "findings" / "scan-1").stat().st_mode)
        assert not (mode & stat.S_IWOTH), (
            f"directory mode {oct(mode)} is writable by 'other' - this should "
            "never be world-writable, only shared-group-writable"
        )

    def test_with_shared_group_chowns_and_sets_group_writable_setgid(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Simulates the real k8s fsGroup scenario: chgrp to the shared group,
        # mode 0o2770 (group rwx + setgid), no access for anyone else.
        monkeypatch.setattr("common.blobstore._shared_group_gid", lambda: os.getegid())
        store = LocalFilesystemBlobStore(tmp_path)
        store.put("findings/scan-1/bandit.json", b"{}")
        st = (tmp_path / "findings" / "scan-1").stat()
        mode = stat.S_IMODE(st.st_mode)
        assert mode == 0o2770, f"expected 0o2770 (group rwx + setgid), got {oct(mode)}"
        assert st.st_gid == os.getegid()

    def test_without_shared_group_falls_back_to_owner_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("common.blobstore._shared_group_gid", lambda: None)
        store = LocalFilesystemBlobStore(tmp_path)
        store.put("findings/scan-1/bandit.json", b"{}")
        mode = stat.S_IMODE((tmp_path / "findings" / "scan-1").stat().st_mode)
        assert mode == 0o770

    def test_intermediate_prefix_directory_is_also_fixed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # CORRECTNESS regression lock: the very first put() under a brand-new
        # prefix creates BOTH `findings/` and `findings/<scan_id>/` in one go.
        # An earlier draft only fixed the leaf - the `findings/` prefix itself
        # stayed at its default restrictive mode, permanently owned by
        # whichever uid happened to create it first. That uid's OWN later
        # writes always succeed (it owns `findings/`), which is exactly why
        # this gap survived an initial round of real-world re-verification
        # before a second, fresh scan_id from the OTHER process's ordering
        # exposed it. Both levels must come out fixed from a single put().
        monkeypatch.setattr("common.blobstore._shared_group_gid", lambda: os.getegid())
        store = LocalFilesystemBlobStore(tmp_path)
        store.put("findings/scan-1/bandit.json", b"{}")
        for rel in ("findings", "findings/scan-1"):
            st = (tmp_path / rel).stat()
            mode = stat.S_IMODE(st.st_mode)
            assert mode == 0o2770, f"{rel}: expected 0o2770, got {oct(mode)}"
            assert st.st_gid == os.getegid(), f"{rel}: group not chowned to the shared gid"

    def test_new_leaf_under_an_already_existing_prefix_still_gets_fixed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The `findings/` prefix already exists (as if created by an EARLIER
        # scan) by the time a BRAND NEW scan_id's directory needs creating.
        # Only the new leaf is created this time - it must still come out
        # fixed on its own.
        monkeypatch.setattr("common.blobstore._shared_group_gid", lambda: os.getegid())
        store = LocalFilesystemBlobStore(tmp_path)
        store.put("findings/scan-1/bandit.json", b"{}")
        store.put("findings/scan-2/yara.json", b"{}")
        mode = stat.S_IMODE((tmp_path / "findings" / "scan-2").stat().st_mode)
        assert mode == 0o2770

    def test_second_write_into_an_existing_directory_does_not_raise(self, tmp_path: Path) -> None:
        # Simulates the real failure shape: mkdir(exist_ok=True) is a silent
        # no-op on an already-existing directory (created moments earlier by
        # "the other process"), so a chown/chmod attempt there can raise
        # PermissionError if we're not its owner - that must be swallowed, not
        # let it prevent the actual write.
        store = LocalFilesystemBlobStore(tmp_path)
        store.put("findings/scan-1/bandit.json", b"first")
        store.put("findings/scan-1/yara.json", b"second")
        assert store.get("findings/scan-1/bandit.json") == b"first"
        assert store.get("findings/scan-1/yara.json") == b"second"

    def test_writes_across_multiple_scan_ids_all_succeed(self, tmp_path: Path) -> None:
        store = LocalFilesystemBlobStore(tmp_path)
        for i in range(5):
            store.put(f"findings/scan-{i}/bandit.json", f"{i}".encode())
        for i in range(5):
            assert store.get(f"findings/scan-{i}/bandit.json") == f"{i}".encode()


class TestExistingBehaviorUnchanged:
    """Regression guard: the permission fix must not break ordinary put/get/
    exists/list_prefix behavior."""

    def test_round_trip(self, tmp_path: Path) -> None:
        store = LocalFilesystemBlobStore(tmp_path)
        store.put("artifacts/abc/pkg.tar", b"payload")
        assert store.exists("artifacts/abc/pkg.tar")
        assert store.get("artifacts/abc/pkg.tar") == b"payload"

    def test_missing_key_raises_not_found(self, tmp_path: Path) -> None:
        store = LocalFilesystemBlobStore(tmp_path)
        try:
            store.get("nope")
        except BlobNotFoundError:
            pass
        else:
            raise AssertionError("expected BlobNotFoundError")

    def test_list_prefix(self, tmp_path: Path) -> None:
        store = LocalFilesystemBlobStore(tmp_path)
        store.put("findings/scan-1/bandit.json", b"{}")
        store.put("findings/scan-1/yara.json", b"{}")
        store.put("findings/scan-2/bandit.json", b"{}")
        assert store.list_prefix("findings/scan-1") == [
            "findings/scan-1/bandit.json",
            "findings/scan-1/yara.json",
        ]
