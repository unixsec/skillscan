"""Shared-blobstore probe (里程碑 E spec §4.3).

Pure filesystem work, no infra needed.
"""

from __future__ import annotations

import logging
import pathlib

import pytest
from common.blobstore import (
    ENGINE_RUNNER_PROBE_ROLE,
    MONOLITH_PROBE_ROLE,
    NOT_SHARED_MESSAGE,
    LocalFilesystemBlobStore,
    ShareProbeMonitor,
    log_share_status,
    probe_identity,
    share_probe,
)


class TestShareProbe:
    def test_two_stores_on_the_same_root_see_each_other(self, tmp_path: pathlib.Path) -> None:
        a = LocalFilesystemBlobStore(str(tmp_path))
        b = LocalFilesystemBlobStore(str(tmp_path))
        share_probe(a, identity="monolith-1", now=1000.0)
        share_probe(b, identity="runner-1", now=1000.0)
        assert share_probe(a, identity="monolith-1", now=1001.0).peers == {"runner-1"}

    def test_two_stores_on_different_roots_see_nobody(self, tmp_path: pathlib.Path) -> None:
        # The failure this whole probe exists to make visible: each pod has its
        # own volume, nothing errors, and scans would silently never complete.
        a = LocalFilesystemBlobStore(str(tmp_path / "a"))
        b = LocalFilesystemBlobStore(str(tmp_path / "b"))
        share_probe(a, identity="monolith-1", now=1000.0)
        share_probe(b, identity="runner-1", now=1000.0)
        assert share_probe(a, identity="monolith-1", now=1001.0).peers == set()

    def test_a_stale_peer_ages_out(self, tmp_path: pathlib.Path) -> None:
        a = LocalFilesystemBlobStore(str(tmp_path))
        share_probe(a, identity="ghost", now=0.0)
        result = share_probe(a, identity="live", now=10_000.0)
        assert "ghost" not in result.peers, "probe files must not accumulate across restarts"

    def test_a_stale_probe_file_is_deleted_not_just_ignored(self, tmp_path: pathlib.Path) -> None:
        # Pod names are unique per restart, so an ignored-but-kept file would
        # grow without bound for the life of the volume.
        a = LocalFilesystemBlobStore(str(tmp_path))
        share_probe(a, identity="ghost", now=0.0)
        share_probe(a, identity="live", now=10_000.0)
        assert [p.name for p in (tmp_path / "_probe").iterdir()] == ["live"]

    def test_an_identity_cannot_escape_the_probe_directory(self, tmp_path: pathlib.Path) -> None:
        store = LocalFilesystemBlobStore(str(tmp_path))
        with pytest.raises(ValueError, match="file-name safe"):
            share_probe(store, identity="../../etc/passwd", now=1000.0)


class TestShareProbeMonitor:
    """The readiness decision on top of `share_probe`: grace window + which
    peer actually counts."""

    def _monitor(
        self, root: pathlib.Path, *, role: str, peer_role: str, instance: str, started_at: float
    ) -> ShareProbeMonitor:
        return ShareProbeMonitor(
            LocalFilesystemBlobStore(root),
            identity=probe_identity(role, instance),
            peer_role=peer_role,
            started_at=started_at,
        )

    def _monolith(
        self, root: pathlib.Path, *, instance: str, started_at: float
    ) -> ShareProbeMonitor:
        return self._monitor(
            root,
            role=MONOLITH_PROBE_ROLE,
            peer_role=ENGINE_RUNNER_PROBE_ROLE,
            instance=instance,
            started_at=started_at,
        )

    def test_unshared_store_is_not_ready_once_the_grace_window_closes(
        self, tmp_path: pathlib.Path
    ) -> None:
        monitor = self._monolith(tmp_path / "vol-a", instance="pod-1", started_at=0.0)
        assert monitor.check(now=30.0).ready is True, "still inside the 60s grace window"
        status = monitor.check(now=90.0)
        assert status.ready is False
        assert status.peers == frozenset()

    def test_grace_window_covers_a_peer_that_starts_late(self, tmp_path: pathlib.Path) -> None:
        # The two pods never become ready at the same instant; without this the
        # very first install always goes red before it goes green.
        monitor = self._monolith(tmp_path, instance="pod-1", started_at=0.0)
        assert monitor.check(now=10.0).ready is True
        peer = self._monitor(
            tmp_path,
            role=ENGINE_RUNNER_PROBE_ROLE,
            peer_role=MONOLITH_PROBE_ROLE,
            instance="pod-2",
            started_at=40.0,
        )
        peer.check(now=40.0)
        status = monitor.check(now=90.0)
        assert status.ready is True
        assert status.peers == {"engine-runner-pod-2"}

    def test_a_sibling_replica_does_not_count_as_the_peer(self, tmp_path: pathlib.Path) -> None:
        # Two monolith replicas on one PVC see each other. That says nothing
        # about the engine-runner, which is the process this check is about -
        # counting it would report healthy on the exact broken deployment this
        # whole mechanism exists to catch.
        replica_1 = self._monolith(tmp_path, instance="pod-1", started_at=0.0)
        replica_2 = self._monolith(tmp_path, instance="pod-2", started_at=0.0)
        replica_2.check(now=100.0)
        assert replica_1.check(now=101.0).ready is False

    def test_a_peer_that_stops_writing_eventually_makes_this_unready(
        self, tmp_path: pathlib.Path
    ) -> None:
        monitor = self._monolith(tmp_path, instance="pod-1", started_at=0.0)
        peer = self._monitor(
            tmp_path,
            role=ENGINE_RUNNER_PROBE_ROLE,
            peer_role=MONOLITH_PROBE_ROLE,
            instance="pod-2",
            started_at=0.0,
        )
        peer.check(now=100.0)
        assert monitor.check(now=100.0).ready is True
        assert monitor.check(now=399.0).ready is True, "still within the 300s TTL"
        assert monitor.check(now=401.0).ready is False


class TestShareStatusLogging:
    def test_the_error_carries_the_string_the_deployment_guide_greps_for(
        self, tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        monitor = ShareProbeMonitor(
            LocalFilesystemBlobStore(tmp_path),
            identity="monolith-pod-1",
            peer_role=ENGINE_RUNNER_PROBE_ROLE,
            started_at=0.0,
        )
        logger = logging.getLogger("test.share.probe")
        with caplog.at_level(logging.INFO):
            log_share_status(logger, monitor.check(now=999.0), peer_role=monitor.peer_role)
        assert "blobstore not shared" in NOT_SHARED_MESSAGE
        errors = [r for r in caplog.records if r.levelno == logging.ERROR]
        assert len(errors) == 1
        assert "blobstore not shared" in errors[0].getMessage()

    def test_a_healthy_store_says_so_once(
        self, tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        # A silent happy path leaves an operator with nothing to confirm.
        peer = ShareProbeMonitor(
            LocalFilesystemBlobStore(tmp_path),
            identity="engine-runner-pod-2",
            peer_role=MONOLITH_PROBE_ROLE,
            started_at=0.0,
        )
        peer.check(now=100.0)
        monitor = ShareProbeMonitor(
            LocalFilesystemBlobStore(tmp_path),
            identity="monolith-pod-1",
            peer_role=ENGINE_RUNNER_PROBE_ROLE,
            started_at=0.0,
        )
        logger = logging.getLogger("test.share.probe.ok")
        with caplog.at_level(logging.INFO):
            for now in (100.0, 115.0, 130.0):
                log_share_status(logger, monitor.check(now=now), peer_role=monitor.peer_role)
        confirmations = [r for r in caplog.records if "sharing confirmed" in r.getMessage()]
        assert len(confirmations) == 1
        assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


class TestTornReads:
    def test_a_half_written_peer_file_is_not_deleted(self, tmp_path: pathlib.Path) -> None:
        # A peer rewriting its own probe file can be read mid-write. Deleting
        # on that would drop a healthy peer out of view for a whole interval.
        store = LocalFilesystemBlobStore(tmp_path)
        share_probe(store, identity="peer", now=1000.0)
        (tmp_path / "_probe" / "peer").write_bytes(b"")
        result = share_probe(store, identity="self", now=1001.0)
        assert result.peers == frozenset()
        assert (tmp_path / "_probe" / "peer").exists()
        (tmp_path / "_probe" / "peer").write_text("1001.0")
        assert share_probe(store, identity="self", now=1002.0).peers == {"peer"}
