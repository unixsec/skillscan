"""Object storage port + local-filesystem test substitute (coding spec §8 MinIO
bucket layout).

SECURITY: this module defines the `BlobStorePort` interface a real MinIO-backed
implementation would satisfy in production; `LocalFilesystemBlobStore` is a
**local testing substitute only** (this dev environment's MinIO build doesn't run
on this macOS version - see docs/USER_GUIDE.md §8.3) - it is NOT S3-compatible,
has no real access-control between prefixes, and must never be used outside
local development/testing.

Bucket layout (both implementations honor the same key structure):
  artifacts/<content_hash>/pkg.tar   - pre-normalization artifact (gateway writes, sandbox reads)
  findings/<scan_id>/<engine>.json  - sandbox writes only this prefix, monolith reads
  _probe/<identity>                 - shared-store self-check, see `share_probe` below

DEPENDENCIES: stdlib only, deliberately - this module is imported by
`libs/skillscan_core`-adjacent code and by the engine-runner sandbox, and the
share probe below has to keep working in both.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class BlobNotFoundError(Exception):
    pass


def _shared_group_gid() -> int | None:
    """The supplementary group this process shares with whichever OTHER
    process might also write here, if any - e.g. Kubernetes' `fsGroup`, which
    always lands as a supplementary group on a container's own process (this
    part of fsGroup's effect applies to every volume type) even on the
    hostPath dev fallback, where fsGroup's normal "chown the volume contents"
    behavior does NOT apply (a documented Kubernetes limitation - kubelet only
    manages ownership for volume types it actually provisions, not
    pre-existing hostPath directories). Returns the first supplementary group
    that isn't this process's own primary gid, or None outside that context
    (e.g. a local pytest run) - callers fall back to owner-only permissions
    there, which is correct since nothing else is writing to the same path.
    """
    primary = os.getegid()
    for gid in os.getgroups():
        if gid != primary:
            return gid
    return None


class BlobStorePort(Protocol):
    def put(self, key: str, data: bytes) -> None: ...
    def get(self, key: str) -> bytes: ...
    def list_prefix(self, prefix: str) -> list[str]: ...
    def exists(self, key: str) -> bool: ...


class ShareProbeStore(Protocol):
    """What `share_probe` needs - deliberately NOT `BlobStorePort` + `delete`:
    widening `BlobStorePort` itself would hand every consumer of a blob store
    (orchestration, the engine-runner worker) the ability to delete artifacts
    and findings, which nothing in this system is allowed to do."""

    def put(self, key: str, data: bytes) -> None: ...
    def get(self, key: str) -> bytes: ...
    def list_prefix(self, prefix: str) -> list[str]: ...
    def delete(self, key: str) -> None: ...


def artifact_key(content_hash: str) -> str:
    return f"artifacts/{content_hash}/pkg.tar"


def findings_key(scan_id: str, engine: str) -> str:
    return f"findings/{scan_id}/{engine}.json"


class LocalFilesystemBlobStore:
    """SECURITY: LOCAL TESTING SUBSTITUTE ONLY - not S3-compatible, not access-
    controlled between prefixes the way MinIO's per-credential bucket policies
    are (coding spec §8: sandbox credentials are artifacts/* read-only +
    findings/* write-only; this class enforces neither, it just maps keys to
    file paths). Never point production configuration at this class.
    """

    def __init__(self, root: Path | str) -> None:
        # `str` accepted as well as `Path` because every real caller starts
        # from a string (`SKILLSCAN_BLOBSTORE_ROOT`) - passing it straight
        # through used to blow up on `.exists()` with a bare AttributeError
        # instead of doing the obvious thing.
        self._root = Path(root)
        if not self._root.exists():
            self._root.mkdir(parents=True)
            self._fix_permissions(self._root)

    def _path_for(self, key: str) -> Path:
        # SECURITY: reject traversal in the key itself - even though this is a
        # local test double, a key derived from attacker-influenced data (e.g. a
        # scan_id) must not be able to escape the store root.
        normalized = Path(key)
        if normalized.is_absolute() or ".." in normalized.parts:
            raise ValueError(f"blob key must be a relative path with no '..': {key!r}")
        return self._root / normalized

    def _fix_permissions(self, path: Path) -> None:
        # SECURITY/BUG (found via a real 200-skill bulk-import test, 2026-07-22:
        # 100% of scans' sandbox-engine writes failed with EACCES): on the k3s
        # hostPath dev fallback, monolith and the sandboxed engine-runner write
        # into the SAME findings/<scan_id>/ directory tree as two DIFFERENT
        # uids. `fsGroup` in the Deployment spec does NOT fix this on its own -
        # it's a documented Kubernetes limitation that fsGroup's ownership/
        # permission adjustment does not apply to hostPath volumes (only to
        # volume types kubelet actually provisions, e.g. emptyDir/PVC). So
        # whichever process creates a given directory level first "owns" it at
        # whatever mode its own umask leaves (typically 0755), and the OTHER
        # process's later write into (or new-subdirectory-creation under) that
        # same directory fails closed.
        #
        # Fix: whoever creates a directory chgrp's it to the shared fsGroup
        # (present as a supplementary group on BOTH processes even though the
        # volume's own ownership was never adjusted) and chmods it 0o2770 -
        # group rwx + setgid (so files/subdirs created inside inherit this
        # group, not the creator's own primary gid) - deliberately NOT
        # world-writable/0o777: an earlier draft used 0o777, which a security
        # review correctly flagged as broader than necessary - only the two
        # processes that share this fsGroup can write here, not every local
        # process on the node. A chown/chmod attempt on a directory some OTHER
        # uid already created (and already fixed, by this same code) fails
        # with PermissionError since we're not its owner - expected and fine,
        # swallow it rather than let it block the caller. Outside a shared-
        # group context (e.g. a local pytest run), 0o770 owner-only is used;
        # nothing else is writing to the same path there.
        shared_gid = _shared_group_gid()
        try:
            if shared_gid is not None:
                os.chown(path, -1, shared_gid)
                path.chmod(0o2770)
            else:
                path.chmod(0o770)
        except PermissionError:
            pass

    def _mkdir_shared(self, path: Path) -> None:
        # CORRECTNESS: a single `mkdir(parents=True)` call can create MULTIPLE
        # missing directory levels in one step (e.g. both the `findings/`
        # prefix AND `findings/<scan_id>/` under it, the first time this store
        # is used since a fresh volume wipe). Fixing permissions only on the
        # deepest (leaf) level - as an earlier draft of this fix did - misses
        # any INTERMEDIATE level created in that same call: whichever uid
        # happened to create `findings/` itself then permanently owns it at
        # its default restrictive mode, and the other uid can never create a
        # NEW scan_id subdirectory under it afterwards (the failure surfaces
        # at the mkdir() syscall itself, before any chmod ever runs). So every
        # level - from the shallowest ancestor below `self._root` down to
        # `path` - gets created (if missing) and (re-)fixed, every call.
        #
        # BUG (found via a real 251-skill bulk-import test, 2026-07-23): an
        # earlier version of this method only called `_fix_permissions()` on
        # levels it just created in THIS call, never on ones that already
        # existed. That leaves two live gaps: (1) any directory created before
        # this fix existed in the deployed code stays permanently broken -
        # 333 such directories were found permanently EACCES-looping in
        # Redis's sandbox-dispatch consumer group (delivery counts 1100+),
        # since nothing ever revisited them; (2) `artifacts/<content_hash>/`
        # keys the same content_hash for repeat/duplicate submissions of
        # identical skill content, so a genuinely NEW submission can land on
        # an OLD, already-existing artifact directory. Re-applying
        # `_fix_permissions()` unconditionally - even to a directory this
        # call didn't create - closes both gaps: if we own that directory, the
        # chgrp/chmod succeeds and repairs it; if we don't, `_fix_permissions`
        # already swallows the resulting PermissionError, same as before.
        chain = []
        cur = path
        while cur != self._root:
            chain.append(cur)
            cur = cur.parent
        for directory in reversed(chain):
            if not directory.exists():
                directory.mkdir(exist_ok=True)
            self._fix_permissions(directory)

    def put(self, key: str, data: bytes) -> None:
        path = self._path_for(key)
        self._mkdir_shared(path.parent)
        path.write_bytes(data)

    def get(self, key: str) -> bytes:
        path = self._path_for(key)
        if not path.is_file():
            raise BlobNotFoundError(key)
        return path.read_bytes()

    def exists(self, key: str) -> bool:
        return self._path_for(key).is_file()

    def list_prefix(self, prefix: str) -> list[str]:
        base = self._path_for(prefix)
        if not base.is_dir():
            return []
        return sorted(str(p.relative_to(self._root)) for p in base.rglob("*") if p.is_file())

    def delete(self, key: str) -> None:
        """Only the share probe needs this (expiring another pod's stale probe
        file); deleting an artifact or a finding is not something any caller
        in this system does, by design - the audit trail depends on them."""
        self._path_for(key).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Shared-store self-check (里程碑 E spec §4.3)
# ---------------------------------------------------------------------------
#
# CORRECTNESS: the monolith writes `artifacts/<hash>/pkg.tar`, the engine-runner
# reads it and writes `findings/<scan_id>/<engine>.json` back, and the monolith
# reads THAT. If the two processes are not looking at the same store, NOTHING
# ERRORS: every pod is Running, /healthz is 200, the logs are clean, and scans
# simply sit at RUNNING forever - the collector is waiting for a findings blob
# that is being written somewhere it will never look. On a first air-gapped
# install (two pods, two PVCs, one typo) that is close to undiagnosable.
#
# So each process writes a probe file naming itself and checks whether it can
# see the other's. Nothing else in this module has an opinion about who else is
# running; this is the only part that does, deliberately.

PROBE_PREFIX = "_probe"
SHARE_PROBE_TTL_S = 300.0
# The grace window is load-bearing, not politeness: the two pods never become
# ready at the same instant (the engine-runner retries its Redis consumer group
# for up to 60s before its first tick), so without it EVERY first install goes
# red before it goes green and the deployment guide has to explain away a
# failure that is not one.
SHARE_PROBE_GRACE_S = 60.0
SHARE_PROBE_INTERVAL_S = 15.0

MONOLITH_PROBE_ROLE = "monolith"
ENGINE_RUNNER_PROBE_ROLE = "engine-runner"

# The deployment guide's troubleshooting section is indexed by symptom and this
# exact string is the anchor for its first entry - `kubectl logs ... | grep
# 'blobstore not shared'`. Do not reword it without updating that section.
NOT_SHARED_MESSAGE = (
    "blobstore not shared: no peer probe file is visible in this process's blob "
    "store, so the monolith and the engine-runner are using DIFFERENT stores - "
    "scans will stay RUNNING forever without any error being raised"
)

_UNSAFE_IDENTITY_CHARS = re.compile(r"[^A-Za-z0-9._-]")


def probe_identity(role: str, instance: str) -> str:
    """`<role>-<instance>`, reduced to something safe to use as a file name.

    Pure: the caller supplies the instance name (pod name / hostname); this
    never reads the environment and never reads the clock.
    """
    safe = _UNSAFE_IDENTITY_CHARS.sub("-", f"{role}-{instance}").strip("-.")
    return (safe or role)[:120]


@dataclass(frozen=True)
class ShareProbeResult:
    identity: str
    peers: frozenset[str]
    # Peers whose probe file was older than the TTL. Reported rather than
    # silently dropped so an operator can tell "the other side was never here"
    # from "the other side was here and stopped".
    expired: frozenset[str]


def share_probe(
    store: ShareProbeStore,
    *,
    identity: str,
    now: float,
    ttl_s: float = SHARE_PROBE_TTL_S,
) -> ShareProbeResult:
    """Announce this process in the store and report which peers it can see.

    Writes `_probe/<identity>` (content: `now`), then reads every OTHER file in
    `_probe/`, discarding any written more than `ttl_s` ago - pod names are
    unique per restart, so without expiry these files would accumulate for the
    life of the volume and a long-dead pod would keep vouching for a store that
    nobody is sharing any more. Expired files are deleted (best effort: the
    peer that wrote one is a different uid, so the unlink may be refused - that
    is not this process's problem to solve, the TTL already handled the lie).

    `now` is a parameter, never `time.time()` read in here: this has to be
    testable without sleeping, and both sides have to agree on the same time
    base (wall clock, since the two processes are in different containers -
    monotonic clocks are not comparable across them).
    """
    # SECURITY: the identity becomes a file name under `_probe/` - reject
    # anything that isn't, rather than relying on `_path_for`'s traversal check
    # downstream (a MinIO-backed store wouldn't have that check at all).
    if not identity or identity in {".", ".."} or _UNSAFE_IDENTITY_CHARS.search(identity):
        raise ValueError(f"probe identity must be file-name safe: {identity!r}")
    key = f"{PROBE_PREFIX}/{identity}"
    store.put(key, f"{now}".encode())

    peers: set[str] = set()
    expired: set[str] = set()
    for peer_key in store.list_prefix(PROBE_PREFIX):
        name = peer_key.rsplit("/", 1)[-1]
        if name == identity:
            continue
        try:
            written = float(store.get(peer_key).decode("utf-8").strip())
        except (BlobNotFoundError, OSError, UnicodeDecodeError, ValueError):
            # Unreadable or half-written: not counted as a peer this round, and
            # deliberately NOT deleted. A peer rewriting its own probe file can
            # be read mid-write; deleting on that would take a healthy peer out
            # of view for a full interval and flap /readyz for no reason. Its
            # next write makes it readable again, and if the peer is really
            # gone the TTL below expires it on a later pass.
            continue
        if now - written > ttl_s:
            expired.add(name)
            try:
                store.delete(peer_key)
            except OSError:
                # A different uid wrote it; the TTL already discounted it,
                # whether or not this process is allowed to unlink it.
                pass
            continue
        peers.add(name)

    return ShareProbeResult(identity=identity, peers=frozenset(peers), expired=frozenset(expired))


@dataclass(frozen=True)
class ShareStatus:
    """The readiness view of the probe: `ready` is what `/readyz` reports."""

    identity: str
    ready: bool
    peers: frozenset[str]
    in_grace: bool
    checked_at: float | None
    # True when this check flipped `ready` - lets a caller log the recovery
    # once instead of on every tick.
    changed: bool


class ShareProbeMonitor:
    """Repeated `share_probe` calls plus the grace window, with no clock of its
    own - every method that needs the time takes it as an argument, same as
    `share_probe` itself.

    `peer_role` matters more than it looks: with two monolith replicas on one
    PVC, "I can see SOME peer" is true even when the engine-runner is mounted
    somewhere else entirely - which is the exact failure this whole mechanism
    exists to catch. Each side looks for the OTHER role specifically.
    """

    def __init__(
        self,
        store: ShareProbeStore,
        *,
        identity: str,
        peer_role: str,
        started_at: float,
        grace_s: float = SHARE_PROBE_GRACE_S,
        ttl_s: float = SHARE_PROBE_TTL_S,
    ) -> None:
        self._store = store
        self._identity = identity
        self._peer_prefix = f"{peer_role}-"
        self._started_at = started_at
        self._grace_s = grace_s
        self._ttl_s = ttl_s
        # Starts ready: an unchecked store must not take a pod out of rotation
        # before the first probe has even run.
        self._status = ShareStatus(
            identity=identity,
            ready=True,
            peers=frozenset(),
            in_grace=True,
            checked_at=None,
            changed=False,
        )

    @property
    def identity(self) -> str:
        return self._identity

    @property
    def status(self) -> ShareStatus:
        return self._status

    @property
    def peer_role(self) -> str:
        return self._peer_prefix.rstrip("-")

    def check(self, now: float) -> ShareStatus:
        result = share_probe(self._store, identity=self._identity, now=now, ttl_s=self._ttl_s)
        peers = frozenset(p for p in result.peers if p.startswith(self._peer_prefix))
        in_grace = (now - self._started_at) < self._grace_s
        ready = bool(peers) or in_grace
        status = ShareStatus(
            identity=self._identity,
            ready=ready,
            peers=peers,
            in_grace=in_grace,
            checked_at=now,
            # The first check counts as a change so that a healthy deployment
            # says so ONCE in its logs. Without this the happy path is
            # completely silent, and "no log line" is not something an operator
            # following the deployment guide can confirm anything from.
            changed=self._status.checked_at is None or ready != self._status.ready,
        )
        self._status = status
        return status


def log_share_status(logger: logging.Logger, status: ShareStatus, *, peer_role: str) -> None:
    """Emit the one log line the deployment guide tells operators to grep for.

    Lives here rather than in each process's own main so the message text and
    the level cannot drift apart between the two - the guide indexes the
    troubleshooting entry by this exact string, in both processes' logs.
    The logger is passed in so this module keeps importing nothing but stdlib.

    Logged on EVERY failing check, not only on the transition into failure: a
    deployment that has been silently broken for an hour must still be
    diagnosable from the last few minutes of logs.
    """
    context = {
        "identity": status.identity,
        "expected_peer_role": peer_role,
        "peers_seen": sorted(status.peers),
    }
    if not status.ready:
        logger.error(
            NOT_SHARED_MESSAGE, extra={"context": {"metric": "blobstore_not_shared", **context}}
        )
    elif status.peers and status.changed:
        # `status.peers` guard: during the grace window a process with no peer
        # yet is "ready", and announcing sharing it has not observed would be
        # the exact false reassurance this check exists to prevent.
        logger.info(
            "blobstore sharing confirmed",
            extra={"context": {"metric": "blobstore_shared", **context}},
        )
