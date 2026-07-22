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
"""

from __future__ import annotations

import os
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

    def __init__(self, root: Path) -> None:
        self._root = root
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
        # newly created level - from the shallowest missing ancestor down to
        # `path` - gets created and fixed one at a time, root-to-leaf.
        missing = []
        cur = path
        while not cur.exists():
            missing.append(cur)
            cur = cur.parent
        for directory in reversed(missing):
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
