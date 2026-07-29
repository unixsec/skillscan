#!/usr/bin/env python3
"""§10A vendoring pipeline helper for the OSS engines vendored under
`vendor/<engine>/` (source committed directly into this repository, pinned
commit/tree/license recorded in `vendor/engines.lock.yaml`).

SECURITY: this script does NOT fetch or add new vendored source - pulling a new
upstream repo in is a deliberate, explicitly-authorized, one-time networked
action performed directly by an operator in a networked session (see
`vendor/VENDOR.md`'s introduction log), never something this script silently
automates on its own. What this script DOES automate, and runs with zero
network access:

  verify-pins    confirm the source committed under each `vendor/<engine>/`
                 still matches its recorded pin in engines.lock.yaml (drift
                 detection).
  license-scan   confirm each vendored engine's LICENSE/COPYING file is
                 consistent with its recorded license and stays on the
                 permissive allowlist (Apache-2.0/BSD-3-Clause/MIT); fail
                 closed on any GPL/LGPL/AGPL marker text found.
  status         print role/adapter_status per engine from engines.lock.yaml.

Run from the repo root: `python scripts/vendor_engines.py <command>`.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCK_FILE = REPO_ROOT / "vendor" / "engines.lock.yaml"
VENDOR_DIR = REPO_ROOT / "vendor"

# SECURITY: fail-closed allowlist - anything not explicitly here is rejected,
# never implicitly permitted.
_ALLOWED_LICENSES = frozenset({"Apache-2.0", "BSD-3-Clause", "MIT"})
_REJECTED_LICENSE_MARKERS = (
    "GNU GENERAL PUBLIC LICENSE",
    "GNU LESSER GENERAL PUBLIC LICENSE",
    "GNU AFFERO GENERAL PUBLIC LICENSE",
)
_LICENSE_FILENAMES = ("LICENSE", "LICENSE.txt", "COPYING")


def load_lock(lock_file: Path = LOCK_FILE) -> dict[str, dict[str, Any]]:
    payload = yaml.safe_load(lock_file.read_text())
    engines = payload.get("engines") if isinstance(payload, dict) else None
    if not isinstance(engines, dict):
        raise ValueError(f"{lock_file}: missing/malformed top-level 'engines' key")
    return engines


def vendored_engines(engines: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    # SECURITY: `repo: TBD` / a missing commit means never vendored - never
    # attempt to inspect a vendor/<name>/ directory that isn't real for those.
    return {
        name: spec
        for name, spec in engines.items()
        if spec.get("repo") != "TBD" and spec.get("commit")
    }


def submodule_dir_name(name: str, spec: dict[str, Any]) -> str:
    """The real on-disk vendor/ directory for this engine - `vendor_path` when
    the lock key doesn't match the actual directory name (e.g. `osv_scanner`'s
    key vs. the real `vendor/osv-scanner/`, which kept the upstream repo's own
    hyphenated name), else the key itself. Never assume key==directory without
    checking - that's exactly the drift verify-pins/license-scan exist to
    catch."""
    return str(spec.get("vendor_path", name))


def read_license_file(submodule_dir: Path) -> str | None:
    for candidate in _LICENSE_FILENAMES:
        path = submodule_dir / candidate
        if path.is_file():
            return path.read_text(errors="replace")
    return None


def committed_tree_hash(repo_root: Path, rel_path: str) -> str:
    """Git tree hash of `rel_path` as committed at HEAD of the repo at `repo_root`.

    HISTORY: this used to be `git -C vendor/<engine> rev-parse HEAD`, valid while
    each engine was a git submodule with its own `.git`. Since the 2026-07-29
    conversion to committed source there is no inner repository, and that old
    command does not fail - it walks UP to the superproject and cheerfully
    returns skillscan's own HEAD, so every engine reports a bogus DRIFT against
    a hash that has nothing to do with it. A wrong-but-plausible answer is worse
    than an error, hence the tree hash instead: it is taken from this
    repository's own HEAD and cannot be confused with anything else.

    Reading HEAD (not the working tree) is deliberate. It verifies what the
    repository actually ships, and it is immune to case-insensitive filesystems
    - on macOS 466 of aig's paths collide and simply cannot all exist on disk,
    so any working-tree-derived hash would be wrong there while the committed
    tree is correct everywhere.
    """
    result = subprocess.run(  # noqa: S603 - fixed argv, no untrusted input
        ["git", "-C", str(repo_root), "rev-parse", f"HEAD:{rel_path}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"`git -C {repo_root} rev-parse HEAD:{rel_path}` failed "
            f"(needs a real git checkout; a source export without .git cannot be "
            f"pin-verified): {result.stderr.strip()}"
        )
    return result.stdout.strip()


def verify_pins(
    engines: dict[str, dict[str, Any]],
    *,
    vendor_dir: Path = VENDOR_DIR,
    repo_root: Path = REPO_ROOT,
) -> list[str]:
    """Returns a list of human-readable failure messages; empty means clean.

    Compares the git tree hash committed under `vendor/<engine>/` against the
    `tree:` recorded in engines.lock.yaml. A tree hash covers every path, mode
    and byte beneath the directory, so this catches both a partial/incomplete
    vendoring and any edit to upstream source (which §10A.1 forbids outright).
    """
    failures: list[str] = []
    for name, spec in vendored_engines(engines).items():
        dir_name = submodule_dir_name(name, spec)
        engine_dir = vendor_dir / dir_name
        expected = str(spec.get("tree") or "")
        if not engine_dir.is_dir():
            failures.append(f"{name}: vendor/{dir_name}/ does not exist (expected tree {expected})")
            continue
        if not expected:
            failures.append(
                f"{name}: no `tree:` recorded in engines.lock.yaml - cannot verify the "
                f"committed source against its pin (see that file's header)"
            )
            continue
        try:
            actual = committed_tree_hash(repo_root, f"vendor/{dir_name}")
        except RuntimeError as exc:
            failures.append(f"{name}: {exc}")
            continue
        if actual != expected:
            failures.append(f"{name}: committed tree {actual} != pinned {expected} (DRIFT)")
    return failures


def license_scan(engines: dict[str, dict[str, Any]], *, vendor_dir: Path = VENDOR_DIR) -> list[str]:
    """Returns a list of human-readable failure messages; empty means clean."""
    failures: list[str] = []
    for name, spec in vendored_engines(engines).items():
        recorded_license = str(spec.get("license", ""))
        if recorded_license not in _ALLOWED_LICENSES:
            failures.append(
                f"{name}: recorded license {recorded_license!r} is not on the permissive "
                f"allowlist {sorted(_ALLOWED_LICENSES)}"
            )
            continue
        dir_name = submodule_dir_name(name, spec)
        submodule_dir = vendor_dir / dir_name
        license_text = read_license_file(submodule_dir)
        if license_text is None:
            failures.append(f"{name}: no LICENSE/COPYING file found in vendor/{dir_name}/")
            continue
        upper_text = license_text.upper()
        for marker in _REJECTED_LICENSE_MARKERS:
            if marker in upper_text:
                failures.append(
                    f"{name}: LICENSE file contains {marker!r} - contradicts recorded "
                    f"{recorded_license!r} (fail-closed on copyleft)"
                )
    return failures


def _cmd_verify_pins(_args: argparse.Namespace) -> int:
    engines = load_lock()
    failures = verify_pins(engines)
    if failures:
        print("PIN VERIFICATION FAILED:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(f"OK: {len(vendored_engines(engines))} vendored engine(s) match their recorded pin.")
    return 0


def _cmd_license_scan(_args: argparse.Namespace) -> int:
    engines = load_lock()
    failures = license_scan(engines)
    if failures:
        print("LICENSE SCAN FAILED:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(
        f"OK: {len(vendored_engines(engines))} vendored engine(s) pass the license allowlist scan."
    )
    return 0


def _cmd_status(_args: argparse.Namespace) -> int:
    engines = load_lock()
    width = max(len(name) for name in engines)
    for name, spec in sorted(engines.items()):
        role = str(spec.get("role", "?"))
        default_adapter_status = "n/a" if spec.get("repo") == "TBD" else "?"
        adapter_status = str(spec.get("adapter_status", default_adapter_status))
        print(f"{name:<{width}}  role={role:<10}  adapter_status={adapter_status}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    verify_parser = sub.add_parser(
        "verify-pins", help="confirm committed vendor/ source matches engines.lock.yaml"
    )
    verify_parser.set_defaults(func=_cmd_verify_pins)

    license_parser = sub.add_parser(
        "license-scan", help="confirm vendored engines pass the permissive-license allowlist"
    )
    license_parser.set_defaults(func=_cmd_license_scan)

    status_parser = sub.add_parser("status", help="print role/adapter_status per engine")
    status_parser.set_defaults(func=_cmd_status)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
