#!/usr/bin/env python3
"""Fail if a monolith module imports ANOTHER module's ORM classes.

ARCHITECTURE: each module under `apps/monolith/modules/` owns its own tables and
its own least-privilege MySQL user (`policies/grants/manifest.yaml`). MySQL
enforces that boundary for real - `test_grant_isolation.py` proves cross-module
writes are refused by the database itself. What nothing enforced until this
script is the *code* side of the same boundary: a module importing another
module's ORM classes and issuing its own `select()` against them routes around
the owning module's service layer entirely, so that module can no longer change
its schema or query semantics without silently breaking a caller it has no
reason to know about.

Why this is not a ruff rule: flake8-tidy-imports' `banned-api` resolves relative
imports to their absolute path before matching, so `from .models import X` and
`from monolith.modules.other.models import X` look identical to it. It cannot
express "your own models are fine, another module's are not" and flags all 74
`*.models` imports in this repo. That distinction is the entire rule, hence a
purpose-built check.

Tests are exempt: they legitimately reach across modules to set up and assert on
real rows (that is what `test_grant_isolation.py` is *for*).

Usage:
    uv run python scripts/check_import_boundaries.py            # check
    uv run python scripts/check_import_boundaries.py --update   # rewrite baseline
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULES_DIR = REPO_ROOT / "apps" / "monolith" / "modules"
BASELINE_PATH = Path(__file__).resolve().parent / "import_boundaries_baseline.txt"

# Pre-existing violations, recorded rather than fixed: untangling them means
# designing real service-layer accessors on the owning modules, which is its own
# piece of work (milestone B'/architecture cleanup). This check exists to stop
# the list from GROWING. Entries are "<path>::<imported module>" with no line
# numbers, so ordinary edits above an import do not churn the baseline.


def _module_of(path: Path) -> str | None:
    """Return the monolith module a file belongs to, or None if outside them."""
    try:
        rel = path.resolve().relative_to(MODULES_DIR)
    except ValueError:
        return None
    return rel.parts[0] if len(rel.parts) > 1 else None


def _imported_orm_module(node: ast.ImportFrom) -> str | None:
    """Return the module whose ORM classes `node` imports, or None.

    Handles both spellings the codebase uses:
      absolute  `from monolith.modules.gate.models import VerdictRow`
      relative  `from ..gate.models import VerdictRow` (level=2)
    A module importing its own models (`from .models import ...`, level=1) is
    the expected pattern and never reported.
    """
    if node.level == 0:
        parts = (node.module or "").split(".")
        # monolith.modules.<X>.models
        if len(parts) == 4 and parts[:2] == ["monolith", "modules"] and parts[3] == "models":
            return parts[2]
        return None

    # Relative: level=1 is "this module", level=2 is a sibling module.
    if node.level == 1:
        return None
    parts = (node.module or "").split(".")
    if node.level == 2 and len(parts) == 2 and parts[1] == "models":
        return parts[0]
    return None


def find_violations() -> list[str]:
    violations: list[str] = []
    for path in sorted(MODULES_DIR.rglob("*.py")):
        own_module = _module_of(path)
        if own_module is None:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            imported = _imported_orm_module(node)
            if imported is not None and imported != own_module:
                rel = path.resolve().relative_to(REPO_ROOT)
                violations.append(f"{rel}::{imported}")
    return sorted(set(violations))


def load_baseline() -> set[str]:
    if not BASELINE_PATH.exists():
        return set()
    return {
        line.strip()
        for line in BASELINE_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--update",
        action="store_true",
        help="rewrite the baseline to match the current tree (review the diff!)",
    )
    args = parser.parse_args()

    current = set(find_violations())

    if args.update:
        header = (
            "# Cross-module ORM imports recorded as a baseline by\n"
            "# scripts/check_import_boundaries.py. This list must only ever shrink.\n"
            "# Regenerate with: uv run python scripts/check_import_boundaries.py --update\n"
        )
        BASELINE_PATH.write_text(header + "\n".join(sorted(current)) + "\n", encoding="utf-8")
        print(f"baseline rewritten: {len(current)} entries -> {BASELINE_PATH}")
        return 0

    baseline = load_baseline()
    added = sorted(current - baseline)
    removed = sorted(baseline - current)

    if added:
        print("NEW cross-module ORM imports (not allowed):", file=sys.stderr)
        for entry in added:
            path, _, imported = entry.partition("::")
            print(f"  {path} imports {imported}'s ORM models", file=sys.stderr)
        print(
            "\nGo through the owning module's service layer instead. If this really is\n"
            "unavoidable, say so explicitly and re-baseline with --update.",
            file=sys.stderr,
        )
        return 1

    if removed:
        # Not a failure - someone fixed one. Nudge so the baseline cannot rot.
        print(f"{len(removed)} baselined violation(s) are gone - shrink the baseline:")
        for entry in removed:
            print(f"  {entry}")
        print("Run: uv run python scripts/check_import_boundaries.py --update")
        return 0

    print(f"import boundaries OK ({len(current)} baselined, 0 new)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
