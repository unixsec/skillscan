"""Grants-manifest guards: every table the schema creates must have an owner,
and a manifest grant that is not in effect must be detectable.

WHY THIS EXISTS (2026-07-29, milestone C correctness review N-1). Schema and
privileges are applied by two separate operations - `alembic upgrade head` and
`db/setup_grants.py` - and nothing connected them. A migration that CREATEs a
table grants nothing, so between the two the deployment has a schema its module
users cannot write to.

That cost nothing user-visible until milestone C Task 8. It added
`scan_engine_health`, whose 15 INSERTs per scan run inside the very transaction
that scores the scan, so on a migrated-but-ungranted database EVERY decide
fails, identically, forever - and nothing announces it, because SQLAlchemy
connects lazily and the grant is only exercised by the INSERT itself.

The defect has two halves and they need two different checks:

  code-time    a migration adds a table and nobody adds it to the manifest.
               Caught HERE, with no database, so it fails in the gate rather
               than on a deployed system.

  deploy-time  the manifest is right and was simply not applied (or was applied
               before the migration). Caught by `db/setup_grants.py --verify`
               against the real database; the pure comparison it is built on is
               exercised here too, so the comparison itself is not the thing
               that is only ever tested in production.

Deliberately in the kernel suite (`uv run pytest tests/ -q`, no MySQL/Redis):
it reads the REAL migrations and the REAL manifest.
"""

from __future__ import annotations

import importlib.util
import re
import unittest
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
MIGRATIONS_DIR = REPO_ROOT / "db" / "migrations" / "versions"
MANIFEST_PATH = REPO_ROOT / "policies" / "grants" / "manifest.yaml"


def _load_setup_grants() -> Any:
    """`db/` is not an importable package (no `__init__.py`, and it holds
    operational scripts rather than library code), so this loads the module by
    path rather than adding a package just to be importable from a test."""
    path = REPO_ROOT / "db" / "setup_grants.py"
    spec = importlib.util.spec_from_file_location("skillscan_setup_grants", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


setup_grants = _load_setup_grants()

# Both spellings the migrations actually use - raw `op.execute("CREATE TABLE ...")`
# (most of the schema, which mirrors the coding spec's DDL verbatim) and
# `op.create_table("name", ...)` (scan_submitter, marketplace_fetch_log).
_RAW_CREATE = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"']?([a-z_]+)", re.I)
_OP_CREATE = re.compile(r"op\.create_table\(\s*[\"']([a-z_]+)[\"']", re.S)

#: Tables that legitimately belong to no module user. Alembic's own bookkeeping
#: table is written by the MIGRATION credential (root/admin), never by an
#: application module - granting a module user access to it would let that
#: module rewrite the recorded schema revision.
_UNGRANTED_BY_DESIGN = frozenset({"alembic_version"})


def _tables_created_by_migrations() -> frozenset[str]:
    names: set[str] = set()
    for path in sorted(MIGRATIONS_DIR.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        names.update(m.group(1).lower() for m in _RAW_CREATE.finditer(source))
        names.update(m.group(1).lower() for m in _OP_CREATE.finditer(source))
    return frozenset(names)


def _manifest() -> dict[str, Any]:
    return setup_grants.load_manifest(MANIFEST_PATH)


def _manifest_tables(manifest: dict[str, Any]) -> frozenset[str]:
    return frozenset(
        table for spec in manifest["users"].values() for table in (spec.get("tables") or {})
    )


class TestEveryCreatedTableHasAnOwner(unittest.TestCase):
    def test_the_parser_actually_finds_the_schema(self) -> None:
        """Guards the guard. Both `CREATE TABLE` spellings must be recognised -
        if the regexes silently matched nothing, every assertion below would
        pass vacuously, which is the failure mode a source-scanning test has."""
        found = _tables_created_by_migrations()
        # `scan_job` is raw DDL, `scan_submitter` is op.create_table - one of
        # each spelling, so a regex that stopped matching cannot hide.
        self.assertIn("scan_job", found)
        self.assertIn("scan_submitter", found)
        self.assertGreaterEqual(len(found), 18)

    def test_every_migrated_table_appears_in_the_grants_manifest(self) -> None:
        """THE code-time half of the defect. A table created by a migration and
        named in no manifest entry is a table every module user is refused
        access to - a deployment that fails only when something writes to it."""
        unowned = _tables_created_by_migrations() - _manifest_tables(_manifest())
        self.assertEqual(
            unowned - _UNGRANTED_BY_DESIGN,
            frozenset(),
            "these tables are created by a migration but granted to no module user in "
            "policies/grants/manifest.yaml - the owning module will start healthy and "
            "fail every write against them",
        )

    def test_the_manifest_names_no_table_the_schema_does_not_have(self) -> None:
        """The opposite drift: a grant on a table that was renamed or dropped.
        MySQL accepts `GRANT ... ON db.gone` happily, so nothing else notices."""
        phantom = _manifest_tables(_manifest()) - _tables_created_by_migrations()
        self.assertEqual(phantom, frozenset())


class TestMissingGrantsDetection(unittest.TestCase):
    """The pure half of `db/setup_grants.py --verify`, exercised without a
    database so the comparison is not a thing that only ever runs on the VM."""

    def test_a_fully_applied_manifest_reports_nothing_missing(self) -> None:
        manifest = _manifest()
        granted = setup_grants.expected_grants(manifest)
        self.assertEqual(setup_grants.missing_grants(manifest, granted), ())

    def test_a_table_granted_to_nobody_is_reported(self) -> None:
        """The deploy-time defect, exactly: the schema has `scan_engine_health`
        and the manifest asks for it, but the grants were never re-applied
        after the migration that created it."""
        manifest = _manifest()
        granted = frozenset(
            g for g in setup_grants.expected_grants(manifest) if g[2] != "scan_engine_health"
        )
        missing = setup_grants.missing_grants(manifest, granted)
        self.assertTrue(missing)
        self.assertTrue(all("scan_engine_health" in m for m in missing))
        self.assertTrue(any("svc_orchestration" in m for m in missing))

    def test_a_grant_present_on_only_one_host_is_still_missing(self) -> None:
        """`_GRANT_HOSTS` exists because a user granted only at '@localhost' is
        invisible to a driver connecting over TCP. A check that accepted
        "granted from at least one host" would call that half-applied state
        healthy, which is the bug that comment was written for."""
        manifest = _manifest()
        granted = frozenset(g for g in setup_grants.expected_grants(manifest) if g[1] != "%")
        missing = setup_grants.missing_grants(manifest, granted)
        self.assertTrue(missing)
        self.assertTrue(all("'%'" in m for m in missing))

    def test_all_expands_to_more_than_select(self) -> None:
        """A user holding only SELECT on a table the manifest grants ALL on
        must not verify clean - the health-row INSERT is precisely what a
        SELECT-only grant would refuse."""
        manifest = _manifest()
        granted = frozenset(
            g
            for g in setup_grants.expected_grants(manifest)
            if not (g[0] == "svc_orchestration" and g[2] == "scan_engine_health")
            or g[3] == "SELECT"
        )
        missing = setup_grants.missing_grants(manifest, granted)
        self.assertTrue(any("INSERT ON scan_engine_health" in m for m in missing))


if __name__ == "__main__":
    unittest.main()
