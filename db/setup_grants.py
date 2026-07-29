#!/usr/bin/env python3
"""Apply policies/grants/manifest.yaml against MySQL (coding spec §7.2).

SECURITY: creates one MySQL user per module, each granted access to ONLY its own
tables per the manifest - never run application code as the root/migration user.
Requires a privileged connection (passed via SKILLSCAN_MIGRATION_DB_URL, same as
alembic); per-module passwords come from the environment variables named in the
manifest (`password_env`), defaulting to a fixed local-dev-only value when unset
so this script is runnable out of the box in a local test environment. Production
must set every `password_env` explicitly (sourced from Vault, coding spec §13) -
this script does not enforce that itself since it has no way to distinguish a
local dev run from a misconfigured production run.

--verify (2026-07-29, milestone C correctness review N-1): reads the grants
back and fails if any manifest entry is not actually in effect.

THE HAZARD IT EXISTS FOR. `alembic upgrade head` and this script are two
separate operations, and a migration that CREATEs a table nothing has granted
yet leaves a deployment whose schema is current and whose privileges are not.
Before milestone C that cost nothing user-visible: every table an existing
module wrote to already carried its grant. Task 8 changed that - it added
`scan_engine_health` and its INSERTs run inside the transaction that scores
every scan, so on a database migrated without re-running this script, EVERY
decide fails, permanently and identically, and the scan never gets a verdict.
Nothing about that state announces itself: the pods start healthy (SQLAlchemy
connects lazily and the grant is only tested by the INSERT).

WHY VERIFICATION RATHER THAN AUTOMATION. Applying the manifest from alembic's
`env.py` would make the bad order impossible, which is strictly stronger, and
it was the first design. It was rejected: the two operations deliberately use
DIFFERENT credentials (`SKILLSCAN_MIGRATION_DB_URL`, a SQLAlchemy async URL,
vs `SKILLSCAN_ADMIN_DB_DSN`, a pymysql DSN), so coupling them means either
translating one into the other - a new place for the parsing bugs this file's
own comments already record three of - or requiring GRANT OPTION on the
migration credential, which would make a legitimate DDL-only migration fail.
It would also fire on `alembic upgrade` in offline/`--sql` mode, where there
is no connection to grant through.

So the ordering stays explicit and gets a check with teeth instead: the deploy
script runs the migration, applies the manifest, and then asserts the manifest
is IN EFFECT - which catches the grants never running, the grants running
before the migration, and a manifest that was never told about a new table.
The code-time half of the same defect (a migration adding a table nobody put
in the manifest at all) is caught earlier and without any database, by
`tests/test_grants_manifest.py`.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import pymysql
import yaml

_LOCAL_DEV_DEFAULT_PASSWORD = "local-dev-only-not-a-secret"  # noqa: S105 - explicitly local-dev-only, documented


def load_manifest(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        manifest = yaml.safe_load(f)
    if not isinstance(manifest, dict) or "users" not in manifest:
        raise ValueError(f"{path}: expected a top-level 'users' mapping")
    return manifest


def _grant_clause(privileges: str | list[str]) -> str:
    if privileges == "ALL":
        return "ALL PRIVILEGES"
    if isinstance(privileges, list):
        return ", ".join(privileges)
    raise ValueError(f"invalid privilege spec: {privileges!r}")


# BUG (found running this against a real Docker-hosted MySQL for the first
# time - every prior successful run was apparently against a native, non-
# containerized MySQL where the client library's "localhost" special-case
# resolves to a Unix socket): a Python DB-API driver (aiomysql/PyMySQL) does
# NOT get that same "localhost" == Unix-socket treatment the `mysql` CLI's
# C client library gives it - confirmed directly: `mysql -hlocalhost -u...`
# succeeds, `mysql -h127.0.0.1 -u...` with the identical credentials fails
# "Access denied ... '@127.0.0.1'", and aiomysql/conftest.py's DSN (which
# literally says "localhost") produces exactly that 127.0.0.1-over-TCP
# connection MySQL then can't match against a user only ever GRANTed
# '@localhost'. A Dockerized MySQL makes this unconditional, not just a
# theoretical driver quirk: even with --network host, the container's own
# Unix socket file lives inside ITS filesystem, unreachable from a process
# on the host regardless of what host string that process passes. Granting
# to both scopes makes this correct under a native local MySQL AND a
# containerized one.
_GRANT_HOSTS: tuple[str, ...] = ("localhost", "%")


def apply_manifest(
    connection: pymysql.connections.Connection, manifest: dict, database: str
) -> None:
    with connection.cursor() as cursor:
        for username, spec in manifest["users"].items():
            password = os.environ.get(spec["password_env"], _LOCAL_DEV_DEFAULT_PASSWORD)
            for grant_host in _GRANT_HOSTS:
                # BUG (found immediately after adding "%" to _GRANT_HOSTS above):
                # pymysql.Cursor.mogrify unconditionally applies Python `%`
                # string formatting to the WHOLE query whenever `args` is not
                # None (confirmed by reading pymysql/cursors.py directly, not
                # assumed) - only for these two statements, which pass
                # `(password,)`. A literal `%` from the wildcard host,
                # unescaped, collides with that and raises "unsupported
                # format character" (Python's `%` operator sees `%'` and
                # doesn't recognize `'` as a conversion type). The GRANT
                # statements below pass no args at all, so mogrify's `if args
                # is not None` guard skips substitution entirely there - a
                # literal `%` is safe in those and must NOT be escaped, or
                # MySQL would see a literal `%%` instead of the wildcard host.
                pct_escaped_host = grant_host.replace("%", "%%")
                cursor.execute(
                    f"CREATE USER IF NOT EXISTS '{username}'@'{pct_escaped_host}' IDENTIFIED BY %s",
                    (password,),
                )
                cursor.execute(
                    f"ALTER USER '{username}'@'{pct_escaped_host}' IDENTIFIED BY %s",
                    (password,),
                )
                for table, privileges in spec["tables"].items():
                    grant = _grant_clause(privileges)
                    # SECURITY: table names/usernames come from our own reviewed manifest
                    # file, not external input - not building this as a parameterized
                    # query is safe here (MySQL doesn't support parameterized identifiers
                    # in GRANT anyway) and matches the coding spec's own "config-as-code,
                    # PR-reviewed" trust model for this file.
                    cursor.execute(
                        f"GRANT {grant} ON {database}.{table} TO '{username}'@'{grant_host}'"
                    )
                    print(f"  GRANT {grant} ON {database}.{table} TO {username}@{grant_host}")
                # SECURITY: LOCK TABLES is only grantable at database/global scope in
                # MySQL (see manifest.yaml header) - modules whose service code issues
                # `SELECT ... FOR UPDATE` declare this explicitly; it is never implied
                # by a table-level grant.
                for db_privilege in spec.get("database_privileges", []):
                    cursor.execute(
                        f"GRANT {db_privilege} ON {database}.* TO '{username}'@'{grant_host}'"
                    )
                    print(f"  GRANT {db_privilege} ON {database}.* TO {username}@{grant_host}")
        cursor.execute("FLUSH PRIVILEGES")
    connection.commit()


#: `GRANT ALL` expands server-side into MySQL's full per-table privilege list,
#: whose exact membership is a server-version detail. Rather than pin that list,
#: verification probes the four privileges "ALL" unambiguously implies on every
#: MySQL 8: all four are present if the GRANT landed, and all four are absent if
#: it did not, which is the only distinction --verify needs to draw.
_ALL_PRIVILEGE_PROBE: tuple[str, ...] = ("SELECT", "INSERT", "UPDATE", "DELETE")

#: One expected/observed grant: (user, host, object, privilege). `object` is a
#: table name, or "*" for a database-scoped privilege (LOCK TABLES).
Grant = tuple[str, str, str, str]


def _privilege_names(privileges: str | list[str]) -> tuple[str, ...]:
    if privileges == "ALL":
        return _ALL_PRIVILEGE_PROBE
    if isinstance(privileges, list):
        return tuple(p.upper() for p in privileges)
    raise ValueError(f"invalid privilege spec: {privileges!r}")


def expected_grants(manifest: dict) -> frozenset[Grant]:
    """Every grant the manifest asks for, PER HOST.

    Per host, not unioned across hosts, deliberately: `_GRANT_HOSTS` exists
    because a user granted only at '@localhost' is invisible to a driver
    connecting over TCP (see its comment - that cost a full debugging session
    once already). A check that accepted "granted from at least one host" would
    call exactly that half-applied state healthy.

    Pure - no database connection, so `tests/test_grants_manifest.py` can
    exercise the comparison on this machine.
    """
    expected: set[Grant] = set()
    for username, spec in manifest["users"].items():
        for host in _GRANT_HOSTS:
            for table, privileges in (spec.get("tables") or {}).items():
                for privilege in _privilege_names(privileges):
                    expected.add((username, host, table, privilege))
            for db_privilege in spec.get("database_privileges", []):
                expected.add((username, host, "*", db_privilege.upper()))
    return frozenset(expected)


def missing_grants(manifest: dict, granted: frozenset[Grant]) -> tuple[str, ...]:
    """Human-readable descriptions of manifest grants that are NOT in effect.
    Empty means the manifest is fully applied. Pure."""
    return tuple(
        f"{privilege} ON {obj} TO '{user}'@'{host}'"
        for user, host, obj, privilege in sorted(expected_grants(manifest) - granted)
    )


def _split_grantee(grantee: str) -> tuple[str, str]:
    """`'svc_gate'@'localhost'` -> `('svc_gate', 'localhost')`."""
    user, _, host = grantee.partition("@")
    return user.strip().strip("'"), host.strip().strip("'")


def fetch_granted(connection: pymysql.connections.Connection, database: str) -> frozenset[Grant]:
    """What MySQL actually grants on `database` right now."""
    granted: set[Grant] = set()
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT GRANTEE, TABLE_NAME, PRIVILEGE_TYPE "
            "FROM information_schema.TABLE_PRIVILEGES WHERE TABLE_SCHEMA = %s",
            (database,),
        )
        for grantee, table, privilege in cursor.fetchall():
            user, host = _split_grantee(grantee)
            granted.add((user, host, table, privilege.upper()))
        # Database-scoped grants (LOCK TABLES) live in a different view -
        # `GRANT ... ON db.*` never appears in TABLE_PRIVILEGES at all.
        cursor.execute(
            "SELECT GRANTEE, PRIVILEGE_TYPE "
            "FROM information_schema.SCHEMA_PRIVILEGES WHERE TABLE_SCHEMA = %s",
            (database,),
        )
        for grantee, privilege in cursor.fetchall():
            user, host = _split_grantee(grantee)
            granted.add((user, host, "*", privilege.upper()))
    return frozenset(granted)


def verify_manifest_applied(
    connection: pymysql.connections.Connection, manifest: dict, database: str
) -> tuple[str, ...]:
    """Read the grants back and return what is missing. See this module's
    docstring for the deployment hazard this closes."""
    return missing_grants(manifest, fetch_granted(connection, database))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verify",
        action="store_true",
        help="only check that the manifest is already in effect; apply nothing",
    )
    args = parser.parse_args()

    manifest_path = Path(__file__).resolve().parent.parent / "policies" / "grants" / "manifest.yaml"
    manifest = load_manifest(manifest_path)

    admin_dsn = os.environ.get("SKILLSCAN_ADMIN_DB_DSN", "mysql://root@localhost/skillscan")
    # crude DSN parse - good enough for the local root@localhost default and simple overrides
    without_scheme = admin_dsn.split("://", 1)[1]
    userinfo, _, hostdb = without_scheme.partition("@")
    hostport, _, database = hostdb.partition("/")
    user_part, sep, password_part = userinfo.partition(":")
    user = user_part if userinfo else "root"
    # BUG (found running this against a real password-protected Docker MySQL
    # for the first time - every prior run had only ever exercised the
    # no-password root@localhost default): this used to drop the password
    # component of the DSN entirely, silently connecting with no password
    # regardless of what SKILLSCAN_ADMIN_DB_DSN actually specified. `sep`
    # (not just a truthy password_part) distinguishes "no ':' at all" from
    # "':' present with an intentionally empty password" - pymysql.connect's
    # own password=None default already means "no password", so only pass
    # password= explicitly when the DSN's ':' was actually present.
    password = password_part if sep else None
    # BUG (found 2026-07-14 running this against a k3s NodePort-exposed MySQL
    # for the first time - every prior run had only ever exercised the
    # port-less `localhost` default): `hostport` used to be passed to
    # pymysql.connect's `host=` verbatim, which for e.g. "localhost:30306"
    # tries to resolve the literal string "localhost:30306" as a hostname
    # (NXDOMAIN) instead of connecting to host "localhost" port 30306 -
    # pymysql takes host/port as separate parameters, unlike a URL.
    host, _, port_str = hostport.partition(":")
    port = int(port_str) if port_str else 3306

    connection = pymysql.connect(
        host=host or "localhost", port=port, user=user, password=password, database=database
    )
    try:
        if not args.verify:
            print(f"Applying {manifest_path} to database {database!r}...")
            apply_manifest(connection, manifest, database)
        # Verified even on the apply path, not only under --verify: this file
        # already records two bugs where apply_manifest ran to completion and
        # granted something other than what was asked for (the '@localhost'
        # socket special-case, the mogrify '%' collision). "The script exited 0"
        # has never been the same claim as "the manifest is in effect".
        print(f"Verifying {manifest_path} is in effect on database {database!r}...")
        missing = verify_manifest_applied(connection, manifest, database)
    finally:
        connection.close()

    if missing:
        print(
            f"!!! {len(missing)} grant(s) in the manifest are NOT in effect on {database!r}.",
            file=sys.stderr,
        )
        print(
            "!!! A module whose grant is missing does not crash - it starts healthy and "
            "fails only when it writes. If a migration just added a table, this is that "
            "table's grant: run this script without --verify.",
            file=sys.stderr,
        )
        for description in missing:
            print(f"  MISSING: GRANT {description}", file=sys.stderr)
        return 1
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
