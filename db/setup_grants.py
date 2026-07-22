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
"""

from __future__ import annotations

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


def main() -> int:
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
        print(f"Applying {manifest_path} to database {database!r}...")
        apply_manifest(connection, manifest, database)
    finally:
        connection.close()
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
