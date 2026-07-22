"""Per-module async SQLAlchemy engine factory (coding spec §7.2).

SECURITY: each module connects as its own least-privilege MySQL user (per
policies/grants/manifest.yaml) - never a shared superuser. There is
deliberately no "give me any table" helper here; each module's own
repository.py imports only its own models.py.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def make_engine(dsn: str) -> AsyncEngine:
    return create_async_engine(dsn, pool_pre_ping=True)


def make_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)
