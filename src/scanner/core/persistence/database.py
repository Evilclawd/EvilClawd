"""Async database engine and session management.

Provides:
- init_database: Initialize async SQLAlchemy engine and create tables
- create_session_factory: Create async session factory
- get_session: Async context manager for database sessions
- shutdown: Clean shutdown of database connections
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .models import Base


# Global session factory (initialized by create_session_factory)
AsyncSessionFactory: Optional[async_sessionmaker[AsyncSession]] = None


async def init_database(db_url: str = "sqlite+aiosqlite:///evilclawd.db") -> AsyncEngine:
    """Initialize async database engine and create all tables.

    Args:
        db_url: SQLAlchemy database URL (default: SQLite in current directory)

    Returns:
        AsyncEngine instance

    Example:
        >>> engine = await init_database("sqlite+aiosqlite:///scanner.db")
        >>> # Tables are now created and engine is ready
    """
    # Create async engine
    engine = create_async_engine(
        db_url,
        echo=False,  # Set to True for SQL query logging during development
        future=True,
    )

    # Create all tables defined in Base metadata
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    return engine


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create async session factory from engine.

    CRITICAL: expire_on_commit=False is required for async usage patterns.
    This prevents SQLAlchemy from expiring all objects after commit,
    which would cause lazy-loaded attributes to fail outside the session.

    Args:
        engine: AsyncEngine instance from init_database()

    Returns:
        async_sessionmaker configured for async usage

    Example:
        >>> engine = await init_database()
        >>> create_session_factory(engine)
        >>> async with get_session() as session:
        ...     # Use session here
    """
    global AsyncSessionFactory

    AsyncSessionFactory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,  # CRITICAL for async
        autoflush=False,
        autocommit=False,
    )

    return AsyncSessionFactory


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Get async database session as context manager.

    Automatically handles:
    - Session creation
    - Commit on success
    - Rollback on exception
    - Session cleanup

    Yields:
        AsyncSession for database operations

    Raises:
        RuntimeError: If session factory not initialized (call create_session_factory first)

    Example:
        >>> async with get_session() as session:
        ...     target = Target(url="https://example.com", scope="[]", authorized_by="user")
        ...     session.add(target)
        ...     # Auto-commits on exit
    """
    if AsyncSessionFactory is None:
        raise RuntimeError(
            "Session factory not initialized. Call create_session_factory() first."
        )

    async with AsyncSessionFactory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def shutdown(engine: AsyncEngine) -> None:
    """Clean shutdown of database engine.

    Closes all connections and disposes of the connection pool.

    Args:
        engine: AsyncEngine to shut down

    Example:
        >>> engine = await init_database()
        >>> # ... use engine ...
        >>> await shutdown(engine)
    """
    await engine.dispose()
