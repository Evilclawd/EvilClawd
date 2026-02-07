"""Immutable audit log with hash chaining.

Provides:
- append_audit_log: Append new audit entry with hash chain integrity
- verify_audit_chain: Verify cryptographic integrity of entire audit chain
"""

from datetime import datetime, timezone
from typing import Any, Dict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import AuditLog


async def append_audit_log(
    session: AsyncSession,
    event_type: str,
    session_id: str,
    actor: str,
    event_data: Dict[str, Any],
) -> AuditLog:
    """Append new entry to audit log with hash chaining.

    Creates a new audit log entry and links it to the previous entry via
    cryptographic hash. The hash chain enables tamper detection.

    Args:
        session: Database session
        event_type: Type of event (e.g., "scan_start", "tool_execute", "finding_validated")
        session_id: Associated session identifier
        actor: Who performed the action ("user", "llm", "system", username)
        event_data: JSON-serializable dictionary of event details

    Returns:
        Created AuditLog entry with computed hash

    Example:
        >>> async with get_session() as session:
        ...     await append_audit_log(
        ...         session,
        ...         "scan_start",
        ...         "sess-123",
        ...         "user",
        ...         {"target": "https://example.com"}
        ...     )
    """
    import json

    # Get the most recent audit entry to establish chain
    stmt = select(AuditLog).order_by(AuditLog.id.desc()).limit(1)
    result = await session.execute(stmt)
    previous_entry = result.scalar_one_or_none()

    # Create new entry
    entry = AuditLog(
        timestamp=datetime.now(timezone.utc),
        event_type=event_type,
        session_id=session_id,
        actor=actor,
        event_data=json.dumps(event_data, sort_keys=True),
        previous_hash=previous_entry.entry_hash if previous_entry else None,
        entry_hash="",  # Will be computed by before_insert event listener
    )

    session.add(entry)
    await session.flush()  # Trigger before_insert event to compute hash

    return entry


async def verify_audit_chain(session: AsyncSession) -> bool:
    """Verify cryptographic integrity of audit log chain.

    Validates that:
    1. Each entry's hash matches its computed hash
    2. Each entry's previous_hash matches the previous entry's hash
    3. The chain is unbroken from start to end

    Args:
        session: Database session

    Returns:
        True if chain is valid, False if tampered

    Example:
        >>> async with get_session() as session:
        ...     is_valid = await verify_audit_chain(session)
        ...     if not is_valid:
        ...         print("WARNING: Audit log has been tampered with!")
    """
    # Get all audit entries in chronological order
    stmt = select(AuditLog).order_by(AuditLog.id.asc())
    result = await session.execute(stmt)
    entries = result.scalars().all()

    if not entries:
        # Empty log is valid
        return True

    previous_hash = None

    for entry in entries:
        # Verify entry hash matches computed hash
        computed_hash = entry.compute_hash()
        if entry.entry_hash != computed_hash:
            return False

        # Verify previous_hash linkage
        if entry.previous_hash != previous_hash:
            return False

        previous_hash = entry.entry_hash

    return True
