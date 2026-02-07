"""Session state checkpointing for pause/resume capability.

Provides:
- save_checkpoint: Save session state at a point in time
- load_latest_checkpoint: Restore most recent session state
- rewind_to_checkpoint: Load specific checkpoint by ID
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import SessionCheckpoint


async def save_checkpoint(
    session: AsyncSession,
    session_id: str,
    thread_id: str = "default",
    state: Optional[Dict[str, Any]] = None,
    checkpoint_metadata: Optional[str] = None,
    parent_checkpoint_id: Optional[int] = None,
) -> int:
    """Save session state checkpoint.

    Creates a new checkpoint with the current session state. Enables pause/resume
    functionality and supports branching via parent_checkpoint_id.

    Args:
        session: Database session
        session_id: Session identifier (consistent across checkpoints)
        thread_id: Thread/conversation identifier (default: "default")
        state: JSON-serializable dictionary of session state (default: empty dict)
        checkpoint_metadata: Optional metadata about checkpoint (JSON string)
        parent_checkpoint_id: Reference to parent checkpoint for branching

    Returns:
        checkpoint_id of created checkpoint

    Example:
        >>> async with get_session() as session:
        ...     checkpoint_id = await save_checkpoint(
        ...         session,
        ...         "sess-123",
        ...         "default",
        ...         {"step": 1, "target": "https://example.com", "findings": []}
        ...     )
        ...     print(f"Saved checkpoint {checkpoint_id}")
    """
    if state is None:
        state = {}

    checkpoint = SessionCheckpoint(
        session_id=session_id,
        thread_id=thread_id,
        timestamp=datetime.now(timezone.utc),
        state=json.dumps(state, sort_keys=True),
        checkpoint_metadata=checkpoint_metadata,
        parent_checkpoint_id=parent_checkpoint_id,
    )

    session.add(checkpoint)
    await session.flush()  # Get auto-generated checkpoint_id

    return checkpoint.checkpoint_id


async def load_latest_checkpoint(
    session: AsyncSession,
    session_id: str,
    thread_id: str = "default",
) -> Optional[Tuple[Dict[str, Any], int]]:
    """Load the most recent checkpoint for a session.

    Args:
        session: Database session
        session_id: Session identifier
        thread_id: Thread/conversation identifier (default: "default")

    Returns:
        Tuple of (state_dict, checkpoint_id) if checkpoint exists, None otherwise

    Example:
        >>> async with get_session() as session:
        ...     result = await load_latest_checkpoint(session, "sess-123")
        ...     if result:
        ...         state, checkpoint_id = result
        ...         print(f"Resumed from checkpoint {checkpoint_id}")
        ...         print(f"State: {state}")
        ...     else:
        ...         print("No checkpoint found, starting fresh")
    """
    stmt = (
        select(SessionCheckpoint)
        .where(
            SessionCheckpoint.session_id == session_id,
            SessionCheckpoint.thread_id == thread_id,
        )
        .order_by(SessionCheckpoint.checkpoint_id.desc())
        .limit(1)
    )

    result = await session.execute(stmt)
    checkpoint = result.scalar_one_or_none()

    if checkpoint is None:
        return None

    state = json.loads(checkpoint.state)
    return (state, checkpoint.checkpoint_id)


async def rewind_to_checkpoint(
    session: AsyncSession,
    session_id: str,
    checkpoint_id: int,
    thread_id: str = "default",
) -> Dict[str, Any]:
    """Load specific checkpoint by ID.

    Allows rewinding to an earlier checkpoint, useful for exploring
    different execution paths or recovering from errors.

    Args:
        session: Database session
        session_id: Session identifier
        checkpoint_id: Specific checkpoint ID to load
        thread_id: Thread/conversation identifier (default: "default")

    Returns:
        State dictionary from checkpoint

    Raises:
        ValueError: If checkpoint not found

    Example:
        >>> async with get_session() as session:
        ...     # Rewind to checkpoint 5
        ...     state = await rewind_to_checkpoint(session, "sess-123", 5)
        ...     print(f"Rewound to: {state}")
    """
    stmt = select(SessionCheckpoint).where(
        SessionCheckpoint.session_id == session_id,
        SessionCheckpoint.thread_id == thread_id,
        SessionCheckpoint.checkpoint_id == checkpoint_id,
    )

    result = await session.execute(stmt)
    checkpoint = result.scalar_one_or_none()

    if checkpoint is None:
        raise ValueError(
            f"Checkpoint not found: session_id={session_id}, "
            f"thread_id={thread_id}, checkpoint_id={checkpoint_id}"
        )

    return json.loads(checkpoint.state)
