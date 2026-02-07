"""Base agent with shared patterns for tool orchestration.

Provides:
- BaseAgent with audit logging and checkpointing
- Shared patterns for session management
- Database session handling
"""

import structlog
from uuid import uuid4
from scanner.core.persistence.database import get_session
from scanner.core.persistence.audit import append_audit_log
from scanner.core.persistence.checkpoint import save_checkpoint, load_latest_checkpoint

logger = structlog.get_logger()


class BaseAgent:
    """Base agent with tool orchestration, audit logging, and checkpointing.

    Provides common functionality for all agents:
    - Session ID management
    - Audit logging to database
    - Checkpoint save/restore
    - Structured logging
    """

    def __init__(self, session_id: str | None = None):
        """Initialize base agent.

        Args:
            session_id: Optional session ID (generates new UUID if not provided)
        """
        self.session_id = session_id or str(uuid4())
        self.log = logger.bind(agent=self.__class__.__name__, session_id=self.session_id)

    async def audit(self, event_type: str, data: dict) -> None:
        """Log an event to the audit trail.

        Creates an immutable audit log entry with hash chain integrity.

        Args:
            event_type: Type of event (e.g., "scan_start", "tool_execute")
            data: Event data dictionary (must be JSON-serializable)

        Example:
            >>> await self.audit("scan_start", {"target": "example.com"})
        """
        async with get_session() as session:
            await append_audit_log(
                session,
                event_type=event_type,
                session_id=self.session_id,
                actor="agent",
                event_data=data,
            )

    async def checkpoint(self, state: dict, metadata: str | None = None) -> int:
        """Save session checkpoint for pause/resume.

        Args:
            state: Session state dictionary (must be JSON-serializable)
            metadata: Optional metadata about checkpoint

        Returns:
            checkpoint_id of created checkpoint

        Example:
            >>> checkpoint_id = await self.checkpoint(
            ...     {"step": "subdomains", "completed": 1, "total": 3},
            ...     metadata="Completed subdomain enumeration"
            ... )
        """
        async with get_session() as session:
            return await save_checkpoint(
                session,
                session_id=self.session_id,
                state=state,
                checkpoint_metadata=metadata,
            )

    async def restore(self) -> dict | None:
        """Restore latest checkpoint for this session.

        Returns:
            State dictionary if checkpoint exists, None otherwise

        Example:
            >>> state = await self.restore()
            >>> if state:
            ...     print(f"Resuming from step: {state['step']}")
        """
        async with get_session() as session:
            result = await load_latest_checkpoint(session, self.session_id)
            return result[0] if result else None
