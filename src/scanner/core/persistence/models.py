"""SQLAlchemy ORM models for async persistence layer.

Models:
- Target: Authorized scan targets
- ScanResult: Completed scan outputs with findings
- AuditLog: Immutable audit trail with hash chaining
- SessionCheckpoint: Resumable session state
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    event,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


class Target(Base):
    """Authorized scan targets.

    Stores targets that have been explicitly authorized for security scanning.
    Includes scope definition and authorization tracking.
    """
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    url: Mapped[str] = mapped_column(String(2048), unique=True, index=True, nullable=False)
    scope: Mapped[str] = mapped_column(Text, nullable=False)  # JSON list of allowed subdomains/paths
    authorized_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    authorized_by: Mapped[str] = mapped_column(String(200), nullable=False)
    last_scanned: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class ScanResult(Base):
    """Completed scan outputs.

    Stores scan session results including findings, status, and timing.
    """
    __tablename__ = "scan_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    session_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), nullable=False)
    chat_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    findings: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON array
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="running")  # running/completed/failed


class AuditLog(Base):
    """Immutable audit trail with hash chaining.

    Each entry is cryptographically linked to the previous entry via SHA-256 hash.
    This provides tamper detection for the audit log.

    Attributes:
        id: Auto-incrementing primary key
        timestamp: When the event occurred (indexed)
        event_type: Type of event (indexed)
        session_id: Associated session (indexed)
        actor: Who performed the action (user/llm/system)
        event_data: JSON payload with event details
        previous_hash: Hash of previous entry (for chain integrity)
        entry_hash: SHA-256 hash of this entry (unique)
    """
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True, nullable=False, default=lambda: datetime.now(timezone.utc))
    event_type: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    session_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    actor: Mapped[str] = mapped_column(String(100), nullable=False)
    event_data: Mapped[str] = mapped_column(Text, nullable=False)  # JSON payload
    previous_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    entry_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)

    __table_args__ = (
        Index("ix_audit_session_timestamp", "session_id", "timestamp"),
        Index("ix_audit_event_timestamp", "event_type", "timestamp"),
    )

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of this audit entry.

        Hash includes: timestamp, event_type, session_id, actor, event_data, previous_hash

        Returns:
            Hexadecimal hash string (64 characters)
        """
        # Ensure timestamp is timezone-aware (SQLite stores naive datetimes)
        timestamp = self.timestamp
        if timestamp and timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        # Create canonical representation for hashing
        hash_input = {
            "timestamp": timestamp.isoformat() if timestamp else "",
            "event_type": self.event_type,
            "session_id": self.session_id,
            "actor": self.actor,
            "event_data": self.event_data,
            "previous_hash": self.previous_hash or "",
        }

        # Sort keys for deterministic hashing
        canonical = json.dumps(hash_input, sort_keys=True, separators=(",", ":"))

        # Compute SHA-256
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class SessionCheckpoint(Base):
    """Resumable session state.

    Stores session state at key points to enable pause/resume functionality.
    Supports multiple threads per session with hierarchical checkpointing.

    Attributes:
        checkpoint_id: Auto-incrementing primary key
        session_id: Session identifier
        thread_id: Thread/conversation identifier within session
        timestamp: When checkpoint was created
        state: JSON serialized session state
        checkpoint_metadata: Optional metadata about checkpoint
        parent_checkpoint_id: Reference to parent checkpoint (for branching)
    """
    __tablename__ = "session_checkpoints"

    checkpoint_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    thread_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    state: Mapped[str] = mapped_column(Text, nullable=False)  # JSON
    checkpoint_metadata: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    parent_checkpoint_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    __table_args__ = (
        Index("ix_checkpoint_session_thread", "session_id", "thread_id"),
    )


class ScanQueue(Base):
    """Database-backed scan queue for one-at-a-time enforcement."""
    __tablename__ = "scan_queue"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    chat_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    command: Mapped[str] = mapped_column(String(50), nullable=False, default="full_pipeline")
    session_id: Mapped[str] = mapped_column(String(36), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued")  # queued/running/completed/failed
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class ApprovalRequest(Base):
    """Tracks pending approval requests for Telegram inline keyboards."""
    __tablename__ = "approval_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    chat_id: Mapped[int] = mapped_column(Integer, nullable=False)
    message_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    step_index: Mapped[int] = mapped_column(Integer, nullable=False)
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    blast_radius_text: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


# Event listener to auto-compute hash before insert
@event.listens_for(AuditLog, "before_insert")
def compute_audit_hash(mapper, connection, target):
    """Automatically compute entry_hash before inserting audit log entry."""
    if not target.entry_hash:
        target.entry_hash = target.compute_hash()
