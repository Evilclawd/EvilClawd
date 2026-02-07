"""Telegram inline keyboard callback handlers.

Handles approval workflow callbacks:
- Approve/Deny buttons for exploit step approval
- Continue/Stop buttons after denial
- JobQueue callbacks for reminder and auto-deny timeouts
"""

import asyncio
from datetime import datetime, timezone

import structlog
from sqlalchemy import select, update as sa_update
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import ContextTypes

from scanner.core.persistence.database import get_session
from scanner.core.persistence.models import ApprovalRequest

logger = structlog.get_logger()


def build_approval_keyboard(approval_id: int) -> InlineKeyboardMarkup:
    """Build inline keyboard with Approve/Deny buttons.

    Args:
        approval_id: Database ID of the approval request

    Returns:
        InlineKeyboardMarkup with two buttons
    """
    keyboard = [
        [
            InlineKeyboardButton("✅ Approve", callback_data=f"approve:{approval_id}"),
            InlineKeyboardButton("❌ Deny", callback_data=f"deny:{approval_id}"),
        ]
    ]
    return InlineKeyboardMarkup(keyboard)


def build_continue_stop_keyboard(session_id: str) -> InlineKeyboardMarkup:
    """Build inline keyboard with Continue/Stop buttons after denial.

    Args:
        session_id: Session ID for the exploitation chain

    Returns:
        InlineKeyboardMarkup with two buttons
    """
    keyboard = [
        [
            InlineKeyboardButton("▶️ Continue", callback_data=f"continue:{session_id}"),
            InlineKeyboardButton("⏹ Stop", callback_data=f"stop:{session_id}"),
        ]
    ]
    return InlineKeyboardMarkup(keyboard)


async def approval_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle Approve/Deny button clicks for approval requests.

    Args:
        update: Telegram update with callback query
        context: Bot context with bot_data for event storage
    """
    query = update.callback_query
    await query.answer()  # Acknowledge button click immediately

    # Parse callback data: "approve:123" or "deny:123"
    callback_data = query.data
    action, approval_id_str = callback_data.split(":", 1)
    approval_id = int(approval_id_str)

    # Load approval request from database
    async with get_session() as session:
        result = await session.execute(
            select(ApprovalRequest).where(ApprovalRequest.id == approval_id)
        )
        approval_request = result.scalar_one_or_none()

        if not approval_request:
            await query.edit_message_text("⚠️ Approval request not found or already resolved")
            return

        if approval_request.status != "pending":
            await query.edit_message_text(f"⚠️ Already {approval_request.status}")
            return

        # Update approval status
        decision = "approved" if action == "approve" else "denied"
        await session.execute(
            sa_update(ApprovalRequest)
            .where(ApprovalRequest.id == approval_id)
            .values(
                status=decision,
                resolved_at=datetime.now(timezone.utc)
            )
        )
        await session.commit()

        logger.info(
            "approval_decision",
            approval_id=approval_id,
            session_id=approval_request.session_id,
            decision=decision,
            tool=approval_request.tool_name,
        )

    # Update message to show decision
    decision_emoji = "✅" if action == "approve" else "❌"
    await query.edit_message_text(
        f"{decision_emoji} {decision.upper()}\n\n{approval_request.blast_radius_text}"
    )

    # Set event in bot_data to unblock waiting exploit handler
    event_key = f"approval_event_{approval_id}"
    if event_key in context.bot_data:
        event: asyncio.Event = context.bot_data[event_key]
        context.bot_data[f"approval_decision_{approval_id}"] = decision
        event.set()


async def continue_stop_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle Continue/Stop buttons after denial.

    Args:
        update: Telegram update with callback query
        context: Bot context with bot_data for event storage
    """
    query = update.callback_query
    await query.answer()

    # Parse callback data: "continue:session-id" or "stop:session-id"
    callback_data = query.data
    action, session_id = callback_data.split(":", 1)

    # Update message
    if action == "continue":
        await query.edit_message_text("▶️ Continuing with remaining steps...")
    else:
        await query.edit_message_text("⏹ Stopped - no further steps will execute")

    # Set event in bot_data
    event_key = f"continue_stop_event_{session_id}"
    if event_key in context.bot_data:
        event: asyncio.Event = context.bot_data[event_key]
        context.bot_data[f"continue_stop_decision_{session_id}"] = action
        event.set()


async def approval_reminder_job(context: ContextTypes.DEFAULT_TYPE):
    """JobQueue callback to send reminder after 5 minutes.

    Args:
        context: Bot context with job.data containing approval_id and chat_id
    """
    approval_id = context.job.data["approval_id"]
    chat_id = context.job.data["chat_id"]

    # Check if still pending
    async with get_session() as session:
        result = await session.execute(
            select(ApprovalRequest).where(ApprovalRequest.id == approval_id)
        )
        approval_request = result.scalar_one_or_none()

        if not approval_request or approval_request.status != "pending":
            return  # Already resolved

    # Send reminder
    await context.bot.send_message(
        chat_id=chat_id,
        text=f"⏰ Reminder: Approval request #{approval_id} still pending (auto-deny in 10 minutes)",
    )


async def approval_auto_deny_job(context: ContextTypes.DEFAULT_TYPE):
    """JobQueue callback to auto-deny after 15 minutes.

    Args:
        context: Bot context with job.data containing approval_id and chat_id
    """
    approval_id = context.job.data["approval_id"]
    chat_id = context.job.data["chat_id"]

    # Check if still pending
    async with get_session() as session:
        result = await session.execute(
            select(ApprovalRequest).where(ApprovalRequest.id == approval_id)
        )
        approval_request = result.scalar_one_or_none()

        if not approval_request or approval_request.status != "pending":
            return  # Already resolved

        # Auto-deny
        await session.execute(
            sa_update(ApprovalRequest)
            .where(ApprovalRequest.id == approval_id)
            .values(
                status="auto_denied",
                resolved_at=datetime.now(timezone.utc)
            )
        )
        await session.commit()

        logger.info(
            "approval_auto_denied",
            approval_id=approval_id,
            session_id=approval_request.session_id,
            tool=approval_request.tool_name,
        )

    # Notify user
    await context.bot.send_message(
        chat_id=chat_id,
        text=f"⏱ Auto-denied approval request #{approval_id} (15 minute timeout)",
    )

    # Set event to unblock waiting exploit handler
    event_key = f"approval_event_{approval_id}"
    if event_key in context.bot_data:
        event: asyncio.Event = context.bot_data[event_key]
        context.bot_data[f"approval_decision_{approval_id}"] = "auto_denied"
        event.set()
