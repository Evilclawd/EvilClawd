"""Tests for Telegram inline keyboard callbacks."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from telegram import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Update

from scanner.telegram_bot.callbacks import (
    approval_callback,
    build_approval_keyboard,
    build_continue_stop_keyboard,
    continue_stop_callback,
)
from scanner.telegram_bot.notifications import TelegramNotifier, get_notifier


def test_build_approval_keyboard():
    """Test approval keyboard has correct buttons and callback data."""
    keyboard = build_approval_keyboard(approval_id=42)

    assert isinstance(keyboard, InlineKeyboardMarkup)
    assert len(keyboard.inline_keyboard) == 1  # One row
    assert len(keyboard.inline_keyboard[0]) == 2  # Two buttons

    # Check Approve button
    approve_button = keyboard.inline_keyboard[0][0]
    assert isinstance(approve_button, InlineKeyboardButton)
    assert "Approve" in approve_button.text
    assert approve_button.callback_data == "approve:42"

    # Check Deny button
    deny_button = keyboard.inline_keyboard[0][1]
    assert isinstance(deny_button, InlineKeyboardButton)
    assert "Deny" in deny_button.text
    assert deny_button.callback_data == "deny:42"


def test_build_continue_stop_keyboard():
    """Test continue/stop keyboard has correct buttons."""
    keyboard = build_continue_stop_keyboard(session_id="test-session-123")

    assert isinstance(keyboard, InlineKeyboardMarkup)
    assert len(keyboard.inline_keyboard) == 1
    assert len(keyboard.inline_keyboard[0]) == 2

    # Check Continue button
    continue_button = keyboard.inline_keyboard[0][0]
    assert "Continue" in continue_button.text
    assert continue_button.callback_data == "continue:test-session-123"

    # Check Stop button
    stop_button = keyboard.inline_keyboard[0][1]
    assert "Stop" in stop_button.text
    assert stop_button.callback_data == "stop:test-session-123"


@pytest.mark.asyncio
async def test_approval_callback_approve_updates_database():
    """Test approval callback updates database and sets event."""
    # Mock update
    update = MagicMock(spec=Update)
    query = MagicMock(spec=CallbackQuery)
    query.answer = AsyncMock()
    query.edit_message_text = AsyncMock()
    query.data = "approve:123"
    update.callback_query = query

    # Mock context
    context = MagicMock()
    event = asyncio.Event()
    context.bot_data = {
        "approval_event_123": event,
    }

    # Mock database
    mock_approval = MagicMock()
    mock_approval.status = "pending"
    mock_approval.session_id = "test-session"
    mock_approval.tool_name = "sqlmap"
    mock_approval.blast_radius_text = "Test blast radius"

    with patch("scanner.telegram_bot.callbacks.get_session") as mock_get_session:
        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.commit = AsyncMock()

        # First execute: load approval request
        mock_result = MagicMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=mock_approval)
        mock_session.execute.return_value = mock_result

        mock_get_session.return_value = mock_session

        await approval_callback(update, context)

        # Verify query was answered
        query.answer.assert_called_once()

        # Verify message was edited
        assert query.edit_message_text.called

        # Verify event was set
        assert event.is_set()

        # Verify decision stored in bot_data
        assert context.bot_data["approval_decision_123"] == "approved"


@pytest.mark.asyncio
async def test_approval_callback_deny_sets_denied():
    """Test denial sets correct decision."""
    update = MagicMock(spec=Update)
    query = MagicMock(spec=CallbackQuery)
    query.answer = AsyncMock()
    query.edit_message_text = AsyncMock()
    query.data = "deny:456"
    update.callback_query = query

    context = MagicMock()
    event = asyncio.Event()
    context.bot_data = {"approval_event_456": event}

    mock_approval = MagicMock()
    mock_approval.status = "pending"
    mock_approval.blast_radius_text = "Test"

    with patch("scanner.telegram_bot.callbacks.get_session") as mock_get_session:
        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=mock_approval)
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()

        mock_get_session.return_value = mock_session

        await approval_callback(update, context)

        assert event.is_set()
        assert context.bot_data["approval_decision_456"] == "denied"


@pytest.mark.asyncio
async def test_continue_stop_callback_continue():
    """Test continue callback sets correct decision."""
    update = MagicMock(spec=Update)
    query = MagicMock(spec=CallbackQuery)
    query.answer = AsyncMock()
    query.edit_message_text = AsyncMock()
    query.data = "continue:session-abc"
    update.callback_query = query

    context = MagicMock()
    event = asyncio.Event()
    context.bot_data = {"continue_stop_event_session-abc": event}

    await continue_stop_callback(update, context)

    assert event.is_set()
    assert context.bot_data["continue_stop_decision_session-abc"] == "continue"
    query.answer.assert_called_once()


@pytest.mark.asyncio
async def test_continue_stop_callback_stop():
    """Test stop callback sets correct decision."""
    update = MagicMock(spec=Update)
    query = MagicMock(spec=CallbackQuery)
    query.answer = AsyncMock()
    query.edit_message_text = AsyncMock()
    query.data = "stop:session-xyz"
    update.callback_query = query

    context = MagicMock()
    event = asyncio.Event()
    context.bot_data = {"continue_stop_event_session-xyz": event}

    await continue_stop_callback(update, context)

    assert event.is_set()
    assert context.bot_data["continue_stop_decision_session-xyz"] == "stop"


@pytest.mark.asyncio
async def test_telegram_notifier_notify():
    """Test TelegramNotifier.notify sends message."""
    with patch("scanner.telegram_bot.notifications.Bot") as MockBot:
        mock_bot = MockBot.return_value
        mock_bot.send_message = AsyncMock()

        notifier = TelegramNotifier(token="test-token")
        result = await notifier.notify(chat_id=12345, message="Test message")

        assert result is True
        mock_bot.send_message.assert_called_once_with(
            chat_id=12345,
            text="Test message",
            parse_mode="HTML",
        )


@pytest.mark.asyncio
async def test_telegram_notifier_notify_handles_error():
    """Test TelegramNotifier handles errors gracefully."""
    from telegram.error import TelegramError

    with patch("scanner.telegram_bot.notifications.Bot") as MockBot:
        mock_bot = MockBot.return_value
        mock_bot.send_message = AsyncMock(side_effect=TelegramError("Network error"))

        notifier = TelegramNotifier(token="test-token")
        result = await notifier.notify(chat_id=12345, message="Test")

        assert result is False


def test_get_notifier_without_token_returns_none():
    """Test get_notifier returns None if TELEGRAM_BOT_TOKEN not set."""
    with patch("scanner.telegram_bot.notifications.os.getenv", return_value=None):
        # Reset global
        import scanner.telegram_bot.notifications
        scanner.telegram_bot.notifications._notifier = None

        notifier = get_notifier()
        assert notifier is None


def test_get_notifier_with_token_returns_instance():
    """Test get_notifier returns TelegramNotifier if token is set."""
    with patch("scanner.telegram_bot.notifications.os.getenv", return_value="test-token-123"):
        # Reset global
        import scanner.telegram_bot.notifications
        scanner.telegram_bot.notifications._notifier = None

        notifier = get_notifier()
        assert notifier is not None
        assert isinstance(notifier, TelegramNotifier)


def test_approval_request_model_imports():
    """Test ApprovalRequest model can be imported."""
    from scanner.core.persistence.models import ApprovalRequest

    assert ApprovalRequest.__tablename__ == "approval_requests"
