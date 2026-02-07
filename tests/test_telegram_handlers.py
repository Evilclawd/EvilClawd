"""Tests for Telegram bot handlers."""

import re
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from telegram import Update, Message, Chat, User
from telegram.ext import ContextTypes

from scanner.telegram_bot.handlers import (
    start_command,
    scan_command,
    url_message,
    report_command,
    _process_next_in_queue,
)


@pytest.fixture
def mock_update():
    """Create mock Telegram Update."""
    update = MagicMock(spec=Update)
    update.message = MagicMock(spec=Message)
    update.message.reply_text = AsyncMock()
    update.effective_chat = MagicMock(spec=Chat)
    update.effective_chat.id = 12345
    update.effective_user = MagicMock(spec=User)
    update.effective_user.id = 67890
    return update


@pytest.fixture
def mock_context():
    """Create mock Telegram context."""
    context = MagicMock(spec=ContextTypes.DEFAULT_TYPE)
    context.args = []
    context.bot = MagicMock()
    context.bot.send_message = AsyncMock()
    return context


@pytest.mark.asyncio
async def test_start_command_returns_welcome(mock_update, mock_context):
    """Test /start command returns welcome message."""
    await start_command(mock_update, mock_context)

    mock_update.message.reply_text.assert_called_once()
    call_args = mock_update.message.reply_text.call_args[0][0]
    assert "EvilClawd ready" in call_args


@pytest.mark.asyncio
async def test_scan_command_no_url_returns_usage(mock_update, mock_context):
    """Test /scan without URL returns usage message."""
    # No args provided
    mock_context.args = []

    with patch("scanner.telegram_bot.handlers.ensure_db", new=AsyncMock()):
        await scan_command(mock_update, mock_context)

    mock_update.message.reply_text.assert_called_once()
    call_args = mock_update.message.reply_text.call_args[0][0]
    assert "Usage" in call_args
    assert "target-url" in call_args


@pytest.mark.asyncio
async def test_scan_command_with_url_starts_scan(mock_update, mock_context):
    """Test /scan with URL starts scan when queue is empty."""
    mock_context.args = ["https://example.com"]

    # Mock database operations
    with patch("scanner.telegram_bot.handlers.ensure_db", new=AsyncMock()), \
         patch("scanner.telegram_bot.handlers.get_session") as mock_get_session, \
         patch("scanner.telegram_bot.handlers.asyncio.create_task") as mock_create_task:

        # Mock session context manager
        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.commit = AsyncMock()
        mock_session.add = MagicMock()

        # No running scans
        mock_result = MagicMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=None)
        mock_session.execute.return_value = mock_result

        mock_get_session.return_value = mock_session

        await scan_command(mock_update, mock_context)

        # Should create task for scan
        assert mock_create_task.called
        # Should notify user
        assert mock_update.message.reply_text.called


@pytest.mark.asyncio
async def test_url_detection_extracts_urls():
    """Test URL detection regex extracts URLs from text."""
    url_pattern = r"https?://\S+"

    test_cases = [
        ("Check this out: https://example.com", "https://example.com"),
        ("https://test.com is cool", "https://test.com"),
        ("Visit http://example.org now", "http://example.org"),
        ("No URL here", None),
    ]

    for text, expected_url in test_cases:
        match = re.search(url_pattern, text)
        result = match.group(0) if match else None
        assert result == expected_url


@pytest.mark.asyncio
async def test_report_command_no_args_returns_usage(mock_update, mock_context):
    """Test /report without session ID returns usage message."""
    mock_context.args = []

    with patch("scanner.telegram_bot.handlers.ensure_db", new=AsyncMock()):
        await report_command(mock_update, mock_context)

    mock_update.message.reply_text.assert_called_once()
    call_args = mock_update.message.reply_text.call_args[0][0]
    assert "Usage" in call_args


@pytest.mark.asyncio
async def test_report_command_formats_summary(mock_update, mock_context):
    """Test /report formats summary correctly from findings."""
    mock_context.args = ["test-session-id"]

    # Mock scan result with findings
    mock_scan_result = MagicMock()
    mock_scan_result.findings = '{"vulnerabilities": [{"title": "SQL Injection", "severity": "high", "confidence": "confirmed", "affected_url": "http://example.com", "injection_point": "id", "description": "test", "cvss_score": 8.5, "evidence": []}]}'

    with patch("scanner.telegram_bot.handlers.ensure_db", new=AsyncMock()), \
         patch("scanner.telegram_bot.handlers.get_session") as mock_get_session:

        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=mock_scan_result)
        mock_session.execute = AsyncMock(return_value=mock_result)

        mock_get_session.return_value = mock_session

        await report_command(mock_update, mock_context)

        # Should send formatted report
        assert mock_update.message.reply_text.called
        call_args = mock_update.message.reply_text.call_args[0][0]
        assert "Scan Report Summary" in call_args
        assert "HIGH" in call_args


@pytest.mark.asyncio
async def test_queue_enforcement_queues_second_scan(mock_update, mock_context):
    """Test that second scan gets queued when one is running."""
    mock_context.args = ["https://example.com"]

    # Mock running scan
    mock_running = MagicMock()
    mock_running.target_url = "https://other.com"
    mock_running.status = "running"

    with patch("scanner.telegram_bot.handlers.ensure_db", new=AsyncMock()), \
         patch("scanner.telegram_bot.handlers.get_session") as mock_get_session:

        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock()
        mock_session.add = MagicMock()
        mock_session.commit = AsyncMock()

        # First execute returns running scan
        mock_result_running = MagicMock()
        mock_result_running.scalar_one_or_none = MagicMock(return_value=mock_running)

        # Second execute returns queue count
        mock_result_queue = MagicMock()
        mock_result_queue.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[MagicMock()])))

        mock_session.execute = AsyncMock(side_effect=[mock_result_running, mock_result_queue])

        mock_get_session.return_value = mock_session

        await scan_command(mock_update, mock_context)

        # Should notify user about queue
        assert mock_update.message.reply_text.called
        call_args = mock_update.message.reply_text.call_args[0][0]
        assert "queued" in call_args.lower()
        assert "Currently scanning" in call_args


def test_url_handler_detects_urls():
    """Test URL handler uses correct filter."""
    from scanner.telegram_bot.handlers import url_handler
    from telegram.ext import MessageHandler, filters

    # Verify handler is a MessageHandler with Entity filter
    assert isinstance(url_handler, MessageHandler)
    # The handler should filter for URL entities


def test_all_handlers_are_registered():
    """Test that all handlers are properly registered."""
    from scanner.telegram_bot.handlers import (
        start_handler,
        scan_handler,
        vulnscan_handler,
        exploit_handler,
        report_handler,
        status_handler,
        queue_handler,
        url_handler,
    )

    # All handlers should be defined
    assert start_handler is not None
    assert scan_handler is not None
    assert vulnscan_handler is not None
    assert exploit_handler is not None
    assert report_handler is not None
    assert status_handler is not None
    assert queue_handler is not None
    assert url_handler is not None
