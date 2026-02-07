"""Cross-interface Telegram notifications.

Provides TelegramNotifier for sending messages from any context (CLI, agents, etc.).
Uses standalone Bot instance initialized from environment variable.
"""

import os
from typing import Optional

import structlog
from telegram import Bot
from telegram.error import TelegramError

logger = structlog.get_logger()


class TelegramNotifier:
    """Standalone Telegram notifier for cross-interface messaging.

    This allows sending Telegram messages from CLI or agent contexts without
    requiring a full Application instance. Uses Bot API directly.
    """

    def __init__(self, token: str):
        """Initialize notifier with bot token.

        Args:
            token: Telegram bot token from @BotFather
        """
        self.bot = Bot(token=token)

    async def notify(self, chat_id: int, message: str, parse_mode: str = "HTML") -> bool:
        """Send notification message to chat.

        Args:
            chat_id: Telegram chat ID to send to
            message: Message text (supports HTML if parse_mode="HTML")
            parse_mode: Message formatting mode (HTML or Markdown)

        Returns:
            True if sent successfully, False otherwise
        """
        try:
            await self.bot.send_message(
                chat_id=chat_id,
                text=message,
                parse_mode=parse_mode,
            )
            return True
        except TelegramError as e:
            logger.error("telegram_notify_failed", chat_id=chat_id, error=str(e))
            return False

    async def notify_scan_complete(
        self,
        chat_id: int,
        session_id: str,
        target_url: str,
        finding_count: int
    ) -> bool:
        """Send scan completion notification.

        Args:
            chat_id: Telegram chat ID
            session_id: Session identifier
            target_url: Target that was scanned
            finding_count: Number of findings discovered

        Returns:
            True if sent successfully
        """
        message = (
            f"✅ <b>Scan Complete</b>\n"
            f"Target: {target_url}\n"
            f"Session: <code>{session_id}</code>\n"
            f"Findings: {finding_count}\n\n"
            f"Use /report {session_id} to view details"
        )
        return await self.notify(chat_id, message)

    async def notify_approval_needed(
        self,
        chat_id: int,
        tool_name: str,
        risk_level: str,
        blast_radius: str,
        approval_id: int
    ) -> bool:
        """Send approval request notification.

        Args:
            chat_id: Telegram chat ID
            tool_name: Tool requiring approval
            risk_level: Risk classification (MODERATE/DESTRUCTIVE)
            blast_radius: Description of potential impact
            approval_id: Database ID for approval tracking

        Returns:
            True if sent successfully
        """
        message = (
            f"⚠️ <b>Approval Required</b>\n"
            f"Tool: {tool_name}\n"
            f"Risk: <b>{risk_level}</b>\n\n"
            f"{blast_radius}\n\n"
            f"Request ID: {approval_id}"
        )
        return await self.notify(chat_id, message)


# Global singleton
_notifier: Optional[TelegramNotifier] = None


def get_notifier() -> Optional[TelegramNotifier]:
    """Get global TelegramNotifier instance.

    Initializes from TELEGRAM_BOT_TOKEN environment variable on first call.
    Returns None if token is not set.

    Returns:
        TelegramNotifier instance or None if no token configured
    """
    global _notifier

    if _notifier is not None:
        return _notifier

    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        logger.debug("telegram_notifier_disabled", reason="TELEGRAM_BOT_TOKEN not set")
        return None

    _notifier = TelegramNotifier(token)
    logger.info("telegram_notifier_initialized")
    return _notifier
