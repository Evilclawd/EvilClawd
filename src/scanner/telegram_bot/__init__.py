"""Telegram bot interface for EvilClawd scanner.

Provides:
- Bot initialization with manual polling lifecycle
- Command handlers for scan operations
- HTML formatters for status messages
- Inline keyboard callback handlers for approval workflow
"""

from telegram.ext import Application, ApplicationBuilder, CallbackQueryHandler

from .handlers import (
    start_handler,
    url_handler,
    scan_handler,
    vulnscan_handler,
    exploit_handler,
    report_handler,
    status_handler,
    queue_handler,
)
from .callbacks import approval_callback, continue_stop_callback


def create_bot_app(token: str) -> Application:
    """Create and configure Telegram bot application.

    Args:
        token: Telegram bot token from @BotFather

    Returns:
        Configured Application instance with all handlers registered
    """
    # Build application
    app = ApplicationBuilder().token(token).build()

    # Register all command and message handlers
    app.add_handler(start_handler)
    app.add_handler(url_handler)
    app.add_handler(scan_handler)
    app.add_handler(vulnscan_handler)
    app.add_handler(exploit_handler)
    app.add_handler(report_handler)
    app.add_handler(status_handler)
    app.add_handler(queue_handler)

    # Register callback query handlers for inline keyboards
    app.add_handler(CallbackQueryHandler(approval_callback, pattern=r"^(approve|deny):\d+$"))
    app.add_handler(CallbackQueryHandler(continue_stop_callback, pattern=r"^(continue|stop):.+$"))

    return app


async def run_bot(app: Application) -> None:
    """Start bot with manual polling lifecycle.

    Does NOT call run_polling() to avoid blocking the event loop.
    Use this in async contexts where you need control over the lifecycle.

    Args:
        app: Application instance from create_bot_app()
    """
    await app.initialize()
    await app.start()
    await app.updater.start_polling()


async def stop_bot(app: Application) -> None:
    """Stop bot and clean up resources.

    Args:
        app: Application instance to stop
    """
    await app.updater.stop()
    await app.stop()
    await app.shutdown()


__all__ = ["create_bot_app", "run_bot", "stop_bot"]
