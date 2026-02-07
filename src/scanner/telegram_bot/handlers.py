"""Telegram bot command and message handlers.

Implements all command handlers for the bot:
- /start - Welcome message
- /scan - Recon-only scan
- /vulnscan - Recon + vulnerability scan
- /exploit - Guided exploitation
- /report - Generate report
- /status - Check scan status
- /queue - Show scan queue
- URL detection - Full pipeline on bare URLs
"""

import asyncio
import html
import json
import re
from datetime import datetime, timezone
from uuid import uuid4

import structlog
from sqlalchemy import select, update
from telegram import Update
from telegram.ext import CommandHandler, ContextTypes, MessageHandler, filters

from scanner.agents import ReconAgent, VulnAgent, ExploitAgent
from scanner.core.config import load_config
from scanner.core.output import Finding
from scanner.core.persistence.database import (
    init_database,
    create_session_factory,
    get_session,
)
from scanner.core.persistence.models import ScanQueue, ScanResult, Target
from .formatters import (
    format_recon_summary,
    format_vuln_summary,
    format_finding_brief,
    format_queue_status,
    format_pipeline_stage,
)

logger = structlog.get_logger()

# Database initialization flag
_db_initialized = False


async def ensure_db():
    """Initialize database if not already initialized."""
    global _db_initialized
    if not _db_initialized:
        engine = await init_database()
        create_session_factory(engine)
        _db_initialized = True


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command."""
    await update.message.reply_text(
        "EvilClawd ready. Send a target URL or use /scan, /vulnscan, /exploit, /report."
    )


async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /scan command - recon only."""
    await ensure_db()

    # Extract URL from command args
    if not context.args:
        await update.message.reply_text(
            "Usage: /scan &lt;target-url&gt;", parse_mode="HTML"
        )
        return

    target_url = context.args[0]
    chat_id = update.effective_chat.id

    # Check queue
    async with get_session() as session:
        result = await session.execute(
            select(ScanQueue).where(ScanQueue.status == "running")
        )
        running = result.scalar_one_or_none()

        if running:
            # Queue this scan
            session_id = str(uuid4())
            queued = ScanQueue(
                chat_id=chat_id,
                target_url=target_url,
                command="scan",
                session_id=session_id,
                status="queued",
            )
            session.add(queued)
            await session.commit()

            # Count queue position
            result = await session.execute(
                select(ScanQueue).where(ScanQueue.status == "queued")
            )
            queue_count = len(result.scalars().all())

            running_url_escaped = html.escape(running.target_url)
            await update.message.reply_text(
                f"Scan queued (#{queue_count} in queue). Currently scanning: {running_url_escaped}",
                parse_mode="HTML",
            )
            return

        # No scan running, create entry and start
        session_id = str(uuid4())
        queue_entry = ScanQueue(
            chat_id=chat_id,
            target_url=target_url,
            command="scan",
            session_id=session_id,
            status="running",
        )
        session.add(queue_entry)
        await session.commit()

    # Run scan in background
    asyncio.create_task(
        _run_scan_pipeline(context.bot, chat_id, target_url, session_id, "scan")
    )
    await update.message.reply_text(f"Starting recon scan on {html.escape(target_url)}...", parse_mode="HTML")


async def vulnscan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /vulnscan command - recon + vuln scan."""
    await ensure_db()

    # Parse args: /vulnscan <url> or /vulnscan --session-id <id>
    if not context.args:
        await update.message.reply_text(
            "Usage: /vulnscan &lt;target-url&gt; or /vulnscan --session-id &lt;id&gt;",
            parse_mode="HTML",
        )
        return

    chat_id = update.effective_chat.id

    if context.args[0] == "--session-id":
        if len(context.args) < 2:
            await update.message.reply_text(
                "Usage: /vulnscan --session-id &lt;id&gt;", parse_mode="HTML"
            )
            return
        session_id = context.args[1]
        target_url = None  # Will load from session
    else:
        target_url = context.args[0]
        session_id = str(uuid4())

    # Check queue
    async with get_session() as session:
        result = await session.execute(
            select(ScanQueue).where(ScanQueue.status == "running")
        )
        running = result.scalar_one_or_none()

        if running:
            # Queue this scan
            queued = ScanQueue(
                chat_id=chat_id,
                target_url=target_url or session_id,
                command="vulnscan",
                session_id=session_id,
                status="queued",
            )
            session.add(queued)
            await session.commit()

            result = await session.execute(
                select(ScanQueue).where(ScanQueue.status == "queued")
            )
            queue_count = len(result.scalars().all())

            running_url_escaped = html.escape(running.target_url)
            await update.message.reply_text(
                f"Scan queued (#{queue_count} in queue). Currently scanning: {running_url_escaped}",
                parse_mode="HTML",
            )
            return

        # No scan running
        queue_entry = ScanQueue(
            chat_id=chat_id,
            target_url=target_url or session_id,
            command="vulnscan",
            session_id=session_id,
            status="running",
        )
        session.add(queue_entry)
        await session.commit()

    # Run scan in background
    asyncio.create_task(
        _run_scan_pipeline(context.bot, chat_id, target_url, session_id, "vulnscan")
    )
    msg = f"Starting vulnerability scan on {html.escape(target_url)}..." if target_url else f"Starting vulnerability scan for session {session_id}..."
    await update.message.reply_text(msg, parse_mode="HTML")


async def exploit_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /exploit command - guided exploitation (Plan 02)."""
    await update.message.reply_text(
        "Exploitation requires approval workflow. Use CLI for now, or wait for inline approval setup."
    )


async def report_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /report command - generate and send report summary."""
    await ensure_db()

    if not context.args:
        await update.message.reply_text("Usage: /report &lt;session-id&gt;", parse_mode="HTML")
        return

    session_id = context.args[0]

    # Load findings from database
    async with get_session() as session:
        result = await session.execute(
            select(ScanResult).where(ScanResult.session_id == session_id)
        )
        scan_result = result.scalar_one_or_none()

    if not scan_result or not scan_result.findings:
        await update.message.reply_text(
            f"No findings found for session {html.escape(session_id)}", parse_mode="HTML"
        )
        return

    findings_data = json.loads(scan_result.findings)
    vulnerabilities = findings_data.get("vulnerabilities", [])

    if not vulnerabilities:
        await update.message.reply_text("No vulnerabilities to report", parse_mode="HTML")
        return

    # Deserialize findings
    findings = [Finding(**vuln_dict) for vuln_dict in vulnerabilities]

    # Count by severity
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for finding in findings:
        severity = finding.severity.upper()
        if severity in by_severity:
            by_severity[severity] += 1

    # Format report summary
    lines = ["<b>Scan Report Summary</b>", f"<b>Session:</b> {html.escape(session_id)}", ""]

    # Severity counts
    for severity, count in by_severity.items():
        if count > 0:
            lines.append(f"<b>{severity}:</b> {count}")

    # Top 3 findings
    lines.append("\n<b>Top Findings:</b>")
    for finding in findings[:3]:
        lines.append(f"• {format_finding_brief(finding)}")

    if len(findings) > 3:
        lines.append(f"... and {len(findings) - 3} more")

    lines.append(f"\n<i>Use CLI 'evilclawd report {session_id}' for full report</i>")

    await update.message.reply_text("\n".join(lines), parse_mode="HTML")


async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /status command - check scan status."""
    await ensure_db()

    if not context.args:
        await update.message.reply_text("Usage: /status &lt;session-id&gt;", parse_mode="HTML")
        return

    session_id = context.args[0]

    # Load scan result
    async with get_session() as session:
        result = await session.execute(
            select(ScanResult).where(ScanResult.session_id == session_id)
        )
        scan_result = result.scalar_one_or_none()

    if not scan_result:
        await update.message.reply_text(
            f"No results found for session {html.escape(session_id)}", parse_mode="HTML"
        )
        return

    # Parse findings for counts
    findings_data = json.loads(scan_result.findings) if scan_result.findings else {}
    vulnerabilities = findings_data.get("vulnerabilities", [])
    attack_surface = findings_data.get("attack_surface", {})
    summary = attack_surface.get("summary", {})

    lines = [
        f"<b>Scan Status</b>",
        f"<b>Session:</b> {html.escape(session_id)}",
        f"<b>Status:</b> {scan_result.status}",
        f"<b>Started:</b> {scan_result.started_at}",
        f"<b>Completed:</b> {scan_result.completed_at or 'In progress'}",
        "",
    ]

    if summary:
        lines.append("<b>Recon Summary:</b>")
        lines.append(f"Subdomains: {summary.get('total_subdomains', 0)}")
        lines.append(f"Open ports: {summary.get('total_open_ports', 0)}")
        lines.append(f"Technologies: {summary.get('total_technologies', 0)}")
        lines.append("")

    if vulnerabilities:
        lines.append(f"<b>Vulnerabilities:</b> {len(vulnerabilities)}")

    await update.message.reply_text("\n".join(lines), parse_mode="HTML")


async def queue_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /queue command - show scan queue."""
    await ensure_db()

    async with get_session() as session:
        result = await session.execute(
            select(ScanQueue)
            .where(ScanQueue.status.in_(["queued", "running"]))
            .order_by(ScanQueue.created_at)
        )
        queue_items = result.scalars().all()

    if not queue_items:
        await update.message.reply_text("Queue is empty")
        return

    message = format_queue_status(queue_items)
    await update.message.reply_text(message, parse_mode="HTML")


async def url_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle URL messages - trigger full pipeline."""
    await ensure_db()

    # Extract URL from message
    url_pattern = r"https?://\S+"
    match = re.search(url_pattern, update.message.text)
    if not match:
        return

    target_url = match.group(0)
    chat_id = update.effective_chat.id

    # Check queue
    async with get_session() as session:
        result = await session.execute(
            select(ScanQueue).where(ScanQueue.status == "running")
        )
        running = result.scalar_one_or_none()

        if running:
            # Queue this scan
            session_id = str(uuid4())
            queued = ScanQueue(
                chat_id=chat_id,
                target_url=target_url,
                command="full_pipeline",
                session_id=session_id,
                status="queued",
            )
            session.add(queued)
            await session.commit()

            result = await session.execute(
                select(ScanQueue).where(ScanQueue.status == "queued")
            )
            queue_count = len(result.scalars().all())

            running_url_escaped = html.escape(running.target_url)
            await update.message.reply_text(
                f"Scan queued (#{queue_count} in queue). Currently scanning: {running_url_escaped}",
                parse_mode="HTML",
            )
            return

        # No scan running
        session_id = str(uuid4())
        queue_entry = ScanQueue(
            chat_id=chat_id,
            target_url=target_url,
            command="full_pipeline",
            session_id=session_id,
            status="running",
        )
        session.add(queue_entry)
        await session.commit()

    # Run full pipeline in background
    asyncio.create_task(
        _run_scan_pipeline(context.bot, chat_id, target_url, session_id, "full_pipeline")
    )
    await update.message.reply_text(
        f"Starting scan on {html.escape(target_url)}...", parse_mode="HTML"
    )


async def _run_scan_pipeline(bot, chat_id: int, target_url: str, session_id: str, command: str):
    """Run scan pipeline in background with status updates.

    Args:
        bot: Telegram bot instance
        chat_id: Chat ID to send updates to
        target_url: Target URL to scan
        session_id: Session ID for this scan
        command: Command type (scan/vulnscan/full_pipeline)
    """
    try:
        # Ensure target is authorized (add automatically with URL as scope)
        async with get_session() as session:
            result = await session.execute(
                select(Target).where(Target.url == target_url)
            )
            target = result.scalar_one_or_none()

            if not target:
                # Auto-authorize target
                target = Target(
                    url=target_url,
                    scope=json.dumps([target_url]),
                    authorized_by="telegram-bot",
                )
                session.add(target)
                await session.commit()

        # Step 1: Run recon
        recon_agent = ReconAgent(session_id=session_id)
        recon_results = await recon_agent.run(target_url)

        # Send recon status update
        subdomain_count = len(recon_results.get("subdomains", []))
        port_count = sum(
            len(host.get("ports", [])) for host in recon_results.get("port_scan", [])
        )
        await bot.send_message(
            chat_id=chat_id,
            text=format_pipeline_stage(
                "Recon complete", f"{subdomain_count} subdomains, {port_count} open ports"
            ),
            parse_mode="HTML",
        )

        # If command is scan-only, stop here
        if command == "scan":
            await _complete_scan(bot, chat_id, session_id, target_url)
            return

        # Step 2: Run vuln scan
        vuln_agent = VulnAgent(session_id=session_id)
        findings = await vuln_agent.scan(target_url, recon_results)

        # Send vuln scan status update
        await bot.send_message(
            chat_id=chat_id, text=format_vuln_summary(findings), parse_mode="HTML"
        )

        # If full pipeline, stop before exploitation
        if command == "full_pipeline":
            await bot.send_message(
                chat_id=chat_id,
                text=f"Pipeline paused before exploitation. {len(findings)} findings ready. Use /exploit to start guided exploitation with approval prompts.",
                parse_mode="HTML",
            )

        # Mark as complete
        await _complete_scan(bot, chat_id, session_id, target_url)

    except Exception as e:
        logger.error("scan_pipeline_failed", error=str(e), session_id=session_id)

        # Update queue status to failed
        async with get_session() as session:
            await session.execute(
                update(ScanQueue)
                .where(ScanQueue.session_id == session_id)
                .values(
                    status="failed",
                    error_message=str(e),
                    completed_at=datetime.now(timezone.utc),
                )
            )
            await session.commit()

        # Send error message
        await bot.send_message(
            chat_id=chat_id, text=f"Scan failed: {html.escape(str(e))}", parse_mode="HTML"
        )

        # Process next in queue
        await _process_next_in_queue(bot)


async def _complete_scan(bot, chat_id: int, session_id: str, target_url: str):
    """Mark scan as complete and process next in queue."""
    # Update queue status
    async with get_session() as session:
        await session.execute(
            update(ScanQueue)
            .where(ScanQueue.session_id == session_id)
            .values(status="completed", completed_at=datetime.now(timezone.utc))
        )
        await session.commit()

    await bot.send_message(
        chat_id=chat_id,
        text=f"Scan complete. Session ID: <code>{session_id}</code>",
        parse_mode="HTML",
    )

    # Process next queued scan
    await _process_next_in_queue(bot)


async def _process_next_in_queue(bot):
    """Check for queued scans and start the next one."""
    async with get_session() as session:
        # Find next queued item
        result = await session.execute(
            select(ScanQueue)
            .where(ScanQueue.status == "queued")
            .order_by(ScanQueue.created_at)
        )
        next_item = result.scalar_one_or_none()

        if next_item:
            # Update status to running
            next_item.status = "running"
            await session.commit()

            # Start the scan
            asyncio.create_task(
                _run_scan_pipeline(
                    bot,
                    next_item.chat_id,
                    next_item.target_url,
                    next_item.session_id,
                    next_item.command,
                )
            )

            # Notify user
            await bot.send_message(
                chat_id=next_item.chat_id,
                text=f"Starting queued scan on {html.escape(next_item.target_url)}...",
                parse_mode="HTML",
            )


# Handler registrations
start_handler = CommandHandler("start", start_command)
scan_handler = CommandHandler("scan", scan_command)
vulnscan_handler = CommandHandler("vulnscan", vulnscan_command)
exploit_handler = CommandHandler("exploit", exploit_command)
report_handler = CommandHandler("report", report_command)
status_handler = CommandHandler("status", status_command)
queue_handler = CommandHandler("queue", queue_command)
url_handler = MessageHandler(filters.Entity("url"), url_message)
