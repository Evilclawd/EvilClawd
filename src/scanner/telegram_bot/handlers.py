"""Telegram bot command and message handlers.

Implements all command handlers for the bot:
- /start - Welcome message
- /scan - Recon-only scan
- /vulnscan - Recon + vulnerability scan
- /exploit - Guided exploitation
- /report - Generate report
- /analyze - LLM-powered offensive/defensive analysis
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
from scanner.core.persistence.models import ScanQueue, ScanResult, Target, ApprovalRequest
from scanner.core.llm.tools import RiskLevel
from .formatters import (
    format_recon_summary,
    format_vuln_summary,
    format_finding_brief,
    format_queue_status,
    format_pipeline_stage,
    format_blast_radius,
)
from .callbacks import build_approval_keyboard, build_continue_stop_keyboard

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
        "EvilClawd ready. Send a target URL to start scanning, or use /help for commands."
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /help command - show available commands and tools."""
    help_text = (
        "<b>EvilClawd - AI Pentesting Assistant</b>\n\n"
        "<b>Quick Start:</b>\n"
        "Send any URL to run a full scan (recon + vuln scan).\n\n"
        "<b>Commands:</b>\n"
        "/scan &lt;url&gt; — Recon only (subdomains, ports, technologies)\n"
        "/vulnscan &lt;url&gt; — Recon + vulnerability scan\n"
        "/exploit &lt;session-id&gt; — Guided exploitation with approval\n"
        "/report &lt;session-id&gt; — View scan summary\n"
        "/analyze &lt;session-id&gt; — AI offensive/defensive analysis\n"
        "/status &lt;session-id&gt; — Check scan progress\n"
        "/queue — View scan queue\n"
        "/help — This message\n\n"
        "<b>Tools Used:</b>\n"
        "• <b>subfinder</b> — Subdomain enumeration\n"
        "• <b>nmap</b> — Port scanning &amp; service detection\n"
        "• <b>whatweb</b> — Technology fingerprinting\n"
        "• <b>sqlmap</b> — SQL injection testing\n"
        "• <b>xsser</b> — Cross-site scripting (XSS) testing\n"
        "• <b>commix</b> — Command injection testing\n"
        "• <b>headers</b> — Security header analysis\n\n"
        "<b>How It Works:</b>\n"
        "1. Send a URL → recon runs automatically\n"
        "2. Vuln scan tests for SQLi, XSS, CMDi, and header issues\n"
        "3. Exploitation shows blast radius and asks for approval\n"
        "4. Safe steps auto-execute, risky steps need your OK\n"
        "5. Use /report to get findings summary\n"
        "6. Use /analyze for AI attack scenarios &amp; remediation\n\n"
        "<i>Only scan targets you have authorization to test.</i>"
    )
    await update.message.reply_text(help_text, parse_mode="HTML")


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
    await update.message.reply_text(
        f"Starting recon scan on {html.escape(target_url)}...\nSession: <code>{session_id}</code>",
        parse_mode="HTML",
    )


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
    await update.message.reply_text(
        f"{msg}\nSession: <code>{session_id}</code>", parse_mode="HTML"
    )


async def exploit_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /exploit command - guided exploitation with inline keyboard approval."""
    await ensure_db()

    # Parse args: /exploit <session-id>
    if not context.args:
        await update.message.reply_text(
            "Usage: /exploit &lt;session-id&gt;", parse_mode="HTML"
        )
        return

    session_id = context.args[0]
    chat_id = update.effective_chat.id

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
        await update.message.reply_text("No exploitable vulnerabilities found", parse_mode="HTML")
        return

    # Deserialize findings
    findings = [Finding(**vuln_dict) for vuln_dict in vulnerabilities]

    # Notify user exploitation is starting
    await update.message.reply_text(
        f"Starting guided exploitation on {len(findings)} finding(s)...", parse_mode="HTML"
    )

    # Run exploitation in background
    asyncio.create_task(
        _run_exploit_chain(context, chat_id, session_id, findings)
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


async def analyze_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /analyze command - LLM-powered offensive/defensive analysis."""
    await ensure_db()

    if not context.args:
        await update.message.reply_text(
            "Usage: /analyze &lt;session-id&gt;", parse_mode="HTML"
        )
        return

    session_id = context.args[0]

    # Load findings and target URL from database
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

        # Get target URL from targets table
        target_result = await session.execute(
            select(Target).where(Target.id == scan_result.target_id)
        )
        target_obj = target_result.scalar_one_or_none()
        target_url = target_obj.url if target_obj else session_id

    findings_data = json.loads(scan_result.findings)
    vulnerabilities = findings_data.get("vulnerabilities", [])

    if not vulnerabilities:
        await update.message.reply_text("No vulnerabilities to analyze", parse_mode="HTML")
        return

    # Deserialize findings
    findings = [Finding(**vuln_dict) for vuln_dict in vulnerabilities]

    # Get recon summary if available
    attack_surface = findings_data.get("attack_surface", {})
    recon_summary = attack_surface.get("summary", None)

    await update.message.reply_text(
        "Generating AI analysis... this may take a moment.",
        parse_mode="HTML",
    )

    # Run analysis
    from scanner.core.reporting.generator import ReportGenerator

    generator = ReportGenerator()
    try:
        analysis = await generator.analyze(
            target=target_url,
            findings=findings,
            recon_summary=recon_summary,
        )
    except Exception as e:
        await update.message.reply_text(
            f"Analysis failed: {html.escape(str(e))}", parse_mode="HTML"
        )
        return

    # Telegram has a 4096 char limit per message — split if needed
    if len(analysis) <= 4000:
        await update.message.reply_text(analysis)
    else:
        # Split into chunks at paragraph boundaries
        chunks = []
        current = ""
        for line in analysis.split("\n"):
            if len(current) + len(line) + 1 > 4000:
                chunks.append(current)
                current = line
            else:
                current = current + "\n" + line if current else line
        if current:
            chunks.append(current)

        for chunk in chunks:
            await update.message.reply_text(chunk)


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

    # Extract URL from message - Telegram already detected it as a URL entity
    text = update.message.text.strip()
    if text.startswith(("http://", "https://")):
        target_url = text
    else:
        target_url = f"https://{text}"
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
        f"Starting scan on {html.escape(target_url)}...\nSession: <code>{session_id}</code>",
        parse_mode="HTML",
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
        # port_scan is a flattened services list, each item is one port
        port_count = sum(
            1 for svc in recon_results.get("port_scan", []) if svc.get("state") == "open"
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

        # Persist vuln findings to database so /exploit and /report can access them
        if findings:
            async with get_session() as session:
                result = await session.execute(
                    select(ScanResult).where(ScanResult.session_id == session_id)
                )
                scan_result = result.scalar_one_or_none()
                if scan_result:
                    existing_data = json.loads(scan_result.findings) if scan_result.findings else {}
                    existing_data["vulnerabilities"] = [f.model_dump() for f in findings]
                    await session.execute(
                        update(ScanResult)
                        .where(ScanResult.session_id == session_id)
                        .values(findings=json.dumps(existing_data, default=str))
                    )
                    await session.commit()

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


async def _run_exploit_chain(context, chat_id: int, session_id: str, findings: list[Finding]):
    """Run exploitation chain with inline keyboard approval workflow.

    Args:
        context: Bot context for callbacks and job queue
        chat_id: Telegram chat ID
        session_id: Session ID for this exploitation
        findings: List of findings to exploit
    """
    try:
        # Use ExploitAgent to generate chains
        exploit_agent = ExploitAgent(session_id=session_id)

        for finding in findings:
            # Generate exploit chain
            chain = await exploit_agent._suggest_chain(finding)

            await context.bot.send_message(
                chat_id=chat_id,
                text=f"<b>Exploit Chain for {html.escape(finding.title)}</b>\n"
                     f"Objective: {html.escape(chain.objective)}\n"
                     f"Steps: {len(chain.steps)}",
                parse_mode="HTML",
            )

            # Execute chain step by step
            for idx, step in enumerate(chain.steps, 1):
                # Format blast radius message
                step_dict = {
                    "tool": step.tool_name,
                    "risk_level": step.risk_level.value,
                    "description": step.description,
                    "blast_radius": step.blast_radius,
                    "affected_systems": step.affected_systems,
                    "reversible": step.reversible,
                }
                blast_radius_text = format_blast_radius(step_dict)

                # SAFE steps auto-execute
                if step.risk_level == RiskLevel.SAFE:
                    await context.bot.send_message(
                        chat_id=chat_id,
                        text=f"<b>Step {idx}/{len(chain.steps)}</b> [AUTO-EXECUTE]\n\n{blast_radius_text}",
                        parse_mode="HTML",
                    )

                    # Execute step (mock for now)
                    result = await exploit_agent._mock_tool_execution(step)

                    # Show result
                    await context.bot.send_message(
                        chat_id=chat_id,
                        text=f"✅ Step {idx} complete: {html.escape(result.get('status', 'success'))}",
                        parse_mode="HTML",
                    )
                    continue

                # MODERATE/DESTRUCTIVE require approval
                async with get_session() as session:
                    # Create approval request
                    approval_request = ApprovalRequest(
                        session_id=session_id,
                        chat_id=chat_id,
                        step_index=idx,
                        tool_name=step.tool_name,
                        risk_level=step.risk_level.value,
                        blast_radius_text=blast_radius_text,
                        status="pending",
                    )
                    session.add(approval_request)
                    await session.commit()
                    await session.refresh(approval_request)
                    approval_id = approval_request.id

                # Send approval request with inline keyboard
                message = await context.bot.send_message(
                    chat_id=chat_id,
                    text=f"<b>Step {idx}/{len(chain.steps)}</b> - APPROVAL REQUIRED\n\n{blast_radius_text}",
                    reply_markup=build_approval_keyboard(approval_id),
                    parse_mode="HTML",
                )

                # Store message_id in database
                async with get_session() as session:
                    await session.execute(
                        update(ApprovalRequest)
                        .where(ApprovalRequest.id == approval_id)
                        .values(message_id=message.message_id)
                    )
                    await session.commit()

                # Create event for this approval
                approval_event = asyncio.Event()
                context.bot_data[f"approval_event_{approval_id}"] = approval_event

                # Schedule reminder (5 minutes)
                context.job_queue.run_once(
                    callback=lambda ctx: ctx.job.data["reminder_callback"](ctx),
                    when=300,  # 5 minutes
                    data={
                        "approval_id": approval_id,
                        "chat_id": chat_id,
                        "reminder_callback": lambda ctx: _send_approval_reminder(ctx, approval_id, chat_id),
                    },
                    name=f"reminder_{approval_id}",
                )

                # Schedule auto-deny (15 minutes)
                context.job_queue.run_once(
                    callback=lambda ctx: ctx.job.data["auto_deny_callback"](ctx),
                    when=900,  # 15 minutes
                    data={
                        "approval_id": approval_id,
                        "chat_id": chat_id,
                        "auto_deny_callback": lambda ctx: _auto_deny_approval(ctx, approval_id, chat_id, approval_event),
                    },
                    name=f"auto_deny_{approval_id}",
                )

                # Wait for user decision
                await approval_event.wait()

                # Get decision
                decision = context.bot_data.get(f"approval_decision_{approval_id}", "denied")

                # Cancel pending jobs
                current_jobs = context.job_queue.get_jobs_by_name(f"reminder_{approval_id}")
                for job in current_jobs:
                    job.schedule_removal()
                current_jobs = context.job_queue.get_jobs_by_name(f"auto_deny_{approval_id}")
                for job in current_jobs:
                    job.schedule_removal()

                # Clean up bot_data
                context.bot_data.pop(f"approval_event_{approval_id}", None)
                context.bot_data.pop(f"approval_decision_{approval_id}", None)

                # Handle denial
                if decision in ("denied", "auto_denied"):
                    await context.bot.send_message(
                        chat_id=chat_id,
                        text=f"Step {idx} {decision}. Continue with remaining steps or stop?",
                        reply_markup=build_continue_stop_keyboard(session_id),
                        parse_mode="HTML",
                    )

                    # Wait for continue/stop decision
                    continue_stop_event = asyncio.Event()
                    context.bot_data[f"continue_stop_event_{session_id}"] = continue_stop_event

                    await continue_stop_event.wait()

                    action = context.bot_data.get(f"continue_stop_decision_{session_id}", "stop")
                    context.bot_data.pop(f"continue_stop_event_{session_id}", None)
                    context.bot_data.pop(f"continue_stop_decision_{session_id}", None)

                    if action == "stop":
                        await context.bot.send_message(
                            chat_id=chat_id,
                            text="Exploitation stopped by user",
                            parse_mode="HTML",
                        )
                        return  # Stop entire exploitation

                    # Continue to next step
                    continue

                # Execute approved step
                result = await exploit_agent._mock_tool_execution(step)

                await context.bot.send_message(
                    chat_id=chat_id,
                    text=f"✅ Step {idx} complete: {html.escape(result.get('status', 'success'))}",
                    parse_mode="HTML",
                )

        # Exploitation complete
        await context.bot.send_message(
            chat_id=chat_id,
            text=f"Exploitation complete for session {html.escape(session_id)}",
            parse_mode="HTML",
        )

    except Exception as e:
        logger.error("exploit_chain_failed", error=str(e), session_id=session_id)
        await context.bot.send_message(
            chat_id=chat_id,
            text=f"Exploitation failed: {html.escape(str(e))}",
            parse_mode="HTML",
        )


async def _send_approval_reminder(context, approval_id: int, chat_id: int):
    """Send reminder for pending approval."""
    async with get_session() as session:
        result = await session.execute(
            select(ApprovalRequest).where(ApprovalRequest.id == approval_id)
        )
        approval_request = result.scalar_one_or_none()

        if not approval_request or approval_request.status != "pending":
            return  # Already resolved

    await context.bot.send_message(
        chat_id=chat_id,
        text=f"⏰ Reminder: Approval request #{approval_id} still pending (auto-deny in 10 minutes)",
    )


async def _auto_deny_approval(context, approval_id: int, chat_id: int, event: asyncio.Event):
    """Auto-deny approval after timeout."""
    async with get_session() as session:
        result = await session.execute(
            select(ApprovalRequest).where(ApprovalRequest.id == approval_id)
        )
        approval_request = result.scalar_one_or_none()

        if not approval_request or approval_request.status != "pending":
            return  # Already resolved

        # Auto-deny
        await session.execute(
            update(ApprovalRequest)
            .where(ApprovalRequest.id == approval_id)
            .values(
                status="auto_denied",
                resolved_at=datetime.now(timezone.utc)
            )
        )
        await session.commit()

    await context.bot.send_message(
        chat_id=chat_id,
        text=f"⏱ Auto-denied approval request #{approval_id} (15 minute timeout)",
    )

    # Set event to unblock
    context.bot_data[f"approval_decision_{approval_id}"] = "auto_denied"
    event.set()


# Handler registrations
start_handler = CommandHandler("start", start_command)
help_handler = CommandHandler("help", help_command)
scan_handler = CommandHandler("scan", scan_command)
vulnscan_handler = CommandHandler("vulnscan", vulnscan_command)
exploit_handler = CommandHandler("exploit", exploit_command)
report_handler = CommandHandler("report", report_command)
analyze_handler = CommandHandler("analyze", analyze_command)
status_handler = CommandHandler("status", status_command)
queue_handler = CommandHandler("queue", queue_command)
url_handler = MessageHandler(filters.Entity("url"), url_message)
