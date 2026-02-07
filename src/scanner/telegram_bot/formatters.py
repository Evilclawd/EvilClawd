"""HTML message formatters for Telegram bot.

All functions return HTML-formatted strings for Telegram's parse_mode="HTML".
User-provided data is escaped to prevent injection.
"""

import html


def format_recon_summary(results: dict) -> str:
    """Format brief recon results summary.

    Args:
        results: Recon results dict with subdomains, port_scan, technologies

    Returns:
        HTML-formatted summary string
    """
    subdomain_count = len(results.get("subdomains", []))
    port_count = sum(len(host.get("ports", [])) for host in results.get("port_scan", []))
    tech_count = sum(len(t.get("technologies", [])) for t in results.get("technologies", []))

    return (
        f"<b>Recon Complete</b>\n"
        f"Subdomains: {subdomain_count}\n"
        f"Open ports: {port_count}\n"
        f"Technologies: {tech_count}"
    )


def format_vuln_summary(findings: list) -> str:
    """Format vulnerability findings grouped by severity.

    Args:
        findings: List of Finding objects or dicts with severity field

    Returns:
        HTML-formatted summary with counts by severity
    """
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for finding in findings:
        severity = finding.get("severity", "INFO").upper() if isinstance(finding, dict) else getattr(finding, "severity", "INFO").upper()
        if severity in severity_counts:
            severity_counts[severity] += 1

    # Build summary with non-zero counts
    lines = ["<b>Vulnerability Scan Complete</b>"]
    for severity, count in severity_counts.items():
        if count > 0:
            lines.append(f"<b>{severity}</b>: {count}")

    return "\n".join(lines)


def format_finding_brief(finding) -> str:
    """Format single finding as one-liner.

    Args:
        finding: Finding object or dict with severity, title

    Returns:
        One-line HTML-formatted finding summary
    """
    if isinstance(finding, dict):
        severity = finding.get("severity", "INFO")
        title = finding.get("title", "Unknown")
    else:
        severity = getattr(finding, "severity", "INFO")
        title = getattr(finding, "title", "Unknown")

    title_escaped = html.escape(title)
    return f"<b>{severity}</b>: {title_escaped}"


def format_blast_radius(step: dict) -> str:
    """Format blast radius for approval messages.

    Args:
        step: Exploitation step dict with tool, risk_level, description, blast_radius, affected_systems, reversible

    Returns:
        HTML-formatted blast radius description
    """
    tool = html.escape(step.get("tool", "Unknown"))
    risk_level = step.get("risk_level", "MODERATE").upper()
    description = html.escape(step.get("description", ""))
    blast_radius = html.escape(step.get("blast_radius", ""))
    affected = step.get("affected_systems", [])
    reversible = step.get("reversible", False)

    lines = [
        f"<b>Tool:</b> {tool}",
        f"<b>Risk:</b> <b>{risk_level}</b>",
        f"<b>Description:</b> {description}",
        f"<b>Blast Radius:</b> {blast_radius}",
    ]

    if affected:
        lines.append("<b>Affected Systems:</b>")
        for system in affected:
            system_escaped = html.escape(str(system))
            lines.append(f"  • {system_escaped}")

    reversible_text = "Yes" if reversible else "No"
    lines.append(f"<b>Reversible:</b> {reversible_text}")

    return "\n".join(lines)


def format_queue_status(queue_items: list) -> str:
    """Format scan queue as numbered list.

    Args:
        queue_items: List of ScanQueue objects or dicts with target_url, status

    Returns:
        HTML-formatted queue list
    """
    if not queue_items:
        return "<b>Queue Status:</b> Empty"

    lines = ["<b>Queue Status:</b>"]
    for idx, item in enumerate(queue_items, 1):
        if isinstance(item, dict):
            url = item.get("target_url", "Unknown")
            status = item.get("status", "unknown")
        else:
            url = getattr(item, "target_url", "Unknown")
            status = getattr(item, "status", "unknown")

        url_escaped = html.escape(url)
        status_label = status.upper()
        lines.append(f"{idx}. {url_escaped} - <b>{status_label}</b>")

    return "\n".join(lines)


def format_pipeline_stage(stage: str, detail: str) -> str:
    """Format single-line pipeline status update.

    Args:
        stage: Stage name (e.g., "Recon complete", "Vuln scan running")
        detail: Detail text (e.g., "12 subdomains, 3 open ports")

    Returns:
        HTML-formatted status line
    """
    stage_escaped = html.escape(stage)
    detail_escaped = html.escape(detail)
    return f"<b>{stage_escaped}:</b> {detail_escaped}"
