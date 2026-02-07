"""AsyncClick CLI for reconnaissance commands.

Provides user-facing commands:
- add-target: Authorize a target for scanning with scope
- scan: Execute full reconnaissance pipeline
- status: Check scan session results
"""

import asyncclick as click
import json
import structlog
from uuid import uuid4
from sqlalchemy.exc import IntegrityError

logger = structlog.get_logger()


async def init_db():
    """Initialize database engine and session factory. Returns engine for cleanup."""
    from scanner.core.persistence.database import init_database, create_session_factory
    engine = await init_database()
    create_session_factory(engine)
    return engine


@click.group()
@click.pass_context
async def cli(ctx):
    """EvilClawd - AI-Powered Penetration Testing Assistant"""
    ctx.ensure_object(dict)


@cli.command("add-target")
@click.argument("url")
@click.option("--scope", "-s", multiple=True, default=None,
              help="Scope patterns (repeatable). Default: the URL itself.")
@click.option("--authorized-by", default="cli-user", help="Who authorized this target")
@click.pass_context
async def add_target(ctx, url: str, scope: tuple[str, ...], authorized_by: str):
    """Authorize a target URL for scanning.

    Examples:
        evilclawd add-target example.com
        evilclawd add-target example.com -s "*.example.com" -s "example.com"
    """
    engine = await init_db()

    try:
        # If scope is empty/None, default to the URL itself
        scope_list = list(scope) if scope else [url]

        from scanner.core.persistence.database import get_session
        from scanner.core.persistence.models import Target

        async with get_session() as session:
            target = Target(
                url=url,
                scope=json.dumps(scope_list),
                authorized_by=authorized_by
            )
            session.add(target)
            await session.commit()

        click.echo(f"[+] Target authorized: {url}")
        click.echo(f"[+] Scope: {scope_list}")

    except IntegrityError:
        click.echo(f"[!] Target already exists: {url}")
    except Exception as e:
        click.echo(f"[-] Error adding target: {e}")
        ctx.exit(1)
    finally:
        await engine.dispose()


@cli.command()
@click.argument("target")
@click.option("--ports", "-p", default=None, help="Port specification (e.g., '80,443' or '1-1000')")
@click.option("--session-id", default=None, help="Resume existing session by ID")
@click.pass_context
async def scan(ctx, target: str, ports: str | None, session_id: str | None):
    """Run reconnaissance scan on an authorized target.

    Examples:
        evilclawd scan example.com
        evilclawd scan example.com -p 80,443,8080
        evilclawd scan example.com --session-id abc123
    """
    engine = await init_db()

    try:
        # Generate session_id if not provided
        session_id = session_id or str(uuid4())

        click.echo("[*] EvilClawd Reconnaissance Scanner")
        click.echo(f"[*] Target: {target}")
        click.echo(f"[*] Session: {session_id}")

        from scanner.agents import ReconAgent

        agent = ReconAgent(session_id=session_id)

        try:
            results = await agent.run(target, ports=ports)
        except RuntimeError as e:
            click.echo(f"\n[-] Scope check failed: {e}")
            click.echo("[-] Use 'add-target' first to authorize this target")
            ctx.exit(1)
        except Exception as e:
            click.echo(f"\n[-] Scan failed: {e}")
            ctx.exit(1)

        # Print formatted results
        click.echo("\n" + "="*60)
        click.echo("[+] Reconnaissance Complete")
        click.echo("="*60)

        # Subdomains
        subdomains = results.get("subdomains", [])
        click.echo(f"\n[+] Subdomains found: {len(subdomains)}")
        for subdomain in subdomains[:10]:  # Limit display to first 10
            # Subdomains are returned as strings from agent
            subdomain_str = subdomain if isinstance(subdomain, str) else subdomain.get('host', 'unknown')
            click.echo(f"    - {subdomain_str}")
        if len(subdomains) > 10:
            click.echo(f"    ... and {len(subdomains) - 10} more")

        # Open ports and services
        port_scan = results.get("port_scan", [])
        click.echo(f"\n[+] Open ports/services: {len(port_scan)}")
        for service in port_scan[:20]:  # Limit display
            host = service.get("host", "unknown")
            port = service.get("port", "?")
            svc_name = service.get("service", "unknown")
            version = service.get("version", "")
            click.echo(f"    {host}:{port} ({svc_name} {version})".strip())
        if len(port_scan) > 20:
            click.echo(f"    ... and {len(port_scan) - 20} more")

        # Technologies
        technologies = results.get("technologies", [])
        click.echo(f"\n[+] Technologies detected: {len(technologies)}")
        for tech in technologies[:15]:  # Limit display
            name = tech.get("name", "unknown")
            version = tech.get("version", "")
            click.echo(f"    - {name} {version}".strip())
        if len(technologies) > 15:
            click.echo(f"    ... and {len(technologies) - 15} more")

        # Attack surface summary
        attack_surface = results.get("attack_surface", {})
        summary = attack_surface.get("summary", {})
        click.echo("\n[+] Attack Surface Summary:")
        click.echo(f"    Total subdomains: {summary.get('total_subdomains', 0)}")
        click.echo(f"    Total open ports: {summary.get('total_open_ports', 0)}")
        click.echo(f"    Total technologies: {summary.get('total_technologies', 0)}")

        scan_id = results.get("scan_id", "unknown")
        click.echo(f"\n[+] Results saved to database (scan ID: {scan_id})")

    finally:
        await engine.dispose()


@cli.command()
@click.argument("session_id")
@click.pass_context
async def status(ctx, session_id: str):
    """Check status of a scan session.

    Example:
        evilclawd status abc-123-def
    """
    engine = await init_db()

    try:
        from scanner.core.persistence.database import get_session
        from scanner.core.persistence.models import ScanResult
        from sqlalchemy import select

        async with get_session() as session:
            result = await session.execute(
                select(ScanResult).where(ScanResult.session_id == session_id)
            )
            scan_result = result.scalar_one_or_none()

        if not scan_result:
            click.echo(f"[-] No results found for session {session_id}")
            return

        click.echo(f"[+] Scan Status for session: {session_id}")
        click.echo(f"    Status: {scan_result.status}")
        click.echo(f"    Started: {scan_result.started_at}")
        click.echo(f"    Completed: {scan_result.completed_at}")

        if scan_result.findings:
            findings = json.loads(scan_result.findings)
            attack_surface = findings.get("attack_surface", {})
            summary = attack_surface.get("summary", {})

            click.echo("\n[+] Summary:")
            click.echo(f"    Subdomains: {summary.get('total_subdomains', 0)}")
            click.echo(f"    Open ports: {summary.get('total_open_ports', 0)}")
            click.echo(f"    Technologies: {summary.get('total_technologies', 0)}")

    except Exception as e:
        click.echo(f"[-] Error retrieving status: {e}")
        ctx.exit(1)
    finally:
        await engine.dispose()


@cli.command("vuln-scan")
@click.argument("target")
@click.option("--session-id", default=None, help="Use existing session ID")
@click.option("--skip-recon", is_flag=True, help="Skip recon if already done (requires --session-id)")
@click.pass_context
async def vuln_scan(ctx, target: str, session_id: str | None, skip_recon: bool):
    """Run vulnerability scan on an authorized target.

    Detects SQL injection, XSS, command injection, and security header issues.
    Can optionally skip reconnaissance if you have an existing session.

    Examples:
        evilclawd vuln-scan example.com
        evilclawd vuln-scan example.com --session-id abc123 --skip-recon
    """
    engine = await init_db()

    try:
        # Generate session_id if not provided
        session_id = session_id or str(uuid4())

        click.echo("[*] EvilClawd Vulnerability Scanner")
        click.echo(f"[*] Target: {target}")
        click.echo(f"[*] Session: {session_id}")

        recon_results = None

        # Step 1: Get recon data (either run recon or load from database)
        if not skip_recon:
            click.echo("\n[*] Running reconnaissance first...")
            from scanner.agents import ReconAgent
            recon_agent = ReconAgent(session_id=session_id)

            try:
                recon_results = await recon_agent.run(target)
                click.echo("[+] Reconnaissance complete")
            except RuntimeError as e:
                click.echo(f"\n[-] Scope check failed: {e}")
                click.echo("[-] Use 'add-target' first to authorize this target")
                ctx.exit(1)
            except Exception as e:
                click.echo(f"\n[-] Reconnaissance failed: {e}")
                ctx.exit(1)
        else:
            # Load recon data from database
            if not session_id:
                click.echo("[-] --skip-recon requires --session-id")
                ctx.exit(1)

            click.echo("\n[*] Loading reconnaissance data from database...")
            from scanner.core.persistence.database import get_session
            from scanner.core.persistence.models import ScanResult
            from sqlalchemy import select

            async with get_session() as session:
                result = await session.execute(
                    select(ScanResult).where(ScanResult.session_id == session_id)
                )
                scan_result = result.scalar_one_or_none()

            if not scan_result or not scan_result.findings:
                click.echo(f"[-] No recon data found for session {session_id}")
                click.echo("[-] Run without --skip-recon first")
                ctx.exit(1)

            recon_results = json.loads(scan_result.findings)
            click.echo("[+] Loaded recon data from database")

        # Step 2: Run vulnerability scan
        click.echo("\n[*] Scanning for vulnerabilities...")
        from scanner.agents.vuln import VulnAgent

        vuln_agent = VulnAgent(session_id=session_id)

        try:
            findings = await vuln_agent.scan(target, recon_results)
        except RuntimeError as e:
            click.echo(f"\n[-] Scope check failed: {e}")
            ctx.exit(1)
        except Exception as e:
            click.echo(f"\n[-] Vulnerability scan failed: {e}")
            ctx.exit(1)

        # Step 3: Display findings summary
        click.echo("\n" + "="*60)
        click.echo("[+] Vulnerability Scan Complete")
        click.echo("="*60)

        # Group findings by severity
        by_severity = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }

        for finding in findings:
            severity = finding.severity.lower()
            if severity in by_severity:
                by_severity[severity].append(finding)

        # Display counts
        click.echo(f"\n[+] Findings Summary:")
        click.echo(f"    Critical: {len(by_severity['critical'])}")
        click.echo(f"    High: {len(by_severity['high'])}")
        click.echo(f"    Medium: {len(by_severity['medium'])}")
        click.echo(f"    Low: {len(by_severity['low'])}")
        click.echo(f"    Info: {len(by_severity['info'])}")
        click.echo(f"    Total: {len(findings)}")

        # Display top findings (max 5 per severity)
        for severity_name in ["critical", "high", "medium", "low", "info"]:
            severity_findings = by_severity[severity_name]
            if severity_findings:
                click.echo(f"\n[+] {severity_name.upper()} Findings:")
                for finding in severity_findings[:5]:
                    click.echo(f"    - {finding.title} (confidence: {finding.confidence})")
                if len(severity_findings) > 5:
                    click.echo(f"    ... and {len(severity_findings) - 5} more")

        # Step 4: Save findings to database
        from scanner.core.persistence.database import get_session
        from scanner.core.persistence.models import ScanResult
        from sqlalchemy import select

        async with get_session() as session:
            # Update existing scan result or create new one
            result = await session.execute(
                select(ScanResult).where(ScanResult.session_id == session_id)
            )
            scan_result = result.scalar_one_or_none()

            # Convert findings to JSON-serializable format
            findings_json = [f.model_dump(mode='json') for f in findings]

            if scan_result:
                # Merge with existing findings
                existing_findings = json.loads(scan_result.findings) if scan_result.findings else {}
                existing_findings["vulnerabilities"] = findings_json
                scan_result.findings = json.dumps(existing_findings)
            else:
                # This shouldn't happen if recon ran, but handle it
                from scanner.core.persistence.models import Target
                target_result = await session.execute(
                    select(Target).where(Target.url == target)
                )
                target_obj = target_result.scalar_one_or_none()

                if target_obj:
                    scan_result = ScanResult(
                        session_id=session_id,
                        target_id=target_obj.id,
                        status="completed",
                        findings=json.dumps({"vulnerabilities": findings_json})
                    )
                    session.add(scan_result)

            await session.commit()

        click.echo(f"\n[+] Findings saved to database (session: {session_id})")
        click.echo(f"[+] Run 'evilclawd exploit {target} --session-id {session_id}' to exploit findings")
        click.echo(f"[+] Run 'evilclawd report {session_id}' to generate pentest report")

    finally:
        await engine.dispose()


@cli.command()
@click.argument("target")
@click.option("--session-id", required=True, help="Session ID from vuln-scan")
@click.pass_context
async def exploit(ctx, target: str, session_id: str):
    """Execute guided exploitation on discovered vulnerabilities.

    Requires a session ID from a previous vuln-scan. Will prompt for
    approval before executing each exploit step.

    Example:
        evilclawd exploit example.com --session-id abc123
    """
    engine = await init_db()

    try:
        click.echo("[*] EvilClawd Exploitation Assistant")
        click.echo(f"[*] Target: {target}")
        click.echo(f"[*] Session: {session_id}")

        # Step 1: Load findings from database
        click.echo("\n[*] Loading vulnerability findings...")
        from scanner.core.persistence.database import get_session
        from scanner.core.persistence.models import ScanResult
        from sqlalchemy import select

        async with get_session() as session:
            result = await session.execute(
                select(ScanResult).where(ScanResult.session_id == session_id)
            )
            scan_result = result.scalar_one_or_none()

        if not scan_result or not scan_result.findings:
            click.echo(f"[-] No findings found for session {session_id}")
            click.echo(f"[-] Run 'evilclawd vuln-scan {target}' first")
            ctx.exit(1)

        findings_data = json.loads(scan_result.findings)
        vulnerabilities = findings_data.get("vulnerabilities", [])

        if not vulnerabilities:
            click.echo("[-] No vulnerabilities found to exploit")
            return

        # Deserialize Finding objects
        from scanner.core.output import Finding
        findings = [Finding(**vuln_dict) for vuln_dict in vulnerabilities]

        click.echo(f"[+] Loaded {len(findings)} findings")

        # Step 2: Run exploitation
        click.echo("\n[*] Starting guided exploitation...")
        from scanner.agents.exploit import ExploitAgent

        exploit_agent = ExploitAgent(session_id=session_id)

        try:
            exploit_results = await exploit_agent.execute(findings)
        except Exception as e:
            click.echo(f"\n[-] Exploitation failed: {e}")
            ctx.exit(1)

        # Step 3: Display results
        click.echo("\n" + "="*60)
        click.echo("[+] Exploitation Complete")
        click.echo("="*60)

        click.echo(f"\n[+] Exploit Results: {len(exploit_results)} chains executed")

        for i, result in enumerate(exploit_results, 1):
            click.echo(f"\n[{i}] {result.chain.finding.title}")
            click.echo(f"    Steps executed: {result.steps_executed}/{result.steps_total}")
            click.echo(f"    Confidence: {result.confidence}")
            if result.poc:
                click.echo(f"    PoC: Available")
            if result.evidence_validated:
                click.echo(f"    Evidence: Validated")

        click.echo(f"\n[+] Run 'evilclawd report {session_id}' to generate full pentest report")

    finally:
        await engine.dispose()


@cli.command()
@click.argument("session_id")
@click.option("--output", "-o", default=None, help="Output file path")
@click.option("--html", is_flag=True, help="Also generate HTML report")
@click.pass_context
async def report(ctx, session_id: str, output: str | None, html: bool):
    """Generate pentest report for a scan session.

    Produces a professional markdown report with all findings, exploit results,
    and remediation guidance. Optionally exports to HTML.

    Examples:
        evilclawd report abc123
        evilclawd report abc123 -o report.md --html
    """
    engine = await init_db()

    try:
        click.echo("[*] EvilClawd Report Generator")
        click.echo(f"[*] Session: {session_id}")

        # Step 1: Load all scan data from database
        click.echo("\n[*] Loading scan data...")
        from scanner.core.persistence.database import get_session
        from scanner.core.persistence.models import ScanResult, Target
        from sqlalchemy import select

        async with get_session() as session:
            result = await session.execute(
                select(ScanResult).where(ScanResult.session_id == session_id)
            )
            scan_result = result.scalar_one_or_none()

        if not scan_result:
            click.echo(f"[-] No results found for session {session_id}")
            ctx.exit(1)

        if not scan_result.findings:
            click.echo(f"[-] No findings to report for session {session_id}")
            ctx.exit(1)

        # Get target info
        async with get_session() as session:
            result = await session.execute(
                select(Target).where(Target.id == scan_result.target_id)
            )
            target = result.scalar_one_or_none()

        target_url = target.url if target else "Unknown"

        # Parse findings
        findings_data = json.loads(scan_result.findings)
        vulnerabilities = findings_data.get("vulnerabilities", [])

        if not vulnerabilities:
            click.echo("[-] No vulnerabilities to report")
            return

        # Deserialize Finding objects
        from scanner.core.output import Finding
        findings = [Finding(**vuln_dict) for vuln_dict in vulnerabilities]

        click.echo(f"[+] Loaded {len(findings)} findings")

        # Extract recon summary if available
        recon_summary = None
        attack_surface = findings_data.get("attack_surface", {})
        if attack_surface:
            recon_summary = attack_surface.get("summary", {})

        # Step 2: Generate report
        click.echo("\n[*] Generating report...")
        from scanner.core.reporting.generator import ReportGenerator

        generator = ReportGenerator()
        markdown_report = generator.generate(
            target=target_url,
            findings=findings,
            exploit_results=None,  # TODO: Load exploit results from database if available
            recon_summary=recon_summary
        )

        # Step 3: Write to file
        if output is None:
            output = f"report-{session_id}.md"

        with open(output, "w") as f:
            f.write(markdown_report)

        click.echo(f"[+] Report generated: {output}")

        # Step 4: Generate HTML if requested
        if html:
            click.echo("\n[*] Generating HTML report...")
            html_path = generator.export_html(markdown_report, output.replace(".md", ".html"))
            click.echo(f"[+] HTML report generated: {html_path}")

        click.echo("\n[+] Report generation complete")

    finally:
        await engine.dispose()


if __name__ == "__main__":
    cli()
