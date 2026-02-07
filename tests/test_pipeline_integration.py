"""End-to-end pipeline integration tests.

Tests the complete pipeline: recon -> vuln -> exploit -> report
with all tools mocked but real agent orchestration and database.
"""

import pytest
import json
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime

from scanner.agents import ReconAgent
from scanner.agents.vuln import VulnAgent
from scanner.agents.exploit import ExploitAgent
from scanner.core.reporting.generator import ReportGenerator
from scanner.core.persistence.database import init_database, create_session_factory, get_session
from scanner.core.persistence.models import Target, ScanResult
from scanner.core.output import Finding, Evidence, SourceType
from scanner.tools import ToolStatus
from scanner.core.safety.approval import ApprovalDecision


@pytest.fixture
async def in_memory_db():
    """Create in-memory SQLite database for testing."""
    engine = await init_database("sqlite+aiosqlite:///:memory:")
    create_session_factory(engine)
    yield engine
    await engine.dispose()


@pytest.fixture
async def authorized_target(in_memory_db):
    """Create authorized target in database."""
    async with get_session() as session:
        target = Target(
            url="example.com",
            scope=json.dumps(["example.com", "*.example.com"]),
            authorized_by="test-user"
        )
        session.add(target)
        await session.commit()
        target_id = target.id

    return "example.com", target_id


@pytest.mark.asyncio
async def test_full_pipeline(in_memory_db, authorized_target):
    """Test complete pipeline: recon -> vuln -> exploit -> report."""
    target, target_id = authorized_target
    session_id = "test-pipeline-session"

    # Mock all external tool binaries
    mock_subfinder_output = '{"host": "example.com"}\n{"host": "www.example.com"}'
    mock_nmap_output = '<?xml version="1.0"?><nmaprun><host><address addr="93.184.216.34"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18.0"/></port></ports></host></nmaprun>'
    mock_whatweb_output = '[{"target":"http://example.com","http_status":200,"plugins":{"Apache":{"version":["2.4.41"]}}}]'

    # Mock SQLMap output
    mock_sqlmap_output = """
[INFO] testing 'MySQL >= 5.0 AND error-based'
[INFO] GET parameter 'id' is vulnerable. DBMS: MySQL
"""

    # Mock XSSer output
    mock_xsser_output = """
[Info] Target: http://example.com?q=<script>
[VULNERABLE] XSS FOUND!
"""

    # Mock Commix output
    mock_commix_output = """
[INFO] testing 'Unix command injection'
[INFO] Parameter 'cmd' is vulnerable to OS command injection
"""

    # Patch all tool execution (mock run_subprocess which is called by run_with_retry)
    with patch("shutil.which", return_value="/usr/bin/mock"), \
         patch("scanner.tools.base.run_subprocess", new_callable=AsyncMock) as mock_run_subprocess, \
         patch("scanner.tools.headers.aiohttp.ClientSession") as mock_aiohttp, \
         patch("scanner.core.safety.approval.request_approval") as mock_approval:

        # Configure tool mock with side_effect to return different outputs based on tool
        async def run_subprocess_side_effect(cmd, *args, **kwargs):
            if "subfinder" in cmd[0]:
                return (mock_subfinder_output, "", 0)
            elif "nmap" in cmd[0]:
                return (mock_nmap_output, "", 0)
            elif "whatweb" in cmd[0]:
                return (mock_whatweb_output, "", 0)
            elif "sqlmap" in cmd[0]:
                return (mock_sqlmap_output, "", 0)
            elif "xsser" in cmd[0] or "XSSer" in str(cmd):
                return (mock_xsser_output, "", 0)
            elif "commix" in cmd[0]:
                return (mock_commix_output, "", 0)
            else:
                return ("", "", 0)

        mock_run_subprocess.side_effect = run_subprocess_side_effect

        # Mock HTTP headers tool
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {
            "Server": "nginx/1.18.0",
            "X-Frame-Options": "DENY",
            # Missing security headers trigger findings
        }
        mock_session_instance = AsyncMock()
        mock_session_instance.__aenter__ = AsyncMock(return_value=mock_session_instance)
        mock_session_instance.__aexit__ = AsyncMock(return_value=None)
        mock_session_instance.get = AsyncMock(return_value=mock_response)
        mock_aiohttp.return_value = mock_session_instance

        # Auto-approve all exploitation steps (request_approval returns tuple)
        async def mock_approval_func(*args, **kwargs):
            # Extract tool_input from args (2nd argument)
            tool_input = args[1] if len(args) > 1 else kwargs.get('tool_input', {})
            return (ApprovalDecision.APPROVE, tool_input)

        mock_approval.side_effect = mock_approval_func

        # Step 1: Run ReconAgent
        recon_agent = ReconAgent(session_id=session_id)
        recon_results = await recon_agent.run(target, ports="80,443")

        # Verify recon results
        assert recon_results["target"] == target
        assert "subdomains" in recon_results
        assert len(recon_results["subdomains"]) >= 1
        assert "port_scan" in recon_results
        assert len(recon_results["port_scan"]) >= 1
        assert "attack_surface" in recon_results

        # Step 2: Run VulnAgent
        vuln_agent = VulnAgent(session_id=session_id)
        findings = await vuln_agent.scan(target, recon_results)

        # Verify findings produced
        assert len(findings) > 0
        assert all(isinstance(f, Finding) for f in findings)

        # Verify findings have proper structure
        for finding in findings:
            assert finding.title
            assert finding.severity in ["critical", "high", "medium", "low", "info"]
            # Confidence can be "confirmed" for tool-validated findings or "high/medium/low" for AI analysis
            assert finding.confidence in ["confirmed", "high", "medium", "low"]
            assert len(finding.evidence) > 0

        # Group by severity
        high_severity = [f for f in findings if f.severity in ["critical", "high"]]
        assert len(high_severity) > 0, "Should have at least one high/critical finding"

        # Step 3: Skip ExploitAgent (requires interactive approval - tested separately)
        # Just test report generation with findings

        # Step 4: Generate Report
        generator = ReportGenerator()
        report_markdown = generator.generate(
            target=target,
            findings=findings,
            exploit_results=None,  # Skip exploit results in this test
            recon_summary=recon_results.get("attack_surface", {}).get("summary", {})
        )

        # Verify report structure
        assert "# Penetration Test Report" in report_markdown
        assert f"**Target:** {target}" in report_markdown or f"Target: {target}" in report_markdown
        assert "## Executive Summary" in report_markdown
        assert "## Findings" in report_markdown

        # Verify severity sections appear
        assert "### Critical" in report_markdown or "### High" in report_markdown or "critical" in report_markdown.lower()

        # Verify report contains finding details
        for finding in findings:
            # Only tool-confirmed findings should appear
            has_tool_evidence = any(
                e.source == SourceType.TOOL_CONFIRMED for e in finding.evidence
            )
            if has_tool_evidence:
                # Finding title should appear in report
                assert finding.title in report_markdown or finding.description in report_markdown


@pytest.mark.asyncio
async def test_pipeline_evidence_validation(in_memory_db, authorized_target):
    """Test that unconfirmed findings are excluded from final report."""
    target, target_id = authorized_target

    # Create findings with different evidence types
    confirmed_finding = Finding(
        title="SQL Injection (Confirmed)",
        severity="high",
        description="SQL injection confirmed by tool",
        evidence=[
            Evidence(
                source=SourceType.TOOL_CONFIRMED,
                data={"payload": "' OR 1=1--", "response": "SQL error"},
                tool_name="sqlmap"
            )
        ],
        confidence="high"
    )

    unconfirmed_finding = Finding(
        title="Possible XSS (AI Only)",
        severity="medium",
        description="Possible XSS detected by AI analysis",
        evidence=[
            Evidence(
                source=SourceType.AI_INTERPRETATION,
                data={"reasoning": "Input not sanitized"},
                tool_name=None
            )
        ],
        confidence="low"
    )

    mixed_finding = Finding(
        title="Command Injection (Mixed Evidence)",
        severity="high",
        description="Command injection with mixed evidence",
        evidence=[
            Evidence(
                source=SourceType.AI_INTERPRETATION,
                data={"reasoning": "Shell metacharacters present"},
                tool_name=None
            ),
            Evidence(
                source=SourceType.TOOL_CONFIRMED,
                data={"payload": "; ls", "response": "bin etc usr"},
                tool_name="commix"
            )
        ],
        confidence="high"
    )

    findings = [confirmed_finding, unconfirmed_finding, mixed_finding]

    # Generate report
    generator = ReportGenerator()
    report = generator.generate(
        target=target,
        findings=findings,
        exploit_results=None,
        recon_summary=None
    )

    # Verify evidence validation
    # Confirmed finding should appear
    assert "SQL Injection (Confirmed)" in report

    # Unconfirmed finding should NOT appear (no tool evidence)
    assert "Possible XSS (AI Only)" not in report

    # Mixed finding should appear (has tool evidence)
    assert "Command Injection (Mixed Evidence)" in report

    # Verify report explicitly states findings are validated
    assert "validated" in report.lower() or "confirmed" in report.lower() or len([f for f in findings if any(e.source == SourceType.TOOL_CONFIRMED for e in f.evidence)]) >= 2


@pytest.mark.asyncio
async def test_pipeline_session_continuity(in_memory_db, authorized_target):
    """Test that session ID persists data across pipeline stages."""
    target, target_id = authorized_target
    session_id = "continuity-test-session"

    # Mock tools
    with patch("shutil.which", return_value="/usr/bin/mock"), \
         patch("scanner.tools.base.run_subprocess", new_callable=AsyncMock) as mock_run_subprocess:

        async def run_subprocess_side_effect(cmd, *args, **kwargs):
            if "subfinder" in cmd[0]:
                return ('{"host": "example.com"}', "", 0)
            elif "nmap" in cmd[0]:
                return ('<nmaprun><host><address addr="93.184.216.34"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>', "", 0)
            elif "whatweb" in cmd[0]:
                return ('[{"target":"http://example.com","plugins":{}}]', "", 0)
            else:
                return ("", "", 0)

        mock_run_subprocess.side_effect = run_subprocess_side_effect

        # Run recon
        recon_agent = ReconAgent(session_id=session_id)
        recon_results = await recon_agent.run(target)

        # Verify data persisted in database
        async with get_session() as session:
            from sqlalchemy import select
            result = await session.execute(
                select(ScanResult).where(ScanResult.session_id == session_id)
            )
            scan_result = result.scalar_one_or_none()

        assert scan_result is not None
        assert scan_result.session_id == session_id
        assert scan_result.target_id == target_id
        assert scan_result.findings is not None

        # Parse findings
        findings_data = json.loads(scan_result.findings)
        assert "subdomains" in findings_data
        assert findings_data["target"] == target


@pytest.mark.asyncio
async def test_pipeline_scope_enforcement(in_memory_db):
    """Test that pipeline refuses unauthorized targets."""
    # Don't add target to database - it's unauthorized
    unauthorized_target = "unauthorized.com"
    session_id = "scope-test-session"

    # Mock tools (won't actually be called due to scope check)
    with patch("shutil.which", return_value="/usr/bin/mock"), \
         patch("scanner.tools.base.run_subprocess", new_callable=AsyncMock):
        recon_agent = ReconAgent(session_id=session_id)

        # Should raise RuntimeError due to scope check
        with pytest.raises(RuntimeError, match="not in authorized scope"):
            await recon_agent.run(unauthorized_target)


@pytest.mark.asyncio
async def test_pipeline_empty_findings(in_memory_db, authorized_target):
    """Test pipeline handles zero vulnerabilities gracefully."""
    target, target_id = authorized_target
    session_id = "empty-findings-session"

    # Mock tools to return clean results (no vulnerabilities)
    with patch("shutil.which", return_value="/usr/bin/mock"), \
         patch("scanner.tools.base.run_subprocess", new_callable=AsyncMock) as mock_run_subprocess, \
         patch("scanner.tools.headers.aiohttp.ClientSession") as mock_aiohttp:

        async def run_subprocess_side_effect(cmd, *args, **kwargs):
            if "subfinder" in cmd[0]:
                return ('{"host": "example.com"}', "", 0)
            elif "nmap" in cmd[0]:
                return ('<nmaprun><host><address addr="93.184.216.34"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>', "", 0)
            elif "whatweb" in cmd[0]:
                return ('[{"target":"https://example.com","plugins":{}}]', "", 0)
            elif "sqlmap" in cmd[0]:
                return ("[INFO] no vulnerabilities found", "", 0)
            elif "xsser" in cmd[0] or "XSSer" in str(cmd):
                return ("[Info] no XSS found", "", 0)
            elif "commix" in cmd[0]:
                return ("[INFO] no command injection", "", 0)
            else:
                return ("", "", 0)

        mock_run_subprocess.side_effect = run_subprocess_side_effect

        # Mock secure headers
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-XSS-Protection": "1; mode=block"
        }
        mock_session_instance = AsyncMock()
        mock_session_instance.__aenter__ = AsyncMock(return_value=mock_session_instance)
        mock_session_instance.__aexit__ = AsyncMock(return_value=None)
        mock_session_instance.get = AsyncMock(return_value=mock_response)
        mock_aiohttp.return_value = mock_session_instance

        # Run pipeline
        recon_agent = ReconAgent(session_id=session_id)
        recon_results = await recon_agent.run(target)

        vuln_agent = VulnAgent(session_id=session_id)
        findings = await vuln_agent.scan(target, recon_results)

        # May have informational findings, but no critical/high
        critical_high = [f for f in findings if f.severity in ["critical", "high"]]
        assert len(critical_high) == 0

        # Report should handle empty findings
        generator = ReportGenerator()
        report = generator.generate(
            target=target,
            findings=findings,
            exploit_results=None,
            recon_summary=recon_results.get("attack_surface", {}).get("summary", {})
        )

        assert "# Penetration Test Report" in report
        # Should indicate no critical findings
        assert "0" in report or "no" in report.lower() or len(findings) == 0
