"""Unit tests for VulnAgent orchestration.

Tests the vulnerability scanning pipeline with mocked tools and database.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from scanner.agents import VulnAgent
from scanner.tools import ToolStatus, ToolResult
from scanner.core.output import SourceType


# Mock reconnaissance results (output from ReconAgent)
MOCK_RECON_RESULTS = {
    "target": "example.com",
    "subdomains": ["example.com", "api.example.com"],
    "port_scan": [
        {"host": "example.com", "port": 443, "protocol": "tcp", "state": "open", "service": "https", "version": ""},
        {"host": "example.com", "port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": ""},
        {"host": "api.example.com", "port": 8080, "protocol": "tcp", "state": "open", "service": "http", "version": ""},
    ],
    "technologies": [{"name": "nginx", "version": "1.21"}],
    "attack_surface": {"services": [], "summary": {}}
}


# Mock tool results
MOCK_HEADERS_MISSING_HSTS = ToolResult(
    status=ToolStatus.SUCCESS,
    data={
        "missing_headers": [
            {
                "header": "Strict-Transport-Security",
                "purpose": "Prevents HTTPS downgrade attacks",
                "severity": "medium"
            }
        ],
        "present_headers": {},
        "cors_issues": [],
        "info_disclosure": [],
        "score": 0,
        "url": "https://example.com"
    },
    raw_output="{'Strict-Transport-Security': 'missing'}"
)

MOCK_HEADERS_CORS_ISSUE = ToolResult(
    status=ToolStatus.SUCCESS,
    data={
        "missing_headers": [],
        "present_headers": {},
        "cors_issues": [
            {
                "issue": "Wildcard CORS origin",
                "header": "Access-Control-Allow-Origin",
                "value": "*",
                "severity": "medium",
                "description": "Allows any origin to access resources"
            }
        ],
        "info_disclosure": [],
        "score": 100,
        "url": "https://example.com"
    },
    raw_output="{'Access-Control-Allow-Origin': '*'}"
)

MOCK_SQLMAP_VULNERABLE = ToolResult(
    status=ToolStatus.SUCCESS,
    data={
        "vulnerable": True,
        "target": "https://example.com",
        "injection_points": [
            {
                "parameter": "id",
                "type": "boolean-based blind",
                "technique": "AND boolean-based blind - WHERE or HAVING clause"
            }
        ],
        "dbms": "MySQL"
    },
    raw_output="Parameter: id (GET) is vulnerable"
)

MOCK_SQLMAP_CLEAN = ToolResult(
    status=ToolStatus.SUCCESS,
    data={
        "vulnerable": False,
        "target": "https://example.com",
        "injection_points": [],
        "dbms": None
    },
    raw_output="No vulnerabilities found"
)

MOCK_XSS_VULNERABLE = ToolResult(
    status=ToolStatus.SUCCESS,
    data={
        "vulnerable": True,
        "target": "https://example.com",
        "xss_vectors": [
            {
                "url": "https://example.com/search",
                "parameter": "q",
                "payload": "<script>alert(1)</script>",
                "type": "reflected"
            }
        ]
    },
    raw_output="XSS FOUND!"
)

MOCK_XSS_CLEAN = ToolResult(
    status=ToolStatus.SUCCESS,
    data={
        "vulnerable": False,
        "target": "https://example.com",
        "xss_vectors": []
    },
    raw_output="No XSS vulnerabilities found"
)

MOCK_COMMIX_VULNERABLE = ToolResult(
    status=ToolStatus.SUCCESS,
    data={
        "vulnerable": True,
        "target": "https://example.com",
        "injection_points": [
            {
                "parameter": "cmd",
                "technique": "classic command injection"
            }
        ],
        "os_detected": "Linux"
    },
    raw_output="Parameter: cmd is vulnerable"
)

MOCK_COMMIX_CLEAN = ToolResult(
    status=ToolStatus.SUCCESS,
    data={
        "vulnerable": False,
        "target": "https://example.com",
        "injection_points": [],
        "os_detected": None
    },
    raw_output="No command injection found"
)

MOCK_TOOL_NOT_INSTALLED = ToolResult(
    status=ToolStatus.NOT_INSTALLED,
    error="sqlmap not installed",
    duration_seconds=0.1
)


@pytest.fixture
def vuln_agent():
    """Create VulnAgent instance with mocked tools."""
    agent = VulnAgent()
    # Mock all tool instances
    agent.sqlmap = AsyncMock()
    agent.xss = AsyncMock()
    agent.commix = AsyncMock()
    agent.headers = AsyncMock()
    return agent


@pytest.mark.asyncio
async def test_vuln_scan_scope_denied(vuln_agent):
    """Test that VulnAgent raises RuntimeError when scope check fails."""
    mock_scope_result = (False, "Target not authorized")

    with patch("scanner.agents.vuln.get_session") as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value.__aenter__.return_value = mock_session

        with patch("scanner.agents.vuln.is_in_scope", return_value=mock_scope_result):
            with patch.object(vuln_agent, "audit", new_callable=AsyncMock):
                with pytest.raises(RuntimeError, match="not in authorized scope"):
                    await vuln_agent.scan("example.com", MOCK_RECON_RESULTS)


@pytest.mark.asyncio
async def test_vuln_scan_headers_finding(vuln_agent):
    """Test that missing HSTS header creates a finding."""
    mock_scope_result = (True, "authorized")

    vuln_agent.headers.run = AsyncMock(return_value=MOCK_HEADERS_MISSING_HSTS)
    vuln_agent.sqlmap.run = AsyncMock(return_value=MOCK_SQLMAP_CLEAN)
    vuln_agent.xss.run = AsyncMock(return_value=MOCK_XSS_CLEAN)
    vuln_agent.commix.run = AsyncMock(return_value=MOCK_COMMIX_CLEAN)

    with patch("scanner.agents.vuln.get_session") as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value.__aenter__.return_value = mock_session

        with patch("scanner.agents.vuln.is_in_scope", return_value=mock_scope_result):
            with patch.object(vuln_agent, "audit", new_callable=AsyncMock):
                with patch.object(vuln_agent, "checkpoint", new_callable=AsyncMock):
                    findings = await vuln_agent.scan("example.com", MOCK_RECON_RESULTS)

    # Should have at least one finding for missing HSTS
    assert len(findings) >= 1

    # Find the HSTS finding
    hsts_finding = next(
        (f for f in findings if "Strict-Transport-Security" in f.title),
        None
    )
    assert hsts_finding is not None
    assert hsts_finding.severity in ["low", "medium", "high"]
    assert len(hsts_finding.evidence) > 0

    # Check evidence source
    evidence = hsts_finding.evidence[0]
    assert evidence.source == SourceType.TOOL_CONFIRMED
    assert evidence.tool_name == "security_headers"
    assert "missing_header" in evidence.data


@pytest.mark.asyncio
async def test_vuln_scan_cors_finding(vuln_agent):
    """Test that CORS misconfiguration creates a finding."""
    mock_scope_result = (True, "authorized")

    vuln_agent.headers.run = AsyncMock(return_value=MOCK_HEADERS_CORS_ISSUE)
    vuln_agent.sqlmap.run = AsyncMock(return_value=MOCK_SQLMAP_CLEAN)
    vuln_agent.xss.run = AsyncMock(return_value=MOCK_XSS_CLEAN)
    vuln_agent.commix.run = AsyncMock(return_value=MOCK_COMMIX_CLEAN)

    with patch("scanner.agents.vuln.get_session") as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value.__aenter__.return_value = mock_session

        with patch("scanner.agents.vuln.is_in_scope", return_value=mock_scope_result):
            with patch.object(vuln_agent, "audit", new_callable=AsyncMock):
                with patch.object(vuln_agent, "checkpoint", new_callable=AsyncMock):
                    findings = await vuln_agent.scan("example.com", MOCK_RECON_RESULTS)

    # Should have CORS finding
    assert len(findings) >= 1
    cors_finding = next(
        (f for f in findings if "CORS" in f.title),
        None
    )
    assert cors_finding is not None
    assert "Wildcard" in cors_finding.title
    assert cors_finding.evidence[0].source == SourceType.TOOL_CONFIRMED


@pytest.mark.asyncio
async def test_vuln_scan_sqli_finding(vuln_agent):
    """Test that SQL injection creates a finding with critical severity."""
    mock_scope_result = (True, "authorized")

    # Mock headers returning clean
    vuln_agent.headers.run = AsyncMock(return_value=ToolResult(
        status=ToolStatus.SUCCESS,
        data={"missing_headers": [], "present_headers": {}, "cors_issues": [], "info_disclosure": [], "score": 100, "url": "https://example.com"}
    ))
    vuln_agent.sqlmap.run = AsyncMock(return_value=MOCK_SQLMAP_VULNERABLE)
    vuln_agent.xss.run = AsyncMock(return_value=MOCK_XSS_CLEAN)
    vuln_agent.commix.run = AsyncMock(return_value=MOCK_COMMIX_CLEAN)

    with patch("scanner.agents.vuln.get_session") as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value.__aenter__.return_value = mock_session

        with patch("scanner.agents.vuln.is_in_scope", return_value=mock_scope_result):
            with patch.object(vuln_agent, "audit", new_callable=AsyncMock):
                with patch.object(vuln_agent, "checkpoint", new_callable=AsyncMock):
                    findings = await vuln_agent.scan("example.com", MOCK_RECON_RESULTS)

    # Should have SQL injection finding
    assert len(findings) >= 1
    sqli_finding = next(
        (f for f in findings if "SQL Injection" in f.title),
        None
    )
    assert sqli_finding is not None
    assert sqli_finding.severity in ["high", "critical"]

    # Check evidence
    evidence = sqli_finding.evidence[0]
    assert evidence.source == SourceType.TOOL_CONFIRMED
    assert evidence.tool_name == "sqlmap"
    assert evidence.data["vulnerable"] is True
    assert "injection_points" in evidence.data
    assert len(evidence.data["injection_points"]) > 0


@pytest.mark.asyncio
async def test_vuln_scan_xss_finding(vuln_agent):
    """Test that XSS creates a finding."""
    mock_scope_result = (True, "authorized")

    vuln_agent.headers.run = AsyncMock(return_value=ToolResult(
        status=ToolStatus.SUCCESS,
        data={"missing_headers": [], "present_headers": {}, "cors_issues": [], "info_disclosure": [], "score": 100, "url": "https://example.com"}
    ))
    vuln_agent.sqlmap.run = AsyncMock(return_value=MOCK_SQLMAP_CLEAN)
    vuln_agent.xss.run = AsyncMock(return_value=MOCK_XSS_VULNERABLE)
    vuln_agent.commix.run = AsyncMock(return_value=MOCK_COMMIX_CLEAN)

    with patch("scanner.agents.vuln.get_session") as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value.__aenter__.return_value = mock_session

        with patch("scanner.agents.vuln.is_in_scope", return_value=mock_scope_result):
            with patch.object(vuln_agent, "audit", new_callable=AsyncMock):
                with patch.object(vuln_agent, "checkpoint", new_callable=AsyncMock):
                    findings = await vuln_agent.scan("example.com", MOCK_RECON_RESULTS)

    # Should have XSS finding
    assert len(findings) >= 1
    xss_finding = next(
        (f for f in findings if "XSS" in f.title),
        None
    )
    assert xss_finding is not None
    assert xss_finding.severity in ["medium", "high"]
    assert xss_finding.evidence[0].tool_name == "xsser"
    assert "xss_vectors" in xss_finding.evidence[0].data


@pytest.mark.asyncio
async def test_vuln_scan_cmdi_finding(vuln_agent):
    """Test that command injection creates a finding."""
    mock_scope_result = (True, "authorized")

    vuln_agent.headers.run = AsyncMock(return_value=ToolResult(
        status=ToolStatus.SUCCESS,
        data={"missing_headers": [], "present_headers": {}, "cors_issues": [], "info_disclosure": [], "score": 100, "url": "https://example.com"}
    ))
    vuln_agent.sqlmap.run = AsyncMock(return_value=MOCK_SQLMAP_CLEAN)
    vuln_agent.xss.run = AsyncMock(return_value=MOCK_XSS_CLEAN)
    vuln_agent.commix.run = AsyncMock(return_value=MOCK_COMMIX_VULNERABLE)

    with patch("scanner.agents.vuln.get_session") as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value.__aenter__.return_value = mock_session

        with patch("scanner.agents.vuln.is_in_scope", return_value=mock_scope_result):
            with patch.object(vuln_agent, "audit", new_callable=AsyncMock):
                with patch.object(vuln_agent, "checkpoint", new_callable=AsyncMock):
                    findings = await vuln_agent.scan("example.com", MOCK_RECON_RESULTS)

    # Should have command injection finding
    assert len(findings) >= 1
    cmdi_finding = next(
        (f for f in findings if "Command Injection" in f.title),
        None
    )
    assert cmdi_finding is not None
    assert cmdi_finding.severity in ["high", "critical"]
    assert cmdi_finding.evidence[0].tool_name == "commix"


@pytest.mark.asyncio
async def test_vuln_scan_no_vulns(vuln_agent):
    """Test that clean scan returns empty findings list."""
    mock_scope_result = (True, "authorized")

    # All tools return clean
    vuln_agent.headers.run = AsyncMock(return_value=ToolResult(
        status=ToolStatus.SUCCESS,
        data={"missing_headers": [], "present_headers": {}, "cors_issues": [], "info_disclosure": [], "score": 100, "url": "https://example.com"}
    ))
    vuln_agent.sqlmap.run = AsyncMock(return_value=MOCK_SQLMAP_CLEAN)
    vuln_agent.xss.run = AsyncMock(return_value=MOCK_XSS_CLEAN)
    vuln_agent.commix.run = AsyncMock(return_value=MOCK_COMMIX_CLEAN)

    with patch("scanner.agents.vuln.get_session") as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value.__aenter__.return_value = mock_session

        with patch("scanner.agents.vuln.is_in_scope", return_value=mock_scope_result):
            with patch.object(vuln_agent, "audit", new_callable=AsyncMock):
                with patch.object(vuln_agent, "checkpoint", new_callable=AsyncMock):
                    findings = await vuln_agent.scan("example.com", MOCK_RECON_RESULTS)

    # Should have no findings
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_vuln_scan_tool_not_installed(vuln_agent):
    """Test graceful degradation when tool is not installed."""
    mock_scope_result = (True, "authorized")

    # SQLMap not installed, others work
    vuln_agent.headers.run = AsyncMock(return_value=ToolResult(
        status=ToolStatus.SUCCESS,
        data={"missing_headers": [], "present_headers": {}, "cors_issues": [], "info_disclosure": [], "score": 100, "url": "https://example.com"}
    ))
    vuln_agent.sqlmap.run = AsyncMock(return_value=MOCK_TOOL_NOT_INSTALLED)
    vuln_agent.xss.run = AsyncMock(return_value=MOCK_XSS_CLEAN)
    vuln_agent.commix.run = AsyncMock(return_value=MOCK_COMMIX_CLEAN)

    with patch("scanner.agents.vuln.get_session") as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value.__aenter__.return_value = mock_session

        with patch("scanner.agents.vuln.is_in_scope", return_value=mock_scope_result):
            with patch.object(vuln_agent, "audit", new_callable=AsyncMock):
                with patch.object(vuln_agent, "checkpoint", new_callable=AsyncMock):
                    # Should not crash
                    findings = await vuln_agent.scan("example.com", MOCK_RECON_RESULTS)

    # Should complete without error (graceful degradation)
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_vuln_scan_audit_logged(vuln_agent):
    """Test that scan start and complete are audit logged."""
    mock_scope_result = (True, "authorized")

    vuln_agent.headers.run = AsyncMock(return_value=ToolResult(
        status=ToolStatus.SUCCESS,
        data={"missing_headers": [], "present_headers": {}, "cors_issues": [], "info_disclosure": [], "score": 100, "url": "https://example.com"}
    ))
    vuln_agent.sqlmap.run = AsyncMock(return_value=MOCK_SQLMAP_CLEAN)
    vuln_agent.xss.run = AsyncMock(return_value=MOCK_XSS_CLEAN)
    vuln_agent.commix.run = AsyncMock(return_value=MOCK_COMMIX_CLEAN)

    mock_audit = AsyncMock()

    with patch("scanner.agents.vuln.get_session") as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value.__aenter__.return_value = mock_session

        with patch("scanner.agents.vuln.is_in_scope", return_value=mock_scope_result):
            with patch.object(vuln_agent, "audit", mock_audit):
                with patch.object(vuln_agent, "checkpoint", new_callable=AsyncMock):
                    await vuln_agent.scan("example.com", MOCK_RECON_RESULTS)

    # Check audit was called for scope_check and vuln_scan_complete
    audit_calls = [call[0][0] for call in mock_audit.call_args_list]
    assert "scope_check" in audit_calls
    assert "vuln_scan_complete" in audit_calls


@pytest.mark.asyncio
async def test_vuln_scan_extracts_web_urls(vuln_agent):
    """Test that _extract_web_urls correctly builds URLs from port_scan services."""
    urls = vuln_agent._extract_web_urls(MOCK_RECON_RESULTS)

    # Should extract 3 URLs from port_scan
    assert len(urls) == 3

    # Check for expected URLs
    assert "https://example.com" in urls
    assert "http://example.com" in urls  # Port 80 uses http
    assert "http://api.example.com:8080" in urls


@pytest.mark.asyncio
async def test_vuln_findings_have_confidence(vuln_agent):
    """Test that all findings have confidence field set."""
    mock_scope_result = (True, "authorized")

    vuln_agent.headers.run = AsyncMock(return_value=MOCK_HEADERS_MISSING_HSTS)
    vuln_agent.sqlmap.run = AsyncMock(return_value=MOCK_SQLMAP_VULNERABLE)
    vuln_agent.xss.run = AsyncMock(return_value=MOCK_XSS_VULNERABLE)
    vuln_agent.commix.run = AsyncMock(return_value=MOCK_COMMIX_CLEAN)

    with patch("scanner.agents.vuln.get_session") as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value.__aenter__.return_value = mock_session

        with patch("scanner.agents.vuln.is_in_scope", return_value=mock_scope_result):
            with patch.object(vuln_agent, "audit", new_callable=AsyncMock):
                with patch.object(vuln_agent, "checkpoint", new_callable=AsyncMock):
                    findings = await vuln_agent.scan("example.com", MOCK_RECON_RESULTS)

    # All findings should have confidence
    assert len(findings) >= 3
    for finding in findings:
        assert finding.confidence in ["confirmed", "likely", "possible"]


@pytest.mark.asyncio
async def test_vuln_findings_have_cvss_severity(vuln_agent):
    """Test that findings use CVSS-based severity labels."""
    mock_scope_result = (True, "authorized")

    vuln_agent.headers.run = AsyncMock(return_value=MOCK_HEADERS_MISSING_HSTS)
    vuln_agent.sqlmap.run = AsyncMock(return_value=MOCK_SQLMAP_VULNERABLE)
    vuln_agent.xss.run = AsyncMock(return_value=MOCK_XSS_CLEAN)
    vuln_agent.commix.run = AsyncMock(return_value=MOCK_COMMIX_CLEAN)

    with patch("scanner.agents.vuln.get_session") as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value.__aenter__.return_value = mock_session

        with patch("scanner.agents.vuln.is_in_scope", return_value=mock_scope_result):
            with patch.object(vuln_agent, "audit", new_callable=AsyncMock):
                with patch.object(vuln_agent, "checkpoint", new_callable=AsyncMock):
                    findings = await vuln_agent.scan("example.com", MOCK_RECON_RESULTS)

    # All findings should have valid CVSS severity labels
    assert len(findings) >= 2
    for finding in findings:
        assert finding.severity in ["info", "low", "medium", "high", "critical"]
