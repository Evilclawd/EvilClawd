"""Tests for SecurityHeadersTool and severity module.

Tests cover:
- SecurityHeadersTool with mocked aiohttp responses
- CVSS severity calculation
- Confidence classification from evidence
- Default CVSS characteristics for common vulnerabilities
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from scanner.core.output import Evidence, Finding, SourceType
from scanner.core.severity import (
    Confidence,
    calculate_severity,
    classify_confidence,
    severity_to_cvss_defaults,
)
from scanner.tools.base import ToolStatus
from scanner.tools.headers import SecurityHeadersTool


# SecurityHeadersTool Tests


@pytest.mark.asyncio
async def test_headers_all_present():
    """Test when all security headers are present."""
    tool = SecurityHeadersTool()

    # Mock aiohttp response with all security headers
    mock_response = MagicMock()
    mock_response.headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'self'",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    mock_response.__aenter__ = AsyncMock(return_value=mock_response)
    mock_response.__aexit__ = AsyncMock(return_value=None)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_response)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        result = await tool.run("https://example.com")

    assert result.status == ToolStatus.SUCCESS
    assert result.data["score"] == 100
    assert len(result.data["missing_headers"]) == 0
    assert len(result.data["present_headers"]) == 7


@pytest.mark.asyncio
async def test_headers_all_missing():
    """Test when no security headers are present."""
    tool = SecurityHeadersTool()

    # Mock aiohttp response with no security headers
    mock_response = MagicMock()
    mock_response.headers = {
        "Content-Type": "text/html",
        "Content-Length": "1234",
    }
    mock_response.__aenter__ = AsyncMock(return_value=mock_response)
    mock_response.__aexit__ = AsyncMock(return_value=None)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_response)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        result = await tool.run("https://example.com")

    assert result.status == ToolStatus.SUCCESS
    assert result.data["score"] == 0
    assert len(result.data["missing_headers"]) == 7

    # Verify severity levels are assigned
    missing = {h["header"]: h["severity"] for h in result.data["missing_headers"]}
    assert missing["Strict-Transport-Security"] == "medium"
    assert missing["X-Frame-Options"] == "low"
    assert missing["Content-Security-Policy"] == "medium"


@pytest.mark.asyncio
async def test_headers_partial():
    """Test when some headers are present and some are missing."""
    tool = SecurityHeadersTool()

    # Mock aiohttp response with partial headers
    mock_response = MagicMock()
    mock_response.headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "X-Frame-Options": "SAMEORIGIN",
        "Content-Type": "text/html",
    }
    mock_response.__aenter__ = AsyncMock(return_value=mock_response)
    mock_response.__aexit__ = AsyncMock(return_value=None)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_response)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        result = await tool.run("https://example.com")

    assert result.status == ToolStatus.SUCCESS
    assert result.data["score"] == 28  # 2 out of 7 = ~28%
    assert len(result.data["missing_headers"]) == 5
    assert len(result.data["present_headers"]) == 2
    assert "Strict-Transport-Security" in result.data["present_headers"]
    assert "X-Frame-Options" in result.data["present_headers"]


@pytest.mark.asyncio
async def test_headers_cors_wildcard():
    """Test detection of wildcard CORS origin."""
    tool = SecurityHeadersTool()

    # Mock aiohttp response with wildcard CORS
    mock_response = MagicMock()
    mock_response.headers = {
        "Access-Control-Allow-Origin": "*",
        "Content-Type": "application/json",
    }
    mock_response.__aenter__ = AsyncMock(return_value=mock_response)
    mock_response.__aexit__ = AsyncMock(return_value=None)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_response)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        result = await tool.run("https://example.com")

    assert result.status == ToolStatus.SUCCESS
    assert len(result.data["cors_issues"]) == 1
    assert result.data["cors_issues"][0]["severity"] == "medium"
    assert result.data["cors_issues"][0]["issue"] == "Wildcard CORS origin"


@pytest.mark.asyncio
async def test_headers_cors_credentials_wildcard():
    """Test detection of dangerous CORS credentials + wildcard combination."""
    tool = SecurityHeadersTool()

    # Mock aiohttp response with credentials + wildcard CORS
    mock_response = MagicMock()
    mock_response.headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
        "Content-Type": "application/json",
    }
    mock_response.__aenter__ = AsyncMock(return_value=mock_response)
    mock_response.__aexit__ = AsyncMock(return_value=None)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_response)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        result = await tool.run("https://example.com")

    assert result.status == ToolStatus.SUCCESS
    # Should have both wildcard issue AND dangerous combination issue
    assert len(result.data["cors_issues"]) >= 1
    # Check for high severity issue
    high_severity_issues = [
        issue for issue in result.data["cors_issues"]
        if issue["severity"] == "high"
    ]
    assert len(high_severity_issues) == 1
    assert "Credentials" in high_severity_issues[0]["description"]


@pytest.mark.asyncio
async def test_headers_info_disclosure():
    """Test detection of information disclosure headers."""
    tool = SecurityHeadersTool()

    # Mock aiohttp response with info disclosure headers
    mock_response = MagicMock()
    mock_response.headers = {
        "Server": "Apache/2.4.49 (Unix)",
        "X-Powered-By": "PHP/7.4.3",
        "Content-Type": "text/html",
    }
    mock_response.__aenter__ = AsyncMock(return_value=mock_response)
    mock_response.__aexit__ = AsyncMock(return_value=None)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_response)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        result = await tool.run("https://example.com")

    assert result.status == ToolStatus.SUCCESS
    assert len(result.data["info_disclosure"]) == 2

    # Check Server header disclosure
    server_disclosure = next(
        (d for d in result.data["info_disclosure"] if d["header"] == "Server"),
        None,
    )
    assert server_disclosure is not None
    assert server_disclosure["severity"] == "info"
    assert "Apache/2.4.49" in server_disclosure["value"]

    # Check X-Powered-By disclosure
    xpb_disclosure = next(
        (d for d in result.data["info_disclosure"] if d["header"] == "X-Powered-By"),
        None,
    )
    assert xpb_disclosure is not None
    assert "PHP/7.4.3" in xpb_disclosure["value"]


@pytest.mark.asyncio
async def test_headers_connection_error():
    """Test handling of connection errors."""
    tool = SecurityHeadersTool()

    # Mock aiohttp raising ClientError
    mock_session = MagicMock()
    mock_session.get = MagicMock(side_effect=Exception("Connection refused"))
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        result = await tool.run("https://example.com")

    assert result.status == ToolStatus.ERROR
    assert "error" in result.data
    assert "Connection refused" in result.data["error"]


@pytest.mark.asyncio
async def test_headers_is_always_available():
    """Test that SecurityHeadersTool is always available (pure Python)."""
    tool = SecurityHeadersTool()
    assert await tool.is_available() is True


# Severity Module Tests


def test_calculate_severity_critical():
    """Test CVSS calculation for critical severity (SQL injection)."""
    characteristics = {
        "attack_vector": "N",
        "attack_complexity": "L",
        "privileges_required": "N",
        "user_interaction": "N",
        "scope": "C",
        "confidentiality": "H",
        "integrity": "H",
        "availability": "H",
    }

    score, label = calculate_severity(characteristics)

    assert score >= 9.0
    assert label == "critical"


def test_calculate_severity_medium():
    """Test CVSS calculation for medium severity (reflected XSS)."""
    characteristics = {
        "attack_vector": "N",
        "attack_complexity": "L",
        "privileges_required": "N",
        "user_interaction": "R",
        "scope": "C",
        "confidentiality": "L",
        "integrity": "L",
        "availability": "N",
    }

    score, label = calculate_severity(characteristics)

    assert 4.0 <= score < 7.0
    assert label == "medium"


def test_calculate_severity_info():
    """Test CVSS calculation for info severity (zero impact)."""
    characteristics = {
        "attack_vector": "N",
        "attack_complexity": "L",
        "privileges_required": "N",
        "user_interaction": "N",
        "scope": "U",
        "confidentiality": "N",
        "integrity": "N",
        "availability": "N",
    }

    score, label = calculate_severity(characteristics)

    assert score == 0.0
    assert label == "info"


def test_calculate_severity_invalid_input():
    """Test CVSS calculation with malformed input."""
    characteristics = {}

    score, label = calculate_severity(characteristics)

    # Should return default info level on error
    assert score == 0.0
    assert label == "info"


def test_classify_confidence_confirmed():
    """Test confidence classification for tool-confirmed finding."""
    finding = Finding(
        title="SQL Injection",
        severity="critical",
        description="Found SQLi vulnerability",
        evidence=[
            Evidence(
                source=SourceType.TOOL_CONFIRMED,
                data={"payload": "' OR 1=1--", "vulnerable": True, "dbms": "MySQL"},
                tool_name="sqlmap",
            )
        ],
        confidence="high",
    )

    confidence = classify_confidence(finding)

    assert confidence == Confidence.CONFIRMED


def test_classify_confidence_likely():
    """Test confidence classification for ambiguous tool evidence."""
    finding = Finding(
        title="Potential XSS",
        severity="medium",
        description="XSS may be present",
        evidence=[
            Evidence(
                source=SourceType.TOOL_CONFIRMED,
                data={},  # Empty data = ambiguous
                tool_name="xsser",
            )
        ],
        confidence="medium",
    )

    confidence = classify_confidence(finding)

    assert confidence == Confidence.LIKELY


def test_classify_confidence_possible():
    """Test confidence classification for AI interpretation."""
    finding = Finding(
        title="Possible SQLi",
        severity="high",
        description="Input may be vulnerable",
        evidence=[
            Evidence(
                source=SourceType.AI_INTERPRETATION,
                data={"reasoning": "Unvalidated input parameter"},
            )
        ],
        confidence="low",
    )

    confidence = classify_confidence(finding)

    assert confidence == Confidence.POSSIBLE


def test_classify_confidence_no_evidence():
    """Test confidence classification with no evidence."""
    finding = Finding(
        title="Unknown Issue",
        severity="low",
        description="No evidence available",
        evidence=[],
        confidence="low",
    )

    confidence = classify_confidence(finding)

    assert confidence == Confidence.POSSIBLE


def test_severity_to_cvss_defaults_sqli():
    """Test default CVSS characteristics for SQL injection."""
    defaults = severity_to_cvss_defaults("sqli")

    assert defaults["attack_vector"] == "N"
    assert defaults["confidentiality"] == "H"
    assert defaults["integrity"] == "H"
    assert defaults["availability"] == "H"

    # Verify it produces critical severity
    score, label = calculate_severity(defaults)
    assert label in ("high", "critical")


def test_severity_to_cvss_defaults_xss():
    """Test default CVSS characteristics for reflected XSS."""
    defaults = severity_to_cvss_defaults("xss_reflected")

    assert defaults["user_interaction"] == "R"
    assert defaults["confidentiality"] == "L"
    assert defaults["integrity"] == "L"

    # Verify it produces medium severity
    score, label = calculate_severity(defaults)
    assert label == "medium"


def test_severity_to_cvss_defaults_command_injection():
    """Test default CVSS characteristics for command injection."""
    defaults = severity_to_cvss_defaults("command_injection")

    assert defaults["attack_vector"] == "N"
    assert defaults["confidentiality"] == "H"
    assert defaults["integrity"] == "H"

    # Verify it produces critical severity
    score, label = calculate_severity(defaults)
    assert label in ("high", "critical")


def test_severity_to_cvss_defaults_unknown():
    """Test default CVSS characteristics for unknown vulnerability type."""
    defaults = severity_to_cvss_defaults("unknown_vuln_type")

    # Should return generic low severity defaults
    assert "attack_vector" in defaults
    assert "confidentiality" in defaults

    # Verify it produces low severity
    score, label = calculate_severity(defaults)
    assert label in ("info", "low", "medium")
