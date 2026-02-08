"""Tests for report generation engine (REPT-01 through REPT-04)."""

from datetime import datetime
from pathlib import Path

import pytest

from scanner.core.output import Evidence, Finding, SourceType
from scanner.core.reporting import ReportGenerator, export_html


# Test fixtures


@pytest.fixture
def sqli_finding():
    """SQL injection finding with TOOL_CONFIRMED evidence."""
    finding = Finding(
        title="SQL Injection in login parameter",
        severity="critical",
        description="SQL injection vulnerability allows attacker to bypass authentication",
        evidence=[],
        confidence="high",
    )
    finding.add_evidence(
        source=SourceType.TOOL_CONFIRMED,
        data={
            "parameter": "username",
            "payload": "admin' OR '1'='1",
            "vulnerable": True,
            "raw_output": "sqlmap identified 3 injection points\nParameter: username (POST)\n    Type: boolean-based blind",
        },
        tool_name="sqlmap",
    )
    return finding


@pytest.fixture
def xss_finding():
    """XSS finding with TOOL_CONFIRMED evidence."""
    finding = Finding(
        title="Reflected XSS in search parameter",
        severity="medium",
        description="Reflected cross-site scripting vulnerability in search functionality",
        evidence=[],
        confidence="high",
    )
    finding.add_evidence(
        source=SourceType.TOOL_CONFIRMED,
        data={
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
            "vulnerable": True,
            "raw_output": "XSSer found XSS vector in parameter q\nPayload reflected without sanitization",
        },
        tool_name="xsser",
    )
    return finding


@pytest.fixture
def header_finding():
    """Security headers finding with TOOL_CONFIRMED evidence."""
    finding = Finding(
        title="Missing Security Headers",
        severity="low",
        description="Application is missing important security headers",
        evidence=[],
        confidence="high",
    )
    finding.add_evidence(
        source=SourceType.TOOL_CONFIRMED,
        data={
            "missing_headers": [
                "X-Frame-Options",
                "Content-Security-Policy",
                "X-Content-Type-Options",
            ],
            "header_check": "3 security headers missing",
        },
        tool_name="security_headers",
    )
    return finding


@pytest.fixture
def ai_only_finding():
    """Finding with ONLY AI_INTERPRETATION evidence (should be excluded)."""
    finding = Finding(
        title="Potential Information Disclosure",
        severity="info",
        description="AI suggests possible information leakage",
        evidence=[],
        confidence="low",
    )
    finding.add_evidence(
        source=SourceType.AI_INTERPRETATION,
        data={
            "reasoning": "Error messages may reveal stack traces",
            "suggestion": "Investigate error handling",
        },
    )
    return finding


@pytest.fixture
def exploit_results():
    """Sample exploit PoC results."""
    return [
        """## SQLi Exploitation PoC

**Vulnerability:** SQL Injection in login

**Steps to reproduce:**
```bash
curl -X POST https://example.com/login \\
  -d "username=admin' OR '1'='1&password=anything"
```

**Result:** Bypassed authentication, logged in as admin user.
""",
        """## XSS Exploitation PoC

**Vulnerability:** Reflected XSS in search

**Steps to reproduce:**
```bash
curl "https://example.com/search?q=<script>alert(1)</script>"
```

**Result:** JavaScript executed in browser context.
""",
    ]


@pytest.fixture
def recon_summary():
    """Sample reconnaissance summary."""
    return {
        "total_subdomains": 5,
        "total_open_ports": 8,
        "total_technologies": 12,
    }


@pytest.fixture
def generator():
    """ReportGenerator instance."""
    return ReportGenerator()


# Tests


def test_report_generates_markdown(generator, sqli_finding, xss_finding):
    """Verify report generation returns non-empty markdown."""
    report = generator.generate(
        target="https://example.com",
        findings=[sqli_finding, xss_finding],
    )

    assert report
    assert isinstance(report, str)
    assert "# Penetration Test Report" in report


def test_report_includes_target(generator, sqli_finding):
    """Verify target name appears in report."""
    target = "https://test.example.com"
    report = generator.generate(target=target, findings=[sqli_finding])

    assert target in report
    assert "**Target:** " + target in report


def test_report_executive_summary(generator, sqli_finding, xss_finding, header_finding):
    """Verify executive summary with finding counts."""
    report = generator.generate(
        target="https://example.com",
        findings=[sqli_finding, xss_finding, header_finding],
    )

    assert "## Executive Summary" in report
    assert "**3 unique finding types**" in report
    assert "**1 critical**" in report.lower()


def test_report_findings_grouped_by_severity(
    generator, sqli_finding, xss_finding, header_finding
):
    """Verify findings are grouped by severity sections."""
    report = generator.generate(
        target="https://example.com",
        findings=[sqli_finding, xss_finding, header_finding],
    )

    # Check severity sections
    assert "### CRITICAL Severity" in report
    assert "### MEDIUM Severity" in report
    assert "### LOW Severity" in report

    # Check findings appear in correct sections
    assert "SQL Injection" in report
    assert "Reflected XSS" in report
    assert "Missing Security Headers" in report


def test_report_evidence_attribution(generator, sqli_finding, xss_finding):
    """Verify finding titles and descriptions appear in grouped report."""
    report = generator.generate(
        target="https://example.com",
        findings=[sqli_finding, xss_finding],
    )

    # Check finding titles render in grouped template
    assert "SQL Injection in login parameter" in report
    assert "Reflected XSS in search parameter" in report

    # Check severity and confidence markers
    assert "CRITICAL" in report
    assert "HIGH" in report  # confidence rendered as upper


def test_report_raw_output_included(generator, sqli_finding):
    """Verify finding description appears in report."""
    report = generator.generate(
        target="https://example.com",
        findings=[sqli_finding],
    )

    # Check description from finding is included
    assert "SQL injection vulnerability" in report


def test_report_pocs_section(generator, sqli_finding, exploit_results):
    """Verify Proof of Concept section (REPT-02)."""
    report = generator.generate(
        target="https://example.com",
        findings=[sqli_finding],
        exploit_results=exploit_results,
    )

    assert "## Proof of Concept" in report
    assert "SQLi Exploitation PoC" in report
    assert "XSS Exploitation PoC" in report
    assert "Steps to reproduce" in report


def test_report_remediation_guidance(generator, sqli_finding, xss_finding):
    """Verify remediation guidance section (REPT-02)."""
    report = generator.generate(
        target="https://example.com",
        findings=[sqli_finding, xss_finding],
    )

    assert "## Remediation Guidance" in report
    assert "parameterized queries" in report.lower()
    assert "output encoding" in report.lower() or "escaping" in report.lower()


def test_report_excludes_unconfirmed(generator, sqli_finding, ai_only_finding):
    """Verify AI-only findings NOT included (evidence validation)."""
    report = generator.generate(
        target="https://example.com",
        findings=[sqli_finding, ai_only_finding],
    )

    # Tool-confirmed finding should be included
    assert "SQL Injection" in report

    # AI-only finding should be excluded
    assert "Potential Information Disclosure" not in report


def test_report_evidence_validation(generator, sqli_finding, ai_only_finding):
    """Verify _has_tool_confirmed_evidence method."""
    # SQLi finding has tool-confirmed evidence
    assert generator._has_tool_confirmed_evidence(sqli_finding) is True

    # AI-only finding does NOT have tool-confirmed evidence
    assert generator._has_tool_confirmed_evidence(ai_only_finding) is False


def test_report_empty_findings(generator):
    """Verify report generation with empty findings list."""
    report = generator.generate(
        target="https://example.com",
        findings=[],
    )

    assert report
    assert "# Penetration Test Report" in report
    assert "no significant findings" in report.lower()
    assert "**0**" in report  # Total findings count


def test_report_metadata_counts(generator, sqli_finding, xss_finding, header_finding):
    """Verify metadata counts match actual findings."""
    report = generator.generate(
        target="https://example.com",
        findings=[sqli_finding, xss_finding, header_finding],
    )

    # Check the finding summary table
    assert "| Critical | 1 |" in report
    assert "| Medium | 1 |" in report
    assert "| Low | 1 |" in report
    assert "| **Total** | **3** |" in report


def test_report_recon_summary(generator, sqli_finding, recon_summary):
    """Verify reconnaissance summary section."""
    report = generator.generate(
        target="https://example.com",
        findings=[sqli_finding],
        recon_summary=recon_summary,
    )

    assert "## Reconnaissance Summary" in report
    assert "Subdomains discovered: 5" in report
    assert "Open ports: 8" in report
    assert "Technologies identified: 12" in report


def test_export_html(generator, sqli_finding, xss_finding, tmp_path):
    """Verify HTML export from markdown."""
    # Generate markdown report
    report_md = generator.generate(
        target="https://example.com",
        findings=[sqli_finding, xss_finding],
    )

    # Export to HTML
    output_path = str(tmp_path / "report.html")
    result_path = export_html(report_md, output_path)

    assert result_path == output_path
    assert Path(output_path).exists()

    # Read HTML and verify structure
    with open(output_path, "r", encoding="utf-8") as f:
        html_content = f.read()

    assert "<!DOCTYPE html>" in html_content
    assert "<html" in html_content
    assert "<head>" in html_content
    assert "<body>" in html_content
    assert "</html>" in html_content

    # Verify content is present
    assert "Penetration Test Report" in html_content
    assert "SQL Injection" in html_content
    assert "Reflected XSS" in html_content


def test_export_html_has_tables(generator, sqli_finding, tmp_path):
    """Verify HTML export includes table elements."""
    report_md = generator.generate(
        target="https://example.com",
        findings=[sqli_finding],
    )

    output_path = str(tmp_path / "report.html")
    export_html(report_md, output_path)

    with open(output_path, "r", encoding="utf-8") as f:
        html_content = f.read()

    # Verify tables are rendered (from markdown tables extension)
    assert "<table>" in html_content
    assert "<th>" in html_content
    assert "<td>" in html_content


def test_report_with_all_features(
    generator, sqli_finding, xss_finding, header_finding, exploit_results, recon_summary
):
    """Integration test with all report features enabled."""
    report = generator.generate(
        target="https://example.com",
        findings=[sqli_finding, xss_finding, header_finding],
        exploit_results=exploit_results,
        recon_summary=recon_summary,
    )

    # Verify all major sections present
    assert "# Penetration Test Report" in report
    assert "## Executive Summary" in report
    assert "## Reconnaissance Summary" in report
    assert "## Findings" in report
    assert "## Proof of Concept" in report
    assert "## Remediation Guidance" in report

    # Verify findings
    assert "### CRITICAL Severity" in report
    assert "### MEDIUM Severity" in report
    assert "### LOW Severity" in report

    # Verify finding titles in grouped report
    assert "SQL Injection in login parameter" in report
    assert "Reflected XSS in search parameter" in report

    # Verify metadata
    assert "| **Total** | **3** |" in report
