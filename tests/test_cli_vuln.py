"""Unit tests for vuln-scan, exploit, and report CLI commands."""

import pytest
import json
from unittest.mock import patch, AsyncMock, MagicMock
from asyncclick.testing import CliRunner
from scanner.cli.recon import cli
from scanner.core.output import Finding, Evidence, SourceType


@pytest.mark.asyncio
async def test_vuln_scan_command_exists():
    """Test that vuln-scan command exists in CLI."""
    runner = CliRunner()
    result = await runner.invoke(cli, ["--help"])

    assert result.exit_code == 0
    assert "vuln-scan" in result.output


@pytest.mark.asyncio
async def test_exploit_command_exists():
    """Test that exploit command exists in CLI."""
    runner = CliRunner()
    result = await runner.invoke(cli, ["--help"])

    assert result.exit_code == 0
    assert "exploit" in result.output


@pytest.mark.asyncio
async def test_report_command_exists():
    """Test that report command exists in CLI."""
    runner = CliRunner()
    result = await runner.invoke(cli, ["--help"])

    assert result.exit_code == 0
    assert "report" in result.output


@pytest.mark.asyncio
async def test_vuln_scan_no_target():
    """Test vuln-scan command without target shows error."""
    runner = CliRunner()
    result = await runner.invoke(cli, ["vuln-scan"])

    assert result.exit_code != 0
    assert "Error" in result.output or "Missing" in result.output


@pytest.mark.asyncio
async def test_vuln_scan_with_target():
    """Test vuln-scan command with target runs successfully."""
    runner = CliRunner()

    # Create mock engine with dispose method
    mock_engine = MagicMock()
    mock_engine.dispose = AsyncMock()

    async def mock_init_db():
        return mock_engine

    # Mock ReconAgent
    mock_recon_results = {
        "scan_id": "test-scan-123",
        "target": "example.com",
        "subdomains": ["example.com", "www.example.com"],
        "port_scan": [
            {"host": "example.com", "port": 80, "service": "http"}
        ],
        "technologies": [{"name": "Apache", "version": "2.4"}],
        "attack_surface": {
            "summary": {
                "total_subdomains": 2,
                "total_open_ports": 1,
                "total_technologies": 1
            }
        }
    }

    # Mock VulnAgent findings
    mock_finding = Finding(
        title="SQL Injection in login",
        severity="high",
        description="SQL injection vulnerability found",
        evidence=[
            Evidence(
                source=SourceType.TOOL_CONFIRMED,
                data={"payload": "' OR 1=1--"},
                tool_name="sqlmap"
            )
        ],
        confidence="high"
    )

    # Mock database interactions
    mock_scan_result = MagicMock()
    mock_scan_result.findings = json.dumps({"recon": "data"})
    mock_scan_result.session_id = "test-session"

    mock_target = MagicMock()
    mock_target.id = 1
    mock_target.url = "example.com"

    mock_db_session = MagicMock()
    mock_db_session.__aenter__ = AsyncMock(return_value=mock_db_session)
    mock_db_session.__aexit__ = AsyncMock(return_value=None)

    mock_execute_result = MagicMock()
    mock_execute_result.scalar_one_or_none = MagicMock(side_effect=[mock_scan_result, mock_target])
    mock_db_session.execute = AsyncMock(return_value=mock_execute_result)
    mock_db_session.commit = AsyncMock()

    def mock_get_session():
        return mock_db_session

    with patch("scanner.cli.recon.init_db", new=mock_init_db), \
         patch("scanner.agents.ReconAgent") as mock_recon_class, \
         patch("scanner.agents.vuln.VulnAgent") as mock_vuln_class, \
         patch("scanner.core.persistence.database.get_session", side_effect=mock_get_session):

        mock_recon_instance = AsyncMock()
        mock_recon_instance.run = AsyncMock(return_value=mock_recon_results)
        mock_recon_class.return_value = mock_recon_instance

        mock_vuln_instance = AsyncMock()
        mock_vuln_instance.scan = AsyncMock(return_value=[mock_finding])
        mock_vuln_class.return_value = mock_vuln_instance

        result = await runner.invoke(cli, ["vuln-scan", "example.com"])

    # Check for errors first to debug
    if result.exit_code != 0:
        print(f"Error output: {result.output}")
        if result.exception:
            import traceback
            print(f"Exception: {''.join(traceback.format_exception(type(result.exception), result.exception, result.exception.__traceback__))}")

    assert result.exit_code == 0
    assert "[+] Vulnerability Scan Complete" in result.output
    assert "Findings Summary" in result.output


@pytest.mark.asyncio
async def test_exploit_requires_session_id():
    """Test exploit command requires --session-id."""
    runner = CliRunner()
    result = await runner.invoke(cli, ["exploit", "example.com"])

    assert result.exit_code != 0
    # AsyncClick will show missing option error


@pytest.mark.asyncio
async def test_exploit_with_session_id():
    """Test exploit command with session ID."""
    runner = CliRunner()

    # Create mock engine
    mock_engine = MagicMock()
    mock_engine.dispose = AsyncMock()

    async def mock_init_db():
        return mock_engine

    # Mock findings in database
    mock_finding_dict = {
        "title": "SQL Injection",
        "severity": "high",
        "description": "SQL injection vulnerability",
        "evidence": [
            {
                "source": "tool_confirmed",
                "timestamp": "2024-01-01T00:00:00",
                "data": {"payload": "' OR 1=1--"},
                "tool_name": "sqlmap"
            }
        ],
        "confidence": "high"
    }

    mock_scan_result = MagicMock()
    mock_scan_result.findings = json.dumps({"vulnerabilities": [mock_finding_dict]})
    mock_scan_result.session_id = "test-session"

    # Mock ExploitResult
    from scanner.agents.exploit import ExploitResult, ExploitChain, ExploitStep
    from scanner.core.output import Finding

    mock_finding = Finding(**mock_finding_dict)
    mock_chain = ExploitChain(
        finding=mock_finding,
        steps=[],
        objective="Test SQL injection"
    )
    mock_result = ExploitResult(
        chain=mock_chain,
        steps_executed=1,
        steps_total=1,
        poc="curl test",
        evidence_validated=True,
        raw_results=[],
        confidence="confirmed"
    )

    mock_db_session = MagicMock()
    mock_db_session.__aenter__ = AsyncMock(return_value=mock_db_session)
    mock_db_session.__aexit__ = AsyncMock(return_value=None)

    mock_execute_result = MagicMock()
    mock_execute_result.scalar_one_or_none = MagicMock(return_value=mock_scan_result)
    mock_db_session.execute = AsyncMock(return_value=mock_execute_result)

    def mock_get_session():
        return mock_db_session

    with patch("scanner.cli.recon.init_db", new=mock_init_db), \
         patch("scanner.agents.exploit.ExploitAgent") as mock_exploit_class, \
         patch("scanner.core.persistence.database.get_session", side_effect=mock_get_session):

        mock_exploit_instance = AsyncMock()
        mock_exploit_instance.execute = AsyncMock(return_value=[mock_result])
        mock_exploit_class.return_value = mock_exploit_instance

        result = await runner.invoke(cli, ["exploit", "example.com", "--session-id", "test-session"])

    assert result.exit_code == 0
    assert "[+] Exploitation Complete" in result.output
    assert "chains executed" in result.output


@pytest.mark.asyncio
async def test_report_generates_file():
    """Test report command generates markdown file."""
    runner = CliRunner()
    import tempfile
    import os

    # Create mock engine
    mock_engine = MagicMock()
    mock_engine.dispose = AsyncMock()

    async def mock_init_db():
        return mock_engine

    # Mock findings
    mock_finding_dict = {
        "title": "SQL Injection",
        "severity": "high",
        "description": "SQL injection vulnerability",
        "evidence": [
            {
                "source": "tool_confirmed",
                "timestamp": "2024-01-01T00:00:00",
                "data": {"payload": "' OR 1=1--"},
                "tool_name": "sqlmap"
            }
        ],
        "confidence": "high"
    }

    mock_scan_result = MagicMock()
    mock_scan_result.findings = json.dumps({
        "vulnerabilities": [mock_finding_dict],
        "attack_surface": {
            "summary": {
                "total_subdomains": 2,
                "total_open_ports": 3,
                "total_technologies": 4
            }
        }
    })
    mock_scan_result.session_id = "test-session"
    mock_scan_result.target_id = 1

    mock_target = MagicMock()
    mock_target.url = "example.com"
    mock_target.id = 1

    mock_db_session = MagicMock()
    mock_db_session.__aenter__ = AsyncMock(return_value=mock_db_session)
    mock_db_session.__aexit__ = AsyncMock(return_value=None)

    mock_execute_result = MagicMock()
    mock_execute_result.scalar_one_or_none = MagicMock(side_effect=[mock_scan_result, mock_target])
    mock_db_session.execute = AsyncMock(return_value=mock_execute_result)

    def mock_get_session():
        return mock_db_session

    # Mock ReportGenerator
    mock_report_content = "# Penetration Test Report\n\nTest report content"

    with patch("scanner.cli.recon.init_db", new=mock_init_db), \
         patch("scanner.core.persistence.database.get_session", side_effect=mock_get_session), \
         patch("scanner.core.reporting.generator.ReportGenerator") as mock_generator_class:

        mock_generator = MagicMock()
        mock_generator.generate = MagicMock(return_value=mock_report_content)
        mock_generator_class.return_value = mock_generator

        # Use temp file for output
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, "test-report.md")
            result = await runner.invoke(cli, ["report", "test-session", "-o", output_file])

            assert result.exit_code == 0
            assert "[+] Report generated:" in result.output
            assert os.path.exists(output_file)

            # Verify file contents
            with open(output_file, "r") as f:
                content = f.read()
                assert "Penetration Test Report" in content


@pytest.mark.asyncio
async def test_report_no_session_data():
    """Test report command with non-existent session."""
    runner = CliRunner()

    # Create mock engine
    mock_engine = MagicMock()
    mock_engine.dispose = AsyncMock()

    async def mock_init_db():
        return mock_engine

    mock_db_session = MagicMock()
    mock_db_session.__aenter__ = AsyncMock(return_value=mock_db_session)
    mock_db_session.__aexit__ = AsyncMock(return_value=None)

    mock_execute_result = MagicMock()
    mock_execute_result.scalar_one_or_none = MagicMock(return_value=None)
    mock_db_session.execute = AsyncMock(return_value=mock_execute_result)

    def mock_get_session():
        return mock_db_session

    with patch("scanner.cli.recon.init_db", new=mock_init_db), \
         patch("scanner.core.persistence.database.get_session", side_effect=mock_get_session):

        result = await runner.invoke(cli, ["report", "nonexistent-session"])

    assert result.exit_code == 1
    assert "No results found" in result.output
