"""Unit tests for CLI commands with mocked agent."""

import pytest
import json
import os
import tempfile
from unittest.mock import patch, AsyncMock
from asyncclick.testing import CliRunner
from scanner.cli.recon import cli
from scanner.core.persistence.database import init_database, create_session_factory, get_session
from scanner.core.persistence.models import Target, ScanResult
from sqlalchemy import select


@pytest.fixture
async def test_db_path():
    """Create a temporary database file path for testing."""
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield db_path
    # Clean up after test
    try:
        os.unlink(db_path)
    except:
        pass


@pytest.fixture
async def db_engine(test_db_path):
    """Fresh temporary database for each test."""
    db_url = f"sqlite+aiosqlite:///{test_db_path}"
    engine = await init_database(db_url)
    create_session_factory(engine)
    yield engine
    await engine.dispose()


@pytest.mark.asyncio
async def test_add_target_creates_record(db_engine):
    """Test that add-target creates a Target record in the database."""
    runner = CliRunner()

    # Mock init_db to return the test database engine
    async def mock_init_db():
        return db_engine

    with patch("scanner.cli.recon.init_db", new=mock_init_db):
        result = await runner.invoke(cli, ["add-target", "example.com"])

    assert result.exit_code == 0
    assert "[+] Target authorized: example.com" in result.output
    assert "[+] Scope: ['example.com']" in result.output

    # Verify database record
    async with get_session() as session:
        db_result = await session.execute(select(Target).where(Target.url == "example.com"))
        target = db_result.scalar_one_or_none()

    assert target is not None
    assert target.url == "example.com"
    assert json.loads(target.scope) == ["example.com"]
    assert target.authorized_by == "cli-user"


@pytest.mark.asyncio
async def test_add_target_with_custom_scope(db_engine):
    """Test add-target with custom scope patterns."""
    runner = CliRunner()

    async def mock_init_db():
        return db_engine

    with patch("scanner.cli.recon.init_db", new=mock_init_db):
        result = await runner.invoke(
            cli,
            ["add-target", "example.com", "-s", "*.example.com", "-s", "example.com"]
        )

    assert result.exit_code == 0
    assert "[+] Scope: ['*.example.com', 'example.com']" in result.output

    # Verify scope in database
    async with get_session() as session:
        db_result = await session.execute(select(Target).where(Target.url == "example.com"))
        target = db_result.scalar_one_or_none()

    assert target is not None
    scope = json.loads(target.scope)
    assert "*.example.com" in scope
    assert "example.com" in scope


@pytest.mark.asyncio
async def test_add_target_duplicate_shows_message(db_engine):
    """Test adding the same target twice shows appropriate message."""
    runner = CliRunner()

    async def mock_init_db():
        return db_engine

    with patch("scanner.cli.recon.init_db", new=mock_init_db):
        # Add target first time
        result1 = await runner.invoke(cli, ["add-target", "example.com"])
        assert result1.exit_code == 0

        # Add same target again
        result2 = await runner.invoke(cli, ["add-target", "example.com"])
        assert result2.exit_code == 0
        assert "[!] Target already exists: example.com" in result2.output


@pytest.mark.asyncio
async def test_scan_unauthorized_target_fails(db_engine):
    """Test that scanning an unauthorized target fails with clear error."""
    runner = CliRunner()

    async def mock_init_db():
        return db_engine

    # Don't add target to database - it's unauthorized
    with patch("scanner.cli.recon.init_db", new=mock_init_db), \
         patch("scanner.agents.ReconAgent.run") as mock_run:
        # Mock run to raise RuntimeError like the real scope check does
        mock_run.side_effect = RuntimeError("Target example.com not in authorized scope")

        result = await runner.invoke(cli, ["scan", "example.com"])

    assert result.exit_code == 1
    assert "Scope check failed" in result.output
    assert "add-target" in result.output


@pytest.mark.asyncio
async def test_scan_authorized_target_runs_pipeline(db_engine):
    """Test scanning an authorized target invokes agent and displays results."""
    runner = CliRunner()

    async def mock_init_db():
        return db_engine

    with patch("scanner.cli.recon.init_db", new=mock_init_db):
        # Add target first
        await runner.invoke(cli, ["add-target", "example.com"])

    # Mock the ReconAgent to return sample data
    sample_results = {
        "scan_id": "test-scan-123",
        "subdomains": [
            {"host": "example.com", "source": "crt"},
            {"host": "api.example.com", "source": "crt"},
            {"host": "www.example.com", "source": "alienvault"}
        ],
        "port_scan": [
            {"host": "93.184.216.34", "port": 80, "service": "http", "version": "Apache"},
            {"host": "93.184.216.34", "port": 443, "service": "https", "version": ""}
        ],
        "technologies": [
            {"name": "Apache", "version": "2.4.41"},
            {"name": "PHP", "version": "8.1.0"}
        ],
        "attack_surface": {
            "summary": {
                "total_subdomains": 3,
                "total_open_ports": 2,
                "total_technologies": 2
            }
        }
    }

    with patch("scanner.cli.recon.init_db", new=mock_init_db), \
         patch("scanner.agents.ReconAgent.run", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = sample_results

        result = await runner.invoke(cli, ["scan", "example.com"])

    assert result.exit_code == 0
    assert "Reconnaissance Complete" in result.output
    assert "Subdomains found: 3" in result.output
    assert "example.com" in result.output
    assert "Open ports/services: 2" in result.output
    assert "93.184.216.34:80" in result.output
    assert "Technologies detected: 2" in result.output
    assert "Apache" in result.output
    assert "Attack Surface Summary" in result.output
    assert "Total subdomains: 3" in result.output
    assert "Results saved to database (scan ID: test-scan-123)" in result.output


@pytest.mark.asyncio
async def test_status_no_results(db_engine):
    """Test status command with non-existent session."""
    runner = CliRunner()

    async def mock_init_db():
        return db_engine

    with patch("scanner.cli.recon.init_db", new=mock_init_db):
        result = await runner.invoke(cli, ["status", "nonexistent-session-id"])

    assert result.exit_code == 0
    assert "No results found for session nonexistent-session-id" in result.output


@pytest.mark.asyncio
async def test_status_with_results(db_engine):
    """Test status command retrieves and displays scan results."""
    runner = CliRunner()

    async def mock_init_db():
        return db_engine

    # Create a target first (required for foreign key)
    async with get_session() as session:
        target = Target(
            url="example.com",
            scope=json.dumps(["example.com"]),
            authorized_by="test-user"
        )
        session.add(target)
        await session.commit()
        target_id = target.id

    # Create a scan result in the database
    session_id = "test-session-123"
    findings = {
        "attack_surface": {
            "summary": {
                "total_subdomains": 5,
                "total_open_ports": 3,
                "total_technologies": 4
            }
        }
    }

    async with get_session() as session:
        scan_result = ScanResult(
            session_id=session_id,
            target_id=target_id,
            status="completed",
            findings=json.dumps(findings)
        )
        session.add(scan_result)
        await session.commit()

    with patch("scanner.cli.recon.init_db", new=mock_init_db):
        result = await runner.invoke(cli, ["status", session_id])

    assert result.exit_code == 0
    assert f"Scan Status for session: {session_id}" in result.output
    assert "Status: completed" in result.output
    assert "Subdomains: 5" in result.output
    assert "Open ports: 3" in result.output
    assert "Technologies: 4" in result.output


@pytest.mark.asyncio
async def test_cli_help_text():
    """Test that CLI help text is displayed."""
    runner = CliRunner()

    result = await runner.invoke(cli, ["--help"])

    assert result.exit_code == 0
    assert "EvilClawd - AI-Powered Penetration Testing Assistant" in result.output
    assert "add-target" in result.output
    assert "scan" in result.output
    assert "status" in result.output


@pytest.mark.asyncio
async def test_add_target_help():
    """Test add-target command help."""
    runner = CliRunner()

    result = await runner.invoke(cli, ["add-target", "--help"])

    assert result.exit_code == 0
    assert "Authorize a target URL for scanning" in result.output
    assert "--scope" in result.output


@pytest.mark.asyncio
async def test_scan_help():
    """Test scan command help."""
    runner = CliRunner()

    result = await runner.invoke(cli, ["scan", "--help"])

    assert result.exit_code == 0
    assert "Run reconnaissance scan on an authorized target" in result.output
    assert "--ports" in result.output
    assert "--session-id" in result.output
