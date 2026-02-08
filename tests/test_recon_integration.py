"""End-to-end integration tests for full reconnaissance pipeline.

Tests verify the complete chain: CLI -> DB -> Agent -> Tools -> DB persistence,
with mocked external tool binaries (no real subfinder/nmap/whatweb required).
"""

import pytest
import json
import os
import tempfile
from unittest.mock import patch, AsyncMock, MagicMock
from asyncclick.testing import CliRunner
from scanner.cli.recon import cli
from scanner.core.persistence.database import init_database, create_session_factory, get_session
from scanner.core.persistence.models import Target, ScanResult
from scanner.tools import ToolResult, ToolStatus
from sqlalchemy import select


# Realistic canned tool outputs for mocking
SUBFINDER_OUTPUT = b'{"host":"example.com","source":"crt"}\n{"host":"api.example.com","source":"crt"}\n{"host":"www.example.com","source":"alienvault"}\n'

NMAP_OUTPUT = b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -Pn -p 80,443 93.184.216.34" start="1234567890" version="7.94">
<host starttime="1234567890" endtime="1234567891">
<address addr="93.184.216.34" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack" reason_ttl="0"/>
<service name="http" product="Apache httpd" version="2.4.41" />
</port>
<port protocol="tcp" portid="443">
<state state="open" reason="syn-ack" reason_ttl="0"/>
<service name="https" product="Apache httpd" version="2.4.41" />
</port>
</ports>
</host>
</nmaprun>
'''

WHATWEB_OUTPUT = b'{"target":"https://example.com","plugins":{"Apache":{"version":["2.4.41"]},"PHP":{"version":["8.1.0"]},"HTTPServer":{"string":["Apache/2.4.41"]}}}\n'


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


def create_mock_subprocess(cmd_outputs: dict):
    """Create a mock for asyncio.create_subprocess_exec.

    Args:
        cmd_outputs: dict mapping binary name to (stdout, stderr, returncode)

    Returns:
        Async function that returns a mock process based on the command
    """
    async def mock_exec(*cmd, **kwargs):
        # Extract binary name (first argument)
        binary = cmd[0].split("/")[-1] if "/" in cmd[0] else cmd[0]

        stdout, stderr, returncode = cmd_outputs.get(binary, (b"", b"", 1))

        process = AsyncMock()
        process.communicate = AsyncMock(return_value=(stdout, stderr))
        process.returncode = returncode
        process.kill = AsyncMock()
        process.wait = AsyncMock()
        return process

    return mock_exec


@pytest.mark.asyncio
async def test_full_recon_pipeline_end_to_end(db_engine):
    """Test the complete pipeline: Target auth -> ReconAgent -> Tool wrappers -> DB persistence."""

    # Set up authorized target
    async with get_session() as session:
        target = Target(
            url="example.com",
            scope=json.dumps(["example.com"]),
            authorized_by="test-user"
        )
        session.add(target)
        await session.commit()
        target_id = target.id

    # Mock tool binaries
    with patch("shutil.which") as mock_which:
        # Pretend all tools are installed
        mock_which.side_effect = lambda x: f"/usr/bin/{x}" if x in ["subfinder", "nmap", "whatweb"] else None

        # Mock subprocess execution
        cmd_outputs = {
            "subfinder": (SUBFINDER_OUTPUT, b"", 0),
            "nmap": (NMAP_OUTPUT, b"", 0),
            "whatweb": (WHATWEB_OUTPUT, b"", 0),
        }

        mock_subprocess = create_mock_subprocess(cmd_outputs)

        with patch("asyncio.create_subprocess_exec", new=mock_subprocess):
            from scanner.agents import ReconAgent

            # Create agent and run pipeline
            session_id = "test-integration-session"
            agent = ReconAgent(session_id=session_id)
            results = await agent.run("example.com")

    # Verify results structure
    assert "subdomains" in results
    assert "port_scan" in results
    assert "technologies" in results
    assert "attack_surface" in results

    # Verify subdomains (3 from mock output)
    subdomains = results["subdomains"]
    assert len(subdomains) == 3
    # Subdomains are returned as list[str], not list[dict]
    assert "example.com" in subdomains
    assert "api.example.com" in subdomains
    assert "www.example.com" in subdomains

    # Verify port scan results (2 open ports from mock nmap XML)
    port_scan = results["port_scan"]
    assert len(port_scan) >= 2
    ports = [s["port"] for s in port_scan]
    assert 80 in ports
    assert 443 in ports

    # Verify technologies (Apache and PHP from mock whatweb)
    technologies = results["technologies"]
    assert len(technologies) >= 2
    tech_names = [t["name"] for t in technologies]
    assert "Apache" in tech_names
    assert "PHP" in tech_names

    # Verify attack surface summary
    attack_surface = results["attack_surface"]
    summary = attack_surface["summary"]
    assert summary["total_subdomains"] == 3
    assert summary["total_open_ports"] >= 2
    assert summary["total_technologies"] >= 2

    # Verify database persistence
    async with get_session() as session:
        db_result = await session.execute(
            select(ScanResult).where(ScanResult.session_id == session_id)
        )
        scan_result = db_result.scalar_one_or_none()

    assert scan_result is not None
    assert scan_result.status == "completed"
    assert scan_result.target_id == target_id

    findings = json.loads(scan_result.findings)
    assert "summary" in findings


@pytest.mark.asyncio
async def test_cli_scan_produces_database_record(db_engine):
    """Full CLI-level test: add-target -> scan -> verify DB persistence."""
    runner = CliRunner()

    async def mock_init_db():
        return db_engine

    # Step 1: Add authorized target via CLI
    with patch("scanner.cli.recon.init_db", new=mock_init_db):
        add_result = await runner.invoke(cli, ["add-target", "example.com"])

    assert add_result.exit_code == 0
    assert "Target authorized: example.com" in add_result.output

    # Step 2: Mock tool binaries and execute scan
    with patch("shutil.which") as mock_which:
        mock_which.side_effect = lambda x: f"/usr/bin/{x}" if x in ["subfinder", "nmap", "whatweb"] else None

        cmd_outputs = {
            "subfinder": (SUBFINDER_OUTPUT, b"", 0),
            "nmap": (NMAP_OUTPUT, b"", 0),
            "whatweb": (WHATWEB_OUTPUT, b"", 0),
        }

        mock_subprocess = create_mock_subprocess(cmd_outputs)

        with patch("scanner.cli.recon.init_db", new=mock_init_db), \
             patch("asyncio.create_subprocess_exec", new=mock_subprocess):
            scan_result = await runner.invoke(cli, ["scan", "example.com"])

    # Step 3: Verify CLI output
    if scan_result.exit_code != 0:
        print(f"CLI output: {scan_result.output}")
        print(f"Exception: {scan_result.exception}")
    assert scan_result.exit_code == 0
    assert "Reconnaissance Complete" in scan_result.output
    assert "Subdomains found: 3" in scan_result.output
    assert "Open ports/services:" in scan_result.output
    assert "Technologies detected:" in scan_result.output
    assert "93.184.216.34:80" in scan_result.output
    assert "Apache" in scan_result.output
    assert "Attack Surface Summary" in scan_result.output
    assert "Results saved to database" in scan_result.output

    # Step 4: Verify database record was created
    async with get_session() as session:
        db_result = await session.execute(select(ScanResult))
        scan_records = db_result.scalars().all()

    assert len(scan_records) == 1
    scan_record = scan_records[0]
    assert scan_record.status == "completed"
    assert scan_record.findings is not None

    findings = json.loads(scan_record.findings)
    assert "summary" in findings
    assert findings["summary"]["total_subdomains"] == 3


@pytest.mark.asyncio
async def test_unauthorized_scan_blocked(db_engine):
    """Verify scope enforcement: unauthorized targets are blocked before tool execution."""
    runner = CliRunner()

    async def mock_init_db():
        return db_engine

    # Do NOT add target to database - it's unauthorized

    # Mock tools to verify they're never called
    with patch("shutil.which") as mock_which, \
         patch("asyncio.create_subprocess_exec") as mock_subprocess:

        mock_which.side_effect = lambda x: f"/usr/bin/{x}"

        with patch("scanner.cli.recon.init_db", new=mock_init_db):
            result = await runner.invoke(cli, ["scan", "unauthorized.com"])

    # Verify scan handled gracefully (returns 0 since we use return instead of ctx.exit(1))
    assert result.exit_code == 0
    assert "Scope check failed" in result.output or "not in authorized scope" in result.output

    # Verify subprocess was NEVER called (tools never executed)
    mock_subprocess.assert_not_called()

    # Verify no database records created
    async with get_session() as session:
        db_result = await session.execute(select(ScanResult))
        scan_records = db_result.scalars().all()

    assert len(scan_records) == 0


@pytest.mark.asyncio
async def test_partial_tool_failure_graceful_degradation(db_engine):
    """Test that pipeline continues even if one tool fails (graceful degradation)."""

    # Set up authorized target
    async with get_session() as session:
        target = Target(
            url="example.com",
            scope=json.dumps(["example.com"]),
            authorized_by="test-user"
        )
        session.add(target)
        await session.commit()

    # Mock tools: subfinder succeeds, nmap fails, whatweb succeeds
    with patch("shutil.which") as mock_which:
        mock_which.side_effect = lambda x: f"/usr/bin/{x}" if x in ["subfinder", "nmap", "whatweb"] else None

        cmd_outputs = {
            "subfinder": (SUBFINDER_OUTPUT, b"", 0),
            "nmap": (b"", b"Error: scan failed", 1),  # Nmap fails
            "whatweb": (WHATWEB_OUTPUT, b"", 0),
        }

        mock_subprocess = create_mock_subprocess(cmd_outputs)

        with patch("asyncio.create_subprocess_exec", new=mock_subprocess):
            from scanner.agents import ReconAgent

            agent = ReconAgent(session_id="partial-failure-test")
            results = await agent.run("example.com")

    # Should still have results from successful tools
    assert "subdomains" in results
    assert len(results["subdomains"]) == 3

    # Port scan might be empty or have limited results due to nmap failure
    assert "port_scan" in results

    # Technologies should still be detected from whatweb
    assert "technologies" in results
    assert len(results["technologies"]) >= 2
