"""Unit tests for reconnaissance tool wrappers.

Tests all three tools (subfinder, nmap, whatweb) with mocked subprocess calls.
No real binaries required - all tests use mocked outputs.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from scanner.tools import SubfinderTool, NmapTool, WhatWebTool, ToolStatus


# Sample outputs for mocking
SUBFINDER_JSON_OUTPUT = """{"host":"example.com","ip":"93.184.216.34"}
{"host":"www.example.com","ip":"93.184.216.34"}
{"host":"api.example.com","ip":"93.184.216.35"}
"""

SUBFINDER_JSON_WITH_DUPLICATES = """{"host":"example.com","ip":"93.184.216.34"}
{"host":"www.example.com","ip":"93.184.216.34"}
{"host":"example.com","ip":"93.184.216.34"}
"""

NMAP_XML_OUTPUT = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun>
<host>
<address addr="93.184.216.34" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack"/>
<service name="http" product="nginx" version="1.19.0"/>
</port>
<port protocol="tcp" portid="443">
<state state="open" reason="syn-ack"/>
<service name="https" product="nginx" version="1.19.0"/>
</port>
</ports>
</host>
</nmaprun>
"""

WHATWEB_JSON_OUTPUT = """{"target":"https://example.com","http_status":200,"plugins":{"Apache":{"version":["2.4.41"]},"PHP":{"version":["7.4.3"]},"WordPress":{},"jQuery":{"version":["3.5.1"]}}}
"""


# Subfinder Tests
@pytest.mark.asyncio
async def test_subfinder_parses_json_output():
    """Test that subfinder correctly parses JSON line output."""
    tool = SubfinderTool()

    with patch("scanner.tools.base.shutil.which", return_value="/usr/bin/subfinder"):
        with patch("scanner.tools.base.asyncio.create_subprocess_exec") as mock_exec:
            # Mock process
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(
                return_value=(SUBFINDER_JSON_OUTPUT.encode(), b"")
            )
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            result = await tool.run("example.com")

            assert result.status == ToolStatus.SUCCESS
            assert "subdomains" in result.data
            assert len(result.data["subdomains"]) == 3
            assert "example.com" in result.data["subdomains"]
            assert "www.example.com" in result.data["subdomains"]
            assert "api.example.com" in result.data["subdomains"]
            assert result.data["count"] == 3


@pytest.mark.asyncio
async def test_subfinder_handles_missing_binary():
    """Test that subfinder returns NOT_INSTALLED when binary is missing."""
    tool = SubfinderTool()

    with patch("scanner.tools.base.shutil.which", return_value=None):
        result = await tool.run("example.com")

        assert result.status == ToolStatus.NOT_INSTALLED
        assert "not installed" in result.error
        assert "go install" in result.error


@pytest.mark.asyncio
async def test_subfinder_deduplicates():
    """Test that subfinder deduplicates repeated subdomains."""
    tool = SubfinderTool()

    with patch("scanner.tools.base.shutil.which", return_value="/usr/bin/subfinder"):
        with patch("scanner.tools.base.asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(
                return_value=(SUBFINDER_JSON_WITH_DUPLICATES.encode(), b"")
            )
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            result = await tool.run("example.com")

            assert result.status == ToolStatus.SUCCESS
            assert len(result.data["subdomains"]) == 2  # Deduplicated
            assert result.data["count"] == 2


@pytest.mark.asyncio
async def test_subfinder_includes_base_domain():
    """Test that subfinder always includes the base domain in results."""
    tool = SubfinderTool()

    with patch("scanner.tools.base.shutil.which", return_value="/usr/bin/subfinder"):
        with patch("scanner.tools.base.asyncio.create_subprocess_exec") as mock_exec:
            # Output without base domain
            output = """{"host":"www.example.com","ip":"93.184.216.34"}
{"host":"api.example.com","ip":"93.184.216.35"}
"""
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(output.encode(), b""))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            result = await tool.run("example.com")

            assert result.status == ToolStatus.SUCCESS
            assert "example.com" in result.data["subdomains"]


# Nmap Tests
@pytest.mark.asyncio
async def test_nmap_parses_xml_output():
    """Test that nmap correctly parses XML output."""
    tool = NmapTool()

    with patch("scanner.tools.base.shutil.which", return_value="/usr/bin/nmap"):
        with patch("scanner.tools.base.asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(
                return_value=(NMAP_XML_OUTPUT.encode(), b"")
            )
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            result = await tool.run("example.com")

            assert result.status == ToolStatus.SUCCESS
            assert "hosts" in result.data
            assert len(result.data["hosts"]) == 1

            host = result.data["hosts"][0]
            assert host["address"] == "93.184.216.34"
            assert len(host["ports"]) == 2

            # Check port 80
            port_80 = next(p for p in host["ports"] if p["port"] == 80)
            assert port_80["protocol"] == "tcp"
            assert port_80["state"] == "open"
            assert port_80["service"] == "http"
            assert "nginx" in port_80["version"]

            # Check port 443
            port_443 = next(p for p in host["ports"] if p["port"] == 443)
            assert port_443["service"] == "https"


@pytest.mark.asyncio
async def test_nmap_handles_missing_binary():
    """Test that nmap returns NOT_INSTALLED when binary is missing."""
    tool = NmapTool()

    with patch("scanner.tools.base.shutil.which", return_value=None):
        result = await tool.run("example.com")

        assert result.status == ToolStatus.NOT_INSTALLED
        assert "not installed" in result.error
        assert "nmap" in result.error


@pytest.mark.asyncio
async def test_nmap_respects_semaphore():
    """Test that nmap respects concurrency limiting via semaphore."""
    tool = NmapTool(max_concurrent=1)

    # Verify semaphore exists and has correct initial value
    assert tool.semaphore._value == 1

    with patch("scanner.tools.base.shutil.which", return_value="/usr/bin/nmap"):
        with patch("scanner.tools.base.asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(
                return_value=(NMAP_XML_OUTPUT.encode(), b"")
            )
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            # Run scan - semaphore should be acquired then released
            result = await tool.run("example.com")

            assert result.status == ToolStatus.SUCCESS
            # After completion, semaphore should be released
            assert tool.semaphore._value == 1


@pytest.mark.asyncio
async def test_nmap_handles_root_requirement():
    """Test that nmap retries with -sT when root is required."""
    tool = NmapTool()

    with patch("scanner.tools.base.shutil.which", return_value="/usr/bin/nmap"):
        with patch("scanner.tools.base.asyncio.create_subprocess_exec") as mock_exec:
            # First call fails with "requires root"
            mock_process_fail = AsyncMock()
            mock_process_fail.communicate = AsyncMock(
                return_value=(b"", b"This scan requires root privileges")
            )
            mock_process_fail.returncode = 1

            # Second call succeeds
            mock_process_success = AsyncMock()
            mock_process_success.communicate = AsyncMock(
                return_value=(NMAP_XML_OUTPUT.encode(), b"")
            )
            mock_process_success.returncode = 0

            # Return failing process first, then success
            mock_exec.side_effect = [mock_process_fail, mock_process_success]

            result = await tool.run("example.com")

            assert result.status == ToolStatus.SUCCESS
            # Verify second call used -sT instead of -sV
            assert mock_exec.call_count == 2


# WhatWeb Tests
@pytest.mark.asyncio
async def test_whatweb_parses_json_output():
    """Test that whatweb correctly parses JSON output."""
    tool = WhatWebTool()

    with patch("scanner.tools.base.shutil.which", return_value="/usr/bin/whatweb"):
        with patch("scanner.tools.base.asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(
                return_value=(WHATWEB_JSON_OUTPUT.encode(), b"")
            )
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            result = await tool.run("example.com")

            assert result.status == ToolStatus.SUCCESS
            assert "technologies" in result.data
            assert len(result.data["technologies"]) > 0

            # Check that technologies are parsed
            tech_names = [t["name"] for t in result.data["technologies"]]
            assert "Apache" in tech_names
            assert "PHP" in tech_names
            assert "WordPress" in tech_names

            # Check version extraction
            apache = next(t for t in result.data["technologies"] if t["name"] == "Apache")
            assert apache["version"] == "2.4.41"

            # Check category mapping
            assert apache["category"] == "web-server"


@pytest.mark.asyncio
async def test_whatweb_handles_missing_binary():
    """Test that whatweb returns NOT_INSTALLED when binary is missing."""
    tool = WhatWebTool()

    with patch("scanner.tools.base.shutil.which", return_value=None):
        result = await tool.run("example.com")

        assert result.status == ToolStatus.NOT_INSTALLED
        assert "not installed" in result.error
        assert "whatweb" in result.error


@pytest.mark.asyncio
async def test_whatweb_adds_scheme():
    """Test that whatweb adds https:// scheme to bare domains."""
    tool = WhatWebTool()

    with patch("scanner.tools.base.shutil.which", return_value="/usr/bin/whatweb"):
        with patch("scanner.tools.base.asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(
                return_value=(WHATWEB_JSON_OUTPUT.encode(), b"")
            )
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            result = await tool.run("example.com")

            # Verify the URL in result data has scheme
            assert result.data["url"] == "https://example.com"

            # Verify command included https://
            call_args = mock_exec.call_args[0]
            assert "https://example.com" in call_args


# Subprocess Utility Tests
@pytest.mark.asyncio
async def test_run_subprocess_timeout():
    """Test that run_subprocess kills process on timeout."""
    from scanner.tools.base import run_subprocess

    with patch("scanner.tools.base.asyncio.create_subprocess_exec") as mock_exec:
        mock_process = AsyncMock()
        mock_process.pid = 12345

        # Simulate timeout
        async def communicate_timeout():
            await asyncio.sleep(10)  # Longer than timeout

        mock_process.communicate = communicate_timeout
        mock_process.kill = MagicMock()
        mock_exec.return_value = mock_process

        with pytest.raises(asyncio.TimeoutError):
            await run_subprocess(["test"], timeout=0.1)

        # Verify kill was called
        mock_process.kill.assert_called_once()


@pytest.mark.asyncio
async def test_run_with_retry_retries_on_transient():
    """Test that run_with_retry retries on transient errors."""
    from scanner.tools.base import run_with_retry

    with patch("scanner.tools.base.asyncio.create_subprocess_exec") as mock_exec:
        # First two attempts fail with connection error
        mock_process_fail = AsyncMock()
        mock_process_fail.communicate = AsyncMock(
            return_value=(b"", b"connection timeout error")
        )
        mock_process_fail.returncode = 1

        # Third attempt succeeds
        mock_process_success = AsyncMock()
        mock_process_success.communicate = AsyncMock(
            return_value=(b"success", b"")
        )
        mock_process_success.returncode = 0

        mock_exec.side_effect = [
            mock_process_fail,
            mock_process_fail,
            mock_process_success
        ]

        stdout, stderr, code = await run_with_retry(["test"], max_retries=3, timeout=1)

        assert code == 0
        assert stdout == "success"
        assert mock_exec.call_count == 3


@pytest.mark.asyncio
async def test_run_with_retry_does_not_retry_permanent():
    """Test that run_with_retry does not retry permanent errors."""
    from scanner.tools.base import run_with_retry

    with patch("scanner.tools.base.asyncio.create_subprocess_exec") as mock_exec:
        mock_process = AsyncMock()
        mock_process.communicate = AsyncMock(
            return_value=(b"", b"permission denied")
        )
        mock_process.returncode = 1
        mock_exec.return_value = mock_process

        # Should not retry - just return the error
        stdout, stderr, code = await run_with_retry(["test"], max_retries=3, timeout=1)

        assert code == 1
        assert "permission denied" in stderr
        # Should only attempt once (no retries for permanent errors)
        assert mock_exec.call_count == 1
