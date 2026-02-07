"""Unit tests for vulnerability tool wrappers.

Tests SQLMapTool, XSSTool, and CommixTool with mocked subprocess calls.
No real binaries required - all tests use mocked outputs.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, patch
from scanner.tools import SQLMapTool, XSSTool, CommixTool, ToolStatus


# Sample outputs for mocking

SQLMAP_VULNERABLE_OUTPUT = """
[12:34:56] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[12:34:57] [INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
[12:34:58] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause'
[12:35:00] [INFO] GET parameter 'id' is 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause' injectable
[12:35:01] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.41
back-end DBMS: MySQL >= 5.0
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause
    Payload: id=1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x3a,0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)
"""

SQLMAP_CLEAN_OUTPUT = """
[12:34:56] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[12:34:57] [INFO] GET parameter 'id' is not injectable
[12:34:58] [INFO] testing 'MySQL >= 5.0 AND error-based'
[12:35:00] [WARNING] GET parameter 'id' does not seem to be injectable
[12:35:01] [CRITICAL] all tested parameters do not appear to be injectable
"""

XSSER_VULNERABLE_OUTPUT = """
[*] Testing [XSS FOUND]
[+] Target: http://example.com/search?q=test
[+] Vulnerable URL: http://example.com/search?q=<script>alert(1)</script>
[+] Parameter: q
[+] Payload: <script>alert(1)</script>
[+] Type: Reflected
[+] Injection Point: GET parameter

XSS FOUND! - Vulnerability Detected
Total Attacks: 1
Successful: 1
"""

XSSER_CLEAN_OUTPUT = """
[*] Testing [GET]
[*] Target: http://example.com/search?q=test
[*] Testing parameter: q
[-] No XSS vulnerabilities found
[*] Total Attacks: 10
[*] Successful: 0
"""

COMMIX_VULNERABLE_OUTPUT = """
[12:34:56] [INFO] Testing parameter 'host' for command injection
[12:34:57] [SUCCESS] The GET parameter 'host' seems injectable via (classic) command injection technique
[12:34:58] [INFO] Testing OS detection
[12:35:00] [INFO] The target operating system: Linux
Parameter: host (GET)
    Technique: classic command injection
    Payload: ;id
    Detected OS: Linux
[12:35:01] [INFO] Parameter 'host' is vulnerable
"""

COMMIX_CLEAN_OUTPUT = """
[12:34:56] [INFO] Testing parameter 'host' for command injection
[12:34:57] [WARNING] Parameter 'host' does not seem to be injectable
[12:34:58] [INFO] All tested parameters do not appear to be injectable
[12:35:00] [CRITICAL] No vulnerabilities detected
"""


# SQLMapTool Tests

@pytest.mark.asyncio
async def test_sqlmap_not_installed():
    """Test that SQLMapTool returns NOT_INSTALLED when binary is missing."""
    tool = SQLMapTool()

    with patch("scanner.tools.base.shutil.which", return_value=None):
        result = await tool.run("http://example.com?id=1")

        assert result.status == ToolStatus.NOT_INSTALLED
        assert "not installed" in result.error
        assert "sqlmap" in result.error.lower()


@pytest.mark.asyncio
async def test_sqlmap_vulnerable_target():
    """Test that SQLMapTool correctly detects SQL injection."""
    tool = SQLMapTool()

    with patch("scanner.tools.base.shutil.which", return_value="/usr/bin/sqlmap"):
        with patch("scanner.tools.base.asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(
                return_value=(SQLMAP_VULNERABLE_OUTPUT.encode(), b"")
            )
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            result = await tool.run("http://example.com?id=1")

            assert result.status == ToolStatus.SUCCESS
            assert result.data["vulnerable"] is True
            assert "injection_points" in result.data
            assert len(result.data["injection_points"]) > 0

            # Verify injection point details
            injection = result.data["injection_points"][0]
            assert injection["parameter"] == "id"
            assert "boolean-based blind" in injection["type"].lower()

            # Verify DBMS detection
            assert result.data["dbms"] == "MySQL"


@pytest.mark.asyncio
async def test_sqlmap_clean_target():
    """Test that SQLMapTool returns no vulnerabilities for clean target."""
    tool = SQLMapTool()

    with patch("scanner.tools.base.shutil.which", return_value="/usr/bin/sqlmap"):
        with patch("scanner.tools.base.asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(
                return_value=(SQLMAP_CLEAN_OUTPUT.encode(), b"")
            )
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            result = await tool.run("http://example.com?id=1")

            assert result.status == ToolStatus.SUCCESS
            assert result.data["vulnerable"] is False
            assert len(result.data["injection_points"]) == 0


@pytest.mark.asyncio
async def test_sqlmap_with_post_data():
    """Test that SQLMapTool correctly adds --data flag for POST data."""
    tool = SQLMapTool()

    with patch("scanner.tools.base.shutil.which", return_value="/usr/bin/sqlmap"):
        with patch("scanner.tools.base.asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(
                return_value=(SQLMAP_CLEAN_OUTPUT.encode(), b"")
            )
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            result = await tool.run(
                "http://example.com/login",
                data="username=admin&password=test"
            )

            assert result.status == ToolStatus.SUCCESS

            # Verify --data was added to command
            call_args = mock_exec.call_args[0]
            assert "--data" in call_args
            assert "username=admin&password=test" in call_args


@pytest.mark.asyncio
async def test_sqlmap_command_construction():
    """Test that SQLMapTool builds command correctly without shell=True."""
    tool = SQLMapTool()

    with patch("scanner.tools.base.shutil.which", return_value="/usr/bin/sqlmap"):
        with patch("scanner.tools.base.asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(
                return_value=(SQLMAP_CLEAN_OUTPUT.encode(), b"")
            )
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            await tool.run("http://example.com?id=1", level=2, risk=2)

            # Verify command structure
            call_args = mock_exec.call_args[0]
            assert call_args[0] == "sqlmap"
            assert "-u" in call_args
            assert "http://example.com?id=1" in call_args
            assert "--batch" in call_args
            assert "--level" in call_args
            assert "2" in call_args


@pytest.mark.asyncio
async def test_sqlmap_timeout():
    """Test that SQLMapTool handles timeout correctly."""
    tool = SQLMapTool(timeout=1)

    with patch("scanner.tools.base.shutil.which", return_value="/usr/bin/sqlmap"):
        with patch("scanner.tools.base.asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.pid = 12345

            # Simulate timeout
            async def communicate_timeout():
                await asyncio.sleep(10)

            mock_process.communicate = communicate_timeout
            mock_process.kill = AsyncMock()
            mock_exec.return_value = mock_process

            result = await tool.run("http://example.com?id=1")

            # Should return ERROR status on timeout
            assert result.status in [ToolStatus.ERROR, ToolStatus.TIMEOUT]


# XSSTool Tests

@pytest.mark.asyncio
async def test_xss_not_installed():
    """Test that XSSTool returns NOT_INSTALLED when binary is missing."""
    tool = XSSTool()

    with patch("scanner.tools.base.shutil.which", return_value=None):
        result = await tool.run("http://example.com/search?q=test")

        assert result.status == ToolStatus.NOT_INSTALLED
        assert "not installed" in result.error
        assert "xsser" in result.error.lower()


@pytest.mark.asyncio
async def test_xss_vulnerable():
    """Test that XSSTool correctly detects XSS vulnerabilities."""
    tool = XSSTool()

    with patch("scanner.tools.base.shutil.which", return_value="/usr/bin/xsser"):
        with patch("scanner.tools.base.asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(
                return_value=(XSSER_VULNERABLE_OUTPUT.encode(), b"")
            )
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            result = await tool.run("http://example.com/search?q=test")

            assert result.status == ToolStatus.SUCCESS
            assert result.data["vulnerable"] is True
            assert "xss_vectors" in result.data
            assert len(result.data["xss_vectors"]) > 0

            # Verify XSS vector details
            vector = result.data["xss_vectors"][0]
            assert "url" in vector
            assert "parameter" in vector
            assert "payload" in vector
            assert "type" in vector


@pytest.mark.asyncio
async def test_xss_clean():
    """Test that XSSTool returns no vulnerabilities for clean target."""
    tool = XSSTool()

    with patch("scanner.tools.base.shutil.which", return_value="/usr/bin/xsser"):
        with patch("scanner.tools.base.asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(
                return_value=(XSSER_CLEAN_OUTPUT.encode(), b"")
            )
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            result = await tool.run("http://example.com/search?q=test")

            assert result.status == ToolStatus.SUCCESS
            assert result.data["vulnerable"] is False
            assert len(result.data["xss_vectors"]) == 0


@pytest.mark.asyncio
async def test_xss_auto_mode():
    """Test that XSSTool correctly adds --auto flag."""
    tool = XSSTool()

    with patch("scanner.tools.base.shutil.which", return_value="/usr/bin/xsser"):
        with patch("scanner.tools.base.asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(
                return_value=(XSSER_CLEAN_OUTPUT.encode(), b"")
            )
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            result = await tool.run("http://example.com", auto=True)

            assert result.status == ToolStatus.SUCCESS

            # Verify --auto was added to command
            call_args = mock_exec.call_args[0]
            assert "--auto" in call_args


# CommixTool Tests

@pytest.mark.asyncio
async def test_commix_not_installed():
    """Test that CommixTool returns NOT_INSTALLED when binary is missing."""
    tool = CommixTool()

    with patch("scanner.tools.base.shutil.which", return_value=None):
        result = await tool.run("http://example.com/ping?host=test")

        assert result.status == ToolStatus.NOT_INSTALLED
        assert "not installed" in result.error
        assert "commix" in result.error.lower()


@pytest.mark.asyncio
async def test_commix_vulnerable():
    """Test that CommixTool correctly detects command injection."""
    tool = CommixTool()

    with patch("scanner.tools.base.shutil.which", return_value="/usr/bin/commix"):
        with patch("scanner.tools.base.asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(
                return_value=(COMMIX_VULNERABLE_OUTPUT.encode(), b"")
            )
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            result = await tool.run("http://example.com/ping?host=test")

            assert result.status == ToolStatus.SUCCESS
            assert result.data["vulnerable"] is True
            assert "injection_points" in result.data
            assert len(result.data["injection_points"]) > 0

            # Verify injection point details
            injection = result.data["injection_points"][0]
            assert injection["parameter"] == "host"
            assert "command injection" in injection["technique"].lower()

            # Verify OS detection
            assert result.data["os_detected"] == "Linux"


@pytest.mark.asyncio
async def test_commix_clean():
    """Test that CommixTool returns no vulnerabilities for clean target."""
    tool = CommixTool()

    with patch("scanner.tools.base.shutil.which", return_value="/usr/bin/commix"):
        with patch("scanner.tools.base.asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(
                return_value=(COMMIX_CLEAN_OUTPUT.encode(), b"")
            )
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            result = await tool.run("http://example.com/ping?host=test")

            assert result.status == ToolStatus.SUCCESS
            assert result.data["vulnerable"] is False
            assert len(result.data["injection_points"]) == 0


@pytest.mark.asyncio
async def test_commix_with_post_data():
    """Test that CommixTool correctly adds --data flag for POST data."""
    tool = CommixTool()

    with patch("scanner.tools.base.shutil.which", return_value="/usr/bin/commix"):
        with patch("scanner.tools.base.asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(
                return_value=(COMMIX_CLEAN_OUTPUT.encode(), b"")
            )
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            result = await tool.run(
                "http://example.com/ping",
                data="host=127.0.0.1"
            )

            assert result.status == ToolStatus.SUCCESS

            # Verify --data was added to command
            call_args = mock_exec.call_args[0]
            assert "--data" in call_args
            assert "host=127.0.0.1" in call_args
