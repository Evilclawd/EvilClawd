"""SQLMap tool wrapper for SQL injection detection (VULN-01).

Wraps the sqlmap binary to detect SQL injection vulnerabilities in web applications.
Parses text output and returns structured injection point data.
"""

import re
import time
import structlog
from .base import ToolResult, ToolStatus, check_binary, run_with_retry

logger = structlog.get_logger()


class SQLMapTool:
    """Wrapper for sqlmap SQL injection detection tool.

    Runs sqlmap with batch mode and parses discovered injection points.
    Handles missing binary gracefully with install instructions.
    """

    name = "sqlmap"
    binary_name = "sqlmap"

    def __init__(self, timeout: int = 600):
        """Initialize sqlmap tool wrapper.

        Args:
            timeout: Timeout in seconds for sqlmap execution (default: 600)
        """
        self.timeout = timeout
        self.log = logger.bind(tool=self.name)

    def is_available(self) -> bool:
        """Check if sqlmap binary is available on PATH.

        Returns:
            True if sqlmap is installed, False otherwise
        """
        return check_binary(self.binary_name)

    async def run(self, target: str, **kwargs) -> ToolResult:
        """Scan target for SQL injection vulnerabilities.

        Runs: sqlmap -u <target> --batch --level <level> --risk <risk>

        Args:
            target: URL to test (e.g., "http://example.com/page?id=1")
            **kwargs:
                data: str - POST data for testing (passed as --data)
                level: int - depth of tests 1-5 (default: 1)
                risk: int - risk level 1-3 (default: 1)
                forms: bool - auto-detect and test forms (default: False)
                technique: str - injection techniques to use (BEUSTQ chars)

        Returns:
            ToolResult with data:
                vulnerable: bool - whether SQL injection was found
                target: str - target URL tested
                injection_points: list[dict] - each dict has:
                    parameter: str - vulnerable parameter name
                    type: str - injection type (e.g., "boolean-based blind")
                    technique: str - technique used (e.g., "AND boolean-based blind")
                dbms: str|None - detected database management system

        Example:
            >>> tool = SQLMapTool()
            >>> result = await tool.run("http://example.com/page?id=1", level=2)
            >>> if result.data.get("vulnerable"):
            ...     print(f"Found {len(result.data['injection_points'])} injection points")
        """
        start_time = time.time()
        self.log.info("sqlmap_start", target=target, kwargs=kwargs)

        # Check if binary is available
        if not self.is_available():
            error_msg = (
                f"{self.binary_name} not installed. "
                "Install: pip install sqlmap or brew install sqlmap (macOS)"
            )
            self.log.warning("binary_not_found", binary=self.binary_name)
            return ToolResult(
                status=ToolStatus.NOT_INSTALLED,
                error=error_msg,
                duration_seconds=time.time() - start_time
            )

        # Build command
        level = kwargs.get("level", 1)
        risk = kwargs.get("risk", 1)

        cmd = [
            self.binary_name,
            "-u", target,
            "--batch",
            "--level", str(level),
            "--risk", str(risk),
            "--output-dir", "/tmp/sqlmap-output"
        ]

        # Add POST data if provided
        if "data" in kwargs and kwargs["data"]:
            cmd.extend(["--data", kwargs["data"]])

        # Add forms flag if provided
        if kwargs.get("forms", False):
            cmd.append("--forms")

        # Add technique if provided
        if "technique" in kwargs and kwargs["technique"]:
            cmd.extend(["--technique", kwargs["technique"]])

        try:
            # Execute with retry for transient failures
            stdout, stderr, returncode = await run_with_retry(
                cmd,
                timeout=self.timeout
            )

            # SQLMap returns 0 even when vulnerabilities are found
            # Check output for vulnerability indicators
            injection_points = self._parse_injection_points(stdout)
            dbms = self._parse_dbms(stdout)
            vulnerable = len(injection_points) > 0

            duration = time.time() - start_time
            self.log.info(
                "sqlmap_complete",
                target=target,
                vulnerable=vulnerable,
                injection_points=len(injection_points),
                dbms=dbms,
                duration=duration
            )

            return ToolResult(
                status=ToolStatus.SUCCESS,
                data={
                    "vulnerable": vulnerable,
                    "target": target,
                    "injection_points": injection_points,
                    "dbms": dbms
                },
                raw_output=stdout,
                duration_seconds=duration
            )

        except Exception as e:
            error_msg = f"sqlmap execution error: {str(e)}"
            self.log.error("sqlmap_exception", error=str(e))
            return ToolResult(
                status=ToolStatus.ERROR,
                error=error_msg,
                duration_seconds=time.time() - start_time
            )

    def _parse_injection_points(self, stdout: str) -> list[dict]:
        """Parse sqlmap output for injection points.

        Looks for patterns like:
        - "Parameter: id (GET)"
        - "Type: boolean-based blind"
        - "Title: AND boolean-based blind - WHERE or HAVING clause"

        Args:
            stdout: Raw sqlmap output text

        Returns:
            List of injection point dictionaries
        """
        injection_points = []

        # Look for "Parameter: <name> (<type>)" followed by injection details
        param_pattern = r"Parameter:\s+([^\s(]+)\s+\(([^)]+)\)"
        type_pattern = r"Type:\s+(.+?)(?:\n|$)"
        title_pattern = r"Title:\s+(.+?)(?:\n|$)"

        lines = stdout.split("\n")
        i = 0
        while i < len(lines):
            line = lines[i]

            # Check if this line contains a parameter declaration
            param_match = re.search(param_pattern, line)
            if param_match:
                parameter = param_match.group(1)
                param_type = param_match.group(2)

                # Look ahead for Type and Title
                injection_type = None
                technique = None

                for j in range(i + 1, min(i + 10, len(lines))):
                    type_match = re.search(type_pattern, lines[j])
                    if type_match:
                        injection_type = type_match.group(1).strip()

                    title_match = re.search(title_pattern, lines[j])
                    if title_match:
                        technique = title_match.group(1).strip()

                    # Stop if we hit another parameter or empty line section
                    if lines[j].startswith("Parameter:") or (lines[j].strip() == "" and j > i + 3):
                        break

                if injection_type:
                    injection_points.append({
                        "parameter": parameter,
                        "type": injection_type,
                        "technique": technique or injection_type
                    })

            i += 1

        # Alternative: look for "is vulnerable" indicators
        if not injection_points and "is vulnerable" in stdout.lower():
            # Generic vulnerability found - parse what we can
            vulnerable_match = re.search(r"([^\s]+)\s+.*?is vulnerable", stdout, re.IGNORECASE)
            if vulnerable_match:
                injection_points.append({
                    "parameter": vulnerable_match.group(1),
                    "type": "SQL injection",
                    "technique": "detected"
                })

        return injection_points

    def _parse_dbms(self, stdout: str) -> str | None:
        """Parse detected database management system from output.

        Looks for patterns like:
        - "back-end DBMS: MySQL"
        - "the back-end DBMS is PostgreSQL"

        Args:
            stdout: Raw sqlmap output text

        Returns:
            DBMS name if detected, None otherwise
        """
        # Pattern: "back-end DBMS: <name>"
        match = re.search(r"back-end DBMS:\s+([^\n]+)", stdout, re.IGNORECASE)
        if match:
            dbms = match.group(1).strip()
            # Clean up version info if present (e.g., "MySQL >= 5.0" -> "MySQL")
            dbms = re.split(r'\s+[><=]', dbms)[0]
            return dbms

        return None
