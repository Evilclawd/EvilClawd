"""Commix tool wrapper for command injection detection (VULN-01).

Wraps the commix binary to detect command injection vulnerabilities in web applications.
Parses text output and returns structured injection point data.
"""

import re
import time
import structlog
from .base import ToolResult, ToolStatus, check_binary, run_with_retry

logger = structlog.get_logger()


class CommixTool:
    """Wrapper for commix command injection detection tool.

    Runs commix in batch mode and parses discovered injection points.
    Handles missing binary gracefully with install instructions.
    """

    name = "commix"
    binary_name = "commix"

    def __init__(self, timeout: int = 300):
        """Initialize commix tool wrapper.

        Args:
            timeout: Timeout in seconds for commix execution (default: 300)
        """
        self.timeout = timeout
        self.log = logger.bind(tool=self.name)

    def is_available(self) -> bool:
        """Check if commix binary is available on PATH.

        Returns:
            True if commix is installed, False otherwise
        """
        return check_binary(self.binary_name)

    async def run(self, target: str, **kwargs) -> ToolResult:
        """Scan target for command injection vulnerabilities.

        Runs: commix --url <target> --batch [options]

        Args:
            target: URL to test (e.g., "http://example.com/ping?host=127.0.0.1")
            **kwargs:
                data: str - POST data for testing (passed as --data)
                level: int - depth of tests 1-3 (default: 1)
                technique: str - injection techniques to use

        Returns:
            ToolResult with data:
                vulnerable: bool - whether command injection was found
                target: str - target URL tested
                injection_points: list[dict] - each dict has:
                    parameter: str - vulnerable parameter name
                    technique: str - injection technique used
                os_detected: str|None - detected operating system

        Example:
            >>> tool = CommixTool()
            >>> result = await tool.run("http://example.com/ping?host=test")
            >>> if result.data.get("vulnerable"):
            ...     print(f"Found {len(result.data['injection_points'])} injection points")
        """
        start_time = time.time()
        self.log.info("commix_start", target=target, kwargs=kwargs)

        # Check if binary is available
        if not self.is_available():
            error_msg = (
                f"{self.binary_name} not installed. "
                "Install: pip install commix or git clone https://github.com/commixproject/commix"
            )
            self.log.warning("binary_not_found", binary=self.binary_name)
            return ToolResult(
                status=ToolStatus.NOT_INSTALLED,
                error=error_msg,
                duration_seconds=time.time() - start_time
            )

        # Build command
        cmd = [
            self.binary_name,
            "--url", target,
            "--batch"
        ]

        # Add POST data if provided
        if "data" in kwargs and kwargs["data"]:
            cmd.extend(["--data", kwargs["data"]])

        # Add level if provided
        if "level" in kwargs and kwargs["level"]:
            cmd.extend(["--level", str(kwargs["level"])])

        # Add technique if provided
        if "technique" in kwargs and kwargs["technique"]:
            cmd.extend(["--technique", kwargs["technique"]])

        try:
            # Execute with retry for transient failures
            stdout, stderr, returncode = await run_with_retry(
                cmd,
                timeout=self.timeout
            )

            # Parse output for injection points
            injection_points = self._parse_injection_points(stdout)
            os_detected = self._parse_os(stdout)
            vulnerable = len(injection_points) > 0

            duration = time.time() - start_time
            self.log.info(
                "commix_complete",
                target=target,
                vulnerable=vulnerable,
                injection_points=len(injection_points),
                os_detected=os_detected,
                duration=duration
            )

            return ToolResult(
                status=ToolStatus.SUCCESS,
                data={
                    "vulnerable": vulnerable,
                    "target": target,
                    "injection_points": injection_points,
                    "os_detected": os_detected
                },
                raw_output=stdout,
                duration_seconds=duration
            )

        except Exception as e:
            error_msg = f"commix execution error: {str(e)}"
            self.log.error("commix_exception", error=str(e))
            return ToolResult(
                status=ToolStatus.ERROR,
                error=error_msg,
                duration_seconds=time.time() - start_time
            )

    def _parse_injection_points(self, stdout: str) -> list[dict]:
        """Parse commix output for command injection points.

        Looks for patterns like:
        - "Parameter: host (GET)"
        - "is vulnerable"
        - "Technique: classic command injection"

        Args:
            stdout: Raw commix output text

        Returns:
            List of injection point dictionaries
        """
        injection_points = []

        # Pattern 1: Look for "Parameter: <name> is vulnerable"
        param_pattern = r"Parameter:\s+([^\s(]+)\s+\(([^)]+)\)"
        vulnerable_pattern = r"is vulnerable"
        technique_pattern = r"Technique:\s+(.+?)(?:\n|$)"

        lines = stdout.split("\n")
        i = 0
        while i < len(lines):
            line = lines[i]

            # Check for parameter declaration
            param_match = re.search(param_pattern, line)
            if param_match:
                parameter = param_match.group(1)

                # Check if vulnerable (look ahead a few lines)
                vulnerable = False
                technique = None

                for j in range(i, min(i + 10, len(lines))):
                    if re.search(vulnerable_pattern, lines[j], re.IGNORECASE):
                        vulnerable = True

                    tech_match = re.search(technique_pattern, lines[j])
                    if tech_match:
                        technique = tech_match.group(1).strip()

                if vulnerable:
                    injection_points.append({
                        "parameter": parameter,
                        "technique": technique or "command injection"
                    })

            i += 1

        # Alternative: look for generic vulnerability indicators
        if not injection_points and re.search(r"vulnerable|injection.*found", stdout, re.IGNORECASE):
            # Try to extract parameter names from anywhere in output
            params = re.findall(r"parameter[:\s]+([^\s,\n]+)", stdout, re.IGNORECASE)
            if params:
                for param in params[:5]:  # Limit to first 5
                    injection_points.append({
                        "parameter": param,
                        "technique": "command injection"
                    })
            else:
                # Generic entry
                injection_points.append({
                    "parameter": "detected",
                    "technique": "command injection"
                })

        return injection_points

    def _parse_os(self, stdout: str) -> str | None:
        """Parse detected operating system from output.

        Looks for patterns like:
        - "Target operating system: Linux"
        - "OS: Windows"

        Args:
            stdout: Raw commix output text

        Returns:
            OS name if detected, None otherwise
        """
        # Pattern: "operating system: <name>" or "OS: <name>"
        os_patterns = [
            r"(?:target\s+)?operating\s+system:\s+([^\n]+)",
            r"OS:\s+([^\n]+)",
            r"identified.*?as\s+(Linux|Windows|Unix|BSD)"
        ]

        for pattern in os_patterns:
            match = re.search(pattern, stdout, re.IGNORECASE)
            if match:
                os_name = match.group(1).strip()
                # Clean up version info if present
                os_name = re.split(r'\s+[0-9]', os_name)[0]
                return os_name

        return None
