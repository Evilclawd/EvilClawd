"""Subfinder tool wrapper for subdomain enumeration (RECON-01).

Wraps the subfinder binary to discover subdomains for a target domain.
Parses JSON output and returns structured results.
"""

import json
import time
import structlog
from .base import Tool, ToolResult, ToolStatus, check_binary, run_with_retry

logger = structlog.get_logger()


class SubfinderTool:
    """Wrapper for subfinder subdomain enumeration tool.

    Runs subfinder with JSON output and parses discovered subdomains.
    Handles missing binary gracefully with install instructions.
    """

    name = "subfinder"
    binary_name = "subfinder"

    def __init__(self, timeout: int = 300):
        """Initialize subfinder tool wrapper.

        Args:
            timeout: Timeout in seconds for subfinder execution (default: 300)
        """
        self.timeout = timeout
        self.log = logger.bind(tool=self.name)

    def is_available(self) -> bool:
        """Check if subfinder binary is available on PATH.

        Returns:
            True if subfinder is installed, False otherwise
        """
        return check_binary(self.binary_name)

    async def run(self, target: str, **kwargs) -> ToolResult:
        """Enumerate subdomains for target domain.

        Runs: subfinder -d <target> -json -silent
        Parses JSON lines output, each line: {"host": "sub.example.com", ...}

        Args:
            target: Domain to enumerate (e.g., "example.com")
            **kwargs: Additional arguments (currently unused)

        Returns:
            ToolResult with data:
                subdomains: list[str]  - deduplicated list of discovered subdomains
                count: int             - number of unique subdomains found

        Example:
            >>> tool = SubfinderTool()
            >>> result = await tool.run("example.com")
            >>> print(result.data["subdomains"])
            ['example.com', 'www.example.com', 'api.example.com']
        """
        start_time = time.time()
        self.log.info("subfinder_start", target=target)

        # Check if binary is available
        if not self.is_available():
            error_msg = (
                f"{self.binary_name} not installed. "
                "Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
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
            "-d", target,
            "-json",
            "-silent"
        ]

        try:
            # Execute with retry for transient failures
            stdout, stderr, returncode = await run_with_retry(
                cmd,
                timeout=self.timeout
            )

            if returncode != 0:
                error_msg = f"subfinder failed with code {returncode}: {stderr}"
                self.log.error("subfinder_failed", returncode=returncode, stderr=stderr)
                return ToolResult(
                    status=ToolStatus.ERROR,
                    error=error_msg,
                    raw_output=stdout,
                    duration_seconds=time.time() - start_time
                )

            # Parse JSON lines output
            subdomains = set()

            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue

                try:
                    data = json.loads(line)
                    if "host" in data:
                        subdomains.add(data["host"])
                except json.JSONDecodeError:
                    # Skip malformed lines
                    self.log.warning("json_parse_error", line=line[:100])
                    continue

            # Ensure base domain is included
            if target not in subdomains:
                subdomains.add(target)

            # Convert to sorted list for consistent output
            subdomain_list = sorted(subdomains)

            duration = time.time() - start_time
            self.log.info(
                "subfinder_complete",
                target=target,
                count=len(subdomain_list),
                duration=duration
            )

            return ToolResult(
                status=ToolStatus.SUCCESS,
                data={
                    "subdomains": subdomain_list,
                    "count": len(subdomain_list)
                },
                raw_output=stdout,
                duration_seconds=duration
            )

        except Exception as e:
            error_msg = f"subfinder execution error: {str(e)}"
            self.log.error("subfinder_exception", error=str(e))
            return ToolResult(
                status=ToolStatus.ERROR,
                error=error_msg,
                duration_seconds=time.time() - start_time
            )
