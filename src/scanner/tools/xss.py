"""XSS tool wrapper for cross-site scripting detection (VULN-01).

Wraps the XSSer binary to detect XSS vulnerabilities in web applications.
Parses text output and returns structured XSS vector data.
"""

import re
import time
import structlog
from .base import ToolResult, ToolStatus, check_binary, run_with_retry

logger = structlog.get_logger()


class XSSTool:
    """Wrapper for XSSer cross-site scripting detection tool.

    Runs XSSer with auto mode and parses discovered XSS vectors.
    Handles missing binary gracefully with install instructions.
    """

    name = "xss_scanner"
    binary_name = "xsser"

    def __init__(self, timeout: int = 300):
        """Initialize XSSer tool wrapper.

        Args:
            timeout: Timeout in seconds for XSSer execution (default: 300)
        """
        self.timeout = timeout
        self.log = logger.bind(tool=self.name)

    def is_available(self) -> bool:
        """Check if xsser binary is available on PATH.

        Returns:
            True if xsser is installed, False otherwise
        """
        return check_binary(self.binary_name)

    async def run(self, target: str, **kwargs) -> ToolResult:
        """Scan target for XSS vulnerabilities.

        Runs: xsser --url <target> [options]

        Args:
            target: URL to test (e.g., "http://example.com/search?q=test")
            **kwargs:
                auto: bool - enable automatic crawling and testing (default: False)
                crawl: int - crawl depth for auto mode
                payload: str - custom XSS payload to test

        Returns:
            ToolResult with data:
                vulnerable: bool - whether XSS was found
                target: str - target URL tested
                xss_vectors: list[dict] - each dict has:
                    url: str - vulnerable URL
                    parameter: str - vulnerable parameter name
                    payload: str - successful XSS payload
                    type: str - XSS type (reflected/stored/dom)

        Example:
            >>> tool = XSSTool()
            >>> result = await tool.run("http://example.com/search", auto=True)
            >>> if result.data.get("vulnerable"):
            ...     print(f"Found {len(result.data['xss_vectors'])} XSS vectors")
        """
        start_time = time.time()
        self.log.info("xss_start", target=target, kwargs=kwargs)

        # Check if binary is available
        if not self.is_available():
            error_msg = (
                f"{self.binary_name} not installed. "
                "Install: pip install xsser or apt-get install xsser (Linux)"
            )
            self.log.warning("binary_not_found", binary=self.binary_name)
            return ToolResult(
                status=ToolStatus.NOT_INSTALLED,
                error=error_msg,
                duration_seconds=time.time() - start_time
            )

        # Build command
        cmd = [self.binary_name, "--url", target]

        # Add auto mode if requested
        if kwargs.get("auto", False):
            cmd.append("--auto")

        # Add crawl depth if provided
        if "crawl" in kwargs and kwargs["crawl"]:
            cmd.extend(["-c", str(kwargs["crawl"])])

        # Add custom payload if provided
        if "payload" in kwargs and kwargs["payload"]:
            cmd.extend(["--Fp", kwargs["payload"]])

        try:
            # Execute with retry for transient failures
            stdout, stderr, returncode = await run_with_retry(
                cmd,
                timeout=self.timeout
            )

            # Parse output for XSS vectors
            xss_vectors = self._parse_xss_output(stdout)
            vulnerable = len(xss_vectors) > 0

            duration = time.time() - start_time
            self.log.info(
                "xss_complete",
                target=target,
                vulnerable=vulnerable,
                xss_vectors=len(xss_vectors),
                duration=duration
            )

            return ToolResult(
                status=ToolStatus.SUCCESS,
                data={
                    "vulnerable": vulnerable,
                    "target": target,
                    "xss_vectors": xss_vectors
                },
                raw_output=stdout,
                duration_seconds=duration
            )

        except Exception as e:
            error_msg = f"xsser execution error: {str(e)}"
            self.log.error("xss_exception", error=str(e))
            return ToolResult(
                status=ToolStatus.ERROR,
                error=error_msg,
                duration_seconds=time.time() - start_time
            )

    def _parse_xss_output(self, stdout: str) -> list[dict]:
        """Parse XSSer output for successful XSS vectors.

        Looks for patterns like:
        - "XSS FOUND!"
        - "Vulnerable URL: http://..."
        - "Payload: <script>alert(1)</script>"
        - "Type: Reflected"

        Args:
            stdout: Raw XSSer output text

        Returns:
            List of XSS vector dictionaries
        """
        xss_vectors = []

        # First check for negative indicators (no vulnerabilities found)
        if re.search(r"no\s+xss|not\s+vulnerable|successful:\s*0", stdout, re.IGNORECASE):
            return xss_vectors

        # Pattern 1: Look for positive XSS indicators
        # Must have "FOUND", "DETECTED", or "Successful: [1-9]" to be a real vulnerability
        has_positive_indicator = (
            re.search(r"XSS.*(?:FOUND|DETECTED)", stdout, re.IGNORECASE) or
            re.search(r"successful:\s*[1-9]", stdout, re.IGNORECASE)
        )

        if not has_positive_indicator:
            return xss_vectors

        # Pattern 2: Try to extract structured XSS information
        # XSSer output can be quite varied, so we look for common patterns

        # Look for URL patterns with potential XSS indicators
        url_pattern = r"(?:URL|Target|Vulnerable):\s*([^\s\n]+)"
        param_pattern = r"(?:Parameter|Param|Vector):\s*([^\s\n]+)"
        payload_pattern = r"(?:Payload|Inject|Code):\s*([^\n]+)"

        lines = stdout.split("\n")
        current_vector = {}

        for i, line in enumerate(lines):
            # Check for XSS indicator
            if re.search(r"XSS.*(?:FOUND|DETECTED)", line, re.IGNORECASE):
                # Start collecting info for this vector
                current_vector = {
                    "url": "",
                    "parameter": "",
                    "payload": "",
                    "type": "reflected"  # Default type
                }

                # Look ahead for details
                for j in range(i, min(i + 10, len(lines))):
                    url_match = re.search(url_pattern, lines[j], re.IGNORECASE)
                    if url_match:
                        current_vector["url"] = url_match.group(1)

                    param_match = re.search(param_pattern, lines[j], re.IGNORECASE)
                    if param_match:
                        current_vector["parameter"] = param_match.group(1)

                    payload_match = re.search(payload_pattern, lines[j], re.IGNORECASE)
                    if payload_match:
                        current_vector["payload"] = payload_match.group(1).strip()

                    # Detect XSS type
                    if re.search(r"stored", lines[j], re.IGNORECASE):
                        current_vector["type"] = "stored"
                    elif re.search(r"dom", lines[j], re.IGNORECASE):
                        current_vector["type"] = "dom"

                if current_vector.get("url"):
                    xss_vectors.append(current_vector)
                    current_vector = {}

        # If we found XSS indicators but couldn't parse structured data,
        # create a generic entry
        if not xss_vectors and has_positive_indicator:
            # Try to extract any URLs mentioned
            urls = re.findall(r'https?://[^\s<>"]+', stdout)
            if urls:
                for url in urls[:3]:  # Limit to first 3 URLs
                    xss_vectors.append({
                        "url": url,
                        "parameter": "unknown",
                        "payload": "detected",
                        "type": "reflected"
                    })
            else:
                # Absolute fallback - we know XSS was found but have no details
                xss_vectors.append({
                    "url": "see raw output",
                    "parameter": "detected",
                    "payload": "see raw output",
                    "type": "reflected"
                })

        return xss_vectors
