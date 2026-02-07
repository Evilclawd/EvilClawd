"""Security headers checker tool (pure Python, no binary).

Checks HTTP security headers and identifies misconfigurations that could
lead to vulnerabilities. Detects missing security headers, CORS issues,
and information disclosure headers.

Provides:
- SecurityHeadersTool: Pure Python HTTP header analysis tool
"""

import aiohttp

from scanner.tools.base import Tool, ToolResult, ToolStatus


class SecurityHeadersTool(Tool):
    """Security headers checker (VULN-03).

    Pure Python tool that analyzes HTTP response headers to identify
    missing or misconfigured security headers. No external binary required.

    Checks for:
    - Missing security headers (HSTS, CSP, X-Frame-Options, etc.)
    - CORS misconfigurations (wildcard origins, overly permissive)
    - Information disclosure headers (Server, X-Powered-By)

    Always available since it's pure Python.
    """

    def __init__(self):
        """Initialize the security headers tool."""
        super().__init__(
            name="security_headers",
            binary_name=None,  # Pure Python, no binary
            version_flag=None,
        )

    async def is_available(self) -> bool:
        """Check if tool is available.

        Always returns True since this is pure Python.

        Returns:
            True (always available)
        """
        return True

    def _header_severity(self, header: str) -> str:
        """Map security header to severity level.

        Args:
            header: Header name (e.g., "Strict-Transport-Security")

        Returns:
            Severity level: "info" | "low" | "medium" | "high" | "critical"
        """
        severity_map = {
            "Strict-Transport-Security": "medium",
            "X-Frame-Options": "low",
            "X-Content-Type-Options": "low",
            "Content-Security-Policy": "medium",
            "X-XSS-Protection": "info",
            "Referrer-Policy": "low",
            "Permissions-Policy": "low",
        }
        return severity_map.get(header, "low")

    async def run(self, target: str, **kwargs) -> ToolResult:
        """Check security headers for the target URL.

        Makes an HTTP GET request to the target and analyzes response headers
        for security issues.

        Args:
            target: Target URL (must include scheme, e.g., https://example.com)
            **kwargs: Additional parameters (timeout override, etc.)

        Returns:
            ToolResult with:
            - data.missing_headers: List of missing security headers with severity
            - data.present_headers: Dict of headers that are present
            - data.cors_issues: List of CORS misconfigurations
            - data.info_disclosure: List of information disclosure headers
            - data.score: 0-100 percentage of security headers present
            - data.url: The checked URL
            - raw_output: String representation of response headers

        Example:
            >>> tool = SecurityHeadersTool()
            >>> result = await tool.run("https://example.com")
            >>> print(result.data["score"])
            42
        """
        timeout_seconds = kwargs.get("timeout", 10)
        timeout = aiohttp.ClientTimeout(total=timeout_seconds)

        # Define required security headers
        required_headers = {
            "Strict-Transport-Security": "Prevents HTTPS downgrade attacks",
            "X-Frame-Options": "Prevents clickjacking attacks",
            "X-Content-Type-Options": "Prevents MIME sniffing attacks",
            "Content-Security-Policy": "Prevents XSS and injection attacks",
            "X-XSS-Protection": "Legacy XSS protection (still recommended)",
            "Referrer-Policy": "Controls referrer information leakage",
            "Permissions-Policy": "Controls browser feature access",
        }

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(target, allow_redirects=True) as response:
                    headers = dict(response.headers)

                    # Analyze missing security headers
                    missing_headers = []
                    present_headers = {}
                    present_count = 0

                    for header, purpose in required_headers.items():
                        # Case-insensitive header check
                        header_lower = header.lower()
                        header_present = any(
                            h.lower() == header_lower for h in headers.keys()
                        )

                        if header_present:
                            present_count += 1
                            # Get actual header value with original casing
                            actual_header = next(
                                (h for h in headers.keys() if h.lower() == header_lower),
                                header,
                            )
                            present_headers[header] = headers[actual_header]
                        else:
                            missing_headers.append({
                                "header": header,
                                "purpose": purpose,
                                "severity": self._header_severity(header),
                            })

                    # Calculate security score
                    score = int((present_count / len(required_headers)) * 100)

                    # Check for CORS misconfigurations
                    cors_issues = []
                    acao_header = next(
                        (h for h in headers.keys()
                         if h.lower() == "access-control-allow-origin"),
                        None,
                    )
                    if acao_header:
                        acao_value = headers[acao_header]
                        if acao_value == "*":
                            cors_issues.append({
                                "issue": "Wildcard CORS origin",
                                "header": "Access-Control-Allow-Origin",
                                "value": acao_value,
                                "severity": "medium",
                                "description": "Allows any origin to access resources",
                            })

                    acac_header = next(
                        (h for h in headers.keys()
                         if h.lower() == "access-control-allow-credentials"),
                        None,
                    )
                    if acac_header and acao_header:
                        acac_value = headers[acac_header]
                        acao_value = headers[acao_header]
                        if acac_value.lower() == "true" and acao_value == "*":
                            cors_issues.append({
                                "issue": "Dangerous CORS configuration",
                                "header": "Access-Control-Allow-Credentials + ACAO",
                                "value": f"Credentials: {acac_value}, Origin: {acao_value}",
                                "severity": "high",
                                "description": "Credentials with wildcard origin",
                            })

                    # Check for information disclosure headers
                    info_disclosure = []
                    server_header = next(
                        (h for h in headers.keys() if h.lower() == "server"),
                        None,
                    )
                    if server_header:
                        server_value = headers[server_header]
                        # Check if version info is disclosed
                        if any(char.isdigit() for char in server_value):
                            info_disclosure.append({
                                "header": "Server",
                                "value": server_value,
                                "severity": "info",
                                "description": "Server version information disclosed",
                            })

                    xpb_header = next(
                        (h for h in headers.keys() if h.lower() == "x-powered-by"),
                        None,
                    )
                    if xpb_header:
                        xpb_value = headers[xpb_header]
                        info_disclosure.append({
                            "header": "X-Powered-By",
                            "value": xpb_value,
                            "severity": "info",
                            "description": "Technology stack information disclosed",
                        })

                    return ToolResult(
                        status=ToolStatus.SUCCESS,
                        data={
                            "missing_headers": missing_headers,
                            "present_headers": present_headers,
                            "cors_issues": cors_issues,
                            "info_disclosure": info_disclosure,
                            "score": score,
                            "url": target,
                        },
                        raw_output=str(dict(response.headers)),
                    )

        except aiohttp.ClientError as e:
            return ToolResult(
                status=ToolStatus.ERROR,
                data={"error": f"Connection error: {e}", "url": target},
                raw_output=str(e),
            )
        except Exception as e:
            return ToolResult(
                status=ToolStatus.ERROR,
                data={"error": f"Unexpected error: {e}", "url": target},
                raw_output=str(e),
            )
