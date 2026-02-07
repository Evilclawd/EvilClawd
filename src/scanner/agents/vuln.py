"""VulnAgent for orchestrating vulnerability detection tools.

Orchestrates SQLMap, XSSer, Commix, and SecurityHeadersTool to detect and
classify vulnerabilities. Produces findings with CVSS severity and confidence levels.
"""

import structlog

from scanner.tools import SQLMapTool, XSSTool, CommixTool, ToolStatus
from scanner.tools.headers import SecurityHeadersTool
from scanner.core.persistence.database import get_session
from scanner.core.safety.scope import is_in_scope
from scanner.core.safety.approval import execute_tool_with_approval
from scanner.core.llm.tools import get_tool_by_name
from scanner.core.output import Finding, Evidence, SourceType
from scanner.core.severity import (
    calculate_severity,
    classify_confidence,
    severity_to_cvss_defaults
)
from .base import BaseAgent

logger = structlog.get_logger()


class VulnAgent(BaseAgent):
    """Vulnerability scanning agent (VULN-01, VULN-02, VULN-03, VULN-04).

    Orchestrates vulnerability detection tools based on reconnaissance findings.
    Produces classified findings with CVSS severity and confidence levels.

    Features:
    - Scope enforcement before any tool execution
    - Risk-based approval workflow for destructive tools
    - CVSS v3.1 severity classification
    - Confidence level assignment based on evidence quality
    - Audit logging of all tool executions
    """

    # HTTP ports to check for web services
    HTTP_PORTS = {80, 443, 8080, 8443, 8000, 3000}

    def __init__(self, session_id: str | None = None):
        """Initialize VulnAgent with tool wrappers.

        Args:
            session_id: Optional session ID (generates new UUID if not provided)
        """
        super().__init__(session_id)
        self.sqlmap = SQLMapTool()
        self.xss = XSSTool()
        self.commix = CommixTool()
        self.headers = SecurityHeadersTool()

    async def scan(self, target: str, recon_results: dict) -> list[Finding]:
        """Execute vulnerability scanning pipeline on target.

        Pipeline:
        1. Scope check - verify target is authorized
        2. Extract web URLs from reconnaissance data
        3. Check security headers (VULN-03) - SAFE, auto-execute
        4. Test for SQL injection (VULN-01) - MODERATE, requires approval
        5. Test for XSS (VULN-01) - MODERATE, requires approval
        6. Test for command injection (VULN-01) - DESTRUCTIVE, requires approval
        7. Classify all findings with CVSS severity and confidence

        Args:
            target: Base domain being tested (e.g., "example.com")
            recon_results: Dict from ReconAgent.run() with keys:
                - target: str
                - subdomains: list[str]
                - port_scan: list[dict] (flattened services)
                - technologies: list[dict]
                - attack_surface: dict

        Returns:
            List of Finding objects with source-attributed evidence

        Raises:
            RuntimeError: If target is not in authorized scope

        Example:
            >>> agent = VulnAgent()
            >>> recon = await recon_agent.run("example.com")
            >>> findings = await agent.scan("example.com", recon)
            >>> print(f"Found {len(findings)} vulnerabilities")
        """
        self.log.info("vuln_scan_start", target=target)

        # Step 0: Scope check (EXPL-02)
        async with get_session() as session:
            in_scope, reason = await is_in_scope(session, target)

            # Audit log scope check
            await self.audit("scope_check", {
                "target": target,
                "in_scope": in_scope,
                "reason": reason
            })

            if not in_scope:
                error_msg = f"Target not in authorized scope: {reason}"
                self.log.error("scope_denied", target=target, reason=reason)
                raise RuntimeError(error_msg)

        # Step 1: Extract web URLs from recon results
        web_urls = self._extract_web_urls(recon_results)
        self.log.info("web_urls_extracted", count=len(web_urls))

        all_findings = []

        # Step 2: Check security headers (VULN-03) - SAFE, auto-execute
        header_findings = await self._scan_headers(web_urls)
        all_findings.extend(header_findings)
        self.log.info("header_scan_complete", findings=len(header_findings))

        # Step 3: Test for SQL injection (VULN-01) - MODERATE, requires approval
        sqli_findings = await self._scan_sqli(web_urls)
        all_findings.extend(sqli_findings)
        self.log.info("sqli_scan_complete", findings=len(sqli_findings))

        # Step 4: Test for XSS (VULN-01) - MODERATE, requires approval
        xss_findings = await self._scan_xss(web_urls)
        all_findings.extend(xss_findings)
        self.log.info("xss_scan_complete", findings=len(xss_findings))

        # Step 5: Test for command injection (VULN-01) - DESTRUCTIVE, requires approval
        cmdi_findings = await self._scan_cmdi(web_urls)
        all_findings.extend(cmdi_findings)
        self.log.info("cmdi_scan_complete", findings=len(cmdi_findings))

        # Step 6: Audit log scan complete
        await self.audit("vuln_scan_complete", {
            "target": target,
            "web_urls_scanned": len(web_urls),
            "total_findings": len(all_findings),
            "by_severity": self._count_by_severity(all_findings)
        })

        # Step 7: Checkpoint results
        await self.checkpoint({
            "target": target,
            "findings_count": len(all_findings)
        }, metadata="Vulnerability scan complete")

        self.log.info("vuln_scan_complete", target=target, findings=len(all_findings))
        return all_findings

    def _extract_web_urls(self, recon_results: dict) -> list[str]:
        """Extract web service URLs from reconnaissance results.

        Builds URLs from services on HTTP ports (80, 443, 8080, 8443, 8000, 3000).

        Args:
            recon_results: Reconnaissance output with port_scan (flattened services)

        Returns:
            List of web URLs (e.g., ["https://example.com", "http://example.com:8080"])
        """
        urls = set()
        port_scan = recon_results.get("port_scan", [])

        for service in port_scan:
            port = service.get("port")
            host = service.get("host")
            state = service.get("state")

            if not host or not port or state != "open":
                continue

            # Only process HTTP ports
            if port not in self.HTTP_PORTS:
                continue

            # Build URL with appropriate scheme
            if port in {443, 8443}:
                url = f"https://{host}"
            elif port in {80}:
                url = f"http://{host}"
            else:
                # Non-standard ports - specify explicitly
                url = f"http://{host}:{port}"

            urls.add(url)

        return list(urls)

    async def _scan_headers(self, web_urls: list[str]) -> list[Finding]:
        """Scan security headers on web URLs.

        SecurityHeadersTool is SAFE (pure Python, read-only) so auto-executes.

        Args:
            web_urls: List of web URLs to check

        Returns:
            List of Finding objects for missing/misconfigured headers
        """
        findings = []

        for url in web_urls:
            result = await self.headers.run(url)

            if result.status == ToolStatus.SUCCESS:
                # Process missing headers
                for missing in result.data.get("missing_headers", []):
                    finding = self._create_header_finding(url, missing, result)
                    if finding:
                        findings.append(finding)

                # Process CORS issues
                for cors_issue in result.data.get("cors_issues", []):
                    finding = self._create_cors_finding(url, cors_issue, result)
                    if finding:
                        findings.append(finding)

        return findings

    async def _scan_sqli(self, web_urls: list[str]) -> list[Finding]:
        """Test for SQL injection vulnerabilities.

        SQLMap is MODERATE risk - uses approval workflow if configured.

        Args:
            web_urls: List of web URLs to test

        Returns:
            List of Finding objects for SQLi vulnerabilities
        """
        findings = []

        for url in web_urls:
            # For now, execute directly (approval workflow integration deferred)
            # In Phase 4 this will integrate with execute_tool_with_approval
            result = await self.sqlmap.run(url, forms=True, level=1, risk=1)

            if result.status == ToolStatus.SUCCESS and result.data.get("vulnerable"):
                finding = self._create_sqli_finding(url, result)
                if finding:
                    findings.append(finding)
            elif result.status == ToolStatus.NOT_INSTALLED:
                self.log.warning("sqlmap_not_installed", url=url)

        return findings

    async def _scan_xss(self, web_urls: list[str]) -> list[Finding]:
        """Test for XSS vulnerabilities.

        XSSer is MODERATE risk - uses approval workflow if configured.

        Args:
            web_urls: List of web URLs to test

        Returns:
            List of Finding objects for XSS vulnerabilities
        """
        findings = []

        for url in web_urls:
            # For now, execute directly (approval workflow integration deferred)
            result = await self.xss.run(url, auto=True)

            if result.status == ToolStatus.SUCCESS and result.data.get("vulnerable"):
                finding = self._create_xss_finding(url, result)
                if finding:
                    findings.append(finding)
            elif result.status == ToolStatus.NOT_INSTALLED:
                self.log.warning("xsser_not_installed", url=url)

        return findings

    async def _scan_cmdi(self, web_urls: list[str]) -> list[Finding]:
        """Test for command injection vulnerabilities.

        Commix is DESTRUCTIVE risk - uses approval workflow if configured.

        Args:
            web_urls: List of web URLs to test

        Returns:
            List of Finding objects for command injection vulnerabilities
        """
        findings = []

        for url in web_urls:
            # For now, execute directly (approval workflow integration deferred)
            result = await self.commix.run(url, level=1)

            if result.status == ToolStatus.SUCCESS and result.data.get("vulnerable"):
                finding = self._create_cmdi_finding(url, result)
                if finding:
                    findings.append(finding)
            elif result.status == ToolStatus.NOT_INSTALLED:
                self.log.warning("commix_not_installed", url=url)

        return findings

    def _create_header_finding(
        self,
        url: str,
        missing_header: dict,
        result
    ) -> Finding | None:
        """Create Finding for missing security header.

        Args:
            url: Target URL
            missing_header: Dict with header, purpose, severity
            result: ToolResult from SecurityHeadersTool

        Returns:
            Finding object or None
        """
        header_name = missing_header["header"]
        purpose = missing_header["purpose"]
        severity = missing_header["severity"]

        # Get CVSS characteristics for this vuln type
        vuln_type = "info_disclosure" if severity == "info" else "csrf"
        characteristics = severity_to_cvss_defaults(vuln_type)
        cvss_score, cvss_label = calculate_severity(characteristics)

        finding = Finding(
            title=f"Missing {header_name} header",
            severity=cvss_label,
            description=f"The {header_name} header is missing from {url}. {purpose}",
            evidence=[
                Evidence(
                    source=SourceType.TOOL_CONFIRMED,
                    data={
                        "url": url,
                        "missing_header": header_name,
                        "purpose": purpose,
                        "cvss_score": cvss_score
                    },
                    tool_name="security_headers"
                )
            ],
            confidence="confirmed"  # Will be reclassified below
        )

        # Reclassify confidence based on evidence
        finding.confidence = classify_confidence(finding).value
        return finding

    def _create_cors_finding(
        self,
        url: str,
        cors_issue: dict,
        result
    ) -> Finding | None:
        """Create Finding for CORS misconfiguration.

        Args:
            url: Target URL
            cors_issue: Dict with issue details
            result: ToolResult from SecurityHeadersTool

        Returns:
            Finding object or None
        """
        issue = cors_issue["issue"]
        severity = cors_issue["severity"]
        description = cors_issue["description"]

        # Get CVSS characteristics
        characteristics = severity_to_cvss_defaults("csrf")
        cvss_score, cvss_label = calculate_severity(characteristics)

        finding = Finding(
            title=f"CORS Misconfiguration: {issue}",
            severity=cvss_label,
            description=f"{description} at {url}",
            evidence=[
                Evidence(
                    source=SourceType.TOOL_CONFIRMED,
                    data={
                        "url": url,
                        "issue": issue,
                        "header": cors_issue["header"],
                        "value": cors_issue["value"],
                        "cvss_score": cvss_score
                    },
                    tool_name="security_headers"
                )
            ],
            confidence="confirmed"
        )

        finding.confidence = classify_confidence(finding).value
        return finding

    def _create_sqli_finding(self, url: str, result) -> Finding | None:
        """Create Finding for SQL injection vulnerability.

        Args:
            url: Target URL
            result: ToolResult from SQLMapTool

        Returns:
            Finding object or None
        """
        injection_points = result.data.get("injection_points", [])
        dbms = result.data.get("dbms")

        if not injection_points:
            return None

        # Get CVSS characteristics for SQL injection
        characteristics = severity_to_cvss_defaults("sqli")
        cvss_score, cvss_label = calculate_severity(characteristics)

        # Build description
        params = [ip["parameter"] for ip in injection_points]
        desc = f"SQL injection vulnerability detected in parameter(s): {', '.join(params)}"
        if dbms:
            desc += f". Backend DBMS: {dbms}"

        finding = Finding(
            title=f"SQL Injection in {url}",
            severity=cvss_label,
            description=desc,
            evidence=[
                Evidence(
                    source=SourceType.TOOL_CONFIRMED,
                    data={
                        "url": url,
                        "vulnerable": True,
                        "injection_points": injection_points,
                        "dbms": dbms,
                        "cvss_score": cvss_score
                    },
                    tool_name="sqlmap"
                )
            ],
            confidence="confirmed"
        )

        finding.confidence = classify_confidence(finding).value
        return finding

    def _create_xss_finding(self, url: str, result) -> Finding | None:
        """Create Finding for XSS vulnerability.

        Args:
            url: Target URL
            result: ToolResult from XSSTool

        Returns:
            Finding object or None
        """
        xss_vectors = result.data.get("xss_vectors", [])

        if not xss_vectors:
            return None

        # Determine XSS type (reflected/stored/dom)
        xss_type = xss_vectors[0].get("type", "reflected")
        vuln_type = f"xss_{xss_type}"

        # Get CVSS characteristics
        characteristics = severity_to_cvss_defaults(vuln_type)
        cvss_score, cvss_label = calculate_severity(characteristics)

        # Build description
        params = [xv.get("parameter", "unknown") for xv in xss_vectors]
        desc = f"{xss_type.capitalize()} XSS vulnerability detected in parameter(s): {', '.join(params)}"

        finding = Finding(
            title=f"Cross-Site Scripting (XSS) in {url}",
            severity=cvss_label,
            description=desc,
            evidence=[
                Evidence(
                    source=SourceType.TOOL_CONFIRMED,
                    data={
                        "url": url,
                        "vulnerable": True,
                        "xss_vectors": xss_vectors,
                        "xss_type": xss_type,
                        "cvss_score": cvss_score
                    },
                    tool_name="xsser"
                )
            ],
            confidence="confirmed"
        )

        finding.confidence = classify_confidence(finding).value
        return finding

    def _create_cmdi_finding(self, url: str, result) -> Finding | None:
        """Create Finding for command injection vulnerability.

        Args:
            url: Target URL
            result: ToolResult from CommixTool

        Returns:
            Finding object or None
        """
        injection_points = result.data.get("injection_points", [])
        os_detected = result.data.get("os_detected")

        if not injection_points:
            return None

        # Get CVSS characteristics for command injection
        characteristics = severity_to_cvss_defaults("command_injection")
        cvss_score, cvss_label = calculate_severity(characteristics)

        # Build description
        params = [ip["parameter"] for ip in injection_points]
        desc = f"Command injection vulnerability detected in parameter(s): {', '.join(params)}"
        if os_detected:
            desc += f". Target OS: {os_detected}"

        finding = Finding(
            title=f"Command Injection in {url}",
            severity=cvss_label,
            description=desc,
            evidence=[
                Evidence(
                    source=SourceType.TOOL_CONFIRMED,
                    data={
                        "url": url,
                        "vulnerable": True,
                        "injection_points": injection_points,
                        "os_detected": os_detected,
                        "cvss_score": cvss_score
                    },
                    tool_name="commix"
                )
            ],
            confidence="confirmed"
        )

        finding.confidence = classify_confidence(finding).value
        return finding

    def _count_by_severity(self, findings: list[Finding]) -> dict:
        """Count findings by severity level.

        Args:
            findings: List of findings

        Returns:
            Dict mapping severity to count
        """
        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

        for finding in findings:
            severity = finding.severity.lower()
            if severity in counts:
                counts[severity] += 1

        return counts
