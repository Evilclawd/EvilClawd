"""Report generator with Jinja2 templates (REPT-01 through REPT-04).

Produces structured markdown pentest reports from findings and exploit results,
with evidence validation, severity grouping, and source attribution.
"""

import os
from datetime import datetime
from pathlib import Path

import structlog
from jinja2 import Environment, FileSystemLoader

from scanner.core.output import Evidence, Finding, SourceType

logger = structlog.get_logger()


class ReportGenerator:
    """Generate structured markdown pentest reports (REPT-01 through REPT-04).

    Produces professional pentest reports with:
    - Executive summary with finding counts
    - Findings grouped by severity (critical/high/medium/low/info)
    - Evidence validation (only tool-confirmed findings included)
    - Source attribution with [TOOL]/[AI] markers (REPT-03)
    - Raw tool output included
    - Reproducible PoCs (REPT-02)
    - Remediation guidance by finding (REPT-02)
    - Optional reconnaissance summary
    """

    def __init__(self, template_dir: str | None = None):
        """Initialize report generator with Jinja2 templates.

        Args:
            template_dir: Path to template directory (defaults to ./templates/)
        """
        if template_dir is None:
            template_dir = str(Path(__file__).parent / "templates")
        self.env = Environment(loader=FileSystemLoader(template_dir))

        # Register render_finding as a Jinja2 global function
        self.env.globals["render_finding"] = self._render_finding

    def generate(
        self,
        target: str,
        findings: list[Finding],
        exploit_results: list[str] | None = None,
        recon_summary: dict | None = None,
    ) -> str:
        """Generate complete pentest report from findings and exploit results.

        Only includes findings with tool-confirmed evidence (evidence validation).
        Groups findings by severity, generates executive summary, includes PoCs,
        and provides remediation guidance.

        Args:
            target: Target URL or IP address
            findings: List of Finding objects (will be filtered for tool-confirmed)
            exploit_results: List of PoC markdown strings (optional)
            recon_summary: Reconnaissance summary dict with counts (optional)

        Returns:
            Markdown report string

        Example:
            >>> generator = ReportGenerator()
            >>> report = generator.generate(
            ...     target="https://example.com",
            ...     findings=[sqli_finding, xss_finding],
            ...     exploit_results=["## SQLi PoC\\n..."],
            ...     recon_summary={"total_subdomains": 5, "total_open_ports": 3}
            ... )
        """
        # Filter findings: only include those with tool-confirmed evidence
        validated_findings = [
            f for f in findings if self._has_tool_confirmed_evidence(f)
        ]

        # Deduplicate: group identical finding titles, collect affected hosts
        grouped = self._group_findings(validated_findings)

        # Group deduplicated findings by severity
        findings_by_severity = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": [],
        }

        for group in grouped:
            severity = group["finding"].severity.lower()
            if severity in findings_by_severity:
                findings_by_severity[severity].append(group)

        # Calculate metadata counts (unique finding types, not raw duplicates)
        unique_count = len(grouped)
        metadata = {
            "critical_count": len(findings_by_severity["critical"]),
            "high_count": len(findings_by_severity["high"]),
            "medium_count": len(findings_by_severity["medium"]),
            "low_count": len(findings_by_severity["low"]),
            "info_count": len(findings_by_severity["info"]),
            "total_findings": unique_count,
            "total_instances": len(validated_findings),
        }

        # Generate executive summary
        executive_summary = self._generate_executive_summary(grouped, target)

        # Generate remediation guidance (deduplicated)
        remediation_guidance = self._generate_remediation(grouped)

        # Build template context
        context = {
            "target": target,
            "date": datetime.utcnow().strftime("%Y-%m-%d"),
            "executive_summary": executive_summary,
            "findings_by_severity": findings_by_severity,
            "exploit_pocs": exploit_results or [],
            "remediation_guidance": remediation_guidance,
            "metadata": metadata,
            "recon_summary": recon_summary,
        }

        # Render main template
        template = self.env.get_template("pentest_report.md.j2")
        return template.render(**context)

    def _group_findings(self, findings: list[Finding]) -> list[dict]:
        """Group duplicate findings by title, collecting affected hosts.

        Args:
            findings: List of validated findings (may have duplicates across hosts)

        Returns:
            List of dicts with 'finding' (representative Finding) and 'hosts' (list of affected hosts)
        """
        groups: dict[str, dict] = {}

        for finding in findings:
            title = finding.title
            # Extract host from evidence data
            host = None
            for evidence in finding.evidence:
                if "url" in evidence.data:
                    host = evidence.data["url"]
                    break
                if "target" in evidence.data:
                    host = evidence.data["target"]
                    break

            if title not in groups:
                groups[title] = {
                    "finding": finding,
                    "hosts": [],
                }

            if host and host not in groups[title]["hosts"]:
                groups[title]["hosts"].append(host)

        return list(groups.values())

    def _has_tool_confirmed_evidence(self, finding: Finding) -> bool:
        """Check if finding has at least one TOOL_CONFIRMED evidence item.

        Evidence validation: only findings with tool-confirmed evidence
        should be included in reports.

        Args:
            finding: Finding to check

        Returns:
            True if finding has tool-confirmed evidence
        """
        return any(
            evidence.source == SourceType.TOOL_CONFIRMED
            for evidence in finding.evidence
        )

    def _generate_executive_summary(
        self, groups: list[dict], target: str
    ) -> str:
        """Generate executive summary paragraph from grouped findings.

        Args:
            groups: List of grouped finding dicts
            target: Target URL/IP

        Returns:
            Executive summary markdown string
        """
        if not groups:
            return f"Automated security assessment of **{target}** completed with no significant findings."

        # Count unique finding types by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        total_instances = 0
        for group in groups:
            severity = group["finding"].severity.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            total_instances += max(len(group["hosts"]), 1)

        total = len(groups)
        critical = severity_counts["critical"]
        high = severity_counts["high"]
        medium = severity_counts["medium"]

        summary_parts = [
            f"Automated security assessment of **{target}** identified **{total} unique finding types** across {total_instances} instances."
        ]

        if critical > 0:
            summary_parts.append(
                f"**{critical} critical** issue{'s' if critical > 1 else ''} require immediate attention."
            )

        if high > 0:
            summary_parts.append(
                f"**{high} high severity** finding{'s' if high > 1 else ''} should be addressed promptly."
            )

        if medium > 0:
            summary_parts.append(
                f"{medium} medium severity issue{'s' if medium > 1 else ''} identified."
            )

        return " ".join(summary_parts)

    def _generate_remediation(self, groups: list[dict]) -> list[dict]:
        """Generate remediation guidance section from grouped findings.

        Args:
            groups: List of grouped finding dicts

        Returns:
            List of remediation dicts with finding_title, severity, recommendation, references
        """
        remediation_list = []

        for group in groups:
            finding = group["finding"]
            remediation = {
                "finding_title": finding.title,
                "severity": finding.severity.upper(),
                "recommendation": self._extract_remediation_text(finding),
                "references": self._extract_references(finding),
            }
            remediation_list.append(remediation)

        return remediation_list

    def _extract_remediation_text(self, finding: Finding) -> str:
        """Extract or generate remediation recommendation text.

        Args:
            finding: Finding to extract remediation from

        Returns:
            Remediation recommendation markdown
        """
        # Check evidence for remediation data
        for evidence in finding.evidence:
            if "remediation" in evidence.data:
                return evidence.data["remediation"]

        # Generate generic remediation based on finding title/description
        if "sql injection" in finding.title.lower():
            return (
                "Use parameterized queries or prepared statements for all database interactions. "
                "Never concatenate user input directly into SQL queries. "
                "Implement input validation and sanitization. "
                "Apply the principle of least privilege to database accounts."
            )
        elif "xss" in finding.title.lower():
            return (
                "Implement context-aware output encoding for all user-controlled data. "
                "Use Content Security Policy (CSP) headers to restrict script execution. "
                "Validate and sanitize all user input. "
                "Consider using a security-focused template engine with auto-escaping."
            )
        elif "command injection" in finding.title.lower():
            return (
                "Avoid invoking shell commands with user-controlled input. "
                "Use language-specific APIs instead of shell execution where possible. "
                "Implement strict input validation with allowlists. "
                "Apply the principle of least privilege to application processes."
            )
        elif "header" in finding.title.lower() or "security" in finding.description.lower():
            return (
                "Configure appropriate security headers to enhance browser-side protections. "
                "Review and implement missing headers based on application requirements. "
                "Test header configuration across all application endpoints."
            )
        else:
            return (
                f"Review and address the identified {finding.severity} severity issue. "
                "Consult security best practices and framework-specific guidelines for remediation. "
                "Test fixes thoroughly before deploying to production."
            )

    def _extract_references(self, finding: Finding) -> list[str]:
        """Extract reference URLs from finding evidence.

        Args:
            finding: Finding to extract references from

        Returns:
            List of reference URL strings
        """
        references = []

        for evidence in finding.evidence:
            if "references" in evidence.data:
                refs = evidence.data["references"]
                if isinstance(refs, list):
                    references.extend(refs)
                elif isinstance(refs, str):
                    references.append(refs)

        # Add default references based on vulnerability type
        if not references:
            if "sql injection" in finding.title.lower():
                references.append("https://owasp.org/www-community/attacks/SQL_Injection")
            elif "xss" in finding.title.lower():
                references.append(
                    "https://owasp.org/www-community/attacks/xss/"
                )
            elif "command injection" in finding.title.lower():
                references.append(
                    "https://owasp.org/www-community/attacks/Command_Injection"
                )

        return references

    def _render_finding(self, finding: Finding) -> str:
        """Render a single finding with evidence and source attribution.

        Used by Jinja2 template to render individual findings.

        Args:
            finding: Finding to render

        Returns:
            Markdown string with finding details
        """
        # Load finding template
        template = self.env.get_template("finding.md.j2")

        # Build context
        context = {
            "finding": finding,
            "format_evidence": self._format_evidence,
        }

        return template.render(**context)

    def _format_evidence(self, evidence: Evidence) -> str:
        """Format evidence item with source attribution markers.

        Args:
            evidence: Evidence item to format

        Returns:
            Markdown string with [TOOL]/[AI] markers (REPT-03)
        """
        # Visual prefix based on source
        prefix_map = {
            SourceType.AI_INTERPRETATION: "[AI]",
            SourceType.TOOL_CONFIRMED: "[TOOL]",
            SourceType.USER_INPUT: "[USER]",
            SourceType.SYSTEM: "[SYSTEM]",
        }
        prefix = prefix_map.get(evidence.source, "[UNKNOWN]")

        tool_info = f" **{evidence.tool_name}**" if evidence.tool_name else ""

        lines = [f"- {prefix}{tool_info}"]

        # Add evidence data
        for key, value in evidence.data.items():
            # Handle multi-line values (raw tool output)
            if isinstance(value, str) and "\n" in value:
                lines.append(f"  - **{key}:**")
                lines.append("    ```")
                lines.append("    " + value.replace("\n", "\n    "))
                lines.append("    ```")
            else:
                lines.append(f"  - **{key}:** {value}")

        return "\n".join(lines)

    async def analyze(
        self,
        target: str,
        findings: list[Finding],
        recon_summary: dict | None = None,
    ) -> str:
        """Generate LLM-powered offensive/defensive analysis of findings.

        Uses Claude to explain each finding in plain language with attack
        scenarios and specific remediation steps.

        Args:
            target: Target URL or domain
            findings: List of Finding objects
            recon_summary: Optional recon data for context

        Returns:
            Markdown analysis string
        """
        from scanner.core.llm.anthropic_provider import AnthropicProvider

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            return "LLM analysis unavailable: ANTHROPIC_API_KEY not set. Add it to your .env file."

        # Filter and group findings
        validated = [f for f in findings if self._has_tool_confirmed_evidence(f)]
        groups = self._group_findings(validated)

        if not groups:
            return f"No tool-confirmed findings to analyze for {target}."

        # Build findings summary for the prompt
        findings_text = []
        for group in groups:
            hosts = ", ".join(group["hosts"][:5])
            if len(group["hosts"]) > 5:
                hosts += f" (+{len(group['hosts']) - 5} more)"
            findings_text.append(
                f"- {group['finding'].title} ({group['finding'].severity.upper()}) "
                f"— {len(group['hosts'])} hosts: {hosts}\n"
                f"  Description: {group['finding'].description}"
            )

        recon_context = ""
        if recon_summary:
            recon_context = (
                f"\nRecon data: {recon_summary.get('total_subdomains', 0)} subdomains, "
                f"{recon_summary.get('total_open_ports', 0)} open ports, "
                f"{recon_summary.get('total_technologies', 0)} technologies detected."
            )

        prompt = f"""You are an expert penetration tester writing an analysis report for {target}.{recon_context}

Here are the deduplicated findings from automated scanning:

{chr(10).join(findings_text)}

For each finding, provide:
1. **What this means** — plain language explanation
2. **Attack scenario** — how a white-hat attacker would exploit this (be specific)
3. **Fix** — specific remediation with config examples (nginx/apache where relevant)
4. **Priority** — relative importance compared to other findings

Then add a brief **Overall Assessment** section at the end summarizing the target's security posture and what to fix first.

Format as clean markdown. Be concise but specific. Use code blocks for config examples."""

        try:
            provider = AnthropicProvider(api_key=api_key, model="claude-sonnet-4-5-20250929")
            response = await provider.complete(
                messages=[{"role": "user", "content": prompt}]
            )

            # Extract text from response
            analysis = ""
            for block in response.get("content", []):
                if block.get("text"):
                    analysis += block["text"]

            logger.info("llm_analysis_complete", target=target, findings=len(groups))
            return analysis

        except Exception as e:
            logger.error("llm_analysis_failed", error=str(e))
            return f"LLM analysis failed: {e}"
