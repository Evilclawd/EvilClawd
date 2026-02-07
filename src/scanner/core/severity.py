"""CVSS v3.1 severity calculation and confidence classification (VULN-04).

Provides standardized severity scoring and confidence levels for all findings.
Uses CVSS v3.1 base score calculation to ensure consistent risk assessment
across different vulnerability types.

Provides:
- calculate_severity: CVSS v3.1 score and severity label from characteristics
- classify_confidence: Confidence level from evidence sources
- Confidence: Enum for confidence levels (CONFIRMED/LIKELY/POSSIBLE)
- severity_to_cvss_defaults: Default CVSS characteristics for common vuln types
"""

from enum import Enum
from typing import Any

from cvss import CVSS3

from scanner.core.output import Evidence, Finding, SourceType


class Confidence(str, Enum):
    """Confidence level for findings.

    Based on the quality and source of evidence:
    - CONFIRMED: Tool output definitively proves vulnerability exists
    - LIKELY: Strong indicators but not definitively proven
    - POSSIBLE: AI interpretation or weak indicators
    """

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"


def calculate_severity(characteristics: dict[str, Any]) -> tuple[float, str]:
    """Calculate CVSS v3.1 score and severity label from vulnerability characteristics.

    Builds a CVSS v3.1 vector string from the provided characteristics,
    calculates the base score, and maps it to a severity label.

    Args:
        characteristics: Dictionary of CVSS metrics:
            - attack_vector: N (network), A (adjacent), L (local), P (physical)
            - attack_complexity: L (low), H (high)
            - privileges_required: N (none), L (low), H (high)
            - user_interaction: N (none), R (required)
            - scope: U (unchanged), C (changed)
            - confidentiality: N (none), L (low), H (high)
            - integrity: N (none), L (low), H (high)
            - availability: N (none), L (low), H (high)

    Returns:
        Tuple of (score, label) where:
        - score: CVSS base score (0.0 - 10.0)
        - label: "info" | "low" | "medium" | "high" | "critical"

    Example:
        >>> chars = {
        ...     "attack_vector": "N",
        ...     "attack_complexity": "L",
        ...     "privileges_required": "N",
        ...     "user_interaction": "N",
        ...     "scope": "U",
        ...     "confidentiality": "H",
        ...     "integrity": "H",
        ...     "availability": "H"
        ... }
        >>> score, label = calculate_severity(chars)
        >>> assert score >= 9.0 and label == "critical"
    """
    try:
        # Build CVSS v3.1 vector string
        vector_parts = ["CVSS:3.1"]

        # Map friendly names to CVSS metric codes
        metric_map = {
            "attack_vector": "AV",
            "attack_complexity": "AC",
            "privileges_required": "PR",
            "user_interaction": "UI",
            "scope": "S",
            "confidentiality": "C",
            "integrity": "I",
            "availability": "A",
        }

        for key, code in metric_map.items():
            value = characteristics.get(key)
            if value:
                vector_parts.append(f"{code}:{value}")

        vector = "/".join(vector_parts)

        # Calculate score using cvss library
        cvss = CVSS3(vector)
        score = cvss.base_score

        # Map score to severity label
        if score == 0.0:
            label = "info"
        elif score < 4.0:
            label = "low"
        elif score < 7.0:
            label = "medium"
        elif score < 9.0:
            label = "high"
        else:
            label = "critical"

        return (score, label)

    except Exception:
        # If calculation fails, return info level
        return (0.0, "info")


def classify_confidence(finding: Finding) -> Confidence:
    """Classify confidence level based on evidence sources.

    Analyzes the finding's evidence to determine how confident we are
    in the vulnerability's existence:

    - CONFIRMED: Has at least one TOOL_CONFIRMED evidence with meaningful data
    - LIKELY: Has TOOL_CONFIRMED evidence but data is ambiguous or incomplete
    - POSSIBLE: Only AI_INTERPRETATION or weak evidence

    Args:
        finding: The finding to classify

    Returns:
        Confidence level (CONFIRMED/LIKELY/POSSIBLE)

    Example:
        >>> from scanner.core.output import Finding, Evidence, SourceType
        >>> finding = Finding(
        ...     title="SQL Injection",
        ...     severity="critical",
        ...     description="Found SQLi",
        ...     evidence=[
        ...         Evidence(
        ...             source=SourceType.TOOL_CONFIRMED,
        ...             data={"payload": "' OR 1=1--", "vulnerable": True},
        ...             tool_name="sqlmap"
        ...         )
        ...     ],
        ...     confidence="high"
        ... )
        >>> assert classify_confidence(finding) == Confidence.CONFIRMED
    """
    if not finding.evidence:
        return Confidence.POSSIBLE

    # Check for TOOL_CONFIRMED evidence with meaningful data
    tool_confirmed = [
        e for e in finding.evidence
        if e.source == SourceType.TOOL_CONFIRMED
    ]

    if tool_confirmed:
        # Check if any tool evidence has substantial data
        for evidence in tool_confirmed:
            if evidence.data and len(evidence.data) > 0:
                # Check for meaningful values (not just empty strings/None)
                has_meaningful_data = any(
                    value and value not in ("", None, [], {})
                    for value in evidence.data.values()
                )
                if has_meaningful_data:
                    return Confidence.CONFIRMED

        # Has tool evidence but it's ambiguous
        return Confidence.LIKELY

    # Only AI interpretation or user input
    return Confidence.POSSIBLE


def severity_to_cvss_defaults(vuln_type: str) -> dict[str, str]:
    """Return default CVSS characteristics for common vulnerability types.

    Provides reasonable default CVSS metrics for well-known vulnerability
    classes. These can be used when detailed characteristics aren't available.

    Args:
        vuln_type: Vulnerability type identifier (e.g., "sqli", "xss_reflected")

    Returns:
        Dictionary of CVSS characteristics

    Supported types:
        - sqli: SQL Injection (critical)
        - xss_reflected: Reflected XSS (medium)
        - xss_stored: Stored XSS (high)
        - command_injection: OS Command Injection (critical)
        - path_traversal: Directory Traversal (high)
        - xxe: XML External Entity (high)
        - ssrf: Server-Side Request Forgery (high)
        - csrf: Cross-Site Request Forgery (medium)
        - open_redirect: Open Redirect (low)
        - info_disclosure: Information Disclosure (low)

    Example:
        >>> defaults = severity_to_cvss_defaults("sqli")
        >>> score, label = calculate_severity(defaults)
        >>> assert label in ("high", "critical")
    """
    defaults = {
        "sqli": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "C",
            "confidentiality": "H",
            "integrity": "H",
            "availability": "H",
        },
        "xss_reflected": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "R",
            "scope": "C",
            "confidentiality": "L",
            "integrity": "L",
            "availability": "N",
        },
        "xss_stored": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "L",
            "user_interaction": "N",
            "scope": "C",
            "confidentiality": "L",
            "integrity": "L",
            "availability": "N",
        },
        "command_injection": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "C",
            "confidentiality": "H",
            "integrity": "H",
            "availability": "H",
        },
        "path_traversal": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "H",
            "integrity": "N",
            "availability": "N",
        },
        "xxe": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "H",
            "integrity": "L",
            "availability": "L",
        },
        "ssrf": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "C",
            "confidentiality": "H",
            "integrity": "L",
            "availability": "L",
        },
        "csrf": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "R",
            "scope": "U",
            "confidentiality": "N",
            "integrity": "L",
            "availability": "N",
        },
        "open_redirect": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "R",
            "scope": "U",
            "confidentiality": "N",
            "integrity": "L",
            "availability": "N",
        },
        "info_disclosure": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "L",
            "integrity": "N",
            "availability": "N",
        },
    }

    # Return defaults for known types, or generic low severity for unknown
    return defaults.get(vuln_type, {
        "attack_vector": "N",
        "attack_complexity": "H",
        "privileges_required": "L",
        "user_interaction": "R",
        "scope": "U",
        "confidentiality": "L",
        "integrity": "N",
        "availability": "N",
    })
