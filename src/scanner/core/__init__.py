"""Core scanner functionality.

Provides:
- Output formatting with source attribution (SAFE-04)
- CVSS severity calculation and confidence classification (VULN-04)
"""

from .output import Evidence, Finding, SourceType, format_evidence_list, format_output
from .severity import Confidence, calculate_severity, classify_confidence, severity_to_cvss_defaults

__all__ = [
    "Evidence",
    "Finding",
    "SourceType",
    "format_evidence_list",
    "format_output",
    "Confidence",
    "calculate_severity",
    "classify_confidence",
    "severity_to_cvss_defaults",
]
