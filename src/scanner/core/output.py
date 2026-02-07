"""Output formatting with source attribution (SAFE-04).

Provides structured output types that clearly distinguish between
AI interpretation and tool-confirmed findings. Every piece of evidence
is tagged with its source type, enabling users to understand the
reliability and origin of each finding.

Provides:
- SourceType: Enum for evidence source classification
- Evidence: Single piece of evidence with source attribution
- Finding: Security finding with source-attributed evidence
- format_output: Format a finding with visual source markers
- format_evidence_list: Format a list of evidence items
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SourceType(str, Enum):
    """Source of information (SAFE-04).

    Distinguishes AI interpretation from tool-confirmed findings,
    enabling users to assess the reliability of each piece of evidence.

    AI_INTERPRETATION: LLM reasoning, analysis, suggestions (may be wrong)
    TOOL_CONFIRMED: Actual tool execution results (verified)
    USER_INPUT: Human-provided information
    SYSTEM: System-generated data (scope checks, config, etc.)
    """

    AI_INTERPRETATION = "ai_interpretation"
    TOOL_CONFIRMED = "tool_confirmed"
    USER_INPUT = "user_input"
    SYSTEM = "system"


class Evidence(BaseModel):
    """Single piece of evidence with source attribution.

    Every evidence item is tagged with its source type and timestamp,
    providing a clear audit trail of how findings were discovered.

    Attributes:
        source: Where this evidence came from
        timestamp: When the evidence was collected
        data: Key-value pairs of evidence data
        tool_name: Name of the tool (only for TOOL_CONFIRMED sources)
    """

    source: SourceType
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    data: dict[str, Any]
    tool_name: str | None = None  # Set if source is TOOL_CONFIRMED


class Finding(BaseModel):
    """Security finding with source-attributed evidence.

    Represents a discovered vulnerability or security issue, with
    all supporting evidence tagged by source type.

    Attributes:
        title: Short description of the finding
        severity: Impact level (info, low, medium, high, critical)
        description: Detailed description of the finding
        evidence: List of evidence items with source attribution
        confidence: How confident we are in the finding (low, medium, high)
    """

    title: str
    severity: str  # info, low, medium, high, critical
    description: str
    evidence: list[Evidence]
    confidence: str  # low, medium, high

    def add_evidence(
        self, source: SourceType, data: dict, tool_name: str | None = None
    ):
        """Add evidence with source attribution.

        Args:
            source: Source type of the evidence
            data: Key-value pairs of evidence data
            tool_name: Tool name if source is TOOL_CONFIRMED
        """
        self.evidence.append(
            Evidence(
                source=source,
                data=data,
                tool_name=tool_name,
            )
        )


def format_output(finding: Finding) -> str:
    """Format finding with clear visual distinction between AI and tool results (SAFE-04).

    Uses prefixes and structured formatting to distinguish:
    - [AI] for LLM interpretation
    - [TOOL] for tool-confirmed findings
    - [USER] for user input
    - [SYSTEM] for system checks

    Args:
        finding: The finding to format

    Returns:
        Formatted string with visual source markers
    """
    output = []
    output.append(f"{'=' * 60}")
    output.append(f"Finding: {finding.title}")
    output.append(
        f"Severity: {finding.severity.upper()} | Confidence: {finding.confidence.upper()}"
    )
    output.append(f"{'=' * 60}")
    output.append(f"\n{finding.description}\n")

    if finding.evidence:
        output.append("Evidence:")
        for idx, evidence in enumerate(finding.evidence, 1):
            # Visual prefix based on source
            prefix_map = {
                SourceType.AI_INTERPRETATION: "[AI]",
                SourceType.TOOL_CONFIRMED: "[TOOL]",
                SourceType.USER_INPUT: "[USER]",
                SourceType.SYSTEM: "[SYSTEM]",
            }
            prefix = prefix_map.get(evidence.source, "[UNKNOWN]")

            tool_info = f" ({evidence.tool_name})" if evidence.tool_name else ""
            output.append(
                f"  {idx}. {prefix}{tool_info} @ {evidence.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
            )

            # Indent evidence data
            for key, value in evidence.data.items():
                output.append(f"     {key}: {value}")

    output.append(f"{'=' * 60}")
    return "\n".join(output)


def format_evidence_list(evidence_list: list[Evidence]) -> str:
    """Format list of evidence items with source markers.

    Provides a compact view of evidence items with their source
    types and associated data.

    Args:
        evidence_list: List of evidence items to format

    Returns:
        Formatted string with numbered evidence items
    """
    lines = []
    for idx, evidence in enumerate(evidence_list, 1):
        source_label = evidence.source.value.replace("_", " ").upper()
        tool_suffix = f" - {evidence.tool_name}" if evidence.tool_name else ""
        lines.append(f"{idx}. [{source_label}]{tool_suffix}")
        for key, value in evidence.data.items():
            lines.append(f"   {key}: {value}")
    return "\n".join(lines)
