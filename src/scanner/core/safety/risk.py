"""Risk-based execution control (SAFE-02, SAFE-03).

Determines whether tool execution requires human approval based on
the tool's risk classification. Risk is a property of the tool definition,
not determined at runtime (per RESEARCH.md Pitfall 4).

Provides:
- should_require_approval: Check if a tool needs human approval
- get_risk_description: Human-readable risk level description
"""

from scanner.core.llm.tools import RiskLevel, ToolDefinition


def should_require_approval(tool: ToolDefinition) -> bool:
    """Determine if tool requires human approval (SAFE-03).

    SAFE tools: auto-approve (read-only operations)
    MODERATE/DESTRUCTIVE: require approval (guided mode)

    Args:
        tool: Tool definition with risk_level attribute

    Returns:
        True if approval is required, False for auto-approve
    """
    return tool.risk_level in [RiskLevel.MODERATE, RiskLevel.DESTRUCTIVE]


def get_risk_description(risk_level: RiskLevel) -> str:
    """Get human-readable description of a risk level.

    Used in approval prompts to help users understand the
    implications of approving a tool execution.

    Args:
        risk_level: The risk level to describe

    Returns:
        Human-readable description string
    """
    descriptions = {
        RiskLevel.SAFE: "Read-only operation with no side effects",
        RiskLevel.MODERATE: "May modify target state (reversible)",
        RiskLevel.DESTRUCTIVE: "Irreversible high-impact operation",
    }
    return descriptions.get(risk_level, "Unknown risk level")
