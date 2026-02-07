"""Tool definitions with risk classification.

Defines the tools available to the LLM during security analysis, with
explicit risk levels to enable safety controls and user approval workflows.
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Risk level classification for tools.

    SAFE: Read-only operations with no potential for harm
    MODERATE: Operations that could affect target system but are reversible
    DESTRUCTIVE: Operations that could cause damage or data loss
    """

    SAFE = "safe"
    MODERATE = "moderate"
    DESTRUCTIVE = "destructive"


class ToolDefinition(BaseModel):
    """Definition of a tool available to the LLM.

    Includes metadata for risk assessment and Anthropic API schema conversion.
    """

    name: str = Field(..., description="Unique tool identifier")
    description: str = Field(..., description="Human-readable tool description")
    risk_level: RiskLevel = Field(..., description="Risk classification")
    input_schema: dict[str, Any] = Field(
        ..., description="JSON schema for tool input parameters"
    )

    def to_anthropic_schema(self) -> dict[str, Any]:
        """Convert to Anthropic tool schema format.

        Returns:
            Tool definition in Anthropic API format
        """
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }


# Tool definitions for security analysis
TOOLS: list[ToolDefinition] = [
    ToolDefinition(
        name="nmap_scan",
        description="Perform network port scanning using nmap to discover open ports and services",
        risk_level=RiskLevel.SAFE,
        input_schema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP address or hostname to scan",
                },
                "ports": {
                    "type": "string",
                    "description": "Port specification (e.g., '80,443' or '1-1000')",
                },
                "scan_type": {
                    "type": "string",
                    "description": "Type of scan (SYN, TCP connect, UDP, etc.)",
                    "enum": ["syn", "tcp", "udp", "version"],
                },
            },
            "required": ["target"],
        },
    ),
    ToolDefinition(
        name="check_scope",
        description="Verify that a target is within the authorized scope for testing",
        risk_level=RiskLevel.SAFE,
        input_schema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP address or hostname to check",
                },
            },
            "required": ["target"],
        },
    ),
    ToolDefinition(
        name="sqlmap_scan",
        description="Test for SQL injection vulnerabilities using SQLMap on web applications",
        risk_level=RiskLevel.MODERATE,
        input_schema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL to test (e.g., 'http://example.com/page?id=1')",
                },
                "data": {
                    "type": "string",
                    "description": "POST data for testing (optional)",
                },
                "level": {
                    "type": "integer",
                    "description": "Depth of tests (1-5, default: 1)",
                    "minimum": 1,
                    "maximum": 5,
                },
                "risk": {
                    "type": "integer",
                    "description": "Risk level (1-3, default: 1)",
                    "minimum": 1,
                    "maximum": 3,
                },
            },
            "required": ["target"],
        },
    ),
    ToolDefinition(
        name="xss_scan",
        description="Test for cross-site scripting (XSS) vulnerabilities using XSSer on web applications",
        risk_level=RiskLevel.MODERATE,
        input_schema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL to test (e.g., 'http://example.com/search?q=test')",
                },
                "auto": {
                    "type": "boolean",
                    "description": "Enable automatic crawling and testing",
                },
                "crawl": {
                    "type": "integer",
                    "description": "Crawl depth for auto mode",
                },
            },
            "required": ["target"],
        },
    ),
    ToolDefinition(
        name="commix_scan",
        description="Test for command injection vulnerabilities using Commix on web applications",
        risk_level=RiskLevel.DESTRUCTIVE,
        input_schema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL to test (e.g., 'http://example.com/ping?host=127.0.0.1')",
                },
                "data": {
                    "type": "string",
                    "description": "POST data for testing (optional)",
                },
                "level": {
                    "type": "integer",
                    "description": "Depth of tests (1-3, default: 1)",
                    "minimum": 1,
                    "maximum": 3,
                },
            },
            "required": ["target"],
        },
    ),
    ToolDefinition(
        name="header_check",
        description="Check HTTP security headers for misconfigurations and missing protections",
        risk_level=RiskLevel.SAFE,
        input_schema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL to check (must include scheme, e.g., 'https://example.com')",
                },
            },
            "required": ["target"],
        },
    ),
    ToolDefinition(
        name="exploit_vulnerability",
        description="Attempt to exploit a discovered vulnerability on the target system",
        risk_level=RiskLevel.DESTRUCTIVE,
        input_schema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP address or hostname",
                },
                "vulnerability": {
                    "type": "string",
                    "description": "CVE identifier or vulnerability type",
                },
                "payload": {
                    "type": "string",
                    "description": "Exploit payload or command to execute",
                },
            },
            "required": ["target", "vulnerability", "payload"],
        },
    ),
]


def get_tool_by_name(name: str) -> ToolDefinition | None:
    """Retrieve a tool definition by name.

    Args:
        name: Tool name to look up

    Returns:
        ToolDefinition if found, None otherwise
    """
    for tool in TOOLS:
        if tool.name == name:
            return tool
    return None
